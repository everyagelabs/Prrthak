"""Security boundaries and backwards compatibility of actual socket channels."""
import os
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from controller import channels


class ChannelTests(unittest.TestCase):
    def test_all_endpoint_routes_are_admitted_only_on_their_channel(self):
        for own, paths in (("control", channels.CONTROL), ("discovery", channels.DISCOVERY)):
            for path, method in paths.items():
                self.assertTrue(channels.admitted(own, method, path), path)
                for other in {"control", "discovery", "management", "unknown"} - {own}:
                    self.assertFalse(channels.admitted(other, method, path), (other, path))
                self.assertFalse(channels.admitted(own, "DELETE", path))
        for path in ("/api/v1/users", "/api/v1/auth/login", "/api/v1/platform/setup", "/servers", "/assets/x.js"):
            self.assertTrue(channels.admitted("management", "GET", path))
            self.assertFalse(channels.admitted("control", "GET", path))
            self.assertFalse(channels.admitted("discovery", "GET", path))

    def test_health_is_allowed_on_known_channels_only(self):
        for name in ("management", "control", "discovery", "combined"):
            self.assertTrue(channels.admitted(name, "GET", "/readyz"))
        self.assertFalse(channels.admitted("unknown", "GET", "/readyz"))

    def test_listener_requires_complete_unique_configuration(self):
        self.assertEqual(channels.listeners("127.0.0.1:8787"), {8787: "combined"})
        self.assertEqual(channels.listeners("0.0.0.0:8787", "0.0.0.0:8788", "0.0.0.0:8789"), {8787: "management",8788: "control",8789: "discovery"})
        for args in (("a:1","a:2",None),("a:1",None,"a:2"),("a:1","b:1","c:2"),("a:1","a:0","a:2")):
            with self.assertRaises(ValueError):channels.listeners(*args)

    def test_channel_uses_socket_not_headers_or_reported_peer(self):
        app=SimpleNamespace(listener_channels={8788: "control"})
        sock=SimpleNamespace(getsockname=lambda:("127.0.0.1",8788))
        self.assertEqual(channels.request_channel(app,sock),"control")
        self.assertEqual(channels.request_channel(app,object()),"unknown")
        self.assertEqual(channels.request_channel(SimpleNamespace(),object()),"combined")

    def test_advertised_urls_preserve_hostname_and_use_reviewed_public_ports(self):
        app=SimpleNamespace(listener_channels={8787:"management",8788:"control",8789:"discovery"},auth=SimpleNamespace(config=SimpleNamespace(redirect_uri="https://controller.example/api/v1/auth/callback")))
        with patch.dict(os.environ,{"SEG_CONTROL_PORT":"9444","SEG_DISCOVERY_PORT":"9445"}):
            status=channels.public_status(app)
        self.assertEqual(status['control_url'],'https://controller.example:9444')
        self.assertEqual(status['discovery_url'],'https://controller.example:9445')
        app.listener_channels={8787:"combined"}
        self.assertEqual(channels.public_status(app)['control_url'],'https://controller.example')

    def test_learning_excludes_every_local_controller_channel(self):
        from controller.learning_policies import _protected
        server={"ips":["192.0.2.1"],"protection":{"controller_url":"https://192.0.2.1:8787"},
                "configuration_state":{"control_url":"https://192.0.2.1:8788","discovery_url":"https://192.0.2.1:8789"}}
        for port in (8787,8788,8789):
            self.assertIn("Protected local controller",_protected(server,port,"tcp"))
        self.assertEqual(_protected(server,8443,"tcp"),"")
