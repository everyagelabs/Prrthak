import tempfile
import unittest
from email.message import Message
from unittest.mock import Mock

from controller.app import App, handler_for
from controller.metadata import subnet_apply, subnet_preview
from controller.source_geography import annotate
from controller.store import Store, stamp
from controller.tests.capture_fixture import typed_event


class SourceGeographyTests(unittest.TestCase):
    @staticmethod
    def origins(ips, *, servers=(), rules=()):
        flows = [{"source_ip": ip} for ip in ips]
        locations = [{"id": "noida"}, {"id": "pune"}]
        return [flow["source_origin"] for flow in annotate(flows, servers, locations, lambda: rules)]

    def test_longest_internal_subnet_matches_without_a_managed_source_endpoint(self):
        rules = [
            {"cidr": "10.0.0.0/8", "location_id": "noida"},
            {"cidr": "10.1.2.0/24", "location_id": "pune"},
            {"cidr": "fd00:abcd::/48", "location_id": "pune"},
            {"cidr": "100.64.0.0/10", "location_id": "noida"},
            {"cidr": "8.8.8.0/24", "location_id": "pune"},
        ]
        self.assertEqual(self.origins(["10.1.2.3", "10.1.3.3", "fd00:abcd::1", "100.100.0.3", "192.168.1.1", "8.8.8.8"], rules=rules), [
            {"kind": "location", "location_id": "pune"},
            {"kind": "location", "location_id": "noida"},
            {"kind": "location", "location_id": "pune"},
            {"kind": "location", "location_id": "noida"},
            {"kind": "private"},
            {"kind": "external"},
        ])

    def test_exact_site_ownership_precedes_subnet_and_conflicts_remain_unmapped(self):
        rules = [{"cidr": "10.0.0.0/8", "location_id": "noida"}]
        servers = [
            {"ips": ["10.0.0.1", "10.0.0.2", "8.8.8.8"], "location_id": "pune"},
            {"ips": ["10.0.0.1"], "location_id": "pune"},  # Shared address within one site.
            {"ips": ["10.0.0.2"], "location_id": "noida"},
            {"ips": ["10.0.0.3"], "location_source": {"type": "conflict"}},
            {"ips": ["10.0.0.4"], "location_source": {"type": "manual", "cleared": True}},
        ]
        self.assertEqual(self.origins(["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "8.8.8.8"], servers=servers, rules=rules), [
            {"kind": "location", "location_id": "pune"},
            {"kind": "private"},
            {"kind": "private"},
            {"kind": "private"},
            {"kind": "location", "location_id": "pune"},
        ])

    def test_no_subnet_read_for_exact_or_unmapped_public_addresses(self):
        load_subnets = Mock(side_effect=AssertionError("Unneeded subnet lookup"))
        flows = [{"source_ip": "10.0.0.1"}, {"source_ip": "8.8.8.8"}]
        servers = [{"ips": ["10.0.0.1"], "location_id": "noida"}]
        annotated = annotate(flows, servers, [{"id": "noida"}], load_subnets)
        self.assertEqual([flow["source_origin"]["kind"] for flow in annotated], ["location", "external"])
        self.assertNotIn("source_origin", flows[0])
        load_subnets.assert_not_called()

    def test_overview_and_nondefault_window_use_current_dashboard_assignments(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            site = store.save_location({"name": "Noida", "location": "Noida, India", "type": "datacenter"}, "admin")
            for name, ip in [("web", "10.0.0.1"), ("client", "10.0.0.2")]:
                store.report(name, {
                    "hostname": name, "ips": [ip], "capabilities": ["traffic_capture_v1"],
                    "listeners": [{"port": 443, "protocol": "tcp", "address": "0.0.0.0"}],
                })
            store.update_server("client", {"location_id": site["id"]}, "admin")
            preview = subnet_preview(store, {"cidr": "10.4.0.0/16", "location_id": site["id"]})
            subnet_apply(store, preview["id"], {"confirmation_nonce": preview["confirmation_nonce"]}, "admin")
            session = store.create_session({"server_ids": ["web"], "ports": [{"port": 443, "protocol": "tcp"}], "duration_seconds": 3600}, "admin")
            store.enqueue_flows("web", {"session_id": session["id"], "batch_id": "map", "events": [
                typed_event(source, 443, identity=source, at=stamp()) for source in ("10.0.0.2", "10.4.0.2", "8.8.8.8")
            ]})
            store.process_flows()
            overview = store.overview()
            expected = {
                "10.0.0.2": {"kind": "location", "location_id": site["id"]},
                "10.4.0.2": {"kind": "location", "location_id": site["id"]},
                "8.8.8.8": {"kind": "external"},
            }
            self.assertEqual({row["source_ip"]: row["source_origin"] for row in overview["flows"]}, expected)
            app = App(store, tokens={"read_only": "fixture-read-token"})
            handler = object.__new__(handler_for(app))
            handler.command = "GET"
            handler.path = "/api/v1/flows?window=21600&server_id=web"
            handler.connection = object()
            handler.client_address = ("127.0.0.1", 12345)
            handler.headers = Message()
            handler.headers["Authorization"] = "Bearer fixture-read-token"
            handler.response = Mock()
            handler.dispatch()
            status, response = handler.response.call_args.args
            self.assertEqual(status, 200)
            self.assertEqual({row["source_ip"]: row["source_origin"] for row in response["items"]}, expected)
            self.assertEqual(overview["stats"]["capture_counts"]["connections"], 3)
            self.assertNotIn("source_origin", store.flows()[0])
