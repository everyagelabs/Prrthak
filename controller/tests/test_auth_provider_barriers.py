"""Local repair authority remains usable inside a global HA business barrier."""
import http.client
import json
import ssl
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

from controller.app import App, handler_for
from controller.auth import EntraAuth, EntraConfig, SESSION_COOKIE
from controller.authentication import Authentication
from controller.pki import init_ca
from controller.store import Store


class LocalProviderBarrierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(self.temp.name)
        pki = init_ca(self.temp.name)
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(pki/'controller.pem',pki/'controller-key.pem')
        self.client_context = ssl.create_default_context(cafile=str(pki/'ca.pem'))
        auth = Authentication(self.store,entra=EntraAuth(self.store,EntraConfig()))
        self.app = App(self.store,auth=auth)
        server = ThreadingHTTPServer(('127.0.0.1',0),handler_for(self.app))
        server.daemon_threads = True
        server.socket = server_context.wrap_socket(server.socket,server_side=True)
        self.server = server
        self.thread = threading.Thread(target=server.serve_forever,daemon=True)
        self.thread.start()
        self.addCleanup(self.close_server)
        self.origin = 'https://localhost:'+str(server.server_port)
        auth.local.origin = self.origin
        # This represents a stale member of an Entra provider transition. Its
        # independent local authority and shared DB are still authentic.
        with self.store.meta() as db:
            self.store._put(db,'maintenance_settings',{'id':'controller_provider_authority',
                                                     'fingerprint':'0'*64,'epoch':''})

    def close_server(self):
        self.server.shutdown();self.thread.join(timeout=5);self.server.server_close()

    def api(self, method, path, value=None, headers=None, status=200):
        outgoing = dict(headers or {})
        raw = None
        if value is not None:
            raw = json.dumps(value).encode();outgoing['Content-Type']='application/json'
        client = http.client.HTTPSConnection('localhost',self.server.server_port,
                                             context=self.client_context,timeout=10)
        try:
            client.request(method,path,body=raw,headers=outgoing)
            response = client.getresponse();body=response.read()
            result = json.loads(body) if body else None
            self.assertEqual(response.status,status,result)
            cookies=[v for k,v in response.getheaders() if k.lower()=='set-cookie']
            return result,cookies
        finally:client.close()

    def sign_in(self):
        auth,cookies=self.api('POST','/api/v1/auth/local',{'username':'admin','password':'admin'},
                              {'Origin':self.origin})
        self.assertTrue(auth['password_change_required'])
        cookie=next(c.split(';',1)[0] for c in cookies if c.startswith(SESSION_COOKIE+'='))
        headers={'Cookie':cookie,'X-CSRF-Token':auth['csrf_token'],'Origin':self.origin}
        self.api('GET','/api/v1/auth',headers=headers)
        changed,cookies=self.api('POST','/api/v1/auth/password',
                                {'current_password':'admin','new_password':'Private-barrier-test-2026!',
                                 'confirm_password':'Private-barrier-test-2026!'},headers)
        self.assertFalse(changed['password_change_required'])
        cookie=next(c.split(';',1)[0] for c in cookies if c.startswith(SESSION_COOKIE+'='))
        return {'Cookie':cookie,'X-CSRF-Token':changed['csrf_token'],'Origin':self.origin}

    def test_stale_directory_authority_allows_own_auth_and_password_but_no_business_access(self):
        headers=self.sign_in()
        auth,_=self.api('GET','/api/v1/auth',headers=headers)
        self.assertEqual(auth['auth_provider'],'local')
        self.api('GET','/api/v1/overview',headers=headers,status=403)
        self.api('POST','/api/v1/policies',{},headers,status=403)
        self.api('POST','/api/v1/enrollment-tokens',{},headers,status=403)
        self.api('POST','/api/v1/auth/logout',{},headers)
        self.assertIsNone(self.app.auth.local.authenticate(headers))
        # An invalid session no longer qualifies for the local repair exception.
        self.api('GET','/api/v1/auth',headers=headers,status=403)

    def test_provider_diagnostics_and_repair_do_not_bypass_the_business_barrier(self):
        headers=self.sign_in()
        providers,_=self.api('GET','/api/v1/auth/providers',headers=headers)
        self.assertTrue(providers['local']['enabled'])
        result,_=self.api('PUT','/api/v1/auth/providers/saml',
                          {'enabled':False,'expected_revision':providers['saml']['revision']},headers)
        self.assertFalse(result['saml']['enabled'])
        self.assertTrue(result['local']['enabled'])
        self.api('GET','/api/v1/auth',headers=headers)
        self.api('GET','/api/v1/overview',headers=headers,status=403)
        self.api('POST','/api/v1/auth-password-bypass',{},headers,status=403)


if __name__=='__main__':unittest.main()
