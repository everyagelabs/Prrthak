"""TEST ONLY private mTLS transport for the fixed in-node helper.

Never copied into the production database image. It exists solely to test the
real local manager/coordinator without mounting the host Docker socket.
"""
from http.server import BaseHTTPRequestHandler,HTTPServer
import json
import os
from pathlib import Path
import signal
import ssl
import subprocess


class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_POST(self):
        length=int(self.headers.get('Content-Length','0'))
        if self.path not in ('/fixed-rotation-helper','/fixed-internal-reload','/fixed-restore-helper') or self.headers.get('Transfer-Encoding') or not 0<length<=4096:
            self.send_error(400);return
        body=self.rfile.read(length)
        if self.path=='/fixed-internal-reload':
            if json.loads(body)!={}:self.send_error(400);return
            os.kill(1,signal.SIGHUP)
            response=subprocess.run(['/usr/lib/postgresql/16/bin/pg_ctl','-D','/var/lib/postgresql/data','reload'],capture_output=True,timeout=30)
            payload={'reloaded':response.returncode==0}
        else:
            filename='restore_helper.py' if self.path=='/fixed-restore-helper' else 'rotation_helper.py'
            response=subprocess.run(['/opt/patroni/bin/python','/opt/prthak/'+filename],input=body,capture_output=True,timeout=60)
            payload=json.loads(response.stdout)
        data=json.dumps(payload).encode();self.send_response(200 if response.returncode==0 else 409)
        self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)


if __name__=='__main__':
    server=HTTPServer(('0.0.0.0',9009),Handler)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
    context.load_cert_chain('/config/node.pem','/config/node-key.pem');context.load_verify_locations('/config/ca.pem');context.verify_mode=ssl.CERT_REQUIRED
    server.socket=context.wrap_socket(server.socket,server_side=True);server.serve_forever()
