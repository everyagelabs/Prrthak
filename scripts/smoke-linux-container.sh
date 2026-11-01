#!/bin/sh
# Disposable Linux discovery/mTLS smoke. Needs Docker and the built Linux agents.
# No host credentials/project state are mounted. No host ports/network/capabilities.
set -eu
PROFILE=${1:-ubuntu}
case "$PROFILE" in ubuntu|ubuntu26|ubi9) ;; *) echo 'Usage: smoke-linux-container.sh ubuntu|ubuntu26|ubi9' >&2; exit 2 ;; esac
PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export PROJECT_ROOT PROFILE
exec "${PYTHON:-python3}" - <<'PY'
import json, os, pathlib, shutil, subprocess, sys, time
root=pathlib.Path(os.environ['PROJECT_ROOT'])
profile=os.environ['PROFILE']
work=root/'.local/linux-smoke'
public=work/'public'
(public/'controller').mkdir(parents=True,exist_ok=True)
(public/'agent').mkdir(exist_ok=True)
for directory in (public,public/'controller',public/'agent'): directory.chmod(0o755)
for source in (root/'controller').glob('*.py'):
 target=public/'controller'/source.name
 shutil.copyfile(source,target);target.chmod(0o644)
for architecture in ('amd64','arm64'):
 source=root/'agent/bin'/('seg-agent-linux-'+architecture)
 if not source.is_file(): raise SystemExit('Build Linux agent binaries first: make build-agent')
 target=public/'agent'/source.name
 shutil.copyfile(source,target);target.chmod(0o755)
runner=public/'run-smoke.py'
runner.write_text(r'''
import json, os, pathlib, platform, secrets, socket, ssl, subprocess, sys, tempfile, threading, time
sys.path.insert(0,'/public')
from controller.app import App, Server
from controller.pki import Signer, init_ca
from controller.store import Store
assert os.geteuid()!=0, 'Smoke runtime must be unprivileged'
with tempfile.TemporaryDirectory(prefix='prthak-linux-smoke-') as temp:
 root=pathlib.Path(temp)
 subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(root/'ssh_host_ed25519_key')],check=True,capture_output=True,timeout=10)
 sshconfig=root/'sshd_config'
 sshconfig.write_text('Port 2022\nListenAddress 127.0.0.1\nHostKey '+str(root/'ssh_host_ed25519_key')+'\nPidFile '+str(root/'sshd.pid')+'\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication no\nPermitRootLogin no\nLogLevel ERROR\n')
 ssh=subprocess.Popen(['/usr/sbin/sshd','-D','-e','-f',str(sshconfig)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
 app=None;server=None
 try:
  deadline=time.monotonic()+8
  while True:
   if ssh.poll() is not None: raise RuntimeError('Disposable sshd failed: '+ssh.stderr.read())
   try:
    with socket.create_connection(('127.0.0.1',2022),timeout=.2): pass
    break
   except OSError:
    if time.monotonic()>deadline: raise RuntimeError('sshd2022 did not start')
    time.sleep(.1)
  pki=init_ca(root/'controller-state')
  store=Store(root/'db')
  app=App(store,signer=Signer(pki/'ca.pem',pki/'ca-key.pem'),tokens={'admin':secrets.token_urlsafe(40)})
  server=Server(('127.0.0.1',8787),app)
  tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.minimum_version=ssl.TLSVersion.TLSv1_2
  tls.load_cert_chain(pki/'controller.pem',pki/'controller-key.pem');tls.load_verify_locations(pki/'ca.pem');tls.verify_mode=ssl.CERT_OPTIONAL
  server.socket=tls.wrap_socket(server.socket,server_side=True,do_handshake_on_connect=False)
  thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();app.start_jobs()
  token=store.create_token('linux-container-smoke','smoke-admin')
  tokenfile=root/'enrollment.token';tokenfile.write_text(token['token']);tokenfile.chmod(0o600)
  state=root/'endpoint'
  config=root/'agent.json';config.write_text(json.dumps({'controller_url':'https://localhost:8787','state_dir':str(state),'ca_cert':str(pki/'ca.pem'),'enrollment_token_file':str(tokenfile),'interval_seconds':60,'discovery_interval_seconds':900}))
  architecture={'aarch64':'arm64','arm64':'arm64','x86_64':'amd64','amd64':'amd64'}[platform.machine()]
  binary='/public/agent/seg-agent-linux-'+architecture
  for run in range(2):
   result=subprocess.run([binary,'--config',str(config),'--once'],capture_output=True,text=True,timeout=30)
   if result.returncode: raise RuntimeError('Agent failed: '+result.stderr)
   servers=store.servers();assert len(servers)==1, 'Enrollment duplicated inventory'
  row=servers[0]
  sshlisteners=[item for item in row['listeners'] if item['port']==2022 and item['protocol']=='tcp']
  assert sshlisteners, 'Actual SSH listener2022 missing from ss discovery'
  listener=sshlisteners[0]
  assert listener.get('service','').lower()=='ssh', 'SSH2022 process identity missing: '+repr(listener)
  assert listener.get('pid',0)>0 and 'sshd' in listener.get('process',''), 'Owning process/PID missing'
  assert row['apply_status']=='preview' and row['applied_version']==0, 'Preview boundary changed'
  assert (state/'agent.crt').is_file(), 'mTLS enrollment did not persist certificate'
  print(json.dumps({'result':'PASS','os':row.get('os'),'os_version':row.get('os_version'),'architecture':architecture,'runtime_uid':os.geteuid(),'server_count':len(servers),'ssh_port':2022,'service':listener['service'],'process':listener['process'],'pid':listener['pid'],'mTLS':'enrolled','second_start_reuses_identity':True,'policy_state':row['apply_status'],'firewalld_state':row.get('firewalld_state'),'discovery_interval_seconds':row.get('discovery_interval_seconds')},sort_keys=True),flush=True)
 finally:
  if app: app.stop.set()
  if server: server.shutdown();server.server_close()
  ssh.terminate()
  try:ssh.wait(timeout=3)
  except subprocess.TimeoutExpired:ssh.kill();ssh.wait()
'''.lstrip())
runner.chmod(0o644)
if profile in ('ubuntu','ubuntu26'):
 base='ubuntu:26.04' if profile=='ubuntu26' else 'ubuntu:24.04';python='/usr/bin/python3'
 install='RUN apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=20 update && DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=20 install -y --no-install-recommends python3 python3-cryptography openssl iproute2 openssh-server ca-certificates && rm -rf /var/lib/apt/lists/* && mkdir -p /run/sshd'
else:
 base='registry.access.redhat.com/ubi9/ubi:latest';python='/usr/bin/python3.11'
 install='RUN dnf --setopt=timeout=20 --setopt=retries=0 -y install python3.11 openssl iproute openssh-server && dnf clean all && mkdir -p /run/sshd'
dockerfile=work/('Dockerfile.'+profile)
dockerfile.write_text('FROM '+base+'\n'+install+'\nUSER 65534:65534\nWORKDIR /tmp\nENV PYTHONDONTWRITEBYTECODE=1\n')
image='prthak-linux-smoke:'+profile
name='prthak-linux-smoke-'+profile+'-'+str(os.getpid())
deadline=time.monotonic()+180
try:
 subprocess.run(['docker','build','--progress=plain','-f',str(dockerfile),'-t',image,str(public)],check=True,timeout=min(130,max(1,deadline-time.monotonic())))
 subprocess.run(['docker','run','--rm','--name',name,'--network','none','--read-only','--user','65534:65534','--cap-drop','ALL','--security-opt','no-new-privileges','--tmpfs','/tmp:rw,nosuid,size=64m,mode=1777','-v',str(public)+':/public:ro',image,python,'/public/run-smoke.py'],check=True,timeout=min(90,max(1,deadline-time.monotonic())))
except subprocess.TimeoutExpired:
 print('BOUNDED SMOKE INCOMPLETE: package/build/runtime time limit reached',file=sys.stderr);sys.exit(2)
finally:
 subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
PY
