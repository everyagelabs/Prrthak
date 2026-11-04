"""Container bootstrap. All secrets are read from private mounted files."""
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import os
from pathlib import Path
import shutil
import ssl
import sys
import tempfile


def initialize(directory):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from urllib.parse import urlsplit
    directory = Path(directory)
    settings = json.loads((directory / 'settings.json').read_text())
    pki = directory / 'pki'
    if pki.exists():
        # An interrupted/foreign identity is never replaced merely to make an
        # installer retry appear successful.
        if pki.is_symlink() or any(not (pki/name).is_file() or (pki/name).is_symlink() for name in ('ca.pem','ca-key.pem','controller.pem','controller-key.pem')):
            raise ValueError('Existing bootstrap PKI is incomplete; preserve it for explicit recovery')
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(pki/'controller.pem',pki/'controller-key.pem')
        ca=x509.load_pem_x509_certificate((pki/'ca.pem').read_bytes())
        leaf=x509.load_pem_x509_certificate((pki/'controller.pem').read_bytes())
        leaf.verify_directly_issued_by(ca)
        if leaf.subject==leaf.issuer:raise ValueError('Bootstrap server identity must be distinct from its issuing CA')
        ca_key=serialization.load_pem_private_key((pki/'ca-key.pem').read_bytes(),password=None)
        if ca.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)!=ca_key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo):
            raise ValueError('Existing bootstrap CA and signing key do not match')
        return
    now = datetime.now(timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Prthak appliance ' + settings['node_id'])])
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-timedelta(minutes=2)).not_valid_after(now+timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False).sign(key, hashes.SHA256()))
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    sans = [x509.DNSName('localhost'), x509.DNSName(settings['node_id']), x509.IPAddress(ipaddress.ip_address('127.0.0.1')), x509.IPAddress(ipaddress.ip_address(settings['node_ip']))]
    hostname = urlsplit(settings['controller_origin']).hostname
    if hostname:
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(hostname)))
        except ValueError:
            sans.append(x509.DNSName(hostname))
    server_name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,(hostname or settings['node_id'])[:64])])
    cert = (x509.CertificateBuilder().subject_name(server_name).issuer_name(ca.subject).public_key(server_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-timedelta(minutes=2)).not_valid_after(now+timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(x509.SubjectAlternativeName(sans), False)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False).sign(key, hashes.SHA256()))
    values = {'ca.pem':ca.public_bytes(serialization.Encoding.PEM), 'controller.pem':cert.public_bytes(serialization.Encoding.PEM),
        'ca-key.pem':key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()),
        'controller-key.pem':server_key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())}
    temporary=Path(tempfile.mkdtemp(prefix='.pki-pending-',dir=directory))
    try:
        for filename, value in values.items():
            with (temporary/filename).open('wb') as output:
                os.fchmod(output.fileno(),0o600);os.fchown(output.fileno(),10001,10001)
                output.write(value);output.flush();os.fsync(output.fileno())
        os.chown(temporary,10001,10001)
        descriptor=os.open(temporary,os.O_RDONLY)
        try:os.fsync(descriptor)
        finally:os.close(descriptor)
        os.rename(temporary,pki)
        descriptor=os.open(directory,os.O_RDONLY)
        try:os.fsync(descriptor)
        finally:os.close(descriptor)
    finally:
        if temporary.exists():shutil.rmtree(temporary)


def validate_initial_environment(environment):
    # Executing this fixed script by path makes /opt/prthak sys.path[0].
    # The bundled read-only controller package is rooted at /app.
    if Path('/app/controller').is_dir():sys.path.insert(0,'/app')
    from controller.auth import EntraConfig
    from controller.management_health import PROBE_FIELDS, probe_configuration
    public=('SEG_ENTRA_TENANT_ID','SEG_ENTRA_CLIENT_ID','SEG_ENTRA_REDIRECT_URI','SEG_BOOTSTRAP_SUPER_ADMIN_OID')
    http=('SEG_HTTP_WORKERS','SEG_HTTP_THREADS')
    pool=('SEG_DB_POOL_META_MAX','SEG_DB_POOL_TRAFFIC_MAX','SEG_DB_POOL_WAIT_SECONDS','SEG_CONTROL_PORT','SEG_DISCOVERY_PORT')
    if not isinstance(environment,dict) or set(environment)-set((*public,*http,*pool,*PROBE_FIELDS,'SEG_ENTRA_CLIENT_SECRET')) or any(not isinstance(value,str) for value in environment.values()):raise ValueError('Fixed initial environment validation requires an exact string mapping')
    config=EntraConfig.from_env(environment);result={}
    if config.enabled:
        result.update(SEG_ENTRA_TENANT_ID=config.tenant_id,SEG_ENTRA_CLIENT_ID=config.client_id,SEG_ENTRA_REDIRECT_URI=config.redirect_uri,SEG_ENTRA_CLIENT_SECRET_FILE='/run/prthak-bootstrap/entra-client-secret')
        if config.bootstrap_oid:result['SEG_BOOTSTRAP_SUPER_ADMIN_OID']=config.bootstrap_oid
    for key,low,high in (('SEG_HTTP_WORKERS',1,16),('SEG_HTTP_THREADS',2,128),('SEG_DB_POOL_META_MAX',1,64),('SEG_DB_POOL_TRAFFIC_MAX',1,16),('SEG_DB_POOL_WAIT_SECONDS',1,15),('SEG_CONTROL_PORT',1,65535),('SEG_DISCOVERY_PORT',1,65535)):
        if environment.get(key):
            number=int(environment[key])
            if not low<=number<=high:raise ValueError('HTTP/database pool configuration exceeds supported bounds')
            result[key]=str(number)
    result.update(probe_configuration(environment))
    return {'validated':True,'entra_enabled':config.enabled,'environment':result}


def controller_environment(settings):
    """Load only fixed public values and private-file references, never secrets."""
    fixed={'PRTHAK_APPLIANCE','PRTHAK_APPLIANCE_NODE_ID','PRTHAK_APPLIANCE_SITE','PRTHAK_APPLIANCE_NODE_IP',
           'PRTHAK_APPLIANCE_DATA_ROOT','PRTHAK_APPLIANCE_MANAGER_SOCKET','PRTHAK_APPLIANCE_MANAGER_TOKEN_FILE',
           'PRTHAK_CLUSTER_PASSWORD_FILE','PRTHAK_EXISTING_NODE_IP','PRTHAK_GUI_PROVIDER_MANAGED','PRTHAK_PROVIDER_EPOCH'}
    public={'SEG_ENTRA_TENANT_ID','SEG_ENTRA_CLIENT_ID','SEG_ENTRA_REDIRECT_URI','SEG_BOOTSTRAP_SUPER_ADMIN_OID',
            'SEG_HTTP_WORKERS','SEG_HTTP_THREADS','SEG_DB_POOL_META_MAX','SEG_DB_POOL_TRAFFIC_MAX','SEG_DB_POOL_WAIT_SECONDS','SEG_CONTROL_PORT','SEG_DISCOVERY_PORT',
            'SEG_MANAGEMENT_PROBE_SOURCE_IP','SEG_MANAGEMENT_PROBE_TARGET_CIDRS'}
    environment=settings.get('environment')
    if not isinstance(environment,dict) or set(environment)-fixed-public-{'SEG_ENTRA_CLIENT_SECRET_FILE'} or any(not isinstance(value,str) or '\x00' in value for value in environment.values()):
        raise ValueError('Controller bootstrap environment contains an unsupported value')
    if environment.get('SEG_ENTRA_CLIENT_SECRET_FILE') not in (None,'','/run/prthak-bootstrap/entra-client-secret'):
        raise ValueError('Controller provider secrets require their fixed private mounted file')
    return dict(environment)


if __name__ == '__main__':
    if os.environ.get('PRTHAK_REQUIRE_INTEGRITY')=='1':
        import importlib.util
        spec=importlib.util.spec_from_file_location('prthak_image_integrity','/opt/prthak-integrity/runtime_verify.py')
        verifier=importlib.util.module_from_spec(spec);spec.loader.exec_module(verifier)
        verifier.verify('/app','/opt/prthak-integrity/runtime-integrity.json','/opt/prthak-integrity/public-trust.json',component='appliance')
    if len(sys.argv)==3 and sys.argv[1]=='--initialize':
        initialize(sys.argv[2])
    elif sys.argv[1:]==['--validate-initial-env']:
        try:
            raw=sys.stdin.buffer.read(65537)
            if len(raw)>65536:raise ValueError('Bounded initial environment required')
            print(json.dumps(validate_initial_environment(json.loads(raw))))
        except Exception:
            print(json.dumps({'validated':False,'error':'Initial provider/runtime configuration is invalid'}));raise SystemExit(1)
    else:
        settings=json.loads(Path('/run/prthak-bootstrap/settings.json').read_text())
        os.environ.update(controller_environment(settings))
        os.environ['SEG_SUPER_ADMIN_TOKEN']=Path('/run/prthak-bootstrap/initial-admin-token').read_text().strip()
        os.environ['PRTHAK_CONTROLLER_ORIGIN']=settings['controller_origin']
        os.execv(sys.executable,[sys.executable,'-m','controller','--listen','0.0.0.0:8787','--control-listen','0.0.0.0:8788','--discovery-listen','0.0.0.0:8789','--appliance-router-proxy','--data-dir','/data',
            '--controller-id',settings['node_id'],'--site',settings['site'],
            '--cert','/run/prthak-bootstrap/pki/controller.pem','--key','/run/prthak-bootstrap/pki/controller-key.pem',
            '--ca','/run/prthak-bootstrap/pki/ca.pem','--ca-key','/run/prthak-bootstrap/pki/ca-key.pem'])
