"""Private installer/manager tests. No host services, Docker socket or PGDATA touched."""
import copy
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch
import uuid
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('prthak_appliance_manager',ROOT/'deploy/appliance/node_manager.py')
appliance=importlib.util.module_from_spec(spec);spec.loader.exec_module(appliance)


class FakeEngine:
    def __init__(self,root,project,state):self.root,self.project,self.shared=Path(root),project,state
    def states(self):return dict(self.shared['states'])
    def foreign_bindings(self,root):return self.shared.get('foreign',[])
    def compose(self,args,timeout=180):
        self.shared['calls'].append(list(args))
        names=[value for value in args if value in appliance.SERVICES]
        if args[0]=='stop' and not self.shared.get('stuck'):
            for name in names:self.shared['states'][name]='exited'
        if args[0]=='up':
            for name in names:self.shared['states'][name]='running'
        return '[]'
    def database_helper(self,request):
        self.shared.setdefault('helper_calls',[]).append(request.copy())
        if self.shared.get('helper_failure'):raise appliance.Blocked('injected fixed helper failure')
        if request['action']=='change-role':
            if self.shared.get('not_primary'):return {'not_primary':True,'mutated':False}
            changed=self.shared['live_password']!=request['password'];self.shared['live_password']=request['password']
            return {'status':'role_changed','mutated':changed}
        if request['password']!=self.shared['live_password']:raise appliance.Blocked('new connection authentication failed')
        return {'verified':True,'new_connection':True}


class ApplianceConfigurationTests(unittest.TestCase):
    def test_offline_images_import_only_after_checksum_and_validate_amd64_ids(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            archive = directory/'images.tar.gz'
            archive.write_bytes(b'transferred images')
            images = {name:'sha256:'+str(index)*64 for index, name in enumerate(appliance.SERVICES)}
            manifest = {'images': images, 'platform': 'linux/amd64',
                        'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest()}
            appliance.atomic(directory/'images.json', manifest)
            engine = Mock()
            engine.run.side_effect = ['', *(image+' linux/amd64\n' for image in images.values())]
            self.assertEqual(appliance.offline_appliance_images(engine, directory), images)
            self.assertEqual(engine.run.call_args_list[0].args[0], ['image', 'load', '--input', str(archive)])
            self.assertTrue(all(call.args[0][:2] == ['image', 'inspect'] for call in engine.run.call_args_list[1:]))
            engine.reset_mock()
            archive.write_bytes(b'incomplete copy')
            with self.assertRaisesRegex(appliance.Blocked, 'checksum'):
                appliance.offline_appliance_images(engine, directory)
            engine.run.assert_not_called()

    def test_database_runtime_only_marks_empty_storage_and_preserves_legacy_physical_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);settings={'node_id':'test'}
            prepared=appliance.database_runtime_settings(root,settings)
            self.assertEqual(prepared['database_runtime'],appliance.DATABASE_RUNTIME)
            self.assertNotIn('database_runtime',settings)
            self.assertFalse((root/'database').exists())
            (root/'database').mkdir();(root/'database/PG_VERSION').write_bytes(b'16\n')
            with self.assertRaisesRegex(appliance.Blocked,'logical backup in GUI'):
                appliance.database_runtime_settings(root,settings)
            self.assertEqual((root/'database/PG_VERSION').read_bytes(),b'16\n')
            self.assertEqual(appliance.database_runtime_settings(root,prepared),prepared)
            with self.assertRaises(appliance.Blocked):
                appliance.database_runtime_settings(root,{**prepared,'database_runtime':'unknown-platform'})
    def test_database_runtime_rejects_a_symlink_even_with_a_current_marker(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/'foreign').mkdir();(root/'database').symlink_to(root/'foreign')
            with self.assertRaises(appliance.Blocked):
                appliance.database_runtime_settings(root,{'database_runtime':appliance.DATABASE_RUNTIME})
    def test_env_is_parsed_without_shell_and_private_values_are_not_printed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);sentinel=root/'MUST_NOT_EXIST';env=root/'.env'
            env.write_text('DATA_ROOT=/mnt/prthak-test\nNODE_ID=noida-01\nSITE=Noida\nNODE_IP=127.0.0.1\nCLUSTER_PASSWORD="$(touch '+str(sentinel)+')"\n')
            env.chmod(0o600)
            result=subprocess.run([sys.executable,str(ROOT/'deploy/appliance/node_manager.py'),'install','--release-root',str(ROOT),'--env-file',str(env),'--validate-only'],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertFalse(sentinel.exists())
            self.assertNotIn('$(touch',result.stdout)
            self.assertEqual(json.loads(result.stdout)['status'],'validated')
    def test_env_rejects_public_files_unknown_fields_duplicates_and_short_secrets(self):
        with tempfile.TemporaryDirectory() as temporary:
            env=Path(temporary)/'.env';env.write_text('NODE_ID=noida\n');env.chmod(0o644)
            with self.assertRaises(appliance.Blocked):appliance.read_env(env)
            env.chmod(0o600)
            for value in ('UNKNOWN=1\n','NODE_ID=a\nNODE_ID=b\n'):
                env.write_text(value)
                with self.assertRaises(appliance.Blocked):appliance.read_env(env)
            with self.assertRaises(appliance.Blocked):appliance.settings({'NODE_IP':'127.0.0.1','CLUSTER_PASSWORD':'short'})
    def test_storage_paths_reject_system_roots_shell_characters_traversal_and_symlinks(self):
        for value in ('/','/etc','/var/lib','/var/lib/a/../b','/mnt/a;id','relative','/home/user/data'):
            with self.subTest(path=value),self.assertRaises(appliance.Blocked):appliance.safe_path(value)
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/'real').mkdir();(root/'link').symlink_to(root/'real')
            with self.assertRaises(appliance.Blocked):appliance.safe_path(str(root/'link/data'),root)
    def test_sample_has_the_same_local_installer_for_all_sites(self):
        sample=(ROOT/'.env.example').read_text()
        for field in ('DATA_ROOT=','NODE_ID=','SITE=','NODE_IP=','CLUSTER_PASSWORD=','EXISTING_NODE_IP='):
            self.assertIn(field,sample)
        script=(ROOT/'scripts/install-controller.sh').read_text()
        self.assertNotIn('source ',script)
        self.assertIn('node_manager.py',script)


class ApplianceBootstrapIdentityTests(unittest.TestCase):
    def test_bootstrap_pki_is_atomic_and_retry_keeps_the_same_identity(self):
        spec=importlib.util.spec_from_file_location('prthak_appliance_bootstrap',ROOT/'deploy/appliance/controller_entrypoint.py')
        bootstrap=importlib.util.module_from_spec(spec);spec.loader.exec_module(bootstrap)
        with tempfile.TemporaryDirectory() as temporary,patch.object(bootstrap.os,'chown'),patch.object(bootstrap.os,'fchown'):
            root=Path(temporary);appliance.atomic(root/'settings.json',{'node_id':'test-only','node_ip':'127.0.0.1','controller_origin':'https://localhost:8787'})
            with patch.object(bootstrap.os,'rename',side_effect=OSError('interrupted commit')):
                with self.assertRaises(OSError):bootstrap.initialize(root)
            self.assertFalse((root/'pki').exists());self.assertEqual(list(root.glob('.pki-pending-*')),[])
            bootstrap.initialize(root);before={p.name:p.read_bytes() for p in (root/'pki').iterdir()}
            client_context=ssl.create_default_context(cafile=str(root/'pki/ca.pem'))
            server_context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);server_context.load_cert_chain(root/'pki/controller.pem',root/'pki/controller-key.pem')
            incoming_client,outgoing_client,incoming_server,outgoing_server=[ssl.MemoryBIO() for _ in range(4)]
            client=client_context.wrap_bio(incoming_client,outgoing_client,server_hostname='localhost')
            server=server_context.wrap_bio(incoming_server,outgoing_server,server_side=True)
            completed=set()
            for _ in range(20):
                for name,endpoint in (('client',client),('server',server)):
                    try:endpoint.do_handshake();completed.add(name)
                    except ssl.SSLWantReadError:pass
                if outgoing_client.pending:incoming_server.write(outgoing_client.read())
                if outgoing_server.pending:incoming_client.write(outgoing_server.read())
                if len(completed)==2:break
            self.assertEqual(completed,{'client','server'})
            bootstrap.initialize(root)
            self.assertEqual(before,{p.name:p.read_bytes() for p in (root/'pki').iterdir()})
            for path in (root/'pki').iterdir():self.assertEqual(path.stat().st_mode&0o777,0o600)
            (root/'pki/controller-key.pem').write_text('incomplete key')
            with self.assertRaises((ValueError,ssl.SSLError)):bootstrap.initialize(root)
            self.assertEqual((root/'pki/ca.pem').read_bytes(),before['ca.pem'])
    def test_incomplete_existing_pki_is_preserved_for_explicit_recovery(self):
        spec=importlib.util.spec_from_file_location('prthak_appliance_bootstrap_partial',ROOT/'deploy/appliance/controller_entrypoint.py')
        bootstrap=importlib.util.module_from_spec(spec);spec.loader.exec_module(bootstrap)
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);appliance.atomic(root/'settings.json',{'node_id':'test-only','node_ip':'127.0.0.1','controller_origin':'https://localhost:8787'})
            appliance.atomic(root/'pki/controller.pem','partial public certificate')
            with self.assertRaises(ValueError):bootstrap.initialize(root)
            self.assertEqual((root/'pki/controller.pem').read_text(),'partial public certificate')


class ApplianceManagerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes,serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        from datetime import datetime,timedelta,timezone
        key=ec.generate_private_key(ec.SECP256R1());name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Private installer test CA')]);now=datetime.now(timezone.utc)
        cert=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True,path_length=None),True).sign(key,hashes.SHA256())
        cls.pki={'ca':cert.public_bytes(serialization.Encoding.PEM).decode(),'certificate':cert.public_bytes(serialization.Encoding.PEM).decode(),'private_key':key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode()}
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(dir=str(Path(tempfile.gettempdir()).resolve()),prefix='prthak-app-');self.addCleanup(self.temporary.cleanup)
        self.parent=Path(self.temporary.name).resolve();self.root=self.parent/'source'
        self.root.mkdir()
        self.shared={'states':{'controller':'running','router':'running'},'calls':[]}
        self.factory=lambda root,project:FakeEngine(root,project,self.shared)
        self.chown=patch.object(appliance.os,'chown');self.fchown=patch.object(appliance.os,'fchown')
        self.chown.start();self.fchown.start();self.addCleanup(self.chown.stop);self.addCleanup(self.fchown.stop)
        self.local={'node_id':'noida-01','site':'Noida','node_ip':'10.240.0.11','bind_ip':'10.240.0.11','controller_port':8787,'controller_backend_port':8786,'database_router_port':5433,'controller_origin':'https://10.240.0.11:8787','existing_node_ip':'','appliance_id':uuid.uuid4().hex}
        appliance.private_dir(self.root/'manager/jobs');appliance.private_dir(self.root/'manager/reviews')
        appliance.atomic(self.root/'config/installed.json',self.local)
        appliance.atomic(self.root/'config/manager-token',secrets.token_urlsafe(48))
        appliance.atomic(self.root/'config/controller/pki/ca.pem','PUBLIC TEST CA')
        self.manager=appliance.Manager(self.root,self.parent/'pointer',self.factory,self.parent)
        self.manager.render()
    def partial(self):
        return {'schema_version':1,'deployment_id':str(uuid.uuid4()),'generation':1,'cluster_name':'site-cluster','controller_origin':self.local['controller_origin'],
            'local_node':{'id':self.local['node_id'],'site':'Noida','ip':self.local['node_ip'],'role':'management'},'voters':[],
            'controller_members':[{'id':self.local['node_id'],'site':'Noida','ip':self.local['node_ip']}]}
    def full(self):
        value=self.partial();value.update(pki=self.pki,secrets={key:'test-only-'+key+'A'*40 for key in ('admin','replication','metadata','traffic')},watchdog={'required':True,'approved':False},voters=[{'id':'voter-'+str(i),'site':'site-'+str(i),'ip':'10.240.1.'+str(i+1)} for i in range(3)])
        return value
    def test_initial_state_is_authenticated_setup_not_a_fake_single_node_ha_cluster(self):
        status=self.manager.status()
        self.assertFalse(status['cluster']['configured']);self.assertEqual(status['cluster']['status'],'bootstrap')
        self.assertEqual(self.manager.enabled(),['controller','router'])
        compose=json.loads((self.root/'runtime/compose.json').read_text())
        self.assertEqual(compose['services']['database']['profiles'],['database'])
        self.assertTrue(all('/var/run/docker.sock' not in json.dumps(value) for value in compose['services'].values()))
        self.assertEqual(compose['services']['controller']['user'],'10001:10001')

    def test_host_ssh_probe_enforces_local_scope_and_proves_the_actual_bound_source(self):
        source_key, target_key = appliance.PROBE_PUBLIC
        appliance.atomic(self.root/'config/controller/settings.json', {'environment': {
            source_key: '10.90.0.5', target_key: '10.40.0.0/24'}})
        request = {'source_ip': '10.90.0.5', 'target_ip': '10.40.0.21', 'ports': [2022]}
        with patch.object(appliance.socket, 'socket') as factory:
            for changes in ({'source_ip': '172.18.0.2'}, {'target_ip': '10.41.0.21'}, {'target_ip': '169.254.169.254'}, {'ports': [2022, 2022]}):
                with self.subTest(changes=changes), self.assertRaises(appliance.Blocked):
                    self.manager.management_probe({**request, **changes})
            factory.assert_not_called()
            connection = factory.return_value.__enter__.return_value
            connection.getsockname.return_value = ('10.90.0.5', 40123)
            connection.recv.side_effect = [b'SSH-2.0-OpenSSH_9\r\n']
            self.assertEqual(self.manager.management_probe(request), {'ssh_checks': [
                {'source_ip': '10.90.0.5', 'target_ip': '10.40.0.21', 'port': 2022, 'ssh_banner_verified': True}]})
            connection.bind.assert_called_once_with(('10.90.0.5', 0))
            connection.connect.assert_called_once_with(('10.40.0.21', 2022))
            connection.recv.side_effect = [b'HTTP/1.1 200 OK\r\n', b'']
            with self.assertRaisesRegex(appliance.Blocked, 'SSH protocol banner'):
                self.manager.management_probe(request)
    def test_fresh_runtime_marker_survives_restart_and_etcd_uses_recorded_immutable_image(self):
        settings=appliance.load(self.root/'config/installed.json')
        self.assertEqual(settings['database_runtime'],appliance.DATABASE_RUNTIME)
        settings['images']={'etcd':'sha256:'+'a'*64};appliance.atomic(self.root/'config/installed.json',settings)
        (self.root/'database/PG_VERSION').write_text('16\n')
        reloaded=appliance.Manager(self.root,self.parent/'pointer',self.factory,self.parent)
        reloaded.render()
        compose=json.loads((self.root/'runtime/compose.json').read_text())
        self.assertEqual(compose['services']['etcd']['image'],settings['images']['etcd'])
        self.assertEqual((self.root/'database/PG_VERSION').read_text(),'16\n')

    def test_offline_compose_uses_local_image_ids_without_pulls(self):
        settings = appliance.load(self.root/'config/installed.json')
        settings['images'] = {name:'sha256:'+str(index)*64 for index, name in enumerate(appliance.SERVICES)}
        appliance.atomic(self.root/'config/installed.json',settings)
        reloaded = appliance.Manager(self.root,self.parent/'pointer',self.factory,self.parent)
        reloaded.render()
        services = appliance.load(self.root/'runtime/compose.json')['services']
        for name, service in services.items():
            self.assertEqual(service['image'], settings['images'][name])
            self.assertEqual(service['pull_policy'], 'never')
    def test_unmarked_legacy_pgdata_blocks_render_and_start_before_any_service_action(self):
        manifest=self.full();manifest['local_node']['role']='database_voter'
        appliance.atomic(self.root/'config/manifest.json',manifest)
        (self.root/'database/PG_VERSION').write_text('16\n')
        self.manager.installed.pop('database_runtime')
        appliance.atomic(self.root/'config/installed.json',self.manager.installed)
        before=(self.root/'runtime/compose.json').read_bytes()
        with self.assertRaises(appliance.Blocked):self.manager.render()
        with self.assertRaises(appliance.Blocked):self.manager.operate('start','all')
        self.assertEqual(self.shared['calls'],[])
        self.assertEqual((self.root/'runtime/compose.json').read_bytes(),before)
        self.assertEqual((self.root/'database/PG_VERSION').read_text(),'16\n')
        self.assertTrue(any('logical backup in GUI' in item for item in self.manager.status()['blockers']))
    def test_partial_manifest_waits_without_starting_db_and_management_count_is_not_three(self):
        manifest=self.partial()
        manifest['controller_members'] += [{'id':'management-'+str(i),'site':'Pune','ip':'10.240.1.'+str(i+1)} for i in range(20)]
        result=self.manager.configure({'expected_revision':0,'configuration':manifest})
        self.assertEqual(result['status'],'waiting_for_voters')
        self.assertIsNone(self.manager.manifest());self.assertEqual(len(self.manager.status()['cluster']['nodes']),21)
        self.assertEqual(self.shared['calls'],[])
    def test_only_three_distinct_quorum_voters_are_allowed(self):
        manifest=self.partial()
        manifest['voters']=[{'id':'voter-'+str(i),'site':'same','ip':'10.240.2.'+str(i+1)} for i in range(4)]
        with self.assertRaises(appliance.Blocked):self.manager.configure({'expected_revision':0,'configuration':manifest})
        manifest['voters']=manifest['voters'][:2]
        with self.assertRaises(appliance.Blocked):self.manager.configure({'expected_revision':0,'configuration':manifest})
    def test_management_cannot_start_database_or_quorum_services(self):
        for name in ('database','etcd'):
            with self.assertRaises(appliance.Blocked):self.manager.operate('start',name)
        self.assertEqual(self.shared['calls'],[])
    def test_fixed_actions_reject_arbitrary_services_and_commands(self):
        with self.assertRaises(appliance.Blocked):self.manager.operate('restart','../../other')
        for body in ({'action':'shell','request_id':'a'*32,'command':'id'},{'action':'status','request_id':'../x'}):
            with self.assertRaises(appliance.Blocked):self.manager.submit(body)
    def test_request_id_is_durable_and_changed_payload_cannot_repeat_a_restart(self):
        body={'request_id':'a'*32,'action':'restart','service':'controller'}
        self.assertEqual(self.manager.submit(body)['id'],body['request_id'])
        self.manager.work_once();self.assertEqual(self.manager.job(body['request_id'])['status'],'completed')
        calls=len(self.shared['calls']);self.manager.submit(body);self.manager.work_once()
        self.assertEqual(len(self.shared['calls']),calls)
        reloaded=appliance.Manager(self.root,self.parent/'pointer',self.factory,self.parent)
        self.assertEqual(reloaded.submit(body)['status'],'completed')
        with self.assertRaises(appliance.Blocked):reloaded.submit({**body,'service':'all'})
    def test_private_job_payload_does_not_escape_job_response(self):
        manifest=self.partial();manifest['secrets']={'replication':'PRIVATE_SENTINEL'}
        job=self.manager.submit({'request_id':'b'*32,'action':'configure','expected_revision':0,'configuration':manifest})
        self.assertNotIn('PRIVATE_SENTINEL',json.dumps(job));self.manager.work_once()
        self.assertNotIn('PRIVATE_SENTINEL',json.dumps(self.manager.job(job['id'])))
        self.assertEqual((self.root/'manager/jobs'/job['id']).stat().st_mode&0o777,0o600)
    def test_fixed_helper_uses_stdin_and_keeps_private_password_out_of_argv(self):
        password='test-only-helper-password-'+'Q'*40
        responses=[SimpleNamespace(returncode=0,communicate=Mock(return_value=(b'a'*64+b'\n',b''))),
                   SimpleNamespace(returncode=0,communicate=Mock(return_value=(b'{"verified":true}',b'')))]
        engine=appliance.Engine(self.root,'prthak-test',docker=('/usr/bin/docker','--host','unix:///var/run/docker.sock'))
        with patch.object(appliance.subprocess,'Popen',side_effect=responses) as command:
            self.assertTrue(engine.database_helper({'action':'probe','password':password,'primary_ip':'10.240.0.11'})['verified'])
        actual=command.call_args_list[1]
        self.assertNotIn(password,' '.join(actual.args[0]));self.assertEqual(json.loads(responses[1].communicate.call_args.args[0])['password'],password)
        self.assertEqual(actual.kwargs['stdin'],subprocess.PIPE)
        self.assertTrue(actual.kwargs['start_new_session'])
        self.assertEqual(actual.args[0][-1],'/opt/prthak/rotation_helper.py')
    def test_web_tls_checks_backend_and_router_and_only_restarts_owned_router(self):
        manifest=self.full();self.manager.configure({'expected_revision':0,'configuration':manifest})
        before={str(path.relative_to(self.root)):path.read_bytes() for path in (self.root/'config/database').iterdir() if path.is_file()}
        request={'certificate_chain':self.pki['certificate'],'server_name':'new-controller.example.internal','expected_revision':1}
        with patch.object(self.manager,'_web_probe') as probe:
            result=self.manager.web_tls(request)
            self.assertTrue(result['verified']);self.assertTrue(result['router_ready']);self.assertEqual(result['revision'],2)
            self.assertEqual([call.args[2] for call in probe.call_args_list],[8786,8787])
            self.assertTrue(self.manager.web_tls(request)['already_applied'])
        self.assertEqual(self.manager.state()['revision'],2)
        self.assertTrue(all('database' not in call and 'etcd' not in call and 'controller' not in call for call in self.shared['calls']))
        self.assertEqual(before,{str(path.relative_to(self.root)):path.read_bytes() for path in (self.root/'config/database').iterdir() if path.is_file()})
        self.assertIn('verifyhost new-controller.example.internal',(self.root/'config/router/haproxy.cfg').read_text())
    def test_web_tls_failed_routed_readiness_restores_exact_old_public_files(self):
        previous={name:(self.root/'config/router'/name).read_bytes() for name in ('haproxy.cfg','controller-ca.pem')}
        def probe(chain,name,port,fingerprint):
            if port==8787:raise appliance.Blocked('injected router failure')
        with patch.object(self.manager,'_web_probe',side_effect=probe),patch.object(appliance.time,'sleep'):
            with self.assertRaises(appliance.Blocked):self.manager.web_tls({'certificate_chain':self.pki['certificate'],'server_name':'new-controller.example.internal','expected_revision':0})
        self.assertFalse((self.root/'config/web-tls.json').exists())
        self.assertEqual(previous,{name:(self.root/'config/router'/name).read_bytes() for name in previous})
        self.assertEqual(appliance.load(self.root/'manager/web-tls-transaction.json')['phase'],'rolled_back')
        self.assertEqual(self.manager.state()['revision'],0)
    def test_web_tls_rejects_private_keys_and_recovers_interrupted_public_only_update(self):
        with self.assertRaises(appliance.Blocked):self.manager.web_tls({'certificate_chain':self.pki['private_key'],'server_name':'example.test','expected_revision':0})
        previous={name:(self.root/'config/router'/name).read_text() for name in ('haproxy.cfg','controller-ca.pem')}
        appliance.atomic(self.root/'manager/web-tls-transaction.json',{'phase':'started','previous_override':None,'previous_files':previous,'router_running':True})
        appliance.atomic(self.root/'config/router/haproxy.cfg','incomplete public update')
        self.manager.recover_web_tls()
        self.assertEqual((self.root/'config/router/haproxy.cfg').read_text(),previous['haproxy.cfg'])
        self.assertEqual(self.shared['calls'][-1],['up','-d','--no-deps','--force-recreate','router'])
    def test_software_watchdog_is_refused_even_when_operator_approved(self):
        manifest=self.full();manifest['watchdog']['approved']=True;appliance.atomic(self.root/'config/manifest.json',manifest)
        real_path=appliance.Path
        def path(value):
            if str(value)=='/dev/watchdog0':return SimpleNamespace(stat=lambda:SimpleNamespace(st_mode=0o020600,st_rdev=os.makedev(10,130)))
            known={'/sys/class/watchdog/watchdog0/dev':'10:130','/sys/class/watchdog/watchdog0/identity':'Software Watchdog','/sys/class/watchdog/watchdog0/state':'inactive'}
            if str(value) in known:return SimpleNamespace(read_text=lambda:known[str(value)])
            return real_path(value)
        with patch.object(appliance,'Path',side_effect=path),patch.object(appliance.os,'chmod') as permission:
            with self.assertRaises(appliance.Blocked):self.manager._watchdog()
            permission.assert_not_called()
    def test_interrupted_job_is_not_replayed_as_a_second_mutation(self):
        body={'request_id':'d'*32,'action':'restart','service':'controller'}
        self.manager.submit(body)
        path=self.root/'manager/jobs'/body['request_id'];record=appliance.load(path);record['status']='running';appliance.atomic(path,record)
        restarted=appliance.Manager(self.root,self.parent/'pointer',self.factory,self.parent)
        self.assertEqual(restarted.submit(body)['phase'],'interrupted')
        self.assertFalse(restarted.work_once());self.assertEqual(self.shared['calls'],[])
    def test_routing_preferences_select_an_enrolled_backend_and_unknown_targets_block(self):
        manifest=self.full();manifest['controller_members'].append({'id':'pune-01','site':'Pune','ip':'10.240.0.12'})
        manifest['preferred_controller_url']='https://10.240.0.12:8787';manifest['fallback_controller_url']=self.local['controller_origin']
        manifest=appliance.validate_manifest(manifest,self.local)
        self.manager.configure({'expected_revision':0,'configuration':manifest})
        lines=(self.root/'config/router/haproxy.cfg').read_text().splitlines()
        preferred=next(line for line in lines if ' server pune-01 ' in line);fallback=next(line for line in lines if ' server local ' in line)
        self.assertNotIn(' backup',preferred);self.assertIn(' backup',fallback)
        self.assertLess(lines.index(preferred),lines.index(fallback))
        manifest['preferred_controller_url']='https://10.240.0.99:8787'
        with self.assertRaises(appliance.Blocked):appliance.validate_manifest(manifest,self.local)
    def test_interrupted_full_configuration_blocks_start_and_recovers_only_owned_previous_state(self):
        manifest=self.full();render=self.manager.render
        def interrupted():
            appliance.atomic(self.root/'config/router/haproxy.cfg','interrupted fixture')
            raise OSError('simulated storage interruption')
        with patch.object(self.manager,'render',side_effect=interrupted):
            with self.assertRaises(OSError):self.manager.configure({'expected_revision':0,'configuration':manifest})
        self.assertTrue(self.manager.state()['configuration_pending'])
        with self.assertRaises(appliance.Blocked):self.manager.operate('start','controller')
        resumed=appliance.Manager(self.root,self.parent/'pointer',self.factory,self.parent)
        result=resumed.configure({'expected_revision':0,'configuration':manifest})
        self.assertEqual(result['status'],'configured');self.assertFalse(resumed.state()['configuration_pending'])
        self.assertEqual(resumed.manifest()['deployment_id'],manifest['deployment_id'])
    def test_replication_password_change_is_explicitly_pending_not_falsely_applied(self):
        manifest=self.full();self.manager.configure({'expected_revision':0,'configuration':manifest})
        changed=copy.deepcopy(manifest);changed['generation']=2;changed['secrets']['replication']='new-test-only-'+'B'*40
        with self.assertRaises(appliance.Blocked):self.manager.configure({'expected_revision':1,'configuration':changed})
        self.assertEqual(self.manager.manifest()['secrets']['replication'],manifest['secrets']['replication'])
        self.assertIn('replication_password',self.manager.status()['pending_changes'])
    def test_cluster_display_rename_does_not_change_patroni_scope_or_namespace(self):
        manifest=appliance.validate_manifest(self.full(),self.local)
        original=appliance.render_patroni(manifest);manifest['cluster_name']='Renamed display only'
        renamed=appliance.render_patroni(manifest)
        self.assertEqual(original['scope'],renamed['scope']);self.assertEqual(original['namespace'],renamed['namespace'])
        self.assertEqual(original['scope'],'prthak-'+manifest['deployment_id'])
    def test_owned_docker_subnet_is_allowed_only_for_application_roles(self):
        manifest=appliance.validate_manifest(self.full(),self.local)
        hba=appliance.render_patroni(manifest,['172.28.0.0/16'])['postgresql']['pg_hba']
        local=[line for line in hba if '172.28.0.0/16' in line]
        self.assertEqual(len(local),2)
        self.assertTrue(all('prthak_metadata' in line or 'prthak_traffic' in line for line in local))
        self.assertFalse(any('prthak_admin' in line or 'replication' in line for line in local))
    def test_observed_health_requires_one_writer_sync_replica_and_fresh_quorum(self):
        manifest=appliance.validate_manifest(self.full(),self.local);appliance.atomic(self.root/'config/manifest.json',manifest)
        def peer(address,port,path):
            if port==2379:return {'health':'true'}
            self.assertEqual(path,'/health')
            return {'state':'running','role':'primary' if address==manifest['voters'][0]['ip'] else 'replica','replication':[{'state':'streaming','sync_state':'sync'}]}
        with patch.object(self.manager,'_peer_json',side_effect=peer):self.manager.refresh_health()
        self.assertTrue(self.manager.status()['health']['database_ready'])
        self.manager.health_snapshot['checked_at']-=60
        self.assertFalse(self.manager.status()['health']['database_ready'])
        with patch.object(self.manager,'_peer_json',side_effect=lambda address,port,path:{'health':'true'} if port==2379 else {'state':'running','role':'primary','replication':[]}):self.manager.refresh_health()
        self.assertFalse(self.manager.status()['health']['database_ready'])
    def test_initial_database_start_requires_all_voters_but_existing_data_needs_majority(self):
        manifest=appliance.validate_manifest(self.full(),self.local);appliance.atomic(self.root/'config/manifest.json',manifest)
        def peer(address,port,path):
            if address==manifest['voters'][2]['ip']:raise OSError('test site down')
            return {'health':'true'}
        with patch.object(self.manager,'_peer_json',side_effect=peer):
            with self.assertRaises(appliance.Blocked):self.manager._quorum()
            appliance.atomic(self.root/'database/PG_VERSION','16')
            self.manager._quorum()
        with patch.object(self.manager,'_peer_json',side_effect=OSError('no quorum')):
            with self.assertRaises(appliance.Blocked):self.manager._quorum()

    def rotation_fixture(self):
        manifest=self.full();manifest['local_node']['role']='database_voter';manifest['voters'][0]={'id':self.local['node_id'],'site':'Noida','ip':self.local['node_ip']}
        self.manager.configure({'expected_revision':0,'configuration':manifest})
        self.shared['live_password']=manifest['secrets']['replication']
        def refresh():
            self.manager.health_snapshot={'status':'observed','checked_at':time.time(),'quorum_healthy':True,'all_voters_healthy':True,'database_ready':True,'primary_count':1,'nodes':[{'id':peer['id'],'ip':peer['ip'],'postgres_running':True,'role':'primary' if index==0 else 'replica','etcd_healthy':True} for index,peer in enumerate(manifest['voters'])]}
        self.manager.refresh_health=refresh;self.manager._reload_patroni=lambda:self.shared.setdefault('reloads',[]).append(True)
        return {'rotation_id':'e'*32,'password':'new-test-password-'+'N'*40,'expected_revision':1,'phase':'prepare'}
    def test_rotation_requires_real_new_auth_and_global_barrier_before_finalizing(self):
        prepare=self.rotation_fixture();old=self.shared['live_password']
        self.assertTrue(self.manager.rotate_replication(prepare)['prepared'])
        self.assertEqual(self.shared['live_password'],old)
        self.assertEqual(appliance.load(self.root/'config/database/patroni.json')['postgresql']['authentication']['replication']['password'],prepare['password'])
        with self.assertRaises(appliance.Blocked):self.manager.rotate_replication({**prepare,'phase':'reload'})
        self.assertTrue(self.manager.rotate_replication({**prepare,'phase':'change-role'})['role_change_ack'])
        self.assertTrue(self.manager.rotate_replication({**prepare,'phase':'reload'})['reload_ack'])
        self.assertTrue(self.manager.rotate_replication({**prepare,'phase':'verify'})['new_connection'])
        with self.assertRaises(appliance.Blocked):self.manager.rotate_replication({**prepare,'phase':'finalize'})
        result=self.manager.rotate_replication({**prepare,'phase':'finalize','all_voters_verified':True})
        self.assertEqual(result['phase'],'finalized');self.assertEqual(self.manager.state()['revision'],2)
        self.assertEqual(self.manager.manifest()['secrets']['replication'],prepare['password'])
        self.assertNotIn(prepare['password'],json.dumps(result))
        self.assertTrue(self.manager.rotate_replication({**prepare,'phase':'finalize','all_voters_verified':True})['verified'])
        self.assertEqual(self.manager.state()['revision'],2)
    def test_rotation_holds_role_change_intent_and_retries_forward_after_unknown_sql_result(self):
        prepare=self.rotation_fixture();self.manager.rotate_replication(prepare);self.shared['helper_failure']=True
        with self.assertRaises(appliance.Blocked):self.manager.rotate_replication({**prepare,'phase':'change-role'})
        record=appliance.load(self.root/'manager/rotation.json');self.assertTrue(record['role_change_intent']);self.assertEqual(record['phase'],'role_change_started')
        with self.assertRaises(appliance.Blocked):self.manager.rotate_replication({**prepare,'phase':'abort'})
        self.shared['helper_failure']=False
        self.assertTrue(self.manager.rotate_replication({**prepare,'phase':'change-role'})['role_change_ack'])
    def test_rotation_abort_proves_old_auth_and_staged_rotation_blocks_other_mutations(self):
        prepare=self.rotation_fixture();self.manager.rotate_replication(prepare)
        with self.assertRaises(appliance.Blocked):self.manager.configure({'expected_revision':1,'configuration':self.manager.manifest()})
        with self.assertRaises(appliance.Blocked):self.manager.storage_review({'data_root':str(self.parent/'target')})
        self.shared['live_password']=prepare['password']
        with self.assertRaises(appliance.Blocked):self.manager.rotate_replication({**prepare,'phase':'abort'})
        self.shared['live_password']=self.manager.manifest()['secrets']['replication']
        self.assertEqual(self.manager.rotate_replication({**prepare,'phase':'abort'})['phase'],'aborted')
        self.assertEqual(appliance.load(self.root/'config/database/patroni.json')['postgresql']['authentication']['replication']['password'],self.shared['live_password'])
    def test_rotation_recovers_prepare_and_reload_write_interruptions_without_claiming_success(self):
        prepare=self.rotation_fixture();original=appliance.atomic
        def fail_staging(path,value,*args,**kwargs):
            if str(path).endswith('/database/patroni.json'):raise OSError('staging disk full')
            return original(path,value,*args,**kwargs)
        with patch.object(appliance,'atomic',side_effect=fail_staging):
            with self.assertRaises(OSError):self.manager.rotate_replication(prepare)
        self.assertEqual(appliance.load(self.root/'manager/rotation.json')['phase'],'prepare_started')
        self.assertEqual(self.manager.rotate_replication(prepare)['phase'],'prepared')
        self.manager.rotate_replication({**prepare,'phase':'change-role'})
        def fail_reloaded(path,value,*args,**kwargs):
            if str(path).endswith('/manager/rotation.json') and value.get('phase')=='reloaded':raise OSError('reload receipt interrupted')
            return original(path,value,*args,**kwargs)
        with patch.object(appliance,'atomic',side_effect=fail_reloaded):
            with self.assertRaises(OSError):self.manager.rotate_replication({**prepare,'phase':'reload'})
        self.assertEqual(appliance.load(self.root/'manager/rotation.json')['phase'],'reload_started')
        self.assertEqual(self.manager.rotate_replication({**prepare,'phase':'reload'})['phase'],'reloaded')
        self.manager.rotate_replication({**prepare,'phase':'verify'})
        def fail_final_receipt(path,value,*args,**kwargs):
            if str(path).endswith('/manager/rotation.json') and value.get('phase')=='finalized':raise OSError('final receipt interrupted')
            return original(path,value,*args,**kwargs)
        with patch.object(appliance,'atomic',side_effect=fail_final_receipt):
            with self.assertRaises(OSError):self.manager.rotate_replication({**prepare,'phase':'finalize','all_voters_verified':True})
        self.assertEqual(self.manager.state()['revision'],2)
        self.assertEqual(self.manager.rotate_replication({**prepare,'phase':'finalize','all_voters_verified':True})['phase'],'finalized')
        self.assertEqual(self.manager.state()['revision'],2)
    def test_rotation_role_race_does_not_ack_change_and_terminal_ids_cannot_replay(self):
        prepare=self.rotation_fixture();self.manager.rotate_replication(prepare);self.shared['not_primary']=True
        result=self.manager.rotate_replication({**prepare,'phase':'change-role'})
        self.assertTrue(result['not_primary']);self.assertNotIn('role_change_ack',result)
        self.shared['not_primary']=False
        for phase in ('change-role','reload','verify'):self.manager.rotate_replication({**prepare,'phase':phase})
        self.manager.rotate_replication({**prepare,'phase':'finalize','all_voters_verified':True})
        next_prepare={**prepare,'rotation_id':'f'*32,'password':'second-test-only-'+'R'*40,'expected_revision':2}
        self.manager.rotate_replication(next_prepare);calls=len(self.shared['helper_calls'])
        self.assertEqual(self.manager.rotate_replication(prepare)['phase'],'finalized')
        self.assertEqual(len(self.shared['helper_calls']),calls)
        with self.assertRaises(appliance.Blocked):self.manager.rotate_replication({**prepare,'password':'wrong-reuse-test-'+'Z'*40})
    def test_unknown_rotation_abort_tombstone_blocks_delayed_prepare_without_changing_active_plan(self):
        prepare=self.rotation_fixture();self.manager.rotate_replication(prepare)
        unknown={**prepare,'rotation_id':'0'*32,'phase':'abort'}
        self.assertEqual(self.manager.rotate_replication(unknown)['phase'],'aborted')
        self.assertEqual(appliance.load(self.root/'manager/rotation.json')['id'],prepare['rotation_id'])
        delayed=self.manager.rotate_replication({**unknown,'phase':'prepare'})
        self.assertEqual(delayed['phase'],'aborted');self.assertNotIn('prepared',delayed)
    def test_missing_native_watchdog_and_incomplete_existing_quorum_fail_closed(self):
        manifest=self.full();manifest['local_node']['role']='database_voter';manifest['voters'][0]={'id':self.local['node_id'],'site':'Noida','ip':self.local['node_ip']}
        self.manager.configure({'expected_revision':0,'configuration':manifest})
        with self.assertRaises(appliance.Blocked):self.manager.operate('start','database')
        self.assertFalse(any('database' in call for call in self.shared['calls']))
        changed=copy.deepcopy(manifest);changed['generation']=2;changed['voters']=changed['voters'][:2]
        with self.assertRaises(appliance.Blocked):self.manager.configure({'expected_revision':1,'configuration':changed})
    def test_storage_move_stops_and_verifies_all_owned_services_before_copy(self):
        appliance.atomic(self.root/'controller/inventory.sqlite3','STOPPED DATABASE FIXTURE')
        target=self.parent/'new-storage';target.mkdir()
        review=self.manager.storage_review({'data_root':str(target)})
        result=self.manager.storage_move(review)
        self.assertEqual(result['phase'],'storage_committed')
        self.assertEqual((target/'controller/inventory.sqlite3').read_text(),'STOPPED DATABASE FIXTURE')
        self.assertEqual((self.root/'controller/inventory.sqlite3').read_text(),'STOPPED DATABASE FIXTURE')
        self.assertEqual((self.parent/'pointer').read_text().strip(),str(target))
        self.assertEqual(self.shared['calls'][0][0],'stop')
        self.assertIn('--force-recreate',self.shared['calls'][-1])
        with self.assertRaises(appliance.Blocked):appliance.Manager(self.root,self.parent/'pointer',self.factory,self.parent)
    def test_running_or_foreign_writers_block_storage_copy(self):
        target=self.parent/'target'
        self.shared['foreign']=['foreign-container']
        with self.assertRaises(appliance.Blocked):self.manager.storage_review({'data_root':str(target)})
        self.shared['foreign']=[];review=self.manager.storage_review({'data_root':str(target)})
        self.shared['stuck']=True
        with self.assertRaises(appliance.Blocked):self.manager.storage_move(review)
        self.assertFalse(target.exists());self.assertFalse((self.parent/'pointer').exists())
    def test_copy_failure_preserves_source_pointer_and_restarts_previous_services(self):
        appliance.atomic(self.root/'controller/data','KEEP')
        target=self.parent/'target';review=self.manager.storage_review({'data_root':str(target)})
        with patch.object(appliance.shutil,'copytree',side_effect=OSError('disk full')):
            with self.assertRaises(OSError):self.manager.storage_move(review)
        self.assertEqual((self.root/'controller/data').read_text(),'KEEP')
        self.assertFalse((self.parent/'pointer').exists())
        self.assertEqual(self.shared['states']['controller'],'running')
    def test_failure_after_storage_pointer_commit_cannot_restart_old_source(self):
        appliance.atomic(self.root/'controller/data','VERIFIED FIXTURE')
        target=self.parent/'after-commit';review=self.manager.storage_review({'data_root':str(target)})
        with patch.object(self.manager,'render',side_effect=OSError('post-commit service configuration interrupted')):
            with self.assertRaises(OSError):self.manager.storage_move(review)
        self.assertEqual(self.manager.root,target)
        self.assertEqual((self.parent/'pointer').read_text().strip(),str(target))
        self.assertEqual((target/'controller/data').read_text(),'VERIFIED FIXTURE')
        self.assertEqual(self.shared['states']['controller'],'exited')
        with self.assertRaises(appliance.Blocked):appliance.Manager(self.root,self.parent/'pointer',self.factory,self.parent)
        recovered=appliance.Manager(target,self.parent/'pointer',self.factory,self.parent)
        self.assertEqual(recovered.root,target)
    def test_storage_move_rejects_external_links_and_stale_review(self):
        target=self.parent/'target';review=self.manager.storage_review({'data_root':str(target)})
        (self.root/'controller/external').symlink_to('/etc/passwd')
        with self.assertRaises(appliance.Blocked):self.manager.storage_move(review)
        self.assertFalse(target.exists())
        (self.root/'controller/external').unlink()
        with self.assertRaises(appliance.Blocked):self.manager.storage_move({**review,'confirmation_nonce':'wrong'})
    def test_unix_socket_authentication_and_job_protocol_are_real(self):
        run=self.parent/'run';servers=[];ready=threading.Event()
        def started(server):servers.append(server);ready.set()
        identity=patch.object(appliance,'controller_identity');identity.start();self.addCleanup(identity.stop)
        thread=threading.Thread(target=appliance.serve,args=(self.manager,run,started),kwargs={'_test_peer_uid':lambda connection:10001},daemon=True);thread.start()
        self.assertTrue(ready.wait(3))
        def request(path,token=None,body=None):
            connection=http.client.HTTPConnection('localhost')
            connection.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);connection.sock.connect(str(run/'manager.sock'))
            headers={'Content-Type':'application/json'}
            if token:headers['Authorization']='Bearer '+token
            connection.request('POST' if body else 'GET',path,json.dumps(body).encode() if body else None,headers)
            reply=connection.getresponse();data=json.loads(reply.read());connection.close();return reply.status,data
        try:
            self.assertEqual(request('/v1/status')[0],403)
            token=(self.root/'config/manager-token').read_text()
            self.assertEqual(request('/v1/status',token)[0],200)
            status,job=request('/v1/jobs',token,{'request_id':'c'*32,'action':'status'})
            self.assertEqual(status,202);self.assertEqual(job['id'],'c'*32)
            self.assertEqual((run/'manager.sock').stat().st_mode&0o777,0o660)
        finally:
            servers[0].shutdown();servers[0].server_close();thread.join(3)


if __name__=='__main__':unittest.main()
