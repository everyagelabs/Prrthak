"""Unix peer and dedicated-account guards; no real account/Docker changes."""
import http.client
import json
import os
import socket
import stat
import struct
import sys
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import test_appliance_installer as baseline

m = baseline.appliance


def user(name=m.CONTROLLER_ACCOUNT, uid=10001, gid=10001, home='/nonexistent', shell='/usr/sbin/nologin'):
    return SimpleNamespace(pw_name=name, pw_uid=uid, pw_gid=gid, pw_dir=home, pw_shell=shell)


def group(name=m.CONTROLLER_ACCOUNT, gid=10001, members=()):
    return SimpleNamespace(gr_name=name, gr_gid=gid, gr_mem=list(members))


class DedicatedAccountTests(unittest.TestCase):
    def test_missing_reservation_blocks_startup_without_creating_host_accounts(self):
        with patch.object(m, '_account_snapshot', return_value=([], [])), patch.object(m, '_account_command') as command:
            with self.assertRaisesRegex(m.Blocked, 'rerun the reviewed installer'):
                m.controller_identity()
            command.assert_not_called()

    def test_foreign_ids_aliases_supplemental_and_primary_members_are_rejected(self):
        cases = [
            ([user('unrelated-service')], []),
            ([], [group('unrelated-group')]),
            ([user(), user('primary-member', uid=12345)], [group()]),
            ([user()], [group(members=('other-user',))]),
            ([user(uid=12345)], [group()]),
            ([user(gid=12345)], [group()]),
            ([user()], [group(gid=12345)]),
            ([user(), user('uid-alias', gid=12345)], [group()]),
            ([user()], [group(), group('gid-alias')]),
        ]
        for users, groups in cases:
            with self.subTest(users=users, groups=groups), patch.object(m, '_account_snapshot', return_value=(users, groups)), patch.object(m, '_locked_controller_password', return_value=True), patch.object(m, '_account_command') as command:
                with self.assertRaises(m.Blocked):m.controller_identity(create=True)
                command.assert_not_called()

    def test_existing_dedicated_account_requires_locked_password_and_no_login_home(self):
        with patch.object(m, '_account_snapshot', return_value=([user()], [group()])), patch.object(m, '_locked_controller_password', return_value=True), patch.object(m, '_account_command') as command:
            m.controller_identity();m.controller_identity(create=True);command.assert_not_called()
        for candidate, locked in [(user(shell='/bin/bash'), True), (user(home='/home/operator'), True), (user(), False)]:
            with self.subTest(candidate=candidate, locked=locked), patch.object(m, '_account_snapshot', return_value=([candidate], [group()])), patch.object(m, '_locked_controller_password', return_value=locked):
                with self.assertRaises(m.Blocked):m.controller_identity()

    def test_linux_installer_reserves_only_fixed_locked_identity_then_rechecks(self):
        users, groups, calls = [], [], []
        def command(arguments):
            calls.append(arguments)
            if arguments[0].endswith('/groupadd'):groups.append(group())
            elif arguments[0].endswith('/useradd'):users.append(user())
            else:self.fail('Unexpected account command')
        with patch.object(m, '_account_snapshot', side_effect=lambda:(list(users), list(groups))), patch.object(m, '_locked_controller_password', return_value=True), patch.object(m, '_fixed_account_tool', side_effect=lambda name:'/usr/sbin/'+name), patch.object(m, '_account_command', side_effect=command), patch.object(m.os, 'geteuid', return_value=0), patch.object(m.sys, 'platform', 'linux'):
            m.controller_identity(create=True)
        self.assertEqual(calls, [
            ['/usr/sbin/groupadd', '--system', '--gid', '10001', 'prthak-controller'],
            ['/usr/sbin/useradd', '--system', '--uid', '10001', '--gid', '10001', '--no-create-home', '--home-dir', '/nonexistent', '--shell', '/usr/sbin/nologin', '--password', '!', 'prthak-controller'],
        ])

    def test_partial_reservation_resumes_but_a_failed_postcondition_stays_blocked(self):
        snapshots = [([], [group()]), ([user()], [group()])]
        with patch.object(m, '_account_snapshot', side_effect=snapshots), patch.object(m, '_locked_controller_password', return_value=True), patch.object(m, '_fixed_account_tool', side_effect=lambda name:'/usr/sbin/'+name), patch.object(m, '_account_command') as command, patch.object(m.os, 'geteuid', return_value=0), patch.object(m.sys, 'platform', 'linux'):
            m.controller_identity(create=True)
            self.assertEqual(command.call_count, 1);self.assertTrue(command.call_args.args[0][0].endswith('/useradd'))
        with patch.object(m, '_account_snapshot', return_value=([], [])), patch.object(m, '_fixed_account_tool', side_effect=lambda name:'/usr/sbin/'+name), patch.object(m, '_account_command'), patch.object(m.os, 'geteuid', return_value=0), patch.object(m.sys, 'platform', 'linux'):
            with self.assertRaisesRegex(m.Blocked, 'did not verify'):m.controller_identity(create=True)

    def test_reservation_cannot_modify_mac_or_nonroot_accounts(self):
        for platform, uid in [('darwin', 0), ('linux', 501)]:
            with self.subTest(platform=platform, uid=uid), patch.object(m, '_account_snapshot', return_value=([], [])), patch.object(m.os, 'geteuid', return_value=uid), patch.object(m.sys, 'platform', platform), patch.object(m, '_account_command') as command:
                with self.assertRaises(m.Blocked):m.controller_identity(create=True)
                command.assert_not_called()

    def test_fixed_account_commands_do_not_inherit_a_caller_environment_or_shell(self):
        with patch.dict(os.environ, {'LD_PRELOAD':'/untrusted/library', 'PYTHONPATH':'/untrusted'}), patch.object(m.subprocess, 'run', return_value=SimpleNamespace(returncode=0)) as run:
            m._account_command(['/usr/sbin/groupadd', '--system', '--gid', '10001', m.CONTROLLER_ACCOUNT])
        _, options = run.call_args
        self.assertNotIn('LD_PRELOAD', options['env']);self.assertNotIn('PYTHONPATH', options['env'])
        self.assertFalse(options.get('shell', False));self.assertEqual(options['cwd'], '/')

    def test_shadow_lock_parser_uses_fixed_readonly_file_and_returns_no_secret(self):
        for value, expected in [('!', True), ('*', True), ('!$6$redacted', True), ('$6$redacted', False), ('', False)]:
            with self.subTest(value=value), tempfile.TemporaryFile(mode='w+t') as temporary:
                temporary.write(m.CONTROLLER_ACCOUNT+':'+value+':0:0:99999:7:::\n');temporary.flush();temporary.seek(0)
                real_fstat=os.fstat;info=real_fstat(temporary.fileno())
                checked=SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=0,st_size=info.st_size)
                with patch.object(m.os, 'open', return_value=os.dup(temporary.fileno())) as opened, patch.object(m.os, 'fstat', return_value=checked):
                    self.assertIs(m._locked_controller_password(), expected)
                    self.assertEqual(opened.call_args.args[0], '/etc/shadow')
                    self.assertTrue(opened.call_args.args[1]&os.O_NOFOLLOW)


class KernelPeerTests(unittest.TestCase):
    def test_linux_peer_uid_comes_from_kernel_and_never_caller_headers(self):
        connection=SimpleNamespace(getsockopt=lambda level, option, size:struct.pack('3i', 1234, 10002, 10001))
        with patch.object(m.socket, 'SO_PEERCRED', 17, create=True):self.assertEqual(m.peer_uid(connection), 10002)
        connection.getsockopt=lambda *args:b'bad'
        with patch.object(m.socket, 'SO_PEERCRED', 17, create=True), self.assertRaises(m.Blocked):m.peer_uid(connection)

    def test_bsd_peer_ids_and_unsupported_kernel_fail_closed(self):
        with patch.object(m, 'socket', SimpleNamespace(SOL_SOCKET=socket.SOL_SOCKET)):
            self.assertEqual(m.peer_uid(SimpleNamespace(getpeereid=lambda:(10001, 20))), 10001)
            with self.assertRaises(m.Blocked):m.peer_uid(SimpleNamespace())
            with self.assertRaises(m.Blocked):m.peer_uid(SimpleNamespace(getpeereid=lambda:(-1, 20)))

    @unittest.skipUnless(sys.platform.startswith('linux') and hasattr(socket,'SO_PEERCRED'), 'Actual Linux kernel credential path')
    def test_actual_linux_unix_socket_credentials(self):
        left,right=socket.socketpair()
        try:self.assertEqual(m.peer_uid(left), os.getuid())
        finally:left.close();right.close()


class PeerTokenWireTests(unittest.TestCase):
    # Reuse only private fixture setup, not the existing functional suite.
    setUp = baseline.ApplianceManagerTests.setUp
    @classmethod
    def setUpClass(cls):baseline.ApplianceManagerTests.setUpClass.__func__(cls)

    def test_real_unix_rpc_requires_both_allowed_peer_uid_and_token(self):
        run=self.parent/'peer-run';servers=[];ready=threading.Event();peer=[10002]
        def started(server):servers.append(server);ready.set()
        with patch.object(m, 'controller_identity'):
            thread=threading.Thread(target=m.serve,args=(self.manager,run,started),kwargs={'_test_peer_uid':lambda connection:peer[0]},daemon=True);thread.start()
            self.assertTrue(ready.wait(3))
            token=(self.root/'config/manager-token').read_text().strip()
            def request(token_value=None,body=None):
                connection=http.client.HTTPConnection('localhost');connection.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);connection.sock.connect(str(run/'manager.sock'))
                headers={'Content-Type':'application/json','X-Peer-UID':'0'}
                if token_value:headers['Authorization']='Bearer '+token_value
                connection.request('POST' if body else 'GET','/v1/jobs' if body else '/v1/status',json.dumps(body).encode() if body else None,headers)
                reply=connection.getresponse();value=json.loads(reply.read());connection.close();return reply.status,value
            try:
                with patch.dict(os.environ, {'PRTHAK_PEER_UID':'0'}):
                    self.assertEqual(request(token)[0],403)
                    self.assertEqual(request(token,{'request_id':'a'*32,'action':'restart','service':'controller'})[0],403)
                self.assertFalse((self.root/'manager/jobs'/('a'*32)).exists())
                for uid in (0,10001):
                    peer[0]=uid
                    self.assertEqual(request()[0],403);self.assertEqual(request('wrong-token')[0],403);self.assertEqual(request(token)[0],200)
                peer[0]=10001
                code,job=request(token,{'request_id':'b'*32,'action':'restart','service':'controller'})
                self.assertEqual(code,202);self.assertEqual(job['id'],'b'*32)
                peer[0]=True;self.assertEqual(request(token)[0],403)
            finally:servers[0].shutdown();servers[0].server_close();thread.join(3)

