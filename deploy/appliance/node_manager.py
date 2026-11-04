#!/usr/bin/env python3
"""Root-owned local appliance manager. No shell, remote Docker or command API.

Controller callers authenticate on a restricted Unix socket. Only generated
Compose services can be operated; private settings and all persistent data live
under DATA_ROOT. This program is deliberately separate from the controller.
"""
from __future__ import annotations

import argparse
import base64
import copy
import fcntl
import functools
import grp
import hashlib
import hmac
import http.client
import importlib.util
from http.server import BaseHTTPRequestHandler
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import signal
import shutil
import socket
import socketserver
import ssl
import stat
import struct
import subprocess
import sys
import tempfile
import shlex
import threading
import time
from urllib.parse import urlsplit
import uuid
from datetime import datetime,timezone

SERVICES = ('controller', 'database', 'etcd', 'router')
ACTIONS = ('status', 'start', 'stop', 'restart', 'configure', 'controller-config', 'storage-review', 'storage-move', 'rotate-replication', 'web-tls', 'internal-tls', 'restore-databases', 'public-port', 'controller-update-review', 'controller-update-apply')
ETCD_IMAGE = 'prthak-etcd:appliance-base'
ROUTER_IMAGE = 'haproxy:3.2-alpine3.24@sha256:5893840576071e6217cd52ebdcc14f454c6f7a631056fa6f4e0f40d3cac4215b'
CONTROLLER_IMAGE = 'prthak-controller:appliance'
DATABASE_IMAGE = 'prthak-database:appliance'
DATABASE_RUNTIME = 'postgres16-alpine3.24-musl-v1'
ENV_KEYS = {'DATA_ROOT', 'NODE_ID', 'SITE', 'NODE_IP', 'CONTROLLER_ORIGIN', 'CONTROLLER_BIND_IP',
    'CONTROLLER_PORT', 'CONTROLLER_BACKEND_PORT', 'DATABASE_ROUTER_PORT', 'EXISTING_NODE_IP',
    'CLUSTER_PASSWORD', 'SUPER_ADMIN_TOKEN', 'WATCHDOG_APPROVED', 'WATCHDOG_DEVICE',
    'SEG_ENTRA_TENANT_ID','SEG_ENTRA_CLIENT_ID','SEG_ENTRA_REDIRECT_URI','SEG_BOOTSTRAP_SUPER_ADMIN_OID',
    'SEG_ENTRA_CLIENT_SECRET','SEG_ENTRA_CLIENT_SECRET_FILE','SEG_HTTP_WORKERS','SEG_HTTP_THREADS',
    'SEG_DB_POOL_META_MAX','SEG_DB_POOL_TRAFFIC_MAX','SEG_DB_POOL_WAIT_SECONDS','SEG_CONTROL_PORT','SEG_DISCOVERY_PORT',
    'SEG_MANAGEMENT_PROBE_SOURCE_IP','SEG_MANAGEMENT_PROBE_TARGET_CIDRS'}
AUTH_PUBLIC=('SEG_ENTRA_TENANT_ID','SEG_ENTRA_CLIENT_ID','SEG_ENTRA_REDIRECT_URI','SEG_BOOTSTRAP_SUPER_ADMIN_OID')
HTTP_PUBLIC=('SEG_HTTP_WORKERS','SEG_HTTP_THREADS')
POOL_PUBLIC=('SEG_DB_POOL_META_MAX','SEG_DB_POOL_TRAFFIC_MAX','SEG_DB_POOL_WAIT_SECONDS')
CHANNEL_PUBLIC=('SEG_CONTROL_PORT','SEG_DISCOVERY_PORT')
PROBE_PUBLIC=('SEG_MANAGEMENT_PROBE_SOURCE_IP','SEG_MANAGEMENT_PROBE_TARGET_CIDRS')
RUNTIME_PUBLIC=HTTP_PUBLIC+POOL_PUBLIC+CHANNEL_PUBLIC+PROBE_PUBLIC
RUNTIME_BOUNDS=(('SEG_HTTP_WORKERS',1,16),('SEG_HTTP_THREADS',2,128),
    ('SEG_DB_POOL_META_MAX',1,64),('SEG_DB_POOL_TRAFFIC_MAX',1,16),('SEG_DB_POOL_WAIT_SECONDS',1,15),
    ('SEG_CONTROL_PORT',1,65535),('SEG_DISCOVERY_PORT',1,65535))
ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\Z')
JOB = re.compile(r'[0-9a-f]{32}\Z')
CONTROLLER_ACCOUNT = 'prthak-controller'
CONTROLLER_UID = 10001
CONTROLLER_GID = 10001
NOLOGIN_SHELLS = frozenset(('/usr/sbin/nologin', '/sbin/nologin', '/usr/bin/nologin', '/bin/nologin', '/usr/bin/false', '/bin/false'))


class Blocked(ValueError):
    pass


@functools.lru_cache(maxsize=1)
def offline_update_module():
    path = Path(__file__).resolve().with_name('offline_update.py')
    spec = importlib.util.spec_from_file_location('prthak_fixed_offline_update', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def active_offline_update(root):
    record = load(root / 'manager/controller-update/active.json', {})
    return record if record and record.get('phase') not in ('committed', 'rolled_back', 'blocked') else None


def _locked_controller_password():
    """Read only the fixed account's lock state; never return password data."""
    try:
        descriptor = os.open('/etc/shadow', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'r') as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 4 * 1024 * 1024:
                raise Blocked('The dedicated account password lock cannot be verified safely')
            for line in source:
                fields = line.rstrip('\n').split(':')
                if fields[0] == CONTROLLER_ACCOUNT:
                    return len(fields) >= 2 and fields[1].startswith(('!', '*'))
    except (OSError, UnicodeError):
        raise Blocked('The dedicated account password lock cannot be verified safely') from None
    return False


def _account_snapshot():
    """NSS lookups plus enumeration detect aliases and primary-GID users."""
    users, groups = list(pwd.getpwall()), list(grp.getgrall())
    for lookup, key, values in ((pwd.getpwnam, CONTROLLER_ACCOUNT, users), (pwd.getpwuid, CONTROLLER_UID, users),
                                (grp.getgrnam, CONTROLLER_ACCOUNT, groups), (grp.getgrgid, CONTROLLER_GID, groups)):
        try:
            value = lookup(key)
            if value not in values:values.append(value)
        except KeyError:pass
    return users, groups


def _identity_state(users, groups):
    named_users = [value for value in users if value.pw_name == CONTROLLER_ACCOUNT]
    named_groups = [value for value in groups if value.gr_name == CONTROLLER_ACCOUNT]
    if any(value.pw_uid == CONTROLLER_UID and value.pw_name != CONTROLLER_ACCOUNT for value in users):
        raise Blocked('Controller UID 10001 belongs to another host account; reserve a dedicated identity before installation')
    if any(value.gr_gid == CONTROLLER_GID and value.gr_name != CONTROLLER_ACCOUNT for value in groups):
        raise Blocked('Controller GID 10001 belongs to another host group; reserve a dedicated identity before installation')
    if any(value.pw_gid == CONTROLLER_GID and value.pw_name != CONTROLLER_ACCOUNT for value in users):
        raise Blocked('An unrelated host account uses controller GID 10001 as its primary group')
    if len(named_users) > 1 or len(named_groups) > 1:
        raise Blocked('The dedicated controller identity has ambiguous account aliases')
    if named_groups and (named_groups[0].gr_gid != CONTROLLER_GID or any(member != CONTROLLER_ACCOUNT for member in named_groups[0].gr_mem)):
        raise Blocked('The dedicated controller group has a different ID or unrelated members')
    if named_users:
        user = named_users[0]
        if user.pw_uid != CONTROLLER_UID or user.pw_gid != CONTROLLER_GID or user.pw_dir != '/nonexistent' or user.pw_shell not in NOLOGIN_SHELLS:
            raise Blocked('The dedicated controller account must have the reserved IDs, no home and a no-login shell')
        if not _locked_controller_password():raise Blocked('The dedicated controller account password must be locked')
    return bool(named_users), bool(named_groups)


def _fixed_account_tool(name):
    for directory in ('/usr/sbin', '/sbin', '/usr/bin', '/bin'):
        candidate = Path(directory) / name
        if not candidate.exists():continue
        resolved = candidate.resolve()
        for item in (resolved, *resolved.parents):
            info = item.stat()
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise Blocked('Dedicated account tools and their ancestors must be root-owned and protected')
        if resolved.is_file() and os.access(resolved, os.X_OK):return str(resolved)
    raise Blocked('A required fixed system account tool is unavailable')


def _account_command(arguments):
    try:
        result = subprocess.run(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C'}, cwd='/', timeout=30, check=False)
        if result.returncode:raise Blocked('The dedicated controller identity could not be reserved; no manager authority was started')
    except (OSError, subprocess.TimeoutExpired):
        raise Blocked('The dedicated controller identity could not be reserved; no manager authority was started') from None


def controller_identity(create=False):
    """Only the reviewed Linux installer creates this locked host identity."""
    present_user, present_group = _identity_state(*_account_snapshot())
    if present_user and present_group:return
    if not create:
        raise Blocked('Dedicated controller UID/GID reservation is missing; rerun the reviewed installer before starting the manager')
    if os.geteuid() != 0 or not sys.platform.startswith('linux'):
        raise Blocked('Dedicated host identity reservation requires the reviewed Linux root installer')
    if not present_group:
        _account_command([_fixed_account_tool('groupadd'), '--system', '--gid', str(CONTROLLER_GID), CONTROLLER_ACCOUNT])
    if not present_user:
        _account_command([_fixed_account_tool('useradd'), '--system', '--uid', str(CONTROLLER_UID), '--gid', str(CONTROLLER_GID),
                          '--no-create-home', '--home-dir', '/nonexistent', '--shell', _fixed_account_tool('nologin'), '--password', '!', CONTROLLER_ACCOUNT])
    if _identity_state(*_account_snapshot()) != (True, True):
        raise Blocked('The dedicated host identity reservation did not verify; no manager authority was started')


def peer_uid(connection):
    """Kernel credentials only; neither request fields nor environment can override them."""
    try:
        if hasattr(socket, 'SO_PEERCRED'):
            raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
            if len(raw) != struct.calcsize('3i'):raise ValueError()
            pid, uid, gid = struct.unpack('3i', raw)
            if pid <= 0 or uid < 0 or gid < 0:raise ValueError()
            return uid
        reader = getattr(connection, 'getpeereid', None)
        if reader:
            uid, gid = reader()
            if not isinstance(uid, int) or isinstance(uid, bool) or uid < 0 or not isinstance(gid, int) or gid < 0:raise ValueError()
            return uid
    except (OSError, ValueError, TypeError, struct.error):
        pass
    raise Blocked('Kernel Unix peer credentials are unavailable; manager access is denied')


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def atomic(path, value, mode=0o600, owner=None):
    path = Path(path)
    if path.is_symlink():
        raise Blocked('Refusing a symlink in a managed private path')
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    data = json.dumps(value, sort_keys=True, separators=(',', ':')).encode() if not isinstance(value, (bytes, str)) else value.encode() if isinstance(value, str) else value
    descriptor, name = tempfile.mkstemp(prefix='.pending-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            if owner is not None:os.fchown(stream.fileno(), owner, owner)
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.replace(name, path)
        parent = os.open(path.parent, os.O_RDONLY)
        try:os.fsync(parent)
        finally:os.close(parent)
    finally:
        if os.path.exists(name):os.unlink(name)


def load(path, default=None):
    path = Path(path)
    if not path.exists():return default
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 4*1024*1024 or info.st_mode & 0o077:
        raise Blocked('Private appliance state has unsafe type, permissions or size')
    return json.loads(path.read_text())


def private_dir(path, owner=None):
    path = Path(path)
    if path.is_symlink():raise Blocked('Managed directories must not be symlinks')
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)
    os.chown(path, 0 if owner is None else owner, 0 if owner is None else owner)


def safe_path(value, allowed_parent=None):
    if not isinstance(value, str) or not re.fullmatch(r'/[A-Za-z0-9_./-]+', value) or '..' in Path(value).parts:
        raise Blocked('Use a dedicated absolute DATA_ROOT without shell characters or parent traversal')
    path = Path(value)
    permitted = (Path(allowed_parent),) if allowed_parent else tuple(Path(value) for value in ('/var/lib', '/mnt', '/srv', '/data'))
    if not any(parent in path.parents for parent in permitted) or path in permitted:
        raise Blocked('DATA_ROOT must be a dedicated subdirectory of /var/lib, /mnt, /srv or /data')
    for parent in (path, *path.parents):
        if parent.is_symlink():raise Blocked('DATA_ROOT and its existing ancestors must not be symlinks')
        if allowed_parent is None and parent.exists():
            info=parent.stat()
            if info.st_uid!=0 or info.st_mode&0o022:raise Blocked('DATA_ROOT and existing ancestors must be root-owned and not writable by other users')
    return path


def acquire_lease(run_dir='/run/prthak-appliance'):
    directory=Path(run_dir)
    if directory.exists():
        info=directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise Blocked('Unsafe local manager runtime directory')
    else:private_dir(directory)
    descriptor=os.open(directory/'manager.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        info=os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o077:raise Blocked('Unsafe local manager lease file')
        try:fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError:raise Blocked('A local manager operation is active; stop the manager for a reviewed reinstall') from None
        return descriptor
    except Exception:os.close(descriptor);raise


def read_env(path):
    path = Path(path)
    info = path.lstat()
    owners = {0, os.getuid()}
    if os.environ.get('SUDO_UID', '').isdigit():owners.add(int(os.environ['SUDO_UID']))
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid not in owners or info.st_size > 65536:
        raise Blocked('.env must be an owned private regular file (chmod 600); it is parsed, never executed')
    import shlex
    values = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith('#'):continue
        key, separator, raw = line.partition('=')
        if not separator or key not in ENV_KEYS or key in values:
            raise Blocked('Unknown or duplicate .env field')
        pieces = shlex.split(raw, comments=True, posix=True)
        if len(pieces)>1:raise Blocked('Quote .env values containing spaces')
        values[key] = pieces[0] if pieces else ''
    return values


def ip(value, loopback=False):
    try:
        parsed = ipaddress.ip_address(value)
        if parsed.version!=4 or parsed.is_unspecified or parsed.is_multicast or parsed.is_link_local or parsed.is_loopback and not loopback:
            raise ValueError()
        return str(parsed)
    except (ValueError, TypeError):raise Blocked('Use a unicast IPv4 node address') from None


def private_auth_secret(path,installed=False):
    path=Path(path)
    if not path.is_absolute():raise Blocked('Use an absolute private Entra client-secret file')
    try:descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    except OSError:raise Blocked('Private Entra client-secret file could not be read; credentials were not changed') from None
    try:
        info=os.fstat(descriptor);owners={0,os.getuid()}
        if os.environ.get('SUDO_UID','').isdigit():owners.add(int(os.environ['SUDO_UID']))
        if installed:owners.add(10001)
        if not stat.S_ISREG(info.st_mode) or info.st_uid not in owners or info.st_mode&0o077 or not 0<info.st_size<=16384:raise Blocked('Entra client-secret file must be an owned private regular file (mode 0600)')
        with os.fdopen(descriptor,'rb',closefd=False) as source:raw=source.read(16385)
        value=raw.decode().strip()
        if not value or len(raw)>16384 or '\x00' in value:raise Blocked('Entra client-secret file is empty or invalid')
        return value
    except UnicodeError:raise Blocked('Entra client-secret file must contain bounded UTF-8 text') from None
    finally:os.close(descriptor)


def initial_environment(values,current=None,root=None):
    """Private stdin validation payload; never persist this raw-secret mapping."""
    current=current or {};environment={key:current[key] for key in (*AUTH_PUBLIC,*RUNTIME_PUBLIC) if current.get(key)}
    for key in (*AUTH_PUBLIC,*RUNTIME_PUBLIC):
        if values.get(key):environment[key]=values[key]
    for key,low,high in RUNTIME_BOUNDS:
        if key in environment:
            try:number=int(environment[key])
            except (ValueError,TypeError):raise Blocked('HTTP/database pool counts must be integers') from None
            if not low<=number<=high:raise Blocked('HTTP/database pool setting exceeds its supported bounds')
            environment[key]=str(number)
    if values.get('SEG_ENTRA_CLIENT_SECRET') and values.get('SEG_ENTRA_CLIENT_SECRET_FILE'):raise Blocked('Choose Entra client secret by private file or private .env value, not both')
    secret=values.get('SEG_ENTRA_CLIENT_SECRET','').strip()
    if values.get('SEG_ENTRA_CLIENT_SECRET_FILE'):secret=private_auth_secret(values['SEG_ENTRA_CLIENT_SECRET_FILE'])
    elif not secret and current.get('SEG_ENTRA_CLIENT_SECRET_FILE'):
        if current['SEG_ENTRA_CLIENT_SECRET_FILE']!='/run/prthak-bootstrap/entra-client-secret' or root is None:raise Blocked('Existing provider secret storage needs explicit protected-state review')
        secret=private_auth_secret(Path(root)/'config/controller/entra-client-secret',installed=True)
    if current.get('SEG_ENTRA_CLIENT_SECRET'):raise Blocked('Existing raw provider environment needs explicit protected-state review; reinstall will not move or rotate it')
    if secret:environment['SEG_ENTRA_CLIENT_SECRET']=secret
    core=[environment.get(key) for key in ('SEG_ENTRA_TENANT_ID','SEG_ENTRA_CLIENT_ID','SEG_ENTRA_REDIRECT_URI','SEG_ENTRA_CLIENT_SECRET')]
    if any(core) or environment.get('SEG_BOOTSTRAP_SUPER_ADMIN_OID'):
        if not all(core) or not isinstance(secret,str) or len(secret)>16384 or '\x00' in secret:raise Blocked('Initial Entra setup requires tenant, client, HTTPS callback and a private client secret')
    return environment


def stage_initial_environment(engine,root,values,existing=None):
    current=(existing or {}).get('environment',{});request=initial_environment(values,current,root)
    result=engine.validate_initial_environment(request)
    if result.get('validated') is not True or not isinstance(result.get('environment'),dict):raise Blocked('The bundled runtime did not validate initial provider/runtime settings')
    environment=result['environment'];allowed=set(AUTH_PUBLIC)|set(RUNTIME_PUBLIC)|{'SEG_ENTRA_CLIENT_SECRET_FILE'}
    if set(environment)-allowed or 'SEG_ENTRA_CLIENT_SECRET' in environment:raise Blocked('The bundled validator returned an unexpected environment field')
    secret=request.get('SEG_ENTRA_CLIENT_SECRET','');path=Path(root)/'config/controller/entra-client-secret'
    if existing:
        previous={key:current[key] for key in allowed if current.get(key)}
        if environment!=previous:raise Blocked('Reinstall preserves existing provider/runtime configuration; reviewed configuration change is required')
        if secret:
            if not path.exists() or private_auth_secret(path,installed=True)!=secret:raise Blocked('Reinstall refuses to rotate or replace an existing provider secret')
        return environment
    if secret:
        if path.exists():
            if private_auth_secret(path,installed=True)!=secret:raise Blocked('A staged provider secret differs; preserve it for explicit review')
        else:atomic(path,secret+'\n',owner=10001)
    return environment


def installation_identity(root,local):
    """Resume only this exact installer-owned staging root after a failure."""
    root=Path(root);installed=load(root/'config/installed.json')
    if installed:
        if installed['node_id']!=local['node_id'] or installed['node_ip']!=local['node_ip']:raise Blocked('An existing appliance node identity/IP cannot be overwritten by installation')
        return installed
    public={key:value for key,value in local.items() if key not in ('cluster_password','super_admin_token','appliance_id')};path=root/'config/install-pending.json';pending=load(path)
    if pending:
        if pending.get('schema_version')!=1 or pending.get('data_root')!=str(root) or pending.get('settings_digest')!=digest(public):raise Blocked('Pending installation belongs to different node settings; preserve it for reviewed recovery')
        identity=pending['identity']
    else:
        if root.exists() and any(root.iterdir()):raise Blocked('DATA_ROOT must be empty or have this installer\'s exact private pending identity')
        private_dir(root);private_dir(root/'config');identity={**public,'appliance_id':uuid.uuid4().hex}
        atomic(path,{'schema_version':1,'data_root':str(root),'settings_digest':digest(public),'identity':identity})
    return {**identity,'cluster_password':local.get('cluster_password',''),'super_admin_token':local.get('super_admin_token','')}


def database_runtime_settings(root,settings):
    """Never reuse unmarked glibc PGDATA with the musl database runtime.

    The marker is installer-owned state outside PGDATA, so initdb still receives
    an empty directory. It survives restarts, reviewed storage moves and backups.
    Only an empty data directory can acquire the marker automatically.
    """
    data=Path(root)/'database'
    if data.is_symlink() or (data.exists() and not data.is_dir()):
        raise Blocked('Database storage must be a real managed directory')
    if settings.get('database_runtime')==DATABASE_RUNTIME:return settings
    if settings.get('database_runtime') is not None or (data.exists() and any(data.iterdir())):
        raise Blocked('Existing PostgreSQL physical data is incompatible with the Alpine runtime. Keep the previous appliance running, create a logical backup in GUI Backups, and restore it into a fresh appliance/storage using GUI Recovery. No existing database files were changed.')
    return {**settings,'database_runtime':DATABASE_RUNTIME}


def origin(value):
    try:
        parsed = urlsplit(value)
        if parsed.scheme!='https' or not parsed.hostname or not re.fullmatch(r'[A-Za-z0-9.-]+',parsed.hostname) or parsed.username or parsed.password or parsed.path not in ('', '/') or parsed.query or parsed.fragment or any(c.isspace() for c in value):raise ValueError()
        port=parsed.port
        return 'https://'+parsed.hostname.lower()+((':'+str(port)) if port and port!=443 else '')
    except (ValueError, TypeError, AttributeError):raise Blocked('A stable HTTPS controller origin is required') from None


def settings(values):
    node = values.get('NODE_ID') or socket.gethostname()
    site = values.get('SITE') or 'local'
    if not ID.fullmatch(node) or not isinstance(site,str) or not site.strip() or len(site)>100:raise Blocked('Provide a valid NODE_ID and SITE')
    address = values.get('NODE_IP', 'auto')
    automatic=address=='auto'
    if automatic:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as probe:
            try:probe.connect(('192.0.2.1',9)); address=probe.getsockname()[0]
            except OSError:raise Blocked('Automatic management IP detection failed; no loopback fallback was selected') from None
    address=ip(address,loopback=not automatic)
    bind=values.get('CONTROLLER_BIND_IP','auto')
    if bind=='auto':bind=address
    if bind!='0.0.0.0':ip(bind,loopback=True)
    ports={}
    for name,default in (('CONTROLLER_PORT',8787),('CONTROLLER_BACKEND_PORT',8786),('DATABASE_ROUTER_PORT',5433)):
        try:value=int(values.get(name) or default)
        except ValueError:raise Blocked('Ports must be integers') from None
        if not (1 if name=='CONTROLLER_PORT' else 1024)<=value<=65535:raise Blocked('Public port must be 1..65535; internal published ports must be 1024..65535')
        ports[name.lower()]=value
    if len(set(ports.values()))!=3:raise Blocked('Controller, backend and database router ports must differ')
    if ports['controller_port'] in (22,2379,2380,5432,8008):raise Blocked('Public controller port collides with a protected host/cluster service')
    password=values.get('CLUSTER_PASSWORD','')
    token=values.get('SUPER_ADMIN_TOKEN','')
    if password and len(password)<16:raise Blocked('The initial shared cluster password needs at least 16 characters')
    if token and len(token)<32:raise Blocked('The initial Super Admin token needs at least 32 random characters')
    if values.get('WATCHDOG_DEVICE','/dev/watchdog0')!='/dev/watchdog0':raise Blocked('Only the explicitly approved /dev/watchdog0 device is supported')
    return {'node_id':node,'site':site.strip(),'node_ip':address,'bind_ip':bind,**ports,
        'controller_origin':origin(values.get('CONTROLLER_ORIGIN') or 'https://'+address+':'+str(ports['controller_port'])),
        'existing_node_ip':values.get('EXISTING_NODE_IP',''),'cluster_password':password,'super_admin_token':token,
        'watchdog_approved':values.get('WATCHDOG_APPROVED','false').lower()=='true','watchdog_device':'/dev/watchdog0'}


def installer_configuration(args,pointer='/etc/prthak/data-root'):
    """Explicit GUI bootstrap never reads an incidental .env or resets identity."""
    if getattr(args,'gui_setup',False):
        if args.env_file is not None:raise Blocked('Choose --gui-setup or an explicit --env-file, not both')
        active=Path(pointer)
        if active.is_symlink():raise Blocked('The active DATA_ROOT pointer must not be a symlink')
        root=safe_path(args.data_root or (active.read_text().strip() if active.exists() else '/var/lib/prthak'))
        installed=load(root/'config/installed.json')
        if installed:return {},copy.deepcopy(installed),root
        pending=load(root/'config/install-pending.json')
        if pending:
            if pending.get('schema_version')!=1 or pending.get('data_root')!=str(root):raise Blocked('Pending GUI installation has another identity')
            return {},{**pending['identity'],'cluster_password':'','super_admin_token':''},root
        return {},settings({}),root
    values=read_env(args.env_file if args.env_file is not None else '.env')
    return values,settings(values),safe_path(args.data_root or values.get('DATA_ROOT','/var/lib/prthak'))


def controller_configuration_binding(body):
    secret=body.get('client_secret','')
    return digest({'kind':'prthak-controller-config-v1','operation_id':body['operation_id'],
        'expected_revision':body['expected_revision'],'expected_config_digest':body['expected_config_digest'],
        'environment':body['environment'],'client_secret_sha256':hashlib.sha256(secret.encode()).hexdigest(),
        'binding_salt':body.get('binding_salt',''),'provider_epoch':body.get('provider_epoch',''),
        'provider_change':body.get('provider_change',False),'profile_convergence':body.get('profile_convergence',False),
        'acknowledge_agent_aliases':body.get('acknowledge_agent_aliases',False)})


class Engine:
    def __init__(self, root, project, docker=None):
        self.root,self.project=Path(root),project
        self.docker=tuple(docker or (shutil.which('docker') or '/usr/bin/docker','--host','unix:///var/run/docker.sock'))
        images = (load(self.root/'config/installed.json') or {}).get('images', {})
        self.controller_image = images.get('controller', CONTROLLER_IMAGE)
    def run(self,args,timeout=180,private_input=None):
        environment={key:os.environ[key] for key in ('PATH','LANG','LC_ALL','HOME') if key in os.environ}
        try:
            process=subprocess.Popen([*self.docker,*args],stdin=subprocess.PIPE if private_input is not None else subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=environment,start_new_session=True)
            try:stdout,stderr=process.communicate(private_input,timeout=timeout)
            except subprocess.TimeoutExpired:
                # Compose is a child plugin; fence its whole process group
                # before compensation can restore an older router mapping.
                try:os.killpg(process.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                process.communicate();raise
        except (OSError,subprocess.TimeoutExpired):raise Blocked('The fixed Docker operation is unavailable or timed out') from None
        if process.returncode or len(stdout)>4*1024*1024:raise Blocked('The fixed Docker operation failed; private command output was not exposed')
        return stdout.decode()
    def compose(self,args,timeout=180):
        return self.run(['compose','--project-name',self.project,'--project-directory',str(self.root/'runtime'),'-f',str(self.root/'runtime/compose.json'),*args],timeout)
    def states(self):
        raw=self.compose(['ps','--all','--format','json'])
        if not raw.strip():return {}
        try:values=json.loads(raw)
        except ValueError:values=[json.loads(line) for line in raw.splitlines() if line.strip()]
        if isinstance(values,dict):values=[values]
        return {value['Service']:value.get('State','unknown') for value in values if value.get('Service') in SERVICES}
    def assert_public_port_free(self,address,port):
        # Docker DNAT may publish a port without a userland listening socket.
        identifiers=self.run(['ps','-q']).split()
        if len(identifiers)>10000 or any(not re.fullmatch('[0-9a-f]{12,64}',value) for value in identifiers):raise Blocked('Docker port ownership inventory is unavailable')
        if identifiers:
            for line in self.run(['inspect','--format','{{json .NetworkSettings.Ports}}',*identifiers]).splitlines():
                for bindings in (json.loads(line) or {}).values():
                    for binding in bindings or []:
                        host=binding.get('HostIp','0.0.0.0')
                        if str(binding.get('HostPort'))==str(port) and (host in ('','0.0.0.0','::',address) or address=='0.0.0.0'):raise Blocked('The proposed public port is already published by a container')
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as probe:
            try:probe.bind((address,port));probe.listen(1)
            except OSError:raise Blocked('The proposed public bind is occupied or unavailable') from None
    def check(self):
        if self.run(['info','--format','{{.OSType}}']).strip()!='linux':raise Blocked('A local Linux Docker Engine is required')
        self.run(['compose','version','--short'])
    def foreign_bindings(self,root):
        identifiers=self.run(['ps','-q']).split()
        if len(identifiers)>1024:raise Blocked('Too many containers to verify a bounded storage fence')
        if not identifiers:return []
        values=json.loads(self.run(['inspect',*identifiers]));foreign=[]
        for value in values:
            labels=value.get('Config',{}).get('Labels') or {}
            owned=labels.get('com.docker.compose.project')==self.project and labels.get('com.docker.compose.service') in SERVICES
            if owned:continue
            for mount in value.get('Mounts',[]):
                if mount.get('Type')!='bind':continue
                source=Path(mount['Source'])
                if source==root or source in root.parents or root in source.parents:foreign.append(value.get('Id','unknown')[:12])
        return foreign
    def local_network_sources(self):
        values=json.loads(self.run(['network','inspect',self.project+'_default']))
        if len(values)!=1 or values[0].get('Labels',{}).get('com.docker.compose.project')!=self.project:raise Blocked('The local application network is not owned by this appliance')
        sources=[]
        for value in values[0].get('IPAM',{}).get('Config',[]):
            network=ipaddress.ip_network(value.get('Subnet',''),strict=True)
            if network.version==4:
                if not network.is_private or network.prefixlen<16:raise Blocked('Owned local Docker network must use a bounded private IPv4 subnet')
                sources.append(str(network))
        if not sources:raise Blocked('Start the initial controller/router so its owned local Docker network can be verified')
        return sources
    def database_helper(self,request):
        identifier=self.compose(['ps','-q','database']).strip()
        if not re.fullmatch(r'[0-9a-f]{12,64}',identifier):raise Blocked('Owned database container is not running')
        return json.loads(self.run(['exec','-i',identifier,'/opt/patroni/bin/python','/opt/prthak/rotation_helper.py'],timeout=30,private_input=json.dumps(request).encode()))
    def restore_database_helper(self,request):
        identifier=self.compose(['ps','-q','database']).strip()
        if not re.fullmatch(r'[0-9a-f]{12,64}',identifier):raise Blocked('Owned database container is not running')
        return json.loads(self.run(['exec','-i',identifier,'/opt/patroni/bin/python','/opt/prthak/restore_helper.py'],timeout=60,private_input=json.dumps(request).encode()))
    def validate_initial_environment(self,environment):
        arguments=['run','--pull=never','--rm','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','--entrypoint','python3','-i',self.controller_image,'/opt/prthak/controller_entrypoint.py','--validate-initial-env']
        try:return json.loads(self.run(arguments,timeout=30,private_input=json.dumps(environment).encode()))
        except Blocked:raise Blocked('Bundled Entra/runtime validation failed; check tenant, client, HTTPS callback and complete private-secret configuration') from None
    def internal_tls_validate(self,request):
        identifier=self.compose(['ps','-q','controller']).strip()
        if re.fullmatch(r'[0-9a-f]{12,64}',identifier):
            arguments=['exec','-i',identifier,'python3','-m','controller.internal_certificates','--validate']
        else:
            arguments=['compose','--project-name',self.project,'--project-directory',str(self.root/'runtime'),'-f',str(self.root/'runtime/compose.json'),'run','--rm','-T','--no-deps','--entrypoint','python3','controller','-m','controller.internal_certificates','--validate']
        return json.loads(self.run(arguments,timeout=30,private_input=json.dumps(request).encode()))
    def internal_tls_probe(self,service,ports,directory,hostname,fingerprint):
        if service not in ('database','etcd'):raise Blocked('Fixed internal TLS network namespace required')
        identifier=self.compose(['ps','-q',service]).strip()
        if not re.fullmatch(r'[0-9a-f]{12,64}',identifier):raise Blocked('Owned internal service is not running')
        arguments=['run','--pull=never','--rm','--network','container:'+identifier,'--user','0','--cap-drop','ALL','--security-opt','no-new-privileges:true','--read-only','--entrypoint','python3','--mount','type=bind,source='+str(directory)+',target=/run/prthak-tls,readonly',self.controller_image,'-m','controller.internal_certificates','--probe']
        return json.loads(self.run(arguments,timeout=45,private_input=json.dumps({'ports':ports,'hostname':hostname,'fingerprint':fingerprint}).encode()))


def validate_manifest(value, local):
    if not isinstance(value,dict) or value.get('schema_version')!=1:raise Blocked('A version1 authorized appliance manifest is required')
    result=copy.deepcopy(value)
    try:result['deployment_id']=str(uuid.UUID(result['deployment_id']))
    except (ValueError,TypeError,KeyError):raise Blocked('A stable deployment UUID is required') from None
    if isinstance(result.get('generation'),bool) or not isinstance(result.get('generation'),int) or result['generation']<1:raise Blocked('Manifest generation must be positive')
    node=result.get('local_node',{})
    if node.get('id')!=local['node_id'] or ip(node.get('ip'),loopback=True)!=local['node_ip'] or node.get('role') not in ('management','database_voter'):raise Blocked('Manifest does not authorize this installed node identity')
    if not isinstance(node.get('site'),str) or not node['site'].strip() or len(node['site'])>100:raise Blocked('A bounded local site name is required')
    result['controller_origin']=origin(result.get('controller_origin'))
    if result.get('controller_tls_server_name') and (not isinstance(result['controller_tls_server_name'],str) or not re.fullmatch(r'[A-Za-z0-9.-]+',result['controller_tls_server_name'])):raise Blocked('Invalid local controller TLS server name')
    voters=result.get('voters',[])
    if not isinstance(voters,list) or len(voters)>3:raise Blocked('At most three explicitly selected database/quorum voters are supported')
    for voter in voters:
        if not isinstance(voter,dict) or not ID.fullmatch(voter.get('id','')) or not isinstance(voter.get('site'),str) or not voter['site'].strip():raise Blocked('Invalid quorum voter identity/site')
        voter['ip']=ip(voter.get('ip'))
        if 'tls_server_name' in voter and (not isinstance(voter['tls_server_name'],str) or not re.fullmatch(r'[A-Za-z0-9.-]+',voter['tls_server_name'])):raise Blocked('Invalid pinned voter TLS server name')
    if len({v['id'] for v in voters})!=len(voters) or len({v['ip'] for v in voters})!=len(voters) or len({v['site'] for v in voters})!=len(voters):raise Blocked('Voters require distinct IDs, addresses and independent sites')
    if node['role']=='database_voter' and not any(v['id']==node['id'] and v['ip']==node['ip'] for v in voters):raise Blocked('Database nodes must be explicitly selected as voters')
    members=result.get('controller_members',[])
    if not isinstance(members,list) or any(not isinstance(m,dict) or not ID.fullmatch(m.get('id','')) for m in members):raise Blocked('Invalid management membership list')
    if len({m['id'] for m in members})!=len(members):raise Blocked('Management member identities must be unique')
    for member in members:
        member['ip']=ip(member.get('ip'),loopback=True)
        if 'backend_port' in member and (isinstance(member['backend_port'],bool) or not isinstance(member['backend_port'],int) or not 1024<=member['backend_port']<=65535):raise Blocked('Controller backend ports must be unprivileged numeric ports')
        if 'tls_server_name' in member and (not isinstance(member['tls_server_name'],str) or not re.fullmatch(r'[A-Za-z0-9.-]+',member['tls_server_name'])):raise Blocked('Invalid pinned controller TLS server name')
    known_hosts={local['node_ip'],urlsplit(local['controller_origin']).hostname,urlsplit(result['controller_origin']).hostname}|{m['ip'] for m in members}
    for key in ('preferred_controller_url','fallback_controller_url'):
        if result.get(key):
            result[key]=origin(result[key])
            if urlsplit(result[key]).hostname not in known_hosts:raise Blocked('Routing preferences must select an enrolled controller address')
    if len(voters)==3:
        private=result.get('pki',{})
        if any(not isinstance(private.get(key),str) or len(private[key])>65536 for key in ('ca','certificate','private_key')):raise Blocked('Signed per-node TLS material is required')
        if any(not isinstance(result.get('secrets',{}).get(key),str) or not 32<=len(result['secrets'][key])<=128 or any(ord(c)<32 or ord(c)>126 for c in result['secrets'][key]) for key in ('admin','replication','metadata','traffic')):raise Blocked('Strong bounded private database role credentials are required')
        if result.get('watchdog',{}).get('required') is not True:raise Blocked('Required watchdog fencing cannot be disabled')
        database=result.setdefault('database',{})
        for kind in ('metadata','traffic'):
            for suffix in ('name','user'):
                name=database.setdefault(kind+'_'+suffix,'prthak_'+kind)
                pattern=r'[a-z][a-z0-9_]{0,62}' if suffix=='name' else r'[a-z][a-z0-9_]{0,47}'
                if not isinstance(name,str) or not re.fullmatch(pattern,name) or name in ('postgres','template0','template1','prthak_admin','prthak_replication'):raise Blocked('Invalid application database identity')
        if database['metadata_name']==database['traffic_name'] or database['metadata_user']==database['traffic_user']:raise Blocked('Separate metadata and traffic database identities are required')
    return result


def render_patroni(manifest,local_sources=(),recovery_aliases=()):
    node=manifest['local_node']; private=manifest['secrets']; database=manifest['database']
    peers=[v['ip']+'/32' for v in manifest['voters']]
    sources=manifest.get('controller_cidrs') or [m['ip']+'/32' for m in manifest.get('controller_members',[])]
    sources=sorted(set(sources+list(local_sources)+['127.0.0.1/32']))
    for source in sources:
        network=ipaddress.ip_network(source,strict=True)
        if network.prefixlen<8 or network.version!=4:raise Blocked('Database sources must be bounded IPv4 networks')
    hba=['local all all peer','hostssl all prthak_admin 127.0.0.1/32 scram-sha-256','hostssl replication prthak_replication 127.0.0.1/32 scram-sha-256']
    for source in peers:hba.extend(['hostssl replication prthak_replication '+source+' scram-sha-256','hostssl all prthak_admin '+source+' scram-sha-256'])
    for source in sources:
        for kind in ('metadata','traffic'):hba.append('hostssl '+database[kind+'_name']+' '+database[kind+'_user']+' '+source+' scram-sha-256')
        for previous in recovery_aliases:
            for kind in ('metadata','traffic'):
                name,user=previous[kind+'_name'],previous[kind+'_user']
                if not re.fullmatch('[a-z][a-z0-9_]{0,62}',name) or not re.fullmatch('[a-z][a-z0-9_]{0,47}',user):raise Blocked('Invalid owned recovery database alias')
                rule='hostssl '+name+' '+user+' '+source+' scram-sha-256'
                if rule not in hba:hba.append(rule)
    hba+=['host all all 0.0.0.0/0 reject','host all all ::/0 reject']
    auth={'sslmode':'verify-full','sslrootcert':'/config/ca.pem'}
    return {'scope':'prthak-'+manifest['deployment_id'],'namespace':'/prthak/'+manifest['deployment_id']+'/', 'name':node['id'],
        'restapi':{'listen':'0.0.0.0:8008','connect_address':node['ip']+':8008','certfile':'/config/node.pem','keyfile':'/config/node-key.pem','cafile':'/config/ca.pem','verify_client':'required'},
        'ctl':{'insecure':False,'cacert':'/config/ca.pem','certfile':'/config/node.pem','keyfile':'/config/node-key.pem'},
        'etcd3':{'hosts':[v['ip']+':2379' for v in manifest['voters']],'protocol':'https','cacert':'/config/ca.pem','cert':'/config/node.pem','key':'/config/node-key.pem'},
        'bootstrap':{'dcs':{'ttl':60,'loop_wait':5,'retry_timeout':5,'check_timeline':True,'synchronous_mode':True,'synchronous_mode_strict':True,'synchronous_node_count':1,'postgresql':{'use_pg_rewind':True,'parameters':{'wal_level':'replica','max_wal_senders':10,'max_replication_slots':10,'wal_log_hints':'on','password_encryption':'scram-sha-256'}}},'initdb':[{'encoding':'UTF8'},'data-checksums'],'pg_hba':hba,'post_bootstrap':'/opt/patroni/bin/python /opt/prthak/bootstrap_roles.py'},
        'postgresql':{'listen':'0.0.0.0:5432','connect_address':node['ip']+':5432','data_dir':'/var/lib/postgresql/data','bin_dir':'/usr/lib/postgresql/16/bin','pgpass':'/tmp/patroni.pgpass','basebackup':[{'checkpoint':'fast'}],'authentication':{'superuser':{'username':'prthak_admin','password':private['admin'],**auth},'replication':{'username':'prthak_replication','password':private['replication'],**auth}},'parameters':{'ssl':'on','ssl_min_protocol_version':'TLSv1.2','ssl_cert_file':'/config/node.pem','ssl_key_file':'/config/node-key.pem','ssl_ca_file':'/config/ca.pem','password_encryption':'scram-sha-256','unix_socket_directories':'/tmp'},'pg_hba':hba},
        'watchdog':{'mode':'required','device':'/dev/watchdog0','safety_margin':-1}}


class Manager:
    def __init__(self,data_root,pointer='/etc/prthak/data-root',engine_factory=Engine,allowed_parent=None,*,recover=True):
        self.allowed_parent=allowed_parent
        self.root=safe_path(str(data_root),allowed_parent)
        self.pointer=Path(pointer);self.engine_factory=engine_factory
        if self.pointer.exists():
            if self.pointer.is_symlink() or not self.pointer.is_file() or self.pointer.read_text().strip()!=str(self.root):raise Blocked('Use only the atomically committed active DATA_ROOT pointer')
        self.lock=threading.RLock();self.worker=None
        self.management_probe_slots=threading.BoundedSemaphore(8)
        self.installed=load(self.root/'config/installed.json')
        if not self.installed:raise Blocked('Appliance has not been installed at this DATA_ROOT')
        if (self.root/'manager/retired.json').exists():raise Blocked('This DATA_ROOT is retired; use the atomically committed active pointer')
        self.project='prthak-'+self.installed['appliance_id'][:12]
        self.engine=engine_factory(self.root,self.project)
        self.health_snapshot={'status':'unverified','quorum_healthy':False,'database_ready':False}
        if not recover:
            return
        # Commands interrupted by a process/host crash are never blindly
        # repeated. The durable same request ID remains inspectable, and a new
        # review is required (including for a move whose pointer did commit).
        for path in (self.root/'manager/jobs').glob('*'):
            if not JOB.fullmatch(path.name):continue
            value=load(path)
            if value.get('status')=='running':
                upgrade = load(self.root / 'manager/controller-update/active.json', {})
                if upgrade and upgrade.get('job_id') == path.name:
                    continue
                value.update(status='error',phase='interrupted',error='Manager restarted during this operation; inspect actual status and submit a fresh reviewed job',updated_at=time.time())
                atomic(path,value)
        self.recover_controller_configuration()
        self.recover_origin_bootstrap()
    def state(self):return load(self.root/'manager/state.json',{'revision':0})
    def manifest(self):return load(self.root/'config/manifest.json')
    def desired(self):return load(self.root/'config/desired.json')
    def enabled(self):
        manifest=self.manifest()
        return ['controller','router']+(['etcd','database'] if manifest and manifest['local_node']['role']=='database_voter' else [])
    def channel_ports(self,environment=None,management_port=None):
        if environment is None:environment=load(self.root/'config/controller/settings.json',{}).get('environment',{})
        result={'management':self.installed['controller_port'] if management_port is None else management_port}
        for channel,default in (('control',8788),('discovery',8789)):
            value=environment.get('SEG_'+channel.upper()+'_PORT') or str(default)
            if not isinstance(value,str) or not re.fullmatch(r'[0-9]{1,5}',value) or not 1<=int(value)<=65535:raise Blocked('Agent channel ports must be whole numbers from 1 to 65535')
            result[channel]=int(value)
        protected={22,2379,2380,5432,8008,8796,8797,9009,self.installed.get('controller_backend_port',8786),self.installed.get('database_router_port',5433)}
        if len(set(result.values()))!=3 or any(port in protected for port in result.values()):raise Blocked('Management, control and discovery ports must differ and cannot overlap protected or internal services')
        return result
    def validate_channel_configuration(self,environment):
        desired=self.channel_ports(environment);previous=self.channel_ports()
        for channel in ('control','discovery'):
            if desired[channel]!=previous[channel]:self.engine.assert_public_port_free(self.installed['bind_ip'],desired[channel])
        return desired
    def _verify_channel_listeners(self,record,previous=False):
        expected=record['previous_settings'] if previous else record['desired_settings']
        ports=self.channel_ports(expected.get('environment',{}));material=record['tls']
        context=ssl.create_default_context(cadata=material['chain'])
        address=self.installed['bind_ip'] if self.installed['bind_ip']!='0.0.0.0' else self.installed['node_ip']
        for channel,backend in (('control',8796),('discovery',8797)):
            for port in {ports[channel],backend}:
                self._web_probe(material['chain'],material['name'],port,material['fingerprint'],path='/healthz')
                with socket.create_connection((address,port),timeout=5) as transport:
                    with context.wrap_socket(transport,server_hostname=material['name']) as tls:
                        if hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()!=material['fingerprint']:raise Blocked('Agent channel HTTPS identity changed')
                        tls.sendall(('GET /api/v1/agent/policy HTTP/1.1\r\nHost: '+material['name']+'\r\nConnection: close\r\n\r\n').encode())
                        response=http.client.HTTPResponse(tls);response.begin();response.read(65537)
                        if response.status!=(403 if channel=='control' else 404):raise Blocked('Agent listener route isolation did not verify')
    def _controller_configuration_snapshot(self):
        for directory in (self.root/'config',self.root/'config/controller'):
            if directory.is_symlink():raise Blocked('Controller configuration directories must not be symlinks')
        settings=load(self.root/'config/controller/settings.json',{'environment':{}})
        environment=settings.get('environment',{})
        if not isinstance(environment,dict) or environment.get('SEG_ENTRA_CLIENT_SECRET'):raise Blocked('Raw provider environment requires explicit protected recovery')
        secret=None
        if environment.get('SEG_ENTRA_CLIENT_SECRET_FILE'):
            if environment['SEG_ENTRA_CLIENT_SECRET_FILE']!='/run/prthak-bootstrap/entra-client-secret':raise Blocked('Unknown provider secret storage')
            secret=private_auth_secret(self.root/'config/controller/entra-client-secret',installed=True)
        value={'appliance_id':self.installed['appliance_id'],'settings':settings,
               'secret_sha256':hashlib.sha256(secret.encode()).hexdigest() if secret else ''}
        salt_path=self.root/'manager/controller-fingerprint-salt'
        if salt_path.is_symlink():raise Blocked('Controller fingerprint key must be a protected regular file')
        if not salt_path.exists():atomic(salt_path,secrets.token_hex(32))
        value['secret_sha256']=hmac.new(salt_path.read_bytes(),(secret or '').encode(),hashlib.sha256).hexdigest()
        return settings,secret,digest(value)
    def controller_configuration_status(self):
        settings,secret,fingerprint=self._controller_configuration_snapshot()
        environment={key:value for key,value in settings.get('environment',{}).items() if key in (*AUTH_PUBLIC,*RUNTIME_PUBLIC)}
        configured=bool(environment.get('SEG_ENTRA_TENANT_ID'))
        record=load(self.root/'manager/controller-config.json')
        return {'expected_revision':self.state()['revision'],'digest':fingerprint,'environment':environment,
                'entra_configured':configured,'provider_managed':settings.get('environment',{}).get('PRTHAK_GUI_PROVIDER_MANAGED')=='1','bootstrap_available':not configured and (self.root/'config/controller/initial-admin-token').is_file(),
                'operation':{key:record[key] for key in ('id','phase','binding_digest') if key in record} if record else None}
    def status(self):
        blockers=[]
        try:states=self.engine.states()
        except Blocked:states={name:'unknown' for name in SERVICES};blockers.append('Local Docker/Compose status is unavailable')
        manifest=self.manifest();desired=self.desired();state=self.state();settings=self.installed
        database_compatible=True
        try:database_runtime_settings(self.root,settings)
        except Blocked as error:database_compatible=False;blockers.append(str(error))
        cluster='configured' if manifest else 'waiting_for_voters' if desired else 'bootstrap'
        health=copy.deepcopy(self.health_snapshot);rotation=load(self.root/'manager/rotation.json')
        if health.get('checked_at',0)<time.time()-45:health.update(status='stale' if health.get('checked_at') else 'unverified',database_ready=False,quorum_healthy=False)
        routing=manifest or desired or {}
        internal=load(self.root/'manager/internal-tls.json',{});pki=(manifest or {}).get('pki',{});fingerprint=self._leaf_fingerprint(pki['certificate']) if pki.get('certificate') else None
        drift=False
        if fingerprint:
            try:drift=any(self._leaf_fingerprint((self.root/'config'/service/'node.pem').read_text())!=fingerprint for service in ('database','etcd','router'))
            except (OSError,ValueError,Blocked):drift=True
        public=load(self.root/'manager/public-port.json',{})
        committed_port=public.get('previous',{}).get('installed',settings)['controller_port'] if public.get('phase') not in (None,'committed','aborted') else settings['controller_port']
        capabilities=['internal_tls_v1','restore_databases_v1','public_port_v1','controller_config_v1','separated_agent_channels_v1']
        if Path(__file__).with_name('offline_update.py').is_file() and offline_update_module().supported(self):
            capabilities.append('offline_update_v1')
        return {'schema_version':1,'installed':True,'appliance_id':settings['appliance_id'],'revision':state['revision'],'database_runtime_profile':DATABASE_RUNTIME,'database_storage_compatible':database_compatible,'capabilities':capabilities,'controller_configuration':self.controller_configuration_status(),'agent_channel_ports':self.channel_ports(),'public_port':committed_port,'bind_address':settings['bind_ip'],'public_listener':{'committed_port':committed_port,'candidate_port':public.get('binding',{}).get('new_port') if public.get('phase') not in (None,'committed','aborted') else None,'phase':public.get('phase'),'operation_id':public.get('id'),'binding_digest':public.get('binding_digest'),'container_port':8787,'backend_port':settings['controller_backend_port'],'origin_mode':'preserve','allowed_min':1,'allowed_max':65535},'internal_tls':{'fingerprint':fingerprint,'phase':internal.get('phase'),'desired_fingerprint':internal.get('fingerprint'),'runtime_verified':internal.get('runtime_verified',False) and not drift,'not_after':internal.get('info',{}).get('not_after'),'drift':drift},'identity':{'id':settings['node_id'],'site':settings['site'],'ip':settings['node_ip']},'data_root':str(self.root),
            'cluster':{'configured':bool(manifest),'status':cluster,'deployment_id':(manifest or desired or {}).get('deployment_id'),'generation':(manifest or desired or {}).get('generation'), 'origin':(manifest or desired or {}).get('controller_origin',settings['controller_origin']),'nodes':[{key:m.get(key) for key in ('id','site','ip','role')} for m in (manifest or desired or {}).get('controller_members',[])], 'voters':[{key:m[key] for key in ('id','site','ip')} for m in (manifest or desired or {}).get('voters',[])], 'cluster_password_configured':bool((self.root/'config/controller/cluster-password').exists()),'replication_password_configured':bool((manifest or {}).get('secrets',{}).get('replication'))},
            'services':[{'id':name,'name':{'database':'PostgreSQL 16 / Patroni','etcd':'etcd quorum','router':'TLS router','controller':'Prṛthak controller'}[name],'state':states.get(name,'stopped'),'enabled':name in self.enabled(),'can_restart':True,'can_stop':True} for name in SERVICES],
            'routing':{'mode':'site_affinity','preferred_controller_url':routing.get('preferred_controller_url',settings['controller_origin']),'fallback_controller_url':routing.get('fallback_controller_url'),'site':settings['site'],'failover_state':'unverified','pools':[(m.get('id'),m.get('site')) for m in routing.get('controller_members',[])]},
            'health':health,'replication_state':'rotation_pending' if rotation and rotation['phase'] not in ('finalized','aborted') else 'configured' if manifest else 'not_configured','replication_rotation':{key:rotation[key] for key in ('id','phase','role_change_intent','generation') if key in rotation} if rotation else None,'pending_changes':state.get('pending_changes',[]),'configuration_pending':bool(state.get('configuration_pending')),'blockers':blockers,'acceptance_gate':'Native watchdog reset, quorum/site partitions and real site-loss recovery remain required before production'}
    def render(self,router_only=False):
        root=self.root;settings=self.installed;manifest=self.manifest();routing=manifest or self.desired() or {};role=(manifest or {}).get('local_node',{}).get('role','management')
        if not router_only:
            prepared=database_runtime_settings(root,settings)
            if prepared!=settings:
                atomic(root/'config/installed.json',prepared);self.installed=settings=prepared
        channels=self.channel_ports()
        private_dir(root/'runtime')
        for name,uid in ((('router',10003),) if router_only else (('controller',10001),('database',999),('etcd',10002),('router',10003))):
            private_dir(root/name,uid);private_dir(root/'config'/name,uid)
        controller_settings=load(root/'config/controller/settings.json') if not router_only else None
        if controller_settings:
            controller_settings['environment']['PRTHAK_APPLIANCE_DATA_ROOT']=str(root)
            controller_settings['site']=settings['site'];controller_settings['environment']['PRTHAK_APPLIANCE_SITE']=settings['site']
            atomic(root/'config/controller/settings.json',controller_settings,owner=10001)
        pki=manifest.get('pki') if manifest and not router_only else None
        if pki:
            for name,uid in (('database',999),('etcd',10002),('router',10003)):
                for filename,key in (('ca.pem','ca'),('node.pem','certificate'),('node-key.pem','private_key')):atomic(root/'config'/name/filename,pki[key],owner=uid)
            atomic(root/'config/router/client.pem',pki['certificate']+'\n'+pki['private_key'],owner=10003)
        if manifest and not router_only:
            node=manifest['local_node']
            etcd={'name':node['id'],'data-dir':'/etcd-data','listen-client-urls':'https://0.0.0.0:2379','advertise-client-urls':'https://'+node['ip']+':2379','listen-peer-urls':'https://0.0.0.0:2380','initial-advertise-peer-urls':'https://'+node['ip']+':2380','initial-cluster':','.join(v['id']+'=https://'+v['ip']+':2380' for v in manifest['voters']),'initial-cluster-token':'prthak-'+manifest['deployment_id'],'initial-cluster-state':'new','tls-min-version':'TLS1.2','client-transport-security':{'cert-file':'/config/node.pem','key-file':'/config/node-key.pem','trusted-ca-file':'/config/ca.pem','client-cert-auth':True},'peer-transport-security':{'cert-file':'/config/node.pem','key-file':'/config/node-key.pem','trusted-ca-file':'/config/ca.pem','client-cert-auth':True}}
            atomic(root/'config/etcd/etcd.json',etcd,owner=10002)
            atomic(root/'config/database/patroni.json',render_patroni(manifest,load(root/'manager/network-sources.json',[]),load(root/'manager/recovery-database-aliases.json',[])),owner=999)
            atomic(root/'config/database/roles.json',{'database':manifest['database'],'secrets':manifest['secrets']},owner=999)
        # L4 passthrough retains dashboard and endpoint TLS/client certificates.
        override=load(root/'config/web-tls.json')
        web_ca=routing.get('controller_ca') or (root/'config/controller/pki/ca.pem').read_text()
        if override:web_ca+='\n'+override['certificate_chain']
        atomic(root/'config/router/controller-ca.pem',web_ca,owner=10003)
        lines=['global','  log stdout format raw local0','defaults','  mode tcp','  timeout connect 5s','  timeout client 90s','  timeout server 90s','frontend controllers','  bind :8787','  default_backend controller_sites','backend controller_sites','  balance leastconn','  option httpchk','  http-check connect ssl','  http-check send meth GET uri /readyz ver HTTP/1.1 hdr Host '+urlsplit(settings['controller_origin']).hostname,'  http-check expect status 200']
        host=(override or {}).get('server_name') or routing.get('controller_tls_server_name') or (urlsplit(routing['controller_origin']).hostname if routing else 'localhost')
        preferred=urlsplit(routing.get('preferred_controller_url') or '').hostname
        fallback=urlsplit(routing.get('fallback_controller_url') or '').hostname
        routes=[{'id':'local','ip':settings['node_ip'],'site':settings['site'],'target':'controller:8787','verifyhost':host}]
        routes.extend({'id':m['id'],'ip':m['ip'],'site':m.get('site'),'target':m['ip']+':'+str(m.get('backend_port',settings['controller_backend_port'])),'verifyhost':m.get('tls_server_name',m['ip'])} for m in routing.get('controller_members',[]) if m['id']!=settings['node_id'])
        if preferred in (host,urlsplit(settings['controller_origin']).hostname,urlsplit(routing.get('controller_origin','')).hostname):preferred=settings['node_ip']
        routes.sort(key=lambda r:(0 if r['ip']==preferred else 1 if r['ip']==fallback else 2 if r['site']==settings['site'] else 3,r['id']))
        for route in routes:
            backup=route['ip']!=preferred if preferred else route['site']!=settings['site']
            lines.append('  server '+route['id']+' '+route['target']+' check check-ssl verify required ca-file /config/controller-ca.pem verifyhost '+route['verifyhost']+' check-sni '+route['verifyhost']+(' backup' if backup else ''))
        for channel,internal,backend in (('control',8788,8796),('discovery',8789,8797)):
            lines+=['frontend agent_'+channel,'  bind :'+str(internal),'  default_backend controller_'+channel+'_sites',
                    'backend controller_'+channel+'_sites','  balance leastconn','  option httpchk',
                    '  http-check connect ssl','  http-check send meth GET uri /readyz ver HTTP/1.1 hdr Host '+host,'  http-check expect status 200']
            for route in routes:
                backup=route['ip']!=preferred if preferred else route['site']!=settings['site']
                target='controller:'+str(internal) if route['id']=='local' else route['ip']+':'+str(backend)
                lines.append('  server '+route['id']+' '+target+' check check-ssl verify required ca-file /config/controller-ca.pem verifyhost '+route['verifyhost']+' check-sni '+route['verifyhost']+(' backup' if backup else ''))
        if manifest:
            lines+=['frontend postgres_writer','  bind :5433','  default_backend postgres_primary','backend postgres_primary','  option httpchk','  http-check connect port 8008 ssl','  http-check send meth GET uri /primary ver HTTP/1.1 hdr Host localhost','  http-check expect status 200']
            for voter in manifest['voters']:lines.append('  server '+voter['id']+' '+voter['ip']+':5432 check check-ssl verify required ca-file /config/ca.pem crt /config/client.pem verifyhost '+voter.get('tls_server_name',voter['ip'])+' check-sni '+voter.get('tls_server_name',voter['ip']))
        atomic(root/'config/router/haproxy.cfg','\n'.join(lines)+'\n',owner=10003)
        if router_only:return
        def bind(source,target,read_only=False):return {'type':'bind','source':str(source),'target':target,'read_only':read_only,'bind':{'create_host_path':False,'selinux':'z'}}
        common={'restart':'unless-stopped','security_opt':['no-new-privileges:true'],'cap_drop':['ALL'],'labels':{'io.prthak.appliance.id':settings['appliance_id']},'tmpfs':['/tmp:rw,noexec,nosuid,size=128m']}
        if 'router' in settings.get('images', {}):
            common['pull_policy'] = 'never'
        compose={'services':{
            'controller':{**common,'image':settings.get('images',{}).get('controller',CONTROLLER_IMAGE),'user':'10001:10001','ports':[settings['bind_ip']+':'+str(settings['controller_backend_port'])+':8787',settings['bind_ip']+':8796:8788',settings['bind_ip']+':8797:8789'],'volumes':[bind(root/'controller','/data'),bind(root/'config/controller','/run/prthak-bootstrap',True),bind('/run/prthak-appliance','/run/prthak-appliance',True)],'read_only':True},
            'router':{**common,'image':settings.get('images',{}).get('router',ROUTER_IMAGE),'user':'10003:10003','command':['haproxy','-W','-db','-f','/config/haproxy.cfg'],'ports':[settings['bind_ip']+':'+str(settings['controller_port'])+':8787',settings['bind_ip']+':'+str(channels['control'])+':8788',settings['bind_ip']+':'+str(channels['discovery'])+':8789',settings['bind_ip']+':'+str(settings['database_router_port'])+':5433'],'volumes':[bind(root/'config/router','/config',True)],'read_only':True},
            'etcd':{**common,'image':settings.get('images',{}).get('etcd',ETCD_IMAGE),'user':'10002:10002','profiles':['database'],'command':['/usr/local/bin/etcd','--config-file=/config/etcd.json'],'ports':[settings['bind_ip']+':2379:2379',settings['bind_ip']+':2380:2380'],'volumes':[bind(root/'etcd','/etcd-data'),bind(root/'config/etcd','/config',True)],'read_only':True},
            'database':{**common,'image':settings.get('images',{}).get('database',DATABASE_IMAGE),'user':'999:999','profiles':['database'],'ports':[settings['bind_ip']+':5432:5432',settings['bind_ip']+':8008:8008'],'volumes':[bind(root/'database','/var/lib/postgresql/data'),bind(root/'config/database','/config',True)],'devices':['/dev/watchdog0:/dev/watchdog0:rwm'],'stop_grace_period':'90s','read_only':True}}}
        agent_releases = root/'runtime/agent-releases'
        if agent_releases.exists() or agent_releases.is_symlink():
            protected_release_directory(agent_releases)
            compose['services']['controller']['volumes'].append(bind(agent_releases, '/run/prthak-agent-releases', True))
        atomic(root/'runtime/compose.json',compose)
    def _watchdog(self):
        value=self.manifest() or {}; approved=value.get('watchdog',{}).get('approved') is True
        try:
            info=Path('/dev/watchdog0').stat()
            if not approved or not stat.S_ISCHR(info.st_mode):raise OSError()
            device=Path('/sys/class/watchdog/watchdog0/dev').read_text().strip()
            identity=Path('/sys/class/watchdog/watchdog0/identity').read_text().strip().lower()
            if device!=str(os.major(info.st_rdev))+':'+str(os.minor(info.st_rdev)) or not identity or any(word in identity for word in ('software','softdog','dummy')):raise OSError()
            current=Path('/sys/class/watchdog/watchdog0/state').read_text().strip()
            if current=='active' and self.engine.states().get('database')!='running':raise OSError()
        except OSError:raise Blocked('Database start requires an approved available native watchdog0; no software or emulated bypass is installed') from None
        os.chown('/dev/watchdog0',999,999);os.chmod('/dev/watchdog0',0o600)
    @staticmethod
    def _leaf_fingerprint(certificate):
        value=re.search(r'-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----',certificate)
        if not value:raise Blocked('A complete PEM node certificate is required')
        return hashlib.sha256(ssl.PEM_cert_to_DER_cert(value.group())).hexdigest()
    def _assert_internal_idle(self):
        record=load(self.root/'manager/internal-tls.json')
        if record and record['phase'] not in ('committed','aborted','rolled_back','superseded'):raise Blocked('Resolve the staged internal identity transaction before another appliance change')
    def _assert_restoration_idle(self):
        record=load(self.root/'manager/restore-databases.json')
        if record and record['phase'] not in ('finalized','aborted'):raise Blocked('Complete the reviewed database recovery before changing appliance services or identity')
    def _assert_public_port_idle(self):
        record=load(self.root/'manager/public-port.json')
        if record and record['phase'] not in ('committed','aborted'):raise Blocked('Finish or abort the reviewed public-port transaction before another appliance mutation')
    def _assert_controller_configuration_idle(self):
        record=load(self.root/'manager/controller-config.json')
        if record and record['phase'] not in ('applied','rolled_back'):raise Blocked('Resolve the interrupted controller configuration before another appliance mutation')
        origin=load(self.root/'manager/origin-bootstrap.json')
        if origin and origin['phase'] not in ('applied','rolled_back'):raise Blocked('Resolve the interrupted initial origin setup before another appliance mutation')
    def _controller_configuration_material(self):
        override=load(self.root/'config/web-tls.json')
        chain=override['certificate_chain'] if override else (self.root/'config/controller/pki/controller.pem').read_text()
        name=override['server_name'] if override else urlsplit(self.installed['controller_origin']).hostname
        return {'chain':chain+'\n'+(self.root/'config/router/controller-ca.pem').read_text(),
                'name':name,'fingerprint':self._leaf_fingerprint(chain)}
    def _controller_configuration_probe(self,record,previous=False):
        material=record['tls'];expected=record['previous_settings'] if previous else record['desired_settings']
        current,secret,_=self._controller_configuration_snapshot()
        expected_secret=record['previous_secret_sha256'] if previous else record['desired_secret_sha256']
        if current!=expected or (hashlib.sha256(secret.encode()).hexdigest() if secret else '')!=expected_secret:raise Blocked('Managed controller configuration no longer matches this exact transaction')
        for port in (self.installed['controller_backend_port'],self.installed['controller_port']):
            self._web_probe(material['chain'],material['name'],port,material['fingerprint'],path='/healthz')
        context=ssl.create_default_context(cadata=material['chain'])
        address=self.installed['bind_ip'] if self.installed['bind_ip']!='0.0.0.0' else self.installed['node_ip']
        with socket.create_connection((address,self.installed['controller_backend_port']),timeout=5) as transport:
            with context.wrap_socket(transport,server_hostname=material['name']) as tls:
                if hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()!=material['fingerprint']:raise Blocked('Controller configuration TLS identity changed')
                tls.sendall(('GET /api/v1/auth/config HTTP/1.1\r\nHost: '+material['name']+'\r\nConnection: close\r\n\r\n').encode())
                response=http.client.HTTPResponse(tls);response.begin();raw=response.read(65537)
                if response.status!=200 or len(raw)>65536:raise Blocked('Controller authentication configuration read-back failed')
                actual=json.loads(raw)
        # The public auth status now includes local and SAML providers. This
        # operation verifies only its reviewed Entra environment, independently
        # of the availability of local password accounts.
        actual=actual.get('entra',actual)
        if not isinstance(actual,dict):raise Blocked('Controller returned an invalid Entra configuration status')
        environment=expected['environment']
        if previous and 'previous_effective_auth' not in record:record['previous_effective_auth']=actual
        if previous and record.get('previous_effective_auth') is not None:
            prior=record['previous_effective_auth'];prior=prior.get('entra',prior);environment={key:prior.get(field) or '' for field,key in (('tenant_id','SEG_ENTRA_TENANT_ID'),('client_id','SEG_ENTRA_CLIENT_ID'),('redirect_uri','SEG_ENTRA_REDIRECT_URI'))}
        if bool(actual.get('configured'))!=bool(environment.get('SEG_ENTRA_TENANT_ID')) or any(actual.get(field)!=(environment.get(key) or None) for field,key in (('tenant_id','SEG_ENTRA_TENANT_ID'),('client_id','SEG_ENTRA_CLIENT_ID'),('redirect_uri','SEG_ENTRA_REDIRECT_URI'))):
            raise Blocked('The restarted controller did not load the reviewed authentication configuration')
        self._verify_channel_listeners(record,previous=previous)
    def _wait_controller_configuration(self,record,previous=False):
        deadline=time.monotonic()+getattr(self,'_controller_configuration_probe_budget',60)
        while True:
            try:self._controller_configuration_probe(record,previous);return
            except (OSError,ValueError,Blocked,http.client.HTTPException):
                if time.monotonic()>=deadline:raise Blocked('Controller TLS/database/authentication readiness could not be verified') from None
                time.sleep(.25)
    def _controller_configuration_result(self,record):
        applied=record['phase']=='applied'
        return {'phase':'controller_config_applied' if applied else 'controller_config_rolled_back','verified':True,
                'applied':applied,'rolled_back':not applied,'binding_digest':record['binding_digest'],
                'configuration_digest':self._controller_configuration_snapshot()[2],'revision':self.state()['revision']}
    def _rollback_controller_configuration(self,record):
        path=self.root/'manager/controller-config.json'
        try:
            atomic(self.root/'config/controller/settings.json',record['previous_settings'],owner=10001)
            secret=self.root/'config/controller/entra-client-secret'
            if record['previous_secret'] is None:secret.unlink(missing_ok=True)
            else:atomic(secret,record['previous_secret']+'\n',owner=10001)
            self.render()
            self.engine.compose(['up','-d','--no-deps','--force-recreate','controller','router'])
            self._wait_controller_configuration(record,True)
            atomic(self.root/'manager/state.json',record['previous_state'])
            record['phase']='rolled_back';atomic(path,record)
        except Exception:
            record['phase']='rollback_failed';atomic(path,record)
            raise Blocked('Controller configuration rollback is unverified; resolve recovery before another change') from None
    def recover_controller_configuration(self):
        record=load(self.root/'manager/controller-config.json')
        if record and record['phase'] not in ('applied','rolled_back'):
            if record.get('appliance_id')!=self.installed['appliance_id']:raise Blocked('Controller configuration recovery belongs to another appliance')
            self._rollback_controller_configuration(record)
    def controller_configuration(self,body):
        allowed={'action','request_id','operation_id','expected_revision','expected_config_digest','environment','client_secret','candidate_login_verified','candidate_binding_digest','binding_salt','provider_epoch','provider_change','profile_convergence','rollback_operation','acknowledge_agent_aliases'}
        if not isinstance(body,dict) or set(body)-allowed:raise Blocked('Only fixed controller provider/runtime settings are accepted')
        if 'acknowledge_agent_aliases' in body and type(body['acknowledge_agent_aliases']) is not bool:raise Blocked('Agent listener alias acknowledgement must be boolean')
        identifier=body.get('operation_id');environment=body.get('environment');secret=body.get('client_secret','')
        if not isinstance(identifier,str) or not JOB.fullmatch(identifier) or isinstance(body.get('expected_revision'),bool) or not isinstance(body.get('expected_revision'),int) or not isinstance(body.get('expected_config_digest'),str) or not re.fullmatch('[a-f0-9]{64}',body['expected_config_digest']):raise Blocked('An exact reviewed controller configuration identity and revision are required')
        if not isinstance(environment,dict) or set(environment)-set((*AUTH_PUBLIC,*RUNTIME_PUBLIC)) or any(not isinstance(value,str) or len(value)>4096 or '\x00' in value for value in environment.values()) or not isinstance(secret,str) or len(secret)>16384 or '\x00' in secret or secret!=secret.strip():raise Blocked('Controller settings must use the bounded fixed schema')
        if not isinstance(body.get('binding_salt',''),str) or body.get('binding_salt') and not re.fullmatch('[a-f0-9]{64}',body['binding_salt']):raise Blocked('A protected random configuration binding is required')
        if not isinstance(body.get('provider_epoch',''),str) or body.get('provider_epoch') and not JOB.fullmatch(body['provider_epoch']):raise Blocked('The provider authority epoch is invalid')
        path=self.root/'manager/controller-config.json';record=load(path)
        if body.get('rollback_operation') is True:
            if not record or record['id']!=identifier:
                if record and record.get('phase') not in ('applied','rolled_back'):raise Blocked('An unrelated controller transaction prevents rollback')
                atomic(self.root/'manager/controller-config-history'/identifier,{'id':identifier,'phase':'rolled_back','rollback_fence':True,'appliance_id':self.installed['appliance_id']})
                return {'phase':'controller_config_unmodified','verified':True,'applied':False,'rolled_back':True}
            if record['phase']!='rolled_back':self._rollback_controller_configuration(record)
            self._wait_controller_configuration(record,True)
            return self._controller_configuration_result(record)
        binding=controller_configuration_binding(body)
        if record and record['id']==identifier:
            if record['binding_digest']!=binding:raise Blocked('Controller operation ID belongs to another reviewed payload')
            if record['phase'] not in ('applied','rolled_back'):self.recover_controller_configuration();record=load(path)
            self._wait_controller_configuration(record,record['phase']=='rolled_back')
            return self._controller_configuration_result(record)
        self._assert_controller_configuration_idle();self._assert_public_port_idle();self._assert_restoration_idle();self._assert_internal_idle()
        if (self.root/'manager/controller-config-history'/identifier).exists():raise Blocked('An older controller configuration operation cannot replace a newer generation')
        previous,previous_secret,fingerprint=self._controller_configuration_snapshot();state=self.state()
        if body['expected_revision']!=state['revision'] or body['expected_config_digest']!=fingerprint:raise Blocked('Controller configuration changed; create a fresh review')
        old_auth={key:value for key,value in previous.get('environment',{}).items() if key in AUTH_PUBLIC and value}
        desired_auth={key:value for key,value in environment.items() if key in AUTH_PUBLIC and value}
        configured=bool(old_auth.get('SEG_ENTRA_TENANT_ID'))
        migration=body.get('provider_change') is True or body.get('profile_convergence') is True
        proof=body.get('candidate_login_verified') is True and body.get('candidate_binding_digest')==binding
        if migration and (not proof or not secret or not desired_auth.get('SEG_ENTRA_TENANT_ID')):raise Blocked('The exact reviewed provider/convergence login must be verified before activation')
        if body.get('provider_change') is True and not body.get('provider_epoch'):raise Blocked('Provider migration requires its shared authority epoch')
        if configured and (desired_auth!=old_auth or secret) and not migration:raise Blocked('Configured provider changes require the exact independently reviewed migration')
        initial=not configured and bool(desired_auth) and not migration
        if initial:
            if self.manifest():raise Blocked('Initial Entra setup must finish before shared cluster activation')
            if not secret or not desired_auth.get('SEG_BOOTSTRAP_SUPER_ADMIN_OID') or not proof:raise Blocked('The exact candidate Entra Super Admin login must be verified before activation')
            if (self.root/'config/controller/entra-client-secret').exists():raise Blocked('An unreferenced provider secret must be preserved for explicit recovery')
        elif secret and not migration:raise Blocked('A provider secret requires its verified provider review')
        request={key:value for key,value in environment.items() if value}
        desired_secret=secret if migration or initial else previous_secret
        if configured or initial or migration:request['SEG_ENTRA_CLIENT_SECRET']=desired_secret
        validated=self.engine.validate_initial_environment(request)
        if validated.get('validated') is not True or not isinstance(validated.get('environment'),dict):raise Blocked('Bundled controller settings validation did not succeed')
        public=validated['environment']
        if set(public)-set((*AUTH_PUBLIC,*RUNTIME_PUBLIC,'SEG_ENTRA_CLIENT_SECRET_FILE')) or 'SEG_ENTRA_CLIENT_SECRET' in public:raise Blocked('Bundled validator returned an unexpected provider field')
        if not previous.get('node_id') or not previous.get('environment'):raise Blocked('Installed controller configuration is unavailable')
        rotation=load(self.root/'manager/rotation.json')
        if state.get('configuration_pending') or rotation and rotation['phase'] not in ('finalized','aborted'):raise Blocked('Finish the pending appliance configuration or replication rotation first')
        if any(self.engine.states().get(service)!='running' for service in ('controller','router')):raise Blocked('Start the existing controller/router before applying reviewed settings')
        self.validate_channel_configuration(environment)
        desired=copy.deepcopy(previous);desired['environment']={key:value for key,value in previous['environment'].items() if key not in (*AUTH_PUBLIC,*RUNTIME_PUBLIC,'SEG_ENTRA_CLIENT_SECRET_FILE')};desired['environment'].update(public)
        if initial or migration:desired['environment']['PRTHAK_GUI_PROVIDER_MANAGED']='1'
        if body.get('provider_epoch'):desired['environment']['PRTHAK_PROVIDER_EPOCH']=body['provider_epoch']
        record_new={'id':identifier,'appliance_id':self.installed['appliance_id'],'phase':'prepared','binding_digest':binding,
                    'previous_settings':previous,'previous_secret':previous_secret,'previous_secret_sha256':hashlib.sha256(previous_secret.encode()).hexdigest() if previous_secret else '',
                    'desired_secret_sha256':hashlib.sha256(desired_secret.encode()).hexdigest() if desired_secret else '',
                    'previous_state':state,'desired_settings':desired,'tls':self._controller_configuration_material()}
        self._controller_configuration_probe(record_new,True)
        if record:atomic(self.root/'manager/controller-config-history'/record['id'],record)
        atomic(path,record_new);record=record_new
        try:
            record['phase']='applying';atomic(path,record)
            if initial or migration:atomic(self.root/'config/controller/entra-client-secret',desired_secret+'\n',owner=10001)
            atomic(self.root/'config/controller/settings.json',desired,owner=10001)
            self.render()
            self.engine.compose(['up','-d','--no-deps','--force-recreate','controller','router'])
            self._wait_controller_configuration(record)
            record['phase']='committing';atomic(path,record)
            atomic(self.root/'manager/state.json',{**state,'revision':state['revision']+1,'last_controller_configuration':identifier})
            record['phase']='applied';atomic(path,record)
            return self._controller_configuration_result(record)
        except Exception:
            self._rollback_controller_configuration(record)
            return self._controller_configuration_result(record)
    @staticmethod
    def _public_port_result(record,phase,**fields):
        binding=record['binding']
        return {'phase':phase,'binding_digest':record['binding_digest'],'current_port':binding['old_port'],'proposed_port':binding['new_port'],'bind_address':binding['bind_address'],**fields}
    @staticmethod
    def _public_port_env(previous,port):
        result=[];replaced=False
        for line in (previous or '').splitlines():
            if line.partition('=')[0].strip()=='CONTROLLER_PORT':
                if replaced:raise Blocked('Ambiguous public-port export requires explicit review')
                result.append('CONTROLLER_PORT='+str(port));replaced=True
            else:result.append(line)
        if not replaced:result.append('CONTROLLER_PORT='+str(port))
        return '\n'.join(result)+'\n'
    def _public_port_publications(self,port):
        channels=self.channel_ports(management_port=port);address=self.installed['bind_ip']
        return [address+':'+str(channels['management'])+':8787',
                address+':'+str(channels['control'])+':8788',
                address+':'+str(channels['discovery'])+':8789',
                address+':'+str(self.installed['database_router_port'])+':5433']
    def _public_port_probe(self,record,old=False):
        binding=record['binding'];port=binding['old_port'] if old else binding['new_port']
        if record.get('cancellation_only'):expected=record.get('cancelled_compose')
        elif old:expected=record.get('previous',{}).get('compose')
        else:expected=record.get('candidate_compose')
        if expected is None or load(self.root/'runtime/compose.json')!=expected:raise Blocked('The exact reviewed publication and its unchanged agent channels are required for readback')
        for attempt in range(8):
            try:self._web_probe(record['trust'],binding['server_name'],port,binding['expected_fingerprint']);return
            except (Blocked,OSError,ValueError):
                if attempt==7:raise
                time.sleep(1)
    def _cancel_unseen_public_port(self,identifier,binding,fingerprint):
        # A lost PREPARE request can arrive after its caller requests abort.
        # Retain a separate immutable cancellation fence; do not replace the
        # previous committed journal or any publication/configuration state.
        if binding['old_port']!=self.installed['controller_port']:raise Blocked('Current publication differs from the unseen operation; review its actual state')
        for key in ('old_port','new_port'):
            if not isinstance(binding[key],int) or isinstance(binding[key],bool) or not 1<=binding[key]<=65535:raise Blocked('A valid reviewed port binding is required for cancellation')
        if not isinstance(binding['expected_fingerprint'],str) or not re.fullmatch('[0-9a-f]{64}',binding['expected_fingerprint']) or not isinstance(binding['server_name'],str) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,252}',binding['server_name']):raise Blocked('Exact old TLS identity is required before cancelling an uncertain operation')
        origin(binding['controller_origin'])
        compose=load(self.root/'runtime/compose.json') or {}
        expected=self._public_port_publications(binding['old_port'])
        if compose.get('services',{}).get('router',{}).get('ports')!=expected:raise Blocked('The exact old owned publication is not available for verified cancellation')
        directory=self.root/'manager/public-port-cancelled'
        if sum(1 for _ in directory.glob('*'))>=1024:raise Blocked('Retained public-port cancellation bound is full; explicit protected-state review is required')
        record={'id':identifier,'phase':'aborted','binding':binding,'binding_digest':fingerprint,'cancellation_only':True,'cancelled_compose':compose,'rollback_verified':True,'trust':(self.root/'config/router/controller-ca.pem').read_text()}
        self._public_port_probe(record,old=True);atomic(directory/identifier,record)
        return self._public_port_result(record,'aborted',rolled_back=True,verified=True,applied_port=binding['old_port'])
    def _rollback_public_port(self,record):
        path=self.root/'manager/public-port.json';previous=record['previous'];current=load(self.root/'runtime/compose.json')
        try:
            if current not in (previous['compose'],record['candidate_compose']):raise Blocked('Unmanaged Compose changes conflict with the public-port rollback')
            installed=load(self.root/'config/installed.json')
            if installed not in (previous['installed'],record['candidate_installed']):raise Blocked('Installed identity changed outside the public-port transaction')
            state=self.state();base=record['binding']['base_revision']
            if state['revision']!=base and not (state['revision']==base+1 and state.get('last_public_port_operation')==record['id']):raise Blocked('Manager revision changed outside the public-port transaction')
            old_settings=previous['settings'];new_settings={**old_settings,'public_port':record['binding']['new_port']} if old_settings else None
            if load(self.root/'config/controller/settings.json') not in (old_settings,new_settings):raise Blocked('Unmanaged settings changes conflict with rollback')
            if load(self.root/'config/application-port.json') not in (previous['application'],record['candidate_application']):raise Blocked('Unmanaged public-port metadata conflicts with rollback')
            current_env=(self.root/'config/gui-overrides.env').read_text() if (self.root/'config/gui-overrides.env').exists() else None
            if current_env not in (previous['env'],record['candidate_env']):raise Blocked('Unmanaged GUI export changes conflict with rollback')
            record['phase']='rolling_back';atomic(path,record)
            atomic(self.root/'runtime/compose.json',previous['compose']);atomic(self.root/'config/installed.json',previous['installed']);self.installed=previous['installed']
            for filename,key in (('controller/settings.json','settings'),('application-port.json','application'),('gui-overrides.env','env')):
                target=self.root/'config'/filename;value=previous[key]
                if value is None:target.unlink(missing_ok=True)
                else:atomic(target,value,owner=10001 if key=='settings' else None)
            self.engine.compose(['up','-d','--no-deps','--force-recreate','router'])
            self._public_port_probe(record,old=True)
            atomic(self.root/'manager/state.json',previous['state'])
            record['phase']='aborted';record['rollback_verified']=True;atomic(path,record)
        except Exception:
            record['phase']='rollback_failed';atomic(path,record)
            raise Blocked('The old public mapping could not be independently restored; resolve this exact transaction before another mutation') from None
    def recover_public_port(self,expired_only=False):
        record=load(self.root/'manager/public-port.json')
        if not record or record['phase'] in ('committed','aborted'):return
        if expired_only and record['deadline']>time.time():return
        if record['phase']=='prepared' and record['deadline']>time.time():return
        self._rollback_public_port(record)
    def public_port(self,body):
        allowed={'action','request_id','operation_id','phase','expected_revision','old_port','new_port','expected_fingerprint','server_name','controller_origin','origin_mode'}
        if not isinstance(body,dict) or set(body)-allowed or not isinstance(body.get('operation_id'),str) or not JOB.fullmatch(body['operation_id']) or body.get('phase') not in ('prepare','activate','verify','commit','abort'):raise Blocked('A fixed reviewed public-port transition is required')
        if not isinstance(body.get('expected_revision'),int) or isinstance(body['expected_revision'],bool) or body['expected_revision']<0:raise Blocked('A precise nonnegative manager revision is required')
        if body.get('origin_mode')!='preserve':raise Blocked('This action preserves the controller origin; Entra, agents and external load balancers require separate reviewed changes')
        self._assert_internal_idle();self._assert_restoration_idle();self.recover_web_tls();self.recover_public_port(expired_only=True)
        state=self.state();identifier=body['operation_id'];phase=body['phase'];path=self.root/'manager/public-port.json';record=load(path)
        self.channel_ports(management_port=body.get('new_port'))
        binding={'kind':'prthak-public-port-v1','operation_id':identifier,'appliance_id':self.installed['appliance_id'],'base_revision':body.get('expected_revision'),'old_port':body.get('old_port'),'new_port':body.get('new_port'),'bind_address':self.installed['bind_ip'],'expected_fingerprint':body.get('expected_fingerprint'),'server_name':body.get('server_name'),'controller_origin':body.get('controller_origin'),'origin_mode':'preserve'}
        fingerprint=digest(binding)
        cancelled=load(self.root/'manager/public-port-cancelled'/identifier)
        if cancelled:
            if cancelled['binding_digest']!=fingerprint:raise Blocked('Cancelled operation is bound to different reviewed settings')
            if phase!='abort':raise Blocked('This uncertain operation was cancelled; a late prepare cannot create a new publication')
            self._public_port_probe(cancelled,old=True)
            return self._public_port_result(cancelled,'aborted',rolled_back=True,verified=True,applied_port=binding['old_port'])
        if record and record['id']!=identifier:
            if record['phase'] not in ('committed','aborted'):raise Blocked('Resolve the previous public-port transition before reviewing another')
            if phase=='abort':return self._cancel_unseen_public_port(identifier,binding,fingerprint)
            if phase!='prepare':raise Blocked('A previous operation cannot mutate a newer public-port generation')
            atomic(self.root/'manager/public-port-history'/record['id'],record);record=None
        if not record and phase=='abort':return self._cancel_unseen_public_port(identifier,binding,fingerprint)
        if record and record['binding_digest']!=fingerprint:raise Blocked('Public-port operation is bound to different reviewed settings')
        if record and record['phase']=='committed':
            self._public_port_probe(record)
            return self._public_port_result(record,'committed',committed=True,verified=True,applied_port=binding['new_port'],revision=self.state()['revision'])
        if record and record['phase']=='aborted':
            if phase!='abort':raise Blocked('A rolled-back public-port approval cannot silently be retried; create a fresh review')
            self._public_port_probe(record,old=True)
            return self._public_port_result(record,'aborted',rolled_back=True,verified=True,applied_port=binding['old_port'])
        if not record:
            if phase!='prepare' or state['revision']!=body.get('expected_revision'):raise Blocked('Review the current manager revision before preparing this transition')
            effective=(self.manifest() or self.desired() or {}).get('controller_origin',self.installed['controller_origin'])
            if origin(body.get('controller_origin'))!=effective:raise Blocked('The reviewed controller origin changed')
            for key in ('old_port','new_port'):
                if not isinstance(body.get(key),int) or isinstance(body[key],bool) or not 1<=body[key]<=65535:raise Blocked('Public ports must be integers from 1 to 65535')
            reserved={22,2379,2380,5432,8008,self.installed['controller_backend_port'],self.installed['database_router_port']}
            if body['old_port']!=self.installed['controller_port'] or body['new_port']==body['old_port'] or body['new_port'] in reserved:raise Blocked('The old mapping is stale or the proposed public port collides with a protected service')
            if not isinstance(body.get('expected_fingerprint'),str) or not re.fullmatch('[0-9a-f]{64}',body['expected_fingerprint']) or not isinstance(body.get('server_name'),str) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,252}',body['server_name']):raise Blocked('The exact current public TLS name and fingerprint are required')
            if self.engine.states().get('router')!='running':raise Blocked('Start the current controller/router before reviewing a live public-port change')
            rotation=load(self.root/'manager/rotation.json')
            if rotation and rotation['phase'] not in ('finalized','aborted'):raise Blocked('Complete credential rotation before changing the public port')
            compose=load(self.root/'runtime/compose.json');expected=self._public_port_publications(body['old_port'])
            if compose.get('services',{}).get('router',{}).get('ports')!=expected:raise Blocked('The current public publication is ambiguous or unmanaged')
            self.engine.assert_public_port_free(self.installed['bind_ip'],body['new_port'])
            candidate=copy.deepcopy(compose);candidate['services']['router']['ports'][0]=self.installed['bind_ip']+':'+str(body['new_port'])+':8787'
            installed={**self.installed,'controller_port':body['new_port']}
            record={'id':identifier,'phase':'prepared','binding':binding,'binding_digest':fingerprint,'deadline':time.time()+300,'trust':(self.root/'config/router/controller-ca.pem').read_text(),'candidate_compose':candidate,'candidate_installed':installed,'previous':{'installed':copy.deepcopy(self.installed),'compose':compose,'state':state,'settings':load(self.root/'config/controller/settings.json'),'application':load(self.root/'config/application-port.json'),'env':(self.root/'config/gui-overrides.env').read_text() if (self.root/'config/gui-overrides.env').exists() else None}}
            if record['previous']['application'] is not None and not isinstance(record['previous']['application'],dict):raise Blocked('Existing public-port metadata needs explicit review')
            record['candidate_application']={**(record['previous']['application'] or {}),'schema_version':1,'mode':'appliance','port':binding['new_port'],'bind_address':binding['bind_address'],'origin_mode':'preserve','controller_origin':binding['controller_origin'],'operation_id':identifier}
            record['candidate_env']=self._public_port_env(record['previous']['env'],binding['new_port'])
            self._public_port_probe(record,old=True);atomic(path,record)
        if phase=='prepare':return self._public_port_result(record,'prepared',prepared=True)
        if phase=='abort':
            self._rollback_public_port(record)
            return self._public_port_result(record,'aborted',rolled_back=True,verified=True,applied_port=binding['old_port'])
        if phase=='activate':
            if record['phase'] not in ('prepared','activating','activated'):raise Blocked('Unexpected public-port activation phase')
            if load(self.root/'runtime/compose.json') not in (record['previous']['compose'],record['candidate_compose']):raise Blocked('Unmanaged Compose edits invalidate this transition')
            record['phase']='activating';atomic(path,record)
            try:
                atomic(self.root/'runtime/compose.json',record['candidate_compose']);self.engine.compose(['up','-d','--no-deps','--force-recreate','router'])
                record['phase']='activated';atomic(path,record)
                return self._public_port_result(record,'activated',activated=True)
            except Exception:
                self._rollback_public_port(record);raise Blocked('Candidate public publication failed; the verified original mapping was restored') from None
        if phase=='verify':
            if record['phase'] not in ('activated','verified'):raise Blocked('Activate the public mapping before verifying it')
            try:self._public_port_probe(record)
            except Exception:
                self._rollback_public_port(record);raise Blocked('Candidate TLS/name/readiness failed; the verified original mapping was restored') from None
            record['phase']='verified';atomic(path,record)
            return self._public_port_result(record,'verified',verified=True,tls_verified=True,readiness_verified=True,observed_port=binding['new_port'])
        if phase=='commit':
            if record['phase']!='verified' or load(self.root/'runtime/compose.json')!=record['candidate_compose'] or self.state()['revision']!=binding['base_revision']:raise Blocked('Exact verified publication is required before commit')
            try:
                self._public_port_probe(record);record['phase']='committing';atomic(path,record)
                self.installed=record['candidate_installed'];atomic(self.root/'config/installed.json',self.installed)
                settings=record['previous']['settings']
                if settings:settings={**settings,'public_port':binding['new_port']};atomic(self.root/'config/controller/settings.json',settings,owner=10001)
                atomic(self.root/'config/application-port.json',record['candidate_application'])
                atomic(self.root/'config/gui-overrides.env',record['candidate_env'])
                state={**state,'revision':binding['base_revision']+1,'last_public_port_operation':identifier};atomic(self.root/'manager/state.json',state)
                record['phase']='committed';atomic(path,record)
                return self._public_port_result(record,'committed',committed=True,verified=True,applied_port=binding['new_port'],revision=state['revision'])
            except Exception:
                self._rollback_public_port(record);raise Blocked('Public-port commit failed; the verified original configuration was restored') from None
        raise Blocked('Unsupported public-port phase')
    def restore_databases(self,body):
        self._assert_public_port_idle()
        allowed={'action','request_id','restore_id','phase','expected_revision','deployment_id','archive_sha256','target_epoch','fence_digest','all_writers_fenced','all_profile_acks'}
        if set(body)-allowed or not JOB.fullmatch(body.get('restore_id','')) or body.get('phase') not in ('prepare','create','verify','finalize'):raise Blocked('A fixed reviewed database recovery operation is required')
        if body.get('all_writers_fenced') is not True:raise Blocked('Every controller writer must acknowledge the exact durable recovery fence')
        self._assert_internal_idle();manifest=self.manifest();state=self.state();phase=body['phase'];identifier=body['restore_id']
        if not manifest or manifest['local_node']['role']!='database_voter':raise Blocked('Recovery database staging runs only on the fixed database voters')
        if body.get('deployment_id')!=manifest['deployment_id'] or not isinstance(body.get('target_epoch'),int) or isinstance(body['target_epoch'],bool) or body['target_epoch']<2 or any(not isinstance(body.get(key),str) or not re.fullmatch('[0-9a-f]{64}',body[key]) for key in ('archive_sha256','fence_digest')):raise Blocked('Recovery deployment, archive, fence and new epoch must be bound exactly')
        if phase=='finalize' and body.get('all_profile_acks') is not True:raise Blocked('Every controller must acknowledge its new protected profile before finalization')
        path=self.root/'manager/restore-databases.json';record=load(path)
        if record and record['id']!=identifier:
            if record['phase']!='finalized':raise Blocked('Resolve the existing reviewed database recovery first')
            atomic(self.root/'manager/restore-history'/record['id'],record);record=None
        binding={key:body[key] for key in ('restore_id','deployment_id','archive_sha256','target_epoch','fence_digest')}
        binding['source_databases']=record['binding']['source_databases'] if record else {kind:manifest['database'][kind+'_name'] for kind in ('metadata','traffic')}
        fingerprint=digest(binding);targets={kind:'prthak_restore_'+identifier+'_'+kind for kind in ('metadata','traffic')}
        if record and record['binding_digest']!=fingerprint:raise Blocked('Recovery identity is already bound to another archive/fence/epoch')
        if record and record['phase']=='finalized':return record['result']
        if not record:
            if phase!='prepare' or body.get('expected_revision')!=state['revision'] or body['target_epoch']<=state.get('restore_epoch',1):raise Blocked('Review a fresh higher recovery epoch before preparing')
            rotation=load(self.root/'manager/rotation.json')
            if rotation and rotation['phase'] not in ('finalized','aborted'):raise Blocked('Finish database credential rotation before recovery')
            inspected=self.engine.restore_database_helper({'action':'inspect','binding':binding})
            if not all(inspected.get(key) is True for key in ('targets_absent','source_fenced','owners_verified')) or inspected.get('binding_digest')!=fingerprint or inspected.get('database_names')!=targets:raise Blocked('Fresh source fences and empty target identities were not verified')
            record={'id':identifier,'phase':'preparing','binding':binding,'binding_digest':fingerprint,'database_names':targets,'base_revision':state['revision'],'source_database':copy.deepcopy(manifest['database']),'previous_patroni':load(self.root/'config/database/patroni.json')};atomic(path,record)
        def result(name,**flags):return {'phase':name,'binding_digest':fingerprint,'database_names':targets,**flags}
        if phase=='prepare':
            if record['phase'] in ('prepared','creating','created','verified'):return result('prepared',prepared=True,hba_reloaded=True)
            if record['phase']!='preparing':raise Blocked('Unexpected database recovery preparation phase')
            configuration=copy.deepcopy(record['previous_patroni']);candidate=copy.deepcopy(manifest)
            for kind,name in targets.items():candidate['database'][kind+'_name']=name
            additions=[rule for rule in render_patroni(candidate,load(self.root/'manager/network-sources.json',[]))['postgresql']['pg_hba'] if len(rule.split())>1 and rule.split()[1] in targets.values()]
            rules=configuration['postgresql']['pg_hba'];offset=next((index for index,rule in enumerate(rules) if rule.startswith('host all all ')),len(rules))
            configuration['postgresql']['pg_hba']=rules[:offset]+[rule for rule in additions if rule not in rules]+rules[offset:]
            atomic(self.root/'config/database/patroni.json',configuration,owner=999)
            self._internal_reload(['database']);record['phase']='prepared';atomic(path,record)
            return result('prepared',prepared=True,hba_reloaded=True)
        if phase=='create':
            if record['phase'] in ('created','verified'):return record['create_result']
            if record['phase'] not in ('prepared','creating'):raise Blocked('Prepare every voter before creating candidates')
            # Persist intent before SQL. Only an exactly named EMPTY candidate
            # may be adopted after a reply is lost between CREATE and COMMENT.
            record['phase']='creating';atomic(path,record)
            created=self.engine.restore_database_helper({'action':'create','binding':binding,'allow_empty_recovery':True})
            if created.get('not_primary') is True:return result('not_primary',not_primary=True,mutated=False)
            if not all(created.get(key) is True for key in ('created','empty','owners_verified')) or created.get('binding_digest')!=fingerprint or created.get('database_names')!=targets:raise Blocked('Empty restricted-owner recovery databases were not verified')
            record.update(phase='created',create_result=created);atomic(path,record);return created
        if phase in ('verify','finalize'):
            if record['phase'] not in ('prepared','creating','created','verified'):raise Blocked('Prepare the exact candidate identities before verification')
            verified=self.engine.restore_database_helper({'action':'verify','binding':binding})
            if not all(verified.get(key) is True for key in ('verified','marker_verified','new_connections')) or verified.get('binding_digest')!=fingerprint or verified.get('database_names')!=targets:raise Blocked('Fresh target schema/namespace/owner connections did not verify')
            record.update(phase='verified',verify_result=verified);atomic(path,record)
            if phase=='verify':return verified
            aliases=load(self.root/'manager/recovery-database-aliases.json',[])
            if record['source_database'] not in aliases:aliases.append(record['source_database'])
            atomic(self.root/'manager/recovery-database-aliases.json',aliases)
            for configuration,name in ((manifest,'manifest.json'),(self.desired(),'desired.json')):
                if configuration:
                    for kind,target in targets.items():configuration['database'][kind+'_name']=target
                    atomic(self.root/'config'/name,configuration)
            self.render();self._internal_reload(['database'])
            state['restore_epoch']=binding['target_epoch'];state['revision']=record['base_revision']+1;atomic(self.root/'manager/state.json',state)
            record.update(phase='finalized',result=result('finalized',finalized=True,verified=True,revision=state['revision'],original_databases_preserved=True));atomic(path,record)
            return record['result']
        raise Blocked('Unsupported fixed recovery phase')
    @staticmethod
    def _internal_old_valid(record):
        return bool(record['info'].get('previous_valid')) and bool(record['info'].get('previous_not_after')) and datetime.fromisoformat(record['info']['previous_not_after'])>datetime.now(timezone.utc)
    def _internal_files(self,certificate):
        for service,owner in (('database',999),('etcd',10002),('router',10003)):
            atomic(self.root/'config'/service/'node.pem',certificate,owner=owner)
        manifest=self.manifest();atomic(self.root/'config/router/client.pem',certificate+'\n'+manifest['pki']['private_key'],owner=10003)
    def _internal_reload(self,services):
        live=self.engine.states()
        if 'database' in services and live.get('database')=='running':
            self.engine.compose(['kill','--signal','SIGHUP','database'])
            self.engine.compose(['exec','-T','database','/usr/lib/postgresql/16/bin/pg_ctl','-D','/var/lib/postgresql/data','reload'])
        if 'router' in services and live.get('router')=='running':self.engine.compose(['up','-d','--no-deps','--force-recreate','router'])
    def _internal_verify(self,record,previous=False):
        fingerprint=record['previous_fingerprint'] if previous else record['fingerprint'];certificate=record['previous_certificate'] if previous else record['certificate_pem']
        directory=self.root/'manager/internal-tls-staging'/record['id'];private_dir(directory)
        manifest=self.manifest()
        for name,data in (('ca.pem',manifest['pki']['ca']),('node.pem',certificate),('node-key.pem',manifest['pki']['private_key'])):atomic(directory/name,data)
        verified=[]
        live=self.engine.states()
        for service,ports in (('etcd',[2379,2380]),('database',[5432,8008])):
            if service in record['services'] and live.get(service)=='running':
                result=self.engine.internal_tls_probe(service,ports,directory,manifest['local_node']['id'],fingerprint)
                if result.get('verified') is not True or result.get('fingerprint')!=fingerprint or result.get('ports')!=ports:raise Blocked('Fresh internal TLS fingerprint/read-back was not verified')
                verified.extend(ports)
        return verified
    def _internal_wait_verify(self,record,previous=False):
        # Patroni replaces its HTTPS listener asynchronously after SIGHUP.
        # Both forward verification and rollback must wait for the exact leaf.
        for attempt in range(8):
            try:return self._internal_verify(record,previous=previous)
            except (Blocked,OSError,ValueError):
                if attempt==7:raise
                time.sleep(1)
    def _internal_fail(self,record,path):
        if self._internal_old_valid(record):
            try:
                self._internal_files(record['previous_certificate']);self._internal_reload(record['services']);self._internal_wait_verify(record,previous=True)
                record['phase']='rolled_back';atomic(path,record)
                raise Blocked('Internal renewal failed; its previous valid identity was restored')
            except Blocked as error:
                if record['phase']=='rolled_back':raise
                record['phase']='rollback_failed';atomic(path,record)
                raise Blocked('Internal identity rollback needs recovery; no newer generation is allowed') from error
            except Exception:
                record['phase']='rollback_failed';atomic(path,record)
                raise Blocked('Internal identity rollback needs recovery; no newer generation is allowed') from None
        record['phase']='rollforward_pending';atomic(path,record)
        raise Blocked('The previous identity is expired; the new valid identity was retained for verified forward recovery')
    def internal_tls(self,body):
        self._assert_public_port_idle()
        self._assert_restoration_idle()
        identifier=body.get('operation_id');phase=body.get('phase');manifest=self.manifest();state=self.state()
        if not JOB.fullmatch(identifier or '') or phase not in ('prepare','activate','verify','commit','abort') or not manifest:raise Blocked('A fixed internal identity operation is required')
        path=self.root/'manager/internal-tls.json';record=load(path)
        fingerprint=self._leaf_fingerprint(body.get('certificate_pem',''))
        if record and record['id']!=identifier and record['phase'] not in ('committed','aborted','rolled_back'):
            if phase=='prepare' and datetime.fromisoformat(record['info']['not_after'])<=datetime.now(timezone.utc):
                record['phase']='superseded';atomic(self.root/'manager/internal-tls-history'/record['id'],record);record=None
            else:raise Blocked('Resolve the previous internal identity transaction before a newer generation')
        if record and record['id']==identifier and (record['fingerprint']!=fingerprint or record['generation']!=body.get('generation')):raise Blocked('Internal identity operation is bound to a different certificate/generation')
        if record and record['id']==identifier and record['phase']=='committed':return {'phase':'committed','fingerprint':fingerprint,'committed':True,'runtime_verified':record['runtime_verified'],'revision':state['revision']}
        if phase=='prepare':
            if record and record['id']==identifier:
                if record['phase'] in ('prepared','activated','verified','activating','rollforward_pending'):return {'phase':'prepared','fingerprint':fingerprint,'prepared':True}
                raise Blocked('Terminal internal identity operation cannot be replayed')
            if body.get('expected_revision')!=state['revision'] or body.get('expected_fingerprint')!=self._leaf_fingerprint(manifest['pki']['certificate']):raise Blocked('Internal identity review is stale')
            if not isinstance(body.get('generation'),int) or isinstance(body['generation'],bool) or body['generation']<manifest['generation']:raise Blocked('Internal identity generation is stale')
            rotation=load(self.root/'manager/rotation.json')
            if rotation and rotation['phase'] not in ('finalized','aborted'):raise Blocked('Finish database credential rotation before internal identity renewal')
            request={'ca':manifest['pki']['ca'],'certificate':body['certificate_pem'],'previous_certificate':manifest['pki']['certificate'],'node_id':manifest['local_node']['id'],'node_ip':manifest['local_node']['ip']}
            info=self.engine.internal_tls_validate(request)
            if info.get('fingerprint')!=fingerprint:raise Blocked('Internal identity validation did not bind the exact signed leaf')
            # Check the new public key against the unchanged local private key.
            directory=self.root/'manager/internal-tls-staging'/identifier;private_dir(directory)
            atomic(directory/'node.pem',body['certificate_pem']);atomic(directory/'node-key.pem',manifest['pki']['private_key'])
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(directory/'node.pem',directory/'node-key.pem')
            services=[name for name,value in self.engine.states().items() if name in ('database','etcd','router') and value=='running']
            record={'id':identifier,'phase':'prepared','fingerprint':fingerprint,'certificate_pem':body['certificate_pem'],'previous_certificate':manifest['pki']['certificate'],'previous_fingerprint':body['expected_fingerprint'],'generation':body['generation'],'base_revision':state['revision'],'services':services,'info':info,'runtime_verified':False}
            atomic(path,record)
            return {'phase':'prepared','fingerprint':fingerprint,'prepared':True,'old_valid':info.get('previous_valid',False)}
        if not record or record['id']!=identifier:raise Blocked('Prepare the matching internal identity before applying it')
        if phase=='abort':
            if record['phase']=='prepared':record['phase']='aborted';atomic(path,record);return {'phase':'aborted','fingerprint':fingerprint,'mutated':False}
            if not self._internal_old_valid(record):
                record['phase']='rollforward_pending';atomic(path,record);return {'phase':'rollforward_pending','fingerprint':fingerprint,'requires_rollforward':True}
            self._internal_files(record['previous_certificate']);self._internal_reload(record['services']);self._internal_wait_verify(record,previous=True)
            record['phase']='rolled_back';atomic(path,record);return {'phase':'rolled_back','fingerprint':fingerprint,'rolled_back':True}
        if phase=='activate':
            if record['phase'] not in ('prepared','activating','activated','rollforward_pending'):raise Blocked('Unexpected internal activation phase')
            if datetime.fromisoformat(record['info']['not_after'])<=datetime.now(timezone.utc):raise Blocked('The staged identity expired; obtain a fresh authenticated same-CA renewal')
            record['phase']='activating';atomic(path,record)
            try:self._internal_files(record['certificate_pem']);self._internal_reload(record['services'])
            except Exception:
                self._internal_fail(record,path)
            record['phase']='activated';atomic(path,record);return {'phase':'activated','fingerprint':fingerprint,'activated':True}
        if phase=='verify':
            if record['phase'] not in ('activated','verified','rollforward_pending'):raise Blocked('Activate the node identity before read-back')
            try:result=self._internal_wait_verify(record)
            except (Blocked,OSError,ValueError):self._internal_fail(record,path)
            required=[2379,2380,5432,8008] if manifest['local_node']['role']=='database_voter' else []
            runtime_verified=bool(required) and sorted(result)==sorted(required)
            record.update(phase='verified',runtime_verified=runtime_verified,verified_ports=result);atomic(path,record)
            return {'phase':'verified','fingerprint':fingerprint,'verified':True,'runtime_verified':runtime_verified,'ports':result}
        if phase=='commit':
            if record['phase']!='verified':raise Blocked('Fresh internal TLS read-back is required before committing')
            if state['revision']>record['base_revision']+1:raise Blocked('Local revision changed outside the internal TLS transaction')
            manifest['pki']['certificate']=record['certificate_pem'];atomic(self.root/'config/manifest.json',manifest)
            desired=self.desired()
            if desired:desired['pki']['certificate']=record['certificate_pem'];atomic(self.root/'config/desired.json',desired)
            state['revision']=record['base_revision']+1;atomic(self.root/'manager/state.json',state)
            record['phase']='committed';atomic(path,record);shutil.rmtree(self.root/'manager/internal-tls-staging'/identifier,ignore_errors=True)
            return {'phase':'committed','fingerprint':fingerprint,'committed':True,'runtime_verified':record['runtime_verified'],'revision':state['revision']}
        raise Blocked('Unsupported internal TLS phase')
    def _web_probe(self,chain,name,port,fingerprint,path='/readyz',expected=200):
        context=ssl.create_default_context(cadata=chain);context.minimum_version=ssl.TLSVersion.TLSv1_2
        address=self.installed['bind_ip'] if self.installed['bind_ip']!='0.0.0.0' else self.installed['node_ip']
        with socket.create_connection((address,port),timeout=5) as transport:
            with context.wrap_socket(transport,server_hostname=name) as tls:
                if hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()!=fingerprint:raise Blocked('Own HTTPS leaf fingerprint does not match the reviewed public certificate')
                tls.sendall(('GET '+path+' HTTP/1.1\r\nHost: '+name+'\r\nConnection: close\r\n\r\n').encode())
                response=http.client.HTTPResponse(tls);response.begin();response.read(65537)
                if response.status!=expected:raise Blocked('Own HTTPS readiness did not succeed through the required route')
    def recover_web_tls(self):
        path=self.root/'manager/web-tls-transaction.json';record=load(path)
        if not record or record['phase'] in ('verified','rolled_back'):return
        try:
            previous=record['previous_override']
            if previous is None:(self.root/'config/web-tls.json').unlink(missing_ok=True)
            else:atomic(self.root/'config/web-tls.json',previous)
            for name,text in record['previous_files'].items():atomic(self.root/'config/router'/name,text,owner=10003)
            if record['router_running']:self.engine.compose(['up','-d','--no-deps','--force-recreate','router'])
            else:self.engine.compose(['stop','--timeout','15','router'])
            record['phase']='rolled_back';atomic(path,record)
        except Exception:
            record['phase']='rollback_failed';atomic(path,record)
            raise Blocked('Prior public router TLS configuration could not be restored; no newer generation was attempted') from None
    def web_tls(self,body):
        self._assert_public_port_idle()
        self._assert_restoration_idle()
        self._assert_internal_idle()
        self.recover_web_tls()
        chain=body.get('certificate_chain');name=body.get('server_name')
        if not isinstance(chain,str) or not 1<=len(chain.encode())<=262144 or not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,252}',name):raise Blocked('A bounded public certificate chain and exact TLS server name are required')
        leaf=re.search(r'-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----',chain)
        if not leaf or 'PRIVATE KEY' in chain:raise Blocked('Only the reviewed public certificate/issuer chain is accepted; no private key belongs in this action')
        fingerprint=hashlib.sha256(ssl.PEM_cert_to_DER_cert(leaf.group())).hexdigest()
        # Restoring a CA-issued bootstrap leaf may supply only its public leaf;
        # retain already trusted public issuers. An unknown corporate issuer
        # still needs its complete chain and cannot be trusted by leaf pin alone.
        trust=chain+'\n'+(self.root/'config/router/controller-ca.pem').read_text()
        desired={'certificate_chain':chain,'server_name':name,'fingerprint_sha256':fingerprint};state=self.state();previous=load(self.root/'config/web-tls.json')
        if previous==desired:
            self._web_probe(trust,name,self.installed['controller_port'],fingerprint)
            return {'status':'verified','phase':'web_tls_verified','verified':True,'router_ready':True,'fingerprint_sha256':fingerprint,'server_name':name,'revision':state['revision'],'already_applied':True}
        if body.get('expected_revision')!=state['revision']:raise Blocked('Appliance revision changed before public router TLS activation')
        rotation=load(self.root/'manager/rotation.json')
        if rotation and rotation['phase'] not in ('finalized','aborted'):raise Blocked('Finish the pinned replication rotation before changing public router TLS')
        # The new child must actually be live before its router trust changes.
        self._web_probe(trust,name,self.installed['controller_backend_port'],fingerprint)
        record={'phase':'started','previous_override':previous,'previous_files':{value:(self.root/'config/router'/value).read_text() for value in ('haproxy.cfg','controller-ca.pem')},'router_running':self.engine.states().get('router')=='running','target_fingerprint':fingerprint,'revision':state['revision']}
        journal=self.root/'manager/web-tls-transaction.json';atomic(journal,record)
        try:
            atomic(self.root/'config/web-tls.json',desired);self.render(router_only=True)
            if record['router_running']:self.engine.compose(['exec','-T','router','haproxy','-c','-f','/config/haproxy.cfg'])
            else:self.engine.compose(['run','--rm','--no-deps','router','haproxy','-c','-f','/config/haproxy.cfg'])
            self.engine.compose(['up','-d','--no-deps','--force-recreate','router'])
            failure=None
            for _ in range(8):
                try:self._web_probe(trust,name,self.installed['controller_port'],fingerprint);failure=None;break
                except (OSError,ValueError,Blocked,ssl.SSLError) as error:failure=error;time.sleep(1)
            if failure:raise Blocked('Updated router TLS/hostname/fingerprint/readiness verification failed')
            state['revision']+=1;atomic(self.root/'manager/state.json',state)
            record['phase']='verified';atomic(journal,record)
            return {'status':'verified','phase':'web_tls_verified','verified':True,'router_ready':True,'fingerprint_sha256':fingerprint,'server_name':name,'revision':state['revision']}
        except Exception:
            self.recover_web_tls()
            raise Blocked('Public router TLS activation failed; its previous public configuration was restored') from None
    def _peer_json(self,address,port,path):
        context=ssl.create_default_context(cafile=str(self.root/'config/database/ca.pem'))
        context.load_cert_chain(self.root/'config/database/node.pem',self.root/'config/database/node-key.pem')
        connection=http.client.HTTPSConnection(address,port,context=context,timeout=3)
        try:
            connection.request('GET',path);reply=connection.getresponse();data=reply.read(65537)
            if reply.status!=200 or len(data)>65536:raise ValueError()
            value=json.loads(data)
            if not isinstance(value,dict):raise ValueError()
            return value
        finally:connection.close()
    def refresh_health(self):
        manifest=self.manifest()
        if not manifest:
            self.health_snapshot={'status':'waiting_for_voters','checked_at':time.time(),'quorum_healthy':False,'database_ready':False};return
        observations=[];primaries=[]
        for voter in manifest['voters']:
            item={'id':voter['id'],'ip':voter['ip'],'etcd_healthy':False,'postgres_running':False,'role':'unknown'}
            try:item['etcd_healthy']=self._peer_json(voter['ip'],2379,'/health').get('health') in (True,'true')
            except (OSError,ValueError,ssl.SSLError):pass
            try:
                postgres=self._peer_json(voter['ip'],8008,'/health');item.update(postgres_running=postgres.get('state')=='running',role=postgres.get('role','unknown'))
                if item['postgres_running'] and item['role'] in ('primary','master'):
                    peers=postgres.get('replication',[])
                    if not isinstance(peers,list):peers=[]
                    item['synchronous_replicas']=sum(isinstance(peer,dict) and peer.get('state')=='streaming' and peer.get('sync_state') in ('sync','quorum') for peer in peers);primaries.append(item)
            except (OSError,ValueError,ssl.SSLError):pass
            observations.append(item)
        quorum=sum(peer['etcd_healthy'] for peer in observations)>=2
        self.health_snapshot={'status':'observed','checked_at':time.time(),'quorum_healthy':quorum,'all_voters_healthy':all(peer['etcd_healthy'] for peer in observations),'primary_count':len(primaries),'database_ready':quorum and len(primaries)==1 and primaries[0]['synchronous_replicas']>=1,'nodes':observations}
    def _quorum(self):
        manifest=self.manifest()
        healthy=0
        for voter in manifest['voters']:
            try:
                if self._peer_json(voter['ip'],2379,'/health').get('health') in (True,'true'):healthy+=1
            except (OSError,ValueError,ssl.SSLError):pass
        required=2 if (self.root/'database/PG_VERSION').exists() else 3
        if healthy<required:raise Blocked('Database start waits for authenticated etcd quorum (all three voters for initial bootstrap); no independent local primary is created')
    def _reload_patroni(self):
        context=ssl.create_default_context(cafile=str(self.root/'config/database/ca.pem'));context.load_cert_chain(self.root/'config/database/node.pem',self.root/'config/database/node-key.pem')
        connection=http.client.HTTPSConnection(self.manifest()['local_node']['ip'],8008,context=context,timeout=5)
        try:
            connection.request('POST','/reload',b'{}',{'Content-Type':'application/json'});response=connection.getresponse();response.read(65537)
            if response.status!=202:raise Blocked('Own authenticated Patroni reload was not accepted')
        finally:connection.close()
    def rotate_replication(self,body):
        self._assert_public_port_idle()
        self._assert_restoration_idle()
        self._assert_internal_idle()
        identifier=body.get('rotation_id');phase=body.get('phase');state=self.state();manifest=self.manifest()
        if not JOB.fullmatch(identifier or '') or phase not in ('prepare','change-role','reload','verify','finalize','abort'):raise Blocked('Fixed rotation ID and phase are required')
        if not manifest or manifest['local_node']['role']!='database_voter':raise Blocked('Replication rotation is restricted to authorized database voters')
        path=self.root/'manager/rotation.json';record=load(path)
        historical=load(self.root/'manager/rotations'/identifier)
        if historical:
            if phase=='prepare' and historical.get('password') is not None and not hmac.compare_digest(historical['password'],body.get('password','')):raise Blocked('Terminal rotation ID cannot be reused for a different credential')
            return {'rotation_id':identifier,'phase':historical['phase'],'verified':historical['phase']=='finalized','mutated':False}
        if phase=='abort' and (not record or record['id']!=identifier):
            atomic(self.root/'manager/rotations'/identifier,{'id':identifier,'phase':'aborted','password':None})
            return {'rotation_id':identifier,'phase':'aborted','mutated':False}
        if record and record['id']!=identifier and record['phase'] not in ('finalized','aborted'):raise Blocked('A different private credential rotation is in progress')
        if record and record['id']==identifier and record['phase'] in ('finalized','aborted'):
            if phase=='prepare' and not hmac.compare_digest(record['password'],body.get('password','')):raise Blocked('Terminal rotation ID cannot be reused for a different credential')
            return {'rotation_id':identifier,'phase':record['phase'],'verified':record['phase']=='finalized','mutated':False}
        if phase=='prepare':
            password=body.get('password')
            if not isinstance(password,str) or not 32<=len(password)<=128 or any(ord(value)<32 or ord(value)>126 for value in password):raise Blocked('Provide a strong bounded private replication credential')
            if record and record['id']==identifier:
                if not hmac.compare_digest(record['password'],password):raise Blocked('Rotation ID was already bound to a different credential')
                if record['phase']=='prepare_started':
                    configuration=copy.deepcopy(record['configuration']);configuration['postgresql']['authentication']['replication']['password']=password
                    atomic(self.root/'config/database/patroni.json',configuration,owner=999)
                    record['phase']='prepared';atomic(path,record)
                return {'rotation_id':identifier,'phase':record['phase'],'prepared':True,'mutated':False}
            if body.get('expected_revision')!=state['revision']:raise Blocked('Appliance changed before rotation review')
            self.refresh_health()
            if not self.health_snapshot.get('database_ready') or not self.health_snapshot.get('all_voters_healthy') or sum(peer.get('postgres_running',False) for peer in self.health_snapshot.get('nodes',[]))!=3:raise Blocked('Credential rotation waits for three healthy voters and a synchronous replica')
            if hmac.compare_digest(password,manifest['secrets']['replication']):raise Blocked('The requested replication credential is already active')
            configuration=load(self.root/'config/database/patroni.json')
            if record:atomic(self.root/'manager/rotations'/record['id'],record)
            record={'id':identifier,'phase':'prepare_started','deployment_id':manifest['deployment_id'],'generation':manifest['generation'],'old_password':manifest['secrets']['replication'],'password':password,'configuration':configuration,'role_change_intent':False,'final_revision':state['revision']+1}
            atomic(path,record)
            configuration=copy.deepcopy(configuration);configuration['postgresql']['authentication']['replication']['password']=password
            atomic(self.root/'config/database/patroni.json',configuration,owner=999)
            record['phase']='prepared';atomic(path,record)
            return {'rotation_id':identifier,'phase':'prepared','prepared':True,'mutated':False,'staged_config':True}
        if not record or record['id']!=identifier or record['deployment_id']!=manifest['deployment_id'] or record['generation']!=manifest['generation']:raise Blocked('A matching pinned private rotation must be prepared first')
        self.refresh_health();health=self.health_snapshot
        primaries=[peer for peer in health.get('nodes',[]) if peer.get('postgres_running') and peer.get('role') in ('primary','master')]
        if len(primaries)!=1 or not health.get('quorum_healthy'):raise Blocked('No authenticated unique primary/quorum is available for this rotation')
        primary=primaries[0]['ip'];request={'action':'probe','password':record['password'],'primary_ip':primary}
        if phase=='change-role':
            if record['phase'] not in ('prepared','role_change_started','role_changed'):raise Blocked('Unexpected role-change phase')
            record.update(phase='role_change_started',role_change_intent=True);atomic(path,record)
            result=self.engine.database_helper({'action':'change-role','password':record['password']})
            if result.get('not_primary'):
                record.update(phase='prepared',role_change_intent=False);atomic(path,record)
                return {'rotation_id':identifier,'phase':'not_primary','not_primary':True,'mutated':False}
            if result.get('status')!='role_changed':raise Blocked('Fixed role change did not acknowledge its actual result')
            record['phase']='role_changed';atomic(path,record)
            return {'rotation_id':identifier,'phase':'role_changed','role_change_ack':True,'mutated':bool(result.get('mutated'))}
        if phase=='abort':
            if record.get('role_change_intent') or record['phase'] not in ('prepare_started','prepared'):raise Blocked('After role-change intent this rotation must resume forward')
            if self.engine.database_helper({'action':'probe','password':record['old_password'],'primary_ip':primary}).get('verified') is not True:raise Blocked('Old credential can no longer prove a pre-role-change abort')
            atomic(self.root/'config/database/patroni.json',record['configuration'],owner=999)
            record['phase']='aborted';atomic(path,record)
            return {'rotation_id':identifier,'phase':'aborted','mutated':False}
        if self.engine.database_helper(request).get('verified') is not True:raise Blocked('A new authenticated replication connection was not verified')
        if phase=='reload':
            if record['phase'] not in ('prepared','role_changed','reload_started','reloaded','verified'):raise Blocked('Unexpected reload phase')
            record['role_change_intent']=True;record['phase']='reload_started';atomic(path,record)
            self._reload_patroni()
            record['phase']='reloaded';atomic(path,record)
            return {'rotation_id':identifier,'phase':'reloaded','reload_ack':True,'mutated':False}
        if phase=='verify':
            if record['phase'] not in ('reloaded','verified'):raise Blocked('Own Patroni reload must precede verification')
            if not health.get('database_ready') or sum(peer.get('postgres_running',False) for peer in health.get('nodes',[]))!=3:raise Blocked('New credential authenticated; waiting for three running copies and synchronous streaming')
            record['phase']='verified';atomic(path,record)
            return {'rotation_id':identifier,'phase':'verified','verified':True,'new_connection':True,'mutated':False}
        if phase=='finalize':
            if record['phase']!='verified' or body.get('all_voters_verified') is not True:raise Blocked('Finalize requires coordinator all-three-verified barrier acknowledgement')
            if state['revision']>record['final_revision']:raise Blocked('Local revision advanced outside the pinned credential rotation')
            manifest['secrets']['replication']=record['password'];atomic(self.root/'config/manifest.json',manifest)
            desired=self.desired()
            if desired:desired['secrets']['replication']=record['password'];atomic(self.root/'config/desired.json',desired)
            roles=load(self.root/'config/database/roles.json');roles['secrets']['replication']=record['password'];atomic(self.root/'config/database/roles.json',roles,owner=999)
            state['revision']=record['final_revision'];state['pending_changes']=[value for value in state.get('pending_changes',[]) if value!='replication_password'];atomic(self.root/'manager/state.json',state)
            record['phase']='finalized';atomic(path,record)
            return {'rotation_id':identifier,'phase':'finalized','verified':True,'mutated':False,'revision':state['revision']}
        raise Blocked('Unsupported rotation phase')
    def operate(self,action,service):
        self._assert_public_port_idle()
        self._assert_restoration_idle()
        if action!='stop':self._assert_internal_idle()
        if service not in (*SERVICES,'all'):raise Blocked('Only owned appliance services are allowed')
        if action!='stop' and self.state().get('configuration_pending'):raise Blocked('Interrupted configuration must be recovered before starting services')
        names=self.enabled() if service=='all' else [service]
        if action!='stop' and any(name not in self.enabled() for name in names):raise Blocked('This member is not an authorized database/quorum voter')
        if action in ('start','restart') and 'database' in names:
            prepared=database_runtime_settings(self.root,self.installed)
            if prepared!=self.installed:
                atomic(self.root/'config/installed.json',prepared);self.installed=prepared
        if action in ('start','restart') and 'etcd' in names:self.engine.compose(['up','-d','--no-deps','etcd'])
        if action in ('start','restart') and 'database' in names:self._watchdog();self._quorum()
        if action=='stop':self.engine.compose(['stop','--timeout','90',*names],timeout=120)
        elif action=='restart':self.engine.compose(['up','-d','--no-deps','--force-recreate',*names],timeout=180)
        else:self.engine.compose(['up','-d','--no-deps',*names],timeout=180)
        return {'status':'completed','phase':action,'services':names,'runtime':self.status()}
    def _bootstrap_origin_settings(self,value):
        """Only the first empty, standalone seed may converge a new GUI origin."""
        if value['controller_origin']==self.installed['controller_origin']:return None
        if self.manifest() or len(value['voters'])>=3:raise Blocked('A live origin change requires a separate ingress and identity migration')
        current=load(self.root/'config/controller/settings.json')
        if not current or current.get('environment',{}).get('SEG_ENTRA_TENANT_ID'):raise Blocked('Set the initial stable origin before enabling Entra')
        self._assert_bootstrap_inventory_empty()
        material=self._controller_configuration_material();hostname=urlsplit(value['controller_origin']).hostname
        for port in (self.installed['controller_backend_port'],self.installed['controller_port']):
            self._web_probe(material['chain'],hostname,port,material['fingerprint'])
        return {**current,'controller_origin':value['controller_origin']}
    def _assert_bootstrap_inventory_empty(self):
        # This is the actual mounted Store path, not an empty-directory guess.
        # Read-only WAL-aware access never creates or checkpoints a database.
        database=self.root/'controller/inventory.sqlite3'
        if database.is_symlink() or not database.is_file():raise Blocked('Standalone inventory must be readable before selecting an initial origin')
        import sqlite3
        try:
            with sqlite3.connect(database.resolve().as_uri()+'?mode=ro',uri=True,timeout=3) as db:
                if db.execute('SELECT COUNT(*) FROM servers').fetchone()[0]:raise Blocked('Enrolled endpoints require a separate reviewed origin migration')
        except sqlite3.Error:raise Blocked('Standalone inventory could not be verified; origin was preserved') from None
    def _origin_bootstrap_probe(self,record,previous=False):
        material=record['tls'];hostname=material['name'] if previous else urlsplit(record['configuration']['controller_origin']).hostname
        deadline=time.monotonic()+getattr(self,'_controller_configuration_probe_budget',60)
        while True:
            try:
                for port in (self.installed['controller_backend_port'],self.installed['controller_port']):self._web_probe(material['chain'],hostname,port,material['fingerprint'])
                return
            except (OSError,ValueError,Blocked,http.client.HTTPException):
                if time.monotonic()>=deadline:raise Blocked('Initial origin readiness could not be verified') from None
                time.sleep(.25)
    def _rollback_origin_bootstrap(self,record):
        path=self.root/'manager/origin-bootstrap.json'
        try:
            self.installed=record['installed'];atomic(self.root/'config/installed.json',self.installed)
            atomic(self.root/'config/controller/settings.json',record['controller_settings'],owner=10001)
            if record['desired'] is None:(self.root/'config/desired.json').unlink(missing_ok=True)
            else:atomic(self.root/'config/desired.json',record['desired'])
            self.render()
            atomic(self.root/'config/controller/settings.json',record['controller_settings'],owner=10001)
            self.engine.compose(['up','-d','--no-deps','--force-recreate','controller'])
            self._origin_bootstrap_probe(record,True);atomic(self.root/'manager/state.json',record['state'])
            record['phase']='rolled_back';atomic(path,record)
        except Exception:
            record['phase']='rollback_failed';atomic(path,record)
            raise Blocked('Initial origin rollback is unverified; no newer appliance change was made') from None
    def recover_origin_bootstrap(self):
        record=load(self.root/'manager/origin-bootstrap.json')
        if record and record['phase'] not in ('applied','rolled_back'):
            if record.get('appliance_id')!=self.installed['appliance_id']:raise Blocked('Initial origin recovery belongs to another appliance')
            self._rollback_origin_bootstrap(record)
    def _configure_bootstrap_origin(self,value,state,settings):
        path=self.root/'manager/origin-bootstrap.json'
        if hasattr(self.engine,'foreign_bindings') and self.engine.foreign_bindings(self.root):raise Blocked('A foreign controller-data writer prevents initial origin setup')
        record={'appliance_id':self.installed['appliance_id'],'phase':'prepared','installed':copy.deepcopy(self.installed),
                'controller_settings':load(self.root/'config/controller/settings.json'),'desired':self.desired(),
                'state':self.state(),'configuration':value,'tls':self._controller_configuration_material()}
        atomic(path,record)
        try:
            atomic(self.root/'manager/state.json',{**state,'configuration_pending':True})
            record['phase']='draining';atomic(path,record)
            self.engine.compose(['stop','--timeout','30','controller'],timeout=60)
            if self.engine.states().get('controller') not in (None,'exited','dead','stopped'):raise Blocked('The owned controller writer did not stop')
            # Repeat after draining: enrollment may have raced the live preflight.
            self._assert_bootstrap_inventory_empty()
            self.installed.update(controller_origin=value['controller_origin'],site=value['local_node']['site'])
            atomic(self.root/'config/installed.json',self.installed);atomic(self.root/'config/controller/settings.json',settings,owner=10001)
            atomic(self.root/'config/desired.json',value);self.render()
            self.engine.compose(['up','-d','--no-deps','--force-recreate','controller'])
            self._origin_bootstrap_probe(record)
            atomic(self.root/'manager/state.json',{**state,'revision':state['revision']+1,'configuration_pending':False})
            record['phase']='applied';atomic(path,record)
            return {'status':'waiting_for_voters','phase':'bootstrap','revision':state['revision']+1,'origin_verified':True,
                    'verification_scope':'Local TLS/hostname/database readiness; external DNS, load balancing and Entra registration are not verified'}
        except Exception:
            self._rollback_origin_bootstrap(record)
            raise Blocked('Initial origin was not committed; the verified previous configuration was restored') from None
    def configure(self,body):
        self._assert_public_port_idle()
        self._assert_restoration_idle()
        self._assert_internal_idle()
        state=self.state()
        rotation=load(self.root/'manager/rotation.json')
        if rotation and rotation['phase'] not in ('finalized','aborted'):raise Blocked('Finish or explicitly abort the pinned replication rotation before changing configuration')
        if state.get('configuration_pending'):
            previous=load(self.root/'manager/config-previous.json')
            if not previous or previous.get('appliance_id')!=self.installed['appliance_id']:raise Blocked('Private configuration recovery record is unavailable')
            if previous['manifest'] is None:(self.root/'config/manifest.json').unlink(missing_ok=True)
            else:atomic(self.root/'config/manifest.json',previous['manifest'])
            if previous.get('installed'):self.installed=previous['installed'];atomic(self.root/'config/installed.json',self.installed)
            self.render();state=previous['state'];atomic(self.root/'manager/state.json',state)
        if body.get('expected_revision')!=state['revision']:raise Blocked('Appliance configuration changed; reload before saving')
        value=validate_manifest(body.get('configuration'),self.installed);old=self.manifest();desired=self.desired()
        if desired and (value['generation']<desired['generation'] or value['generation']==desired['generation'] and digest(value)!=digest(desired)):raise Blocked('Manifest generation is stale or divergent')
        if old and old['deployment_id']!=value['deployment_id']:raise Blocked('An owned node cannot be silently assigned to another deployment')
        if old and old.get('pki')!=value.get('pki'):
            if any(old['pki'][key]!=value['pki'][key] for key in ('ca','private_key')):raise Blocked('Live internal CA/key replacement requires reviewed all-member offline recovery; silent trust replacement is refused')
            raise Blocked('Use the staged internal-tls lifecycle before ordinary configuration can replace a node certificate')
        if old and len(value['voters'])<3:raise Blocked('An initialized three-voter deployment cannot be reduced to an incomplete bootstrap manifest')
        if old and old.get('secrets',{}).get('replication')!=value.get('secrets',{}).get('replication'):
            state['pending_changes']=['replication_password'];atomic(self.root/'manager/state.json',state)
            raise Blocked('Replication password is pending: a coordinated real PostgreSQL/Patroni rotation is required, not an environment-file edit')
        if old and digest(old['voters'])!=digest(value['voters']) and (self.root/'etcd/member').exists():raise Blocked('Initialized etcd membership changes require a reviewed quorum-backed membership operation')
        if len(value['voters'])==3 and hasattr(self.engine,'local_network_sources'):
            atomic(self.root/'manager/network-sources.json',self.engine.local_network_sources())
        initial_origin=self._bootstrap_origin_settings(value) if len(value['voters'])<3 else None
        if initial_origin is not None:return self._configure_bootstrap_origin(value,state,initial_origin)
        atomic(self.root/'config/desired.json',value)
        state['revision']+=1
        if len(value['voters'])<3:
            self.installed['site']=value['local_node']['site'];atomic(self.root/'config/installed.json',self.installed);self.render()
            atomic(self.root/'manager/state.json',state)
            return {'status':'waiting_for_voters','phase':'bootstrap','revision':state['revision']}
        # Pair validation before replacing private active material.
        with tempfile.TemporaryDirectory(dir=self.root/'manager') as temporary:
            cert,key=Path(temporary)/'cert',Path(temporary)/'key'
            cert.write_text(value['pki']['certificate']);key.write_text(value['pki']['private_key'])
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key)
            ssl.create_default_context(cadata=value['pki']['ca'])
        atomic(self.root/'manager/config-previous.json',{'appliance_id':self.installed['appliance_id'],'manifest':old,'state':self.state(),'installed':self.installed})
        pending=self.state();pending['configuration_pending']=True;atomic(self.root/'manager/state.json',pending)
        self.installed['site']=value['local_node']['site'];atomic(self.root/'config/installed.json',self.installed)
        atomic(self.root/'config/manifest.json',value);self.render()
        state['configuration_pending']=False;atomic(self.root/'manager/state.json',state)
        return {'status':'configured','phase':'rendered','revision':state['revision'],'database_active':False,'requires_service_start':True,'requires_service_restart':True}
    def _tree(self,path):
        proof={}
        for item in sorted(path.rglob('*')):
            if item.is_symlink() or not (item.is_file() or item.is_dir()):raise Blocked('Storage migration refuses symlinks, sockets, devices or external tablespaces')
            if item.is_file():
                hashed=hashlib.sha256()
                with item.open('rb') as stream:
                    for chunk in iter(lambda:stream.read(1024*1024),b''):hashed.update(chunk)
                info=item.stat();proof[str(item.relative_to(path))]=[info.st_size,hashed.hexdigest(),stat.S_IMODE(info.st_mode),info.st_uid,info.st_gid]
        return proof
    def storage_review(self,body):
        self._assert_public_port_idle()
        self._assert_restoration_idle()
        self._assert_internal_idle()
        rotation=load(self.root/'manager/rotation.json')
        if rotation and rotation['phase'] not in ('finalized','aborted'):raise Blocked('Finish the pinned replication rotation before reviewing a storage move')
        target=safe_path(body.get('data_root'),self.allowed_parent)
        if target==self.root or self.root in target.parents or target in self.root.parents:raise Blocked('Choose a separate dedicated target, not the current root or an ancestor/child')
        if target.exists() and any(target.iterdir()):raise Blocked('Storage target must be empty; no foreign files are overwritten')
        if self.engine.foreign_bindings(self.root):raise Blocked('A foreign running container can write DATA_ROOT; no storage fence can be claimed')
        review={'id':secrets.token_hex(16),'source':str(self.root),'target':str(target),'appliance_id':self.installed['appliance_id'],'revision':self.state()['revision'],'nonce':secrets.token_urlsafe(24),'expires_at':time.time()+600}
        atomic(self.root/'manager/reviews'/review['id'],review)
        return {'status':'review','review_id':review['id'],'data_root':str(target),'confirmation_nonce':review['nonce'],'requires_stopped_services':True,'source_preserved':True}
    def storage_move(self,body):
        self._assert_public_port_idle()
        self._assert_restoration_idle()
        self._assert_internal_idle()
        rotation=load(self.root/'manager/rotation.json')
        if rotation and rotation['phase'] not in ('finalized','aborted'):raise Blocked('Finish the pinned replication rotation before moving stopped database state')
        review=load(self.root/'manager/reviews'/body.get('review_id','')) if JOB.fullmatch(body.get('review_id','')) else None
        if not review or review['expires_at']<time.time() or body.get('confirmation_nonce')!=review['nonce'] or review['source']!=str(self.root) or review['revision']!=self.state()['revision']:raise Blocked('Storage review changed, expired or was not confirmed exactly')
        target=safe_path(review['target'],self.allowed_parent)
        if target.exists() and any(target.iterdir()):raise Blocked('Reviewed storage target is no longer empty')
        if self.engine.foreign_bindings(self.root):raise Blocked('A foreign running container can write DATA_ROOT; no copy was attempted')
        previous=[name for name,value in self.engine.states().items() if value=='running']
        self.engine.compose(['stop','--timeout','90',*SERVICES],timeout=120)
        if any(value=='running' for value in self.engine.states().values()):raise Blocked('An owned service is still running; no PGDATA copy was attempted')
        if (self.manifest() or {}).get('local_node',{}).get('role')=='database_voter':
            try:
                if Path('/sys/class/watchdog/watchdog0/state').read_text().strip()!='inactive':raise OSError()
            except OSError:raise Blocked('Storage migration waits for confirmed watchdog disarm after database shutdown') from None
        original=self.root;proof=self._tree(original)
        try:
            private_dir(target)
            shutil.copytree(original,target,copy_function=shutil.copy2,dirs_exist_ok=True)
            for path in [target,*target.rglob('*')]:
                relative=path.relative_to(target);source=original/relative;info=source.stat();os.chown(path,info.st_uid,info.st_gid)
            if self._tree(target)!=proof:raise Blocked('Stopped-data checksum/ownership verification failed')
            for path in target.rglob('*'):
                if path.is_file():
                    descriptor=os.open(path,os.O_RDONLY)
                    try:os.fsync(descriptor)
                    finally:os.close(descriptor)
            for path in [*reversed([p for p in target.rglob('*') if p.is_dir()]),target]:
                descriptor=os.open(path,os.O_RDONLY)
                try:os.fsync(descriptor)
                finally:os.close(descriptor)
            atomic(target/'manager/storage-verified.json',{'source':str(original),'target':str(target),'appliance_id':self.installed['appliance_id'],'digest':digest(proof)})
            atomic(self.pointer,str(target)+'\n')
            self.root=target;self.engine=self.engine_factory(target,self.project);self.render()
            if previous:
                if 'etcd' in previous:self.engine.compose(['up','-d','--no-deps','etcd'])
                if 'database' in previous:self._watchdog();self._quorum()
                self.engine.compose(['up','-d','--no-deps','--force-recreate',*previous])
            atomic(original/'manager/retired.json',{'active_data_root':str(target),'appliance_id':self.installed['appliance_id']})
            return {'status':'completed','phase':'storage_committed','data_root':str(target),'source_preserved':True,'verified_files':len(proof)}
        except Exception:
            if self.root==original and previous:
                if 'etcd' in previous:self.engine.compose(['up','-d','--no-deps','etcd'])
                if 'database' in previous:self._watchdog();self._quorum()
                self.engine.compose(['up','-d','--no-deps',*previous])
            raise
    def management_probe(self, body):
        if not isinstance(body, dict) or set(body) != {'source_ip', 'target_ip', 'ports'}:
            raise Blocked('Provide an exact native SSH probe source, destination and port set')
        if any(not isinstance(body[key], str) or len(body[key]) > 128 for key in ('source_ip', 'target_ip')):
            raise Blocked('The SSH probe requires literal source and destination addresses')
        ports = body['ports']
        if (not isinstance(ports, list) or not 1 <= len(ports) <= 8
                or any(type(port) is not int or not 1 <= port <= 65535 for port in ports)
                or ports != sorted(set(ports))):
            raise Blocked('The SSH probe port set must contain one to eight exact ports')
        settings_path = self.root/'config/controller/settings.json'
        environment = load(settings_path, {}).get('environment', {})
        scope = tuple(environment.get(key, '') for key in PROBE_PUBLIC)
        try:
            source, target = [ipaddress.ip_address(body[key]) for key in ('source_ip', 'target_ip')]
            if any(getattr(item, 'scope_id', None) is not None or getattr(item, 'ipv4_mapped', None) is not None
                   or item.is_loopback or item.is_link_local or item.is_multicast or item.is_unspecified or item.is_reserved
                   for item in (source, target)):
                raise ValueError()
            targets = [ipaddress.ip_network(value) for value in scope[1].split(',')]
            if (str(source) != scope[0] or source.version != target.version or not 1 <= len(targets) <= 32
                    or any(net.prefixlen == 0 or net.version != source.version for net in targets)
                    or not any(target in net for net in targets)):
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise Blocked('The SSH probe is outside this host’s reviewed source or destination scope') from None
        if not self.management_probe_slots.acquire(blocking=False):
            raise Blocked('The host SSH probe is busy; retry the reviewed operation')
        try:
            family = socket.AF_INET if source.version == 4 else socket.AF_INET6
            deadline = time.monotonic() + 8
            checks = []
            for port in ports:
                if time.monotonic() >= deadline:
                    raise Blocked('The host SSH probe deadline expired')
                with socket.socket(family, socket.SOCK_STREAM) as connection:
                    connection.settimeout(min(2, max(0.01, deadline - time.monotonic())))
                    connection.bind((str(source), 0))
                    connection.connect((str(target), port))
                    banner = b''
                    while len(banner) < 1024 and time.monotonic() < deadline:
                        connection.settimeout(min(2, max(0.01, deadline - time.monotonic())))
                        data = connection.recv(min(256, 1024 - len(banner)))
                        if not data:
                            break
                        banner += data
                        if any(line.rstrip(b'\r').startswith((b'SSH-2.0-', b'SSH-1.99-')) for line in banner.split(b'\n')[:-1]):
                            checks.append({'target_ip': str(target), 'port': port, 'source_ip': connection.getsockname()[0],
                                           'ssh_banner_verified': True})
                            break
                if len(checks) == 0 or checks[-1]['port'] != port:
                    raise Blocked('The endpoint did not return a fresh SSH protocol banner')
            current = load(settings_path, {}).get('environment', {})
            if tuple(current.get(key, '') for key in PROBE_PUBLIC) != scope:
                raise Blocked('The reviewed host SSH probe scope changed during the check')
            return {'ssh_checks': checks}
        except OSError:
            raise Blocked('SSH is unreachable from the configured controller host source IP; check its address and route') from None
        finally:
            self.management_probe_slots.release()

    def submit(self,body):
        if not isinstance(body,dict):raise Blocked('A manager job must be a JSON object')
        request_id=body.get('request_id')
        if not isinstance(request_id,str) or not JOB.fullmatch(request_id) or body.get('action') not in ACTIONS:raise Blocked('A 32-hex request_id and fixed supported action are required')
        fingerprint=digest(body);path=self.root/'manager/jobs'/request_id
        with self.lock:
            old=load(path)
            if old:
                if old['request_digest']!=fingerprint:raise Blocked('request_id was already used for a different payload')
                return self.public_job(old)
            if active_offline_update(self.root) and body['action'] != 'status':
                raise Blocked('Wait for the offline controller update to finish')
            value={'id':request_id,'request_digest':fingerprint,'request':body,'status':'queued','phase':'queued','created_at':time.time()}
            atomic(path,value)
        return self.public_job(value)
    def public_job(self,value):return {key:value[key] for key in ('id','status','phase','result','error','created_at','updated_at') if key in value}
    def job(self,identifier):
        if not JOB.fullmatch(identifier):raise Blocked('Invalid manager job identifier')
        value=load(self.root/'manager/jobs'/identifier)
        if not value:raise KeyError(identifier)
        return self.public_job(value)
    def work_once(self):
        with self.lock:
            for path in sorted((self.root/'manager/jobs').glob('*')):
                if not JOB.fullmatch(path.name):continue
                value=load(path)
                if value.get('status')!='queued':continue
                if active_offline_update(self.root) and value['request']['action'] != 'status':
                    continue
                value.update(status='running',phase=value['request']['action']);atomic(path,value)
                body=value['request'];action=body['action']
                try:
                    if action not in ('status','controller-config'):self._assert_controller_configuration_idle()
                    if action not in ('status','public-port'):self._assert_public_port_idle()
                    if action!='status':self.recover_web_tls()
                    if action=='status':result=self.status()
                    elif action=='configure':result=self.configure(body)
                    elif action=='controller-config':result=self.controller_configuration(body)
                    elif action=='storage-review':result=self.storage_review(body)
                    elif action=='storage-move':result=self.storage_move(body)
                    elif action=='rotate-replication':result=self.rotate_replication(body)
                    elif action=='web-tls':result=self.web_tls(body)
                    elif action=='internal-tls':result=self.internal_tls(body)
                    elif action=='restore-databases':result=self.restore_databases(body)
                    elif action=='public-port':result=self.public_port(body)
                    elif action=='controller-update-review':result=offline_update_module().review(self,body,sys.modules[__name__])
                    elif action=='controller-update-apply':
                        offline_update_module().queue(self,body,sys.modules[__name__])
                        return True  # The independent systemd worker completes the durable job.
                    else:result=self.operate(action,body.get('service','all'))
                    value.update(status='completed',phase=result.get('phase',action),result=result)
                except Exception as error:
                    value.update(status='blocked' if isinstance(error,Blocked) else 'error',error=str(error) if isinstance(error,Blocked) else 'Fixed appliance operation failed; private data and source were retained')
                value['updated_at']=time.time();atomic(self.root/'manager/jobs'/value['id'],value)
                return True
        return False


class UnixServer(socketserver.ThreadingMixIn,socketserver.UnixStreamServer):
    daemon_threads=True
    def server_close(self):
        if hasattr(self,'manager_stop'):self.manager_stop.set()
        super().server_close()


def serve(manager,run_dir='/run/prthak-appliance',ready=None,*,_test_peer_uid=None):
    # The sole override is an in-process test dependency, never an RPC field,
    # command-line option, environment variable or production auth bypass.
    controller_identity()
    manager.recover_public_port()
    private_dir(run_dir)
    path=Path(run_dir)/'manager.sock'
    if path.exists():
        if not stat.S_ISSOCK(path.lstat().st_mode):raise Blocked('Manager socket path is occupied by a non-socket')
        path.unlink()
    token=(manager.root/'config/manager-token').read_text().strip()
    atomic(Path(run_dir)/'manager-token',token,0o640);os.chown(Path(run_dir)/'manager-token',0,10001)
    class Handler(BaseHTTPRequestHandler):
        def setup(self):super().setup();self.connection.settimeout(10)
        def log_message(self,*args):pass
        def send(self,status,value):
            data=json.dumps(value,separators=(',',':')).encode();self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
        def authorized(self):
            try:
                uid=(_test_peer_uid or peer_uid)(self.connection)
                return isinstance(uid,int) and not isinstance(uid,bool) and uid in (0,CONTROLLER_UID) and hmac.compare_digest(self.headers.get('Authorization',''),'Bearer '+token)
            except (Blocked,OSError,ValueError,TypeError):return False
        def do_GET(self):
            if not self.authorized():return self.send(403,{'error':'Manager authentication required'})
            try:
                value=manager.status() if self.path=='/v1/status' else manager.job(self.path.removeprefix('/v1/jobs/')) if self.path.startswith('/v1/jobs/') else None
                self.send(200,value) if value is not None else self.send(404,{'error':'Unknown fixed manager route'})
            except (Blocked,KeyError):self.send(409,{'error':'Manager state unavailable'})
        def do_POST(self):
            if not self.authorized():return self.send(403,{'error':'Manager authentication required'})
            try:
                size=int(self.headers.get('Content-Length','0'))
                if self.headers.get('Transfer-Encoding') or self.headers.get('Content-Type','').split(';')[0]!='application/json':raise Blocked('Bounded JSON manager request required')
                if self.path=='/v1/management-probe' and 0<size<=4096:
                    self.send(200,manager.management_probe(json.loads(self.rfile.read(size))))
                elif self.path=='/v1/jobs' and 0<size<=2097152:
                    self.send(202,manager.submit(json.loads(self.rfile.read(size))))
                else:raise Blocked('Bounded JSON manager request required')
            except (Blocked,ValueError,TypeError) as error:self.send(409,{'error':str(error)})
    server=UnixServer(str(path),Handler);os.chown(path,0,10001);path.chmod(0o660);os.chmod(run_dir,0o750);os.chown(run_dir,0,10001)
    server.manager_stop=threading.Event()
    def worker():
        next_health=0
        while not server.manager_stop.is_set():
            try:
                with manager.lock:
                    manager.recover_public_port(expired_only=True)
                    manager.recover_controller_configuration()
                    manager.recover_origin_bootstrap()
                manager.work_once()
                if time.monotonic()>=next_health:manager.refresh_health();next_health=time.monotonic()+15
            except Exception:pass
            time.sleep(.25)
    threading.Thread(target=worker,daemon=True).start()
    if ready:ready(server)
    server.serve_forever()


def build_appliance_images(engine, release, build):
    for name in ('base','controller','database','etcd','router'):private_dir(build/name)
    for name in ('controller','dashboard'):
        destination=build/'base'/name
        if destination.exists():shutil.rmtree(destination)
        shutil.copytree(release/name,destination,ignore=shutil.ignore_patterns('__pycache__','*.pyc','tests'))
    (build/'base/deploy/cluster').mkdir(parents=True,exist_ok=True)
    shutil.copyfile(release/'deploy/cluster/node_helper.py',build/'base/deploy/cluster/node_helper.py')
    for filename in ('runtime-integrity.json','release-public-trust.json'):shutil.copyfile(release/'deploy'/filename,build/'base/deploy'/filename)
    shutil.copyfile(release/'deploy/verify_runtime_entrypoint.py',build/'base/deploy/verify_runtime_entrypoint.py')
    shutil.copyfile(release/'deploy/Dockerfile.controller',build/'base/Dockerfile')
    for name,filename in (('controller','controller_entrypoint.py'),('database','bootstrap_roles.py')):
        shutil.copyfile(release/'deploy/appliance'/('Dockerfile.'+name),build/name/'Dockerfile');shutil.copyfile(release/'deploy/appliance'/filename,build/name/filename)
    shutil.copyfile(release/'deploy/appliance/rotation_helper.py',build/'database/rotation_helper.py')
    shutil.copyfile(release/'deploy/appliance/restore_helper.py',build/'database/restore_helper.py')
    shutil.copyfile(release/'deploy/appliance/Dockerfile.etcd',build/'etcd/Dockerfile')
    shutil.copyfile(release/'deploy/appliance/etcd-build-inputs.json',build/'etcd/etcd-build-inputs.json')
    shutil.copyfile(release/'deploy/appliance/Dockerfile.router',build/'router/Dockerfile')
    shutil.copyfile(release/'deploy/appliance/router-entrypoint.sh',build/'router/router-entrypoint.sh')
    engine.run(['build','-t','prthak-controller:appliance-base',str(build/'base')],timeout=1800)
    builds={'controller':CONTROLLER_IMAGE,'database':DATABASE_IMAGE,'etcd':ETCD_IMAGE,'router':'prthak-router:appliance'}
    for name,image in builds.items():engine.run(['build','-t',image,str(build/name)],timeout=1800)
    images={}
    for name,image in builds.items():
        identifier=engine.run(['image','inspect','--format','{{.Id}}',image]).strip()
        if not re.fullmatch(r'sha256:[a-f0-9]{64}',identifier):raise Blocked('A locally built immutable image identity is required')
        images[name]=identifier
    return images


def offline_appliance_images(engine, directory):
    metadata = directory/'images.json'
    archive = directory/'images.tar.gz'
    if metadata.stat().st_size > 16384 or not 1 <= archive.stat().st_size < 2 * 1024**3:
        raise Blocked('Offline image payload exceeds its size limits')
    manifest = load(metadata)
    if (not isinstance(manifest, dict) or set(manifest) != {'platform', 'images', 'archive_sha256'}
            or manifest['platform'] != 'linux/amd64' or not isinstance(manifest['images'], dict)
            or set(manifest['images']) != set(SERVICES)):
        raise Blocked('A complete Linux AMD64 offline image manifest is required')
    images = manifest['images']
    if any(not isinstance(image, str) or not re.fullmatch(r'sha256:[a-f0-9]{64}', image)
           for image in images.values()):
        raise Blocked('The offline image manifest contains an invalid image identity')
    digest = hashlib.sha256()
    with archive.open('rb') as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    if digest.hexdigest() != manifest['archive_sha256']:
        raise Blocked('The offline image archive does not match the manifest checksum')
    engine.run(['image', 'load', '--input', str(archive)], timeout=1800)
    for name, image in images.items():
        result = engine.run(['image', 'inspect', '--format', '{{.Id}} {{.Os}}/{{.Architecture}}', image])
        if result.strip() != image + ' linux/amd64':
            raise Blocked('The imported image does not match the offline manifest: ' + name)
    return images


def protected_release_directory(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise Blocked('The agent release directory must be root-owned, protected and free of symlinks')


def stage_agent_releases(release, data_root):
    source = release/'agent-releases'
    if not source.exists() and not source.is_symlink():
        source = release/'offline/agents'
    if not source.exists() and not source.is_symlink():
        return
    protected_release_directory(source.parent)
    protected_release_directory(source)
    version = re.search(r'^__version__ = "([0-9]+\.[0-9]+\.[0-9]+)"$',
                        (release/'controller/__init__.py').read_text(), re.MULTILINE)
    if not version:
        raise Blocked('Cannot identify the matching agent release version')
    files = {}
    for arch in ('amd64', 'arm64'):
        archive = 'prthak-agent-' + version[1] + '-linux-' + arch + '.tar.gz'
        for name, maximum in ((archive, 16 * 1024**2), (archive+'.signature.json', 16384)):
            descriptor = os.open(source/name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                        or info.st_nlink != 1 or not 0 < info.st_size <= maximum):
                    raise Blocked('The agent release contains an unsafe file')
                files[name] = stream.read(maximum + 1)
                if len(files[name]) != info.st_size:
                    raise Blocked('An agent release file changed during staging')
    runtime = data_root/'runtime'
    private_dir(runtime)
    destination = runtime/'agent-releases'
    destination.mkdir(mode=0o755, exist_ok=True)
    protected_release_directory(destination)
    destination.chmod(0o755)
    for name, data in files.items():
        atomic(destination/name, data, 0o644)


def write_manager_unit(engine, image):
    interpreter = str(Path(sys.executable).resolve())
    command = [engine.docker[0], '--host', 'unix:///var/run/docker.sock', 'run', '--rm', '--network', 'none',
               '--pull=never', '--read-only', '--security-opt', 'no-new-privileges:true', '--cap-drop', 'ALL',
               '--security-opt', 'label=disable', '--user', '10001:10001']
    checks = []
    for filename, flag in (('node_manager.py', '--check-host'), ('offline_update.py', '--check-host-update')):
        mount = 'type=bind,source=/opt/prthak-appliance/' + filename + ',target=/prthak-host/' + filename + ',readonly'
        checks.append('ExecStartPre=' + shlex.join([*command, '--mount', mount, '--entrypoint', 'python3',
                                                   image, '/opt/prthak-integrity/launch.py', flag, '/prthak-host/' + filename]))
    unit = '\n'.join([
        '[Unit]', 'Description=Prthak fixed local appliance manager', 'After=docker.service network-online.target',
        'Wants=docker.service network-online.target', '[Service]', 'Type=simple', 'User=root', *checks,
        f'ExecStart={interpreter} -I /opt/prthak-appliance/node_manager.py serve', 'Restart=on-failure',
        'RestartSec=3', 'UMask=0077', 'NoNewPrivileges=yes', 'ProtectSystem=full', 'ReadWritePaths=/etc/prthak',
        'ProtectHome=yes', '[Install]', 'WantedBy=multi-user.target', '',
    ])
    atomic('/etc/systemd/system/prthak-appliance-manager.service', unit, 0o644)


def write_update_unit(interpreter):
    # On reboot the immutable dispatcher uses the complete pre-update worker
    # pair, even if the manager and helper replacements were interrupted.
    bootstrap = '''import json, os, pathlib, re, stat, sys

def protected(path, *, directory=False):
    info = path.lstat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise SystemExit('Offline update recovery paths are not protected')

pointer = pathlib.Path('/etc/prthak/data-root')
protected(pointer)
root = pathlib.Path(pointer.read_text().strip())
if not root.is_absolute() or '..' in root.parts:
    raise SystemExit('Invalid appliance data root')
for path in (root, *root.parents):
    protected(path, directory=True)
base = root / 'manager/controller-update'
journal = base / 'active.json'
if not journal.exists():
    raise SystemExit(0)
for path in (base.parent, base):
    protected(path, directory=True)
protected(journal)
record = json.loads(journal.read_text())
identifier = record.get('review_id', '')
if not re.fullmatch('[0-9a-f]{32}', identifier):
    raise SystemExit('Invalid offline update recovery identity')
if record.get('phase') in ('queued', 'committed', 'rolled_back', 'blocked'):
    code = pathlib.Path('/opt/prthak-appliance')
else:
    code = base / ('backup-' + identifier)
for path in (code, *code.parents):
    protected(path, directory=True)
for filename in ('node_manager.py', 'offline_update.py'):
    protected(code / filename)
os.execv(sys.executable, [sys.executable, '-I', str(code / 'node_manager.py'), 'update'])
'''
    atomic('/opt/prthak-appliance/update-bootstrap.py', bootstrap, 0o755)
    unit = '\n'.join([
        '[Unit]', 'Description=Prthak signed offline appliance update and recovery', 'After=docker.service',
        'Wants=docker.service', '[Service]', 'Type=oneshot', 'User=root',
        f'ExecStart={interpreter} -I /opt/prthak-appliance/update-bootstrap.py',
        'TimeoutStartSec=1h', 'Restart=on-failure', 'RestartSec=15', 'UMask=0077',
        'NoNewPrivileges=yes', 'ProtectHome=yes', '[Install]', 'WantedBy=multi-user.target', '',
    ])
    atomic('/etc/systemd/system/prthak-appliance-update.service', unit, 0o644)


def install(args):
    release=Path(args.release_root).resolve()
    update_only=release/'OFFLINE-UPDATE-ONLY'
    if update_only.exists() or update_only.is_symlink():
        raise Blocked('Use Platform settings > Updates to upload this GUI-only archive and its detached signature')
    values,local,root=installer_configuration(args)
    if args.validate_only:
        provider=initial_environment(values)
        print(json.dumps({'status':'validated','data_root':str(root),'node_id':local['node_id'],'site':local['site'],'private_values_excluded':True,'provider_validation':'bundled_runtime_required' if provider.get('SEG_ENTRA_TENANT_ID') else 'disabled'}));return
    if os.geteuid()!=0:raise Blocked('Install with sudo; the controller itself remains nonroot')
    if Path('/proc/1/comm').read_text().strip()!='systemd':raise Blocked('The host installer requires genuine Linux systemd')
    interpreter=Path(sys.executable).resolve()
    for path in (interpreter,*interpreter.parents):
        info=path.stat()
        if info.st_uid!=0 or info.st_mode&0o022:raise Blocked('The privileged manager needs a root-owned system Python interpreter and protected ancestors')
    controller_identity(create=True)
    lease=acquire_lease()
    pointer=Path('/etc/prthak/data-root')
    if pointer.exists() and pointer.read_text().strip()!=str(root):raise Blocked('DATA_ROOT differs from the committed active pointer; use reviewed GUI storage migration')
    installed=load(root/'config/installed.json')
    local=installation_identity(root,local)
    local=database_runtime_settings(root,local)
    private_dir(root);private_dir(root/'config');private_dir(root/'manager/jobs');private_dir(root/'manager/reviews')
    project='prthak-'+local['appliance_id'][:12];engine=Engine(root,project);engine.check()
    if getattr(args, 'offline', False):
        images = offline_appliance_images(engine, release/'offline')
    else:
        images = build_appliance_images(engine, release, root/'runtime/build')
    stage_agent_releases(release, root)
    engine.controller_image = images['controller']
    local['images']=images
    private_dir(root/'config/controller',10001);private_dir(root/'controller',10001)
    existing_settings=load(root/'config/controller/settings.json')
    initial_env=stage_initial_environment(engine,root,values,existing_settings)
    if not installed:
        token=local.pop('super_admin_token') or secrets.token_urlsafe(48)
        password=local.pop('cluster_password')
        atomic(root/'config/installed.json',local)
    else:
        token=values.get('SUPER_ADMIN_TOKEN') or secrets.token_urlsafe(48);password=values.get('CLUSTER_PASSWORD','')
        atomic(root/'config/installed.json',local)
    if not (root/'config/manager-token').exists():atomic(root/'config/manager-token',secrets.token_urlsafe(48))
    if not (root/'config/controller/initial-admin-token').exists():
        if any((root/'controller').iterdir()):raise Blocked('Existing controller data has lost its bootstrap token; no replacement identity was invented')
        atomic(root/'config/controller/initial-admin-token',token,owner=10001)
    if password and not (root/'config/controller/cluster-password').exists():atomic(root/'config/controller/cluster-password',password,owner=10001)
    if not (root/'config/controller/settings.json').exists():
        environment={'PRTHAK_APPLIANCE':'1','PRTHAK_APPLIANCE_NODE_ID':local['node_id'],'PRTHAK_APPLIANCE_SITE':local['site'],'PRTHAK_APPLIANCE_NODE_IP':local['node_ip'],'PRTHAK_APPLIANCE_DATA_ROOT':str(root),'PRTHAK_APPLIANCE_MANAGER_SOCKET':'/run/prthak-appliance/manager.sock','PRTHAK_APPLIANCE_MANAGER_TOKEN_FILE':'/run/prthak-appliance/manager-token','PRTHAK_CLUSTER_PASSWORD_FILE':'/run/prthak-bootstrap/cluster-password','PRTHAK_EXISTING_NODE_IP':local['existing_node_ip']}
        environment.update(initial_env)
        atomic(root/'config/controller/settings.json',{**{key:local[key] for key in ('node_id','node_ip','site','controller_origin')},'environment':environment},owner=10001)
    engine.run(['run','--pull=never','--rm','--network','none','--user','0','--entrypoint','python3','--mount','type=bind,source='+str(root/'config/controller')+',target=/bootstrap',images['controller'],'/opt/prthak/controller_entrypoint.py','--initialize','/bootstrap'])
    manager=Manager(root);manager.recover_web_tls();manager.recover_public_port();manager.render()
    (root/'config/install-pending.json').unlink(missing_ok=True)
    code=Path('/opt/prthak-appliance');code.mkdir(parents=True,exist_ok=True)
    for filename in ('node_manager.py', 'offline_update.py'):
        atomic(code / filename, (release / 'deploy/appliance' / filename).read_bytes(), 0o755)
    atomic('/etc/prthak/data-root',str(root)+'\n')
    write_manager_unit(engine, images['controller'])
    write_update_unit(interpreter)
    os.close(lease)
    if not args.no_start:
        subprocess.run(['systemctl','daemon-reload'],check=True)
        subprocess.run(['systemctl','enable','prthak-appliance-update.service'],check=True)
        subprocess.run(['systemctl','enable','--now','prthak-appliance-manager.service'],check=True)
        manager.operate('start','controller');manager.operate('start','router')
    print('Prṛthak appliance installed at '+str(root)+'. Initial admin token FILE: '+str(root/'config/controller/initial-admin-token'))
    print('Setup URL: '+local['controller_origin']+'/settings')
    print('Database promotion remains disabled until three authorized voters and required native fencing are configured and validated.')


def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='command',required=True)
    add=sub.add_parser('install');add.add_argument('--env-file');add.add_argument('--gui-setup',action='store_true');add.add_argument('--data-root');add.add_argument('--release-root',required=True);add.add_argument('--no-start',action='store_true');add.add_argument('--validate-only',action='store_true');add.add_argument('--offline',action='store_true')
    sub.add_parser('serve');sub.add_parser('update');args=parser.parse_args()
    try:
        if sys.version_info<(3,9):raise Blocked('Host manager needs Python3.9+; controller runtime is bundled')
        if args.command=='install':install(args)
        elif args.command=='update':
            if os.geteuid() != 0:raise Blocked('The fixed offline update service must run as root')
            root = Path(Path('/etc/prthak/data-root').read_text().strip())
            offline_update_module().run(root, sys.modules[__name__])
        else:
            if os.geteuid()!=0:raise Blocked('The fixed local manager must run as root')
            controller_identity()
            lease=acquire_lease()
            root=Path(Path('/etc/prthak/data-root').read_text().strip())
            update = active_offline_update(root)
            if update and load('/run/prthak-appliance/controller-update-start.json', {}) != {'job_id':update['job_id']}:
                raise Blocked('Wait for the offline update recovery service before starting the manager')
            if update:
                offline_update_module().repair_fence(root, update, sys.modules[__name__])
            manager=Manager(root)
            manager.recover_web_tls()
            serve(manager)
    except (Blocked,OSError,ValueError,subprocess.SubprocessError) as error:
        print('Prṛthak appliance blocked: '+str(error),file=sys.stderr);return 1
    return 0


if __name__=='__main__':raise SystemExit(main())
