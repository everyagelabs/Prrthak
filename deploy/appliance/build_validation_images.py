#!/usr/bin/env python3
"""Build disposable validation images from an exact public-source allowlist."""
import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile
import re


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--context',required=True);parser.add_argument('--prefix',default='prthak-appliance');args=parser.parse_args()
    if not re.fullmatch(r'[a-z][a-z0-9-]{0,50}',args.prefix):parser.error('Use a simple image prefix')
    release=Path(__file__).resolve().parents[2]
    def build(path,tag):subprocess.run(['docker','--context',args.context,'build','-t',tag,str(path)],check=True)
    with tempfile.TemporaryDirectory(prefix='prthak-public-images-') as temporary:
        root=Path(temporary);base=root/'base';base.mkdir()
        for name in ('controller','dashboard'):shutil.copytree(release/name,base/name,ignore=shutil.ignore_patterns('__pycache__','*.pyc','tests'))
        (base/'deploy/cluster').mkdir(parents=True)
        shutil.copyfile(release/'deploy/cluster/node_helper.py',base/'deploy/cluster/node_helper.py')
        for filename in ('runtime-integrity.json','release-public-trust.json'):shutil.copyfile(release/'deploy'/filename,base/'deploy'/filename)
        shutil.copyfile(release/'deploy/verify_runtime_entrypoint.py',base/'deploy/verify_runtime_entrypoint.py')
        shutil.copyfile(release/'deploy/Dockerfile.controller',base/'Dockerfile')
        build(base,args.prefix+'-controller-base-test')
        for kind,tag in (('database',args.prefix+'-database-test'),('controller',args.prefix+'-controller-test')):
            target=root/kind;target.mkdir()
            text=(release/'deploy/appliance'/('Dockerfile.'+kind)).read_text()
            extras=['bootstrap_roles.py','rotation_helper.py','restore_helper.py','helper_rpc_fixture.py'] if kind=='database' else ['controller_entrypoint.py','node_manager.py','rotation_helper.py']
            if kind=='controller':
                text=text.replace('FROM prthak-controller:appliance-base','FROM '+args.prefix+'-controller-base-test')
                if (release/'deploy/appliance/coordinator_fixture.py').exists():extras.append('coordinator_fixture.py')
                if (release/'deploy/appliance/internal_tls_fixture.py').exists():extras.append('internal_tls_fixture.py')
                if (release/'deploy/appliance/restore_fixture.py').exists():extras.append('restore_fixture.py')
            for filename in extras:shutil.copyfile(release/'deploy/appliance'/filename,target/filename)
            text+='\nCOPY '+' '.join(extras)+' /opt/prthak/\n'
            (target/'Dockerfile').write_text(text);build(target,tag)
        router=root/'router-action';router.mkdir()
        for filename in ('node_manager.py','web_tls_fixture.py'):shutil.copyfile(release/'deploy/appliance'/filename,router/filename)
        (router/'Dockerfile').write_text('FROM haproxy:3.2-trixie@sha256:de853dd229e0f13e0104b288a487e1e12eb3965618f9b88f49ef8d5a6d83c001\nUSER root\nRUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends python3 python3-cryptography && rm -rf /var/lib/apt/lists/*\nCOPY node_manager.py web_tls_fixture.py /opt/prthak/\nENTRYPOINT ["python3", "/opt/prthak/web_tls_fixture.py"]\n')
        build(router,args.prefix+'-router-action-test')


if __name__=='__main__':main()
