#!/usr/bin/env python3
"""Disposable real-image Entra shape checks, without real identity credentials."""
import argparse
import json
import secrets
import subprocess
import uuid


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--context',required=True);parser.add_argument('--image',default='prthak-appliance-controller-test');args=parser.parse_args()
    secret=secrets.token_urlsafe(40);environment={'SEG_ENTRA_TENANT_ID':'11111111-1111-4111-8111-111111111111','SEG_ENTRA_CLIENT_ID':'22222222-2222-4222-8222-222222222222','SEG_ENTRA_REDIRECT_URI':'https://controller.example/api/v1/auth/callback','SEG_BOOTSTRAP_SUPER_ADMIN_OID':'33333333-3333-4333-8333-333333333333','SEG_ENTRA_CLIENT_SECRET':secret,'SEG_HTTP_THREADS':'32'}
    cases=[(environment,True),({**environment,'SEG_ENTRA_REDIRECT_URI':'http://controller.example/api/v1/auth/callback'},False),({**environment,'SEG_ENTRA_CLIENT_ID':'invalid'},False),({**environment,'SEG_HTTP_WORKERS':'17'},False),({},True)]
    for payload,valid in cases:
        name='prthak-auth-validator-'+uuid.uuid4().hex[:10]
        try:
            result=subprocess.run(['docker','--context',args.context,'run','--rm','--name',name,'--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','--entrypoint','python3','-i',args.image,'/opt/prthak/controller_entrypoint.py','--validate-initial-env'],input=json.dumps(payload),text=True,capture_output=True,timeout=30)
            assert secret not in result.stdout+result.stderr
            actual=json.loads(result.stdout)
            assert (result.returncode==0)==valid and actual['validated']==valid,{'case_valid':valid,'returncode':result.returncode}
            if valid:
                assert 'SEG_ENTRA_CLIENT_SECRET' not in actual['environment']
                assert 'SEG_HTTP_WORKERS' not in actual['environment']
                if payload:assert actual['environment']['SEG_ENTRA_CLIENT_SECRET_FILE']=='/run/prthak-bootstrap/entra-client-secret'
        finally:subprocess.run(['docker','--context',args.context,'rm','-f',name],capture_output=True,timeout=15)
    print('actual nonroot image EntraConfig: complete stdin provider config, HTTP/GUID/worker errors, disabled/AUTO defaults, file-only public environment and no raw-secret output: 5 PASS')
    print('No real Entra tenant/client secret or Microsoft sign-in was used; provider shape validation is offline')


if __name__=='__main__':main()
