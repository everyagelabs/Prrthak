"""Image bootstrap: verify /app before importing any application module."""
import importlib.util
import os
from pathlib import Path
import sys


def verified_module():
    path=Path('/opt/prthak-integrity/runtime_verify.py')
    spec=importlib.util.spec_from_file_location('prthak_image_integrity',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


if __name__=='__main__':
    verifier=verified_module()
    if sys.argv[1:2]==['--check-host']:
        if len(sys.argv)!=3:raise SystemExit('One fixed host-manager artifact is required')
        verifier.verify('/app','/opt/prthak-integrity/runtime-integrity.json','/opt/prthak-integrity/public-trust.json',component='base',host_manager=sys.argv[2])
        print('Signed host-manager runtime bytes verified');raise SystemExit(0)
    verifier.verify('/app','/opt/prthak-integrity/runtime-integrity.json','/opt/prthak-integrity/public-trust.json',component='base')
    os.execvp('python3',['python3','-m','controller',*sys.argv[1:]])
