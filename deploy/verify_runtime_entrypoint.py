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
    checks={'--check-host':'host_manager','--check-host-update':'host_update'}
    if len(sys.argv)>1 and sys.argv[1] in checks:
        if len(sys.argv)!=3:raise SystemExit('One fixed host artifact is required')
        verifier.verify('/app','/opt/prthak-integrity/runtime-integrity.json','/opt/prthak-integrity/public-trust.json',component='base',**{checks[sys.argv[1]]:sys.argv[2]})
        print('Signed host runtime bytes verified');raise SystemExit(0)
    verifier.verify('/app','/opt/prthak-integrity/runtime-integrity.json','/opt/prthak-integrity/public-trust.json',component='base')
    os.execvp('python3',['python3','-m','controller',*sys.argv[1:]])
