"""Describe the checked-out source without claiming dirty bytes match a commit."""
import os
from pathlib import Path
import subprocess


def provenance(root=None):
    root=Path(root or Path(__file__).resolve().parents[1]).resolve()
    environment=dict(os.environ,GIT_OPTIONAL_LOCKS='0')
    for name in ('GIT_DIR','GIT_WORK_TREE','GIT_COMMON_DIR','GIT_INDEX_FILE',
                 'GIT_OBJECT_DIRECTORY','GIT_ALTERNATE_OBJECT_DIRECTORIES',
                 'GIT_NAMESPACE'):
        environment.pop(name,None)
    def git(*args):
        try:
            result=subprocess.run(['git',*args],cwd=root,env=environment,capture_output=True,text=True,check=False)
        except OSError:
            return None
        return result.stdout.strip() if result.returncode==0 else None
    toplevel=git('rev-parse','--show-toplevel')
    bound=bool(toplevel) and Path(toplevel).resolve()==root
    revision=git('rev-parse','--verify','HEAD') if bound else None
    state=git('status','--porcelain','--untracked-files=normal') if bound else None
    clean=revision is not None and state==''
    return {'source_commit':revision if clean else None,'source_base_commit':revision,
            'source_dirty':not clean,'source_tag':git('describe','--tags','--exact-match','HEAD') if clean else None,
            'artifact_authority':'Externally signed candidate; native OS/DC acceptance is separate'}
