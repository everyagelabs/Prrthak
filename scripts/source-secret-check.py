#!/usr/bin/env python3
"""Check staged repository content without printing matched credentials."""
import argparse
import re
import subprocess
from pathlib import PurePosixPath

PATTERNS={
    'complete private key':re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----\s+[A-Za-z0-9+/=\r\n]{64,}-----END (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----'),
    'GitHub credential':re.compile(rb'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,})\b'),
    'AWS access identifier':re.compile(rb'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'),
}
parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--worktree',action='store_true');args=parser.parse_args()
files=subprocess.check_output(['git','ls-files','--cached','-z']).split(b'\0');problems=[]
for raw in files:
    if not raw:continue
    name=raw.decode();path=PurePosixPath(name)
    if path.parts[0] in ('.local','tmp','dist') or path.name=='.env' or path.name.startswith('.env.') and path.name!='.env.example' or path.suffix.lower() in ('.seed','.key','.p12','.pfx','.token','.sqlite','.sqlite3','.db'):
        problems.append((name,'private/runtime path'));continue
    data=subprocess.check_output(['git','show',':'+name]) if not args.worktree else __import__('pathlib').Path(name).read_bytes()
    for kind,pattern in PATTERNS.items():
        if pattern.search(data):problems.append((name,kind))
if problems:
    for name,kind in problems:print(name+': '+kind+' detected (value hidden)')
    raise SystemExit(1)
print('Staged source check passed: '+str(sum(bool(name) for name in files))+' files; no prohibited private paths or complete credential patterns')
