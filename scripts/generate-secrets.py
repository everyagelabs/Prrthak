#!/usr/bin/env python3
"""Create local controller role tokens without printing credentials."""
import os
from pathlib import Path
import secrets
import sys

path = Path(sys.argv[1] if len(sys.argv) > 1 else '.local/controller.env')
path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as stream:
    for role in ('SUPER_ADMIN', 'ADMIN', 'READ_ONLY'):
        stream.write(f'SEG_{role}_TOKEN={secrets.token_urlsafe(36)}\n')
print(f'Created role credentials in {path}; permissions 0600. Keep this file private.')
