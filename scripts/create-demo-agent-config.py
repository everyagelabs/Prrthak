#!/usr/bin/env python3
"""Create an isolated loopback-only simulated endpoint configuration."""
import json
from pathlib import Path
import os

root = Path(__file__).resolve().parent.parent
path = root / '.local' / 'demo-agent.json'
path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
config = {'controller_url': 'http://127.0.0.1:8787',
          'state_dir': str(root / '.local' / 'demo-agent'),
          'interval_seconds': 10, 'discovery_interval_seconds': 900, 'demo_agent_id': 'prthak-demo-endpoint', 'enforce': False}
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as stream:
    json.dump(config, stream, indent=2)
print(f'Created {path}. Use this file only with --simulate and the loopback demo.')
