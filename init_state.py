#!/usr/bin/env python3
"""Create private local credentials without replacing existing files."""
import os
from pathlib import Path
import secrets

ROOT = Path(__file__).resolve().parent

if __name__ == '__main__':
    os.umask(0o077)
    state = ROOT / 'state'
    state.mkdir(mode=0o700, exist_ok=True)
    for name in ('api.token', 'agent.token'):
        path = state / name
        try:
            with path.open('x') as stream:
                stream.write(secrets.token_hex(32) + '\n')
        except FileExistsError:
            print('Kept existing', path)
        else:
            print('Created', path)
