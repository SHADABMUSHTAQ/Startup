#!/usr/bin/env python3
"""Wrapper: load .env into environment then run scripts/load_http.py.

This avoids placing secrets on the command line; the wrapper reads .env
in the repo root and sets those keys in os.environ before invoking the
HTTP load generator.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for raw in path.read_text(encoding='utf-8').splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if '=' not in line:
            continue
        key, val = line.split('=', 1)
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        # do not override existing environment variables
        os.environ.setdefault(key, val)


def main() -> int:
    base = Path(__file__).resolve().parents[1]
    dotenv = base / '.env'
    load_dotenv(dotenv)

    cmd = [sys.executable, str(base / 'scripts' / 'load_http.py')] + sys.argv[1:]
    print('Wrapper running:', ' '.join(cmd))
    # run in repo root so relative paths like tmp/phase2 are correct
    rc = subprocess.run(cmd, cwd=str(base)).returncode
    return rc


if __name__ == '__main__':
    raise SystemExit(main())
