#!/usr/bin/env python3
"""Selected isolated checks for the public source snapshot; no live providers."""
import ast
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SUITES = [
    ('tests', 'test_input_times.py'),
    ('tests', 'test_jsonl_unicode.py'),
    ('tests', 'test_memory_corpus_scope.py'),
    ('tests', 'test_control_http.py'),
    ('tests', 'test_owner_auth.py'),
    ('tests', 'test_raw_preservation_v3.py'),
    ('scripts/tests/v02', 'test_drop_bridge.py'),
    ('scripts/tests/v02', 'test_submit_drop.py'),
]

def main():
    for folder in ('scripts', 'tests', 'tools', 'examples'):
        for path in (ROOT / folder).rglob('*.py'):
            if any(part in {'.venv', 'venv', '__pycache__', 'node_modules'} for part in path.parts):
                continue
            ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', JAVIS_TEST_CODE_ROOT=str(ROOT))
    env['PYTHONPATH'] = os.pathsep.join([str(ROOT / 'scripts'), str(ROOT / 'tools/memory-adapter')])
    subprocess.run([sys.executable, str(ROOT / 'examples/offline_demo.py')], cwd=ROOT, env=env, check=True)
    failed = []
    for directory, pattern in SUITES:
        print(f'Checking {directory}/{pattern}', flush=True)
        run = subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-s', directory, '-p', pattern],
                             cwd=ROOT, env=env, timeout=120)
        if run.returncode:
            failed.append(pattern)
    if failed:
        print('Failed suites: ' + ', '.join(failed), file=sys.stderr)
        return 1
    print('Public smoke checks passed: syntax, offline demo, and 8 isolated suites.')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
