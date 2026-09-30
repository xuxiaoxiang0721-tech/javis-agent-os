"""Durable local writes and advisory locks."""
import fcntl
import json
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path

@contextmanager
def lock(path, *, shared=False, blocking=True):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a') as f:
        mode = fcntl.LOCK_SH if shared else fcntl.LOCK_EX
        fcntl.flock(f, mode | (0 if blocking else fcntl.LOCK_NB))
        try: yield
        finally: fcntl.flock(f, fcntl.LOCK_UN)

def atomic_json(path, value):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(value, f, ensure_ascii=False, indent=2)
            f.write('\n'); f.flush(); os.fsync(f.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name): os.unlink(name)
