#!/usr/bin/env python3
"""Compatibility entry point for the Javis task runtime."""
import sys
from task_runtime import run
from raw_policy import sanitize
if __name__ == '__main__':
    try: code=run(sys.argv[1:])
    except BlockingIOError: print('task already running',file=sys.stderr); code=75
    except (ValueError,KeyError,FileNotFoundError) as exc: print(sanitize(str(exc)),file=sys.stderr); code=2
    sys.exit(code)
