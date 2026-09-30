#!/usr/bin/env bash
set -euo pipefail
export JAVIS_INPUT_KIND=original
exec python3 "$(dirname "$0")/role-run.py" gpt-star "$@"
