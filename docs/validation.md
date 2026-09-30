# Public snapshot validation

Validated locally on 2026-09-30, using Python 3.10 in Ubuntu/WSL and a newly
created virtual environment with the pinned workbench dependencies.

| Check | Result |
| --- | --- |
| Python source syntax parsing | Passed |
| Offline task acceptance/replay demo | Passed |
| Input timestamp contracts | 17 passed |
| JSONL Unicode handling | 10 passed |
| Corpus identity scope binding | 16 passed |
| HTTP task-control boundaries | 13 passed |
| Owner passkey verification fixtures | 12 passed |
| RAW original preservation | 15 passed |
| Atomic drop consumer | 20 passed |
| Atomic drop producer | 12 passed |
| Workbench JavaScript syntax | Passed |

**115 selected regression tests passed.** Reproduce the Python checks with
`python scripts/public_smoke.py` after installing the workbench dependencies.

The fixtures use temporary data and synthetic identities. Tests do not validate
live model calls, cloud bot configuration, a complete fresh deployment,
real-device passkey enrollment, Windows scheduled services or unattended use.
The broader integration/test tree has not been fully rerun for this release.

Publication preparation used a source allowlist, credential-pattern review and
an exact comparison against known local secret values. Runtime archives and
private configuration were excluded; account paths and bot identifiers were
replaced with examples. This is not a full security audit.
