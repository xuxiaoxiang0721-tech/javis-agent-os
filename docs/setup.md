# Setup

## Start with the offline demo

Use Linux or WSL with Python 3.10 or newer. From the repository root:

```bash
python3 examples/offline_demo.py
```

This path only uses the standard library and synthetic temporary data.

## Explore the local browser workbench

The optional workbench needs its Python dependencies. Run from a clone in the
Linux filesystem, not from your existing production Javis directory:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r tools/control-panel/requirements.lock
python scripts/control-panel.py --root "$PWD" --enroll-owner
```

Open **http://localhost:8766**. The explicit enrollment flag opens a ten-minute
window for registering the local owner's passkey. Browser/WSL passkey support
depends on the host. Keep the service on localhost.

The workbench does not start the task dispatcher. Data created while exploring
is kept under ignored local runtime directories. This is an exploration recipe,
not a verified unattended deployment procedure.

## Before connecting real agents

1. Review `scripts/role_registry.py` and replace synthetic bot identities with
   your verified mappings. The export helper also has a separate mapping in
   `scripts/export-javis-confirmed-for-grok.py`.
2. Create the corresponding `workspace/roles/<role-id>/` directories and supply
   your own role instructions. Private role prompts are not included.
3. Review the worker permissions and install/authenticate a compatible Codex CLI.
   The execution adapter uses CLI permission options that may be version-specific.
4. Configure the memory provider and, if needed, Graphiti/Neo4j separately. The
   core ledger and graph projection are separate modules. Provider login and
   API-key flows depend on your own provider configuration.
5. Set `JAVIS_ROOT` for runtime entry points that support it. Set
   `JAVIS_DROP_BASE` or pass `--base` for the public drop producer/consumer.
   Review other scripts for installation-specific defaults before use.
6. Adapt Windows scheduling, backup and lifecycle templates to your account and
   paths, and validate one isolated task before enabling scheduled dispatch.

Examples under `/home/user/` and `C:\Users\user\` are placeholders.
The reference service, graph and Windows helper scripts are not a portable installer.

## Tests

The selected smoke suite uses disposable fixtures. It needs the workbench
dependencies above and does not require provider credentials:

```bash
python scripts/public_smoke.py
```

The larger source tree also contains environment-dependent and live integration
checks. Review their prerequisites before running them. Do not point test roots
at an existing personal deployment.
