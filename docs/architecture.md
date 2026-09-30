# Architecture

Javis separates task acceptance, execution, evidence and memory.

## Task path

A trusted adapter constructs a Principal and submits original text to
`scripts/task_service.py`. Task acceptance persists a control event and queues
execution. Replaying the same command returns the original receipt; a changed
payload under the same identity is rejected.

`scripts/task_dispatch.py`, `role-run.py` and `task_runtime.py` handle
dispatch and worker execution. An attempt's executor-authored result determines
completion. A worker's final message alone does not establish successful delivery.

## Evidence and memory

`raw_storage.py` preserves event provenance and file snapshots. Safe projections
and encrypted sensitive originals have distinct access paths. Runtime data stays
outside version control.

The memory modules cover intake, scope binding, proposals, review, revision,
recall and usage records. `tools/memory-adapter/javis_memory_adapter/` contains
the structured ledger and optional graph projection. Confirmed decisions and
projection health are separate: an unavailable graph does not undo a recorded
owner decision.

## Workbench and trust

`control-panel.py` serves the static assets in `tools/control-panel/web/`.
It binds to loopback port 8766. Owner-sensitive operations use passkey proofs
bound to a decision; browser-supplied identity fields do not establish ownership.

The native worker policy restricts tools to reviewed role/task inputs and
outputs. Role workspaces do not create OS account isolation. Local administrators
remain within the trust boundary.

## Public snapshot

Published numeric bot IDs and UUIDs are synthetic fixtures. Personal role labels
and account paths have been generalized. The original runtime's credentials,
state, memory contents and service configuration are not included.
