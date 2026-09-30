#!/usr/bin/env bash
# Entry: rebuild Neo4j group from a meta_dir structured store (no LLM).
set -euo pipefail
META_DIR="${1:?meta_dir required}"
GROUP_ID="${2:?target group_id required}"
export JAVA_HOME="${JAVA_HOME:-$HOME/javis/tools/jdk-21}"
export PATH="$JAVA_HOME/bin:$PATH"
ROOT="${JAVIS_MEMORY_ADAPTER_ROOT:-$HOME/javis/tools/memory-adapter}"
bash "$ROOT/scripts/neo4j-managed.sh" start
source "$HOME/javis/tools/graphiti/.venv/bin/activate"
set -a; source "$HOME/javis/tools/graphiti/.env"; set +a
export PYTHONPATH="$ROOT:${PYTHONPATH:-}"
python3 - << PY
import asyncio, os
from pathlib import Path
from javis_memory_adapter.structured_store import StructuredStore
from javis_memory_adapter.type_b import rebuild_group_from_store
store=StructuredStore(Path("$META_DIR"))
async def main():
    r=await rebuild_group_from_store(
        store=store,
        target_group_id="$GROUP_ID",
        neo4j_uri=os.environ["NEO4J_URI"],
        neo4j_user=os.environ["NEO4J_USER"],
        neo4j_password=os.environ["NEO4J_PASSWORD"],
    )
    import json; print(json.dumps(r, ensure_ascii=False, indent=2))
asyncio.run(main())
PY
