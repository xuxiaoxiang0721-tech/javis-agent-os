"""Read the local memory model usage meter; never make a model request."""
from pathlib import Path
import argparse
import json
import sys

CODE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODE_ROOT / "tools/memory-adapter"))
from javis_memory_adapter.usage_meter import summary, recent

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=CODE_ROOT)
    parser.add_argument("--recent", type=int, default=20)
    args = parser.parse_args()
    if not 0 <= args.recent <= 500:
        parser.error("--recent must be between 0 and 500")
    print(json.dumps({"summary": summary(args.root), "recent": recent(args.root, limit=args.recent)},
                     ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
