from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from analyzers.phase1_pipeline import Phase1Pipeline
from phase2.pipeline import Phase2Config, Phase2Pipeline


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Phase 1 then evidence-aware Phase 2 multi-agent reasoning.")
    parser.add_argument("path", help="Python/C/C++ file")
    parser.add_argument("--out", default="phase2_report.json")
    parser.add_argument("--provider", default=None, choices=["openai", "claude", "gemini", "ollama"])
    parser.add_argument("--max-groups", type=int, default=50)
    args = parser.parse_args()

    phase1 = Phase1Pipeline()
    report = phase1.analyze_file(args.path)

    phase2 = Phase2Pipeline(Phase2Config(provider=args.provider, max_groups=args.max_groups))
    result = asyncio.run(phase2.analyze_report(report))
    Path(args.out).write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Phase-2 report written to {args.out}")
    print(json.dumps(result["metadata"], indent=2))


if __name__ == "__main__":
    main()
