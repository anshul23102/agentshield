"""Run the detector over the curated evaluation set and print precision, recall,
false-positive rate and a per-attack-style breakdown.

    cd backend
    python -m evaluation.evaluate                 # deterministic layers only (no network)
    python -m evaluation.evaluate --llm --delay 2 # include Layer 4 with whichever provider key is set

Rate-limit note: --llm makes one provider call per prompt, so pass --delay to
stay under a free-tier requests-per-minute limit.
"""
import argparse
import asyncio
import json
import os
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _configure_env(use_llm: bool):
    # Importing the detector constructs the analyzer, which reads provider keys
    # from the environment (and from backend/.env). Blank them unless --llm.
    if not use_llm:
        for name in ("GITHUB_TOKEN", "GROQ_API_KEY", "OPENROUTER_API_KEY"):
            os.environ[name] = ""


async def run(use_llm: bool, delay: float, limit: int | None):
    from shield.detector import ThreatDetector
    from evaluation.curated_dataset import rows
    from evaluation import metrics

    detector = ThreatDetector()
    if use_llm and not detector.analyzer.is_llm_available:
        sys.exit("No LLM provider key is configured; set GITHUB_TOKEN, GROQ_API_KEY or OPENROUTER_API_KEY.")

    results = []
    data = list(rows())
    if limit:
        data = data[:limit]
    for text, label, category in data:
        result = await detector.inspect(text, session_id=f"eval-{uuid.uuid4()}", skip_llm=not use_llm)
        results.append({
            "text": text, "label": label, "category": category, "action": result.action,
            "score": result.trust_score, "flagged": result.action in ("warn", "block"),
            "blocked": result.action == "block", "layers": result.layers_executed,
        })
        if use_llm and delay:
            await asyncio.sleep(delay)
    return detector, results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--llm", action="store_true", help="include the LLM layer (needs a provider key; sends prompts to that provider)")
    parser.add_argument("--delay", type=float, default=0.0, help="seconds to wait between LLM calls")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--json", type=str, default=None, help="write raw per-prompt results to this path")
    args = parser.parse_args()
    _configure_env(args.llm)

    from evaluation import metrics
    started = time.time()
    detector, results = asyncio.run(run(args.llm, args.delay, args.limit))

    flagged = metrics.summarize(*metrics.confusion((r["label"], r["flagged"]) for r in results))
    blocked = metrics.summarize(*metrics.confusion((r["label"], r["blocked"]) for r in results))
    mode = f"deterministic layers + LLM ({detector.analyzer.provider})" if args.llm else "deterministic layers only (L1 to L3)"
    print(metrics.format_report(
        f"Curated set, {mode}, {len(results)} prompts",
        flagged, blocked,
        metrics.per_category_recall(results), metrics.per_category_false_positives(results),
        [r["text"] for r in results if r["label"] == "attack" and not r["flagged"]],
        [r["text"] for r in results if r["label"] == "benign" and r["flagged"]],
    ))
    print(f"\n({time.time() - started:.1f}s)")
    if args.json:
        Path(args.json).write_text(json.dumps(results, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
