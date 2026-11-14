"""Evaluate the detector on a PUBLIC prompt-injection dataset the author did not write.

    cd backend
    python -m evaluation.evaluate_public                       # deterministic layers only
    python -m evaluation.evaluate_public --llm --delay 2       # with the configured LLM provider

Dataset: deepset/prompt-injections on Hugging Face (Apache 2.0), labels 1 = injection,
0 = legitimate. It mixes English and German, and many "injections" are role-play
or jailbreak style rather than the textbook "ignore previous instructions", which
makes it a hard, honest test for a signature-based detector.

The rows are read over HTTPS into memory through the public datasets-server API
and are never written to disk or committed. Do NOT tune patterns against this
dataset's attack texts: that would turn an independent check into a training set.
"""
import argparse
import asyncio
import json
import os
import sys
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

API = "https://datasets-server.huggingface.co/rows"
DATASET = "deepset/prompt-injections"


def fetch(split: str):
    rows, offset = [], 0
    while True:
        query = urllib.parse.urlencode({"dataset": DATASET, "config": "default", "split": split, "offset": offset, "length": 100})
        with urllib.request.urlopen(f"{API}?{query}", timeout=30) as resp:
            payload = json.load(resp)
        batch = payload.get("rows", [])
        rows += [(r["row"]["text"], "attack" if r["row"]["label"] == 1 else "benign") for r in batch]
        offset += len(batch)
        if not batch or offset >= payload.get("num_rows_total", 0):
            return rows


async def run(rows, use_llm, delay):
    from shield.detector import ThreatDetector
    detector = ThreatDetector()
    if use_llm and not detector.analyzer.is_llm_available:
        sys.exit("No LLM provider key is configured.")
    out = []
    for text, label in rows:
        res = await detector.inspect(text[:20000], session_id=f"pub-{uuid.uuid4()}", skip_llm=not use_llm)
        out.append({"text": text, "label": label, "flagged": res.action in ("warn", "block"), "blocked": res.action == "block"})
        if use_llm and delay:
            await asyncio.sleep(delay)
    return detector, out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--split", default="test", choices=["train", "test", "both"])
    parser.add_argument("--llm", action="store_true")
    parser.add_argument("--delay", type=float, default=0.0)
    args = parser.parse_args()
    if not args.llm:
        for name in ("GITHUB_TOKEN", "GROQ_API_KEY", "OPENROUTER_API_KEY"):
            os.environ[name] = ""

    from evaluation import metrics
    rows = []
    for split in (["train", "test"] if args.split == "both" else [args.split]):
        rows += fetch(split)
    detector, results = asyncio.run(run(rows, args.llm, args.delay))
    flagged = metrics.summarize(*metrics.confusion((r["label"], r["flagged"]) for r in results))
    blocked = metrics.summarize(*metrics.confusion((r["label"], r["blocked"]) for r in results))
    mode = f"LLM ({detector.analyzer.provider}) + deterministic" if args.llm else "deterministic layers only"
    attacks = sum(r["label"] == "attack" for r in results)
    print(metrics.format_report(
        f"{DATASET} [{args.split}], {mode}, {len(results)} prompts ({attacks} injections)",
        flagged, blocked, {}, {},
        [], [r["text"] for r in results if r["label"] == "benign" and r["flagged"]],
    ))


if __name__ == "__main__":
    main()
