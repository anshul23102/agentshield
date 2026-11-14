"""Shared scoring helpers for the evaluation scripts."""
from collections import defaultdict


def confusion(rows):
    """rows: iterable of (label, predicted_positive). label is 'attack' or 'benign'."""
    tp = fp = tn = fn = 0
    for label, predicted in rows:
        if label == "attack":
            tp += predicted
            fn += not predicted
        else:
            fp += predicted
            tn += not predicted
    return tp, fp, tn, fn


def summarize(tp, fp, tn, fn):
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) else 0.0
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": precision, "recall": recall,
            "false_positive_rate": fpr, "f1": f1, "accuracy": accuracy}


def per_category_recall(results):
    """results: list of dicts with label, category, flagged."""
    buckets = defaultdict(lambda: [0, 0])
    for r in results:
        if r["label"] != "attack":
            continue
        buckets[r["category"]][1] += 1
        buckets[r["category"]][0] += bool(r["flagged"])
    return {cat: (hit, total) for cat, (hit, total) in sorted(buckets.items())}


def per_category_false_positives(results):
    buckets = defaultdict(lambda: [0, 0])
    for r in results:
        if r["label"] != "benign":
            continue
        buckets[r["category"]][1] += 1
        buckets[r["category"]][0] += bool(r["flagged"])
    return {cat: (bad, total) for cat, (bad, total) in sorted(buckets.items())}


def format_report(title, summary_flagged, summary_blocked, attack_cats, benign_cats, misses, false_positives, show=10):
    lines = [f"== {title} =="]
    for name, s in (("flagged (warn or block)", summary_flagged), ("blocked only", summary_blocked)):
        lines.append(
            f"{name:26s} precision {s['precision']:.3f}  recall {s['recall']:.3f}  F1 {s['f1']:.3f}  "
            f"false-positive rate {s['false_positive_rate']:.3f}  (TP {s['tp']} FP {s['fp']} TN {s['tn']} FN {s['fn']})"
        )
    if attack_cats:
        lines.append("recall by attack style:")
        for cat, (hit, total) in attack_cats.items():
            lines.append(f"  {cat:22s} {hit:3d}/{total:<3d} = {hit / total:.2f}")
    if benign_cats:
        lines.append("false positives by benign type:")
        for cat, (bad, total) in benign_cats.items():
            lines.append(f"  {cat:22s} {bad:3d}/{total:<3d} = {bad / total:.2f}")
    if false_positives:
        lines.append(f"benign prompts wrongly flagged (first {show}):")
        lines += [f"  - {t[:110]}" for t in false_positives[:show]]
    if misses:
        lines.append(f"attacks missed (first {show}):")
        lines += [f"  - {t[:110]}" for t in misses[:show]]
    return "\n".join(lines)
