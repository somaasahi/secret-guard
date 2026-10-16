"""Run secret-guard, gitleaks and TruffleHog on the labelled corpus and score them.

Scoring is per line: a finding on a line labelled as a secret is a true
positive; a finding on any other line is a false positive; a secret line with
no finding is a false negative. Filename-only findings (secret-guard's
forbidden-file rule) are excluded so every tool is judged on content alone.
TruffleHog runs with --no-verification so no fake key is sent to any provider.
"""

import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict


def timed(cmd, cwd=None, runs=5):
    times, proc = [], None
    for _ in range(runs):
        start = time.perf_counter()
        proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
        times.append((time.perf_counter() - start) * 1000)
    return proc, statistics.median(times)


def rel(path, root):
    return os.path.relpath(os.path.join(root, path) if not os.path.isabs(path) else path, root)


def run_secret_guard(files_root, entropy, runs):
    with tempfile.TemporaryDirectory() as cwd:
        with open(os.path.join(cwd, ".secretguard.json"), "w") as fh:
            json.dump({"entropy": {"enabled": entropy}}, fh)
        proc, ms = timed([sys.executable, "-m", "secret_guard", "scan", "--files", files_root,
                          "--format", "json"], cwd=cwd, runs=runs)
    found = {(rel(f["path"], files_root), f["line"]) for f in json.loads(proc.stdout)["findings"] if f["line"]}
    return found, ms


def run_gitleaks(files_root, runs):
    with tempfile.TemporaryDirectory() as tmp:
        report = os.path.join(tmp, "report.json")
        _, ms = timed(["gitleaks", "dir", files_root, "--report-format", "json", "--report-path", report,
                       "--no-banner", "--log-level", "error"], runs=runs)
        with open(report) as fh:
            data = json.load(fh)
    return {(rel(f["File"], files_root), f["StartLine"]) for f in data}, ms


def run_trufflehog(files_root, runs):
    proc, ms = timed(["trufflehog", "filesystem", files_root, "--json", "--no-verification", "--no-update",
                      "--results=verified,unverified,unknown"], runs=runs)
    found = set()
    for line in proc.stdout.splitlines():
        try:
            meta = json.loads(line)["SourceMetadata"]["Data"]["Filesystem"]
        except (ValueError, KeyError):
            continue
        found.add((rel(meta["file"], files_root), meta.get("line", 0)))
    return found, ms


def score(found, labels):
    """Score per credential. A credential spanning several lines (an AWS key pair, a
    PEM block) is one unit, detected if any of its lines is flagged; findings inside
    a PEM body belong to that key rather than counting as false positives."""
    unit_of_line = {(l["path"], l["line"]): l["group"] for l in labels if l["secret"]}
    pem_start = {l["path"]: (l["line"], l["group"]) for l in labels if l["category"] == "private-key"}

    def unit_of(item):
        if item in unit_of_line:
            return unit_of_line[item]
        path, line = item
        if path in pem_start and line >= pem_start[path][0]:
            return pem_start[path][1]
        return None

    secret_units = set(unit_of_line.values())
    flagged_units = {unit_of(f) for f in found} - {None}
    tp = len(flagged_units & secret_units)
    fn = len(secret_units) - tp
    fp = sum(1 for f in found if unit_of(f) is None)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    by_category = defaultdict(lambda: [set(), set()])  # category -> [flagged units, all units]
    for l in labels:
        by_category[l["category"]][1].add(l["group"])
        hit = l["group"] in flagged_units if l["secret"] else (l["path"], l["line"]) in found
        if hit:
            by_category[l["category"]][0].add(l["group"])
    return {"tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall, "f1": f1,
            "by_category": {k: {"flagged": len(v[0]), "total": len(v[1])} for k, v in sorted(by_category.items())}}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus", help="directory produced by make_corpus.py")
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--out", default="bench_results.json")
    args = ap.parse_args()

    files_root = os.path.abspath(os.path.join(args.corpus, "files"))
    with open(os.path.join(args.corpus, "labels.json")) as fh:
        labels = json.load(fh)

    tools = {
        "secret-guard (rules + entropy)": lambda: run_secret_guard(files_root, True, args.runs),
        "secret-guard (rules only)": lambda: run_secret_guard(files_root, False, args.runs),
    }
    if shutil.which("gitleaks"):
        tools["gitleaks"] = lambda: run_gitleaks(files_root, args.runs)
    if shutil.which("trufflehog"):
        tools["TruffleHog (verification off)"] = lambda: run_trufflehog(files_root, args.runs)

    results = {}
    for name, run in tools.items():
        found, ms = run()
        results[name] = {**score(found, labels), "median_ms": round(ms, 1)}

    with open(args.out, "w") as fh:
        json.dump(results, fh, indent=2)

    print(f"{'Tool':<32}{'TP':>5}{'FP':>5}{'FN':>5}{'Prec':>8}{'Recall':>8}{'F1':>7}{'ms':>9}")
    for name, r in results.items():
        print(f"{name:<32}{r['tp']:>5}{r['fp']:>5}{r['fn']:>5}{r['precision']:>8.3f}{r['recall']:>8.3f}"
              f"{r['f1']:>7.3f}{r['median_ms']:>9.1f}")


if __name__ == "__main__":
    main()
