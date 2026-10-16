"""Measure pre-commit scan latency against the size of the staged change.

For each size, a fresh repository stages N lines of ordinary Python code spread
over files of 100 lines, then each tool scans the staged changes. The median of
several runs is reported. TruffleHog is omitted: its pre-commit mode scans
commits rather than the staging area, so it is not directly comparable.
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

LINE_TEMPLATES = [
    "def handler_{i}(event, context):",
    "    items = [x * {i} for x in range(10) if x % 2 == 0]",
    "    logger.info('processing order %s', event.get('order_id_{i}'))",
    "    return {{'statusCode': 200, 'body': json.dumps(items)}}",
]


def median_ms(cmd, cwd, runs):
    times = []
    for _ in range(runs):
        start = time.perf_counter()
        subprocess.run(cmd, cwd=cwd, capture_output=True)
        times.append((time.perf_counter() - start) * 1000)
    return statistics.median(times)


def make_repo(root, n_lines):
    env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    subprocess.run(["git", "init", "-q"], cwd=root, check=True, env=env)
    per_file = 100
    for f in range(max(1, n_lines // per_file)):
        lines = [LINE_TEMPLATES[i % 4].format(i=f * per_file + i) for i in range(min(per_file, n_lines))]
        with open(os.path.join(root, f"module_{f}.py"), "w") as fh:
            fh.write("\n".join(lines) + "\n")
    subprocess.run(["git", "add", "-A"], cwd=root, check=True, env=env)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", default="10,100,1000,10000")
    ap.add_argument("--runs", type=int, default=7)
    ap.add_argument("--out", default="commit_timing.json")
    args = ap.parse_args()

    project = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env_sg = [sys.executable, "-m", "secret_guard", "scan", "-q"]
    results = []
    for size in map(int, args.sizes.split(",")):
        with tempfile.TemporaryDirectory() as repo:
            make_repo(repo, size)
            os.environ["PYTHONPATH"] = project
            row = {"lines": size, "secret-guard_ms": round(median_ms(env_sg, repo, args.runs), 1)}
            if shutil.which("gitleaks"):
                row["gitleaks_ms"] = round(median_ms(
                    ["gitleaks", "git", "--pre-commit", "--staged", "--no-banner", "--log-level", "error", "."],
                    repo, args.runs), 1)
            results.append(row)
            print(row)
    with open(args.out, "w") as fh:
        json.dump(results, fh, indent=2)


if __name__ == "__main__":
    main()
