"""Thin wrappers around the git CLI."""

import re
import subprocess

HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


class GitError(RuntimeError):
    pass


def git(*args, cwd=None, check=True) -> str:
    proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    if check and proc.returncode != 0:
        raise GitError(proc.stderr.strip() or f"git {' '.join(args)} failed")
    return proc.stdout


def repo_root(cwd=None) -> str:
    return git("rev-parse", "--show-toplevel", cwd=cwd).strip()


def parse_added_lines(diff_text: str):
    """Parse a unified diff into {path: [(lineno, text), ...]} of added lines only.

    Deleted files are skipped; binary files produce no hunks and are ignored.
    """
    files, current, lineno = {}, None, 0
    for raw in diff_text.splitlines():
        if raw.startswith("+++ "):
            target = raw[4:]
            current = None if target == "/dev/null" else target[2:] if target.startswith("b/") else target
            if current is not None:
                files.setdefault(current, [])
            continue
        if raw.startswith("--- ") or raw.startswith("diff --git"):
            continue
        m = HUNK_HEADER.match(raw)
        if m:
            lineno = int(m.group(1))
            continue
        if current is None:
            continue
        if raw.startswith("+"):
            files[current].append((lineno, raw[1:]))
            lineno += 1
        elif raw.startswith(" "):
            lineno += 1
    return files


def staged_diff(cwd=None) -> str:
    return git("diff", "--cached", "--unified=0", "--no-color", "--no-ext-diff",
               "--diff-filter=ACMR", cwd=cwd)


def range_diff(since: str, cwd=None) -> str:
    # Three-dot form compares against the merge base, which is what a PR introduces.
    return git("diff", "--unified=0", "--no-color", "--no-ext-diff",
               "--diff-filter=ACMR", f"{since}...HEAD", cwd=cwd)


def changed_files(diff_args, cwd=None):
    out = git("diff", "--name-only", "--diff-filter=ACMR", *diff_args, cwd=cwd)
    return [p for p in out.splitlines() if p]


def ignored_paths(paths, cwd=None) -> set:
    """Return the subset of paths that .gitignore excludes."""
    if not paths:
        return set()
    proc = subprocess.run(["git", "check-ignore", "--stdin"], cwd=cwd, input="\n".join(paths),
                          capture_output=True, text=True)
    return set(proc.stdout.splitlines())
