"""Install and remove the pre-commit hook, per repository or machine-wide."""

import os
import stat
import sys

from .gitutil import git

MARKER = "# managed-by: secret-guard"
BACKUP_SUFFIX = ".secret-guard-backup"
GLOBAL_HOOKS_DIR = os.path.expanduser("~/.config/secret-guard/hooks")
GLOBAL_STATE_FILE = os.path.expanduser("~/.config/secret-guard/previous-hooksPath")

# Repository-level hook: runs any pre-existing hook first, then the scanner.
REPO_HOOK = """#!/bin/sh
{marker}
HOOK_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -x "$HOOK_DIR/pre-commit{backup}" ]; then
  "$HOOK_DIR/pre-commit{backup}" "$@" || exit $?
fi
exec "{python}" -m secret_guard scan
"""

# Global hook: core.hooksPath disables .git/hooks, so chain to the repo's own hook.
GLOBAL_HOOK = """#!/bin/sh
{marker}
LOCAL_HOOK="$(git rev-parse --git-dir)/hooks/pre-commit"
if [ -x "$LOCAL_HOOK" ] && ! grep -q "{marker}" "$LOCAL_HOOK"; then
  "$LOCAL_HOOK" "$@" || exit $?
fi
exec "{python}" -m secret_guard scan
"""


def _write_executable(path: str, content: str):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _is_ours(path: str) -> bool:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return MARKER in fh.read()
    except OSError:
        return False


def repo_hooks_dir() -> str:
    path = git("rev-parse", "--git-path", "hooks").strip()
    return os.path.abspath(path)


def install_repo() -> str:
    hooks = repo_hooks_dir()
    os.makedirs(hooks, exist_ok=True)
    hook = os.path.join(hooks, "pre-commit")
    if os.path.exists(hook) and not _is_ours(hook):
        os.replace(hook, hook + BACKUP_SUFFIX)
    _write_executable(hook, REPO_HOOK.format(marker=MARKER, backup=BACKUP_SUFFIX,
                                             python=sys.executable))
    return hook


def uninstall_repo() -> str:
    hook = os.path.join(repo_hooks_dir(), "pre-commit")
    if not _is_ours(hook):
        return "secret-guard hook not installed in this repository"
    os.remove(hook)
    if os.path.exists(hook + BACKUP_SUFFIX):
        os.replace(hook + BACKUP_SUFFIX, hook)
        return f"Removed hook and restored previous hook at {hook}"
    return f"Removed {hook}"


def install_global() -> str:
    os.makedirs(GLOBAL_HOOKS_DIR, exist_ok=True)
    previous = git("config", "--global", "--get", "core.hooksPath", check=False).strip()
    if previous and os.path.abspath(os.path.expanduser(previous)) != GLOBAL_HOOKS_DIR:
        with open(GLOBAL_STATE_FILE, "w", encoding="utf-8") as fh:
            fh.write(previous)
    hook = os.path.join(GLOBAL_HOOKS_DIR, "pre-commit")
    _write_executable(hook, GLOBAL_HOOK.format(marker=MARKER, python=sys.executable))
    git("config", "--global", "core.hooksPath", GLOBAL_HOOKS_DIR)
    return hook


def uninstall_global() -> str:
    current = git("config", "--global", "--get", "core.hooksPath", check=False).strip()
    if os.path.abspath(os.path.expanduser(current or "")) != GLOBAL_HOOKS_DIR:
        return "secret-guard is not the global hooks path; nothing changed"
    if os.path.exists(GLOBAL_STATE_FILE):
        with open(GLOBAL_STATE_FILE, encoding="utf-8") as fh:
            git("config", "--global", "core.hooksPath", fh.read().strip())
        os.remove(GLOBAL_STATE_FILE)
        return "Restored previous global core.hooksPath"
    git("config", "--global", "--unset", "core.hooksPath")
    return "Removed global core.hooksPath"
