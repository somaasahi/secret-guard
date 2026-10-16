"""Local exposure audit.

Git-centric scanners only ask "will this secret enter the repository?".
AI coding agents read the working tree directly, so a secret in a git-ignored
.env file is invisible to Git but fully visible to the agent. This module
reports secrets from the agent's point of view.
"""

import json
import os
from dataclasses import dataclass, field

from .config import Config
from .gitutil import ignored_paths
from .rules import forbidden_file
from .scanner import Finding, read_text_file, scan_lines

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox",
             ".mypy_cache", ".pytest_cache", "dist", "build", ".next", "vendor"}

# Claude Code settings files, from most to least specific.
CLAUDE_SETTINGS = (".claude/settings.local.json", ".claude/settings.json",
                   "~/.claude/settings.json")


@dataclass
class AuditReport:
    tracked: list = field(default_factory=list)       # secrets in files Git would track
    git_ignored: list = field(default_factory=list)   # secrets hidden from Git, visible to agents
    agent_read_protected: bool = False
    protected_by: list = field(default_factory=list)
    aws_long_term_keys: bool = False

    @property
    def exposed(self) -> bool:
        # A Read() deny rule is only a partial mitigation: it does not cover indirect
        # reads such as `grep -r` or a script opening the file, so plaintext secrets
        # always count as exposed.
        return bool(self.tracked or self.git_ignored)


def walk_files(root: str):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                continue
            yield os.path.relpath(full, root)


def claude_deny_rules(root: str):
    """Return Claude Code permission deny entries that protect .env-style files."""
    hits = []
    for candidate in CLAUDE_SETTINGS:
        path = os.path.expanduser(candidate) if candidate.startswith("~") else os.path.join(root, candidate)
        try:
            with open(path, encoding="utf-8") as fh:
                deny = json.load(fh).get("permissions", {}).get("deny", [])
        except (OSError, ValueError):
            continue
        for entry in deny:
            if isinstance(entry, str) and entry.startswith("Read(") and ".env" in entry:
                hits.append(f"{candidate}: {entry}")
    return hits


def has_aws_long_term_keys() -> bool:
    """Long-term IAM user keys on a developer machine let an agent call AWS as the developer."""
    path = os.path.expanduser(os.environ.get("AWS_SHARED_CREDENTIALS_FILE", "~/.aws/credentials"))
    lines = read_text_file(path) or []
    return any("aws_access_key_id" in l and "AKIA" in l for l in lines)


def run_audit(root: str, cfg: Config) -> AuditReport:
    report = AuditReport()
    paths = list(walk_files(root))
    ignored = ignored_paths(paths, cwd=root)
    for rel in paths:
        if cfg.path_excluded(rel):
            continue
        lines = read_text_file(os.path.join(root, rel))
        findings = []
        if lines is not None:
            findings = scan_lines(rel, enumerate(lines, start=1), cfg)
        if not findings and forbidden_file(rel) and lines:
            findings = [Finding(rel, 0, "forbidden-file", "Credential file present in working tree", "")]
        (report.git_ignored if rel in ignored else report.tracked).extend(findings)

    report.protected_by = claude_deny_rules(root)
    report.agent_read_protected = bool(report.protected_by)
    report.aws_long_term_keys = has_aws_long_term_keys()
    return report
