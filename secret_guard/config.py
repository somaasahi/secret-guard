"""Per-repository configuration (.secretguard.json) and allowlist (.secretguard-allow)."""

import fnmatch
import hashlib
import json
import os
import re
from dataclasses import dataclass, field

from .rules import BUILTIN_RULES, Rule

CONFIG_FILE = ".secretguard.json"
ALLOW_FILE = ".secretguard-allow"
IGNORE_MARKER = "secretguard:ignore"

DEFAULT_EXCLUDE_PATHS = (
    ".git/*", "node_modules/*", "*/node_modules/*", "vendor/*", ".venv/*", "venv/*",
    "*.lock", "package-lock.json", "*.min.js", "*.map", "*.svg",
)


@dataclass
class Config:
    entropy_base64: float = 4.5
    entropy_hex: float = 3.0
    entropy_min_length: int = 20
    entropy_enabled: bool = True
    exclude_paths: tuple = DEFAULT_EXCLUDE_PATHS
    rules: list = field(default_factory=lambda: list(BUILTIN_RULES))
    allowed_paths: list = field(default_factory=list)
    allowed_fingerprints: set = field(default_factory=set)

    def path_excluded(self, path: str) -> bool:
        return any(fnmatch.fnmatch(path, g) for g in self.exclude_paths) or any(
            fnmatch.fnmatch(path, g) for g in self.allowed_paths
        )


def fingerprint(value: str) -> str:
    """Stable identifier that lets users allowlist a value without storing it."""
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()[:16]


def load_config(root: str) -> Config:
    cfg = Config()
    path = os.path.join(root, CONFIG_FILE)
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        ent = data.get("entropy", {})
        cfg.entropy_enabled = ent.get("enabled", cfg.entropy_enabled)
        cfg.entropy_base64 = ent.get("base64", cfg.entropy_base64)
        cfg.entropy_hex = ent.get("hex", cfg.entropy_hex)
        cfg.entropy_min_length = ent.get("min_length", cfg.entropy_min_length)
        cfg.exclude_paths = tuple(cfg.exclude_paths) + tuple(data.get("exclude_paths", []))
        disabled = set(data.get("disable_rules", []))
        cfg.rules = [r for r in cfg.rules if r.id not in disabled]
        for extra in data.get("extra_rules", []):
            cfg.rules.append(Rule(extra["id"], extra.get("description", extra["id"]),
                                  re.compile(extra["regex"]), extra.get("min_entropy", 0.0)))

    allow = os.path.join(root, ALLOW_FILE)
    if os.path.isfile(allow):
        with open(allow, encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("sha256:"):
                    cfg.allowed_fingerprints.add(line)
                else:
                    cfg.allowed_paths.append(line)
    return cfg
