"""Core scanning logic shared by the commit hook, CI mode and audit mode."""

from dataclasses import dataclass, asdict

from .config import IGNORE_MARKER, Config, fingerprint
from .rules import (classify_charset, entropy_candidates, forbidden_file,
                    is_placeholder, shannon_entropy)


@dataclass
class Finding:
    path: str
    line: int          # 0 when the finding concerns the file itself
    rule_id: str
    description: str
    secret: str        # raw value; never printed, only masked or fingerprinted

    @property
    def masked(self) -> str:
        if self.line == 0:
            return ""
        visible = min(4, len(self.secret) // 4)
        return self.secret[:visible] + "*" * min(len(self.secret) - visible, 28)

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.secret) if self.secret else ""

    def to_dict(self) -> dict:
        d = asdict(self)
        del d["secret"]
        d["masked"] = self.masked
        d["fingerprint"] = self.fingerprint
        return d


def scan_filename(path: str, cfg: Config):
    if forbidden_file(path) and not cfg.path_excluded(path):
        return [Finding(path, 0, "forbidden-file", "Credential file must not be committed", "")]
    return []


def scan_line(path: str, lineno: int, text: str, cfg: Config):
    """Return findings for one line. Rule matches take precedence over entropy."""
    if IGNORE_MARKER in text:
        return []
    findings, taken = [], []

    def overlaps(start, end):
        return any(start < e and s < end for s, e in taken)

    for rule in cfg.rules:
        for m in rule.pattern.finditer(text):
            start, end = m.span(1)
            value = m.group(1)
            if overlaps(start, end) or is_placeholder(value):
                continue
            if rule.min_entropy and shannon_entropy(value) < rule.min_entropy:
                continue
            taken.append((start, end))
            findings.append(Finding(path, lineno, rule.id, rule.description, value))

    if cfg.entropy_enabled:
        for start, end, value in entropy_candidates(text):
            if len(value) < cfg.entropy_min_length or overlaps(start, end):
                continue
            if is_placeholder(value) or value.startswith(("http://", "https://", "/")):
                continue
            charset = classify_charset(value)
            threshold = {"hex": cfg.entropy_hex, "base64": cfg.entropy_base64}.get(charset)
            if threshold is None or shannon_entropy(value) < threshold:
                continue
            # Hex strings of SHA-1/SHA-256 length are usually commit IDs or digests.
            if charset == "hex" and len(value) in (40, 64):
                continue
            taken.append((start, end))
            findings.append(Finding(path, lineno, f"high-entropy-{charset}",
                                    "High-entropy string (possible secret)", value))

    return [f for f in findings if f.fingerprint not in cfg.allowed_fingerprints]


def scan_lines(path: str, numbered_lines, cfg: Config):
    """numbered_lines: iterable of (lineno, text)."""
    if cfg.path_excluded(path):
        return []
    out = []
    for lineno, text in numbered_lines:
        out.extend(scan_line(path, lineno, text, cfg))
    return out


def read_text_file(path: str, max_bytes: int = 1_000_000):
    """Return file lines, or None for binary / oversized / unreadable files."""
    try:
        with open(path, "rb") as fh:
            data = fh.read(max_bytes + 1)
    except OSError:
        return None
    if len(data) > max_bytes or b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace").splitlines()
