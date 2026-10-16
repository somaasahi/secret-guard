"""Detection rules: forbidden filenames, known secret formats, and entropy."""

import fnmatch
import math
import os
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    pattern: re.Pattern
    # Minimum entropy the captured value must reach (0 = no check).
    # Used by generic rules to suppress low-randomness values such as "password123".
    min_entropy: float = 0.0


def _r(rule_id, description, regex, min_entropy=0.0):
    return Rule(rule_id, description, re.compile(regex), min_entropy)


# Each pattern must expose the secret value as capture group 1.
# Ordered from most to least specific; overlapping matches are de-duplicated
# so the first (most specific) rule wins.
BUILTIN_RULES = [
    _r("private-key", "Private key block",
       r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)"),
    _r("aws-access-key-id", "AWS access key ID",
       r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"),
    _r("aws-secret-access-key", "AWS secret access key",
       r"(?i)aws.{0,20}?(?:secret|private).{0,20}?[\s:=\"']+([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"),
    _r("github-token", "GitHub token",
       r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255})\b"),
    _r("github-fine-grained-pat", "GitHub fine-grained PAT",
       r"\b(github_pat_[A-Za-z0-9_]{82})\b"),
    _r("anthropic-api-key", "Anthropic API key",
       r"\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,})"),
    _r("openai-api-key", "OpenAI API key",
       r"\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,})"),
    _r("stripe-secret-key", "Stripe secret/restricted key",
       r"\b((?:sk|rk)_live_[0-9A-Za-z]{24,})\b"),
    _r("slack-token", "Slack token",
       r"\b(xox[abposr]-[0-9A-Za-z\-]{10,})\b"),
    _r("slack-webhook", "Slack incoming webhook",
       r"(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,})"),
    _r("mailgun-api-key", "Mailgun API key",
       r"\b(key-[0-9a-f]{32})\b"),
    _r("mailgun-api-key-v2", "Mailgun API key",
       r"\b([0-9a-f]{32}-[0-9a-f]{8}-[0-9a-f]{8})\b"),
    _r("sendgrid-api-key", "SendGrid API key",
       r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b"),
    _r("google-api-key", "Google API key",
       r"\b(AIza[0-9A-Za-z_\-]{35})\b"),
    _r("generic-secret-assignment", "Hard-coded credential assignment",
       r"(?i)(?:api[_\-]?key|apikey|secret|token|passw(?:or)?d|pwd|access[_\-]?key|auth|credential)[\w\-]*"
       r"[\"']?\s*(?::=|=>|[:=])\s*[\"']([^\"'\s]{8,})[\"']",
       min_entropy=3.0),
    # dotenv / shell style: MAILGUN_API_KEY=abc123... (unquoted)
    _r("dotenv-secret-assignment", "Credential in KEY=VALUE assignment",
       r"(?i)^\s*(?:export\s+)?[A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|PWD|CREDENTIAL)[A-Z0-9_]*"
       r"\s*=\s*([^\s\"'#$]{8,})\s*$",
       min_entropy=3.0),
]

# Values that are obviously not real secrets.
PLACEHOLDER_MARKERS = (
    "example", "sample", "placeholder", "dummy", "changeme", "change_me",
    "your_", "your-", "yourkey", "<", ">", "${", "{{", "xxxx", "****",
    "redacted", "todo", "fixme", "notreal", "not_real", "fake",
)

# Filenames whose mere presence in a commit is a policy violation.
FORBIDDEN_FILE_GLOBS = (
    ".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "*.jks",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".npmrc", ".pypirc",
    "credentials", "*.tfstate",
)
# Template files that are expected to be committed.
ALLOWED_FILE_GLOBS = (
    ".env.example", ".env.sample", ".env.template", ".env.dist", "*.pub",
)

BASE64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-")
HEX_CHARS = set("0123456789abcdefABCDEF")
QUOTED_STRING = re.compile(r"[\"'`]([^\"'`\s]{16,})[\"'`]|[=:]\s*([^\"'`\s]{16,})\s*$")


def shannon_entropy(value: str) -> float:
    """Bits of entropy per character."""
    if not value:
        return 0.0
    counts = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def is_placeholder(value: str) -> bool:
    lowered = value.lower()
    if any(marker in lowered for marker in PLACEHOLDER_MARKERS):
        return True
    # Long runs of one character ("aaaaaaaa", "00000000") are never real keys.
    return len(set(value)) <= 3


def forbidden_file(path: str) -> bool:
    name = os.path.basename(path)
    if any(fnmatch.fnmatch(name, g) for g in ALLOWED_FILE_GLOBS):
        return False
    return any(fnmatch.fnmatch(name, g) for g in FORBIDDEN_FILE_GLOBS)


def entropy_candidates(line: str):
    """Yield (start, end, value) for string tokens worth an entropy check."""
    for m in QUOTED_STRING.finditer(line):
        group = 1 if m.group(1) is not None else 2
        yield m.start(group), m.end(group), m.group(group)


def classify_charset(value: str):
    chars = set(value)
    if chars <= HEX_CHARS:
        return "hex"
    if chars <= BASE64_CHARS:
        return "base64"
    return None
