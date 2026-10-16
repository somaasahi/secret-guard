"""Synthetic credentials for tests.

Keys are generated at runtime so that no credential-shaped literal is stored
in this repository (which would otherwise trip secret-guard itself, as well as
GitHub push protection).
"""

import random
import string

_rng = random.Random(7008)
UPPER_DIGITS = string.ascii_uppercase + string.digits
ALNUM = string.ascii_letters + string.digits
HEX = "0123456789abcdef"
B64 = ALNUM + "/+"


def _pick(alphabet, n):
    return "".join(_rng.choice(alphabet) for _ in range(n))


def aws_access_key_id():
    return "AK" + "IA" + _pick(UPPER_DIGITS, 16)


def aws_secret_access_key():
    return _pick(B64, 40)


def github_token():
    return "gh" + "p_" + _pick(ALNUM, 36)


def stripe_live_key():
    return "sk_" + "live_" + _pick(ALNUM, 24)


def mailgun_key():
    return "ke" + "y-" + _pick(HEX, 32)


def slack_token():
    return "xo" + "xb-" + _pick(string.digits, 12) + "-" + _pick(ALNUM, 24)


def google_api_key():
    return "AI" + "za" + _pick(ALNUM + "_-", 35)


def sendgrid_key():
    return "S" + "G." + _pick(ALNUM, 22) + "." + _pick(ALNUM, 43)


def random_token(n=40):
    """Unknown-format secret: only the entropy detector can find it."""
    return _pick(ALNUM, n)
