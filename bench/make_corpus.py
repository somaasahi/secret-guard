"""Generate a labelled evaluation corpus of synthetic secrets and tricky non-secrets.

Every credential is random and fake. The corpus is regenerated on each run
(deterministic seed) and is never committed, so the repository itself holds no
credential-shaped literals.

Output: <out>/files/... and <out>/labels.json, a list of
{"path", "line", "secret": bool, "category"} for every labelled line.
Unlabelled lines (blank lines, imports, braces) are non-secrets too.
"""

import argparse
import base64
import hashlib
import json
import os
import random
import string
import subprocess
import uuid

ALNUM = string.ascii_letters + string.digits
UPPER_DIGITS = string.ascii_uppercase + string.digits
HEX = "0123456789abcdef"
BASE32 = string.ascii_uppercase + "234567"  # real AWS key IDs use this alphabet


class Corpus:
    def __init__(self, root, seed):
        self.root = root
        self.rng = random.Random(seed)
        self.files = {}   # path -> list of lines
        self.labels = []

    def pick(self, alphabet, n):
        return "".join(self.rng.choice(alphabet) for _ in range(n))

    def add(self, path, text, secret=None, category=None, group=None):
        lines = self.files.setdefault(path, [])
        lines.append(text)
        if category is not None:
            self.labels.append({"path": path, "line": len(lines), "secret": secret, "category": category,
                                "group": group or f"{path}:{len(lines)}"})

    def write(self):
        for path, lines in self.files.items():
            full = os.path.join(self.root, "files", path)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")
        with open(os.path.join(self.root, "labels.json"), "w", encoding="utf-8") as fh:
            json.dump(self.labels, fh, indent=1)


# ------------------------------------------------------------------ secrets
def positives(c: Corpus):
    k = c.pick
    for i in range(10):
        f = f"services/aws_client_{i}.py"
        c.add(f, "import boto3")
        c.add(f, "")
        # The key ID and secret form one credential; finding either line counts once.
        c.add(f, f'AWS_ACCESS_KEY_ID = "AK{"IA"}{k(BASE32, 16)}"', True, "aws-credential-pair", group=f)
        c.add(f, f'AWS_SECRET_ACCESS_KEY = "{k(ALNUM + "/+", 40)}"', True, "aws-credential-pair", group=f)
        c.add(f, "s3 = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY_ID)")
    for i in range(10):
        f = f"scripts/release_{i}.sh"
        c.add(f, "#!/bin/sh")
        c.add(f, f'export GITHUB_TOKEN="gh{"p_"}{k(ALNUM, 36)}"', True, "github-token")
        c.add(f, 'gh release create "$TAG"')
    for i in range(10):
        f = f"billing/stripe_{i}.js"
        c.add(f, "const Stripe = require('stripe');")
        c.add(f, f"const stripe = Stripe('sk_{'live_'}{k(ALNUM, 24)}');", True, "stripe-secret-key")
        c.add(f, "module.exports = stripe;")
    for i in range(8):
        f = f"bots/notify_{i}.py"
        c.add(f, "from slack_sdk import WebClient")
        c.add(f, f'client = WebClient(token="xo{"xb-"}{k(string.digits, 12)}-{k(string.digits, 13)}-{k(ALNUM, 24)}")',
              True, "slack-token")
    for i in range(10):
        f = f"mail/mailer_{i}.py"
        c.add(f, "import requests")
        c.add(f, f'MAILGUN_API_KEY = "ke{"y-"}{k(HEX, 32)}"', True, "mailgun-api-key")
        c.add(f, "requests.post(URL, auth=('api', MAILGUN_API_KEY))")
    for i in range(8):
        f = f"mail/sendgrid_{i}.ts"
        c.add(f, "import sgMail from '@sendgrid/mail';")
        c.add(f, f"sgMail.setApiKey('S{'G.'}{k(ALNUM + '_-', 22)}.{k(ALNUM + '_-', 43)}');", True, "sendgrid-api-key")
    for i in range(8):
        f = f"web/maps_{i}.yaml"
        c.add(f, "maps:")
        c.add(f, f"  api_key: AI{'za'}{k(ALNUM + '_-', 35)}", True, "google-api-key")
    for i in range(6):
        f = f"ai/llm_{i}.py"
        c.add(f, "from openai import OpenAI")
        c.add(f, f'client = OpenAI(api_key="sk-proj-{k(ALNUM, 20)}T3Blbk{"FJ"}{k(ALNUM, 20)}")', True, "openai-api-key")
    for i in range(5):
        f = f"deploy/key_{i}.txt"
        # Freshly generated throwaway keys: structurally valid, never used anywhere.
        pem = subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
                             capture_output=True, text=True, check=True).stdout.splitlines()
        for j, line in enumerate(pem):
            c.add(f, line, True, "private-key", group=f) if j == 0 else c.add(f, line)
    for i in range(10):
        f = f"config/database_{i}.yml"
        c.add(f, "production:")
        c.add(f, "  host: db.internal")
        c.add(f, f'  password: "{k(ALNUM + "!#%&*", 18)}"', True, "generic-password")
    # Unknown formats: only entropy or keyword-based detection can find these.
    for i in range(10):
        f = f"integrations/vendor_{i}.py"
        c.add(f, f'client = AcmeClient("{k(ALNUM, 40)}")', True, "unknown-format-token")
    for i in range(10):
        f = f"env/service_{i}.env"
        c.add(f, "# Local development settings")
        c.add(f, "PORT=8080")
        c.add(f, f"PAYMENTS_API_KEY={k(ALNUM, 32)}", True, "dotenv-api-key")


# -------------------------------------------------------------- non-secrets
def negatives(c: Corpus):
    k = c.pick
    for i in range(20):
        f = f"tools/changelog_{i}.py"
        c.add(f, f'FIXED_IN = "{k(HEX, 40)}"  # commit', False, "git-sha")
    for i in range(15):
        f = f"tools/checksums_{i}.py"
        c.add(f, f'EXPECTED_SHA256 = "{hashlib.sha256(str(i).encode()).hexdigest()}"', False, "sha256-digest")
    for i in range(20):
        f = f"models/ids_{i}.ts"
        c.add(f, f"export const DEFAULT_TENANT = '{uuid.UUID(int=c.rng.getrandbits(128))}';", False, "uuid")
    for i in range(15):
        f = f"web/lock_{i}.json"
        c.add(f, "{")
        digest = base64.b64encode(hashlib.sha512(str(i).encode()).digest()).decode()
        c.add(f, f'  "integrity": "sha512-{digest}"', False, "sri-integrity-hash")
        c.add(f, "}")
    for i in range(5):
        f = f"docs/aws_example_{i}.md"
        c.add(f, f"Use `AKIAIOSFODNN7EXAMPLE` as the access key in examples.", False, "documented-example-key")
    placeholders = ["your-api-key-here", "<YOUR_TOKEN>", "changeme", "xxxxxxxxxxxxxxxxxxxxxxxx",
                    "${MAILGUN_API_KEY}", "REPLACE_WITH_REAL_KEY", "dummy-secret-for-tests"]
    for i in range(15):
        f = f"config/sample_{i}.py"
        c.add(f, f'API_KEY = "{placeholders[i % len(placeholders)]}"', False, "placeholder")
    for i in range(20):
        f = f"app/settings_{i}.py"
        c.add(f, "import os")
        c.add(f, f'SECRET_TOKEN = os.environ["SERVICE_{i}_TOKEN"]', False, "env-lookup")
        c.add(f, f"api_key = ssm.get_parameter(Name='/app/prod/key_{i}', WithDecryption=True)", False, "ssm-lookup")
    for i in range(10):
        f = f"web/assets_{i}.css"
        png = base64.b64encode(bytes(c.rng.getrandbits(8) for _ in range(60))).decode()
        c.add(f, f".logo {{ background: url('data:image/png;base64,{png}'); }}", False, "data-uri")
    for i in range(10):
        f = f"tests/test_login_{i}.py"
        c.add(f, f'PASSWORD = "password{i}"', False, "weak-test-password")
    for i in range(10):
        f = f"web/routes_{i}.ts"
        c.add(f, f"const url = 'https://api.example.org/v1/accounts/{k(ALNUM, 24)}/settings';", False, "url-with-id")
    normal = [
        "def send_mail(to, subject, body):",
        "    return client.send(to=to, subject=subject, body=body)",
        "for item in items: total += item.price * item.quantity",
        "const handler = async (event) => ({ statusCode: 200 });",
        "logger.info('token refreshed for user %s', user_id)",
        "if not secret_name: raise ValueError('secret name is required')",
        "password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())",
        "export function getApiKeyFromStore(name: string) { return store.get(name); }",
    ]
    for i in range(40):
        f = f"app/module_{i}.py"
        c.add(f, normal[i % len(normal)], False, "ordinary-code")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--seed", type=int, default=7008)
    args = ap.parse_args()
    c = Corpus(args.out, args.seed)
    positives(c)
    negatives(c)
    c.write()
    pos = sum(1 for l in c.labels if l["secret"])
    print(f"{len(c.files)} files, {pos} secret lines, {len(c.labels) - pos} labelled non-secret lines")


if __name__ == "__main__":
    main()
