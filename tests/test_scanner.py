import unittest

from secret_guard.config import Config
from secret_guard.gitutil import parse_added_lines
from secret_guard.rules import forbidden_file, shannon_entropy
from secret_guard.scanner import scan_line

from . import fakes


def rule_ids(line, cfg=None):
    return [f.rule_id for f in scan_line("app.py", 1, line, cfg or Config())]


class KnownFormatTests(unittest.TestCase):
    def test_known_formats_are_detected(self):
        cases = {
            "aws-access-key-id": f'AWS_KEY = "{fakes.aws_access_key_id()}"',
            "aws-secret-access-key": f'aws_secret_access_key = "{fakes.aws_secret_access_key()}"',
            "github-token": f'token = "{fakes.github_token()}"',
            "stripe-secret-key": f'stripe.api_key = "{fakes.stripe_live_key()}"',
            "mailgun-api-key": f'MAILGUN = "{fakes.mailgun_key()}"',
            "slack-token": f'SLACK = "{fakes.slack_token()}"',
            "google-api-key": f'maps_key: "{fakes.google_api_key()}"',
            "sendgrid-api-key": f'SENDGRID = "{fakes.sendgrid_key()}"',
            "private-key": "-----BEGIN RSA PRIVATE KEY-----",
        }
        for expected, line in cases.items():
            with self.subTest(expected):
                self.assertIn(expected, rule_ids(line))

    def test_one_finding_per_secret(self):
        # The specific rule wins; generic/entropy detectors must not double-report.
        self.assertEqual(rule_ids(f'api_key = "{fakes.mailgun_key()}"'), ["mailgun-api-key"])


class GenericAndEntropyTests(unittest.TestCase):
    def test_unknown_format_found_by_entropy(self):
        ids = rule_ids(f'client = Client("{fakes.random_token()}")')
        self.assertEqual(ids, ["high-entropy-base64"])

    def test_generic_assignment(self):
        self.assertIn("generic-secret-assignment", rule_ids('DB_PASSWORD = "Tr0ub4dor&3xK9"'))

    def test_dotenv_line_without_quotes(self):
        self.assertTrue(rule_ids(f"MAILGUN_API_KEY={fakes.random_token(32)}"))

    def test_entropy_can_be_disabled(self):
        cfg = Config(entropy_enabled=False)
        self.assertEqual(rule_ids(f'x = "{fakes.random_token()}"', cfg), [])

    def test_entropy_metric(self):
        self.assertEqual(shannon_entropy("aaaa"), 0.0)
        self.assertAlmostEqual(shannon_entropy("ab"), 1.0)


class FalsePositiveTests(unittest.TestCase):
    def test_clean_code_passes(self):
        for line in (
            "def send_mail(to, subject):",
            'api_key = os.environ["MAILGUN_API_KEY"]',
            "api_key = ssm.get_parameter(Name='/app/prod/mailgun', WithDecryption=True)",
            'url = "https://api.mailgun.net/v3/mg.example.org/messages"',
            'commit = "3f786850e387550fdab836ed7e6dc881de23001b"',
            'password = "password"',
        ):
            with self.subTest(line):
                self.assertEqual(rule_ids(line), [])

    def test_placeholders_are_ignored(self):
        for line in (
            'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"',
            'api_key = "your-api-key-here"',
            'token = "<TOKEN>"',
            'secret = "xxxxxxxxxxxxxxxxxxxxxxxx"',
        ):
            with self.subTest(line):
                self.assertEqual(rule_ids(line), [])

    def test_inline_ignore_marker(self):
        line = f'KEY = "{fakes.github_token()}"  # secretguard:ignore'
        self.assertEqual(rule_ids(line), [])

    def test_fingerprint_allowlist(self):
        line = f'KEY = "{fakes.github_token()}"'
        finding = scan_line("app.py", 1, line, Config())[0]
        cfg = Config(allowed_fingerprints={finding.fingerprint})
        self.assertEqual(rule_ids(line, cfg), [])

    def test_masking_never_reveals_secret(self):
        token = fakes.github_token()
        finding = scan_line("app.py", 1, f'KEY = "{token}"', Config())[0]
        self.assertNotIn(token[8:], finding.masked)
        self.assertNotIn("secret", finding.to_dict())


class FilenameTests(unittest.TestCase):
    def test_forbidden_files(self):
        for path in (".env", "config/.env.production", "deploy/server.pem", "id_ed25519"):
            with self.subTest(path):
                self.assertTrue(forbidden_file(path))

    def test_templates_allowed(self):
        for path in (".env.example", ".env.sample", "id_ed25519.pub", "app.py"):
            with self.subTest(path):
                self.assertFalse(forbidden_file(path))


class DiffParserTests(unittest.TestCase):
    def test_only_added_lines_with_correct_numbers(self):
        diff = (
            "diff --git a/app.py b/app.py\n"
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -10,0 +11,2 @@\n"
            "+first\n"
            "+second\n"
            "@@ -20 +22 @@\n"
            "-removed\n"
            "+replaced\n"
            "diff --git a/old.py b/old.py\n"
            "--- a/old.py\n"
            "+++ /dev/null\n"
            "@@ -1 +0,0 @@\n"
            "-gone\n"
        )
        self.assertEqual(parse_added_lines(diff),
                         {"app.py": [(11, "first"), (12, "second"), (22, "replaced")]})


if __name__ == "__main__":
    unittest.main()
