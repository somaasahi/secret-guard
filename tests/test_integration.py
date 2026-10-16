"""End-to-end tests: real git repositories with the hook installed."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

from . import fakes

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(cmd, cwd, env=None):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env=env)


class RepoTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = self.tmp.name
        # Isolate from the user's global git config (e.g. a global core.hooksPath).
        self.env = dict(os.environ, PYTHONPATH=PROJECT_ROOT, HOME=self.repo,
                        GIT_CONFIG_GLOBAL=os.path.join(self.repo, ".gitconfig-test"),
                        GIT_CONFIG_NOSYSTEM="1")
        for cmd in (["git", "init", "-q"], ["git", "config", "user.email", "t@example.org"],
                    ["git", "config", "user.name", "Test"], ["git", "config", "commit.gpgsign", "false"]):
            run(cmd, self.repo, self.env)
        result = self.cli("install")
        self.assertEqual(result.returncode, 0, result.stderr)

    def tearDown(self):
        self.tmp.cleanup()

    def cli(self, *args):
        return run([sys.executable, "-m", "secret_guard", *args], self.repo, self.env)

    def write(self, rel, content):
        path = os.path.join(self.repo, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(content)

    def commit(self, *paths):
        run(["git", "add", "-f", *paths], self.repo, self.env)
        return run(["git", "commit", "-q", "-m", "test"], self.repo, self.env)


class CommitHookTests(RepoTestCase):
    def test_hardcoded_key_is_blocked(self):
        self.write("mailer.py", f'MAILGUN_API_KEY = "{fakes.mailgun_key()}"\n')
        result = self.commit("mailer.py")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Mailgun API key", result.stderr)

    def test_dotenv_file_is_blocked(self):
        self.write(".env", f"MAILGUN_API_KEY={fakes.mailgun_key()}\n")
        result = self.commit(".env")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Credential file must not be committed", result.stderr)

    def test_clean_code_is_allowed(self):
        self.write("mailer.py", "import os\nKEY = os.environ['MAILGUN_API_KEY']\n")
        self.assertEqual(self.commit("mailer.py").returncode, 0)

    def test_env_template_is_allowed(self):
        self.write(".env.example", "MAILGUN_API_KEY=your-mailgun-key\n")
        self.assertEqual(self.commit(".env.example").returncode, 0)

    def test_existing_hook_is_chained(self):
        hooks = os.path.join(self.repo, ".git", "hooks")
        self.cli("uninstall")
        with open(os.path.join(hooks, "pre-commit"), "w") as fh:
            fh.write("#!/bin/sh\necho previous-hook-ran >&2\n")
        os.chmod(os.path.join(hooks, "pre-commit"), 0o755)
        self.cli("install")
        self.write("a.py", "x = 1\n")
        result = self.commit("a.py")
        self.assertEqual(result.returncode, 0)
        self.assertIn("previous-hook-ran", result.stderr)

    def test_no_verify_bypasses_local_hook(self):
        # Documents the limitation that motivates the CI backstop.
        self.write("mailer.py", f'KEY = "{fakes.mailgun_key()}"\n')
        run(["git", "add", "mailer.py"], self.repo, self.env)
        result = run(["git", "commit", "-q", "--no-verify", "-m", "x"], self.repo, self.env)
        self.assertEqual(result.returncode, 0)

    def test_ci_mode_catches_bypassed_commit(self):
        self.write("a.py", "x = 1\n")
        self.commit("a.py")
        run(["git", "branch", "base"], self.repo, self.env)
        self.write("mailer.py", f'KEY = "{fakes.mailgun_key()}"\n')
        run(["git", "add", "mailer.py"], self.repo, self.env)
        run(["git", "commit", "-q", "--no-verify", "-m", "x"], self.repo, self.env)
        result = self.cli("scan", "--since", "base", "--format", "json")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["findings"][0]["rule_id"], "mailgun-api-key")


class AuditTests(RepoTestCase):
    def test_gitignored_secret_reported_as_agent_visible(self):
        self.write(".gitignore", ".env\n")
        self.write(".env", f"MAILGUN_API_KEY={fakes.mailgun_key()}\n")
        result = self.cli("audit", "--format", "json")
        report = json.loads(result.stdout)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(report["tracked"], [])
        self.assertEqual(report["git_ignored"][0]["path"], ".env")
        self.assertFalse(report["agent_read_protected"])

    def test_claude_deny_rule_detected(self):
        self.write(".claude/settings.json",
                   json.dumps({"permissions": {"deny": ["Read(./.env)", "Read(./.env.*)"]}}))
        report = json.loads(self.cli("audit", "--format", "json").stdout)
        self.assertTrue(report["agent_read_protected"])

    def test_clean_tree(self):
        self.write("app.py", "import boto3\n")
        self.assertEqual(self.cli("audit").returncode, 0)


if __name__ == "__main__":
    unittest.main()
