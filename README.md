# secret-guard

Blocks API keys and other secrets before they are committed, and audits which
plaintext secrets in a working tree are readable by AI coding agents.

Python 3.9+, standard library only.

## Install

```bash
pip install git+https://github.com/somaasahi/secret-guard
```

Then choose one of:

| Scope | Command |
|---|---|
| One repository | `secret-guard install` (an existing pre-commit hook is backed up and chained) |
| Team, via the pre-commit framework | copy `examples/pre-commit-config.yaml` to `.pre-commit-config.yaml`, run `pre-commit install` |
| Every repository on the machine | `secret-guard install --global` (sets `core.hooksPath`; repo-local hooks still run) |

Remove with `secret-guard uninstall [--global]`.

A local hook can be bypassed with `git commit --no-verify`, so also run the
scan server-side; see `examples/github-actions.yml`.

## Commands

| Command | Purpose |
|---|---|
| `secret-guard scan` | Scan staged changes (called by the hook) |
| `secret-guard scan --since <ref>` | Scan commits since `<ref>` (CI) |
| `secret-guard scan --files <path>...` | Scan files or directories directly (benchmarking) |
| `secret-guard audit [path]` | Report secrets readable by AI agents, including git-ignored `.env` files |

`--format json` is available on `scan` and `audit`. Exit codes: 0 clean, 1 findings, 2 error.

## Detection pipeline

1. **Filename policy**: `.env`, `.env.*`, `*.pem`, `id_rsa`, ... are blocked outright
   (`.env.example` and similar templates are allowed).
2. **Known formats**: regular expressions for AWS, GitHub, Stripe, Slack, Mailgun,
   SendGrid, Google, OpenAI, Anthropic keys and private key blocks.
3. **Generic assignments**: `api_key = "..."`, `PASSWORD=...` with an entropy floor.
4. **Entropy**: Shannon entropy over quoted tokens (base64 >= 4.5, hex >= 3.0 bits/char,
   length >= 20) to catch unknown formats.
5. **False-positive filters**: placeholders (`EXAMPLE`, `your-api-key`, `<TOKEN>`, ...),
   `# secretguard:ignore`, and `.secretguard-allow` (path globs or `sha256:` fingerprints).

Only added lines are scanned. Secrets are never printed: output shows a masked
prefix and a truncated SHA-256 fingerprint that can be allowlisted.

## Configuration

Optional `.secretguard.json` at the repository root; see `examples/secretguard.json`.

## Tests

```bash
python3 -m unittest -v
```

Test credentials are generated at runtime (`tests/fakes.py`), so the repository
contains no credential-shaped literals.
