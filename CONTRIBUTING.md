# Contributing

Use Python 3.11 or later. Keep changes focused and use English for code, documentation, commit messages, and pull requests.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m pytest -q
python -m ruff check .
python -m pip check
```

On Windows, activate with `.venv\Scripts\Activate.ps1` in PowerShell.

Tests intercept HTTPX requests with RESPX; unmatched requests are rejected. Never use real credentials or scan third-party infrastructure in a test. Add a regression test for a bug fix and assert observable behavior. CLI tests must isolate configuration from the developer's home directory.

To verify release artifacts:

```bash
python -m build
python -m twine check --strict dist/*
```

The build creates an sdist and builds the wheel from that sdist. Install the wheel into a fresh virtual environment and run `geminihunter --version` and `python -m geminihunter --help` outside the repository before releasing. The version is defined in `src/geminihunter/__init__.py`.

CI runs tests on Python 3.11–3.14, with additional macOS and Windows jobs. It also checks lint, package metadata, installation, known dependency vulnerabilities, and Git history for secrets. Dependency and GitHub Actions updates are configured through Dependabot.

Optional local security checks:

```bash
pip-audit --skip-editable
gitleaks git --redact --no-banner
```

Install these development tools separately if needed. `.gitleaksignore` contains only reviewed historical synthetic test keys. Do not add exceptions for real credentials.

Before submitting, remove private scan output and temporary files. Explain what changed, why, and how it was verified. Use Conventional Commits for new commits and PR titles, for example `fix(cli): reject invalid configuration`.
