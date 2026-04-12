# Contributing

Contributions welcome! Each scanner is an independent module — easy to add new ones or improve existing checks.

## Getting Started

```bash
# 1. Fork on GitHub, then clone your fork
git clone https://github.com/YOUR_USERNAME/domain-audit.git
cd domain-audit

# 2. Set up development environment
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# 3. Run tests
pytest tests/ -v

# 4. Create a feature branch
git checkout -b feature/new-scanner
```

## Code Quality

This project uses [ruff](https://docs.astral.sh/ruff/) for linting/formatting and [mypy](https://mypy-lang.org/) for type checking.

```bash
# Lint
ruff check domain_audit tests

# Format
ruff format domain_audit tests

# Type check
mypy domain_audit --ignore-missing-imports
```

Pre-commit hooks are available to run these automatically:

```bash
pip install pre-commit
pre-commit install
```

## Using Your Fork in Google Colab

If you want to run your own modified version in Colab instead of the published package:

```python
# Install from YOUR fork (replace YOUR_USERNAME)
!pip install git+https://github.com/YOUR_USERNAME/domain-audit.git -q

# Or install a specific branch
!pip install git+https://github.com/YOUR_USERNAME/domain-audit.git@feature/my-branch -q

# Or clone and install in editable mode (for live editing in Colab)
!git clone https://github.com/YOUR_USERNAME/domain-audit.git /content/domain-audit
!pip install -e /content/domain-audit -q
```

## Keeping Your Fork in Sync

```bash
# Add upstream remote (one-time)
git remote add upstream https://github.com/Opticsponge/domain-audit.git

# Fetch and merge upstream changes
git fetch upstream
git merge upstream/main

# Push updated main to your fork
git push origin main
```

## Submitting Changes

1. Push your feature branch to your fork
2. Open a PR against `Opticsponge/domain-audit:main`
3. Include tests for new scanners or changed behavior
4. CI will run linting, type checking, and tests automatically

## Releasing a New Version (maintainers only)

Releases are automated via GitHub Actions using [Trusted Publishers](https://docs.pypi.org/trusted-publishers/) (no API tokens needed).

**One-time setup:**

1. Create accounts on [PyPI](https://pypi.org) and [TestPyPI](https://test.pypi.org)
2. On each, go to "Publishing" and add a Trusted Publisher:
   - Owner: `Opticsponge`
   - Repository: `domain-audit`
   - Workflow: `publish.yml`
   - Environment: `pypi` (or `testpypi` for TestPyPI)
3. In your GitHub repo, create two environments under Settings > Environments:
   - `testpypi`
   - `pypi` (optionally add required reviewers for extra safety)

**To release:**

1. Bump version in `pyproject.toml`
2. Update `CHANGELOG.md`
3. Commit, push, and create a GitHub Release with tag `v0.X.0`
4. The publish workflow automatically: builds, uploads to TestPyPI, then uploads to PyPI

**First-time manual upload (if not using Trusted Publishers yet):**

```bash
pip install build twine
python -m build

# Test on TestPyPI first
python -m twine upload --repository testpypi dist/*

# Verify: pip install -i https://test.pypi.org/simple/ domain-audit

# Then upload to real PyPI
python -m twine upload dist/*
```
