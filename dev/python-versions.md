# Python versions

## Current baseline

The customer-supported runtime baseline is Python 3.11.

Keep these in sync when changing the baseline:

- `.python-version`
- `pyproject.toml` `requires-python`, pyright `pythonVersion`, and ruff `target-version`
- `renovate.json`'s Python `allowedVersions` guard
- GitHub Actions CI / release `PYTHON_VERSION`
- Customer release wheelhouse labels and install instructions
- `README.md` install commands
- `src-py-lib`'s matching Python support and published version in `pyproject.toml`

Do not change `requires-python` until both this repo and `src-py-lib` are tested
with the target version and matching customer wheelhouses can be built.

## Renovate notes

Renovate may propose Python version updates after onboarding. Those PRs should
not be merged automatically because Python version changes affect customer
install requirements and wheelhouse compatibility.

Recommended guard while Python 3.11 is the supported baseline:

```json
{
  "packageRules": [
    {
      "matchPackageNames": ["python"],
      "allowedVersions": "<3.12"
    }
  ]
}
```

When intentionally moving to a newer Python, update the guard in the same change
as the package metadata, lockfile, wheelhouse matrix, and release docs.
