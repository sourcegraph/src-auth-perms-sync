# AGENTS.md

## Linting

```bash
### GitHub Actions workflows
actionlint

### Markdown files
npx --yes markdownlint-cli2@0.22.1

### Python files

# Lint + auto-fix safe issues
uv run ruff check src/src_auth_perms_sync/ --fix

# Format
uv run ruff format src/src_auth_perms_sync/

# Type check
uv run pyright

# Basic test
uv run src-auth-perms-sync --help
```

## Testing

- First run a dry-run (default behaviour, without `--apply` flag) against a Sourcegraph instance

```bash
uv run src-auth-perms-sync [--get]
uv run src-auth-perms-sync --set maps.yaml --full
uv run src-auth-perms-sync --restore backups/<source>/<run>/before.json
```

- Read the output, and evaluate the expected changes
- If the expected changes look correct
  - Run with the `--apply` flag against the test instance
  - Read and evaluate the output for expected changes
  - Run with the `--restore` flag against the test instance
  - Always inspect the before / after snapshots in
    `src-auth-perms-sync-runs/<endpoint>/backups/` afterward to confirm the diff matches what you expected

## Release process

- The tagged source commit must already contain the package version it
  releases. Do not make the customer release workflow edit `pyproject.toml`.
- Prepare the version bump on a branch. Set `VERSION`, then copy / paste:
- As part of every release bump, find old release-version literals in
  `AGENTS.md`, `README.md`, and release snippets, and replace them with the
  new version where they are meant to stay current.

```bash
set -euo pipefail

VERSION=0.2.1
BRANCH="release-v${VERSION}"

git fetch origin --tags --prune
git switch main
git pull --ff-only
git switch -c "${BRANCH}"

uv run python - "${VERSION}" <<'PY'
from pathlib import Path
import re
import sys

version = sys.argv[1]
path = Path("pyproject.toml")
text = path.read_text()
new_text = re.sub(
    r'(?m)^version = "[^"]+"$',
    f'version = "{version}"',
    text,
    count=1,
)
if new_text == text:
    raise SystemExit("pyproject.toml version was not updated")
path.write_text(new_text)
PY

uv lock
```

- Validate the release candidate before opening / merging the PR:

```bash
set -euo pipefail

uv lock --check
actionlint
uv run ruff check src/src_auth_perms_sync/ tests/
uv run ruff format --check src/src_auth_perms_sync/ tests/
uv run pyright
uv run python -m unittest discover -s tests
uv run src-auth-perms-sync --help
npx --yes markdownlint-cli2@0.22.1
uv build --wheel --out-dir /tmp/src-auth-perms-sync-release-check --no-create-gitignore
rm -rf /tmp/src-auth-perms-sync-release-check
```

- Commit, push, open the PR, wait for checks, then merge it. If review is
  required, stop after `gh pr checks` and ask for review before merging.

```bash
set -euo pipefail

VERSION=0.2.1
BRANCH="release-v${VERSION}"
GH_REPO="sourcegraph/src-auth-perms-sync"

git add pyproject.toml uv.lock
git commit -m "Release v${VERSION}"
git push -u origin "${BRANCH}"

gh pr create \
  --repo "${GH_REPO}" \
  --base main \
  --head "${BRANCH}" \
  --title "Release v${VERSION}" \
  --body "Bump src-auth-perms-sync package metadata to ${VERSION}."

gh pr checks "${BRANCH}" --repo "${GH_REPO}" --watch --fail-fast
gh pr merge "${BRANCH}" --repo "${GH_REPO}" --squash --delete-branch
```

- Tag the merged `main` commit. Do not tag a feature branch commit.

```bash
set -euo pipefail

VERSION=0.2.1

git fetch origin --tags --prune
git switch main
git pull --ff-only
git tag "v${VERSION}"
git push origin "v${VERSION}"
```

- Watch the customer release workflow and confirm the GitHub release assets
  are uploaded:

```bash
set -euo pipefail

VERSION=0.2.1
GH_REPO="sourcegraph/src-auth-perms-sync"

RUN_ID="$(
  gh run list \
    --repo "${GH_REPO}" \
    --workflow release.yml \
    --branch "v${VERSION}" \
    --limit 1 \
    --json databaseId \
    --jq '.[0].databaseId // empty'
)"
test -n "${RUN_ID}"
gh run watch "${RUN_ID}" --repo "${GH_REPO}" --exit-status
gh release view "v${VERSION}" --repo "${GH_REPO}"
```

- If a pushed tag points at the wrong commit, move it only after explicit
  human approval:

```bash
set -euo pipefail

VERSION=0.2.1
GH_REPO="sourcegraph/src-auth-perms-sync"

git fetch origin --tags --prune
git switch main
git pull --ff-only
git tag -f "v${VERSION}" origin/main
git push origin "refs/tags/v${VERSION}" --force

RUN_ID="$(
  gh run list \
    --repo "${GH_REPO}" \
    --workflow release.yml \
    --branch "v${VERSION}" \
    --limit 1 \
    --json databaseId \
    --jq '.[0].databaseId // empty'
)"
test -n "${RUN_ID}"
gh run watch "${RUN_ID}" --repo "${GH_REPO}" --exit-status
gh release view "v${VERSION}" --repo "${GH_REPO}"
```

## Hard invariants — do not break

Violating these can silently grant the wrong users access to the wrong
repos.

1. **bindID is always Sourcegraph username**, never email. Multiple users
   can share an email; renaming would let one user inherit another's
   permissions. Enforced by `validate_site_config()`.
2. **Apply unions across rules, then overwrites per repo.**
   `setRepositoryPermissionsForUsers` replaces a repo's explicit list, so
   compute the per-repo union BEFORE dispatching mutations.
3. **Snapshots gate reversibility.** `--apply` and `--restore --apply`
   default to before/after snapshots. `--no-backup` is an escape hatch;
   never make it the default or remove the snapshot path unprompted.
4. **Retries fire only on transient transport failures** (network errors,
   HTTP 408/429/500/502/503/504). GraphQL application errors propagate
   on the first attempt.

## Other notes

- Don't hallucinate GraphQL fields, read the schema in `dev/schema.gql`

## Code style

- Always use meaningful, human-understandable, whole words when naming things
  - The human should be able to read a name, and understand what it is / does / stores, without
    needing to read a bunch of other code to figure it out
- Refactor the code to improve brevity, simplicity, and code style

## What this is

A Python CLI that syncs Sourcegraph repo permissions and organizations
from auth-provider data. Repo permissions map users to code-host repos;
organization sync maps SAML groups to Sourcegraph org membership. Read
[README.md](./README.md) first.

## Layout

CLI lives in `src/src_auth_perms_sync/`; invoke with `uv run src-auth-perms-sync`.
Strict pyright covers the package. Root modules are entrypoints only:

- `cli.py` — `main()`, arg parsing, owns the CLI description.
- `shared/` — cross-workflow helpers: Sourcegraph auth-provider/user list
  helpers, shared GraphQL operations and TypedDicts, site-config validation,
  and SAML group parsing.

Business workflows live in packages:

- `permissions/` — repo permission sync (`command.py`, `maps.py`,
  `mapping.py`, `sourcegraph.py`, `snapshot.py`, `apply.py`, `queries.py`,
  `types.py`). Add new mapping filters in `permissions/types.py` and
  `permissions/mapping.py`.
- `orgs/` — SAML group → Sourcegraph organization sync (`command.py`,
  `queries.py`, `types.py`).

## Toolchain

- Python 3.11 + [uv](https://docs.astral.sh/uv/). Never invoke `python`
  directly; always `uv run ...`.
- `uv run pyright` must be clean. No `# type: ignore` to silence —
  fix the underlying type.
- Local tests use stdlib `unittest`: `uv run python -m unittest discover -s tests`.
- For Sourcegraph mutation-path changes, also verify by dry-running `--get` /
  `--set` / `--restore` against a real instance and diffing. If the expected
  changes look right, run `--apply` against a scratch instance and inspect
  before/after snapshots.

## Coding conventions

- Wrap non-trivial operations in `event(...)`; use `stage(...)` or
  `logging_context(...)` at command / phase boundaries.
- `from __future__ import annotations` at the top of new modules.
- Paginate via `src_py_lib.clients.graphql.stream_connection_nodes()`.
- Concurrency: use `submit_with_log_context(...)` when work leaves the
  main thread so structured log context is preserved.

## Naming

Per the human's "meaningful, human-understandable, whole words" rule,
prefer full words over abbreviations. Two sweeps of renames have already
removed names like `ev`, `ex`, `exc`, `cfg`, `conn`, `resp`, `fn`,
`op_name`, `cur`, `tok`, `sha`, `mem`, `sdl`, `ts`, `dt`, `cv`, `es`,
`rid`, `u`, `p`, `r`, `i`, `k`, `v`, etc. Don't reintroduce them.

Short names that ARE acceptable (don't rewrite these on sight):

- **TypedDict / dataclass fields that mirror the wire format**: `id`,
  `url`, `kind` on `ExternalService` etc. These match GraphQL/JSON
  keys and renaming would break the contract.
- **Real English words even if short**: `raw`, `head`, `old`, `new`,
  `key`, `value`, `name`, `kind`.
- **Stdlib idioms**: `ctx` for `contextvars.copy_context()`.
- **Loop / comprehension variables when the type is obvious from one
  line of context** is still discouraged — prefer `user`, `repo`,
  `provider`, `service`, `permission`, `node`, `entry`, `match`,
  `account`, `future`, `executor`, `exception`, `event`, `connection`,
  `response`, `timestamp`, `current`, `outcome`, `index`, `field_name`.

If you need a 3-character abbreviation for a brand-new concept, write
out the full word; almost any name shorter than ~6 chars probably
should be longer.
