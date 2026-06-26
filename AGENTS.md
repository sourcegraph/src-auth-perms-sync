# AGENTS.md

## Reference materials

- GraphQL schema and database migrations (changes to SQL schema) are available in
  <https://github.com/sourcegraph/artifacts>

## Linting

```bash
### GitHub Actions workflows
actionlint

### Markdown files
npx --yes -p markdownlint-cli2@0.22.1 -p markdownlint-rule-relative-links@5.1.0 markdownlint-cli2

### Non-ASCII characters in tracked text files
uv run python tests/unicode_scan.py

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

All testing runs through one entrypoint: `tests/run.py`. Output goes to the
console and to a per-run log file under `logs/`. Each level runs only its
own checks.

```bash
# Fast, no network (also what the pre-commit hook runs):
# lint, format, pyright, non-ASCII character scan, unit + fixture
# tests, CLI rejection matrix,
# randomized permission invariants
uv run tests/run.py

# End-to-end runs against the .env test instance with independent GraphQL
# read-back verification, and a wheel install smoke test
uv run tests/run.py --live

# Run a subset: comma-delimited test names, substring match
uv run tests/run.py --live full-overwrite-unions
uv run tests/run.py --live wheel,baseline

# Repeated timed runs with Jaeger trace retention, RSS sampling,
# optional kubectl load monitoring, and baseline comparison
uv run tests/run.py --performance --repeat 3
uv run tests/run.py --performance --baseline-command "uvx src-auth-perms-sync@latest" \
  --fail-on-memory-regression-percent 10

# Regenerate fixture goldens after editing tests/e2e/fixtures/ cases
uv run tests/run.py --update-golden
```

- Fixture cases live in `tests/e2e/fixtures/<case>/` - see the README there
  for the format. Add cases there to cover new mapping behaviors.
- For manual verification against a real instance, dry-run first (no
  `--apply`), read the planned changes, then `--apply` on a scratch instance
  and inspect the before/after snapshots under
  `src-auth-perms-sync-runs/<endpoint>/runs/`.

## Release process

- Package versions are derived from Git tags through `hatch-vcs`.
- `pyproject.toml` must use `dynamic = ["version"]`; do not add a hard-coded
  `project.version` for releases.
- The release tag must be `vMAJOR.MINOR.PATCH` and point at a commit reachable
  from `origin/main`.
- The release workflow builds from the tag and checks that wheel and source
  distribution filenames match the tag version before publishing.
- Do not make the release workflow edit `pyproject.toml` or `uv.lock`.
- Validate the remote head of `main` before tagging it:

```bash
set -euo pipefail

VERSION_INPUT=<next-version>
VERSION="${VERSION_INPUT#v}"

[[ "${VERSION_INPUT}" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+$ ]]
git fetch origin --tags --prune
git switch main
git pull --ff-only
test "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)"

uv lock --check
actionlint
uv run ruff check src/src_auth_perms_sync/ tests/
uv run ruff format --check src/src_auth_perms_sync/ tests/
uv run pyright
uv run python -m unittest discover -s tests
uv run src-auth-perms-sync --help
npx --yes -p markdownlint-cli2@0.22.1 -p markdownlint-rule-relative-links@5.1.0 markdownlint-cli2
uv build --wheel --sdist --out-dir /tmp/src-auth-perms-sync-release-check --no-create-gitignore
rm -rf /tmp/src-auth-perms-sync-release-check
```

- Tag the remote head of `main` directly:

```bash
set -euo pipefail

VERSION_INPUT=<next-version>
VERSION="${VERSION_INPUT#v}"
GH_REPO="sourcegraph/src-auth-perms-sync"

[[ "${VERSION_INPUT}" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+$ ]]
git fetch origin --tags --prune
MAIN_COMMIT="$(git rev-parse origin/main)"
git tag -a "v${VERSION}" "${MAIN_COMMIT}" -m "Release v${VERSION}"
git push origin "v${VERSION}"

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

VERSION_INPUT=<version-to-fix>
VERSION="${VERSION_INPUT#v}"
GH_REPO="sourcegraph/src-auth-perms-sync"

[[ "${VERSION_INPUT}" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+$ ]]
git fetch origin --tags --prune
git tag -f -a "v${VERSION}" origin/main -m "Release v${VERSION}"
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

## Hard invariants - do not break

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

- `cli.py` - `main()`, arg parsing, owns the CLI description. Module
  wrappers (`Get`/`Set`/`Restore`/`SyncSamlOrgs`) return result dataclasses
  and never install logging handlers; only `main()` runs CLI-mode logging.
- `shared/` - cross-workflow helpers: Sourcegraph auth-provider/user list
  helpers, shared GraphQL operations and TypedDicts, site-config validation,
  and SAML group parsing. `shared/backups.py` defines `RunPaths`: every
  filesystem path for one run, resolved once at the edge
  (`resolve_run_paths`) and threaded explicitly - never recompute paths
  from cwd or globals below the edge, and honor `run_paths.write_files`
  (False under `--no-files`) before any disk write.

Business workflows live in packages:

- `permissions/` - repo permission sync (`command.py`, `maps.py`,
  `mapping.py`, `sourcegraph.py`, `snapshot.py`, `apply.py`, `queries.py`,
  `types.py`). Add new mapping filters in `permissions/types.py` and
  `permissions/mapping.py`.
- `orgs/` - SAML group -> Sourcegraph organization sync (`command.py`,
  `queries.py`, `types.py`).

## Toolchain

- Python 3.11 + [uv](https://docs.astral.sh/uv/). Never invoke `python`
  directly; always `uv run ...`.
- `uv run pyright` must be clean. No `# type: ignore` to silence -
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

- **Established domain abbreviations**: `org` / `orgs` for Sourcegraph
  organizations, matching the `sync-saml-orgs` command, the `orgs/`
  package, and the `sync_saml_orgs` config field. Do not expand these
  back to `organization(s)` in identifiers.
- **TypedDict / dataclass fields that mirror the wire format**: `id`,
  `url`, `kind` on `ExternalService` etc. These match GraphQL/JSON
  keys and renaming would break the contract.
- **Real English words even if short**: `raw`, `head`, `old`, `new`,
  `key`, `value`, `name`, `kind`.
- **Stdlib idioms**: `ctx` for `contextvars.copy_context()`.
- **Loop / comprehension variables when the type is obvious from one
  line of context** is still discouraged - prefer `user`, `repo`,
  `provider`, `service`, `permission`, `node`, `entry`, `match`,
  `account`, `future`, `executor`, `exception`, `event`, `connection`,
  `response`, `timestamp`, `current`, `outcome`, `index`, `field_name`.

If you need a 3-character abbreviation for a brand-new concept, write
out the full word; almost any name shorter than ~6 chars probably
should be longer.
