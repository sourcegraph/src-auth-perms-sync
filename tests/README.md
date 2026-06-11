# Testing

All testing is driven by one entrypoint and one case registry:

| Path | Purpose |
| ---- | ------- |
| [run.py](./run.py) | The single test entrypoint: `uv run tests/run.py [--local \| --live \| --performance \| --install]` |
| [tests.yaml](./tests.yaml) | The case registry: what each case runs, where, and what it must produce (see its header comment for the full schema) |
| [e2e/fixtures/](./e2e/fixtures/) | Per-case state files, in a directory matching the case name |
| [e2e/case_runner.py](./e2e/case_runner.py) | The case execution engine: registry loader, in-memory Sourcegraph instance (`FakeSourcegraphClient`), full-command runs for state cases, in-process parser replays for replay cases |
| [e2e/test_local_cases.py](./e2e/test_local_cases.py) | `unittest` entrypoint: runs every local-mode registry case and validates ALL registry entries (including live/performance ones) |
| [unit/](./unit/), [integration/](./integration/) | Plain `unittest` suites, run by the local tier's gate |

## How the pieces fit

```text
tests.yaml ──registry──▶ e2e/case_runner.py ◀──imports── run.py
                                ▲                        (--local/--live/--performance)
                                │
                    e2e/test_local_cases.py
                    (unittest discovery: local cases + registry validation)
```

- `case_runner.py` is a library, not a test module: it executes registry
  cases without any network. Both consumers above import it.
- `test_local_cases.py` exists so plain `uv run python -m unittest discover
  -s tests` asserts every local case with no orchestrator — which is exactly
  what run.py's "unit + fixture tests" gate, the release checklist, and CI
  run.
- Live and performance execution (instance prerequisites, seed → apply →
  verify → restore, traces, sampling) lives only in `run.py`.

## Files in a fixture case directory

A directory is only needed when the case uses files — a read-only non-set
command can be registered in tests.yaml with no directory at all.

- `before.json`: Full instance state before the run: providers, services, users,
  repos with `explicitPermissionsUsers`. Required for local mode and for
  mutating (`--apply`) live/performance runs.
- `maps.yaml`: The mapping rules under test (same format as the real
  `maps.yaml`). Required for `set` commands that do not pass their own
  `--maps-path`.
- `after.json`: Expected full instance state after the run (golden file). Omit
  it for cases where state must NOT change (no-op and expected-error cases).

Live-capable cases must use REAL test-instance users/repos in their fixture
files (e.g. `test_user_09991`, `test-repo-49981`), and exact selectors only
(`usernames:`/`emails:` for users, `names:` for repos).

## What each mode does with a case

- **local** — runs the case's `cliCommand` through the real argument parser
  (and `importConfig` through the Python import API, when present) against an
  in-memory instance built from `before.json`, then asserts the full
  resulting state against `after.json`. Replay-style cases
  (`expectedExitCode`/`expectedOutput`) assert parser behavior instead and
  need no files.
- **live** — FUNCTIONAL tier: fast, scoped checks against the `.env` test
  instance; the whole tier should take minutes. Read-only commands assert
  exit code and output. Mutating `set --apply` commands run the full cycle:
  seed the `before.json` state onto the involved repos, run, verify the
  result with an independent GraphQL read-back, then restore the original
  state. Seeding and restoring write the involved repos directly via
  GraphQL — never through the product's `restore` command, whose full
  instance capture takes minutes at 10k users and whose whole-instance
  semantics clobber concurrent runs. Cases may declare `live.involvedRepos`
  (extra repos to read/seed/restore; the ones absent from `after.json` are
  canaries that must come back unchanged — this is how widened regex
  selectors get caught) and `live.usersWithoutOtherGrants` (preflight:
  named users must hold no grants outside the involved repos). Cases whose
  main command intrinsically scans the whole instance (full captures,
  candidate scans over all users/repos) belong in **performance**, not
  live.
- **performance** — SCALE tier: same workflow as live, but timed and
  measured (traces, RSS sampling, TSV row), and the place for cases whose
  commands walk all 10k users / 50k repos. Run deliberately, not
  pre-commit. The legacy whole-instance stress cycle (`set --full` with the
  root maps.yaml — 10k users x ~1,150 repos, known to crash the test
  instance's Postgres) is opt-in only: `uv run tests/run.py --live "full
  cycle"`.

Functional coverage of scale-only code paths (pagination, batch stepping,
dedupe) does NOT require scale data: the local fake serves site-user pages
of at most 2 (`SITE_USERS_PAGE_CAP` in `e2e/case_runner.py`), so a fixture
with 4 users already spans 2 pages — that is what catches selection
truncation bugs locally in milliseconds.

## Instance state: setup.py / setup.yaml

[setup.py](./setup.py) converges the test instance to the desired state in
[setup.yaml](./setup.yaml) — run it BEFORE `run.py --live`:

```bash
uv run tests/setup.py            # report drift, change nothing
uv run tests/setup.py --apply    # converge the instance
```

It verifies site config, synthetic user/repo counts, rewrites any legacy
real-looking addresses to `{username}@perms-sync.test`, fabricates SAML
external accounts (group claims for `samlGroups` live cases, written via
SQL on the pgsql pod and verified back through the product's own GraphQL
parser), deletes orphaned explicit grants on deleted repos, and clears
pending permissions. GraphQL is used for instance-level reads; bulk state
goes through `kubectl exec` + psql because it is orders of magnitude
faster. Everything it touches is synthetic (`test_user_*`); it never
creates or deletes users itself.

Live cases declare their identity preconditions in tests.yaml:
`live.requiredSamlGroups` (preflight: fabricated accounts must match, with
a pointer to setup.py on drift) and `live.temporaryUsers` (the harness
creates the named users fresh via `createUser` — `created_at` = now — and
hard-deletes them afterwards; `{today}` in a cliCommand resolves to the
run's UTC date, which makes positive `--created-after` selection
deterministic against the long-pre-existing synthetic users).

## PyPI install smoke (`--install`)

`uv run tests/run.py --install` pip-installs the **published** package into a
clean venv (`--install-python`, default `python3.13`) and runs every `--help`
command, asserting exit 0 and usage output. It needs network to pypi.org
only — no Sourcegraph instance. `--install-package` pins a version
(`src-auth-perms-sync==1.2.3`) or points at a wheel path. This complements
the live tier's "wheel install smoke", which builds and installs the
*local* wheel; CI separately installs the locally-built wheel in
validate.yml. Use `--install` after a release to verify the artifact
operators actually download.

## Workflow for adding or editing a case

1. Register the case in [tests.yaml](./tests.yaml); create the fixture
   directory with any required files (`before.json`, `maps.yaml`).
2. Either write `after.json` by hand (strongest: states your intent), or run
   `uv run tests/run.py --update-golden` to generate it from the actual
   result.
3. **Review `after.json` carefully** — it is the assertion. Confirm every
   added/removed grant is what you intended before committing.
4. Run `uv run tests/run.py` to confirm the suite passes. The unit tests
   fail on unregistered fixture directories, missing required files, or
   malformed registry entries.
