# Testing

All testing is driven by one entrypoint and one case registry:

| Path | Purpose |
| ---- | ------- |
| [run.py](./run.py) | The single test entrypoint: `uv run tests/run.py [--local \| --live \| --performance]` |
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
- **live** — runs `cliCommand` against the `.env` test instance. Read-only
  commands assert exit code and output. Mutating `set --apply` commands run
  the full cycle: seed the `before.json` state onto the involved repos, run,
  verify the result with an independent GraphQL read-back, then restore the
  original state. Cases may declare `live.involvedRepos` (extra repos to
  capture/seed/restore; the ones absent from `after.json` are canaries that
  must come back unchanged — this is how widened regex selectors get caught)
  and `live.usersWithoutOtherGrants` (preflight: named users must hold no
  grants outside the involved repos).
- **performance** — same as live, but timed and measured (traces, RSS
  sampling, TSV row).

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
