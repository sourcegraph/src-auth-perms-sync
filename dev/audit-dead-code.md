# Dead-code audit with Sourcegraph

Use this guide when looking for dead code in this repo with Sourcegraph code
intel, the SCIP Python index, the function call graph, MCP search tools, and
Deep Search.

## Goal

Produce a reviewed list of deletion candidates. Do not treat any tool result as
proof that code is safe to delete; Python has dynamic dispatch, config-driven
behavior, and wire-format types that static references can miss.

## Inputs

- Exact Sourcegraph repo name and revision.
- Current local branch and local diff, to avoid mixing unrelated edits.
- Entry points from `pyproject.toml`, especially the `src-auth-perms-sync` script.
- Tests and command examples that must keep working.
- Sourcegraph schema, if using GraphQL directly. Do not guess field names; read
  `dev/schema.gql` first.

## Root set

Start reachability from production roots, not from every test.

- CLI script target: `src_auth_perms_sync.cli:main`.
- Functions called by argparse subcommands.
- Imported modules that intentionally run module-level registration or setup.
- Public helpers used by documented command flows.

Then decide whether to include test roots. Include tests when the goal is
"unused anywhere". Exclude tests when the goal is "unused in production, but
possibly test-only".

## Sourcegraph workflow

1. Confirm the repo and revision with MCP repo/file search.
2. Ask Deep Search for likely dead-code candidates, with an explicit prompt:

   ```text
   Find likely dead code in github.com/sourcegraph/src-auth-perms-sync. Focus on
   Python functions, classes, methods, constants, and imports with no
   production references. Exclude CLI entry points, argparse dispatch,
   GraphQL/JSON TypedDict shapes, decorators, protocol methods, fixtures, and
   code referenced through config or strings. Return candidates with file,
   symbol, reference evidence, why it may be dead, and deletion risk.
   ```

3. For each candidate, use precise references if available. Zero references,
   or only self/test references, is a signal to inspect manually.
4. Use the function call graph, if exposed by the active Sourcegraph tools:
   - Traverse callees from the root set.
   - Compare reachable functions to all functions under `src/src_auth_perms_sync/`.
   - Treat unresolved dynamic calls as manual-review barriers, not as proof of
     dead code.
5. If call-graph traversal is not exposed through MCP, use Deep Search plus
   exact Sourcegraph searches for each candidate symbol and call site.

## Vulture workflow

Use Vulture as a candidate generator, not as proof. Do not add it as a project
dependency unless we decide to maintain a repeatable CI/local audit.

Run the strict pass first:

```sh
uv run --with vulture vulture --min-confidence 80 --sort-by-size src/src_auth_perms_sync tests
```

Then run the full advisory passes:

```sh
uv run --with vulture vulture --sort-by-size src/src_auth_perms_sync tests
uv run --with vulture vulture --sort-by-size src/src_auth_perms_sync
uv run --with vulture vulture --sort-by-size tests
```

Interpret the results this way:

- Findings in `src/src_auth_perms_sync tests` are stronger "unused anywhere" candidates.
- Findings only in `src/src_auth_perms_sync` may be test-only helpers or symmetric APIs.
- Findings only in `tests` may be stale fixtures or test helpers.
- `TypedDict` fields and GraphQL/JSON wire keys are usually false positives.
- Low-confidence findings are still useful, but require exact reference checks.

For each real-looking Vulture finding, run an exact local search and, when
available, a Sourcegraph reference search before deleting:

```sh
rg -n "symbol_name" src/src_auth_perms_sync tests
```

## Complexity workflow

Use Radon and Lizard when the code is live but hard to follow. These tools rank
complexity, size, and maintainability; they do not prove a refactor is safe.
Run them transiently with `uv run --with` instead of adding project dependencies.

Start with the file under suspicion:

```sh
uv run --with radon radon cc -s -a src/src_auth_perms_sync/cli.py
uv run --with radon radon mi -s src/src_auth_perms_sync/cli.py
uv run --with radon radon raw -s src/src_auth_perms_sync/cli.py
uv run --with lizard lizard src/src_auth_perms_sync/cli.py
```

Then scan the package for bigger hotspots:

```sh
uv run --with radon radon cc -s --min C src/src_auth_perms_sync
uv run --with lizard lizard -C 15 -L 80 src/src_auth_perms_sync
```

Optional Ruff check for functions over a chosen cyclomatic-complexity threshold:

```sh
uv run ruff check src/src_auth_perms_sync/cli.py \
  --select C901 \
  --config 'lint.mccabe.max-complexity = 10'
```

Interpret the results this way:

- Radon `C` or worse is worth inspecting; `D`/`F` should usually be split.
- High Lizard CCN means too many branches; high length means too many steps.
- High fan-out orchestration can be acceptable if the function is shallow and
  names each phase clearly.
- Repeated branch logic across functions is a better refactor target than a
  single dispatcher with clear phases.
- Prefer extracting pure decision helpers and command-state objects before
  moving API calls or mutation behavior.

For `cli.py`, also sketch the local function call graph before refactoring so
the problem is clear: deep nesting, repeated decisions, or broad orchestration.

## Triage rules

Prefer deleting only low-risk, local code first.

Good candidates:

- Private functions, methods, classes, or constants with no production callers.
- Imports that become unused after candidate removal.
- Old branch-specific helpers with no command path from `main()`.

High-risk false positives:

- CLI handlers, argparse callbacks, and entry points.
- TypedDicts, dataclasses, and constants that mirror GraphQL or JSON keys.
- Decorated functions, protocol methods, context managers, and magic methods.
- Test fixtures, mocks, and helpers referenced by pytest/unittest discovery.
- Names looked up through strings, config files, environment variables, or API
  payloads.

## Deletion loop

Work in small batches.

1. Record the candidate, evidence, and risk in the working notes or PR body.
2. Delete the smallest self-contained candidate set.
3. Remove imports and tests that only existed for that deleted code.
4. Re-run references/search for the deleted symbols to confirm no live callers
   remain.
5. If a failure shows the code is live, restore only that candidate and keep the
   evidence.

## Validation

Run the narrowest checks that cover the deleted code. For normal Python dead-code
deletions, run:

```sh
uv run ruff check src/src_auth_perms_sync/ --fix
uv run ruff format src/src_auth_perms_sync/
uv run pyright
uv run python -m unittest discover -s tests
uv run src-auth-perms-sync --help
```

If the deletion touches command behavior, also run the affected command help or
dry-run path. If it touches Sourcegraph mutation or snapshot behavior, follow
the dry-run and backup inspection flow from `AGENTS.md`.

## Handoff format

Use this compact table when handing candidates to another thread or a PR review.

| Symbol | Path | Evidence | Risk | Action |
| --- | --- | --- | --- | --- |
| `name` | `path/to/file.py` | No production refs; unreachable from CLI root | Low | Delete |

Keep any long-lived follow-up tasks in `dev/TODO.md`. Delete temporary audit
notes when they are folded into `dev/TODO.md`, the PR body, or the commit
message.
