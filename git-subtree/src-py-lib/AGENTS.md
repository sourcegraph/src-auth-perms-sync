# Agents

<!-- HUMAN-MAINTAINED - START -->

## Project principles

- This repo is public, never write non-public information in this repo
- Keep code and docs brief, for humans to read / understand / audit quickly
- Reuse and improve existing solutions / approaches / designs / helpers / tools / patterns,
  before adding new / similar ones
- Keep runtime dependencies minimal; justify new dependencies in code review
- Preserve unrelated user or agent edits in the worktree

## Standard commands

```sh
npx --yes markdownlint-cli2
uv sync
uv run ruff format .
uv run ruff check .
uv run pyright
uv run python -m unittest discover -s tests
```

<!-- HUMAN-MAINTAINED - END -->

<!-- AGENT-MAINTAINED - START -->

## Toolchain

- Use `uv` for dependency management, virtualenv creation, and command running
- Use pyright in strict mode; fix linting / typing issues instead of suppressing them
- Use ruff for formatting, import sorting, and linting

## Runtime standards

- Configure the root logger by default (`logger_name=""`) so project modules
  and shared `src_py_lib` modules are captured by the same handlers
- Startup logs should include command, sanitized runtime config, commit when
  available, and log file path when applicable
- Use shared HTTP/client helpers for timeout policy, API error wrapping, and
  rate-limit handling

## Code organization

- Put importable package code under `src/`
- Put tests under `tests/`
- Keep module-level constants near the top of each module, after imports
- Prefer specific package/module names over broad `helpers` or `utils` modules

## Before finishing changes

- Re-read edited files for organization and stale comments
- Update `README.md` when setup or user-facing behavior changes
- Update this `AGENTS.md` only with durable project-specific discoveries

<!-- AGENT-MAINTAINED - END -->
