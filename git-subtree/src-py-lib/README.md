# src-py-lib

Reusable libraries for Sourcegraph-adjacent Python projects

This repo is the shared implementation layer for patterns which get
rebuilt in separate scripts: API clients, HTTP retries/timeouts, structured logging,
etc.

## Experimental - This is not a supported Sourcegraph product

This repo was created for Sourcegraph Implementation Engineering deployments,
and is not intended, designed, built, or supported for use in any other scenario.
Feel free to open issues or PRs, but responses are best effort.

## Install from another project

```sh
uv add git+https://github.com/sourcegraph/src-py-lib.git
```

## What is included

- `src_py_lib.utils.logging` — centralized human stderr logs plus optional structured
  JSONL events, run IDs, git commit metadata, context fields, event timing,
  retention, startup metadata, and sanitized config snapshots.
- `src_py_lib.utils.config` — Pydantic-backed `Config` models loaded from code
  defaults, `python-dotenv` `.env` parsing, shell environment, and CLI
  overrides, with typed values, required checks, safe snapshots, and `op://...`
  reference resolution.
- `src_py_lib.utils.http` — pooled `httpx` JSON HTTP client with a shared
  30-second timeout, retry policy, `Retry-After` support, and contextual errors.
- `src_py_lib.utils.tsv` — padded TSV writer for human-readable tabular exports,
  with newline/tab cleanup, URL preservation, and Unicode-aware column widths.
- `src_py_lib.clients.graphql` — shared GraphQL execution with automatic cursor
  pagination, batched alias lookups, and schema introspection export.
- `src_py_lib.clients.sourcegraph` — Sourcegraph GraphQL client with token
  validation, endpoint normalization, connection streaming, and shared config
  fields for `SRC_ENDPOINT` (default: `https://sourcegraph.com`) and
  `SRC_ACCESS_TOKEN`.
- `src_py_lib.clients.linear` — Linear GraphQL client with automatic cursor
  handling, token validation, shared config fields, and injectable HTTP policy.
- `src_py_lib.clients.slack` — Slack Web API client with token validation,
  cursor pagination, and method pacing. Consider `slack_sdk` if usage grows
  beyond simple GET, pagination, and rate-limit handling.
- `src_py_lib.clients.github` — GitHub GraphQL client, PR URL parsing, and
  batched PR lookups, with token validation. Defaults to `https://github.com`;
  pass `github_url` for GitHub Enterprise Server. Keep lightweight for GraphQL;
  GitHub SDKs help more for REST.
- `src_py_lib.clients.one_password` — tiny 1Password CLI wrapper for signing in,
  validating authenticated `op` access, and resolving `op://...` references after config loading.
- `src_py_lib.clients.google_sheets` — Google Sheets API primitives with
  spreadsheet access validation using gcloud Application Default Credentials or
  a provided access token. Prefer Google's official libraries if Sheets usage
  grows beyond small primitives, because auth, quota project, token refresh,
  batching, and error shapes are subtle.

Prefer this library for shared logging, HTTP policy, and thin API wrappers.
Prefer vendor SDKs when they replace tricky auth, token refresh, retries,
pagination, quota behavior, or complex request models.

## Example

Define one project-specific `Config` model, then load it once at CLI startup.
For common CLI and client usage, import the curated root API:

```python
from pathlib import Path

import src_py_lib as src


class LinearExportConfig(src.LinearClientConfig):
    output_dir: Path = src.config_field(
        default=Path("."),
        env_var="LINEAR_EXPORT_OUTPUT_DIR",
        cli_flag="--output-dir",
        metavar="PATH",
        help="Directory for generated files.",
    )

config = src.parse_args(LinearExportConfig, description="Export Linear data.")
client = src.linear_client_from_config(config)
print(f"Writing files under {config.output_dir}")
```

Config precedence is: code defaults, `.env`, shell environment, then CLI
overrides. API client modules can provide shared Config base classes such as
`LinearClientConfig`, and `parse_args` resolves `op://...` references by
default. `config_field(default=...)` supports aliases, store-true /
store-false command flags, optional values, numeric bounds, and string patterns
for simple CLIs. Pass a custom `argparse.ArgumentParser` to `parse_args` only when you
need parsing beyond Config fields. Help text preserves description and
argument-help newlines, and reserves enough option-column width for long config
flags. Mark sensitive fields with `secret=True` so snapshots do not expose
resolved values.

## Logging example

Configure logging once at process startup. Prefer configuring the root logger
(`logger_name=""`, the default) so project modules and shared `src_py_lib` modules
such as `src_py_lib.utils.http` are captured by the same terminal and JSONL handlers.
Use `logging()` in CLIs to configure logging, add the command field to all
structured events, and emit standard run/startup/run-end metadata.
Use `debug()`, `info()`, `warning()`, `error()`, and `critical()` for one-off
structured events. Use `event()` blocks around timed work; they emit `trace`,
`span`, and nested `parent_span` fields. Use `start_level="debug"` to hide
noisy start events while keeping end timing visible, and
`omit_success_status=True` for very high-volume success events. Use `stage()`
for workflow context such as `stage="apply"`.
When the root logger is configured, noisy `httpx`/`httpcore` records are suppressed;
`HTTPClient` emits structured `http_request` events instead.
Run-end events include HTTP attempt/byte/status/retry counters. Set
`LoggingSettings.resource_sample_interval_seconds` to emit DEBUG
`resource_sample` events and include process resource totals on run end. Set
`SRC_LOG_LEVEL=INFO` for a run to omit DEBUG events from the log file.
`LoggingConfig` includes `--verbose/-v`, `--quiet/-q`, and `--silent/-s`
shortcuts (also available as `SRC_LOG_VERBOSE`, `SRC_LOG_QUIET`, and
`SRC_LOG_SILENT`). Use `logging_settings_from_config()` to build
`LoggingSettings` from those conventions.

```python
import src_py_lib as src

with src.logging({"src_token": "provided"}):
    src.info("sync_started", repository_count=3)

    client = src.SourcegraphClient("https://sourcegraph.example.com", "token")
    data = client.graphql("query Viewer { currentUser { username } }")
```

## Development

```sh
uv sync
uv run ruff format .
uv run ruff check .
uv run pyright
uv run python -m unittest discover -s tests
npx --yes markdownlint-cli2
```
