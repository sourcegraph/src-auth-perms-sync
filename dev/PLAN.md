# PLAN: file handling + observability redesign

> **Status (2026-06-12): fully implemented**, including Track A Phase A4
> (in-memory mapping rules for `Set`). Shipped as src-py-lib v0.3.0 and
> src-auth-perms-sync v0.5.0 (`refactor-logging-and-files` PR), with A4
> following in the `in-memory-mapping-rules` PR. Phases were compressed
> into one PR per repo (no ContextVar bridge phase was needed);
> everything landed as specified.

Spans both repos (we own both, both greenfield, no external users):

- `src-py-lib` — reusable plumbing (logging, events, OTel, HTTP, config)
- `src-auth-perms-sync` — consumer; runs as a CLI and as an importable
  Python module (`src.Get(config)` etc.)

Two tracks. Track A fixes how files are handled. Track B fixes how logs and
structured events are handled. They meet where the JSONL event sink takes its
path from `RunPaths`.

## Goals

1. Module-import customers get data back in memory, control over (or freedom
   from) disk writes, and their own `logging` config left untouched.
2. CLI customers get explicit control over where files land, with default
   paths unchanged.
3. Structured events become first-class, OTel-standard wide events instead of
   stowaways on the stdlib logging pipe.
4. Net code reduction: delete the path ContextVars, the logging demux filters,
   and the magic record attributes.

## Current state (verified in code, this thread)

### Files written today

All output roots at `Path.cwd()/src-auth-perms-sync-runs/<endpoint>/` via
`backups.endpoint_artifacts_directory()`. Three species share that tree:

| Species | Files | Nature |
| --- | --- | --- |
| Human-edited input | `maps.yaml` | `get` creates empty if missing; `set` reads |
| Regenerated reference | `code-hosts.yaml`, `auth-providers.yaml` | overwritten by every `get` |
| Append-only audit | `runs/<ts>-<cmd>/{before,after,diff}.json` + copies | gate reversibility |

The audit run directory also carries a `maps.yaml` copy and `log.json`.

Path plumbing: `cli.py:_run_or_raise` computes a run directory, then sets two
ContextVars (`backups.run_artifacts_context`). Deep code in
`permissions/restore.py`, `permissions/full_set.py`, `orgs/sync.py` calls
`backups.backup_timestamp()` / `backups.backup_path(name, ts, endpoint, cmd,
state)`, which read the ContextVars or silently recompute from cwd.

### What `--no-backup` does and does not do

`--no-backup` skips only the reversibility artifacts (before/after snapshots,
maps.yaml backup copy). Even with it set, the tool still writes:

- `maps.yaml` creation (`run_get`, unconditional)
- `code-hosts.yaml` / `auth-providers.yaml` (`cmd_get`, unconditional)
- `log.json` (`_run_or_raise` always passes a log file path)
- dry-run snapshots/diffs — `full_set.py` gates on
  `if not (dry_run or do_backup)`, so dry runs write regardless, because the
  diff is the dry run's output

### Logging today

- Two record species ride one stdlib logging pipe: human messages
  (`log.info(...)` on module loggers) and structured events
  (`span()`/`log_event()`), the latter with message `event=%s` and the payload
  smuggled in record attrs `_src_py_lib_structured_event` /
  `_src_py_lib_structured_fields`, emitted on the ROOT logger
  (`logger_name=""` default).
- Demux at sinks: terminal handler carries `_DropStructuredEvents`;
  `JSONLogFileHandler` knows the magic attrs and renders both species into
  `log.json` (human records become `{"event": "log", ...}`).
- OTel spans open in parallel inside `span()`; OTel SDK is a hard dependency.

### Bugs / hazards found during investigation

1. **Module import nukes customer logging.** `configure_logging()` runs on
   every `src.Get(config)` call and, with `logger_name=""`, clears the ROOT
   logger's handlers and sets `propagate = False`. A host application's
   logging config is destroyed.
2. **Snapshot filename collision risk.** In a combined `set
   --sync-saml-orgs` run, permission snapshots and org snapshots both resolve
   to `before.json` in the same run directory (`backup_path` ignores
   `source_name` when `state` is given).
3. **Run-directory collision.** Timestamps are second-precision; concurrent
   module calls or rapid CLI invocations can collide.
4. **HTTP metric reset misplaced.** `reset_observability_metrics()` lives in
   `configure_logging()`; skip handler config and a long-running script's
   second run reports cumulative counters.
5. **Audit events ride logger levels.** A host that sets root level WARNING
   silently drops our info-level audit events.

## Hard invariants (do not break; see AGENTS.md)

All four AGENTS.md invariants apply. The one this plan touches most is
invariant 3 — snapshots gate reversibility: `--apply` defaults to
before/after snapshots; `--no-backup` stays an explicit escape hatch, never
the default.

New corollary adopted in this plan: any flag combination that removes the
undo path must be stated explicitly twice (`--no-files` + `--apply` requires
`--no-backup`).

---

## Track A: file handling (`RunPaths`)

### Design decisions

- **One knob**: `artifacts_dir` Config field, CLI `--artifacts-dir`, env
  `SRC_AUTH_PERMS_SYNC_ARTIFACTS_DIR`. Semantics: the directory that contains
  endpoint subdirectories. Default `./src-auth-perms-sync-runs` — existing
  default paths do not move. Resolve to absolute once at startup
  (`Path.resolve(strict=False)`) so later `os.chdir()` in a host script
  cannot redirect writes. No XDG / platformdirs: these are audit artifacts in
  secured offline environments; explicit operator paths beat OS conventions.
- **One value object**: frozen `RunPaths`, built once at the edge
  (`_run_or_raise`) by `resolve_run_paths(config, endpoint, command)`:

  ```python
  @dataclass(frozen=True)
  class RunPaths:
      timestamp: str
      artifacts_dir: Path        # resolved artifacts root
      endpoint_directory: Path   # artifacts_dir / <endpoint-dirname>
      maps_path: Path            # respects --maps-path override
      code_hosts_path: Path
      auth_providers_path: Path
      run_directory: Path        # endpoint_directory / runs / <ts>-<artifact-name>
      log_path: Path
  ```

  Threaded explicitly down `run_command` → `cmd_*` → workflow helpers. Deep
  code receives concrete `Path`s; nothing recomputes from
  `(timestamp, endpoint, command)`.
- **`maps.yaml` default stays endpoint-scoped.** Endpoint scoping prevents
  applying one instance's mappings to another; a silent default move creates
  two plausible maps files. Instead make `--maps-path` symmetric: `get` gains
  the flag (today only `set` has it), so `get --maps-path ./maps.yaml`
  creates/leaves that file and `set --maps-path ./maps.yaml` reads it.
- **Run directories are created exclusively**; on collision append a numeric
  suffix (`...-set-apply-2`). Never overwrite run artifacts.
- **Artifact families are named.** Permission snapshots keep `before.json` /
  `after.json` / `diff.json`; org-sync snapshots become
  `saml-organizations-before.json` etc., so combined runs cannot collide.
- **Writability preflight.** Apply-mode commands resolve paths, create the
  run directory, and verify the snapshot destination is writable BEFORE the
  first mutation. Never mutate first and discover backups can't be written.
- **`no_files` knob** (CLI `--no-files`, Config field): suppress all disk
  output. Distinct axis from `no_backup` (reversibility) — keep both flags.
  - Guardrail 1: `no_files=True` + `apply=True` is a config error unless
    `no_backup=True` is also set (give up the undo button explicitly, twice).
  - Guardrail 2: `no_files` governs output only; `set` still reads its
    `maps_path` input (until Track A Phase 4 in-memory maps).
  - `no_files` implies `log_file=None` (lib already supports no file handler)
    and no JSONL event sink.
  - For CLI dry runs `--no-files` discards `diff.json` — operator's explicit
    choice; the real audience is module customers, but offer uniformly.
- **Result objects.** Command wrappers return dataclasses; `__bool__` returns
  `succeeded` so existing `if src.Get(config):` keeps working. Note
  `__bool__` is only partial compat (`Get(c) is True` breaks); acceptable —
  no external users yet. `GetResult` carries the same dicts dumped to YAML
  (`cmd_get` already has them in memory; thread out via
  `run_context.CommandData`):

  ```python
  @dataclass(frozen=True)
  class GetResult:
      succeeded: bool
      auth_providers: list[dict[str, Any]]   # as written to auth-providers.yaml
      code_hosts: list[dict[str, Any]]       # as written to code-hosts.yaml
      maps_path: Path
      maps_created: bool
      paths: RunPaths | None

      def __bool__(self) -> bool: ...
  ```

  Same pattern for `SetResult` (planned/applied diff), `RestoreResult`,
  `SyncSamlOrgsResult`. Export the path helpers (`default_maps_path`,
  `endpoint_artifacts_directory`) from the package `__init__`.

### Track A phases (each ships independently)

- **A0 — characterization tests first.** Pin current behavior before
  touching paths: default `get` output locations; default `set` maps path;
  relative `--maps-path` is cwd-relative; `--no-backup` opt-in only; apply
  fails before mutation when artifact paths are unwritable; combined
  `set --sync-saml-orgs` snapshot naming (exposes the collision).
- **A1 — `artifacts_dir` + `RunPaths` at the edge.** Add the config field,
  `resolve_run_paths()`, exclusive run-dir creation, `no_files` knob with
  guardrails, `--maps-path` on `get`. Keep the two ContextVars as a
  temporary bridge (`run_artifacts_context(paths.run_directory, ...)`). QoL
  lands immediately; refactor risk stays low.
- **A2 — thread `RunPaths` down; delete the ContextVars.** Change
  signatures: `run_command(..., paths)` → `run_get/run_set/run_restore/
  run_sync_saml_organizations(..., paths)` → workflow helpers take concrete
  paths (`write_maps_backup(paths)`, `write_snapshot_pair(paths, ...)`).
  Apply artifact-family naming. When no deep code calls `backup_path()` /
  `backup_timestamp()`, delete `run_artifacts_context`, both ContextVars,
  and the cwd fallback. Net code reduction.
- **A3 — result dataclasses + exported helpers.** As specified above. CLI
  ignores the result; module callers stop re-parsing YAML the library just
  wrote.
- **A4 — in-memory mapping rules for `Set` (optional, later).** Module
  customers pass parsed mapping rules instead of a maps file; the full
  get → assemble → dry-run set loop never touches disk. Snapshots still go
  to disk on `--apply` unless `no_files` + `no_backup` are both explicit.

---

## Track B: observability (`EventSink` + OTel wide events)

### Design decisions: three concerns, three channels

```text
Human messages                Structured events             Tracing
log.info("Wrote %s")          span() / log_event()          OTel spans
       │                             │                         │
       ▼                             ▼                         │
stdlib logging              EventSink (explicit, per run)      │
module loggers only           ├ JSONLEventSink → log.json      │
       │                      ├ InMemoryEventSink (tests,      │
       │                      │   module customers)            │
       │                      ├ CallbackEventSink              │
       │                      ├ OtelLogsSink (--otel)          │
       │                      └ NullEventSink (default)        │
CLI mode only:                       ▲                         │
terminal handler         EventBridgeHandler forwards human     │
on package loggers,      log records INTO the sink so          │
never root               log.json keeps everything             │
```

- **Bridge direction reversed.** Today rich events are flattened onto the
  logging pipe (magic attrs) and unpacked at the file handler. Instead:
  events go to the sink directly as dicts; ONE `EventBridgeHandler`
  (CLI-installed) wraps lossy human log records into `{"event_name": "log"}`
  events. The adapter direction matches data richness.
- **Entrypoint is the mode signal — no `manage_logging` knob.**
  `main()` runs CLI mode (terminal handler + bridge + JSONL sink, handlers
  attached only to `("src_auth_perms_sync", "src_py_lib")`, never root, no
  `handlers.clear()`, no `propagate` changes on host loggers).
  `Get/Set/Restore/SyncSamlOrgs` run guest mode: no handler changes
  anywhere, `NullEventSink` default, optional caller-provided sink. Standard
  etiquette `logging.NullHandler()` on the package loggers.
- **Sink resolution via ContextVar (`EventRuntime`).** One deliberate
  exception to the "kill ContextVars" rule: the event runtime
  (`run`, `sink`, `min_level`, `base_fields`) is genuinely ambient execution
  context, like the current OTel span. Guardrails: only
  `observability_context()` sets it; default is `NullEventSink`; thread
  pools keep using `contextvars.copy_context()` via
  `submit_with_log_context`; no import-time side effects.
  (`RunPaths` stays explicitly threaded — paths are not ambient.)
- **`span()` / `log_event()` / `event()` / `stage()` signatures unchanged.**
  Only the backend moves; consumer call sites in src-auth-perms-sync are
  untouched.
- **Split `logging_context()`** (currently does too much) into:
  - `observability_context(name, *, sink, run, run_fields, open_telemetry,
    resource_sample_interval_seconds, ...)` — sets the EventRuntime, OTel
    only if explicitly requested, run start/end events, resource sampler,
    metric reset (moved here from `configure_logging`), sink lifecycle.
  - `cli_logging_handlers(*, sink, run, logger_names, terminal_level,
    audit_log_level)` — adds/removes only its own handlers.
- **Teardown ordering** (baked into one context manager): stop resource
  sampler → wait for worker threads → emit run-end event → flush/close JSONL
  sink → force-flush OTel → remove CLI handlers. Run-end event must land
  even on `SystemExit` / exceptions; OTel flush failure must not prevent
  JSON flush; no logging from inside sink error handling (recursion).
- **OTel global provider hygiene.** Never configure OTel in guest mode
  unless the caller asks; if the host already configured OTel, `span()`
  uses it. Add an `owned` flag to `OpenTelemetryRuntime`; only force-flush
  providers this run configured.
- **Level policy.** Audit completeness is governed by the sink, not logger
  levels: `log.json` defaults to complete (debug); `--quiet` affects
  terminal only. Lifecycle events (run start/end, startup config snapshot,
  errors) are always emitted.
- **Thread safety.** JSONL sink locks around writes; copy event dicts before
  customer callbacks; worker pools complete inside the observability
  context; document that `ProcessPoolExecutor` does not inherit context.

### OTel standards adoption (decided inside B1/B2, not a separate phase)

- **Event schema = OTel Logs Data Model field names:**

  | Today | OTel standard |
  | --- | --- |
  | `ts` (string) | `time_unix_nano` |
  | `level` | `severity_text` + `severity_number` (INFO=9, WARN=13, ERROR=17) |
  | `event` key | `event_name` |
  | `message` | `body` |
  | `trace` / `span` / `parent_span` | `trace_id` / `span_id` (hex from our OTel spans) |
  | other fields | `attributes` |
  | run-level fields | `resource` attributes, stamped once per run |

- **Semantic conventions for attribute names**, pinned in one
  `semconv.py` constants module (semconv is versioned and partly
  experimental; an upstream rename must be a one-file change):
  `error_type` → `error.type`; pid → `process.pid`; Python version →
  `process.runtime.version`; `service.name` / `service.version`; HTTP
  run-summary counters aligned to `http.client.*`. App-specific fields get
  our own namespace so they can never collide: `sync.command`,
  `sync.endpoint`, `sync.run.id`, `sync.parallelism`, etc.
- **Wide-event discipline: one event per unit of work.** The span-END event
  is THE wide event (the codebase already accumulates attributes onto
  `cmd_event[...]` during work — keep that pattern). Demote span-START
  events to debug; demote run-start once `startup_event` carries the config
  snapshot. `log.json` gets ~half the lines and every line is worth reading.
- **File format: flat JSONL with OTel field names** (human-greppable,
  audit-friendly, one trivial transform from OTLP). NOT per-line OTLP/JSON
  envelopes (`resourceLogs[...]` — three envelopes deep, miserable to audit
  by eye). True-OTLP interop is a separate sink: when `--otel` is on,
  `OtelLogsSink` emits wide events through the OTel Logs SDK
  (`LoggerProvider` → OTLP/HTTP) — already a dependency. Offline customers
  keep the readable file; connected ones get standard wire logs correlated
  with our traces via `trace_id`/`span_id`.

### Custom logic carry-over inventory (audited 2026-06-12)

Existing custom logic in `src_py_lib/utils/logging.py` and its fate. Most
survives because `span()` / `log_event()` / context machinery keep their
signatures; four items live in code Track B deletes and MUST be carried over
explicitly:

1. **HTTP header secret redaction** (`_http_headers` +
   `SECRET_FIELD_FRAGMENTS`): scrubs authorization/cookie/token headers
   before they reach `log.json`. Lives in the handler path B6 deletes. Move
   the redaction (and `_is_sensitive_log_field`) into the bridge/mining path.
   Losing this writes bearer tokens to disk during wire debugging.
2. **httpcore/httpx wire-debug mining** (`_structured_log_fields`):
   `ast.literal_eval`s httpcore debug messages into structured
   `status_code` / `http_version` / redacted-header fields; demotes httpx
   "HTTP Request:" lines to debug. The bridge attaches to package loggers
   only, so httpx/httpcore records never reach the sink — the opt-in
   wire-debug mode (`suppress_http_dependency_logs=False`) would silently
   die. Carry-over: when suppression is disabled, also attach the bridge to
   `("httpx", "httpcore")` and keep the mining + redaction in the bridge.
3. **Log-file retention** (`_prune_old_log_files`, `retain_log_files`):
   inert for src-auth-perms-sync (per-run directories don't match the
   prune glob) but active for other src-py-lib consumers using the default
   `logs/` dir. Keep pruning where the sink's file is created
   (`logs_dir`-style construction helper), not in the sink itself.
4. **`exc_info` traceback formatting and field ordering**
   (`_ordered_payload`, `LOG_FIELD_ORDER`): move traceback rendering into
   `EventBridgeHandler`; move ordering into the JSONL sink, updated to the
   OTel field names (`time_unix_nano`, `severity_text`, `event_name`,
   `trace_id`, `span_id` first, attributes alphabetical).

Verified safe without action (mechanism unchanged by the plan):
`log_context`/`stage` inherited fields; `submit_with_log_context`;
trace-field stamping; HTTP metric counters wired into `HTTPClient`;
`ResourceSampler` (emits via `log_event`, so it follows the sink);
`startup_event` git hash + `sanitized_config_snapshot` (incl. `op://` →
"reference" secret-state detection); run-end `SystemExit(0)`/exit-code
semantics; `-v/-q/-s` alias validation and level parsing; OTel span
attributes/status and traceparent propagation for `fetch_sg_traces`.

`_DropHTTPDependencyLogs` on the terminal handler becomes unnecessary by
construction (handlers sit on package loggers, so httpx/httpcore noise
never reaches them) — delete it; behavior is preserved.

### Track B steps (lib first, consumer second)

- **B1 — sinks beside the old code (src-py-lib).** `EventSink` protocol;
  `NullEventSink`, `JSONLEventSink` (locked writes, flush/close),
  `CompositeEventSink`, `InMemoryEventSink`, `CallbackEventSink`;
  `EventRuntime` ContextVar; `semconv.py`; tests for JSONL output shape
  (OTel field names, severity numbers, resource stamping).
- **B2 — move `log_event()` off stdlib logging (src-py-lib).** Build the
  OTel-shaped payload, emit to the current sink, keep OTel span-event
  emission; delete the `LogRecord.extra` magic-attr path. Apply wide-event
  discipline (start events → debug).
- **B3 — `EventBridgeHandler` (src-py-lib).** Human records → sink as
  `event_name="log"` events. CLI-installed only, attached to
  `("src_auth_perms_sync", "src_py_lib")`.
- **B4 — split `logging_context()` (src-py-lib).** Into
  `observability_context()` and `cli_logging_handlers()` as above; move
  `reset_observability_metrics()` into `observability_context()`; OTel
  `owned` flag.
- **B5 — consumer wiring (src-auth-perms-sync).** `_run_or_raise(...,
  cli_mode: bool)`; `main()` passes `cli_mode=True` (JSONL sink at
  `RunPaths.log_path`, terminal + bridge handlers); `Get/Set/Restore/
  SyncSamlOrgs` pass `cli_mode=False` (guest mode; optional `event_sink`
  parameter for customers who want events programmatically). README gains a
  module-logging snippet (root WARNING default means a long sync looks
  silent — show `logging.getLogger("src_auth_perms_sync")` setup).
- **B6 — delete the old demux (src-py-lib).** Remove
  `_DropStructuredEvents`, `_STRUCTURED_EVENT_ATTR`,
  `_STRUCTURED_FIELDS_ATTR`, the structured branch in `JSONLogFileHandler`
  (or the whole handler, replaced by the sink), and the destructive root
  `handlers.clear()`. Regression tests: CLI produces `log.json`;
  `log.info()` appears as `event_name="log"`; structured events appear with
  full attributes; module `Get(config)` does not mutate root handlers or
  levels; thread-pool events retain run/context fields; run-end event
  appears on exceptions; second module run in one process reports per-run
  (not cumulative) HTTP counters.

---

## Track interaction points

- `JSONLEventSink` path comes from `RunPaths.log_path` (A1 must land before
  B5's consumer wiring, or B5 temporarily uses the current log path helper).
- `no_files` (A1) disables the JSONL sink and the log file; guest mode (B5)
  defaults to no file output anyway — `no_files` mainly matters for CLI and
  for module callers who set `artifacts_dir`.
- Result dataclasses (A3) and `InMemoryEventSink` / `CallbackEventSink` (B1)
  together complete the module story: data back in memory, events back in
  memory, zero disk unless asked (and snapshots on `--apply`, always, unless
  doubly opted out).

## Verification

- `uv run tests/run.py` (lint, format, pyright, unit + fixture tests, CLI
  rejection matrix, randomized permission invariants) after every phase.
- `uv run tests/run.py --live` for mutation-path phases (A2 especially), with
  before/after snapshot inspection under `src-auth-perms-sync-runs/`.
- A0 characterization tests are the safety net for every later phase: default
  paths must not move.
- New fixture cases for: `--artifacts-dir`, `get --maps-path`, `--no-files`
  rejection matrix (`--no-files --apply` without `--no-backup` is an error),
  combined-run snapshot naming, log.json schema goldens.
- Per AGENTS.md: dry-run against the .env test instance and read the planned
  changes before any `--apply`; inspect snapshots afterward.

## Explicitly out of scope (revisit triggers noted)

- **Moving the `maps.yaml` default** out of the artifacts tree — revisit only
  if compatibility constraints loosen; `--maps-path` symmetry covers the need.
- **XDG / platformdirs** — explicit flag + env is correct for secured offline
  environments.
- **`QueueEventSink` / async writer thread** — only if event volume, slow
  customer callbacks, or OTLP backpressure measurably hurt sync runs.
- **Artifact manifest / `ArtifactStore` abstraction** — only if artifact
  families multiply beyond the current three.
- **Strict per-line OTLP/JSON file format** — only if a customer needs
  collector `otlpjsonfile` ingestion of `log.json` as-is; ship as a sink
  variant, not a default.

## Sequencing summary

```text
A0 characterization tests
A1 artifacts_dir + RunPaths (bridge) + no_files + get --maps-path
B1 sinks + OTel schema + semconv      (src-py-lib, parallel with A1/A2)
B2 log_event → sink, wide events
A2 thread RunPaths, delete ContextVars
B3 bridge handler
B4 observability_context split
B5 consumer cli_mode wiring           (needs A1 for RunPaths.log_path)
A3 result dataclasses + exports
B6 delete demux + regression tests
A4 in-memory maps for Set             (optional, last)
```

Each step lands as its own PR from a clean worktree off `origin/main`, lint
and tests green, docs updated.
