# Memory efficiency testing

Use this when full snapshot capture or full-set apply is slow. The goal is to
correlate `src-auth-perms-sync` structured logs with Sourcegraph Jaeger spans
and pod/Postgres load. Request-ready evidence and copy/paste text for
Sourcegraph Engineering live in
[engineering-requests.md](./engineering-requests.md).

## Capture a focused trace

Run a small command with `--fetch-sg-traces`. This sends
`X-Sourcegraph-Request-Trace` and a W3C `traceparent` header on each GraphQL
request. Sourcegraph may also return `x-trace`, `x-trace-span`, and
`x-trace-url` response headers.

```bash
uv run src-auth-perms-sync get \
  --fetch-sg-traces \
  --sample-interval 0 \
  --parallelism 2 \
  --explicit-permissions-batch-size 25
```

Find the slow GraphQL HTTP requests in the run log:

```bash
LOG=src-auth-perms-sync-runs/<endpoint>/runs/<run>/log.json

jq -r '
  select(.event == "http_request" and .phase == "end") |
  select(.url | endswith("/.api/graphql")) |
  [
    .duration_ms,
    (.response_headers["x-trace"] // ""),
    (.response_headers["x-trace-url"] // ""),
    (.request_headers.traceparent // "")
  ] | @tsv
' "$LOG" | sort -nr | head -20
```

Prefer the `x-trace` value when present. If Sourcegraph did not return one,
extract the trace ID from `traceparent`:

```bash
TRACEPARENT=00-<trace-id>-<span-id>-01
TRACE_ID="$(printf '%s' "$TRACEPARENT" | cut -d- -f2)"
```

Fetch the trace JSON from Jaeger:

```bash
curl -sS \
  -H "Authorization: token $SRC_ACCESS_TOKEN" \
  "$SRC_ENDPOINT/-/debug/jaeger/api/traces/$TRACE_ID" \
  > /tmp/sourcegraph-trace.json
```

Jaeger ingestion can lag. If the API returns `trace not found`, wait briefly
and retry. For long runs, fetch traces as soon as the relevant command
finishes; older trace IDs can disappear before a full matrix ends.

Summarize the hottest spans:

```bash
uv run python - <<'PY'
import collections
import json

trace = json.load(open("/tmp/sourcegraph-trace.json"))["data"][0]
durations_by_operation = collections.defaultdict(list)
for span in trace["spans"]:
    durations_by_operation[span["operationName"]].append(span["duration"] / 1000)

for operation, durations in sorted(
    durations_by_operation.items(),
    key=lambda item: sum(item[1]),
    reverse=True,
)[:15]:
    print(
        f"{operation}: count={len(durations)} "
        f"sum_ms={sum(durations):.1f} "
        f"max_ms={max(durations):.1f}"
    )
PY
```

Do not commit tokens, customer URLs, raw trace JSON, benchmark CSVs, or monitor
artifacts. Keep them in `/tmp` unless a human asks to preserve them.

## Trace the end-to-end matrix

Prefer the end-to-end runner as the single orchestrator. With
`--fetch-sg-traces`, it passes Sourcegraph debug trace collection to every child
CLI command, tails child JSON logs, and fetches Jaeger traces in the background
while each child command is still running.

```bash
uv run python dev/test-end-to-end.py \
  --fetch-sg-traces \
  --sample-interval 0 \
  --external-sample-interval 0 \
  --results-json /tmp/src-auth-perms-sync-end-to-end-trace.json \
  --results-csv /tmp/src-auth-perms-sync-end-to-end-trace.csv
```

Useful trace options:

- `--jaeger-trace-limit N`: fetch only the `N` slowest GraphQL traces per case.
- `--jaeger-trace-limit 0`: send trace headers but skip Jaeger fetching.
- `--jaeger-trace-parallelism N`: tune concurrent Jaeger fetches.
- `--jaeger-trace-jsonl PATH`: stream compact trace summaries as JSON Lines.
- `--jaeger-trace-dir PATH`: store complete raw Jaeger payloads.

Raw trace files include:

- `trace_request`: CLI-side HTTP and `graphql_query` correlation metadata,
  including query name, page number, page size, cursor presence, query byte
  count, variable names, response fields, status, and timing.
- `jaeger_summary`: compact hot-operation and GraphQL-operation summary.
- `jaeger_trace`: the complete Jaeger trace JSON returned by Sourcegraph.

All runner flags are Config-backed. You can set them in the shell or `.env`
with `SRC_AUTH_PERMS_SYNC_E2E_*` names, plus `SRC_ENDPOINT`,
`SRC_ACCESS_TOKEN`, and `SRC_AUTH_PERMS_SYNC_TEST_USER`.

For each tested batch size and parallelism, record:

- CLI `capture_explicit_grants` duration from the structured log
- slowest GraphQL `http_request` duration and its trace metadata
- Jaeger counts and summed duration for `GraphQL Request`, `repos.Get`,
  `sql.conn.query`, and `database.PermsStore.LoadUserPermissions`
- run-end `http_retry_count`, `http_request_attempt_count`, and timeout/error
  counts

## Monitor Sourcegraph load during e2e runs

The runner can start the Sourcegraph pod/Postgres monitor and write monitor
artifact paths into the result JSON:

```bash
uv run python dev/test-end-to-end.py \
  --fetch-sg-traces \
  --monitor-sourcegraph-load \
  --sample-interval 0 \
  --external-sample-interval 0 \
  --results-json /tmp/src-auth-perms-sync-end-to-end-trace.json \
  --results-csv /tmp/src-auth-perms-sync-end-to-end-trace.csv
```

By default, monitor output is written beside `--results-json` or
`--results-csv` as `*-sourcegraph-load`, and the monitor's stdout/stderr goes
to `*-sourcegraph-load.log`. Override the location with
`--monitor-output-dir PATH`. Tune Kubernetes targets and sample intervals with
the `--monitor-*` flags if the test namespace or pod names differ.

The lower-level helper remains available for focused profiling outside a full
e2e run:

```bash
dev/memory-efficiency-monitor-sourcegraph.sh \
  --namespace m \
  --output-dir /tmp/src-auth-perms-sync-sourcegraph-load-$(date -u +%Y%m%d-%H%M%S)
```

Stop the helper with Ctrl-C, or add `--duration-seconds N`. It samples
Kubernetes CPU/memory, frontend and Postgres processes, cgroup CPU/memory
pressure, Postgres active queries/waits/locks, `pg_stat_statements` when
enabled, and frontend logs. On startup it runs `CREATE EXTENSION IF NOT EXISTS
pg_stat_statements` and `pg_stat_statements_reset()` through `kubectl exec`
against `pod/pgsql-0`, so statement summaries start clean for the monitored
run.

## Engineering requests

Request-ready trace findings, stress evidence, Sourcegraph codepath notes,
proposed GraphQL APIs, and copy/paste issue text now live in
[engineering-requests.md](./engineering-requests.md).
