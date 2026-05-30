# Sourcegraph explicit-permissions tracing

Use this when full snapshot capture is slow. The goal is to correlate
`src-auth-perms-sync` HTTP timings with Sourcegraph Jaeger spans, then use
the evidence to ask Sourcegraph engineering for a bulk explicit-permissions
read path.

## Capture sampled traces

Run with `--trace` to send a sampled W3C `traceparent` header on every HTTP
request. The trace ID is logged in each `http_request.request_headers` entry.

```bash
uv run src-auth-perms-sync --get \
  --trace \
  --sample-interval 0 \
  --parallelism 2 \
  --explicit-permissions-batch-size 25
```

Find the slow GraphQL requests in the run log:

```bash
LOG=src-auth-perms-sync-runs/<endpoint>/runs/<run>/log.json

jq -r '
  select(.event == "http_request" and .phase == "end") |
  select(.url | endswith("/.api/graphql")) |
  [
    .duration_ms,
    .request_headers.traceparent,
    (.response_headers["x-trace-url"] // "")
  ] | @tsv
' "$LOG" | sort -nr | head -20
```

Extract the W3C trace ID from a `traceparent` value:

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

Jaeger ingestion can lag by a few seconds. If the API returns `trace not
found`, wait briefly and retry the same URL.

For long runs such as `dev/test-end-to-end.py --trace`, fetch the
slow traces as soon as the relevant command finishes, or rerun a focused case
and fetch those traces immediately. On the sgdev test instance, a fully traced
end-to-end run can emit thousands of sampled traces; the in-memory Jaeger data
may evict or restart before the whole matrix finishes, returning `trace not
found` or temporary 502s for earlier trace IDs.

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

Do not commit tokens, customer URLs, or raw trace files. Keep trace JSON and
benchmark CSVs in `/tmp` unless a human asks to preserve them.

## Evidence to collect

To trace the full integration matrix, run the end-to-end script with its own
`--trace` flag. The runner forwards it to every child CLI invocation, then
tails each child run log and fetches all traced GraphQL Jaeger traces in the
background while that child command is still running. The runner uses
`src-py-lib` Config parsing, logging, Sourcegraph endpoint normalization,
`SourcegraphClient.fetch_jaeger_trace()`, `summarize_jaeger_trace()`, and a
shared HTTP pool, so trace fetch and summary behavior match the CLI's
Sourcegraph client:

```bash
uv run python dev/test-end-to-end.py \
  --trace \
  --sample-interval 0 \
  --external-sample-interval 0 \
  --results-json /tmp/src-auth-perms-sync-end-to-end-trace.json \
  --results-csv /tmp/src-auth-perms-sync-end-to-end-trace.csv
```

Use `--jaeger-trace-limit N` to fetch only the `N` slowest GraphQL traces per
case, or `--jaeger-trace-limit 0` to disable in-run Jaeger fetching while still
sending sampled trace headers. The default is to fetch every traced GraphQL
request.

The runner writes trace summaries incrementally as JSON Lines. By default, it
uses a sibling of `--results-json` or `--results-csv`, named
`*-jaeger-traces.jsonl`. Override this with `--jaeger-trace-jsonl PATH`.

The runner also writes complete raw Jaeger trace payloads for in-depth
follow-up. By default, it uses a sibling directory named `*-jaeger-traces`.
Override this with `--jaeger-trace-dir PATH`. Each file is stored by variant,
iteration, case, and trace ID:

```text
<trace-dir>/
  candidate/
    iteration-0001/
      set-full-no-backup-apply/
        <trace-id>.json
```

Each raw trace file includes:

- `trace_request`: CLI-side correlation metadata from the HTTP request and the
  surrounding `graphql_query` event, including query name, page number, page
  size, cursor presence, query byte count, variable names, response fields,
  status, and timing. If `src-py-lib` later logs sanitized GraphQL variable
  values, the same field will include them as `variables`, `input_variables`,
  or `variable_values`.
- `jaeger_summary`: compact hot-operation and GraphQL-operation summary.
- `jaeger_trace`: the complete Jaeger trace JSON returned by Sourcegraph.

The shared `src-py-lib` `stream_jaeger_trace_summaries()` helper now fetches in
parallel for in-process Sourcegraph clients. The end-to-end script still uses a
bounded global worker pool because the traced requests happen in child
processes and are discovered by tailing their JSON logs. Tune this with
`--jaeger-trace-parallelism N` (default 8). The runner drains outstanding
background collectors once at the end, before it writes JSON/CSV results, so
Jaeger collection does not add a blocking phase between child cases.

All runner flags are Config-backed. You can set them in the shell or `.env`
with `SRC_AUTH_PERMS_SYNC_E2E_*` names, plus `SRC_ENDPOINT`,
`SRC_ACCESS_TOKEN`, and `SRC_AUTH_PERMS_SYNC_TEST_USER`.

For each tested batch size and parallelism, record:

- CLI `capture_explicit_grants` duration from the structured log
- slowest `http_request` duration and its `x-trace` / `traceparent` metadata
- Jaeger counts and summed duration for `GraphQL Request`, `repos.Get`,
  `sql.conn.query`, and `database.PermsStore.LoadUserPermissions`
- retries/timeouts from the CLI log

## Monitor Sourcegraph pod load during e2e runs

Prefer running the end-to-end script as the single orchestrator. It can start
the Sourcegraph pod/Postgres monitor, collect Jaeger traces in parallel with
each child CLI command, and write all artifact paths into the result JSON:

```bash
uv run python dev/test-end-to-end.py \
  --trace \
  --monitor-sourcegraph-load \
  --sample-interval 0 \
  --external-sample-interval 0 \
  --results-json /tmp/src-auth-perms-sync-end-to-end-trace.json \
  --results-csv /tmp/src-auth-perms-sync-end-to-end-trace.csv
```

By default, monitor output is written beside `--results-json` or
`--results-csv` as `*-sourcegraph-load`, and the monitor's own stdout/stderr is
written to `*-sourcegraph-load.log`. Override the location with
`--monitor-output-dir PATH`. Tune Kubernetes targets and sample intervals with
the `--monitor-*` flags if the test namespace or pod names differ.

The lower-level helper remains available for focused profiling outside a full
e2e run:

```bash
dev/monitor-sourcegraph-load.sh \
  --namespace m \
  --output-dir /tmp/src-auth-perms-sync-sourcegraph-load-$(date -u +%Y%m%d-%H%M%S)
```

Stop the helper with Ctrl-C after the e2e run finishes, or add
`--duration-seconds N`. The script samples Kubernetes CPU/memory, frontend and
Postgres processes, cgroup CPU/memory pressure, Postgres active queries/waits/locks,
`pg_stat_statements` when enabled, and frontend logs. Outputs are timestamped
files in the selected directory. On startup, it runs `CREATE EXTENSION IF NOT
EXISTS pg_stat_statements` and `pg_stat_statements_reset()` through
`kubectl exec` against `pod/pgsql-0`, so the statement summary starts clean for
the monitored run.

In a traced sgdev end-to-end run after the matrix was trimmed to avoid
overlapping code paths, all 36 cases passed. Child command time summed to about
1,126 seconds. The JSONL trace summary file contained 3,256 GraphQL trace
lookups, but Jaeger returned only 26 summaries; most lookups returned `trace
not found`. The expensive cases were still dominated by full snapshot capture
and full apply / restore paths:

| Case | Elapsed | GraphQL requests | Slowest GraphQL request | Dominant phase |
| --- | ---: | ---: | ---: | --- |
| `restore-full-apply-cleanup` | 234s | 913 | 3.2s | `capture_explicit_grants` / restore |
| `set-full-apply` | 214s | 917 | 3.2s | `capture_explicit_grants` / apply |
| `restore-full-no-backup-cleanup` | 135s | 510 | 3.2s | `capture_explicit_grants` / restore |
| `set-full-no-backup-apply` | 129s | 129 | 1.2s | apply mutations |
| `get-sync-saml-orgs-dry-run` | 116s | 510 | 3.2s | `capture_explicit_grants` |

Fetch Jaeger traces immediately for long runs. In that same full matrix, older
trace IDs were no longer available by the time the run finished. Focused reruns
with immediate fetches gave stable Jaeger data.

For current `src-auth-perms-sync`, `UserExplicitReposBatch` requests only repo
IDs from `User.permissionsInfo.repositories(source: API)`. A focused traced
batch for one user with 19 explicit repos showed per-user fanout:

| User aliases | CLI request | Jaeger spans | `LoadUserPermissions` | `sql.conn.query` |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 398ms | 13 | 1 | 7 |
| 25 | 508ms | 157 | 25 | 127 |
| 100 | 1,185ms | 607 | 100 | 502 |

The remaining repository-name hydration is a second fanout. A traced
`RepositoryNamesByID` query for 19 repos produced 46 spans, including 19
`repos.Get` spans and 22 `sql.conn.query` spans.

An older trace shape that resolved repository objects directly inside
`permissionsInfo.repositories` showed the per-repo resolver fanout more
dramatically:

| Request shape | Root GraphQL span | Jaeger fanout |
| --- | ---: | --- |
| 25 user aliases, 19 explicit repos each | ~770 ms | 475 `repos.Get`, 603 `sql.conn.query` |
| 100 user aliases, 19 explicit repos each | ~3,769 ms | 1,900 `repos.Get`, 2,403 `sql.conn.query` |

Together these point to Sourcegraph server-side GraphQL / DB resolver fanout,
not local Python CPU. Larger batches reduce request count but increase per
request resolver and SQL work enough to create timeouts on this instance.

## Sourcegraph engineering request

`src-auth-perms-sync` needs to snapshot explicit API permissions for many
users. Today it calls `User.permissionsInfo.repositories(source: API)` with
GraphQL aliases. This is correct, but expensive at scale.

[Deep Search findings](https://sourcegraph.sourcegraph.com/deepsearch/52a24164-1eb3-4db1-a92d-e320ef1c7557)
from `github.com/sourcegraph/sourcegraph`:

- Schema: `cmd/frontend/graphqlbackend/authz.graphql` exposes
  `User.permissionsInfo.repositories(source: PermissionSource)`.
- `UserResolver.PermissionsInfo` enters
  `cmd/frontend/internal/authz/resolvers/resolver.go` and calls
  `db.Perms().LoadUserPermissions(ctx, userID)` before the repositories
  connection is resolved.
- `userPermissionsInfoResolver.Repositories` in
  `cmd/frontend/internal/authz/resolvers/permissions_info.go` uses the generic
  connection resolver, so `nodes` and `totalCount` can evaluate separately.
- Each permission node's `Repository()` resolver calls `db.Repos().Get`,
  creating an N+1 query pattern for repository hydration.
- Even when the client asks only for permission repo IDs, each aliased user
  still runs `LoadUserPermissions` and several SQL queries. Current
  `src-auth-perms-sync` then has to hydrate repository names separately through
  `node(id)`, which also resolves as one `repos.Get` per repository ID.
- `internal/database/perms_store.go` has bulk write helpers for setting repo
  permissions, but the read path uses per-user connection queries and repo
  resolver fanout.

Request a bulk read API for explicit permissions. GraphQL semantics make this
a query, not a mutation:

```graphql
type ExplicitRepositoryPermission {
  userID: ID!
  repositoryID: ID!
  repositoryName: String!
  updatedAt: DateTime!
}

extend type Query {
  explicitRepositoryPermissionsForUsers(
    userIDs: [ID!]!
    source: PermissionSource = API
  ): [ExplicitRepositoryPermission!]!
}
```

Back it with one SQL shape per user batch:

```sql
SELECT urp.user_id, urp.repo_id, repo.name, urp.updated_at
FROM user_repo_permissions urp
JOIN repo ON repo.id = urp.repo_id AND repo.deleted_at IS NULL
WHERE urp.user_id = ANY($1)
  AND urp.source = 'api'
ORDER BY urp.user_id, repo.name;
```

Important requirements:

- Return compact scalar data, not `Repository` GraphQL objects, to avoid
  per-repo resolver hydration.
- Enforce the same authorization policy as the current user permissions
  resolver.
- Support batching / pagination for large user lists.
- Add Jaeger spans around the new store method and around existing
  `ListUserPermissions` / `CountUserPermissions` so future investigations do
  not require inferring work from `sql.conn.query` spans alone.

Expected benefit: replace hundreds or thousands of per-repo resolver SQL spans
per request with one indexed `user_repo_permissions` join per user batch.

## Copy/paste request

Title: Add a bulk GraphQL read path for explicit repository permissions

Problem: `src-auth-perms-sync` must snapshot explicit API repo permissions for
many users. The only current GraphQL read path is
`User.permissionsInfo.repositories(source: API)`. Current traces show this is
per-user work even when the client asks only for repo IDs: 25 aliases produced
25 `LoadUserPermissions` spans and 127 SQL spans; 100 aliases produced 100
`LoadUserPermissions` spans and 502 SQL spans. The client must then hydrate
repository names separately; a 19-repo `RepositoryNamesByID` query produced 19
`repos.Get` spans and 22 SQL spans. Older traces that resolved repository
objects directly inside `permissionsInfo.repositories` produced 475 `repos.Get`
spans for 25 aliases and 1,900 for 100 aliases. Larger batches and higher
concurrency therefore increase server-side resolver/SQL fanout enough to cause
timeouts instead of improving throughput.

Request: add a bulk explicit-permissions read API that accepts many user IDs and
returns compact permission edges (`userID`, `repositoryID`, `repositoryName`,
`updatedAt`) for `source: API`, without resolving full `Repository` GraphQL
objects. A single indexed query over `user_repo_permissions` joined to `repo`
should be enough for each user batch.

Acceptance criteria:

- One request can fetch explicit API repo permissions for many users.
- The response includes repository ID and name without triggering per-repo
  `db.Repos().Get` resolver calls.
- The implementation preserves current authorization checks.
- The store method and resolver have Jaeger spans/metrics that make per-batch
  latency visible.
- `src-auth-perms-sync` can replace its aliased
  `User.permissionsInfo.repositories(source: API)` calls with this API.
