# Memory efficiency testing

Use this when full snapshot capture or full-set apply is slow. The goal is to
correlate `src-auth-perms-sync` structured logs with Sourcegraph Jaeger spans
and pod/Postgres load, then use the evidence to ask Sourcegraph engineering for
bulk explicit-permissions APIs.

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

## Current trace findings

Current `src-auth-perms-sync` snapshots explicit API grants by calling
`User.permissionsInfo.repositories(source: API)` through aliased
`UserExplicitReposBatch` queries. It requests only permission repo IDs, then
hydrates names separately with `RepositoryNamesByID`.

A focused traced batch for one user with 19 explicit repos showed per-user
fanout even when only IDs were requested:

| User aliases | CLI request | Jaeger spans | `LoadUserPermissions` | `sql.conn.query` |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 398ms | 13 | 1 | 7 |
| 25 | 508ms | 157 | 25 | 127 |
| 100 | 1,185ms | 607 | 100 | 502 |

The second hydration query also fans out. A traced `RepositoryNamesByID` query
for 19 repos produced 46 spans, including 19 `repos.Get` spans and 22
`sql.conn.query` spans.

An older trace shape that resolved repository objects directly inside
`permissionsInfo.repositories` showed the per-repo resolver fanout more
dramatically:

| Request shape | Root GraphQL span | Jaeger fanout |
| --- | ---: | --- |
| 25 user aliases, 19 explicit repos each | ~770ms | 475 `repos.Get`, 603 `sql.conn.query` |
| 100 user aliases, 19 explicit repos each | ~3,769ms | 1,900 `repos.Get`, 2,403 `sql.conn.query` |

Together these point to Sourcegraph server-side GraphQL / DB resolver fanout,
not local Python CPU. Larger batches reduce request count but can increase
per-request resolver and SQL work enough to cause timeouts on the test
instance.

One live-instance behavior is expected: if Sourcegraph returns a GraphQL
application error showing that a repo/user disappeared between planning and the
mutation, `src-auth-perms-sync` logs a skipped mutation and continues. The next
scheduled run will re-plan against the then-current users/repos. Other GraphQL
application errors still fail normally.

## Stress-run evidence

A prior hard stress map used about 10,001 users and about 1,000 repos, planning
roughly 10 million explicit grants. That run showed Sourcegraph-side read and
write costs were the bottleneck. `pg_stat_statements` attributed most database
time to explicit-permissions helpers:

| Sourcegraph operation | Calls | Total time | Mean time |
| --- | ---: | ---: | ---: |
| `permsStore.ListUserPermissions` | 19,974 | 30,862.6s | 1,545ms |
| `permsStore.upsertUserRepoPermissions-range1` | 472 | 1,178.8s | 2,497ms |

Compared with focused traces at normal scale, `ListUserPermissions` became much
slower under the large explicit-perms state. This reinforces that the CLI needs
better Sourcegraph bulk read and write APIs for very large explicit permission
sets.

## Concurrent-operator evidence (2026-06-10)

Four `src-auth-perms-sync` processes ran full explicit-permissions captures
concurrently against the 10k-user / 50k-repo test instance (each at
`--parallelism 8`, `--explicit-permissions-batch-size 25`), while a fifth ran
a small `set` command. Instance: single `pgsql-0` on an 8-core node.

Observed during the concurrent captures:

- `pgsql-0` CPU (`kubectl top`): 7,636–7,683 millicores of 8,000 (saturated).
- `frontend` / `gitserver` CPU: 124–138m / 2–3m (idle bystanders).
- `pg_stat_activity`: 29 active statements, all
  `permsStore.ListUserPermissions`, **zero wait events** — pure CPU, no lock
  contention.
- `pg_stat_statements`: `permsStore.ListUserPermissions` at 24,026 calls,
  27,635.6s total, 1,150ms mean.
- Per-client capture throughput: 23 users/sec solo → 2–4 users/sec at 4-way
  concurrency.
- Aggregate throughput: 8–16 users/sec at 4-way — **below the 23 users/sec a
  single client achieves alone** (negative scaling).
- ALB (CloudWatch): no 5xx, no rejected connections — the edge and frontend
  are not the bottleneck.
- Collateral failure: the fifth client's queries exceeded the 60s read
  timeout under this load; 5 retry attempts exhausted; its run failed with
  exit 1.

Implications for the engineering request:

- A single per-user `permissionsInfo.repositories(source: API)` read costs
  roughly 0.3–0.4s of Postgres CPU at this state size (1,150ms mean execution
  under contention), so one operator at modest parallelism can saturate the
  database by itself, and two concurrent operators degrade each other below
  single-operator throughput.
- Timeout/retry behavior amplifies the problem: once statements exceed the
  client read timeout, retries re-run the same expensive queries, adding load
  exactly when the database is saturated.
- A bulk read API (one query returning explicit grants for many users or for
  whole repos) would replace ~10,000 × ~1s statements per capture with a
  single scan, and would also make concurrent operators viable.

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
  `src-auth-perms-sync` then hydrates repository names separately through
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

The `get --users-without-explicit-perms` path also needs a cheaper presence
check. Today it has to ask
`User.permissionsInfo.repositories(source: API, first: 1)` for every candidate
user, in aliased batches. Recent test runs show the client can parallelize
those batches, but the Sourcegraph frontend / load balancer can still return
502/503s under that resolver load. Add one or both direct APIs:

```graphql
type ExplicitRepositoryPermissionPresence {
  userID: ID!
  hasExplicitRepositoryPermissions: Boolean!
}

extend type Query {
  explicitRepositoryPermissionPresenceForUsers(
    userIDs: [ID!]!
    source: PermissionSource = API
  ): [ExplicitRepositoryPermissionPresence!]!

  usersWithoutExplicitRepositoryPermissions(
    createdAt: DateTimeFilter
    source: PermissionSource = API
    first: Int
    after: String
  ): UserConnection!
}
```

Expected benefit: `src-auth-perms-sync get --users-without-explicit-perms`
can either check explicit-permission presence for candidate users in one indexed
batch query, or ask Sourcegraph for the filtered user set directly instead of
probing every user through the expensive permissions connection resolver.

The stress profile also needs attention on the write path. A purpose-built
bulk overwrite API that accepts many repo/user edges at once, streams or stages
the input server-side, and avoids repeated per-repo permission reconciliation
would make worst-case full syncs much safer.

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
should be enough for each user batch. Also add a cheaper presence/filter path
for `get --users-without-explicit-perms`: either `userID -> has explicit API
repo permissions` for many users, or a direct query for users without explicit
API repo permissions, optionally filtered by `createdAt`.

Acceptance criteria:

- One request can fetch explicit API repo permissions for many users.
- The response includes repository ID and name without triggering per-repo
  `db.Repos().Get` resolver calls.
- The implementation preserves current authorization checks.
- The store method and resolver have Jaeger spans/metrics that make per-batch
  latency visible.
- `src-auth-perms-sync` can replace its aliased
  `User.permissionsInfo.repositories(source: API)` calls with this API.
- `src-auth-perms-sync get --users-without-explicit-perms` can stop probing
  every candidate user through `User.permissionsInfo.repositories(source: API,
  first: 1)`.
- Follow-up: evaluate a bulk overwrite API for large full-set applies. The
  stress run planned roughly 10 million grants and observed
  `permsStore.upsertUserRepoPermissions-range1` averaging about 2.5s per call.
