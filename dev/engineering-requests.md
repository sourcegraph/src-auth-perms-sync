# Engineering requests

Use this when opening Sourcegraph Engineering issues from memory-efficiency
evidence. Capture steps stay in [memory-efficiency.md](./memory-efficiency.md);
this file keeps the request-ready problem statement, evidence, proposed API
shape, and copy/paste issue text.

## Requested Sourcegraph changes

1. Add a bulk GraphQL read path for explicit API repository permissions.
2. Add script-oriented API endpoints for user/auth-provider inventory,
   repository/code-host inventory, SAML group membership, explicit-permission
   snapshots, and bulk applies.
3. Add efficient REST / Connect endpoints for explicit API permission listing,
   presence checks, and bulk repo replacement.
4. Add a cheaper presence/filter path for users without explicit API repo
   permissions.
5. Add Jaeger spans / metrics around the new store methods and around current
   `ListUserPermissions` / `CountUserPermissions` paths.
6. Follow up with a bulk overwrite API for large full-set applies.

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
`--parallelism 8`, `--explicit-permissions-batch-size 25`), while a fifth ran a
small `set` command. Instance: single `pgsql-0` on an 8-core node.

Observed during the concurrent captures:

- `pgsql-0` CPU (`kubectl top`): 7,636-7,683 millicores of 8,000 (saturated).
- `frontend` / `gitserver` CPU: 124-138m / 2-3m (idle bystanders).
- `pg_stat_activity`: 29 active statements, all
  `permsStore.ListUserPermissions`, **zero wait events** — pure CPU, no lock
  contention.
- `pg_stat_statements`: `permsStore.ListUserPermissions` at 24,026 calls,
  27,635.6s total, 1,150ms mean.
- Per-client capture throughput: 23 users/sec solo → 2-4 users/sec at 4-way
  concurrency.
- Aggregate throughput: 8-16 users/sec at 4-way — **below the 23 users/sec a
  single client achieves alone** (negative scaling).
- ALB (CloudWatch): no 5xx, no rejected connections — the edge and frontend
  are not the bottleneck.
- Collateral failure: the fifth client's queries exceeded the 60s read timeout
  under this load; 5 retry attempts exhausted; its run failed with exit 1.

Implications for the engineering request:

- A single per-user `permissionsInfo.repositories(source: API)` read costs
  roughly 0.3-0.4s of Postgres CPU at this state size (1,150ms mean execution
  under contention), so one operator at modest parallelism can saturate the
  database by itself, and two concurrent operators degrade each other below
  single-operator throughput.
- Timeout/retry behavior amplifies the problem: once statements exceed the
  client read timeout, retries re-run the same expensive queries, adding load
  exactly when the database is saturated.
- A bulk read API (one query returning explicit grants for many users or for
  whole repos) would replace ~10,000 x ~1s statements per capture with a
  single scan, and would also make concurrent operators viable.

## Sourcegraph codepath findings

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

## Presence-check resolver internals (2026-06-12)

Measured on the 10k-user / 50k-repo test instance, the presence probe
`User.permissionsInfo.repositories(source: API, first: 1)` costs 225-350ms of
server work per user, and alias batching barely helps (21,004 single-user
probes averaged 351.6ms; 25-user batches averaged 5,616ms ≈ 224.7ms/user). A
single `set --users-without-explicit-perms` run probing all 10,002 users at
batch size 1 spent 4,269s of its 5,210s total in these probes.

Reading the resolver code in `github.com/sourcegraph/sourcegraph` explains why
`first: 1` does not make the probe cheap:

- `UserResolver.PermissionsInfo` (resolver.go) **unconditionally** calls
  `db.Perms().LoadUserPermissions`, which runs
  `SELECT ... FROM user_repo_permissions WHERE user_id = $1` with **no LIMIT
  and no source filter**, only to compute the parent object's `source` /
  `updatedAt` fields. The rows are discarded afterward.
- `userPermissionsInfoResolver.Repositories` (permissions_info.go) builds a
  CTE (`reposPermissionsInfoQueryFmt` in perms_store.go) that **materializes
  every repo accessible to the user** — a full `repo` ⋈
  `external_service_repos` ⋈ `external_services` join with the correlated
  authz `EXISTS` predicate and an `ORDER BY` — before the outer query applies
  `urp.source = 'API'` and the LIMIT. `first: 1` becomes `LIMIT 2` on the
  outer query only; the CTE is not short-circuited.
- Requesting `totalCount` adds a second independent execution of the same CTE
  (`CountUserPermissions`).
- `user_repo_permissions` has only two indexes:
  `(user_id, user_external_account_id, repo_id)` unique and `(repo_id)`.
  Nothing covers `source`, so even the row-level filter cannot use an index.

The cheap query Sourcegraph could run instead is a single indexed scan:

```sql
SELECT DISTINCT user_id FROM user_repo_permissions WHERE source = 'api';
```

Client-side mitigation shipped in `src-auth-perms-sync` (2026-06-12):
`set --users-without-explicit-perms` now matches maps.yaml user selectors
locally BEFORE probing, so probes scale with the rule-matched user count
instead of the instance's user count, and user hydration runs as aliased
25-user batches instead of one `UserByID` request per user. The remaining
inherent cost — ~225ms x probed user — is exactly what the
presence/filter API requested below would remove, and
`get --users-without-explicit-perms` still has to probe every active user
because its semantics are instance-wide.

## Current explicit-permissions REST API findings

[Deep Search findings](https://sourcegraph.sourcegraph.com/deepsearch/972e0964-1b41-4805-8774-65dad2ad58c6)
from `github.com/sourcegraph/sourcegraph` show that the new REST / Connect API
is useful for one-off permission CRUD, but is not efficient enough for
`src-auth-perms-sync` bulk sync workloads yet.

Current endpoints:

- `POST /api/explicitrepopermissions.v1.Service/GetExplicitRepoPermission`
- `POST /api/explicitrepopermissions.v1.Service/ListExplicitRepoPermissions`
- `POST /api/explicitrepopermissions.v1.Service/CreateExplicitRepoPermission`
- `POST /api/explicitrepopermissions.v1.Service/DeleteExplicitRepoPermission`

Current efficiency gaps:

- `CreateExplicitRepoPermission` creates one repo/user edge at a time. The
  backing `AddUserToRepo` path checks whether the edge exists, then upserts one
  row. Using it to sync one repo with hundreds or thousands of users becomes
  hundreds or thousands of REST calls and SQL operations.
- `DeleteExplicitRepoPermission` deletes one repo/user edge at a time. It is
  fine for UI-style single deletes, but not for reconciling a full repo state.
- `ListExplicitRepoPermissions(parent = users/{user})` is the best current REST
  read path. It uses `ListUserPermissions` with `SourceAPI`, but still works for
  only one user per request.
- `ListExplicitRepoPermissions(parent = repositories/{repo})` has an N+1 shape:
  after listing repo permissions, the handler calls `loadExplicitRepoPermission`
  for each returned user, and that helper loads all permissions for that user to
  check whether the requested repo has an API-sourced edge.
- There is no REST equivalent of GraphQL `setRepositoryPermissionsForUsers`, so
  REST cannot currently replace all explicit users for a repo atomically.

Implication: `src-auth-perms-sync` should keep using GraphQL for bulk overwrites
until REST has batch endpoints backed by direct `user_repo_permissions` queries.

## Proposed bulk read API

`src-auth-perms-sync` needs to snapshot explicit API permissions for many
users. Today it calls `User.permissionsInfo.repositories(source: API)` with
GraphQL aliases. This is correct, but expensive at scale.

Request a bulk read API for explicit permissions. GraphQL semantics make this a
query, not a mutation:

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

## Proposed presence/filter API

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

Expected benefit: `src-auth-perms-sync get --users-without-explicit-perms` can
either check explicit-permission presence for candidate users in one indexed
batch query, or ask Sourcegraph for the filtered user set directly instead of
probing every user through the expensive permissions connection resolver.

## API endpoints needed to make this script much more efficient

The biggest win is not only replacing individual GraphQL resolvers. The CLI
needs server-side endpoints that match its workflow: load planning inputs,
snapshot explicit grants, compute missing/present grant sets, then apply a bulk
repo replacement. These can be GraphQL fields or REST / Connect methods; the
important part is that they return scalar sync data from direct store methods
instead of full GraphQL objects with nested resolver fanout.

- `ListPermissionSyncUsers`: replaces `users { externalAccounts { accountData } }`
  pages with compact users and selected auth account data from one store path.
- `ListPermissionSyncRepositories`: replaces nested `repositories {
  externalServices }` and per-service repo lists with scalar repo inventory.
- `ListAuthProviderGroupMemberships`: replaces downloading every SAML
  `accountData` blob and parsing groups locally.
- `ExportExplicitRepoPermissionsSnapshot`: replaces per-user
  `permissionsInfo.repositories(source: API)` probes with a paginated
  `user_repo_permissions` export.
- `BatchCheckExplicitRepoPermissionPresence`: replaces `first: 1` probes for
  every candidate user/repo with batched presence booleans.
- `BatchReplaceExplicitRepoPermissions`: replaces one GraphQL overwrite per
  repo, or REST one-edge create/delete loops, with bulk store writes.

### `ListPermissionSyncUsers`

`src-auth-perms-sync` needs active users with enough auth-provider metadata to
match mapping rules and org-sync rules. Today it paginates GraphQL `users` and
requests nested `externalAccounts(first: 50)`, optionally including full SAML /
OIDC `accountData` JSON.

Request shape:

```protobuf
rpc ListPermissionSyncUsers(ListPermissionSyncUsersRequest)
  returns (ListPermissionSyncUsersResponse);

message ListPermissionSyncUsersRequest {
  google.protobuf.Timestamp created_after = 1;
  bool include_emails = 2;
  bool include_auth_accounts = 3;
  bool include_account_data = 4;
  int32 page_size = 5;
  string page_token = 6;
}

message PermissionSyncUser {
  string user = 1; // users/{id}
  string username = 2;
  bool builtin_auth = 3;
  google.protobuf.Timestamp created_at = 4;
  repeated string verified_emails = 5;
  repeated PermissionSyncAuthAccount auth_accounts = 6;
}

message PermissionSyncAuthAccount {
  string service_type = 1;
  string service_id = 2;
  string client_id = 3;
  bytes account_data_json = 4;
}

message ListPermissionSyncUsersResponse {
  repeated PermissionSyncUser users = 1;
  string next_page_token = 2;
}
```

Requirements:

- Page by stable user ID or creation timestamp, not offset, so large instances
  do not repeatedly scan earlier rows.
- Let the client omit emails and account data unless rules need them.
- Return compact account rows. Do not hydrate full user GraphQL objects.

### `ListPermissionSyncRepositories`

The CLI needs repository candidates with `id`, `name`, `createdAt`, and the set
of external service IDs. Today it either pages all repositories with nested
`externalServices(first: 50)` or calls `repositories(externalService: ...)` once
per code host connection.

Request shape:

```protobuf
rpc ListPermissionSyncRepositories(ListPermissionSyncRepositoriesRequest)
  returns (ListPermissionSyncRepositoriesResponse);

message ListPermissionSyncRepositoriesRequest {
  repeated string repository_names = 1;
  google.protobuf.Timestamp created_after = 2;
  repeated string external_services = 3; // externalServices/{id}
  bool include_explicit_permission_presence = 4;
  int32 page_size = 5;
  string page_token = 6;
}

message PermissionSyncRepository {
  string repository = 1; // repositories/{id}
  string name = 2;
  google.protobuf.Timestamp created_at = 3;
  repeated string external_services = 4;
  bool has_explicit_repo_permissions = 5;
}

message ListPermissionSyncRepositoriesResponse {
  repeated PermissionSyncRepository repositories = 1;
  string next_page_token = 2;
}
```

Expected SQL shape: one query over `repo`, `external_service_repos`, and an
optional `EXISTS` on `user_repo_permissions source = 'api'`, grouped by repo.
This directly supports `--repos`, `--repos-created-after`, and
`--repos-without-explicit-perms` without first building a full before-snapshot.

### `ListAuthProviderGroupMemberships`

The org-sync and SAML-group mapping paths need `(auth provider, group, user)`
membership data. Today the CLI downloads user external account `accountData` and
parses SAML assertion JSON locally.

Request shape:

```protobuf
rpc ListAuthProviderGroupMemberships(ListAuthProviderGroupMembershipsRequest)
  returns (ListAuthProviderGroupMembershipsResponse);

message ListAuthProviderGroupMembershipsRequest {
  repeated string auth_provider_config_ids = 1;
  repeated string groups = 2;
  string groups_attribute_name = 3;
  int32 page_size = 4;
  string page_token = 5;
}

message AuthProviderGroupMember {
  string auth_provider_config_id = 1;
  string service_type = 2;
  string service_id = 3;
  string client_id = 4;
  string group = 5;
  string user = 6; // users/{id}
  string username = 7;
}

message ListAuthProviderGroupMembershipsResponse {
  repeated AuthProviderGroupMember members = 1;
  string next_page_token = 2;
}
```

Requirements:

- Use Sourcegraph's configured SAML/OIDC group attribute semantics so the CLI
  does not need to duplicate provider-specific parsing.
- Support filtering to the groups named by mapping rules, while still allowing
  an unfiltered discovery mode for `get`.
- Keep secret provider config values out of the response.

### `ExportExplicitRepoPermissionsSnapshot`

For `get`, `set --full`, and `restore`, the CLI needs the current explicit API
permission graph. A snapshot export endpoint would be more useful than many
single-user list calls.

Request shape:

```protobuf
rpc ExportExplicitRepoPermissionsSnapshot(
  ExportExplicitRepoPermissionsSnapshotRequest)
  returns (ExportExplicitRepoPermissionsSnapshotResponse);

message ExportExplicitRepoPermissionsSnapshotRequest {
  repeated string users = 1;        // optional users/{id} filter
  repeated string repositories = 2; // optional repositories/{id} filter
  int32 page_size = 3;
  string page_token = 4;
}

message ExplicitRepoPermissionSnapshotEdge {
  string user = 1;
  string username = 2;
  string repository = 3;
  string repository_name = 4;
  google.protobuf.Timestamp updated_at = 5;
}

message ExportExplicitRepoPermissionsSnapshotResponse {
  repeated ExplicitRepoPermissionSnapshotEdge explicit_repo_permissions = 1;
  repeated string pending_bind_ids = 2;
  string next_page_token = 3;
}
```

Expected benefit: replace tens of thousands of per-user permission resolver
queries with a paginated scan of `user_repo_permissions WHERE source = 'api'`,
joined to `users` and `repo` for names.

### `GetPermissionSyncDiscovery`

The `get` command writes `code-hosts.yaml` and `auth-providers.yaml`, then uses
the same discovery data for mapping. A single discovery endpoint would simplify
this and avoid multiple round trips.

Request shape:

```protobuf
rpc GetPermissionSyncDiscovery(GetPermissionSyncDiscoveryRequest)
  returns (GetPermissionSyncDiscoveryResponse);

message GetPermissionSyncDiscoveryRequest {
  bool include_external_service_config = 1;
  bool include_auth_provider_config = 2;
}

message GetPermissionSyncDiscoveryResponse {
  repeated PermissionSyncExternalService external_services = 1;
  repeated PermissionSyncAuthProvider auth_providers = 2;
  string permissions_user_mapping_bind_id = 3;
  bool permissions_user_mapping_enabled = 4;
}
```

Requirements:

- Include the current non-secret fields the CLI writes to generated YAML.
- Preserve the existing site-admin / RBAC checks.
- Return the site-config invariants the CLI validates before mutating explicit
  permissions.

## Proposed REST / Connect endpoints

Add REST / Connect endpoints shaped for automation clients, not just UI-style
single edge CRUD. The generated OpenAPI routes can follow the existing
`/api/explicitrepopermissions.v1.Service/<Method>` style.

### Batch list explicit repo permissions

Request:

```protobuf
rpc BatchListExplicitRepoPermissions(BatchListExplicitRepoPermissionsRequest)
  returns (BatchListExplicitRepoPermissionsResponse);

message BatchListExplicitRepoPermissionsRequest {
  // Exactly one of users or repositories must be non-empty per request.
  repeated string users = 1;        // users/{id}
  repeated string repositories = 2; // repositories/{id}
  int32 page_size = 3;
  string page_token = 4;
}

message ExplicitRepoPermissionEdge {
  string user = 1;            // users/{id}
  string username = 2;
  string repository = 3;      // repositories/{id}
  string repository_name = 4;
  google.protobuf.Timestamp updated_at = 5;
}

message BatchListExplicitRepoPermissionsResponse {
  repeated ExplicitRepoPermissionEdge explicit_repo_permissions = 1;
  string next_page_token = 2;
}
```

Back user-scoped requests with one indexed SQL shape per page:

```sql
SELECT urp.user_id, users.username, urp.repo_id, repo.name, urp.updated_at
FROM user_repo_permissions urp
JOIN users ON users.id = urp.user_id AND users.deleted_at IS NULL
JOIN repo ON repo.id = urp.repo_id AND repo.deleted_at IS NULL
WHERE urp.source = 'api'
  AND urp.user_id = ANY($1)
ORDER BY urp.user_id, repo.name, repo.id;
```

Back repo-scoped requests with the symmetric shape:

```sql
SELECT urp.user_id, users.username, urp.repo_id, repo.name, urp.updated_at
FROM user_repo_permissions urp
JOIN users ON users.id = urp.user_id AND users.deleted_at IS NULL
JOIN repo ON repo.id = urp.repo_id AND repo.deleted_at IS NULL
WHERE urp.source = 'api'
  AND urp.repo_id = ANY($1)
ORDER BY urp.repo_id, users.username, users.id;
```

Requirements:

- Do not call `ListRepoPermissions` and then `loadExplicitRepoPermission` per
  user. The endpoint must not have the current repo-parent N+1 pattern.
- Return scalar user/repo identifiers and names. Do not hydrate full GraphQL
  `User` or `Repository` objects.
- Support keyset pagination over `(user_id, repo_id)` or `(repo_id, user_id)`.
- Preserve the current permission checks for reading explicit repo permissions.

### Batch check explicit repo permission presence

Request:

```protobuf
rpc BatchCheckExplicitRepoPermissionPresence(
  BatchCheckExplicitRepoPermissionPresenceRequest)
  returns (BatchCheckExplicitRepoPermissionPresenceResponse);

message BatchCheckExplicitRepoPermissionPresenceRequest {
  repeated string users = 1; // users/{id}
}

message ExplicitRepoPermissionPresence {
  string user = 1; // users/{id}
  bool has_explicit_repo_permissions = 2;
}

message BatchCheckExplicitRepoPermissionPresenceResponse {
  repeated ExplicitRepoPermissionPresence users = 1;
}
```

Expected SQL shape:

```sql
SELECT users.id,
       EXISTS (
         SELECT 1
         FROM user_repo_permissions urp
         WHERE urp.user_id = users.id
           AND urp.source = 'api'
       ) AS has_explicit_repo_permissions
FROM users
WHERE users.id = ANY($1)
  AND users.deleted_at IS NULL;
```

Expected benefit: `get --users-without-explicit-perms` can stop probing every
candidate user through `User.permissionsInfo.repositories(source: API, first:
1)` or one-user REST list calls.

### Batch replace explicit repo permissions

Request:

```protobuf
rpc BatchReplaceExplicitRepoPermissions(
  BatchReplaceExplicitRepoPermissionsRequest)
  returns (BatchReplaceExplicitRepoPermissionsResponse);

message ExplicitRepoPermissionReplacement {
  string repository = 1;      // repositories/{id}
  repeated string users = 2;  // users/{id}; optional @username support is OK
}

message BatchReplaceExplicitRepoPermissionsRequest {
  repeated ExplicitRepoPermissionReplacement replacements = 1;
}

message ExplicitRepoPermissionReplacementResult {
  string repository = 1;
  int32 added = 2;
  int32 removed = 3;
  int32 found = 4;
}

message BatchReplaceExplicitRepoPermissionsResponse {
  repeated ExplicitRepoPermissionReplacementResult results = 1;
}
```

Requirements:

- Replace all API-sourced explicit users for each repo, matching
  `setRepositoryPermissionsForUsers` semantics.
- Avoid per-edge `CreateExplicitRepoPermission` / `DeleteExplicitRepoPermission`
  loops.
- Resolve users in batches. Numeric `users/{id}` support is enough for
  `src-auth-perms-sync`, because the CLI already enumerates Sourcegraph users;
  optional `users/@username` support is useful for hand-authored requests.
- Make replacement atomic per repository. A later improvement can make a whole
  multi-repo request atomic if that is practical.
- Reuse or generalize the existing bulk store write path instead of adding a new
  row-at-a-time implementation.

## Bulk overwrite follow-up

The stress profile also needs attention on the write path. A purpose-built bulk
overwrite API that accepts many repo/user edges at once, streams or stages the
input server-side, and avoids repeated per-repo permission reconciliation would
make worst-case full syncs much safer.

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

## Copy/paste REST request

Title: Add efficient REST endpoints for explicit repository permissions

Problem: The current explicit-permissions REST / Connect API only supports
single-edge CRUD plus one-parent listing. That shape is not efficient for
automation clients such as `src-auth-perms-sync`. To sync one repo with many
users, the client would need one `CreateExplicitRepoPermission` or
`DeleteExplicitRepoPermission` call per edge instead of one bulk replacement.
The repo-parent list path also has an N+1 pattern: after listing repo
permissions, it calls `loadExplicitRepoPermission` for each returned user, and
that helper loads all permissions for that user before checking for the API
edge.

Request: add automation-friendly REST / Connect endpoints:

- `BatchListExplicitRepoPermissions`: accept many `users/{id}` or many
  `repositories/{id}` and return scalar edges (`user`, `username`,
  `repository`, `repository_name`, `updated_at`) directly from
  `user_repo_permissions` joined to `users` and `repo`, with keyset
  pagination.
- `BatchCheckExplicitRepoPermissionPresence`: accept many `users/{id}` and
  return whether each user has any API-sourced explicit repo permission.
- `BatchReplaceExplicitRepoPermissions`: accept many repo replacements and
  atomically replace the full API-sourced explicit user set for each repo,
  matching `setRepositoryPermissionsForUsers` semantics without per-edge
  create/delete loops.

Acceptance criteria:

- Listing by repo does not call `loadExplicitRepoPermission` once per returned
  user.
- Listing by user or repo is one indexed SQL page over `user_repo_permissions`,
  joined only to the scalar user/repo tables needed for IDs and names.
- Presence checks for many users run as one batch query.
- Bulk replacement resolves users in batches and uses a bulk write path; it does
  not dispatch one SQL-backed create/delete operation per edge.
- The new store methods and handlers have Jaeger spans / metrics so operators
  can see page size, edge count, and latency.
