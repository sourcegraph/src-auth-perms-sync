# Large-scale test plan for `src-auth-perms-sync`

## Known constraints

1. **`src-auth-perms-sync` snapshot/diff/expected-set state is fully in-memory.**
   Snapshot cost scales with the **number of explicit grants**, not with the
   number of synced repos. A `1M repos × 10K users = 10⁹ grants` literal
   one-shot run will OOM on `build_snapshot` long before it stresses
   anything server-side. Split scaling tests into three axes:
   **repo count**, **users-per-mutation payload**, and **total grants**.

2. **`setRepositoryPermissionsForUsers` is one short transaction with an
   in-transaction `DELETE` of stale rows.** Concurrent mutations on
   *different* repos do not block each other on rows but do contend on
   B-tree pages of `user_repo_permissions_perms_unique_idx` and
   `user_repo_permissions_repo_id_user_id_idx`. Practical ceiling on a
   reasonable Postgres: **~200–500 mutations/s** at `--parallelism` 100–200.
   Throughput plateaus or degrades above ~256 workers.

---

## Scaling risks

1. **Snapshot OOM** in scenarios d / g. The script holds
   `repo_users`, `expected_users`, `user_repos`, and `Snapshot.repos`
   simultaneously in RAM. Mitigation: bound scenario d at the smallest
   cliff that reproduces the OOM; do not insist on full-corpus backup.
2. **Inode exhaustion** at corpus generation. Mitigation: `mkfs.ext4 -i 4096`.
3. **`/v1/list-repos` timeout** if a single shard accidentally gets
   >50K repos. Mitigation: hard-cap shard size at 10K and assert
   directory count after generation.
4. **`repoConcurrentExternalServiceSyncers=3` default** silently
   serializing 100-shard sync to ~33× the expected wall clock.
   Mitigation: assert site config value before triggering sync.
5. **GraphQL request body size** in scenario g. A 10K-user payload at
   ~80 bytes/user is ~800KB, well under the typical 1MB body limit but
   close. Watch for HTTP 413.
6. **FD exhaustion** at `--parallelism 256`. Mitigation:
   `ulimit -n 8192` before each run; monitor `num_fds` in
   `resource_sample`.
7. **`externalAccounts(first: 50)` truncation** if any user gets
   over-seeded. Mitigation: SQL assertion
   `SELECT user_id, COUNT(*) FROM user_external_accounts GROUP BY 1 HAVING COUNT(*) > 50;`
   must return zero rows.

---

## Measurement plan

The script already emits the right primitives in
`src-auth-perms-sync-runs/<endpoint>/runs/<run-id>/log.json`.
Use `jq` and Python for post-run analysis; do not modify the script.

### Per-run assertions (correctness gates, fail the test on violation)

```bash
F=src-auth-perms-sync-runs/<endpoint>/runs/<RUN_ID>/log.json
# Every event() emits paired phase=="start"/"end" records; aggregations
# below filter on phase=="end" so they only see completed operations
# (start records have no duration_ms / status / mutation counters).
jq -s '.[-1]' $F | jq '.event == "run" and .phase == "end" and .exit_code == 0'
jq 'select(.event=="apply_payloads" and .phase=="end") | .failed' $F | grep -v '^0$' && exit 1
jq 'select(.event=="cmd_set" and .phase=="end") | .mutations_failed' $F | grep -v '^0$' && exit 1
# For backup runs, restore residual diff must be empty
```

### Per-run KPIs (extract and store; plot across the sweep)

For each event of interest (`set_repo_perms`, `graphql_request` filtered
by `query_name == "SetRepoPerms"`, `paginate_page`, `resource_sample`):

- p50 / p95 / p99 / max `duration_ms`
- count, retry count (`retry_wait` events)
- `request_bytes_total`, `response_bytes_total`
- `peak_rss_mb`, `max_num_fds`, `max_num_threads`, `max_process_cpu_percent`
- mutation throughput =
  `apply_payloads.succeeded / (apply_payloads.duration_ms / 1000)`

### Pagination cliff plot

```bash
jq -r 'select(.event=="paginate_page" and .phase=="end") |
  [.query_name, .page_index, .duration_ms] | @tsv' $F \
  > paginate.tsv
# Plot duration_ms vs page_index, faceted by query_name.
# Expect:
#   ListUsers:               ~constant (~10 pages of 1000 users)
#   ReposByExternalService:  ~constant per ES (10 pages × 100 ES)
#   UserExplicitRepos:       grows linearly with explicit repo count
```

### Parallelism sweep

```bash
for P in 1 16 64 128 256; do
  ulimit -n 8192
  uv run src-auth-perms-sync --set full-00.yaml --apply --parallelism $P --no-backup
  cp src-auth-perms-sync-runs/<endpoint>/runs/*/log.json results/sweep-p$P.jsonl
done
```

Plot mutation throughput vs P. Expect the throughput curve to rise to
~P=64 then plateau or regress as Postgres lock contention dominates.
Watch retry rate (`retry_wait` count) — if it climbs steeply past P=128
that's the server saying "back off."

### Snapshot scaling sweep (scenario d)

```text
100K grants  → expect peak_rss ~ ?, snapshot wall ~ ?
500K  → ?
1M    → ?
2M    → ? (likely first cliff)
5M    → goal: confirm OOM threshold
```

These numbers don't have published baselines yet; this run *creates*
them. The deliverable is "we now know `--set --apply` with `--parallelism 16`
hits N MB RSS and W seconds of snapshot wall-clock at G grants."

### Memory-per-grant model

Generate exact users × repos maps and, when ready, run them through the CLI:

```bash
uv run python dev/run-memory-model-sweep.py

uv run python dev/run-memory-model-sweep.py \
  --run \
  --parallelism 1
```

The runner writes generated maps and `results.json` under
`src-auth-perms-sync-runs/<endpoint>/memory-model-sweep/<timestamp>/`.
It uses an inventory-aware `--cases auto` sweep and dry-run mode by default.
On an instance with 1K+ visible repos, `auto` includes repo-axis points up to
1K repos and mixed cases up to 100K planned grants. Use explicit cases for
larger stress points, and use `--mode apply-no-backup --allow-apply` only on a
scratch instance:

```bash
uv run python dev/run-memory-model-sweep.py \
  --cases '1x1,10000x1,1x1000,100x1000,1000x1000,10000x1000' \
  --run \
  --parallelism 1
```

Fit memory from repeated e2e JSON results instead of dividing one run's
`peak_rss_mb` by one run's grants:

```bash
uv run python dev/analyze-memory.py results/*.json \
  --command set_full \
  --case-regex 'set-full' \
  --features users,repos,grants \
  --estimate-users 10000 \
  --estimate-repos 100
```

The analyzer fits:

```text
peak RSS MiB = intercept + users*b1 + repos*b2 + grants*b3
```

Use one command mode per fit (`set_full` with backup, `set_full --no-backup`,
`restore`, etc.). Mixing modes smears fixed snapshot / apply costs into the
per-grant coefficient.

On the sgdev test instance with 10,001 users and 1,023 visible repos, a
dry-run `10000x1000` case planned 10M grants. Before the lazy-union planner,
it measured about 651 MiB peak RSS; after Phase 1 in
[mapping-efficiency.md](./mapping-efficiency.md), the same case measured about
68 MiB. Re-measure after meaningful mapping or snapshot changes; these numbers
describe dry-run planning memory, not apply mutation throughput.

The e2e `workload` object now uses event-aware names. In older result JSON,
`total_users: 40004` came from `apply_username_overwrites` and meant "username
entries in mutation payloads" (`4 mutated repos × 10001 users`), not total
Sourcegraph users. Likewise `repo_count: 575` came from a batch fetch and meant
"grant rows fetched for 25 users" (`25 × 23`), not distinct repos. New results
expose those as `apply_payload_grant_count` and
`batch_fetched_grant_count_max`, plus canonical `memory_model_user_count`,
`memory_model_repo_count`, and `memory_model_grant_count` fields for modeling.

---

## Failure injection (scenario e)

### Kill a shard mid-sync

1. Start fresh ES creation in the SG admin UI / GraphQL.
2. After ~30s of sync, `docker kill sg-serve-042`.
3. Sync wait probe should observe `lastSyncError != null` and stay
   below `repoCount == 10000` for that shard.
4. **Assert: `--apply` is not started yet** (the wait probe blocks).
5. `docker start sg-serve-042`. Re-probe. Sync resumes. Proceed.

### Kill Sourcegraph mid-apply

1. Start `--set full-00.yaml --apply --parallelism 64 --no-backup`.
2. After ~10–20% of `set_repo_perms` events appear in the JSONL,
   `kubectl rollout restart deployment/frontend` (or equivalent).
3. The script will record retries, then GraphQL errors, and exit non-zero.
4. **Assert: `cmd_set.mutations_failed > 0` and `set_repo_perms.error_type`
   includes `GraphQLError`.**
5. Re-run the same command. Because `setRepositoryPermissionsForUsers` is
   an idempotent overwrite, the second run should converge to
   `mutations_failed == 0` and post-apply validation should match the
   expected per-repo user sets.

### Concurrent race (scenario f)

1. Run `maps-A.yaml` and `maps-B.yaml` (overlapping ES IDs, different
   buckets) in two terminals with `--apply` simultaneously.
2. **Expected**: last-writer-wins per repo; the `validate_post_apply`
   step in at least one of the two runs logs a per-repo expected-vs-actual
   mismatch warning (drift detected). Both runs exit 0; the warning is
   the signal.

---

## Cleanup and iteration

### Per-run reset (fast, ~seconds)

```sql
DELETE FROM user_repo_permissions WHERE source = 'api';
DELETE FROM user_pending_permissions;
```

### Topology reset (after a full scenario, ~minutes)

- Delete all 100 shard external services via GraphQL (this cascades to
  `external_service_repos`; `repo` rows are GC'd by the syncer).
- Recreate when the next scenario starts.

### Best inner-loop primitive: DB snapshot

After steps 1–4 of §3 are complete (users seeded, providers
configured, ES synced, `user_repo_permissions` empty), take a `pg_dump`
or take a logical Postgres snapshot. Restore between runs in seconds.
Keep the on-disk repo corpus immutable across runs — it is the slow
part to rebuild.

### What to NEVER do between runs

- Do not regenerate the 1M repo corpus.
- Do not re-create the 100 external services unless the shard topology
  changes.
- Do not restart `src serve-git` containers between runs (they're
  stateless; killing them only forces a re-walk on next sync).

---

## Deliverables

1. Generator scripts under `scripts/loadtest/` (corpus + docker compose
   for 100 shards + SG site-config snippet + user/account seeding SQL).
2. 10 generated `full-NN.yaml` mapping configs + the smoke / medium /
   giant-payload / failure / race configs.
3. A `runner.sh` that drives scenarios a → g in order, gates on the
   per-run assertions in §5, and copies
   `src-auth-perms-sync-runs/<endpoint>/runs/<run-id>/log.json` plus
   same-directory snapshots into a timestamped
   `results/<scenario>/` dir.
4. `analyze.py` that consumes a `results/<scenario>/` dir and emits a
   markdown report: KPIs, percentile tables, paginate-cost plot,
   parallelism sweep curve, snapshot-cliff curve.
5. This document, updated with measured numbers once scenarios c, c′,
   and d have actually run (the snapshot cliffs especially are unknown
   until measured).
