# Mapping efficiency

## Rectangular maps example

Input maps

```yaml
maps:
  - name: engineers get generated repos
    users:
      usernames:
        - alice
        - bob
        - carol
    repos:
      names:
        - repo-1
        - repo-2
        - repo-3
```

Current: Repo-centric plan

repo-1 -> (alice, bob, carol)
repo-2 -> (alice, bob, carol)
repo-3 -> (alice, bob, carol)

Grouped plan

(alice, bob, carol) -> (repo-1, repo-2, repo-3)

## Current semantics

Each `maps:` entry is naturally a grouped rule:

```text
selected users × selected repos
```

The full-set command must combine all entries before mutating Sourcegraph,
because `setRepositoryPermissionsForUsers` overwrites a repo's whole explicit
permission list. The required final state is:

```text
desired_users(repo) = union(users_i for each map_i where repo is in repos_i)
```

Only after this union is known can the command safely apply per-repo overwrite
mutations.

## Phase 1: lazy per-repo union sets

The old full-set planner immediately expanded every map entry into:

```text
repo_id -> set(username)
```

That is expensive for rectangular maps such as `10000 users × 1000 repos`:
the username strings are shared, but each repo owns a large Python set with one
hash-table entry per planned grant.

Phase 1 keeps the existing downstream plan shape:

```text
repo_id -> tuple(username)
```

but builds it more carefully:

1. For a non-overlapping map entry, create one sorted username tuple and reuse
   that same tuple for every matched repo.
2. If a later map entry touches a repo that already has users, promote only
   that repo to a temporary set and union the usernames.
3. Convert only promoted repos back to sorted tuples after all map entries are
   processed.

This preserves the hard invariant while avoiding the large per-repo sets in
the common non-overlapping rectangular case.

Measured on the sgdev test instance, the dry-run `10000x1000` case planned 10M
grants. Before Phase 1 it peaked at about 651 MiB RSS; after Phase 1 it peaked
at about 68 MiB RSS.

## Phase 2: final grouped plan, if needed

If Phase 1 is not enough, store the combined final plan as groups of repos that
share the same final user set:

```text
tuple(username) -> tuple(repo_id)
```

This is not just one group per `maps:` entry. Map entries are input overlays;
final groups are the compressed result after every map entry has been unioned
onto the repo space.

Example:

```text
map A: alice,bob  -> repo-1,repo-2
map B: bob,chris  -> repo-2,repo-3

final:
alice,bob        -> repo-1
alice,bob,chris  -> repo-2
bob,chris        -> repo-3
```

One practical data model would be:

```python
@dataclass(frozen=True)
class RepositoryPermissionGroup:
    usernames: tuple[str, ...]
    repository_ids: tuple[str, ...]


@dataclass(frozen=True)
class FullSetPlan:
    groups: tuple[RepositoryPermissionGroup, ...]
    repo_names: dict[str, str]
    repo_to_group_index: dict[str, int]

    def usernames_for_repo(self, repo_id: str) -> tuple[str, ...]:
        return self.groups[self.repo_to_group_index[repo_id]].usernames
```

Apply still happens per repo:

```text
for group in groups:
    for repo_id in group.repository_ids:
        setRepositoryPermissionsForUsers(repo_id, group.usernames)
```

Phase 2 touches more code than Phase 1: projected snapshots, diffs,
short-circuit filtering, apply iteration, and validation all currently expect
direct `repo_id -> usernames` lookups. Do it only if Phase 1 measurements still
show unacceptable memory use.
