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

### Original

- Repo-centric plan, but every repo gets a full copy of the list of users,
  so the memory storage size is truly users x repos
- If your list of users is 1,000 users, and 10 MB RAM, and you have 1,000 repos,
  then this is 1,000,000 repo+user pairs, which is 1,000 x 10 MB RAM = 10 GB RAM
- This is a "full square"

repo-1 -> (alice, bob, carol)
repo-2 -> (alice, bob, carol)
repo-3 -> (alice, bob, dan)
repo-4 -> (alice, bob, dan)

### Current: Groups of users

- We anticipate that many users will be grouped up into a small number of sets,
  and that most repos' perms will be one of the sets
- This example cuts in ~half the amount memory consumed by lists of users as the Current example

user-group-a = (alice, bob, carol)
user-group-b = (alice, bob, dan)

repo-1 -> user-group-a
repo-2 -> user-group-a
repo-3 -> user-group-b
repo-4 -> user-group-b

### Phase 2: Groups of users x Groups of repos

- Realistically, we anticipate that many repos will also be grouped up into a small number of sets

user-group-a = (alice, bob, carol)
user-group-b = (alice, bob, dan)

repo-group-1 = (repo-1, repo-2)
repo-group-2 = (repo-3, repo-4)

user-group-a -> repo-group-1
user-group-b -> repo-group-2

## Current semantics

Each `maps:` entry is naturally a grouped rule:

```text
selected users x selected repos
```

The maps schema keeps this restrictive: `users:` and `repos:` are selector
maps, top-level selectors inside each map are ANDed together, and values inside
one selector list are ORed together. To OR across selectors, write more
top-level `maps:` entries.

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

That is expensive for rectangular maps such as `10000 users x 1000 repos`:
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
