# TODO

## Medium priority: Lightweight incremental updates

- When a new user's account is created, or a new repo is synced from a code host,
  they sit outside the mapping until this script runs again
- Find ways to create lightweight run modes to check for new users / repos,
  and create the needed perms for them

## Medium priority: Remote trigger on demand

- Sourcegraph webhook for new user coming in v7.4.0
- Requested a webhook for new repos
- Receive the webhook event
- Parse the new user / repo name
- Run a lightweight sync for the changed user / repo

- Where does this run? Sidecar in the customer's environment? CI job?
  Sourcegraph executor?
- How do we avoid stampedes (e.g., bulk repo sync triggering thousands
  of re-runs)?

## Medium priority: Verify perms are updated when a user's SAML groups change

- If a user gets added to a new SAML group, which hits a mapping, ensure they
  get the new perms

## Low priority: Repo-centric path, when users > repos, or for cross-checking

We previously had a repo-centric capture path
(`build_snapshot_repo_centric` etc.) intended as a scale optimization
when the planned-repo set is much smaller than the user set.
Reasons we might want to bring it back later:

- **Cross-check / validation.** Querying the same explicit-grant set
  from both directions (user-centric and repo-centric) and comparing
  is a strong audit signal: any mismatch surfaces a bug in our
  capture, a server-side inconsistency, or a race with a concurrent
  mutator.
- **Targeted snapshots.** A "planned-scope" capture (only the repos
  the mapping rules touch) is faster than a full instance scan when
  the user-centric path is the long pole AND the planned set is small.
  Would need either a server-side `source` filter on the repo→users
  connection, or a follow-up user-centric `source: API` query per
  ambiguous (site-admin) user to disambiguate.
- **Adaptive capture path after SG adds `source` to repo→users.** Once
  `RepositoryPermissionsInfo.users(source: PermissionSource)` exists,
  compute the expected request count both ways before snapshotting:
  sum `userCount` across all auth providers and sum `repoCount` across
  all code hosts. Use the lower total to choose the primary explicit
  permissions polling path: user-centric
  `UserPermissionsInfo.repositories(source: API)` or repo-centric
  `RepositoryPermissionsInfo.users(source: API)`, for the purposes of sending the lower number
  of requests to the SG instance

If/when we revisit:

1. Decide whether to ship as a parallel cross-check (slower but a
   valid signal) or as an alternate primary capture path (needs the
   ambiguous-user follow-up to be correct).
2. Restore `QUERY_REPO_EXPLICIT_USERS` from git history; implement
   `list_repo_explicit_users` returning `(definitely, ambiguous)` and
   actually consume both buckets — the previous code did neither.
3. Add a CLI flag (e.g. `--cross-check-capture`) gated behind a clear
   "this doubles capture cost" warning.

## Low priority: Grouped full-set plan if memory is still too high

Phase 1 now avoids per-repo username sets for non-overlapping full-set maps.
If memory remains too high after re-measuring, implement the Phase 2 grouped
plan in [mapping-efficiency.md](./mapping-efficiency.md): combine map-entry
overlays into final groups of repos that share the same desired username tuple.

## Low priority:  Expand group-membership filters beyond SAML

`allowGroups`-style enforcement exists on more than just SAML, but only
SAML actually persists the group list. Recovery options for each:

- OIDC has no `allowGroups` field on `OpenIDConnectAuthProvider`.
  `UserClaims` stores only name/email fields; the `groups` claim is never
  parsed. Recovery needs an upstream change to persist the claim.
- GitHub OAuth has `allowOrgs`, `allowOrgsMap` (org→teams), and
  `requiredSsoOrgs`. Org/team checks happen live in `verifyUserOrgs` /
  `verifyUserTeams` and are discarded. Recovery needs an upstream change to
  persist the claim.
- GitLab OAuth has `allowGroups`, but `verifyUserGroups` calls
  `glClient.IsGroupMember` live and discards the result. Recovery needs an
  upstream change to persist the claim.
