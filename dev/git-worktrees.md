# Git worktrees

Git worktrees let one repository have multiple checkout directories that share
the same object database. Each worktree can use a different branch, index, and
working tree.

Use them when the human and one or more agents need to work in parallel without
mixing unrelated uncommitted changes in one checkout.

## Why use worktrees for agent work

Benefits:

- Each task gets a clean branch and clean index.
- Agents cannot accidentally edit or stage the human's current local changes.
- VS Code review is clearer because Source Control shows one task's changes.
- Branches can be merged or rebased one at a time.
- Git prevents the same branch from being checked out in two worktrees.

Worktrees do not remove real conflicts. If two branches edit the same lines or
the same behavior, the conflict still has to be resolved when those branches are
merged or rebased. Worktrees make that conflict explicit instead of silently
mixing edits in one dirty working tree.

## Create a task worktree

From the main checkout:

```sh
git worktree add ../src-auth-perms-sync-backup-diffs \
  -b amp/backup-diff-files \
  HEAD
```

Then work from the new directory:

```sh
cd ../src-auth-perms-sync-backup-diffs
```

If the task should start from a remote branch instead of the current commit,
replace `HEAD` with that branch, for example `origin/split-main-into-modules`.

## Review in VS Code

Open the task worktree directly:

```sh
code ../src-auth-perms-sync-backup-diffs
```

VS Code treats it like a normal repo checkout. The Source Control view shows the
changes for that worktree only, without unrelated edits from other worktrees.

## Merge conflict expectations

Worktrees reduce accidental interference, not semantic overlap.

Good parallelism:

- One agent updates SAML org sync.
- Another agent updates packaging docs.
- The human edits a config example.

Risky parallelism:

- Two agents refactor `src/src_auth_perms_sync/cli.py` at the same time.
- One branch renames functions while another branch edits their call sites.
- Two branches change the same GraphQL mutation flow.

For long-running tasks, rebase the task branch regularly:

```sh
git fetch origin
git rebase origin/split-main-into-modules
```

Resolve any conflicts in the task worktree, run validation, then continue.

## Clean up a finished worktree

After the branch is merged or no longer needed:

```sh
git worktree remove ../src-auth-perms-sync-backup-diffs
git branch -d amp/backup-diff-files
```

Use `git branch -D` only for an unmerged branch that is intentionally discarded.
