from __future__ import annotations

import unittest

import src_py_lib as src

from src_auth_perms_sync.permissions import restore as permission_restore
from src_auth_perms_sync.permissions import snapshot as permission_snapshot
from src_auth_perms_sync.permissions import types as permission_types


class RestoreTests(unittest.TestCase):
    def test_plan_full_restore_skips_repos_that_already_match(self) -> None:
        matching_repo_id = src.encode_repository_id(1)
        changed_repo_id = src.encode_repository_id(2)
        extra_repo_id = src.encode_repository_id(3)
        target_snapshot = self.make_snapshot(
            {
                matching_repo_id: self.make_repo_snapshot(
                    "github.com/sourcegraph/matching",
                    ["alice", "bob"],
                ),
                changed_repo_id: self.make_repo_snapshot(
                    "github.com/sourcegraph/changed",
                    ["alice"],
                ),
            }
        )
        current_snapshot = self.make_snapshot(
            {
                matching_repo_id: self.make_repo_snapshot(
                    "github.com/sourcegraph/matching",
                    ["bob", "alice"],
                ),
                changed_repo_id: self.make_repo_snapshot(
                    "github.com/sourcegraph/changed",
                    ["bob"],
                ),
                extra_repo_id: self.make_repo_snapshot(
                    "github.com/sourcegraph/extra",
                    ["alice"],
                ),
            }
        )
        snapshot_state = permission_restore.RestoreSnapshotState(
            target_snapshot=target_snapshot,
            current_snapshot=current_snapshot,
            users=[],
        )

        plan = permission_restore.plan_full_restore(snapshot_state)

        self.assertEqual(2, len(plan.overwrites))
        self.assertEqual(2, plan.snapshot_repo_count)
        self.assertEqual(1, plan.skipped_repo_count)
        self.assertEqual(1, plan.extra_repo_count)
        overwrites_by_repo = {
            overwrite.repository_id: (overwrite.repository_name, overwrite.usernames)
            for overwrite in plan.overwrites
        }
        self.assertNotIn(matching_repo_id, overwrites_by_repo)
        self.assertEqual(
            (
                "github.com/sourcegraph/changed",
                ("alice",),
            ),
            overwrites_by_repo[changed_repo_id],
        )
        self.assertEqual(("github.com/sourcegraph/extra", ()), overwrites_by_repo[extra_repo_id])

    def test_plan_full_restore_restores_and_wipes_pending_grants(self) -> None:
        matching_repo_id = src.encode_repository_id(1)
        drifted_repo_id = src.encode_repository_id(2)
        pending_only_target_repo_id = src.encode_repository_id(3)
        pending_only_current_repo_id = src.encode_repository_id(4)
        matching_repo: permission_types.Repository = {
            "id": matching_repo_id,
            "name": "github.com/sourcegraph/matching",
        }
        drifted_repo: permission_types.Repository = {
            "id": drifted_repo_id,
            "name": "github.com/sourcegraph/drifted",
        }
        pending_only_target_repo: permission_types.Repository = {
            "id": pending_only_target_repo_id,
            "name": "github.com/sourcegraph/pending-only-target",
        }
        pending_only_current_repo: permission_types.Repository = {
            "id": pending_only_current_repo_id,
            "name": "github.com/sourcegraph/pending-only-current",
        }
        target_snapshot = self.make_snapshot(
            {
                matching_repo_id: self.make_repo_snapshot(matching_repo["name"], ["alice"]),
                drifted_repo_id: self.make_repo_snapshot(drifted_repo["name"], ["alice"]),
            },
            pending_users={
                "ghost": [matching_repo, drifted_repo, pending_only_target_repo],
            },
        )
        current_snapshot = self.make_snapshot(
            {
                matching_repo_id: self.make_repo_snapshot(matching_repo["name"], ["alice"]),
                drifted_repo_id: self.make_repo_snapshot(drifted_repo["name"], ["alice"]),
            },
            pending_users={
                "ghost": [matching_repo],
                "stale": [pending_only_current_repo],
            },
        )
        snapshot_state = permission_restore.RestoreSnapshotState(
            target_snapshot=target_snapshot,
            current_snapshot=current_snapshot,
            users=[],
        )

        plan = permission_restore.plan_full_restore(snapshot_state)

        overwrites_by_repo = {
            overwrite.repository_id: (overwrite.repository_name, overwrite.usernames)
            for overwrite in plan.overwrites
        }
        # Real users and pending both match — no mutation.
        self.assertNotIn(matching_repo_id, overwrites_by_repo)
        # Pending grant missing from current state — restored alongside alice.
        self.assertEqual(
            (drifted_repo["name"], ("alice", "ghost")),
            overwrites_by_repo[drifted_repo_id],
        )
        # Repo with only a pending grant in the target — recreated.
        self.assertEqual(
            (pending_only_target_repo["name"], ("ghost",)),
            overwrites_by_repo[pending_only_target_repo_id],
        )
        # Pending-only repo absent from the target — wiped.
        self.assertEqual(
            (pending_only_current_repo["name"], ()),
            overwrites_by_repo[pending_only_current_repo_id],
        )
        self.assertEqual(3, plan.snapshot_repo_count)
        self.assertEqual(1, plan.skipped_repo_count)
        self.assertEqual(1, plan.extra_repo_count)

    def make_repo_snapshot(
        self,
        name: str,
        users: list[str],
    ) -> permission_snapshot.RepoSnapshot:
        return {
            "name": name,
            "users": users,
        }

    def make_snapshot(
        self,
        repos: dict[str, permission_snapshot.RepoSnapshot],
        pending_users: dict[str, list[permission_types.Repository]] | None = None,
    ) -> permission_snapshot.Snapshot:
        total_grants = sum(len(repo_snapshot["users"]) for repo_snapshot in repos.values())
        users_with_explicit_grants = {
            username for repo_snapshot in repos.values() for username in repo_snapshot["users"]
        }
        return {
            "schema_version": permission_snapshot.SNAPSHOT_SCHEMA_VERSION,
            "captured_at": "2026-05-26T00:00:00+00:00",
            "endpoint": "https://sourcegraph.example.com",
            "bindID_mode": "USERNAME",
            "config_file": None,
            "config_sha256": None,
            "pending_users": pending_users or {},
            "stats": {
                "total_users_scanned": len(users_with_explicit_grants),
                "users_with_explicit_grants": len(users_with_explicit_grants),
                "repos_with_explicit_grants": len(repos),
                "total_grants": total_grants,
            },
            "repos": repos,
        }
