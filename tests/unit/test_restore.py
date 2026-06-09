from __future__ import annotations

import unittest

import src_py_lib as src

from src_auth_perms_sync.permissions import restore as permission_restore
from src_auth_perms_sync.permissions import snapshot as permission_snapshot


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
            "pending_bindIDs": [],
            "stats": {
                "total_users_scanned": len(users_with_explicit_grants),
                "users_with_explicit_grants": len(users_with_explicit_grants),
                "repos_with_explicit_grants": len(repos),
                "total_grants": total_grants,
            },
            "repos": repos,
        }
