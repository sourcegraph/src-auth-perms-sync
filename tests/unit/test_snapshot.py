from __future__ import annotations

import json
import tempfile
import unittest
from collections.abc import Iterable, Sequence
from concurrent.futures import Future
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import patch

import src_py_lib as src

from src_auth_perms_sync.permissions import snapshot as permission_snapshot
from src_auth_perms_sync.permissions import sourcegraph as permissions_sourcegraph
from src_auth_perms_sync.permissions import types as permission_types
from src_auth_perms_sync.permissions import workflow as permission_workflow
from src_auth_perms_sync.shared import backups


class SnapshotTests(unittest.TestCase):
    def test_capture_explicit_grants_inverts_repos_without_per_user_buffer(self) -> None:
        repo_one_id = src.encode_repository_id(1)
        repo_two_id = src.encode_repository_id(2)
        users: list[permission_snapshot.SnapshotUser] = [
            {"id": "user-1", "username": "carol"},
            {"id": "user-2", "username": "alice"},
            {"id": "user-3", "username": "bob"},
        ]
        repository_ids_by_user_id: dict[str, list[str]] = {
            "user-1": [repo_one_id, repo_two_id],
            "user-2": [repo_one_id],
            "user-3": [],
        }
        repositories_by_id: dict[str, permission_types.Repository] = {
            repo_one_id: {"id": repo_one_id, "name": "github.com/sourcegraph/one"},
            repo_two_id: {"id": repo_two_id, "name": "github.com/sourcegraph/two"},
        }
        hydrated_repository_ids: list[str] = []

        def list_repo_ids(
            _client: src.SourcegraphClient,
            user_ids: Sequence[str],
            *,
            batch_size: int,
        ) -> dict[str, list[str]]:
            return {user_id: repository_ids_by_user_id[user_id] for user_id in user_ids}

        def list_repositories_by_ids(
            _client: src.SourcegraphClient,
            repository_ids: Iterable[str],
        ) -> dict[str, permission_types.Repository]:
            hydrated_repository_ids.extend(repository_ids)
            return repositories_by_id

        with (
            patch.object(
                permission_snapshot.permissions_sourcegraph,
                "list_users_explicit_repo_ids",
                side_effect=list_repo_ids,
            ),
            patch.object(
                permission_snapshot.permissions_sourcegraph,
                "list_repositories_by_ids",
                side_effect=list_repositories_by_ids,
            ),
        ):
            repos, user_count = permission_snapshot.capture_explicit_grants(
                cast(src.SourcegraphClient, object()),
                users,
                parallelism=1,
                explicit_permissions_batch_size=25,
                total_users=len(users),
            )

        self.assertEqual(3, user_count)
        self.assertEqual([repo_one_id, repo_two_id], hydrated_repository_ids)
        self.assertEqual(
            {
                repo_one_id: {
                    "name": "github.com/sourcegraph/one",
                    "explicit_permissions_users": ["alice", "carol"],
                },
                repo_two_id: {
                    "name": "github.com/sourcegraph/two",
                    "explicit_permissions_users": ["carol"],
                },
            },
            repos,
        )

    def test_capture_explicit_grants_bounds_pending_batches(self) -> None:
        users: list[permission_snapshot.SnapshotUser] = [
            {"id": f"user-{index}", "username": f"user-{index}"} for index in range(9)
        ]
        pending_counts: list[int] = []
        real_wait = permission_snapshot.wait

        def recording_wait(futures: Iterable[Future[Any]], **kwargs: Any) -> Any:
            futures_list = list(futures)
            pending_counts.append(len(futures_list))
            return real_wait(futures_list, **kwargs)

        def list_repo_ids(
            _client: src.SourcegraphClient,
            user_ids: Sequence[str],
            *,
            batch_size: int,
        ) -> dict[str, list[str]]:
            return {user_id: [] for user_id in user_ids}

        with (
            patch.object(
                permission_snapshot.permissions_sourcegraph,
                "list_users_explicit_repo_ids",
                side_effect=list_repo_ids,
            ),
            patch.object(
                permission_snapshot.permissions_sourcegraph,
                "list_repositories_by_ids",
                return_value={},
            ),
            patch.object(permission_snapshot, "wait", side_effect=recording_wait),
        ):
            _, user_count = permission_snapshot.capture_explicit_grants(
                cast(src.SourcegraphClient, object()),
                users,
                parallelism=2,
                explicit_permissions_batch_size=1,
                total_users=len(users),
            )

        self.assertEqual(9, user_count)
        self.assertTrue(pending_counts)
        self.assertLessEqual(max(pending_counts), 4)

    def test_list_users_explicit_repos_batches_aliases_and_follows_pages(self) -> None:
        repo_one: permission_types.Repository = {
            "id": src.encode_repository_id(1),
            "name": "github.com/sourcegraph/one",
        }
        repo_two: permission_types.Repository = {
            "id": src.encode_repository_id(2),
            "name": "github.com/sourcegraph/two",
        }
        repo_three: permission_types.Repository = {
            "id": src.encode_repository_id(3),
            "name": "github.com/sourcegraph/three",
        }
        calls: list[tuple[str, src.JSONDict, bool]] = []
        responses: list[src.JSONDict] = [
            cast(
                src.JSONDict,
                {
                    "user0": self.user_explicit_repos_page([repo_one], has_next_page=False),
                    "user1": self.user_explicit_repos_page(
                        [repo_two],
                        has_next_page=True,
                        end_cursor="cursor-two",
                    ),
                },
            ),
            cast(
                src.JSONDict,
                {
                    "user0": self.user_explicit_repos_page([repo_three], has_next_page=False),
                },
            ),
            cast(
                src.JSONDict,
                {
                    "repo0": repo_one,
                    "repo1": repo_two,
                    "repo2": repo_three,
                },
            ),
        ]

        class FakeGraphQLClient:
            def __init__(self, **_kwargs: object) -> None:
                pass

            def execute(
                self,
                query: str,
                variables: src.JSONDict,
                *,
                follow_pages: bool = True,
            ) -> src.JSONDict:
                calls.append((query, dict(variables), follow_pages))
                return responses.pop(0)

        def graphql(query: str, variables: object = None) -> src.JSONDict:
            return FakeGraphQLClient().execute(query, cast(src.JSONDict, variables or {}))

        client = cast(
            src.SourcegraphClient,
            SimpleNamespace(
                endpoint="https://sourcegraph.example.com",
                token="secret",
                http=object(),
                graphql=graphql,
            ),
        )
        with patch.object(permissions_sourcegraph.src, "GraphQLClient", FakeGraphQLClient):
            repos_by_user_id = permissions_sourcegraph.list_users_explicit_repos(
                client,
                ["user-1", "user-2"],
                batch_size=2,
            )

        self.assertEqual(
            {
                "user-1": [repo_one],
                "user-2": [repo_two, repo_three],
            },
            repos_by_user_id,
        )
        self.assertIn("user0: node(id: $user0)", calls[0][0])
        self.assertIn("user1: node(id: $user1)", calls[0][0])
        self.assertNotIn("repository {", calls[0][0])
        self.assertNotIn("updatedAt", calls[0][0])
        self.assertFalse(calls[0][2])
        self.assertEqual("user-1", calls[0][1]["user0"])
        self.assertEqual("user-2", calls[0][1]["user1"])
        self.assertIsNone(calls[0][1]["after0"])
        self.assertIsNone(calls[0][1]["after1"])
        self.assertFalse(calls[1][2])
        self.assertEqual("user-2", calls[1][1]["user0"])
        self.assertEqual("cursor-two", calls[1][1]["after0"])
        self.assertIn("repo0: node(id: $repo0)", calls[2][0])
        self.assertEqual(repo_one["id"], calls[2][1]["repo0"])
        self.assertEqual(repo_two["id"], calls[2][1]["repo1"])
        self.assertEqual(repo_three["id"], calls[2][1]["repo2"])

    def test_write_snapshot_uses_username_list_for_explicit_permissions(self) -> None:
        snapshot = self.make_snapshot()

        with tempfile.TemporaryDirectory() as directory_name:
            snapshot_path = Path(directory_name) / "before.json"

            permission_snapshot.write_snapshot(snapshot_path, snapshot)
            on_disk = json.loads(snapshot_path.read_text())

        self.assertEqual(
            ["alice", "bob"],
            on_disk["repos"]["1"]["explicit_permissions_users"],
        )
        self.assertNotIn("explicit_user_permissions", on_disk["repos"]["1"])

    def test_snapshot_diff_omits_unchanged_users(self) -> None:
        before = self.make_snapshot()
        after = self.make_snapshot()
        repo_id = src.encode_repository_id(1)
        after["repos"][repo_id]["explicit_permissions_users"] = ["alice", "carol"]

        diff = permission_snapshot.build_snapshot_diff(before, after)

        self.assertEqual(["carol"], diff["repos"][0]["added"])
        self.assertEqual(["bob"], diff["repos"][0]["removed"])
        self.assertNotIn("alice", json.dumps(diff))

    def test_write_projected_snapshot_keeps_after_repos_out_of_memory(self) -> None:
        before = self.make_snapshot()
        existing_repo_id = src.encode_repository_id(1)
        new_repo_id = src.encode_repository_id(2)
        expected_users = {
            existing_repo_id: ("alice", "carol"),
            new_repo_id: ("dana",),
        }
        repo_names = {
            existing_repo_id: "github.com/sourcegraph/example",
            new_repo_id: "github.com/sourcegraph/new",
        }

        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            after_path = directory / "after.json"
            after = permission_workflow.write_projected_snapshot(
                after_path,
                before,
                expected_users,
                repo_names,
            )
            with backups.run_artifacts_context(directory, "test-run"):
                diff_path = permission_workflow.write_projected_snapshot_diff_file(
                    directory / "maps.yaml",
                    "test-run",
                    before["endpoint"],
                    "set-dry-run",
                    before,
                    after,
                    expected_users,
                    repo_names,
                )

            after_on_disk = json.loads(after_path.read_text())
            diff_on_disk = json.loads(diff_path.read_text())

        self.assertEqual({}, after["repos"])
        self.assertEqual(
            ["alice", "carol"],
            after_on_disk["repos"]["1"]["explicit_permissions_users"],
        )
        self.assertEqual(
            ["dana"],
            after_on_disk["repos"]["2"]["explicit_permissions_users"],
        )
        self.assertEqual(2, diff_on_disk["summary"]["repos_changed"])
        self.assertEqual(2, diff_on_disk["summary"]["grants_added"])
        self.assertEqual(1, diff_on_disk["summary"]["grants_removed"])

    def test_render_diff_omits_unchanged_users(self) -> None:
        repo_id = src.encode_repository_id(1)

        rendered = permission_snapshot.render_diff(
            {
                repo_id: {
                    "name": "github.com/sourcegraph/example",
                    "added": ["carol"],
                    "removed": ["bob"],
                }
            }
        )

        self.assertIn("+ added (1): carol", rendered)
        self.assertIn("- removed (1): bob", rendered)
        self.assertNotIn("unchanged", rendered)
        self.assertNotIn("alice", rendered)

    def test_read_snapshot_rejects_old_schema_versions(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            snapshot_path = Path(directory_name) / "before.json"
            on_disk = self.make_snapshot()
            on_disk["schema_version"] = 2
            snapshot_path.write_text(json.dumps(on_disk))

            with self.assertRaises(SystemExit) as exit_context:
                permission_snapshot.read_snapshot(snapshot_path)

        self.assertIn("expected 3", str(exit_context.exception))

    def make_snapshot(self) -> permission_snapshot.Snapshot:
        return {
            "schema_version": permission_snapshot.SNAPSHOT_SCHEMA_VERSION,
            "captured_at": "2026-05-26T00:00:00+00:00",
            "endpoint": "https://sourcegraph.example.com",
            "bindID_mode": "USERNAME",
            "config_file": None,
            "config_sha256": None,
            "pending_bindIDs": [],
            "stats": {
                "total_users_scanned": 2,
                "users_with_explicit_grants": 2,
                "repos_with_explicit_grants": 1,
                "total_grants": 2,
            },
            "repos": {
                src.encode_repository_id(1): {
                    "name": "github.com/sourcegraph/example",
                    "explicit_permissions_users": ["alice", "bob"],
                }
            },
        }

    def user_explicit_repos_page(
        self,
        repositories: list[permission_types.Repository],
        *,
        has_next_page: bool,
        end_cursor: str | None = None,
    ) -> src.JSONDict:
        return cast(
            src.JSONDict,
            {
                "permissionsInfo": {
                    "repositories": {
                        "nodes": [{"id": repository["id"]} for repository in repositories],
                        "pageInfo": {"hasNextPage": has_next_page, "endCursor": end_cursor},
                    }
                }
            },
        )
