"""File-writing behavior of command workflows under write_files True/False.

These guard the --no-files contract: with write_files=False a run must leave
no artifacts on disk while still returning discovery data in memory, and with
write_files=True the on-disk YAML must match the in-memory views exactly.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest import mock

import src_py_lib as src
import yaml

from src_auth_perms_sync.permissions import command as permissions_command
from src_auth_perms_sync.permissions import snapshot as permission_snapshot
from src_auth_perms_sync.permissions import types as permission_types
from src_auth_perms_sync.permissions import workflow as permission_workflow
from src_auth_perms_sync.shared import backups
from src_auth_perms_sync.shared import types as shared_types


def make_run_paths(directory: Path, *, write_files: bool) -> backups.RunPaths:
    endpoint_directory = directory / "artifacts" / "sourcegraph.example.com"
    return backups.RunPaths(
        timestamp="2026-06-12-00-00-00",
        artifacts_dir=directory / "artifacts",
        endpoint_directory=endpoint_directory,
        maps_path=directory / "maps.yaml",
        code_hosts_path=endpoint_directory / "code-hosts.yaml",
        auth_providers_path=endpoint_directory / "auth-providers.yaml",
        run_directory=endpoint_directory / "runs" / "2026-06-12-00-00-00-get",
        write_files=write_files,
    )


def make_auth_provider() -> shared_types.AuthProvider:
    return {
        "serviceType": "github",
        "serviceID": "https://github.example.com",
        "clientID": "client-1",
        "displayName": "GitHub Enterprise SSO",
        "isBuiltin": False,
        "configID": "github-sso",
    }


def make_external_service() -> permission_types.ExternalService:
    return {
        "id": "RXh0ZXJuYWxTZXJ2aWNlOjE=",
        "kind": "GITHUB",
        "displayName": "GitHub Enterprise",
        "url": "https://github.example.com",
        "repoCount": 1,
        "createdAt": "2026-06-09T00:00:00Z",
        "updatedAt": "2026-06-09T00:00:00Z",
        "lastSyncAt": None,
        "nextSyncAt": None,
        "lastSyncError": None,
        "warning": None,
        "unrestricted": False,
        "suspended": False,
        "hasConnectionCheck": False,
        "supportsRepoExclusion": False,
        "creator": None,
        "lastUpdater": None,
        "config": "{}",
    }


def make_snapshot() -> permission_snapshot.Snapshot:
    return {
        "schema_version": permission_snapshot.SNAPSHOT_SCHEMA_VERSION,
        "captured_at": "2026-06-12T00:00:00+00:00",
        "endpoint": "https://sourcegraph.example.com",
        "bindID_mode": "USERNAME",
        "config_file": None,
        "config_sha256": None,
        "pending_users": {},
        "stats": {
            "total_users_scanned": 1,
            "users_with_explicit_grants": 1,
            "repos_with_explicit_grants": 1,
            "total_grants": 1,
        },
        "repos": {
            src.encode_repository_id(1): {
                "name": "github.com/sourcegraph/example",
                "users": ["alice"],
            }
        },
    }


def run_cmd_get(
    run_paths: backups.RunPaths,
    *,
    do_backup: bool,
) -> permissions_command.run_context.CommandData:
    client = cast(
        src.SourcegraphClient,
        SimpleNamespace(endpoint="https://sourcegraph.example.com"),
    )
    with (
        mock.patch.object(
            permissions_command,
            "load_discovery",
            return_value=([make_auth_provider()], [make_external_service()], {}),
        ),
        mock.patch.object(permissions_command, "_load_get_users", return_value=[]),
        mock.patch.object(
            permissions_command.permission_snapshot,
            "build_snapshot",
            return_value=make_snapshot(),
        ),
    ):
        return permissions_command.cmd_get(
            client,
            run_paths,
            user_identifiers=(),
            users_without_explicit_perms=False,
            user_created_after=None,
            repository_names=(),
            repositories_without_explicit_perms=False,
            repository_created_after=None,
            parallelism=1,
            explicit_permissions_batch_size=25,
            bind_id_mode="USERNAME",
            saml_groups_attribute_name_by_config_id={},
            auth_providers_by_config_id={},
            do_backup=do_backup,
        )


class CmdGetFileBehaviorTests(unittest.TestCase):
    def test_no_files_run_creates_nothing_but_returns_views(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            maps_path = directory / "maps.yaml"
            maps_path.write_text("maps: []\n")
            run_paths = make_run_paths(directory, write_files=False)

            command_data = run_cmd_get(run_paths, do_backup=True)

            # Only the pre-existing maps file remains; no YAML, snapshots,
            # maps backups, or run directories appeared anywhere.
            self.assertEqual({maps_path}, set(directory.rglob("*")))

        self.assertIsNotNone(command_data.auth_provider_views)
        self.assertIsNotNone(command_data.code_host_views)
        assert command_data.auth_provider_views is not None
        assert command_data.code_host_views is not None
        self.assertEqual("github", command_data.auth_provider_views[0]["type"])
        self.assertEqual("GitHub Enterprise", command_data.code_host_views[0]["displayName"])

    def test_writing_run_dumps_yaml_matching_the_returned_views(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            run_paths = make_run_paths(directory, write_files=True)

            command_data = run_cmd_get(run_paths, do_backup=False)

            self.assertTrue(run_paths.code_hosts_path.is_file())
            self.assertTrue(run_paths.auth_providers_path.is_file())
            code_hosts_on_disk = yaml.safe_load(run_paths.code_hosts_path.read_text())
            auth_providers_on_disk = yaml.safe_load(run_paths.auth_providers_path.read_text())

        self.assertEqual(command_data.code_host_views, code_hosts_on_disk["codeHostConnections"])
        self.assertEqual(command_data.auth_provider_views, auth_providers_on_disk["authProviders"])


class WriteMapsBackupTests(unittest.TestCase):
    def test_copies_the_input_file_into_the_run_directory_with_its_name(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            maps_path = directory / "team-maps.yaml"
            maps_path.write_text("maps: []\n")
            run_paths = make_run_paths(directory, write_files=True)
            run_paths.run_directory.mkdir(parents=True)

            backup_path = permission_workflow.write_maps_backup(maps_path, run_paths)

            self.assertEqual(run_paths.run_directory / "team-maps.yaml", backup_path)
            assert backup_path is not None
            self.assertEqual("maps: []\n", backup_path.read_text())

    def test_returns_none_without_writing_when_the_input_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            run_paths = make_run_paths(directory, write_files=True)
            run_paths.run_directory.mkdir(parents=True)

            backup_path = permission_workflow.write_maps_backup(
                directory / "missing-maps.yaml",
                run_paths,
            )

            self.assertIsNone(backup_path)
            self.assertEqual([], list(run_paths.run_directory.iterdir()))


class WriteSnapshotPairTests(unittest.TestCase):
    def test_writes_before_after_and_diff_at_artifact_paths(self) -> None:
        before = make_snapshot()
        after = make_snapshot()
        after["repos"][src.encode_repository_id(1)] = {
            "name": "github.com/sourcegraph/example",
            "users": ["alice", "bob"],
        }

        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            run_paths = make_run_paths(directory, write_files=True)
            run_paths.run_directory.mkdir(parents=True)

            before_path, after_path, diff_path = permission_workflow.write_snapshot_pair(
                run_paths,
                before,
                after,
            )

            self.assertEqual(run_paths.artifact_path("before"), before_path)
            self.assertEqual(run_paths.artifact_path("after"), after_path)
            self.assertEqual(run_paths.artifact_path("diff"), diff_path)
            before_on_disk = json.loads(before_path.read_text())
            after_on_disk = json.loads(after_path.read_text())
            diff_on_disk = json.loads(diff_path.read_text())

        self.assertEqual(["alice"], before_on_disk["repos"]["1"]["users"])
        self.assertEqual(["alice", "bob"], after_on_disk["repos"]["1"]["users"])
        self.assertEqual(1, diff_on_disk["summary"]["grants_added"])


if __name__ == "__main__":
    unittest.main()
