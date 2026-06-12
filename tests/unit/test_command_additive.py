from __future__ import annotations

import base64
import tempfile
import unittest
from pathlib import Path
from typing import Any, cast

import src_py_lib as src

from src_auth_perms_sync.permissions import command
from src_auth_perms_sync.permissions import types as permission_types
from src_auth_perms_sync.shared import backups
from src_auth_perms_sync.shared import types as shared_types


class _AdditiveCommandClient:
    endpoint = "https://sourcegraph.example.com"

    def __init__(
        self,
        *,
        services: list[permission_types.ExternalService],
        repos_by_service_id: dict[str, list[permission_types.Repository]],
        users_by_username: dict[str, shared_types.User],
        explicit_repo_ids_by_user_id: dict[str, list[str]] | None = None,
    ) -> None:
        self.services = services
        self.repos_by_service_id = repos_by_service_id
        self.users_by_username = users_by_username
        self.explicit_repo_ids_by_user_id = explicit_repo_ids_by_user_id or {}
        self.repo_service_ids: list[str] = []
        self.explicit_repo_fetch_count = 0

    def graphql(
        self,
        query: str,
        variables: src.JSONDict | None = None,
        *,
        follow_pages: bool = True,
    ) -> src.JSONDict:
        del follow_pages
        if "authProviders" in query:
            return cast(src.JSONDict, {"site": {"authProviders": {"nodes": []}}})
        if "query UserByUsername" in query:
            if variables is None:
                raise AssertionError("expected username variables")
            username = variables.get("username")
            return cast(src.JSONDict, {"user": self.users_by_username.get(str(username))})
        if "query UserByEmail" in query:
            return cast(src.JSONDict, {"user": None})
        if "query RepositoryNamesByID" in query:
            if variables is None:
                raise AssertionError("expected repository variables")
            return cast(src.JSONDict, self._repositories_by_alias(variables))
        raise AssertionError(f"unexpected query: {query[:80]}")

    def stream_connection_nodes(
        self,
        query: str,
        variables: src.JSONDict | None = None,
        *,
        connection_path: tuple[str, ...],
        page_size: int,
    ) -> list[dict[str, Any]]:
        del connection_path, page_size
        if "externalServices" in query:
            return cast(list[dict[str, Any]], self.services)
        if "query ReposByExternalService" in query:
            service_id_value = None if variables is None else variables.get("esID")
            if not isinstance(service_id_value, str):
                raise AssertionError("expected external service ID")
            self.repo_service_ids.append(service_id_value)
            return cast(
                list[dict[str, Any]],
                self.repos_by_service_id.get(service_id_value, []),
            )
        if "query UserExplicitRepos" in query:
            user_id_value = None if variables is None else variables.get("id")
            if not isinstance(user_id_value, str):
                raise AssertionError("expected user ID")
            self.explicit_repo_fetch_count += 1
            return [
                {"id": repository_id}
                for repository_id in self.explicit_repo_ids_by_user_id.get(user_id_value, [])
            ]
        raise AssertionError(f"unexpected stream query: {query[:80]}")

    def _repositories_by_alias(self, variables: src.JSONDict) -> dict[str, object]:
        repos_by_id = {
            repository["id"]: repository
            for repositories in self.repos_by_service_id.values()
            for repository in repositories
        }
        response: dict[str, object] = {}
        for variable_name, repository_id in variables.items():
            if not variable_name.startswith("repo") or not isinstance(repository_id, str):
                continue
            response[variable_name] = repos_by_id.get(repository_id)
        return response


def make_run_paths(directory: Path, maps_path: Path) -> backups.RunPaths:
    endpoint_directory = directory / "artifacts" / "sourcegraph.example.com"
    return backups.RunPaths(
        timestamp="2026-06-09-10-00-00",
        artifacts_dir=directory / "artifacts",
        endpoint_directory=endpoint_directory,
        maps_path=maps_path,
        code_hosts_path=endpoint_directory / "code-hosts.yaml",
        auth_providers_path=endpoint_directory / "auth-providers.yaml",
        run_directory=directory / "run-artifacts",
    )


class AdditiveCommandTests(unittest.TestCase):
    def test_no_backup_dry_run_skips_artifacts_and_repo_load_when_no_rule_matches(
        self,
    ) -> None:
        service = make_external_service(1, "GitHub Enterprise")
        client = _AdditiveCommandClient(
            services=[service],
            repos_by_service_id={service["id"]: [make_repository(1, "github.com/example/repo")]},
            users_by_username={"marc": make_user("user-1", "marc")},
        )

        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            maps_path = directory / "maps.yaml"
            maps_path.write_text(
                """
maps:
  - name: alice repos
    users:
      usernames: [alice]
    repos:
      codeHostConnection:
        displayName: GitHub Enterprise
      names: [github.com/example/repo]
""".lstrip(),
                encoding="utf-8",
            )
            run_paths = make_run_paths(directory, maps_path)

            command.cmd_set_additive_users(
                cast(src.SourcegraphClient, client),
                run_paths,
                ("marc",),
                None,
                dry_run=True,
                parallelism=1,
                bind_id_mode="USERNAME",
                saml_groups_attribute_name_by_config_id={},
                do_backup=False,
            )

            self.assertFalse(run_paths.run_directory.exists())
            self.assertEqual([], client.repo_service_ids)
            self.assertEqual(0, client.explicit_repo_fetch_count)

    def test_additive_users_loads_only_referenced_code_hosts(self) -> None:
        first_service = make_external_service(1, "GitHub Enterprise")
        second_service = make_external_service(2, "GitLab")
        client = _AdditiveCommandClient(
            services=[first_service, second_service],
            repos_by_service_id={
                first_service["id"]: [make_repository(1, "github.com/example/repo")],
                second_service["id"]: [make_repository(2, "gitlab.example.com/example/repo")],
            },
            users_by_username={"alice": make_user("user-1", "alice")},
        )

        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            maps_path = directory / "maps.yaml"
            maps_path.write_text(
                """
maps:
  - name: alice repos
    users:
      usernames: [alice]
    repos:
      codeHostConnection:
        displayName: GitHub Enterprise
      names: [github.com/example/repo]
""".lstrip(),
                encoding="utf-8",
            )

            command.cmd_set_additive_users(
                cast(src.SourcegraphClient, client),
                make_run_paths(directory, maps_path),
                ("alice",),
                None,
                dry_run=True,
                parallelism=1,
                bind_id_mode="USERNAME",
                saml_groups_attribute_name_by_config_id={},
                do_backup=False,
            )

        self.assertEqual([first_service["id"]], client.repo_service_ids)
        self.assertEqual(1, client.explicit_repo_fetch_count)

    def test_backup_dry_run_reuses_planning_explicit_repo_read_for_snapshot(self) -> None:
        service = make_external_service(1, "GitHub Enterprise")
        client = _AdditiveCommandClient(
            services=[service],
            repos_by_service_id={service["id"]: [make_repository(1, "github.com/example/repo")]},
            users_by_username={"alice": make_user("user-1", "alice")},
        )

        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            maps_path = directory / "maps.yaml"
            maps_path.write_text(
                """
maps:
  - name: alice repos
    users:
      usernames: [alice]
    repos:
      codeHostConnection:
        displayName: GitHub Enterprise
      names: [github.com/example/repo]
""".lstrip(),
                encoding="utf-8",
            )
            run_paths = make_run_paths(directory, maps_path)
            run_paths.run_directory.mkdir(parents=True)

            command.cmd_set_additive_users(
                cast(src.SourcegraphClient, client),
                run_paths,
                ("alice",),
                None,
                dry_run=True,
                parallelism=1,
                bind_id_mode="USERNAME",
                saml_groups_attribute_name_by_config_id={},
                do_backup=True,
            )

            run_directory = run_paths.run_directory
            self.assertTrue((run_directory / "before.json").exists())
            self.assertTrue((run_directory / "after.json").exists())
            self.assertTrue((run_directory / "diff.json").exists())
            self.assertTrue((run_directory / "maps.yaml").exists())

        self.assertEqual(1, client.explicit_repo_fetch_count)


def make_graphql_id(kind: str, identifier: int) -> str:
    return base64.b64encode(f"{kind}:{identifier}".encode()).decode()


def make_user(user_id: str, username: str) -> shared_types.User:
    return {
        "id": user_id,
        "username": username,
        "builtinAuth": True,
        "externalAccounts": {"nodes": []},
    }


def make_repository(identifier: int, name: str) -> permission_types.Repository:
    return {"id": make_graphql_id("Repository", identifier), "name": name}


def make_external_service(identifier: int, display_name: str) -> permission_types.ExternalService:
    return {
        "id": make_graphql_id("ExternalService", identifier),
        "kind": "GITHUB",
        "displayName": display_name,
        "url": f"https://code-host-{identifier}.example.com",
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


if __name__ == "__main__":
    unittest.main()
