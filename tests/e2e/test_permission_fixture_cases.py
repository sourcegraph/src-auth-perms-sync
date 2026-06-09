from __future__ import annotations

import json
import unittest
from collections.abc import Iterator, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NotRequired, TypedDict, cast

import src_py_lib as src

from src_auth_perms_sync import cli
from src_auth_perms_sync.shared import types as shared_types

FIXTURES_DIR = Path(__file__).with_name("fixtures")
SITE_CONFIG = json.dumps(
    {
        "permissions.userMapping": {"enabled": True, "bindID": "username"},
        "auth.enableUsernameChanges": False,
        "auth.providers": [],
    }
)


class FixtureEmail(TypedDict):
    email: str
    verified: bool


class FixtureExternalAccount(TypedDict, total=False):
    serviceType: str
    serviceID: str
    clientID: str
    accountData: dict[str, Any] | None


class FixtureUser(TypedDict):
    id: int
    username: str
    builtinAuth: bool
    createdAt: str
    emails: list[FixtureEmail]
    externalAccounts: list[FixtureExternalAccount]


class FixtureExternalService(TypedDict):
    id: int
    kind: str
    displayName: str
    url: str
    config: str


class FixtureRepo(TypedDict):
    id: int
    name: str
    externalServiceID: int
    explicitPermissionsUsers: list[str]


class FixtureState(TypedDict):
    endpoint: str
    authProviders: list[shared_types.AuthProvider]
    externalServices: list[FixtureExternalService]
    users: list[FixtureUser]
    repos: list[FixtureRepo]
    pendingBindIDs: list[str]


class FixtureSetOptions(TypedDict, total=False):
    full: bool
    users: list[str]
    usersWithoutExplicitPerms: bool
    createdAfter: str


class FixtureCase(TypedDict):
    description: str
    set: FixtureSetOptions
    expectedMutations: NotRequired[int]


@dataclass(frozen=True, slots=True)
class FixtureStateCounts:
    users: int
    repos: int
    permission_pairs: int


@dataclass(frozen=True, slots=True)
class FixtureRunResult:
    name: str
    description: str
    before_counts: FixtureStateCounts
    expected_counts: FixtureStateCounts
    actual_counts: FixtureStateCounts
    expected_mutations: int | None
    actual_mutations: int
    expected_state: FixtureState
    actual_state: FixtureState
    command_failure: str | None = None

    @property
    def failure(self) -> str | None:
        if self.command_failure is not None:
            return self.command_failure
        if self.expected_state != self.actual_state:
            return "actual state did not match after.json"
        if self.expected_mutations is not None and self.expected_mutations != self.actual_mutations:
            return f"expected {self.expected_mutations} mutation(s), got {self.actual_mutations}"
        return None

    @property
    def passed(self) -> bool:
        return self.failure is None


class FakeSourcegraphClient:
    """Small in-memory GraphQL surface for permission-sync fixture cases."""

    def __init__(self, state: FixtureState) -> None:
        self.endpoint = state["endpoint"]
        self._auth_providers = list(state["authProviders"])
        self._external_services = list(state["externalServices"])
        self._users = list(state["users"])
        self._repos = list(state["repos"])
        self._pending_bind_ids = list(state["pendingBindIDs"])
        self._mutation_count = 0

        self._users_by_graphql_id = {
            self._user_graphql_id(user["id"]): user for user in self._users
        }
        self._users_by_username = {user["username"]: user for user in self._users}
        self._repos_by_graphql_id = {
            self._repository_graphql_id(repository["id"]): repository for repository in self._repos
        }
        self._external_service_ids_by_graphql_id = {
            self._external_service_graphql_id(service["id"]): service["id"]
            for service in self._external_services
        }
        self._permissions_by_repository_id = {
            repository["id"]: set(repository["explicitPermissionsUsers"])
            for repository in self._repos
        }

    @property
    def mutation_count(self) -> int:
        return self._mutation_count

    def graphql(
        self,
        query: str,
        variables: Mapping[str, object] | None = None,
        *,
        follow_pages: bool = True,
        page_size: int | None = None,
        first_variable: str = "first",
        after_variable: str = "after",
    ) -> dict[str, Any]:
        del follow_pages, page_size, first_variable, after_variable
        variable_values = dict(variables or {})

        if "query ValidatePermissionsConfig" in query:
            return {
                "site": {
                    "permissionsUserMappingBindID": "USERNAME",
                    "configuration": {"effectiveContents": SITE_CONFIG},
                }
            }
        if "query ListAuthProviders" in query:
            return {"site": {"authProviders": {"nodes": self._auth_providers}}}
        if "query CountUsers" in query:
            return {"users": {"totalCount": len(self._users)}}
        if "query UserByUsername" in query:
            return {"user": self._graphql_user_by_username(variable_values["username"])}
        if "query UserByEmail" in query:
            return {"user": self._graphql_user_by_email(variable_values["email"])}
        if "query UserByID" in query:
            return {"node": self._graphql_user_by_id(variable_values["id"])}
        if "query SiteUsers" in query:
            return {"site": {"users": self._site_users(variable_values)}}
        if "query UserExplicitRepoExists" in query:
            return {"node": self._user_explicit_repo_exists(variable_values["id"])}
        if "query UserExplicitReposBatch" in query:
            return self._user_explicit_repos_batch(variable_values)
        if "query RepositoryNamesByID" in query:
            return self._repository_names_by_id(variable_values)
        if "query PendingBindIDs" in query:
            return {"usersWithPendingPermissions": list(self._pending_bind_ids)}
        if "mutation SetRepoPerms" in query:
            self._set_repo_permissions(variable_values)
            return {"setRepositoryPermissionsForUsers": {"alwaysNil": None}}
        if "mutation AddRepoPerm" in query:
            self._add_repo_permission(variable_values)
            return {"addRepositoryPermissionForUser": {"alwaysNil": None}}
        if "mutation RemoveRepoPerm" in query:
            self._remove_repo_permission(variable_values)
            return {"removeRepositoryPermissionForUser": {"alwaysNil": None}}

        first_line = query.strip().splitlines()[0]
        raise AssertionError(f"Unhandled fixture GraphQL operation: {first_line}")

    def stream_connection_nodes(
        self,
        query: str,
        variables: Mapping[str, object] | None = None,
        *,
        connection_path: Sequence[str],
        page_size: int | None = None,
        first_variable: str = "first",
        after_variable: str = "after",
    ) -> Iterator[dict[str, Any]]:
        del query, page_size, first_variable, after_variable
        variable_values = dict(variables or {})
        path = tuple(connection_path)
        if path == ("users",):
            return iter(self._graphql_users())
        if path == ("externalServices",):
            return iter(self._graphql_external_services())
        if path == ("repositories",):
            return iter(self._repositories_for_external_service(variable_values["esID"]))
        if path == ("node", "permissionsInfo", "repositories"):
            return iter(self._explicit_repository_nodes_for_user(variable_values["id"]))
        raise AssertionError(f"Unhandled fixture connection path: {path}")

    def export_state(self) -> FixtureState:
        repos: list[FixtureRepo] = []
        for repository in self._repos:
            repos.append(
                {
                    "id": repository["id"],
                    "name": repository["name"],
                    "externalServiceID": repository["externalServiceID"],
                    "explicitPermissionsUsers": sorted(
                        self._permissions_by_repository_id[repository["id"]]
                    ),
                }
            )
        return {
            "endpoint": self.endpoint,
            "authProviders": self._auth_providers,
            "externalServices": self._external_services,
            "users": self._users,
            "repos": repos,
            "pendingBindIDs": self._pending_bind_ids,
        }

    def _graphql_user_by_username(self, username_value: object) -> dict[str, Any] | None:
        if not isinstance(username_value, str):
            raise AssertionError("username variable must be a string")
        user = self._users_by_username.get(username_value)
        return self._graphql_user(user) if user is not None else None

    def _graphql_user_by_email(self, email_value: object) -> dict[str, Any] | None:
        if not isinstance(email_value, str):
            raise AssertionError("email variable must be a string")
        for user in self._users:
            if any(email["email"] == email_value and email["verified"] for email in user["emails"]):
                return self._graphql_user(user)
        return None

    def _graphql_user_by_id(self, user_id_value: object) -> dict[str, Any] | None:
        if not isinstance(user_id_value, str):
            raise AssertionError("id variable must be a string")
        user = self._users_by_graphql_id.get(user_id_value)
        return self._graphql_user(user) if user is not None else None

    def _graphql_users(self) -> list[dict[str, Any]]:
        return [self._graphql_user(user) for user in self._users]

    def _graphql_user(self, user: FixtureUser) -> dict[str, Any]:
        return {
            "id": self._user_graphql_id(user["id"]),
            "username": user["username"],
            "builtinAuth": user["builtinAuth"],
            "emails": list(user["emails"]),
            "externalAccounts": {"nodes": list(user["externalAccounts"])},
        }

    def _graphql_external_services(self) -> list[dict[str, Any]]:
        return [self._graphql_external_service(service) for service in self._external_services]

    def _graphql_external_service(self, service: FixtureExternalService) -> dict[str, Any]:
        repository_count = sum(
            1 for repository in self._repos if repository["externalServiceID"] == service["id"]
        )
        return {
            "id": self._external_service_graphql_id(service["id"]),
            "kind": service["kind"],
            "displayName": service["displayName"],
            "url": service["url"],
            "repoCount": repository_count,
            "createdAt": "2026-01-01T00:00:00Z",
            "updatedAt": "2026-01-01T00:00:00Z",
            "lastSyncAt": None,
            "nextSyncAt": None,
            "lastSyncError": None,
            "warning": None,
            "unrestricted": False,
            "suspended": False,
            "hasConnectionCheck": False,
            "supportsRepoExclusion": True,
            "creator": None,
            "lastUpdater": None,
            "config": service["config"],
        }

    def _repositories_for_external_service(
        self, external_service_id_value: object
    ) -> list[dict[str, Any]]:
        if not isinstance(external_service_id_value, str):
            raise AssertionError("esID variable must be a string")
        external_service_id = self._external_service_ids_by_graphql_id[external_service_id_value]
        repositories: list[dict[str, Any]] = []
        for repository in self._repos:
            if repository["externalServiceID"] != external_service_id:
                continue
            graphql_repository = self._graphql_repository(repository)
            assert graphql_repository is not None
            repositories.append(graphql_repository)
        return repositories

    def _explicit_repository_nodes_for_user(self, user_id_value: object) -> list[dict[str, Any]]:
        if not isinstance(user_id_value, str):
            raise AssertionError("id variable must be a string")
        user = self._users_by_graphql_id.get(user_id_value)
        if user is None:
            return []
        username = user["username"]
        return [
            {"id": self._repository_graphql_id(repository["id"])}
            for repository in self._repos
            if username in self._permissions_by_repository_id[repository["id"]]
        ]

    def _site_users(self, variables: dict[str, object]) -> dict[str, Any]:
        created_at_filter = variables.get("createdAt")
        created_after: str | None = None
        if isinstance(created_at_filter, dict):
            created_after_value = cast(dict[str, object], created_at_filter).get("gte")
            if isinstance(created_after_value, str):
                created_after = created_after_value
        candidates = [
            user
            for user in self._users
            if created_after is None or user["createdAt"] >= created_after
        ]
        offset = self._integer_variable(variables, "offset")
        limit = self._integer_variable(variables, "limit")
        nodes = [
            {
                "id": self._user_graphql_id(user["id"]),
                "username": user["username"],
                "email": user["emails"][0]["email"] if user["emails"] else None,
                "createdAt": user["createdAt"],
                "deletedAt": None,
            }
            for user in candidates[offset : offset + limit]
        ]
        return {"totalCount": len(candidates), "nodes": nodes}

    def _user_explicit_repo_exists(self, user_id_value: object) -> dict[str, Any] | None:
        nodes = self._explicit_repository_nodes_for_user(user_id_value)
        return {"permissionsInfo": {"repositories": {"nodes": nodes[:1]}}}

    def _user_explicit_repos_batch(self, variables: dict[str, object]) -> dict[str, Any]:
        data: dict[str, Any] = {}
        index = 0
        while f"user{index}" in variables:
            data[f"user{index}"] = {
                "permissionsInfo": {
                    "repositories": self._connection(
                        self._explicit_repository_nodes_for_user(variables[f"user{index}"])
                    )
                }
            }
            index += 1
        return data

    def _repository_names_by_id(self, variables: dict[str, object]) -> dict[str, Any]:
        data: dict[str, Any] = {}
        index = 0
        while f"repo{index}" in variables:
            repository_id_value = variables[f"repo{index}"]
            if not isinstance(repository_id_value, str):
                raise AssertionError(f"repo{index} variable must be a string")
            repository = self._repos_by_graphql_id.get(repository_id_value)
            data[f"repo{index}"] = self._graphql_repository(repository) if repository else None
            index += 1
        return data

    def _set_repo_permissions(self, variables: dict[str, object]) -> None:
        repository_id = self._repository_integer_id(variables["repo"])
        user_permissions = cast(list[dict[str, str]], variables["userPerms"])
        self._permissions_by_repository_id[repository_id] = {
            user_permission["bindID"] for user_permission in user_permissions
        }
        self._mutation_count += 1

    def _add_repo_permission(self, variables: dict[str, object]) -> None:
        repository_id = self._repository_integer_id(variables["repo"])
        username = self._username_from_user_graphql_id(variables["user"])
        self._permissions_by_repository_id[repository_id].add(username)
        self._mutation_count += 1

    def _remove_repo_permission(self, variables: dict[str, object]) -> None:
        repository_id = self._repository_integer_id(variables["repo"])
        username = self._username_from_user_graphql_id(variables["user"])
        self._permissions_by_repository_id[repository_id].discard(username)
        self._mutation_count += 1

    def _repository_integer_id(self, repository_id_value: object) -> int:
        if not isinstance(repository_id_value, str):
            raise AssertionError("repo variable must be a string")
        return src.decode_repository_id(repository_id_value)

    def _username_from_user_graphql_id(self, user_id_value: object) -> str:
        if not isinstance(user_id_value, str):
            raise AssertionError("user variable must be a string")
        return self._users_by_graphql_id[user_id_value]["username"]

    def _graphql_repository(self, repository: FixtureRepo | None) -> dict[str, Any] | None:
        if repository is None:
            return None
        return {"id": self._repository_graphql_id(repository["id"]), "name": repository["name"]}

    def _connection(self, nodes: list[dict[str, Any]]) -> dict[str, Any]:
        return {"nodes": nodes, "pageInfo": {"hasNextPage": False, "endCursor": None}}

    def _integer_variable(self, variables: dict[str, object], name: str) -> int:
        value = variables.get(name)
        if not isinstance(value, int):
            raise AssertionError(f"{name} variable must be an integer")
        return value

    def _user_graphql_id(self, user_id: int) -> str:
        return src.encode_sourcegraph_node_id("User", user_id)

    def _repository_graphql_id(self, repository_id: int) -> str:
        return src.encode_repository_id(repository_id)

    def _external_service_graphql_id(self, external_service_id: int) -> str:
        return src.encode_sourcegraph_node_id("ExternalService", external_service_id)


def fixture_case_dirs() -> list[Path]:
    return sorted(path for path in FIXTURES_DIR.iterdir() if path.is_dir())


def run_fixture_case(case_dir: Path) -> FixtureRunResult:
    case = load_case(case_dir / "case.json")
    before_state = load_state(case_dir / "before.json")
    expected_state = FakeSourcegraphClient(load_state(case_dir / "after.json")).export_state()
    client = FakeSourcegraphClient(before_state)
    command_failure: str | None = None

    try:
        config = config_for_case(case, case_dir / "maps.yaml", client.endpoint)
        command = cli.resolve_command("set", config)
        with ThreadPoolExecutor(max_workers=config.parallelism) as worker_pool:
            cli.run_command(
                config,
                command,
                cast(src.SourcegraphClient, client),
                worker_pool,
            )
    except SystemExit as exception:
        command_failure = f"SystemExit: {exception.code!r}"
    except Exception as exception:
        command_failure = f"{type(exception).__name__}: {exception}"

    actual_state = client.export_state()
    return FixtureRunResult(
        name=case_dir.name,
        description=case["description"],
        before_counts=state_counts(before_state),
        expected_counts=state_counts(expected_state),
        actual_counts=state_counts(actual_state),
        expected_mutations=case.get("expectedMutations"),
        actual_mutations=client.mutation_count,
        expected_state=expected_state,
        actual_state=actual_state,
        command_failure=command_failure,
    )


def state_counts(state: FixtureState) -> FixtureStateCounts:
    return FixtureStateCounts(
        users=len(state["users"]),
        repos=len(state["repos"]),
        permission_pairs=sum(
            len(repository["explicitPermissionsUsers"]) for repository in state["repos"]
        ),
    )


def config_for_case(case: FixtureCase, maps_path: Path, endpoint: str) -> cli.Config:
    set_options = case["set"]
    updates: dict[str, object] = {
        "maps_path": maps_path,
        "apply": True,
        "no_backup": True,
        "parallelism": 1,
        "full": bool(set_options.get("full", False)),
        "users": tuple(set_options.get("users", [])),
        "users_without_explicit_perms": bool(set_options.get("usersWithoutExplicitPerms", False)),
        "created_after": set_options.get("createdAfter"),
    }
    return cli.Config(
        src_endpoint=endpoint,
        src_access_token="fixture-token",
    ).model_copy(update=updates)


def load_case(path: Path) -> FixtureCase:
    return cast(FixtureCase, json.loads(path.read_text(encoding="utf-8")))


def load_state(path: Path) -> FixtureState:
    return cast(FixtureState, json.loads(path.read_text(encoding="utf-8")))


class PermissionFixtureCaseTests(unittest.TestCase):
    maxDiff = None

    def test_permission_fixture_cases(self) -> None:
        for case_dir in fixture_case_dirs():
            with self.subTest(case=case_dir.name):
                result = run_fixture_case(case_dir)
                self.assertIsNone(result.command_failure)
                self.assertEqual(result.expected_state, result.actual_state)
                if result.expected_mutations is not None:
                    self.assertEqual(result.expected_mutations, result.actual_mutations)


if __name__ == "__main__":
    unittest.main(verbosity=2)
