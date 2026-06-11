"""Execution engine for the tests/tests.yaml case registry.

Loads the registry, builds in-memory Sourcegraph instances from
fixture state files (FakeSourcegraphClient), and runs cases through
the real CLI code paths: full command runs for state cases, and
in-process argument-parser replays for replay-style cases.

Consumed by tests/run.py (local checks and randomized invariants) and
by tests/e2e/test_local_cases.py (unittest discovery entrypoint).
"""

from __future__ import annotations

import contextlib
import io
import json
import shlex
import sys
from collections.abc import Iterator, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NotRequired, TypedDict, cast

import src_py_lib as src
import yaml

from src_auth_perms_sync import cli
from src_auth_perms_sync.shared import types as shared_types

FIXTURES_DIR = Path(__file__).with_name("fixtures")

# Maximum site-users page width the fake serves, regardless of the requested
# limit. Small enough that fixtures with a handful of users span multiple
# pages, so pagination handling is functionally tested without scale data.
SITE_USERS_PAGE_CAP = 2
E2E_TESTS_PATH = Path(__file__).resolve().parents[1] / "tests.yaml"
DEFAULT_CASE_MODES = ["local"]
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
    createdAt: NotRequired[str]  # default: 2026-01-01T00:00:00Z


class FixtureState(TypedDict):
    endpoint: str
    authProviders: list[shared_types.AuthProvider]
    externalServices: list[FixtureExternalService]
    users: list[FixtureUser]
    repos: list[FixtureRepo]
    pendingBindIDs: list[str]


class FixtureCase(TypedDict):
    """One entry under `cases:` in tests.yaml. See that file for docs."""

    description: str
    modes: NotRequired[list[str]]  # local, live, performance (default: [local])
    cliCommand: NotRequired[str]  # CLI arguments; --maps-path is appended for set
    importConfig: NotRequired[dict[str, Any]]  # Python-import-mode Config fields
    expectedMutations: NotRequired[int]
    # When set, the command must fail, every listed substring must appear in
    # the failure text, and the instance state must be left unchanged.
    expectedErrors: NotRequired[list[str]]
    # Either of these makes the case replay-style: assert exit code and
    # output substrings instead of instance state. Locally, replay cases run
    # the real argument parser in-process and need no fixture files.
    expectedExitCode: NotRequired[int]
    expectedOutput: NotRequired[list[str]]


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
    expected_changed_repos: int
    actual_changed_repos: int
    expected_mutations: int | None
    actual_mutations: int
    expected_state: FixtureState
    actual_state: FixtureState
    command_failure: str | None = None
    expected_errors: tuple[str, ...] = ()
    runner: str = "cli"  # "cli" (parsed argv) or "import" (programmatic Config)

    @property
    def failure(self) -> str | None:
        if self.expected_errors:
            return self._expected_error_failure()
        if self.command_failure is not None:
            return self.command_failure
        if self.expected_state != self.actual_state:
            return "actual state did not match after.json"
        if self.expected_mutations is not None and self.expected_mutations != self.actual_mutations:
            return f"expected {self.expected_mutations} mutation(s), got {self.actual_mutations}"
        return None

    def _expected_error_failure(self) -> str | None:
        if self.command_failure is None:
            return "expected the command to fail validation, but it succeeded"
        missing = [
            expected for expected in self.expected_errors if expected not in self.command_failure
        ]
        if missing:
            return (
                f"command failure did not contain expected error(s) {missing}; "
                f"got: {self.command_failure}"
            )
        if self.expected_state != self.actual_state:
            return "state changed during a run that was expected to fail validation"
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
        if "query UserExplicitRepoExistsBatch" in query:
            batch_data: dict[str, Any] = {}
            index = 0
            while f"user{index}" in variable_values:
                batch_data[f"user{index}"] = self._user_explicit_repo_exists(
                    variable_values[f"user{index}"]
                )
                index += 1
            return batch_data
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
            if "esID" in variable_values:
                return iter(self._repositories_for_external_service(variable_values["esID"]))
            return iter(self._repository_candidates(variable_values))
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

    def _repository_candidates(self, variables: dict[str, object]) -> list[dict[str, Any]]:
        """Serve the repository-candidate queries (by names, all, by created-at).

        The created-at variant orders newest-first server-side and is filtered
        client-side by the CLI, so no date filtering happens here.
        """
        repositories = self._repos
        names_value = variables.get("names")
        if isinstance(names_value, list):
            wanted_names = set(cast("list[str]", names_value))
            repositories = [
                repository for repository in repositories if repository["name"] in wanted_names
            ]
        else:
            # The created-at candidate query returns newest first, and the CLI
            # stops streaming at the first repo older than the threshold.
            repositories = sorted(
                repositories,
                key=lambda repository: repository.get("createdAt", "2026-01-01T00:00:00Z"),
                reverse=True,
            )
        return [
            {
                "id": self._repository_graphql_id(repository["id"]),
                "name": repository["name"],
                "createdAt": repository.get("createdAt", "2026-01-01T00:00:00Z"),
                "externalServices": {
                    "nodes": [
                        {"id": self._external_service_graphql_id(repository["externalServiceID"])}
                    ]
                },
            }
            for repository in repositories
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
        # Serve pages no wider than SITE_USERS_PAGE_CAP regardless of the
        # requested limit, mimicking a server-side nodes(limit:) cap. This
        # makes every local fixture with >2 users exercise multi-page
        # candidate selection (offset stepping, dedupe, the sequential
        # paging branch). The 2026-06-10 first-page-only truncation bug is
        # invisible to local tests without this.
        limit = min(self._integer_variable(variables, "limit"), SITE_USERS_PAGE_CAP)
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


def load_e2e_cases() -> dict[str, FixtureCase]:
    """Load the case registry from tests.yaml, keyed by fixture dir name."""
    raw = cast("dict[str, Any]", yaml.safe_load(E2E_TESTS_PATH.read_text(encoding="utf-8")))
    return cast("dict[str, FixtureCase]", raw["cases"])


def case_modes(case: FixtureCase) -> list[str]:
    return case.get("modes", DEFAULT_CASE_MODES)


def case_runners(case: FixtureCase) -> list[str]:
    """Return how a case runs in local mode: parsed argv and/or import API.

    Every state case with a cliCommand runs BOTH ways: once through the
    real argument parser, and once through the Python import API with a
    Config derived from the same command line — proving each behavior for
    CLI consumers and library consumers alike. An explicit importConfig
    overrides the derived one (for testing specific kwargs spellings).
    Replay cases assert parser behavior, which has no import equivalent.
    """
    if is_replay_case(case):
        return ["cli"] if "cliCommand" in case else []
    runners: list[str] = []
    if "cliCommand" in case:
        runners += ["cli", "import"]
    elif "importConfig" in case:
        runners.append("import")
    return runners


def case_cli_arguments(case: FixtureCase, case_name: str) -> list[str]:
    """Return cliCommand as argv, appending the case's maps file for set commands."""
    cli_command = case.get("cliCommand")
    if cli_command is None:
        raise ValueError(f"case {case_name!r} has no cliCommand")
    argv = shlex.split(cli_command)
    if argv and argv[0] == "set" and "--maps-path" not in argv:
        argv += ["--maps-path", str(FIXTURES_DIR / case_name / "maps.yaml")]
    return argv


def is_replay_case(case: FixtureCase) -> bool:
    """Replay-style cases assert exit code and output rather than state."""
    return "expectedExitCode" in case or "expectedOutput" in case


def expected_exit_code(case: FixtureCase) -> int:
    return case.get("expectedExitCode", 1 if case.get("expectedErrors") else 0)


def run_local_replay_case(case_name: str) -> str:
    """Run one replay case through the real argument parser in-process.

    Covers parse-level behavior: argument rejection (exit 2), --help (exit 0),
    and config validation errors. Returns a failure detail, or "" on success.
    """
    case = load_e2e_cases()[case_name]
    argv = case_cli_arguments(case, case_name)
    # A bare invocation (empty cliCommand) must stay bare: appending
    # credential flags would change the parse error under test.
    if argv and "--help" not in argv and "-h" not in argv:
        argv += [
            "--src-endpoint",
            "https://fixture.sourcegraph.test",
            "--src-access-token",
            "fixture-token",
        ]
    output_buffer = io.StringIO()
    exit_code = 0
    # argparse derives the usage `prog` from sys.argv[0]; pin it to the real
    # entrypoint name so replay output matches what operators see.
    original_argv0 = sys.argv[0]
    sys.argv[0] = "src-auth-perms-sync"
    try:
        with contextlib.redirect_stdout(output_buffer), contextlib.redirect_stderr(output_buffer):
            try:
                cli.load_cli(argv)
            except SystemExit as exception:
                exit_code = exception.code if isinstance(exception.code, int) else 1
    finally:
        sys.argv[0] = original_argv0
    output = output_buffer.getvalue()
    expected_exit = expected_exit_code(case)
    if exit_code != expected_exit:
        return f"expected exit {expected_exit}, got {exit_code}; output: {output[-300:]!r}"
    for substring in [*case.get("expectedOutput", []), *case.get("expectedErrors", [])]:
        if substring not in output:
            return f"output did not contain {substring!r}; output: {output[-300:]!r}"
    return ""


def required_case_files(case: FixtureCase) -> set[str]:
    """Return which files a case's fixture directory must contain.

    The directory itself is optional: a read-only non-set command needs no
    files at all. before.json is needed wherever instance state is built
    (local mode, and mutating live/performance runs); maps.yaml is needed by
    set commands that do not pass their own --maps-path / maps_path.
    Replay-style cases never get past argument parsing locally, so they need
    no files.
    """
    files: set[str] = set()
    if is_replay_case(case):
        return files
    modes = case_modes(case)
    argv = shlex.split(case["cliCommand"]) if "cliCommand" in case else []
    import_config = case.get("importConfig")
    if "local" in modes:
        files.add("before.json")
    if ({"live", "performance"} & set(modes)) and "--apply" in argv:
        files.add("before.json")
    if argv[:1] == ["set"] and "--maps-path" not in argv:
        files.add("maps.yaml")
    if (
        import_config is not None
        and import_config.get("command") == "set"
        and "maps_path" not in import_config
    ):
        files.add("maps.yaml")
    return files


def derived_import_input(case: FixtureCase, case_name: str, endpoint: str) -> cli.CliInput:
    """Build the import-API equivalent of a case's command line.

    Parses the cliCommand, then reconstructs the Config the way a library
    consumer would: keyword construction plus model_copy of the fields
    that differ from defaults. Asserting the same expected state through
    both entrypoints proves CLI and import parity for every case.
    """
    argv = case_cli_arguments(case, case_name)
    argv += ["--src-endpoint", endpoint, "--src-access-token", "fixture-token"]
    parsed = cli.load_cli(argv)
    defaults = cli.Config(src_endpoint=endpoint, src_access_token="fixture-token")
    updates = {
        name: getattr(parsed.config, name)
        for name in type(parsed.config).model_fields
        if getattr(parsed.config, name) != getattr(defaults, name)
    }
    config = defaults.model_copy(update=updates)
    return cli.CliInput(command_name=parsed.command_name, config=config)


def cli_input_for_case(
    case: FixtureCase, case_name: str, endpoint: str, runner: str
) -> cli.CliInput:
    """Build the parsed command for one case, via argv or the import API."""
    if runner == "cli":
        argv = case_cli_arguments(case, case_name)
        argv += ["--src-endpoint", endpoint, "--src-access-token", "fixture-token"]
        return cli.load_cli(argv)
    import_config = case.get("importConfig")
    if import_config is None:
        return derived_import_input(case, case_name, endpoint)
    options = dict(import_config)
    command_name = cast(cli.CommandName, options.pop("command"))
    updates: dict[str, object] = {
        name: tuple(cast("list[object]", value)) if isinstance(value, list) else value
        for name, value in options.items()
    }
    if command_name == "set" and "maps_path" not in updates:
        updates["maps_path"] = FIXTURES_DIR / case_name / "maps.yaml"
    config = cli.Config(
        src_endpoint=endpoint,
        src_access_token="fixture-token",
    ).model_copy(update=updates)
    return cli.CliInput(command_name=command_name, config=config)


def run_fixture_case(case_name: str, runner: str = "cli") -> FixtureRunResult:
    case = load_e2e_cases()[case_name]
    case_dir = FIXTURES_DIR / case_name
    before_state = load_state(case_dir / "before.json")
    # after.json is optional: cases that must not change anything (no-op and
    # expected-validation-error cases) compare against the before state.
    after_path = case_dir / "after.json"
    expected_source = after_path if after_path.is_file() else case_dir / "before.json"
    expected_state = FakeSourcegraphClient(load_state(expected_source)).export_state()
    client = FakeSourcegraphClient(before_state)
    command_failure: str | None = None

    try:
        cli_input = cli_input_for_case(case, case_name, client.endpoint, runner)
        # Local runs execute in-process against the in-memory fake, where
        # client parallelism buys nothing and only adds scheduling
        # nondeterminism — pin it to 1 regardless of the case's command
        # line. Live/performance runs use the command line as written.
        local_config = cli_input.config.model_copy(update={"parallelism": 1})
        command = cli.resolve_command(cli_input.command_name, local_config)
        with ThreadPoolExecutor(max_workers=local_config.parallelism) as worker_pool:
            cli.run_command(
                local_config,
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
        name=case_name,
        description=case["description"],
        before_counts=state_counts(before_state),
        expected_counts=state_counts(expected_state),
        actual_counts=state_counts(actual_state),
        expected_changed_repos=changed_repo_count(before_state, expected_state),
        actual_changed_repos=changed_repo_count(before_state, actual_state),
        expected_mutations=case.get("expectedMutations"),
        actual_mutations=client.mutation_count,
        expected_state=expected_state,
        actual_state=actual_state,
        command_failure=command_failure,
        expected_errors=tuple(case.get("expectedErrors", [])),
        runner=runner,
    )


def state_counts(state: FixtureState) -> FixtureStateCounts:
    return FixtureStateCounts(
        users=len(state["users"]),
        repos=len(state["repos"]),
        permission_pairs=sum(
            len(repository["explicitPermissionsUsers"]) for repository in state["repos"]
        ),
    )


def changed_repo_count(before_state: FixtureState, after_state: FixtureState) -> int:
    before_permissions = repo_permission_users_by_id(before_state)
    after_permissions = repo_permission_users_by_id(after_state)
    return sum(
        1
        for repository_id in set(before_permissions) | set(after_permissions)
        if before_permissions.get(repository_id, ()) != after_permissions.get(repository_id, ())
    )


def repo_permission_users_by_id(state: FixtureState) -> dict[int, tuple[str, ...]]:
    return {
        repository["id"]: tuple(sorted(repository["explicitPermissionsUsers"]))
        for repository in state["repos"]
    }


def load_state(path: Path) -> FixtureState:
    return cast(FixtureState, json.loads(path.read_text(encoding="utf-8")))
