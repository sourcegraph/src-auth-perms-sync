from __future__ import annotations

import threading
import unittest
from typing import cast

import src_py_lib as src

from src_auth_perms_sync.permissions import sourcegraph as permissions_sourcegraph


class _SiteUsersClient:
    def __init__(self, total_count: int) -> None:
        self.total_count = total_count
        self.calls: list[src.JSONDict] = []
        self.lock = threading.Lock()

    def graphql(
        self,
        query: str,
        variables: src.JSONDict | None = None,
        *,
        follow_pages: bool = True,
    ) -> src.JSONDict:
        del query, follow_pages
        if variables is None:
            raise AssertionError("expected SiteUsers variables")
        with self.lock:
            self.calls.append(dict(variables))

        limit_value = variables.get("limit")
        offset_value = variables.get("offset")
        if not isinstance(limit_value, int) or not isinstance(offset_value, int):
            raise AssertionError("expected integer limit and offset")

        page_nodes: list[dict[str, object]] = []
        for user_number in range(offset_value, min(offset_value + limit_value, self.total_count)):
            page_nodes.append(
                {
                    "id": f"user-{user_number}",
                    "username": f"user-{user_number}",
                    "email": None,
                    "createdAt": "2026-06-09T00:00:00Z",
                    "deletedAt": None,
                }
            )
        return cast(
            src.JSONDict,
            {"site": {"users": {"totalCount": self.total_count, "nodes": page_nodes}}},
        )


class _ExplicitReposClient:
    def __init__(self, explicit_user_ids: set[str]) -> None:
        self.explicit_user_ids = explicit_user_ids
        self.calls: list[src.JSONDict] = []
        self.queries: list[str] = []

    def graphql(
        self,
        query: str,
        variables: src.JSONDict | None = None,
        *,
        follow_pages: bool = True,
    ) -> src.JSONDict:
        if variables is None:
            raise AssertionError("expected explicit-repo variables")
        if follow_pages:
            raise AssertionError("existence batch should not ask the client to follow pages")
        self.calls.append(dict(variables))
        self.queries.append(query)

        response: dict[str, object] = {}
        for variable_name, variable_value in variables.items():
            if not variable_name.startswith("user"):
                continue
            if not isinstance(variable_value, str):
                raise AssertionError("expected user ID variable")
            user_index = int(variable_name.removeprefix("user"))
            permission_nodes: list[dict[str, str]] = []
            if variable_value in self.explicit_user_ids:
                permission_nodes.append({"id": "repo-with-explicit-grant"})
            response[f"user{user_index}"] = {
                "permissionsInfo": {
                    "repositories": {
                        "nodes": permission_nodes,
                    }
                }
            }
        return cast(src.JSONDict, response)


class _RepoConnectionClient:
    def __init__(self) -> None:
        self.page_sizes: list[int] = []
        self.variables: list[src.JSONDict | None] = []

    def stream_connection_nodes(
        self,
        query: str,
        variables: src.JSONDict | None = None,
        *,
        connection_path: tuple[str, ...],
        page_size: int,
    ) -> list[dict[str, str]]:
        del connection_path
        if "query ReposByExternalService" not in query:
            raise AssertionError(f"unexpected query: {query[:80]}")
        self.page_sizes.append(page_size)
        self.variables.append(variables)
        return [{"id": "repo-1", "name": "github.com/example/repo"}]


class _PipelinedCandidateClient:
    def __init__(self) -> None:
        self.total_count = 1001
        self.explicit_user_ids = {"user-10"}
        self.release_second_page = threading.Event()
        self.second_page_returned = threading.Event()
        self.explicit_started_before_second_page_returned = False

    def graphql(
        self,
        query: str,
        variables: src.JSONDict | None = None,
        *,
        follow_pages: bool = True,
    ) -> src.JSONDict:
        if variables is None:
            raise AssertionError("expected variables")
        if "query SiteUsers" in query:
            return self._site_users(variables)
        if "query UserExplicitRepoExistsBatch" in query:
            if not follow_pages:
                self.explicit_started_before_second_page_returned = bool(
                    self.explicit_started_before_second_page_returned
                    or not self.second_page_returned.is_set()
                )
                self.release_second_page.set()
                return self._explicit_repos(variables)
            raise AssertionError("existence batch should not ask the client to follow pages")
        raise AssertionError(f"unexpected query: {query[:80]}")

    def _site_users(self, variables: src.JSONDict) -> src.JSONDict:
        limit_value = variables.get("limit")
        offset_value = variables.get("offset")
        if not isinstance(limit_value, int) or not isinstance(offset_value, int):
            raise AssertionError("expected integer limit and offset")
        if offset_value == 1000:
            if not self.release_second_page.wait(timeout=5):
                raise AssertionError(
                    "explicit permission lookup did not start before page load finished"
                )
            self.second_page_returned.set()

        page_nodes: list[dict[str, object]] = []
        for user_number in range(offset_value, min(offset_value + limit_value, self.total_count)):
            page_nodes.append(
                {
                    "id": f"user-{user_number}",
                    "username": f"user-{user_number}",
                    "email": None,
                    "createdAt": "2026-06-09T00:00:00Z",
                    "deletedAt": None,
                }
            )
        return cast(
            src.JSONDict,
            {"site": {"users": {"totalCount": self.total_count, "nodes": page_nodes}}},
        )

    def _explicit_repos(self, variables: src.JSONDict) -> src.JSONDict:
        response: dict[str, object] = {}
        for variable_name, variable_value in variables.items():
            if not variable_name.startswith("user"):
                continue
            if not isinstance(variable_value, str):
                raise AssertionError("expected user ID variable")
            user_index = int(variable_name.removeprefix("user"))
            permission_nodes: list[dict[str, str]] = []
            if variable_value in self.explicit_user_ids:
                permission_nodes.append({"id": "repo-with-explicit-grant"})
            response[f"user{user_index}"] = {
                "permissionsInfo": {"repositories": {"nodes": permission_nodes}}
            }
        return cast(src.JSONDict, response)


class _UserHydrationClient:
    """Serves UsersByIDBatch; `missing_user_ids` hydrate to null nodes."""

    def __init__(self, missing_user_ids: set[str]) -> None:
        self.missing_user_ids = missing_user_ids
        self.calls: list[src.JSONDict] = []
        self.queries: list[str] = []

    def graphql(
        self,
        query: str,
        variables: src.JSONDict | None = None,
        *,
        follow_pages: bool = True,
    ) -> src.JSONDict:
        if variables is None:
            raise AssertionError("expected UsersByIDBatch variables")
        if follow_pages:
            raise AssertionError("hydration batch should not ask the client to follow pages")
        self.calls.append(dict(variables))
        self.queries.append(query)

        response: dict[str, object] = {}
        for variable_name, variable_value in variables.items():
            if not isinstance(variable_value, str):
                raise AssertionError("expected user ID variable")
            if variable_value in self.missing_user_ids:
                response[variable_name] = None
                continue
            response[variable_name] = {
                "id": variable_value,
                "username": f"name-of-{variable_value}",
                "builtinAuth": True,
                "externalAccounts": {"nodes": []},
            }
        return cast(src.JSONDict, response)


class PermissionsSourcegraphTests(unittest.TestCase):
    def test_get_users_by_ids_batches_hydration_and_preserves_order(self) -> None:
        requested_user_ids = [f"user-{user_number}" for user_number in range(60)]
        client = _UserHydrationClient(missing_user_ids={"user-30"})

        users = permissions_sourcegraph.get_users_by_ids(
            cast(src.SourcegraphClient, client),
            requested_user_ids,
            parallelism=1,
        )

        self.assertEqual(len(users), 60)
        self.assertIsNone(users[30])
        hydrated_ids = [user["id"] for user in users if user is not None]
        self.assertEqual(
            hydrated_ids,
            [user_id for user_id in requested_user_ids if user_id != "user-30"],
        )
        # 60 users at the hydration batch size of 25 → 3 requests.
        self.assertEqual([len(call) for call in client.calls], [25, 25, 10])
        for query in client.queries:
            self.assertIn("query UsersByIDBatch", query)
            self.assertNotIn("permissionsInfo", query)

    def test_list_repos_for_external_service_uses_larger_pages(self) -> None:
        client = _RepoConnectionClient()

        repos = permissions_sourcegraph.list_repos_for_external_service(
            cast(src.SourcegraphClient, client),
            "external-service-1",
        )

        self.assertEqual(repos, [{"id": "repo-1", "name": "github.com/example/repo"}])
        self.assertEqual(client.page_sizes, [1000])
        self.assertEqual(client.variables, [{"esID": "external-service-1"}])

    def test_list_site_user_candidates_uses_larger_pages(self) -> None:
        client = _SiteUsersClient(total_count=2500)

        candidates = permissions_sourcegraph.list_site_user_candidates(
            cast(src.SourcegraphClient, client),
            None,
            parallelism=4,
        )

        self.assertEqual(len(candidates), 2500)
        self.assertEqual(candidates[0]["id"], "user-0")
        self.assertEqual(candidates[-1]["id"], "user-2499")
        limits, offsets = _site_users_call_page_args(client.calls)
        self.assertEqual(set(limits), {1000})
        self.assertEqual(sorted(offsets), [0, 1000, 2000])

    def test_user_ids_with_explicit_repos_batches_existence_checks(self) -> None:
        client = _ExplicitReposClient({"user-2", "user-3"})

        explicit_user_ids = permissions_sourcegraph.user_ids_with_explicit_repos(
            cast(src.SourcegraphClient, client),
            ["user-1", "user-2", "user-3"],
            batch_size=2,
            parallelism=1,
        )

        self.assertEqual(explicit_user_ids, {"user-2", "user-3"})
        for query in client.queries:
            self.assertIn("query UserExplicitRepoExistsBatch", query)
            self.assertIn("repositories(source: API, first: 1)", query)
            self.assertNotIn("pageInfo", query)
            self.assertNotIn("after", query)
        self.assertEqual(
            [[call.get("user0"), call.get("user1")] for call in client.calls],
            [["user-1", "user-2"], ["user-3", None]],
        )
        for call in client.calls:
            self.assertNotIn("first", call)
            self.assertFalse(any(variable_name.startswith("after") for variable_name in call))

    def test_candidates_without_explicit_repos_pages_past_first_page_sequentially(self) -> None:
        # Regression: with parallelism=1 and more users than one page, the
        # selection used to silently consider ONLY the first page (1000
        # users) — every later user was excluded from candidates.
        site_users = _SiteUsersClient(total_count=2500)
        explicit_repos = _ExplicitReposClient({"user-1500"})

        class _CombinedClient:
            def graphql(
                self,
                query: str,
                variables: src.JSONDict | None = None,
                *,
                follow_pages: bool = True,
            ) -> src.JSONDict:
                if "query SiteUsers" in query:
                    return site_users.graphql(query, variables, follow_pages=follow_pages)
                if "query UserExplicitRepoExistsBatch" in query:
                    return explicit_repos.graphql(query, variables, follow_pages=follow_pages)
                raise AssertionError(f"unexpected query: {query[:80]}")

        selection = permissions_sourcegraph.list_site_user_candidates_without_explicit_repos(
            cast(src.SourcegraphClient, _CombinedClient()),
            None,
            batch_size=1000,
            parallelism=1,
        )

        self.assertEqual(selection.explicit_user_count, 1)
        self.assertEqual(len(selection.candidates), 2499)
        candidate_ids = {candidate["id"] for candidate in selection.candidates}
        self.assertIn("user-2499", candidate_ids)
        self.assertNotIn("user-1500", candidate_ids)
        _, offsets = _site_users_call_page_args(site_users.calls)
        self.assertEqual(sorted(offsets), [0, 1000, 2000])

    def test_candidates_without_explicit_repos_pipelines_checks_after_first_page(self) -> None:
        client = _PipelinedCandidateClient()

        selection = permissions_sourcegraph.list_site_user_candidates_without_explicit_repos(
            cast(src.SourcegraphClient, client),
            None,
            batch_size=1000,
            parallelism=2,
        )

        self.assertTrue(client.explicit_started_before_second_page_returned)
        self.assertEqual(selection.explicit_user_count, 1)
        self.assertEqual(len(selection.candidates), 1000)
        self.assertNotIn("user-10", {candidate["id"] for candidate in selection.candidates})


def _site_users_call_page_args(calls: list[src.JSONDict]) -> tuple[list[int], list[int]]:
    limits: list[int] = []
    offsets: list[int] = []
    for call in calls:
        limit_value = call.get("limit")
        offset_value = call.get("offset")
        if not isinstance(limit_value, int) or not isinstance(offset_value, int):
            raise AssertionError("expected integer limit and offset")
        limits.append(limit_value)
        offsets.append(offset_value)
    return limits, offsets


if __name__ == "__main__":
    unittest.main()
