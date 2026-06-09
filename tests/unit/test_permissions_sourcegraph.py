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


class _UsersByIDClient:
    def __init__(self, missing_user_ids: set[str] | None = None) -> None:
        self.missing_user_ids = missing_user_ids or set()
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
            raise AssertionError("expected user variables")
        if follow_pages:
            raise AssertionError("user batch should not ask the client to follow pages")
        self.calls.append(dict(variables))
        self.queries.append(query)
        response: dict[str, object] = {}
        for variable_name, variable_value in variables.items():
            if not variable_name.startswith("user"):
                continue
            if not isinstance(variable_value, str):
                raise AssertionError("expected user ID variable")
            user_index = int(variable_name.removeprefix("user"))
            response[f"user{user_index}"] = (
                None
                if variable_value in self.missing_user_ids
                else {
                    "id": variable_value,
                    "username": variable_value.replace("user-", "username-"),
                    "builtinAuth": False,
                    "externalAccounts": {"nodes": []},
                }
            )
        return cast(src.JSONDict, response)


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


class PermissionsSourcegraphTests(unittest.TestCase):
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

    def test_get_users_by_ids_batches_user_hydration(self) -> None:
        client = _UsersByIDClient(missing_user_ids={"user-2"})

        users = permissions_sourcegraph.get_users_by_ids(
            cast(src.SourcegraphClient, client),
            ["user-1", "user-2", "user-3"],
        )

        self.assertEqual(
            [user["id"] if user else None for user in users],
            ["user-1", None, "user-3"],
        )
        self.assertEqual(
            client.calls,
            [{"user0": "user-1", "user1": "user-2", "user2": "user-3"}],
        )
        self.assertEqual(len(client.queries), 1)
        self.assertIn("query UsersByIDBatch", client.queries[0])
        self.assertIn("externalAccounts(first: 50)", client.queries[0])
        self.assertNotIn("emails {", client.queries[0])

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
