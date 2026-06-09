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
