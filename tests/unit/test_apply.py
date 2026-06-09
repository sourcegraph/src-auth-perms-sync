from __future__ import annotations

import unittest
from typing import Any, cast

import src_py_lib as src

from src_auth_perms_sync.permissions import apply
from src_auth_perms_sync.permissions import types as permission_types


class _FakeSourcegraphClient:
    def __init__(self, exception: BaseException | None = None) -> None:
        self.exception = exception
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def graphql(self, query: str, variables: src.JSONDict) -> dict[str, Any]:
        self.calls.append((query, dict(variables)))
        if self.exception is not None:
            raise self.exception
        return {}


class ApplyTests(unittest.TestCase):
    def test_repo_not_found_overwrite_is_skipped_not_failed(self) -> None:
        client = _FakeSourcegraphClient(
            src.GraphQLError(
                "Sourcegraph GraphQL errors: [{'message': 'repo not found: id=264'}]",
                is_application_error=True,
            )
        )
        counts = apply.apply_username_overwrites(
            cast(src.SourcegraphClient, client),
            [
                permission_types.RepositoryUsernameOverwrite(
                    repository_id=src.encode_repository_id(264),
                    repository_name="test-repo-0241",
                    usernames=("alice",),
                )
            ],
            parallelism=1,
        )

        self.assertEqual(0, counts.succeeded)
        self.assertEqual(1, counts.skipped)
        self.assertEqual(0, counts.failed)
        self.assertEqual(0, counts.canceled)
        self.assertEqual(1, len(client.calls))

    def test_user_not_found_addition_is_skipped_not_failed(self) -> None:
        client = _FakeSourcegraphClient(
            src.GraphQLError(
                "Sourcegraph GraphQL errors: [{'message': 'user not found: id=123'}]",
                is_application_error=True,
            )
        )
        counts = apply.apply_additions(
            cast(src.SourcegraphClient, client),
            [
                apply.PermissionAddition(
                    user_id="VXNlcjoxMjM=",
                    username="deleted-user",
                    repo_id=src.encode_repository_id(264),
                    repo_name="test-repo-0241",
                )
            ],
            parallelism=1,
        )

        self.assertEqual(0, counts.succeeded)
        self.assertEqual(1, counts.skipped)
        self.assertEqual(0, counts.failed)
        self.assertEqual(0, counts.canceled)
        self.assertEqual(1, len(client.calls))

    def test_non_missing_graphql_error_is_failed(self) -> None:
        client = _FakeSourcegraphClient(
            src.GraphQLError(
                "Sourcegraph GraphQL errors: [{'message': 'permission denied'}]",
                is_application_error=True,
            )
        )
        counts = apply.apply_username_overwrites(
            cast(src.SourcegraphClient, client),
            [
                permission_types.RepositoryUsernameOverwrite(
                    repository_id=src.encode_repository_id(264),
                    repository_name="test-repo-0241",
                    usernames=("alice",),
                )
            ],
            parallelism=1,
        )

        self.assertEqual(0, counts.succeeded)
        self.assertEqual(0, counts.skipped)
        self.assertEqual(1, counts.failed)
        self.assertEqual(0, counts.canceled)


if __name__ == "__main__":
    unittest.main()
