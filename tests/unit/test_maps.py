from __future__ import annotations

import base64
import itertools
import tempfile
import unittest
from pathlib import Path
from typing import cast

import yaml

from src_auth_perms_sync.permissions import full_set, mapping, maps
from src_auth_perms_sync.permissions import queries as permission_queries
from src_auth_perms_sync.permissions import types as permission_types
from src_auth_perms_sync.shared import queries as shared_queries
from src_auth_perms_sync.shared import types as shared_types


class MapsTests(unittest.TestCase):
    def test_create_maps_yaml_if_missing_preserves_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            maps_path = Path(directory_name) / "nested" / "maps.yaml"

            self.assertTrue(maps.create_maps_yaml_if_missing(maps_path))
            created_content = maps_path.read_text()
            self.assertIn("maps:", created_content)
            maps_path.write_text("maps: []\n")

            self.assertFalse(maps.create_maps_yaml_if_missing(maps_path))
            self.assertEqual("maps: []\n", maps_path.read_text())

    def test_default_maps_yaml_is_valid_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            maps_path = Path(directory_name) / "maps.yaml"

            maps.create_maps_yaml_if_missing(maps_path)

            self.assertEqual({"maps": [{"name": "Map 1"}]}, yaml.safe_load(maps_path.read_text()))

    def test_count_users_per_provider_counts_each_user_once_per_provider(self) -> None:
        users: list[shared_types.User] = [
            {
                "id": "user-1",
                "username": "alice",
                "builtinAuth": True,
                "externalAccounts": {
                    "nodes": [
                        {
                            "serviceType": "saml",
                            "serviceID": "https://idp.example.com",
                            "clientID": "sourcegraph",
                        },
                        {
                            "serviceType": "saml",
                            "serviceID": "https://idp.example.com",
                            "clientID": "sourcegraph",
                        },
                    ]
                },
            },
            {
                "id": "user-2",
                "username": "bob",
                "builtinAuth": False,
                "externalAccounts": {
                    "nodes": [
                        {
                            "serviceType": "github",
                            "serviceID": "https://github.com/",
                            "clientID": "github-client",
                        }
                    ]
                },
            },
        ]

        counts = maps.count_users_per_provider(users)

        self.assertEqual(1, counts[maps.BUILTIN_PROVIDER_KEY])
        self.assertEqual(1, counts[("saml", "https://idp.example.com", "sourcegraph")])
        self.assertEqual(1, counts[("github", "https://github.com/", "github-client")])


class MappingTests(unittest.TestCase):
    def test_mapping_rules_need_user_emails_tracks_email_filters(self) -> None:
        rules_without_email_filters = cast(
            list[permission_types.MappingRule],
            [
                {
                    "users": {"usernames": ["alice"]},
                    "repos": {"names": ["github.com/example/private-repo"]},
                }
            ],
        )
        rules_with_email_filters = cast(
            list[permission_types.MappingRule],
            [
                {
                    "users": {"emails": ["alice@example.com"]},
                    "repos": {"names": ["github.com/example/private-repo"]},
                }
            ],
        )

        self.assertFalse(mapping.mapping_rules_need_user_emails(rules_without_email_filters))
        self.assertTrue(mapping.mapping_rules_need_user_emails(rules_with_email_filters))

    def test_user_filter_matchers_intersect_without_expanding_selection(self) -> None:
        providers: list[shared_types.AuthProvider] = [
            {
                "serviceType": "builtin",
                "serviceID": "",
                "clientID": "",
                "displayName": "Builtin",
                "isBuiltin": True,
                "configID": "",
            }
        ]
        users = [
            self.make_user("user-1", "alice", True, "alice@example.com", True),
            self.make_user("user-2", "bob", True, "bob@example.com", True),
            self.make_user("user-3", "carol", True, "carol@example.com", False),
            self.make_user("user-4", "dana", False, "dana@example.com", True),
        ]
        user_filters: dict[str, object] = {
            "authProvider": {"type": "builtin"},
            "emails": ["alice@example.com", "carol@example.com", "dana@example.com"],
            "usernames": ["alice", "bob", "carol"],
        }
        single_filter_usernames = {
            name: self.usernames_for(
                mapping.resolve_users({name: matcher}, users, providers),
            )
            for name, matcher in user_filters.items()
        }

        for filter_count in range(2, len(user_filters) + 1):
            for filter_names in itertools.combinations(user_filters, filter_count):
                matched_usernames = self.usernames_for(
                    mapping.resolve_users(
                        {name: user_filters[name] for name in filter_names},
                        users,
                        providers,
                    )
                )
                expected_usernames = self.intersection_for(filter_names, single_filter_usernames)

                self.assertEqual(expected_usernames, matched_usernames)
                for name in filter_names:
                    self.assertLessEqual(matched_usernames, single_filter_usernames[name])

        self.assertEqual(
            {"alice"},
            self.usernames_for(mapping.resolve_users(user_filters, users, providers)),
        )

    def test_repo_filter_matchers_intersect_without_expanding_selection(self) -> None:
        sourcegraph_repo = self.make_repo("repo-1", "github.com/sourcegraph/sourcegraph")
        example_private_repo = self.make_repo("repo-2", "github.com/example/private-repo")
        gitlab_repo = self.make_repo("repo-3", "gitlab.com/example/private-repo")
        example_public_repo = self.make_repo("repo-4", "github.com/example/public-repo")
        all_repos = {
            sourcegraph_repo["id"]: sourcegraph_repo,
            example_private_repo["id"]: example_private_repo,
            gitlab_repo["id"]: gitlab_repo,
            example_public_repo["id"]: example_public_repo,
        }
        services_by_id = {
            1: self.make_external_service(1, "GITHUB", "GitHub Enterprise"),
            2: self.make_external_service(2, "GITHUB", "GitHub Cloud"),
        }
        repos_by_external_service_id = {
            1: [sourcegraph_repo, example_private_repo, gitlab_repo],
            2: [example_public_repo],
        }
        repo_filters: dict[str, object] = {
            "codeHostConnection": {"id": 1},
            "names": [
                "github.com/example/private-repo",
                "gitlab.com/example/private-repo",
            ],
            "regexes": [
                r"^github\.com/example/",
                r"^gitlab\.com/example/",
            ],
        }
        single_filter_repo_names = {
            name: self.repo_names_for(
                mapping.resolve_repos(
                    {name: matcher},
                    services_by_id,
                    repos_by_external_service_id,
                    all_repos,
                )
            )
            for name, matcher in repo_filters.items()
        }

        for filter_count in range(2, len(repo_filters) + 1):
            for filter_names in itertools.combinations(repo_filters, filter_count):
                matched_repo_names = self.repo_names_for(
                    mapping.resolve_repos(
                        {name: repo_filters[name] for name in filter_names},
                        services_by_id,
                        repos_by_external_service_id,
                        all_repos,
                    )
                )
                expected_repo_names = self.intersection_for(filter_names, single_filter_repo_names)

                self.assertEqual(expected_repo_names, matched_repo_names)
                for name in filter_names:
                    self.assertLessEqual(matched_repo_names, single_filter_repo_names[name])

        self.assertEqual(
            {"github.com/example/private-repo", "gitlab.com/example/private-repo"},
            self.repo_names_for(
                mapping.resolve_repos(
                    repo_filters,
                    services_by_id,
                    repos_by_external_service_id,
                    all_repos,
                )
            ),
        )

    def test_validate_mapping_rules_accepts_string_list_filters(self) -> None:
        mapping.validate_mapping_rules(
            cast(
                list[permission_types.MappingRule],
                [
                    {
                        "users": {
                            "emails": ["alice@example.com"],
                            "usernames": ["alice"],
                        },
                        "repos": {
                            "names": ["github.com/example/private-repo"],
                            "regexes": [r"^github\.com/example/"],
                        },
                    }
                ],
            )
        )

    def test_repos_regexes_match_any_pattern(self) -> None:
        sourcegraph_repo = self.make_repo("repo-1", "github.com/sourcegraph/sourcegraph")
        github_repo = self.make_repo("repo-2", "github.com/example/private-repo")
        gitlab_repo = self.make_repo("repo-3", "gitlab.com/example/private-repo")
        all_repos = {
            sourcegraph_repo["id"]: sourcegraph_repo,
            github_repo["id"]: github_repo,
            gitlab_repo["id"]: gitlab_repo,
        }

        matched_repos = mapping.resolve_repos(
            {
                "regexes": [
                    r"^github\.com/example/",
                    r"^gitlab\.com/example/",
                ],
            },
            {},
            {},
            all_repos,
        )

        self.assertEqual(
            {"github.com/example/private-repo", "gitlab.com/example/private-repo"},
            self.repo_names_for(matched_repos),
        )

    def test_validate_mapping_rules_rejects_non_string_list_filters(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            mapping.validate_mapping_rules(
                cast(
                    list[permission_types.MappingRule],
                    [
                        {
                            "users": {
                                "emails": "alice@example.com",
                                "usernames": [""],
                            },
                            "repos": {
                                "names": [123],
                                "regexes": ["["],
                            },
                        },
                        {
                            "users": {"usernames": ["alice"]},
                            "repos": {"regex": r"^github\.com/example/"},
                        },
                    ],
                )
            )

        message = str(raised.exception)
        self.assertIn("users.emails must be a list of strings", message)
        self.assertIn("users.usernames[0] is an empty string", message)
        self.assertIn("repos.names[0] must be a string", message)
        self.assertIn("repos.regexes[0] is not a valid Python regex", message)
        self.assertIn("unknown repos matcher 'regex'", message)

    def make_user(
        self,
        user_id: str,
        username: str,
        builtin_auth: bool,
        email: str,
        verified: bool,
    ) -> shared_types.User:
        return {
            "id": user_id,
            "username": username,
            "builtinAuth": builtin_auth,
            "emails": [{"email": email, "verified": verified}],
            "externalAccounts": {"nodes": []},
        }

    def make_repo(self, repo_id: str, name: str) -> permission_types.Repository:
        return {"id": repo_id, "name": name}

    def make_external_service(
        self,
        external_service_id: int,
        kind: str,
        display_name: str,
    ) -> permission_types.ExternalService:
        graphql_id = base64.b64encode(f"ExternalService:{external_service_id}".encode()).decode()
        return {
            "id": graphql_id,
            "kind": kind,
            "displayName": display_name,
            "url": f"https://code-host-{external_service_id}.example.com",
            "repoCount": 0,
            "createdAt": "2026-05-30T00:00:00Z",
            "updatedAt": "2026-05-30T00:00:00Z",
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

    def usernames_for(self, users: list[shared_types.User]) -> set[str]:
        return {user["username"] for user in users}

    def repo_names_for(self, repos: list[permission_types.Repository]) -> set[str]:
        return {repo["name"] for repo in repos}

    def intersection_for(
        self, names: tuple[str, ...], sets_by_name: dict[str, set[str]]
    ) -> set[str]:
        matched = set(sets_by_name[names[0]])
        for name in names[1:]:
            matched &= sets_by_name[name]
        return matched


class FullSetPlanningTests(unittest.TestCase):
    def test_full_set_plan_reuses_user_tuple_for_non_overlapping_repos(self) -> None:
        users = [self.make_user("user-1", "bob"), self.make_user("user-2", "alice")]
        repositories = [
            self.make_repo("repo-1", "github.com/example/one"),
            self.make_repo("repo-2", "github.com/example/two"),
        ]
        context = self.make_context(
            [
                {
                    "users": {"usernames": ["alice", "bob"]},
                    "repos": {"names": ["github.com/example/one", "github.com/example/two"]},
                }
            ],
            repositories,
        )

        plan = full_set.plan_full_set_permissions(context, users)

        self.assertEqual(("alice", "bob"), plan.expected_users["repo-1"])
        self.assertEqual(("alice", "bob"), plan.expected_users["repo-2"])
        self.assertIs(plan.expected_users["repo-1"], plan.expected_users["repo-2"])
        self.assertEqual(4, plan.total_grants)

    def test_full_set_plan_unions_only_overlapping_repos(self) -> None:
        users = [
            self.make_user("user-1", "alice"),
            self.make_user("user-2", "bob"),
            self.make_user("user-3", "chris"),
        ]
        repositories = [
            self.make_repo("repo-1", "github.com/example/one"),
            self.make_repo("repo-2", "github.com/example/two"),
            self.make_repo("repo-3", "github.com/example/three"),
        ]
        context = self.make_context(
            [
                {
                    "users": {"usernames": ["alice", "bob"]},
                    "repos": {"names": ["github.com/example/one", "github.com/example/two"]},
                },
                {
                    "users": {"usernames": ["bob", "chris"]},
                    "repos": {"names": ["github.com/example/two", "github.com/example/three"]},
                },
            ],
            repositories,
        )

        plan = full_set.plan_full_set_permissions(context, users)

        self.assertEqual(("alice", "bob"), plan.expected_users["repo-1"])
        self.assertEqual(("alice", "bob", "chris"), plan.expected_users["repo-2"])
        self.assertEqual(("bob", "chris"), plan.expected_users["repo-3"])
        self.assertEqual(7, plan.total_grants)

    def make_context(
        self,
        mapping_rules: list[permission_types.MappingRule],
        repositories: list[permission_types.Repository],
    ) -> permission_types.MappingContext:
        return permission_types.MappingContext(
            mapping_rules=mapping_rules,
            providers=[],
            saml_groups_attribute_names={},
            services_by_id={},
            repos_by_external_service_id={},
            all_repos_by_id={repository["id"]: repository for repository in repositories},
        )

    def make_user(self, user_id: str, username: str) -> shared_types.User:
        return {
            "id": user_id,
            "username": username,
            "builtinAuth": True,
            "emails": [],
            "externalAccounts": {"nodes": []},
        }

    def make_repo(self, repo_id: str, name: str) -> permission_types.Repository:
        return {"id": repo_id, "name": name}


class QueryTests(unittest.TestCase):
    def test_user_email_fields_are_opt_in(self) -> None:
        self.assertNotIn("emails {", shared_queries.QUERY_USERS)
        self.assertNotIn("emails {", shared_queries.query_users())
        self.assertIn("emails {", shared_queries.query_users(include_emails=True))

        self.assertNotIn("emails {", permission_queries.QUERY_USER_BY_ID)
        self.assertNotIn("emails {", permission_queries.query_user_by_id())
        self.assertIn("emails {", permission_queries.query_user_by_id(include_emails=True))
