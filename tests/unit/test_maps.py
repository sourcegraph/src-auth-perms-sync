from __future__ import annotations

import base64
import itertools
import json
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

    def test_external_service_to_yaml_lifts_username_without_config(self) -> None:
        service: permission_types.ExternalService = {
            "id": "RXh0ZXJuYWxTZXJ2aWNlOjE=",
            "kind": "BITBUCKETSERVER",
            "displayName": "Bitbucket LOB1",
            "url": "https://bitbucket.example.com/",
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
            "config": json.dumps({"username": "LOB1-SA1", "token": "REDACTED"}),
        }

        rendered = maps.external_service_to_yaml(service)

        self.assertEqual("LOB1-SA1", rendered["username"])
        self.assertNotIn("config", rendered)


class MappingTests(unittest.TestCase):
    def test_mapping_rules_need_user_emails_tracks_email_filters(self) -> None:
        rules_without_email_filters = cast(
            list[permission_types.MappingRule],
            [
                {
                    "name": "username only",
                    "users": {"usernames": ["alice"]},
                    "repos": {"names": ["github.com/example/private-repo"]},
                }
            ],
        )
        rules_with_email_filters = cast(
            list[permission_types.MappingRule],
            [
                {
                    "name": "email only",
                    "users": {"emails": ["alice@example.com"]},
                    "repos": {"names": ["github.com/example/private-repo"]},
                }
            ],
        )

        self.assertFalse(mapping.mapping_rules_need_user_emails(rules_without_email_filters))
        self.assertTrue(mapping.mapping_rules_need_user_emails(rules_with_email_filters))

    def test_mapping_rules_need_saml_account_data_tracks_saml_group_filters(self) -> None:
        rules_without_saml_group_filters = cast(
            list[permission_types.MappingRule],
            [
                {
                    "name": "provider only",
                    "users": {"authProvider": {"type": "saml"}},
                    "repos": {"names": ["github.com/example/private-repo"]},
                }
            ],
        )
        rules_with_saml_group_filters = cast(
            list[permission_types.MappingRule],
            [
                {
                    "name": "saml group",
                    "users": {"authProvider": {"type": "saml", "samlGroup": "eng"}},
                    "repos": {"names": ["github.com/example/private-repo"]},
                }
            ],
        )

        self.assertFalse(
            mapping.mapping_rules_need_saml_account_data(rules_without_saml_group_filters)
        )
        self.assertTrue(mapping.mapping_rules_need_saml_account_data(rules_with_saml_group_filters))

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
        user_fields: dict[str, object] = {
            "authProvider": {"type": "builtin"},
            "emails": ["alice@example.com", "carol@example.com", "dana@example.com"],
            "emailRegexes": [r"^(alice|bob|carol)@example\.com$"],
            "usernames": ["alice", "bob", "carol"],
            "usernameRegexes": [r"^(alice|dana)$"],
        }
        single_filter_usernames = {
            name: self.usernames_for(
                mapping.resolve_users(
                    cast(permission_types.UserSelector, {name: matcher}), users, providers
                ),
            )
            for name, matcher in user_fields.items()
        }

        for filter_count in range(2, len(user_fields) + 1):
            for filter_names in itertools.combinations(user_fields, filter_count):
                matched_usernames = self.usernames_for(
                    mapping.resolve_users(
                        cast(
                            permission_types.UserSelector,
                            {name: user_fields[name] for name in filter_names},
                        ),
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
            self.usernames_for(
                mapping.resolve_users(
                    cast(permission_types.UserSelector, user_fields), users, providers
                )
            ),
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
            1: self.make_external_service(1, "GITHUB", "GitHub Enterprise", "enterprise-sync"),
            2: self.make_external_service(2, "GITHUB", "GitHub Cloud", "cloud-sync"),
        }
        repos_by_external_service_id = {
            1: [sourcegraph_repo, example_private_repo, gitlab_repo],
            2: [example_public_repo],
        }
        repository_fields: dict[str, object] = {
            "codeHostConnection": {"username": "enterprise-sync"},
            "names": [
                "github.com/example/private-repo",
                "gitlab.com/example/private-repo",
            ],
            "nameRegexes": [r"^github\.com/example/"],
        }
        single_filter_repo_names = {
            name: self.repo_names_for(
                mapping.resolve_repos(
                    cast(permission_types.RepositorySelector, {name: matcher}),
                    services_by_id,
                    repos_by_external_service_id,
                    all_repos,
                )
            )
            for name, matcher in repository_fields.items()
        }

        for filter_count in range(2, len(repository_fields) + 1):
            for filter_names in itertools.combinations(repository_fields, filter_count):
                matched_repo_names = self.repo_names_for(
                    mapping.resolve_repos(
                        cast(
                            permission_types.RepositorySelector,
                            {name: repository_fields[name] for name in filter_names},
                        ),
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
            {"github.com/example/private-repo"},
            self.repo_names_for(
                mapping.resolve_repos(
                    cast(permission_types.RepositorySelector, repository_fields),
                    services_by_id,
                    repos_by_external_service_id,
                    all_repos,
                )
            ),
        )

    def test_service_ids_required_by_repository_selectors_uses_code_host_filter(self) -> None:
        services_by_id = {
            1: self.make_external_service(1, "GITHUB", "GitHub Enterprise", "enterprise-sync"),
            2: self.make_external_service(2, "GITHUB", "GitHub Cloud", "cloud-sync"),
        }

        service_ids = mapping.service_ids_required_by_repository_selectors(
            services_by_id,
            [
                cast(
                    permission_types.RepositorySelector,
                    {"codeHostConnection": {"displayName": "GitHub Enterprise"}},
                )
            ],
        )

        self.assertEqual({1}, service_ids)

    def test_service_ids_required_by_repository_selectors_loads_all_for_global_filter(
        self,
    ) -> None:
        services_by_id = {
            1: self.make_external_service(1, "GITHUB", "GitHub Enterprise"),
            2: self.make_external_service(2, "GITLAB", "GitLab"),
        }

        service_ids = mapping.service_ids_required_by_repository_selectors(
            services_by_id,
            [cast(permission_types.RepositorySelector, {"nameRegexes": [".*"]})],
        )

        self.assertEqual({1, 2}, service_ids)

    def test_validate_mapping_rules_accepts_flat_text_selector_lists(self) -> None:
        mapping.validate_mapping_rules(
            cast(
                list[permission_types.MappingRule],
                [
                    {
                        "name": "flat selector lists",
                        "users": {
                            "emails": ["alice@example.com"],
                            "emailRegexes": [r"^team-.*@example\.com$"],
                            "usernames": ["alice"],
                            "usernameRegexes": [r"^team-.*"],
                        },
                        "repos": {
                            "names": ["github.com/example/private-repo"],
                            "nameRegexes": [r"^github\.com/example/"],
                        },
                    }
                ],
            )
        )

    def test_repository_name_matches_any_pattern(self) -> None:
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
                "nameRegexes": [
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

    def test_username_matches_any_pattern(self) -> None:
        providers: list[shared_types.AuthProvider] = []
        users = [
            self.make_user("user-1", "alice", True, "alice@example.com", True),
            self.make_user("user-2", "test_user_00001", True, "one@example.com", True),
            self.make_user("user-3", "test_user_00100", True, "hundred@example.com", True),
            self.make_user("user-4", "service-account", True, "service@example.com", True),
        ]

        matched_users = mapping.resolve_users(
            {"usernameRegexes": [r"^(alice|test_user_00[0-9]{3})$"]},
            users,
            providers,
        )

        self.assertEqual(
            {"alice", "test_user_00001", "test_user_00100"},
            self.usernames_for(matched_users),
        )

    def test_validate_mapping_rules_rejects_invalid_text_matchers(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            mapping.validate_mapping_rules(
                cast(
                    list[permission_types.MappingRule],
                    [
                        {
                            "name": "invalid flat selector lists",
                            "users": {
                                "emails": "alice@example.com",
                                "usernames": [""],
                            },
                            "repos": {"names": [123], "nameRegexes": ["["]},
                        },
                        {
                            "name": "invalid code host field",
                            "users": {"usernames": ["alice"]},
                            "repos": {
                                "codeHostConnection": {"config": {"username": "old"}, "id": 1},
                                "regex": r"^github\.com/example/",
                            },
                        },
                        {
                            "name": "invalid username regex",
                            "users": {"usernameRegexes": ["["]},
                            "repos": {"names": ["github.com/example/private-repo"]},
                        },
                        {
                            "users": {"usernames": ["alice"]},
                            "repos": {"names": ["github.com/example/private-repo"]},
                        },
                    ],
                )
            )

        message = str(raised.exception)
        self.assertIn("users.emails must be a list of strings", message)
        self.assertIn("users.usernames[0] is an empty string", message)
        self.assertIn("repos.names[0] must be a string", message)
        self.assertIn("repos.nameRegexes[0] is not a valid Python regex", message)
        self.assertIn("users.usernameRegexes[0] is not a valid Python regex", message)
        self.assertIn("unknown repos field 'regex'", message)
        self.assertIn("unknown repos.codeHostConnection field 'config'", message)
        self.assertIn("unknown repos.codeHostConnection field 'id'", message)
        self.assertIn("`name:` is missing", message)

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
        username: str | None = None,
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
            "config": json.dumps({"username": username} if username else {}),
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
                    "name": "alice and bob get example repos",
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
                    "name": "alice and bob get first repos",
                    "users": {"usernames": ["alice", "bob"]},
                    "repos": {"names": ["github.com/example/one", "github.com/example/two"]},
                },
                {
                    "name": "bob and chris get second repos",
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

    def test_account_data_fields_are_opt_out(self) -> None:
        self.assertIn("accountData", shared_queries.QUERY_USERS)
        self.assertIn("accountData", shared_queries.query_users())
        self.assertNotIn("accountData", shared_queries.query_users(include_account_data=False))

        self.assertIn("accountData", permission_queries.QUERY_USER_BY_ID)
        self.assertIn("accountData", permission_queries.query_user_by_id())
        self.assertNotIn(
            "accountData",
            permission_queries.query_user_by_id(include_account_data=False),
        )
