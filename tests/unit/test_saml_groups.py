from __future__ import annotations

import unittest

from src_auth_perms_sync.shared import saml_groups
from src_auth_perms_sync.shared import types as shared_types


class SamlGroupTests(unittest.TestCase):
    def test_extract_saml_groups_from_raw_assertion_info(self) -> None:
        account_data = {
            "Assertions": [
                {
                    "AttributeStatement": {
                        "Attributes": [
                            {
                                "Name": "groups",
                                "Values": [
                                    {"Value": "engineering"},
                                    {"Value": "engineering"},
                                    {"Value": "platform"},
                                ],
                            },
                            {"Name": "email", "Values": [{"Value": "alice@example.com"}]},
                        ]
                    }
                }
            ]
        }

        self.assertEqual(["engineering", "platform"], saml_groups.extract_saml_groups(account_data))

    def test_extract_saml_groups_from_flattened_saml_values(self) -> None:
        account_data = {
            "Values": {
                "teams": {
                    "Values": [
                        {"Value": "sales"},
                        {"Value": "support"},
                    ]
                }
            }
        }

        self.assertEqual(
            ["sales", "support"], saml_groups.extract_saml_groups(account_data, "teams")
        )

    def test_attribute_names_by_provider_key_uses_only_saml_providers_with_overrides(self) -> None:
        providers: list[shared_types.AuthProvider] = [
            {
                "serviceType": "saml",
                "serviceID": "https://idp.example.com",
                "clientID": "sourcegraph",
                "displayName": "SAML",
                "isBuiltin": False,
                "configID": "okta",
            },
            {
                "serviceType": "github",
                "serviceID": "https://github.com/",
                "clientID": "github-client",
                "displayName": "GitHub",
                "isBuiltin": False,
                "configID": "github",
            },
        ]

        by_provider = saml_groups.attribute_names_by_provider_key(
            providers, {"okta": "teams", "github": "orgs"}
        )

        self.assertEqual({("https://idp.example.com", "sourcegraph"): "teams"}, by_provider)
        self.assertEqual(
            "teams",
            saml_groups.attribute_name_for(by_provider, "https://idp.example.com", "sourcegraph"),
        )
        self.assertEqual(
            "groups", saml_groups.attribute_name_for(by_provider, "missing", "missing")
        )

    def test_count_users_per_saml_group_counts_missing_and_deduplicates_user_groups(self) -> None:
        users: list[shared_types.User] = [
            {
                "id": "user-1",
                "username": "alice",
                "builtinAuth": False,
                "externalAccounts": {
                    "nodes": [
                        {
                            "serviceType": "saml",
                            "serviceID": "https://idp.example.com",
                            "clientID": "sourcegraph",
                            "accountData": {
                                "Values": {
                                    "teams": {
                                        "Values": [
                                            {"Value": "engineering"},
                                            {"Value": "engineering"},
                                        ]
                                    }
                                }
                            },
                        },
                        {
                            "serviceType": "saml",
                            "serviceID": "https://idp.example.com",
                            "clientID": "sourcegraph",
                            "accountData": None,
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
                            "serviceType": "saml",
                            "serviceID": "https://idp.example.com",
                            "clientID": "sourcegraph",
                            "accountData": None,
                        }
                    ]
                },
            },
            {
                "id": "user-3",
                "username": "carol",
                "builtinAuth": False,
                "externalAccounts": {
                    "nodes": [
                        {
                            "serviceType": "github",
                            "serviceID": "https://github.com/",
                            "clientID": "github-client",
                            "accountData": None,
                        }
                    ]
                },
            },
        ]

        counts = saml_groups.count_users_per_saml_group(
            users,
            {("https://idp.example.com", "sourcegraph"): "teams"},
        )

        self.assertEqual(
            {
                ("https://idp.example.com", "sourcegraph"): {
                    "engineering": 1,
                    saml_groups.MISSING_GROUP_NAME: 1,
                }
            },
            counts,
        )

    def test_compact_saml_group_users_keeps_only_org_sync_fields(self) -> None:
        providers: list[shared_types.AuthProvider] = [
            {
                "serviceType": "saml",
                "serviceID": "https://idp.example.com",
                "clientID": "sourcegraph",
                "displayName": "SAML",
                "isBuiltin": False,
                "configID": "okta",
            },
            {
                "serviceType": "github",
                "serviceID": "https://github.com/",
                "clientID": "github-client",
                "displayName": "GitHub",
                "isBuiltin": False,
                "configID": "github",
            },
        ]
        users: list[shared_types.User] = [
            {
                "id": "user-1",
                "username": "alice",
                "builtinAuth": False,
                "externalAccounts": {
                    "nodes": [
                        {
                            "serviceType": "saml",
                            "serviceID": "https://idp.example.com",
                            "clientID": "sourcegraph",
                            "accountData": {
                                "Values": {
                                    "teams": {
                                        "Values": [
                                            {"Value": "engineering"},
                                            {"Value": "engineering"},
                                            {"Value": "platform"},
                                        ]
                                    }
                                }
                            },
                        },
                        {
                            "serviceType": "github",
                            "serviceID": "https://github.com/",
                            "clientID": "github-client",
                            "accountData": {"large": "ignored"},
                        },
                    ]
                },
            },
            {
                "id": "user-2",
                "username": "bob",
                "builtinAuth": False,
                "externalAccounts": {"nodes": []},
            },
        ]

        compact_users = saml_groups.compact_saml_group_users(
            users,
            providers,
            {("https://idp.example.com", "sourcegraph"): "teams"},
        )

        self.assertEqual(
            [
                shared_types.SamlGroupUser(
                    user_id="user-1",
                    username="alice",
                    saml_group_memberships=(
                        shared_types.SamlGroupMembership(
                            provider_config_id="okta", group_name="engineering"
                        ),
                        shared_types.SamlGroupMembership(
                            provider_config_id="okta", group_name="platform"
                        ),
                    ),
                )
            ],
            compact_users,
        )
