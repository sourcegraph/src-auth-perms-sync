# /// script
# requires-python = ">=3.11"
# dependencies = ["src-auth-perms-sync"]
# ///
"""Sync Sourcegraph repo permissions from your own Python code.

export SRC_ENDPOINT="https://sourcegraph.example.com"
export SRC_ACCESS_TOKEN="sgp_..."  # site-admin token
uv run example-import.py
"""

import logging
import os

import src_auth_perms_sync as src

# Configure your logger
logging.basicConfig(level=logging.INFO)

# The import API does not read environment variables or .env files on its
# own (the CLI does); pass every value explicitly.
config = src.Config(
    src_endpoint=os.environ["SRC_ENDPOINT"],
    src_access_token=os.environ["SRC_ACCESS_TOKEN"],
)

# Discover the instance's auth providers and code hosts
discovery = src.Get(config)
for auth_provider in discovery.auth_providers:
    print("auth provider:", auth_provider.get("displayName"))
for code_host_connection in discovery.code_host_connections:
    print("code host:", code_host_connection.get("displayName"))

# Configure your mapping rules
mapping_rules: list[src.MappingRule] = [
    {
        "name": "LOB1-GROUP1 members get the LOB1-SA1 repos",
        "users": {"authProvider": {"samlGroup": "LOB1-GROUP1"}},
        "repos": {"codeHostConnection": {"username": "LOB1-SA1"}},
    },
    {
        "name": "LOB2-GROUP2 members get the LOB2-SA2 repos",
        "users": {"authProvider": {"samlGroup": "LOB2-GROUP2"}},
        "repos": {"codeHostConnection": {"username": "LOB2-SA2"}},
    },
]

# Run the set dry run, also syncing SAML groups to Sourcegraph organizations
result = src.Set(
    config.model_copy(update={"full": True, "apply": False, "sync_saml_orgs": True}),
    mapping_rules=mapping_rules,
)
# Print if it succeeded
print("permission sync dry run:", "ok" if result else "failed")

# Run the set apply, also syncing SAML groups to Sourcegraph organizations
result = src.Set(
    config.model_copy(update={"full": True, "apply": True, "sync_saml_orgs": True}),
    mapping_rules=mapping_rules,
)

# Print if it succeeded
print("permission sync apply:", "ok" if result else "failed")
