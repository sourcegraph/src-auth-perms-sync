"""Shared auth-provider/user GraphQL operations sent to Sourcegraph."""

from __future__ import annotations

QUERY_VALIDATE_PERMISSIONS_CONFIG = """
query ValidatePermissionsConfig {
  site {
    permissionsUserMappingBindID
    configuration {
      effectiveContents
    }
  }
}
"""

QUERY_AUTH_PROVIDERS = """
query ListAuthProviders {
  site {
    authProviders {
      nodes {
        serviceType
        serviceID
        clientID
        displayName
        isBuiltin
        configID
      }
    }
  }
}
"""

QUERY_USER_COUNT = """
query CountUsers {
  users(first: 1) {
    totalCount
  }
}
"""

USER_EMAIL_FIELDS = """      emails {
        email
        verified
      }
"""

USER_ACCOUNT_DATA_FIELD = """          # accountData is the parsed gosaml2
          # AssertionInfo JSON for SAML
          # accounts (used by saml_groups extraction). The server gates
          # it on Site Admin for SAML/OIDC; we already require Site
          # Admin. Returns null for serviceType where the resolver does
          # not expose data (e.g. plain GitHub OAuth without SSO).
          accountData
"""


def query_users(
    *,
    include_emails: bool = False,
    include_account_data: bool = True,
) -> str:
    """Return the users page query, adding heavier fields only when requested."""
    email_fields = USER_EMAIL_FIELDS if include_emails else ""
    account_data_field = USER_ACCOUNT_DATA_FIELD if include_account_data else ""
    return f"""
query ListUsers($first: Int!, $after: String) {{
  users(first: $first, after: $after) {{
    nodes {{
      id
      username
      builtinAuth
{email_fields}      externalAccounts(first: 50) {{
        nodes {{
          serviceType
          serviceID
          clientID
{account_data_field}        }}
      }}
    }}
    pageInfo {{ hasNextPage endCursor }}
  }}
}}
"""


QUERY_USERS = query_users()
