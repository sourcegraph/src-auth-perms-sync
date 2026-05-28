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

QUERY_USERS = """
query ListUsers($first: Int!, $after: String) {
  users(first: $first, after: $after) {
    nodes {
      id
      username
      builtinAuth
      externalAccounts(first: 50) {
        nodes {
          serviceType
          serviceID
          clientID
          # accountData is the parsed gosaml2 AssertionInfo JSON for SAML
          # accounts (used by saml_groups extraction). The server gates
          # it on Site Admin for SAML/OIDC; we already require Site
          # Admin. Returns null for serviceType where the resolver does
          # not expose data (e.g. plain GitHub OAuth without SSO).
          accountData
        }
      }
    }
    pageInfo { hasNextPage endCursor }
  }
}
"""
