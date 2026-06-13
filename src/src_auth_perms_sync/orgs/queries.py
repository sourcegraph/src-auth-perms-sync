"""GraphQL operations for Sourcegraph organization sync."""

from __future__ import annotations

QUERY_CURRENT_USER = """
query SamlOrganizationSyncCurrentUser {
  currentUser { id username }
}
"""

# One search request finds every tool-managed (`synced-` prefixed) org.
# totalCount > len(nodes) signals truncation; callers must then fall back
# to per-name lookups.
QUERY_SYNCED_ORGANIZATIONS = """
query SyncedOrganizations($first: Int!, $query: String!) {
  currentUser { id username }
  organizations(first: $first, query: $query) {
    totalCount
    nodes {
      id
      name
    }
  }
}
"""


def users_organizations_batch_query(batch_size: int) -> str:
    """Fetch many users' org memberships in one aliased `node()` request.

    Used to validate a scoped org sync: re-reading each scoped user's own
    org list is far cheaper than paging every touched org's member list.
    """
    variables = ", ".join(f"$user{index}: ID!" for index in range(batch_size))
    aliases = "".join(
        f"""
  user{index}: node(id: $user{index}) {{
    ... on User {{
      id
      username
      organizations {{
        nodes {{ id name }}
      }}
    }}
  }}"""
        for index in range(batch_size)
    )
    return f"query UsersOrganizationsBatch({variables}) {{{aliases}\n}}"


QUERY_ORGANIZATION_MEMBERS_PAGE = """
query OrganizationMembersPage($id: ID!, $first: Int!, $after: String) {
  node(id: $id) {
    ... on Org {
      id
      name
      members(first: $first, after: $after) {
        totalCount
        nodes { id username }
        pageInfo { hasNextPage endCursor }
      }
    }
  }
}
"""

MUTATION_CREATE_ORGANIZATION = """
mutation CreateOrganization($name: String!, $displayName: String) {
  createOrganization(name: $name, displayName: $displayName) {
    id
    name
  }
}
"""

MUTATION_ADD_USER_TO_ORGANIZATION = """
mutation AddUserToOrganization($organization: ID!, $username: String!) {
  addUserToOrganization(organization: $organization, username: $username) {
    alwaysNil
  }
}
"""

MUTATION_REMOVE_USER_FROM_ORGANIZATION = """
mutation RemoveUserFromOrganization($organization: ID!, $user: ID!) {
  removeUserFromOrganization(organization: $organization, user: $user) {
    alwaysNil
  }
}
"""
