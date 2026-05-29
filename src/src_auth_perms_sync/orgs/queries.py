"""GraphQL operations for Sourcegraph organization sync."""

from __future__ import annotations

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
