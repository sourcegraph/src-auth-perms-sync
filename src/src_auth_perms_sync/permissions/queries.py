"""GraphQL operations for repo-permission sync."""

from __future__ import annotations

QUERY_EXTERNAL_SERVICES = """
query ListExternalServices($first: Int!, $after: String) {
  externalServices(first: $first, after: $after) {
    nodes {
      id
      kind
      displayName
      url
      repoCount
      createdAt
      updatedAt
      lastSyncAt
      nextSyncAt
      lastSyncError
      warning
      unrestricted
      suspended
      hasConnectionCheck
      supportsRepoExclusion
      creator { username }
      lastUpdater { username }
      config
    }
    pageInfo { hasNextPage endCursor }
  }
}
"""

QUERY_REPOS_BY_EXTERNAL_SERVICE = """
query ReposByExternalService($esID: ID!, $first: Int!, $after: String) {
  repositories(
    first: $first
    after: $after
    externalService: $esID
    cloned: true
    notCloned: true
  ) {
    nodes {
      id
      name
    }
    pageInfo { hasNextPage endCursor }
  }
}
"""

MUTATION_SET_REPO_PERMISSIONS = """
mutation SetRepoPerms($repo: ID!, $userPerms: [UserPermissionInput!]!) {
  setRepositoryPermissionsForUsers(repository: $repo, userPermissions: $userPerms) {
    alwaysNil
  }
}
"""

MUTATION_ADD_REPO_PERMISSION = """
mutation AddRepoPerm($repo: ID!, $user: ID!) {
  addRepositoryPermissionForUser(
    permission: { repository: $repo }
    userID: $user
  ) {
    alwaysNil
  }
}
"""

MUTATION_REMOVE_REPO_PERMISSION = """
mutation RemoveRepoPerm($repo: ID!, $user: ID!) {
  removeRepositoryPermissionForUser(repository: $repo, userID: $user) {
    alwaysNil
  }
}
"""

USER_FIELDS = """
id
username
builtinAuth
externalAccounts(first: 50) {
  nodes {
    serviceType
    serviceID
    clientID
    accountData
  }
}
"""

USER_EMAIL_FIELDS = """
emails {
  email
  verified
}
"""


def user_fields(*, include_emails: bool = False) -> str:
    """Return user fields, adding emails only when downstream matching needs them."""
    if include_emails:
        return f"{USER_FIELDS}\n{USER_EMAIL_FIELDS}"
    return USER_FIELDS


def query_user_by_username(*, include_emails: bool = False) -> str:
    return f"""
query UserByUsername($username: String!) {{
  user(username: $username) {{
    {user_fields(include_emails=include_emails)}
  }}
}}
"""


def query_user_by_email(*, include_emails: bool = False) -> str:
    return f"""
query UserByEmail($email: String!) {{
  user(email: $email) {{
    {user_fields(include_emails=include_emails)}
  }}
}}
"""


def query_user_by_id(*, include_emails: bool = False) -> str:
    return f"""
query UserByID($id: ID!) {{
  node(id: $id) {{
    ... on User {{
      {user_fields(include_emails=include_emails)}
    }}
  }}
}}
"""


QUERY_USER_BY_USERNAME = query_user_by_username()
QUERY_USER_BY_EMAIL = query_user_by_email()
QUERY_USER_BY_ID = query_user_by_id()

QUERY_SITE_USERS = """
query SiteUsers($limit: Int!, $offset: Int!, $createdAt: SiteUsersDateRangeInput) {
  site {
    users(createdAt: $createdAt, deletedAt: { empty: true }) {
      totalCount
      nodes(limit: $limit, offset: $offset, orderBy: CREATED_AT) {
        id
        username
        email
        createdAt
        deletedAt
      }
    }
  }
}
"""

# Server-side filtered to PermissionSource.API — explicit grants only, never
# code-host-synced. We always invert (user→repos) here because
# Repository.permissionsInfo.users does NOT accept a `source` filter on this
# SG version, so the repo-centric direction can't cleanly distinguish
# explicit-API grants from sync/site-admin grants.
QUERY_USER_EXPLICIT_REPOS = """
query UserExplicitRepos($id: ID!, $first: Int!, $after: String) {
  node(id: $id) {
    ... on User {
      permissionsInfo {
        repositories(source: API, first: $first, after: $after) {
          nodes {
            id
          }
          pageInfo { hasNextPage endCursor }
        }
      }
    }
  }
}
"""

QUERY_USER_EXPLICIT_REPO_EXISTS = """
query UserExplicitRepoExists($id: ID!) {
  node(id: $id) {
    ... on User {
      permissionsInfo {
        repositories(source: API, first: 1) {
          nodes { id }
        }
      }
    }
  }
}
"""

# Used as part of post-apply validation: any of OUR bindIDs appearing in
# this list means the bindID didn't resolve to a real user (typically a
# username typo or a recent rename — would fail for our case since we
# only ever pass usernames the script already enumerated from the users
# query).
QUERY_PENDING_BINDIDS = """
query PendingBindIDs {
  usersWithPendingPermissions
}
"""
