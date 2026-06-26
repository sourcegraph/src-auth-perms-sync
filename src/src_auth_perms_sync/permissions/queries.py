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

REPOSITORY_CANDIDATE_FIELDS = """
id
name
createdAt
externalServices(first: 50) {
  nodes { id }
}
"""

QUERY_REPOSITORIES_BY_NAMES = f"""
query RepositoriesByNames($names: [String!]!, $first: Int!, $after: String) {{
  repositories(
    names: $names
    first: $first
    after: $after
    cloned: true
    notCloned: true
  ) {{
    nodes {{
      {REPOSITORY_CANDIDATE_FIELDS}
    }}
    pageInfo {{ hasNextPage endCursor }}
  }}
}}
"""

QUERY_REPOSITORY_CANDIDATES = f"""
query RepositoryCandidates($first: Int!, $after: String) {{
  repositories(
    first: $first
    after: $after
    cloned: true
    notCloned: true
    orderBy: REPOSITORY_NAME
  ) {{
    nodes {{
      {REPOSITORY_CANDIDATE_FIELDS}
    }}
    pageInfo {{ hasNextPage endCursor }}
  }}
}}
"""

QUERY_REPOSITORY_CANDIDATES_BY_CREATED_AT = f"""
query RepositoryCandidatesByCreatedAt($first: Int!, $after: String) {{
  repositories(
    first: $first
    after: $after
    cloned: true
    notCloned: true
    orderBy: REPO_CREATED_AT
    descending: true
  ) {{
    nodes {{
      {REPOSITORY_CANDIDATE_FIELDS}
    }}
    pageInfo {{ hasNextPage endCursor }}
  }}
}}
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

USER_BASE_FIELDS = """
id
username
builtinAuth
externalAccounts(first: 50) {
  nodes {
    serviceType
    serviceID
    clientID
__ACCOUNT_DATA_FIELD__
  }
}
"""

USER_ACCOUNT_DATA_FIELD = "    accountData"

USER_EMAIL_FIELDS = """
emails {
  email
  verified
}
"""

# Inlining org memberships into user hydration saves a separate per-user
# lookup when scoped org sync needs them.
USER_ORGANIZATIONS_FIELDS = """
organizations {
  nodes { id name }
}
"""


def user_fields(
    *,
    include_emails: bool = False,
    include_account_data: bool = True,
    include_organizations: bool = False,
) -> str:
    """Return user fields, adding heavier fields only when downstream needs them."""
    fields = USER_BASE_FIELDS.replace(
        "__ACCOUNT_DATA_FIELD__",
        USER_ACCOUNT_DATA_FIELD if include_account_data else "",
    )
    if include_emails:
        fields = f"{fields}\n{USER_EMAIL_FIELDS}"
    if include_organizations:
        fields = f"{fields}\n{USER_ORGANIZATIONS_FIELDS}"
    return fields


def query_user_by_username(
    *,
    include_emails: bool = False,
    include_account_data: bool = True,
    include_organizations: bool = False,
) -> str:
    fields = user_fields(
        include_emails=include_emails,
        include_account_data=include_account_data,
        include_organizations=include_organizations,
    )
    return f"""
query UserByUsername($username: String!) {{
  user(username: $username) {{
    {fields}
  }}
}}
"""


def query_user_by_email(
    *,
    include_emails: bool = False,
    include_account_data: bool = True,
    include_organizations: bool = False,
) -> str:
    fields = user_fields(
        include_emails=include_emails,
        include_account_data=include_account_data,
        include_organizations=include_organizations,
    )
    return f"""
query UserByEmail($email: String!) {{
  user(email: $email) {{
    {fields}
  }}
}}
"""


def query_user_by_id(
    *,
    include_emails: bool = False,
    include_account_data: bool = True,
    include_organizations: bool = False,
) -> str:
    fields = user_fields(
        include_emails=include_emails,
        include_account_data=include_account_data,
        include_organizations=include_organizations,
    )
    return f"""
query UserByID($id: ID!) {{
  node(id: $id) {{
    ... on User {{
      {fields}
    }}
  }}
}}
"""


def users_by_ids_batch_query(
    batch_size: int,
    *,
    include_emails: bool = False,
    include_account_data: bool = True,
    include_organizations: bool = False,
) -> str:
    """Hydrate many users in one request via aliased `node()` lookups.

    Replaces one `UserByID` round trip per user: the per-request overhead
    dominates user hydration, so batching cuts request count by the batch
    size with the same per-user fields.
    """
    fields = user_fields(
        include_emails=include_emails,
        include_account_data=include_account_data,
        include_organizations=include_organizations,
    )
    variables = ", ".join(f"$user{index}: ID!" for index in range(batch_size))
    aliases = "".join(
        f"""
  user{index}: node(id: $user{index}) {{
    ... on User {{
      {fields}
    }}
  }}"""
        for index in range(batch_size)
    )
    return f"query UsersByIDBatch({variables}) {{{aliases}\n}}"


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

# Server-side filtered to PermissionSource.API - explicit grants only, never
# code-host-synced. We always invert (user->repos) here because
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

# Explicit-API grants whose bindID didn't resolve to a real user yet
# ("grant before first login"). Snapshots capture them so set/restore can
# preserve them, and post-apply validation checks none of OUR usernames
# landed here (which would mean a write didn't bind to a real user).
QUERY_PENDING_BINDIDS = """
query PendingBindIDs {
  usersWithPendingPermissions
}
"""

# For a bindID with no matching user, this resolver falls back to the
# pending-permissions store and returns the repos the bindID is pending
# on ("late binding" - see the GraphQL schema comment). That fallback is
# the only API that exposes WHICH repos a pending bindID has.
QUERY_PENDING_USER_REPOS = """
query PendingUserRepos($bindID: String!, $first: Int!, $after: String) {
  authorizedUserRepositories(username: $bindID, first: $first, after: $after) {
    nodes {
      id
      name
    }
    pageInfo { hasNextPage endCursor }
  }
}
"""
