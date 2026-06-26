# src-auth-perms-sync
<!-- HUMAN-MAINTAINED SECTION START - DO NOT EDIT THIS SECTION -->

src-auth-perms-sync automates Sourcegraph's Explicit Permissions GraphQL API,
setting user-to-repo permissions based on mapping rules, for example:

- Users who authenticated to SAML auth provider A,
  and their SAML assertion includes group 1,
  are granted access to repos cloned via code host X

## Experimental - This is not a supported Sourcegraph product

This repo was created for Sourcegraph Implementation Engineering deployments,
and is not intended, designed, built, or supported for use in any other scenario.
Feel free to open issues or PRs, but responses are best effort.

## Semantic Versioning

- Release versions are `major.minor.patch`
- Because this project is still major version 0:
  - Minor version updates are probably breaking changes
  - Patch version updates are probably not breaking changes

## Principles

- Customers need to be able to trust this, and audit this, similar to code
  host permissions

- To keep the interface simple, auditable, and trustable, the user and repo filters in
  each map only match "all," not "any," i.e., adding multiple filters to each
  map casts a smaller net of users / repos. This can result in more maps,
  but they will be easier to understand and trust.

- Backup files are saved in `src-auth-perms-sync-runs/<src_endpoint>/runs/<run>/`,
  unless the `--no-backup` arg is provided,
  so customers can review the changes made over time,
  and restore to a specific backup file, if needed

- It is assumed that this script is the only operator of Explicit Permissions on the Sourcegraph
  instance. Any other Explicit Permissions may be overwritten by this script.

- As with all usage of the Explicit Permissions API, user-repo permissions synced from
  code hosts are not affected by this script, but an Explicit Permissions rule
  overrides any conflicting permissions synced from code hosts

- One installation of this script can apply separate `maps.yaml` files on
  separate Sourcegraph instances
  - By default, each Sourcegraph instance gets its own generated `maps.yaml`
    under `src-auth-perms-sync-runs/<src_endpoint>/`
  - If you pass `--maps-path`, relative paths are resolved from your current
    working directory
  - Set the `SRC_ENDPOINT` and `SRC_ACCESS_TOKEN` environment variables correctly for each run

## Prerequisites

- As we're using the Explicit Permissions API, bindIDs are always usernames, never email addresses
  - The Sourcegraph instance's site config must contain:

    ```json
    {
      "auth.enableUsernameChanges": false,
      "permissions.userMapping": {
        "bindID": "username",
        "enabled": true
      }
    }
    ```

- As different SAML providers have different schemas, this script uses the
  Sourcegraph instance's `groupsAttributeName` site config attribute of each auth provider config
  - If `groupsAttributeName` is not set, then the default `groups` is used
  - If `groupsAttributeName` is set, then the `configID` attribute is also required
  - If org mapping is used, then the `configID` attribute is also required

    ```json
    {
      "auth.providers": [
        {
          "allowSignup": true,
          "configID": "okta", // Required because groupsAttributeName is set, or for org mapping
          "groupsAttributeName": "custom-group-attribute-name",
          "identityProviderMetadataURL": "https://example.okta.com/app/example-id/sso/saml/metadata",
          "type": "saml"
        }
      ]
    }
    ```

- It is strongly recommended to configure SCIM between your auth provider, and your Sourcegraph instance,
  so the new user's account is created on the Sourcegraph instance immediately after they're approved,
  giving this script more time to run before the user tries logging in for the first time

## Install

- Requires Python >= 3.11
- Recommended: Use a Python virtual environment

### Install from PyPI

```bash
# Set up virtual environment
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip

# Install package from PyPI
python -m pip install src-auth-perms-sync

# Run the CLI
src-auth-perms-sync --help
```

### Restricted / offline install from a GitHub Release

Download the .tar.gz file from [a GitHub release](https://github.com/sourcegraph/src-auth-perms-sync/releases)

```bash
tar -xzf src-auth-perms-sync-linux-x64.tar.gz

pip install --no-index --find-links ./wheelhouse src-auth-perms-sync

# Run the CLI
src-auth-perms-sync --help
```

### Import into your own Python script

```python
from pathlib import Path

import src_auth_perms_sync as src

config = src.Config(
    src_endpoint="https://sourcegraph.example.com",
    src_access_token="sgp_...",
    maps_path=Path("/absolute/path/to/maps.yaml"),
    apply=False,  # Dry run (default), set to True to make changes
)

result = src.Set(config)  # truthy on success; result.paths has run artifacts

# Discovery returns the auth provider and code host data in memory, so you
# can assemble mapping rules without re-parsing the generated YAML files:
get_result = src.Get(config)
for provider in get_result.auth_providers:
    ...
for code_host_connection in get_result.code_host_connections:
    ...

# Mapping rules can be passed in memory instead of a maps YAML file -
# same structure and validation as maps.yaml entries:
rules: list[src.MappingRule] = [
    {
        "name": "Map 1",
        "users": {"usernameRegexes": [".*"]},
        "repos": {"codeHostConnection": {"kind": "GITHUB"}},
    },
]
result = src.Set(config, mapping_rules=rules)
# When files are enabled, the rules actually used are written into the
# run directory for auditability. Snapshots still gate apply=True unless
# no_files=True and no_backup=True are both set explicitly.

# Other command wrappers:
# result = src.Restore(config)
# result = src.SyncSamlOrgs(config)
```

The import API does not read environment variables or `.env` files on its
own - those apply to the CLI only. Pass every value explicitly to
`src.Config(...)` (read `os.environ` yourself if you want env-driven
configuration, as the example above does).

Module mode never touches your `logging` handlers or the root logger - your
application's logging config stays in charge. To see progress messages:

```python
import logging

logging.basicConfig(level=logging.INFO)  # or your own handlers
logging.getLogger("src_auth_perms_sync").setLevel(logging.INFO)
logging.getLogger("src_py_lib").setLevel(logging.INFO)
```

To receive structured wide events programmatically, pass an event sink:

```python
events = src.InMemoryEventSink()
src.Get(config, event_sink=events)   # or src.CallbackEventSink(my_function)
```

To run fully disk-free (no generated YAML, snapshots, or log file), set
`no_files=True`. Combined with `apply=True` this also requires
`no_backup=True`, because skipping files gives up the before/after
snapshots that make `--apply` reversible.

## Inputs

- Environment variables (CLI), or src.Config args (Python import)
  - `SRC_ENDPOINT`
  - `SRC_ACCESS_TOKEN` from a user with site-admin perms
  - See [.env.example](./examples/.env.example)

- YAML maps file
  - By default: `src-auth-perms-sync-runs/<src_endpoint>/maps.yaml`
  - Or pass `--maps-path ./path/to/maps.yaml` (works for both `get` and `set`,
    so the maps file can live outside the generated artifacts tree)
  - `--artifacts-dir DIR` moves the whole artifacts tree (generated YAML,
    snapshots, logs); the default is `./src-auth-perms-sync-runs`
  - `--no-files` writes nothing to disk; with `--apply` it also requires
    `--no-backup`
  - A list of mapping rules
  - Each mapping rule takes
    - A map of filters for users
    - A map of filters for repos
  - See [maps.yaml](./examples/maps.yaml)
  - An empty maps.yaml file is created for you on the first `get` run

## Usage: Permission sync

1. **Get auth providers and code hosts**

    ```bash
    src-auth-perms-sync get
    ```

    - Queries the Sourcegraph instance for auth providers and code host connections
    - Writes generated reference files `auth-providers.yaml` and `code-host-connections.yaml` under
      `src-auth-perms-sync-runs/<src_endpoint>/`
    - Creates an empty `maps.yaml` if it doesn't exist

2. **Configure mapping rules**

    - Edit `src-auth-perms-sync-runs/<src_endpoint>/maps.yaml`
    - Add mapping rules under the `maps:` top level key
    - See [maps.yaml](./examples/maps.yaml)

3. **Set: Dry run**

    ```bash
    src-auth-perms-sync set --full
    ```

4. **Set: Apply**

    ```bash
    src-auth-perms-sync set --full --apply
    ```

    - To use a maps file outside the generated endpoint directory, pass an
      explicit path, for example `--maps-path ./maps.yaml`

5. **Restore: Dry run**

    ```bash
    src-auth-perms-sync restore \
      --restore-path src-auth-perms-sync-runs/<src_endpoint>/runs/<run>/before.json
    ```

    - Roll back the explicit-permissions state on the
      instance to match a previously captured snapshot
    - Relative `--restore-path` values are resolved from your current working directory

6. **Restore: Apply**

    ```bash
    src-auth-perms-sync restore \
      --restore-path src-auth-perms-sync-runs/<src_endpoint>/runs/<run>/before.json \
      --apply
    ```

## Usage: Org sync

1. **Get user and org metadata**

    ```bash
    src-auth-perms-sync sync-saml-orgs --full
    ```

    - Queries the Sourcegraph instance for auth providers, users, users' SAML groups, and orgs
    - Dry run

2. **Apply org sync**

    ```bash
    src-auth-perms-sync sync-saml-orgs --full --apply
    ```

    - Creates the orgs if they don't exist, and sync the members from the SAML groups to the orgs
    - `--sync-saml-orgs` can also be added to a `set` run, to run both at the same time

3. **Scoped org sync for selected users**

    ```bash
    src-auth-perms-sync sync-saml-orgs --users alice,bob
    src-auth-perms-sync sync-saml-orgs --users-created-after 2026-06-01
    src-auth-perms-sync sync-saml-orgs --users-without-explicit-perms
    ```

    - Same user filters as `get` and `set`; a mode flag is required - there
      is no bare `sync-saml-orgs`

### Org sync behavior

- Org names are `synced-<configID>-<group name>` (non-alphanumeric characters
  become `-`). The `synced-` prefix marks tool ownership: the sync only ever
  modifies orgs whose name carries it, so manually created orgs are never touched.
- The org sync mode is always explicit - no surprises:
  - **Full** (`sync-saml-orgs --full`, or `set --full` / `--repos*`
    `--sync-saml-orgs`): converges every synced org against all users. A synced
    org whose SAML group disappeared has all members removed, but the org itself
    is kept (its settings survive in case the group comes back).
  - **Scoped** (user filters on `sync-saml-orgs`, or `set --users` /
    `--users-without-explicit-perms` / `--users-created-after` with
    `--sync-saml-orgs`): syncs org membership for exactly the selected users -
    per-user additions AND removals, computed from each user's own SAML
    assertion and org list. Other users' memberships never change, and no full
    user scan or org member listing is needed, so API traffic stays
    proportional to the selection.

## Options

Run `src-auth-perms-sync --help` for options

## File tree

```text
src-auth-perms-sync-runs/<src_endpoint>/
|-- auth-providers.yaml
|-- code-host-connections.yaml
|-- maps.yaml
`-- runs
    `-- timestamp-command
        |-- before.json
        |-- after.json
        |-- diff.json
        |-- log.json
        `-- maps.yaml
```

- The `src-auth-perms-sync-runs` dir is created under your current working directory
- The `<src_endpoint>` dir is created with the hostname from `SRC_ENDPOINT`
- If `maps.yaml` doesn't exist already, it'll be created for you
- `auth-providers.yaml` and `code-host-connections.yaml` are created / replaced by the `get` command,
  for you to copy values from, to use in your `maps.yaml`
- Only one `maps.yaml` file can be used at a time per Sourcegraph instance, as each `set --apply`
  command resets the state on the Sourcegraph instance to the `maps.yaml` file which was used
- Each run of the script creates a new `timestamp-command` dir under the `runs` dir, with:
  - A `before.json` file, capturing the before state, which can be used in a restore run
  - A log file
  - A backup copy of the `maps.yaml` file which was used in that run
- Runs using `--apply` also create
  - An `after.json` file, capturing the new state
  - A `diff.json` file, a shorter, reviewable file containing the diffs between before and after

<!-- HUMAN-MAINTAINED SECTION END - DO NOT EDIT ABOVE -->
