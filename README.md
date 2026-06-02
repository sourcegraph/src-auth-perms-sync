# src-auth-perms-sync
<!-- HUMAN-MAINTAINED SECTION START — DO NOT EDIT THIS SECTION -->

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
  - Minor version updates are breaking changes
  - Patch version updates are not breaking changes

## Principles

- Customers need to be able to trust this, and audit this, similar to code
  host permissions

- To keep the interface simple, auditable, and trustable, the user and repo filters in
  each map only match "all," not "any," i.e., adding multiple filters to each
  map casts a smaller net of users / repos. This can result in more maps,
  but they will be easier to understand and trust.

- Backup files are saved in `src-auth-perms-sync-runs/<endpoint>/backups/`,
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
  - Be sure to specify the path to the correct `maps.yaml` file for each run
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

- Requires Python 3.11
- Recommended: Use a Python virtual environment

### Install from PyPI

```bash
pip install src-auth-perms-sync

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

succeeded = src.Set(config)

# Other command wrappers:
# succeeded = src.Get(config)
# succeeded = src.Restore(config)
# succeeded = src.SyncSamlOrgs(config)
```

## Inputs

- Environment variables
  - `SRC_ENDPOINT`
  - `SRC_ACCESS_TOKEN` from a user with site-admin perms
  - Supplied via the environment or a `.env` file
  - See [.env.example](./.env.example)

- YAML maps file `src-auth-perms-sync-runs/<endpoint>/maps.yaml`
  - A list of mapping rules
  - Each mapping rule takes
    - A list of filters for users
    - A list of filters for repos
  - See [maps-example.yaml](./maps-example.yaml)
  - An empty maps.yaml file is created for you on the first `get` run

## Usage: Permission sync

1. **Get auth providers and code hosts**

    ```bash
    uv run src-auth-perms-sync get
    ```

    - Queries the Sourcegraph instance for auth providers and code host connections
    - Writes generated reference files `auth-providers.yaml` and `code-hosts.yaml` under
      `src-auth-perms-sync-runs/<endpoint>/`
    - Creates an empty `maps.yaml` if it doesn't exist

2. **Configure mapping rules**

    - Edit `maps.yaml`
    - Add mapping rules under the `maps:` top level key
    - See [maps-example.yaml](./maps-example.yaml)

3. **Set: Dry run**

    ```bash
    uv run src-auth-perms-sync set --maps-path maps.yaml --full
    ```

4. **Set: Apply**

    ```bash
    uv run src-auth-perms-sync set --maps-path maps.yaml --full --apply
    ```

5. **Restore: Dry run**

    ```bash
    uv run src-auth-perms-sync restore \
      --restore-path backups/maps.yaml/2026-04-27-08-24-25-set-apply/before.json
    ```

    - Roll back the explicit-permissions state on the
      instance to match a previously captured snapshot

6. **Restore: Apply**

    ```bash
    uv run src-auth-perms-sync restore \
      --restore-path backups/maps.yaml/2026-04-27-08-24-25-set-apply/before.json \
      --apply
    ```

## Usage: Org sync

1. **Get user and org metadata**

    ```bash
    uv run src-auth-perms-sync sync-saml-orgs
    ```

    - Queries the Sourcegraph instance for auth providers, users, users' SAML groups, and orgs
    - Dry run

2. **Apply org sync**

    ```bash
    uv run src-auth-perms-sync sync-saml-orgs --apply
    ```

    - Creates the orgs if they don't exist, and sync the members from the SAML groups to the orgs
    - `--sync-saml-orgs` can also be added to a `get` or `set` run, to run both at the same time

## Options

Run `uv run src-auth-perms-sync --help` for options

## File tree

```text
src-auth-perms-sync-runs/endpoint/
├── auth-providers.yaml
├── code-hosts.yaml
├── maps.yaml
└── runs
    └── timestamp-command
        ├── after.json
        ├── before.json
        ├── diff.json
        ├── log.json
        └── maps.yaml
```

- The `src-auth-perms-sync-runs` dir is created under your current working directory
- The `endpoint` dir is created with the hostname from `SRC_ENDPOINT`
- If `maps.yaml` doesn't exist already, it'll be created for you
- `auth-providers.yaml` and `code-hosts.yaml` are created / replaced by the `get` command,
  for you to copy values from, to use in your `maps.yaml`
- Only one `maps.yaml` file can be used at a time per Sourcegraph instance, as each `set --apply`
  command resets the state on the Sourcegraph instance to the `maps.yaml` file which was used
- Each run of the script creates a new `timestamp-command` dir under the `runs` dir, with:
  - A log file
  - A backup copy of the `maps.yaml` file which was used in that run
  - A `before.json` file, capturing the before state, which can be restored from
- Runs using `--apply` also create
  - An `after.json` file, capturing the new state
  - A `diff.json` file, a shorter, reviewable file containing the diffs between before and after

<!-- HUMAN-MAINTAINED SECTION END — DO NOT EDIT ABOVE -->
