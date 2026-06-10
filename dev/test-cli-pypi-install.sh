#!/usr/bin/env bash
# Description: Tests CLI mode install

set -euo pipefail

# Set the working directory
working_directory="${TMPDIR:-/tmp}/src-auth-perms-sync-pypi-install"

# Delete, recreate, and cd to working directory
rm -rf "${working_directory}" && mkdir -p "${working_directory}" && cd "${working_directory}"

# Use python3.13 to create and activate a venv
# shellcheck disable=SC1091
python3.13 -m venv .venv && source .venv/bin/activate

# pip install latest from https://pypi.org/project/src-auth-perms-sync
python3.13 -m pip install --upgrade pip src-auth-perms-sync

# Run commands
src-auth-perms-sync --help
src-auth-perms-sync get --help
src-auth-perms-sync set --help
src-auth-perms-sync restore --help
src-auth-perms-sync sync-saml-orgs --help
