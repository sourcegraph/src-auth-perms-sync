#!/usr/bin/env bash
# Description: Tests CLI mode install

set -euox pipefail

# Set the working directory
tmp_root="${TMPDIR:-/tmp}"
working_directory="${tmp_root%/}/src-auth-perms-sync-pypi-install"

# Delete, recreate, and cd to working directory
rm -rf "${working_directory}" && mkdir -p "${working_directory}" && cd "${working_directory}"

log_file="${working_directory}/test-cli-pypi-install.log"
exec > >(tee "${log_file}") 2>&1
echo "Writing output to ${log_file}"
echo ""
echo "Dir contents in ${working_directory} before"
ls -al

# Use python3.13 to create and activate a venv
# shellcheck disable=SC1091
echo ""
python3.13 -m venv .venv && source .venv/bin/activate
which python
python --version

# Ensure pip is up to date
echo ""
python -m pip install --upgrade pip

# pip install latest from https://pypi.org/project/src-auth-perms-sync
echo ""
python -m pip install src-auth-perms-sync

# Run commands
echo ""
src-auth-perms-sync --help
echo ""
src-auth-perms-sync get --help
echo ""
src-auth-perms-sync set --help
echo ""
src-auth-perms-sync restore --help
echo ""
src-auth-perms-sync sync-saml-orgs --help

echo ""
echo "Dir contents in ${working_directory} after"
ls -al
echo ""
