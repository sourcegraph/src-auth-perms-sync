#!/usr/bin/env bash
set -euo pipefail

subtree_path="git-subtree/src-py-lib"
allow_environment_variable="ALLOW_SRC_PY_LIB_SUBTREE_CHANGE"

usage() {
  cat <<EOF
Usage:
  $0 --staged
  $0 --branch [base-revision]

Set ${allow_environment_variable}=1 for intentional subtree import/update commits.
EOF
}

mode="${1:---branch}"
if [[ "$mode" == "--help" || "$mode" == "-h" ]]; then
  usage
  exit 0
fi

if [[ "${!allow_environment_variable:-}" == "1" ]]; then
  exit 0
fi

reject_change() {
  cat <<EOF >&2
Do not edit ${subtree_path} directly in src-auth-perms-sync.

Make changes in sourcegraph/src-py-lib first, merge them upstream, then update this repo with:

  git subtree pull --prefix ${subtree_path} src-py-lib main --squash

For an intentional subtree import/update, rerun with ${allow_environment_variable}=1.

Changed files:
EOF
  printf '%s\n' "$@" >&2
  exit 1
}

case "$mode" in
  --staged)
    if git diff --cached --quiet -- "$subtree_path"; then
      exit 0
    fi

    changed_files="$(git diff --cached --name-only -- "$subtree_path")"
    reject_change "$changed_files"
    ;;

  --branch)
    base_revision="${2:-origin/main}"
    if ! git rev-parse --verify --quiet "${base_revision}^{commit}" >/dev/null; then
      cat <<EOF >&2
Could not find base revision '${base_revision}' for subtree guard.
Fetch the base branch or pass an explicit base revision.
EOF
      exit 1
    fi

    merge_base_revision="$(git merge-base "$base_revision" HEAD)"
    if git diff --quiet "${merge_base_revision}...HEAD" -- "$subtree_path"; then
      exit 0
    fi

    if git log --format=%B "${merge_base_revision}..HEAD" \
      | grep -Fx "git-subtree-dir: ${subtree_path}" >/dev/null; then
      exit 0
    fi

    changed_files="$(git diff --name-only "${merge_base_revision}...HEAD" -- "$subtree_path")"
    reject_change "$changed_files"
    ;;

  *)
    usage >&2
    exit 2
    ;;
esac
