"""Fixture-backed end-to-end tests."""

import logging

# Tests exercise failure paths that emit operator-facing WARNING/ERROR logs
# (e.g. "FAIL <repo> ..."). Without a handler, logging.lastResort prints them
# to stderr, where they masquerade as real failures in test-runner output. A
# log line saying FAIL must only ever mean a test actually failed. Installed
# here (not only in tests/__init__.py) because unittest discovery imports
# these subpackages as top-level packages, skipping the parent package.
logging.getLogger().addHandler(logging.NullHandler())
