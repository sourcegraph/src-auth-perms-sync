"""Tests for src-auth-perms-sync."""

import logging

# Unit tests deliberately exercise failure paths, which emit operator-facing
# WARNING/ERROR logs such as "FAIL <repo> ...". Without any configured
# handler, logging.lastResort prints those to stderr, where they masquerade
# as real test failures in test-runner output. A NullHandler keeps expected
# log noise out of test output; a log line saying FAIL should only ever mean
# a test actually failed. Tests that care about log output should assert it
# explicitly with assertLogs.
logging.getLogger().addHandler(logging.NullHandler())
