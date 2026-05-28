from __future__ import annotations

import subprocess
import sys
import unittest


class CliEntrypointTests(unittest.TestCase):
    def test_module_help_prints_usage(self) -> None:
        completed_process = subprocess.run(
            [sys.executable, "-m", "auth_perms_sync", "--help"],
            check=True,
            capture_output=True,
            text=True,
        )

        self.assertIn("Sourcegraph Auth Perms Sync", completed_process.stdout)
        self.assertIn("--set", completed_process.stdout)
        self.assertIn("--sync-saml-orgs", completed_process.stdout)
        self.assertEqual("", completed_process.stderr)
