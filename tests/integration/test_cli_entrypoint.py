from __future__ import annotations

import subprocess
import sys
import unittest


class CliEntrypointTests(unittest.TestCase):
    def test_module_help_prints_usage(self) -> None:
        completed_process = subprocess.run(
            [sys.executable, "-m", "src_auth_perms_sync", "--help"],
            check=True,
            capture_output=True,
            text=True,
        )

        self.assertIn("src-auth-perms-sync", completed_process.stdout)
        self.assertIn("set:\n- Explicit repo permissions", completed_process.stdout)
        self.assertIn("Organizations and memberships\n\nSee", completed_process.stdout)
        self.assertIn("{get,set,restore,sync-saml-orgs}", completed_process.stdout)
        self.assertIn("--maps-path", completed_process.stdout)
        self.assertIn("--restore-path", completed_process.stdout)
        self.assertIn("--sync-saml-orgs", completed_process.stdout)
        self.assertEqual("", completed_process.stderr)
