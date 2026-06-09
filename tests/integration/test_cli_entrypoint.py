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
        self.assertIn("commands:", completed_process.stdout)
        self.assertIn("COMMAND", completed_process.stdout)
        self.assertIn("get", completed_process.stdout)
        self.assertIn("set", completed_process.stdout)
        self.assertIn("sync-saml-orgs", completed_process.stdout)
        self.assertIn("Sync orgs from SAML groups", completed_process.stdout)
        self.assertNotIn("--maps-path", completed_process.stdout)
        self.assertEqual("", completed_process.stderr)

    def test_command_help_prints_command_specific_options(self) -> None:
        get_help = subprocess.run(
            [sys.executable, "-m", "src_auth_perms_sync", "get", "--help"],
            check=True,
            capture_output=True,
            text=True,
        )
        set_help = subprocess.run(
            [sys.executable, "-m", "src_auth_perms_sync", "set", "--help"],
            check=True,
            capture_output=True,
            text=True,
        )
        restore_help = subprocess.run(
            [sys.executable, "-m", "src_auth_perms_sync", "restore", "--help"],
            check=True,
            capture_output=True,
            text=True,
        )
        sync_saml_orgs_help = subprocess.run(
            [sys.executable, "-m", "src_auth_perms_sync", "sync-saml-orgs", "--help"],
            check=True,
            capture_output=True,
            text=True,
        )

        self.assertNotIn("--apply", get_help.stdout)
        self.assertIn("--no-backup", get_help.stdout)
        self.assertNotIn("--sync-saml-orgs", get_help.stdout)
        self.assertIn("--users USERS", get_help.stdout)
        self.assertNotIn("--user USER", get_help.stdout)
        self.assertIn("--maps-path FILE", set_help.stdout)
        self.assertIn("--users USERS", set_help.stdout)
        self.assertIn("--sync-saml-orgs", set_help.stdout)
        self.assertNotIn("--restore-path", set_help.stdout)
        self.assertIn("Permission sync:", set_help.stdout)
        self.assertIn("Organization sync:", set_help.stdout)
        self.assertIn("Sourcegraph:", set_help.stdout)
        self.assertIn("Logging:", set_help.stdout)
        self.assertLess(set_help.stdout.index("\nLogging:"), set_help.stdout.index("\nConfig:"))
        self.assertIn("--restore-path FILE", restore_help.stdout)
        self.assertNotIn("--maps-path", restore_help.stdout)
        self.assertIn("--apply", sync_saml_orgs_help.stdout)
        self.assertNotIn("--sync-saml-orgs", sync_saml_orgs_help.stdout)
        self.assertEqual("", get_help.stderr)
        self.assertEqual("", set_help.stderr)
        self.assertEqual("", restore_help.stderr)
        self.assertEqual("", sync_saml_orgs_help.stderr)
