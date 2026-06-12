from __future__ import annotations

import subprocess
import sys
import unittest

import src_py_lib as src

import src_auth_perms_sync
from src_auth_perms_sync import cli
from src_auth_perms_sync.shared import backups


class PackageImportTests(unittest.TestCase):
    def test_importing_the_package_exposes_module_mode_names(self) -> None:
        self.assertIs(src_auth_perms_sync.GetResult, cli.GetResult)
        self.assertIs(src_auth_perms_sync.CommandResult, cli.CommandResult)
        self.assertIs(src_auth_perms_sync.RunPaths, backups.RunPaths)
        self.assertIs(src_auth_perms_sync.EventSink, src.EventSink)
        for exported_name in ("GetResult", "CommandResult", "RunPaths", "EventSink"):
            self.assertIn(exported_name, src_auth_perms_sync.__all__)


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

        # get is read-only: the --apply option must not exist (it is only
        # mentioned inside the --no-files help text).
        self.assertNotIn("[--apply]", get_help.stdout)
        self.assertNotIn("Apply changes", get_help.stdout)
        self.assertIn("--no-backup", get_help.stdout)
        self.assertIn("--maps-path FILE", get_help.stdout)
        self.assertIn("--artifacts-dir DIR", get_help.stdout)
        self.assertIn("--no-files", get_help.stdout)
        self.assertNotIn("--sync-saml-orgs", get_help.stdout)
        self.assertIn("--users USERS", get_help.stdout)
        self.assertNotIn("--user USER", get_help.stdout)
        self.assertIn("--maps-path FILE", set_help.stdout)
        self.assertIn("--artifacts-dir DIR", set_help.stdout)
        self.assertIn("--no-files", set_help.stdout)
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
