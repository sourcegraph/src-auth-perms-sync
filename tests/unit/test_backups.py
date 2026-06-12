from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from src_auth_perms_sync.shared import backups

FIXED_TIMESTAMP = "2026-06-12-00-00-00"


def make_run_paths(run_directory: Path) -> backups.RunPaths:
    return backups.RunPaths(
        timestamp=FIXED_TIMESTAMP,
        artifacts_dir=run_directory.parent,
        endpoint_directory=run_directory.parent,
        maps_path=run_directory.parent / "maps.yaml",
        code_hosts_path=run_directory.parent / "code-hosts.yaml",
        auth_providers_path=run_directory.parent / "auth-providers.yaml",
        run_directory=run_directory,
    )


class EndpointDirectoryNameTests(unittest.TestCase):
    def test_uses_hostname_and_port(self) -> None:
        self.assertEqual(
            "sourcegraph.example.com",
            backups.endpoint_directory_name("https://sourcegraph.example.com"),
        )
        self.assertEqual(
            "sourcegraph.example.com-3443",
            backups.endpoint_directory_name("https://sourcegraph.example.com:3443"),
        )

    def test_lowercases_hostnames(self) -> None:
        self.assertEqual(
            "sourcegraph.example.com",
            backups.endpoint_directory_name("https://Sourcegraph.Example.COM"),
        )

    def test_accepts_scheme_less_endpoints(self) -> None:
        self.assertEqual(
            "sourcegraph.example.com",
            backups.endpoint_directory_name("sourcegraph.example.com"),
        )
        self.assertEqual(
            "sourcegraph.example.com-3443",
            backups.endpoint_directory_name("sourcegraph.example.com:3443/path"),
        )

    def test_replaces_unsafe_characters(self) -> None:
        self.assertEqual("host_name", backups.endpoint_directory_name("Host Name"))
        self.assertEqual("unknown", backups.endpoint_directory_name("///"))


class SafeFilenamePartTests(unittest.TestCase):
    def test_falls_back_for_empty_values(self) -> None:
        self.assertEqual("unknown", backups.safe_filename_part("///"))
        self.assertEqual("a_b-c.d", backups.safe_filename_part("a/b-c.d"))

    def test_strips_leading_dots_so_traversal_cannot_survive(self) -> None:
        self.assertEqual("etc_passwd", backups.safe_filename_part("../../etc/passwd"))
        self.assertEqual("unknown", backups.safe_filename_part(".."))


class ResolveRunPathsTests(unittest.TestCase):
    def resolve(
        self,
        current_directory: Path,
        *,
        artifacts_dir: Path | None = None,
        maps_path: Path | None = None,
        write_files: bool = True,
    ) -> backups.RunPaths:
        return backups.resolve_run_paths(
            endpoint="https://sourcegraph.example.com",
            command_artifact_name="get",
            artifacts_dir=artifacts_dir,
            maps_path=maps_path,
            write_files=write_files,
            current_directory=current_directory,
        )

    def test_default_artifacts_dir_is_runs_directory_under_current_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            run_paths = self.resolve(directory)

        self.assertEqual(
            (directory / backups.ARTIFACTS_DIR_NAME).resolve(),
            run_paths.artifacts_dir,
        )
        self.assertEqual(
            run_paths.artifacts_dir / "sourcegraph.example.com",
            run_paths.endpoint_directory,
        )

    def test_relative_artifacts_dir_resolves_against_current_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            run_paths = self.resolve(directory, artifacts_dir=Path("custom-artifacts"))

        self.assertEqual((directory / "custom-artifacts").resolve(), run_paths.artifacts_dir)

    def test_absolute_artifacts_dir_is_used_verbatim(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            artifacts_dir = directory / "absolute-artifacts"
            run_paths = self.resolve(directory / "elsewhere", artifacts_dir=artifacts_dir)

        self.assertEqual(artifacts_dir.resolve(), run_paths.artifacts_dir)

    def test_default_maps_path_is_endpoint_directory_maps_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            run_paths = self.resolve(Path(directory_name))

        self.assertEqual(
            run_paths.endpoint_directory / backups.DEFAULT_MAPS_FILE_NAME,
            run_paths.maps_path,
        )

    def test_relative_maps_path_resolves_against_current_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            run_paths = self.resolve(directory, maps_path=Path("custom-maps.yaml"))

        self.assertEqual((directory / "custom-maps.yaml").resolve(), run_paths.maps_path)

    def test_absolute_maps_path_override_is_respected(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            maps_path = directory / "team-maps.yaml"
            run_paths = self.resolve(directory, maps_path=maps_path)

        self.assertEqual(maps_path.resolve(), run_paths.maps_path)

    def test_generated_yaml_paths_live_in_the_endpoint_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            run_paths = self.resolve(Path(directory_name))

        self.assertEqual(
            run_paths.endpoint_directory / backups.CODE_HOSTS_FILE_NAME,
            run_paths.code_hosts_path,
        )
        self.assertEqual(
            run_paths.endpoint_directory / backups.AUTH_PROVIDERS_FILE_NAME,
            run_paths.auth_providers_path,
        )

    def test_creates_the_run_directory_exclusively(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            with mock.patch.object(backups, "run_timestamp", return_value=FIXED_TIMESTAMP):
                run_paths = self.resolve(directory)

            self.assertTrue(run_paths.run_directory.is_dir())
            self.assertEqual(f"{FIXED_TIMESTAMP}-get", run_paths.run_directory.name)
            self.assertEqual(
                run_paths.endpoint_directory / backups.RUNS_DIR_NAME,
                run_paths.run_directory.parent,
            )

    def test_same_second_collisions_get_distinct_suffixed_directories(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            with mock.patch.object(backups, "run_timestamp", return_value=FIXED_TIMESTAMP):
                first_run = self.resolve(directory)
                colliding_run = self.resolve(directory)
                third_run = self.resolve(directory)

            self.assertEqual(f"{FIXED_TIMESTAMP}-get", first_run.run_directory.name)
            self.assertEqual(f"{FIXED_TIMESTAMP}-get-2", colliding_run.run_directory.name)
            self.assertEqual(f"{FIXED_TIMESTAMP}-get-3", third_run.run_directory.name)
            self.assertEqual(
                3,
                len(
                    {
                        first_run.run_directory,
                        colliding_run.run_directory,
                        third_run.run_directory,
                    }
                ),
            )
            self.assertTrue(colliding_run.run_directory.is_dir())
            self.assertTrue(third_run.run_directory.is_dir())

    def test_pre_existing_timestamp_directory_is_never_reused(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            artifacts_dir = (directory / backups.ARTIFACTS_DIR_NAME).resolve()
            occupied_run_directory = (
                artifacts_dir
                / "sourcegraph.example.com"
                / backups.RUNS_DIR_NAME
                / f"{FIXED_TIMESTAMP}-get"
            )
            occupied_run_directory.mkdir(parents=True)
            sentinel = occupied_run_directory / "before.json"
            sentinel.write_text("{}")

            with mock.patch.object(backups, "run_timestamp", return_value=FIXED_TIMESTAMP):
                run_paths = self.resolve(directory)

            self.assertEqual(f"{FIXED_TIMESTAMP}-get-2", run_paths.run_directory.name)
            self.assertNotEqual(occupied_run_directory, run_paths.run_directory)
            # The occupied run's artifacts stay untouched.
            self.assertEqual("{}", sentinel.read_text())

    def test_write_files_false_creates_no_directories(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            run_paths = self.resolve(directory, write_files=False)

            self.assertFalse(run_paths.write_files)
            self.assertFalse(run_paths.run_directory.exists())
            self.assertEqual([], list(directory.iterdir()))


class RunPathsArtifactTests(unittest.TestCase):
    def test_artifact_path_names_state_files(self) -> None:
        run_directory = Path("/artifacts/sourcegraph.example.com/runs/run")
        run_paths = make_run_paths(run_directory)

        self.assertEqual(run_directory / "before.json", run_paths.artifact_path("before"))
        self.assertEqual(run_directory / "after.json", run_paths.artifact_path("after"))
        self.assertEqual(run_directory / "diff.json", run_paths.artifact_path("diff"))

    def test_artifact_path_family_prefixes_keep_combined_runs_collision_free(self) -> None:
        run_directory = Path("/artifacts/sourcegraph.example.com/runs/run")
        run_paths = make_run_paths(run_directory)

        family_paths = {
            run_paths.artifact_path(state, family="saml-organizations")
            for state in ("before", "after", "diff")
        }
        permission_paths = {run_paths.artifact_path(state) for state in ("before", "after", "diff")}

        self.assertEqual(
            run_directory / "saml-organizations-before.json",
            run_paths.artifact_path("before", family="saml-organizations"),
        )
        self.assertEqual(set(), family_paths & permission_paths)

    def test_artifact_path_supports_custom_suffixes(self) -> None:
        run_paths = make_run_paths(Path("/artifacts/endpoint/runs/run"))

        self.assertEqual(
            run_paths.run_directory / "before.yaml",
            run_paths.artifact_path("before", suffix="yaml"),
        )

    def test_artifact_path_sanitizes_hostile_names_inside_the_run_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            run_directory = Path(directory_name) / "runs" / "run"
            run_paths = make_run_paths(run_directory)

            for hostile_name in ("../../etc/passwd", "..", "/etc/shadow", "a/../../b"):
                with self.subTest(hostile_name=hostile_name):
                    artifact = run_paths.artifact_path(hostile_name)
                    self.assertEqual(run_directory, artifact.parent)
                    self.assertTrue(
                        artifact.resolve().is_relative_to(run_directory.resolve()),
                        f"{artifact} escapes {run_directory}",
                    )

    def test_input_copy_path_keeps_the_original_file_name(self) -> None:
        run_paths = make_run_paths(Path("/artifacts/endpoint/runs/run"))

        self.assertEqual(
            run_paths.run_directory / "maps.yaml",
            run_paths.input_copy_path("maps.yaml"),
        )

    def test_input_copy_path_sanitizes_hostile_names_inside_the_run_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            run_directory = Path(directory_name) / "runs" / "run"
            run_paths = make_run_paths(run_directory)

            for hostile_name in ("../../etc/passwd", "..", "/etc/shadow"):
                with self.subTest(hostile_name=hostile_name):
                    copy_path = run_paths.input_copy_path(hostile_name)
                    self.assertEqual(run_directory, copy_path.parent)
                    self.assertTrue(
                        copy_path.resolve().is_relative_to(run_directory.resolve()),
                        f"{copy_path} escapes {run_directory}",
                    )

    def test_log_path_is_log_json_in_the_run_directory(self) -> None:
        run_paths = make_run_paths(Path("/artifacts/endpoint/runs/run"))

        self.assertEqual(run_paths.run_directory / backups.LOG_FILE_NAME, run_paths.log_path)
        self.assertEqual("log.json", run_paths.log_path.name)


if __name__ == "__main__":
    unittest.main()
