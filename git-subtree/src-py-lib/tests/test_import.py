"""Basic package import smoke test."""

from __future__ import annotations

import unittest

import src_py_lib


class PackageImportTest(unittest.TestCase):
    """Verify the package can be imported."""

    def test_package_imports(self) -> None:
        self.assertIsNotNone(src_py_lib)

    def test_root_public_api_exports_common_entrypoints(self) -> None:
        self.assertIsNotNone(src_py_lib.GitHubClient)
        self.assertIsNotNone(src_py_lib.GraphQLClient)
        self.assertIsNotNone(src_py_lib.HTTPClient)
        self.assertIsNotNone(src_py_lib.JSONDict)
        self.assertIsNotNone(src_py_lib.LinearClientConfig)
        self.assertIsNotNone(src_py_lib.LoggingConfig)
        self.assertIsNotNone(src_py_lib.LoggingSettings)
        self.assertIsNotNone(src_py_lib.resolve_log_level_name)
        self.assertIsNotNone(src_py_lib.SlackClient)
        self.assertIsNotNone(src_py_lib.SlackPacer)
        self.assertIsNotNone(src_py_lib.SourcegraphClient)
        self.assertIsNotNone(src_py_lib.SourcegraphClientConfig)
        self.assertIsNotNone(src_py_lib.config_field)
        self.assertIsNotNone(src_py_lib.gh_cli_token)
        self.assertIsNotNone(src_py_lib.gcloud_adc_access_token)
        self.assertIsNotNone(src_py_lib.info)
        self.assertIsNotNone(src_py_lib.json_dicts)
        self.assertIsNotNone(src_py_lib.json_str)
        self.assertIsNotNone(src_py_lib.log)
        self.assertIsNotNone(src_py_lib.logging)
        self.assertIsNotNone(src_py_lib.logging_settings_from_config)
        self.assertIsNotNone(src_py_lib.linear_client_from_config)
        self.assertIsNotNone(src_py_lib.load_json_cache)
        self.assertIsNotNone(src_py_lib.normalize_sourcegraph_endpoint)
        self.assertIsNotNone(src_py_lib.parse_args)
        self.assertIsNotNone(src_py_lib.quota_project_from_adc)
        self.assertIsNotNone(src_py_lib.save_json_cache)
        self.assertIsNotNone(src_py_lib.slack_client_from_config)
        self.assertIsNotNone(src_py_lib.sourcegraph_client_from_config)
        self.assertIsNotNone(src_py_lib.stream_connection_nodes)
        self.assertIsNotNone(src_py_lib.write_tsv)


if __name__ == "__main__":
    unittest.main()
