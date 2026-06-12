"""Converge the test Sourcegraph instance to the state in tests/setup.yaml.

Run BEFORE tests/run.py. Dry-run by default; --apply mutates.

    uv run tests/setup.py            # report drift
    uv run tests/setup.py --apply    # fix drift

Reads SRC_ENDPOINT / SRC_ACCESS_TOKEN from .env. GraphQL is used for
instance-level reads (site config, auth providers, SAML verification);
raw SQL via `kubectl exec` against the pgsql pod is used for bulk state
(user/repo counts, email rewrites, fabricated SAML accounts, permission
hygiene) because it is orders of magnitude faster than per-user GraphQL.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

import src_py_lib as src
import yaml
from dotenv import dotenv_values

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from src_auth_perms_sync.shared import saml_groups  # noqa: E402
from src_auth_perms_sync.shared import site_config as shared_site_config  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("setup")

SETUP_CONFIG_PATH = Path(__file__).with_name("setup.yaml")
ENV_PATH = Path(__file__).resolve().parents[1] / ".env"

SAFE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9._@+-]+$")

EXTERNAL_ACCOUNTS_QUERY = """
query SetupSamlAccounts($username: String!) {
  user(username: $username) {
    externalAccounts(first: 50) {
      nodes { serviceType serviceID clientID accountData }
    }
  }
}
"""

AUTH_PROVIDERS_QUERY = """
query SetupAuthProviders {
  site {
    authProviders {
      nodes { serviceType serviceID clientID }
    }
  }
}
"""

PENDING_PERMISSIONS_QUERY = "query SetupPending { usersWithPendingPermissions }"


def run_sql(kubectl_config: dict[str, Any], statement: str) -> list[list[str]]:
    """Run SQL on the pgsql pod; return rows of pipe-separated fields."""
    script = f"SET app.current_tenant = '{int(kubectl_config['tenantID'])}';\n{statement}"
    command = [
        "kubectl",
        "exec",
        "-i",
        "-n",
        str(kubectl_config["namespace"]),
        f"pod/{kubectl_config['pod']}",
        "--",
        "psql",
        "-X",
        "-q",
        "-At",
        "-v",
        "ON_ERROR_STOP=1",
        "-U",
        str(kubectl_config["databaseUser"]),
        "-d",
        str(kubectl_config["database"]),
    ]
    completed = subprocess.run(command, input=script, capture_output=True, text=True, timeout=120)
    if completed.returncode != 0:
        raise RuntimeError(f"psql failed: {completed.stderr.strip()}")
    return [line.split("|") for line in completed.stdout.splitlines() if line]


def upsert_saml_account(
    kubectl_config: dict[str, Any],
    username: str,
    groups: list[str],
    *,
    service_id: str,
    client_id: str,
    account_id: str,
) -> None:
    """Write one fabricated SAML external account directly to the database.

    Also used by tests/run.py's live SAML-group-change check, so the
    interpolated names are validated here, right at the SQL boundary.
    """
    if not SAFE_NAME_PATTERN.match(username) or not all(
        SAFE_NAME_PATTERN.match(group) for group in groups
    ):
        raise RuntimeError(f"unsafe username/group name for {username!r}")
    account_data = json.dumps(
        {
            "NameID": account_id,
            "Values": {
                "groups": {
                    "Name": "groups",
                    "Values": [{"Value": group} for group in groups],
                },
                "Email": {"Name": "Email", "Values": [{"Value": account_id}]},
            },
        }
    )
    run_sql(
        kubectl_config,
        "INSERT INTO user_external_accounts "
        "  (user_id, service_type, service_id, client_id, account_id, "
        "   account_data, encryption_key_id, kind) "
        f"SELECT u.id, 'saml', '{service_id}', '{client_id}', '{account_id}', "
        f"  '{account_data}', '', 'AUTH' "
        f"FROM users u WHERE u.username = '{username}' AND u.deleted_at IS NULL "
        "ON CONFLICT (tenant_id, user_id, service_type, service_id, client_id, "
        "             account_id, kind) WHERE deleted_at IS NULL "
        "DO UPDATE SET account_data = EXCLUDED.account_data, updated_at = now();",
    )


@dataclass
class Outcome:
    """One named check: in-sync, fixed, or needing attention."""

    name: str
    ok: bool
    detail: str


@dataclass
class Setup:
    config: dict[str, Any]
    client: src.SourcegraphClient
    apply: bool
    outcomes: list[Outcome] = field(default_factory=lambda: list[Outcome]())

    # -- helpers ------------------------------------------------------------

    def record(self, name: str, ok: bool, detail: str) -> None:
        self.outcomes.append(Outcome(name, ok, detail))
        log.log(
            logging.INFO if ok else logging.ERROR, "%s %s — %s", "✓" if ok else "✗", name, detail
        )

    def sql(self, statement: str) -> list[list[str]]:
        """Run SQL on the pgsql pod; return rows of pipe-separated fields."""
        return run_sql(self.config["kubectl"], statement)

    def sql_value(self, statement: str) -> str:
        rows = self.sql(statement)
        return rows[0][0] if rows and rows[0] else ""

    # -- checks -------------------------------------------------------------

    def check_site_config(self) -> None:
        try:
            validated = shared_site_config.validate_site_config(self.client)
            self.record("site-config", True, f"bindID={validated.bind_id_mode}")
        except SystemExit as exception:
            self.record("site-config", False, str(exception))

    def saml_provider(self) -> tuple[str, str] | None:
        data = self.client.graphql(AUTH_PROVIDERS_QUERY, follow_pages=False)
        providers = cast(
            "list[dict[str, str]]",
            cast("dict[str, Any]", cast("dict[str, Any]", data)["site"])["authProviders"]["nodes"],
        )
        for provider in providers:
            if provider["serviceType"] == "saml":
                return provider["serviceID"], provider["clientID"]
        return None

    def check_users_and_repos(self) -> None:
        users_config = self.config["users"]
        repos_config = self.config["repos"]
        user_count = int(
            self.sql_value(
                "SELECT count(*) FROM users "
                f"WHERE username ~ '{users_config['usernamePattern']}' AND deleted_at IS NULL;"
            )
        )
        repo_count = int(
            self.sql_value(
                "SELECT count(*) FROM repo "
                f"WHERE name ~ '{repos_config['namePattern']}' AND deleted_at IS NULL;"
            )
        )
        self.record(
            "users",
            user_count >= int(users_config["count"]),
            f"{user_count} live synthetic users (need {users_config['count']}); "
            "bulk creation is out of setup's scope — reprovision the instance if short",
        )
        self.record(
            "repos",
            repo_count >= int(repos_config["count"]),
            f"{repo_count} live synthetic repos (need {repos_config['count']})",
        )

    def check_emails(self) -> None:
        users_config = self.config["users"]
        template = str(users_config["emailTemplate"])
        suffix = template.replace("{username}", "")
        if (
            not SAFE_NAME_PATTERN.match(suffix.lstrip("@"))
            or template[: len("{username}")] != "{username}"
        ):
            raise RuntimeError(f"emailTemplate must be '{{username}}@<domain>': {template!r}")
        drift_condition = (
            "u.id = ue.user_id "
            f"AND u.username ~ '{users_config['usernamePattern']}' "
            "AND u.deleted_at IS NULL AND ue.deleted_at IS NULL "
            f"AND ue.email <> u.username || '{suffix}'"
        )
        stale = int(
            self.sql_value(
                f"SELECT count(*) FROM user_emails ue JOIN users u ON {drift_condition};"
            )
        )
        if stale == 0:
            self.record("emails", True, f"all live synthetic users match {template}")
            return
        if not self.apply:
            self.record(
                "emails", False, f"{stale} address(es) to rewrite to {template} (run with --apply)"
            )
            return
        updated = self.sql_value(
            "WITH updated AS ("
            f"  UPDATE user_emails ue SET email = u.username || '{suffix}' "
            f"  FROM users u WHERE {drift_condition} RETURNING 1"
            ") SELECT count(*) FROM updated;"
        )
        self.record("emails", True, f"rewrote {updated} address(es) to {template}")

    def check_saml_accounts(self) -> None:
        provider = self.saml_provider()
        if provider is None:
            self.record("saml-provider", False, "no SAML auth provider on the instance")
            return
        service_id, client_id = provider
        self.record("saml-provider", True, f"serviceID={service_id}")

        email_template = str(self.config["users"]["emailTemplate"])
        accounts = cast("dict[str, list[str]]", self.config["samlAccounts"])
        drift: list[str] = []
        for username, groups in accounts.items():
            if not SAFE_NAME_PATTERN.match(username) or not all(
                SAFE_NAME_PATTERN.match(group) for group in groups
            ):
                raise RuntimeError(f"unsafe username/group name for {username!r}")
            current = self.fabricated_groups_on_instance(username, service_id, client_id)
            if current == list(groups):
                continue
            drift.append(f"{username}: {current} → {list(groups)}")
            if self.apply:
                upsert_saml_account(
                    self.config["kubectl"],
                    username,
                    groups,
                    service_id=service_id,
                    client_id=client_id,
                    account_id=email_template.replace("{username}", username),
                )
        if not drift:
            self.record("saml-accounts", True, f"{len(accounts)} fabricated account(s) in sync")
        elif self.apply:
            for username in accounts:
                expected = list(accounts[username])
                actual = self.fabricated_groups_on_instance(username, service_id, client_id)
                if actual != expected:
                    self.record(
                        "saml-accounts", False, f"{username}: wrote {expected}, read back {actual}"
                    )
                    return
            self.record("saml-accounts", True, f"converged: {'; '.join(drift)}")
        else:
            self.record("saml-accounts", False, f"drift (run with --apply): {'; '.join(drift)}")

    def fabricated_groups_on_instance(
        self, username: str, service_id: str, client_id: str
    ) -> list[str] | None:
        """Read the user's SAML groups back through the REAL consumer path:
        GraphQL accountData parsed by the product's own extract_saml_groups."""
        data = self.client.graphql(
            EXTERNAL_ACCOUNTS_QUERY, {"username": username}, follow_pages=False
        )
        user = cast("dict[str, Any] | None", cast("dict[str, Any]", data).get("user"))
        if user is None:
            return None
        for account in cast(
            "list[dict[str, Any]]", cast("dict[str, Any]", user["externalAccounts"])["nodes"]
        ):
            if (
                account["serviceType"] == "saml"
                and account["serviceID"] == service_id
                and account["clientID"] == client_id
            ):
                raw = account.get("accountData")
                if isinstance(raw, str):
                    raw = json.loads(raw)
                return saml_groups.extract_saml_groups(cast("dict[str, Any] | None", raw))
        return None

    def check_permissions_hygiene(self) -> None:
        hygiene = self.config["permissionsHygiene"]
        orphaned = int(
            self.sql_value(
                "SELECT count(*) FROM user_repo_permissions urp "
                "JOIN repo r ON r.id = urp.repo_id "
                "WHERE urp.source = 'api' AND r.deleted_at IS NOT NULL;"
            )
        )
        if orphaned and self.apply:
            self.sql(
                "DELETE FROM user_repo_permissions urp USING repo r "
                "WHERE r.id = urp.repo_id AND urp.source = 'api' "
                "AND r.deleted_at IS NOT NULL;"
            )
            self.record("orphaned-grants", True, f"deleted {orphaned} grant(s) on deleted repos")
        else:
            self.record(
                "orphaned-grants",
                orphaned == 0,
                "none"
                if orphaned == 0
                else f"{orphaned} grant(s) on deleted repos (--apply deletes)",
            )

        live_grants = int(
            self.sql_value(
                "SELECT count(*) FROM user_repo_permissions urp "
                "JOIN repo r ON r.id = urp.repo_id "
                "WHERE urp.source = 'api' AND r.deleted_at IS NULL;"
            )
        )
        threshold = int(hygiene["maxExplicitGrants"])
        detail = f"{live_grants} explicit grant(s) on live repos (threshold {threshold})"
        if live_grants > threshold:
            top_rows = self.sql(
                "SELECT r.name, count(*) FROM user_repo_permissions urp "
                "JOIN repo r ON r.id = urp.repo_id "
                "WHERE urp.source = 'api' AND r.deleted_at IS NULL "
                "GROUP BY r.name ORDER BY count(*) DESC LIMIT 5;"
            )
            top = ", ".join(f"{name}={count}" for name, count in top_rows)
            detail += f"; leftovers from an unfinished run? top: {top}"
        self.record("live-grants", live_grants <= threshold, detail)

    def check_pending_permissions(self) -> None:
        """Pending bindIDs (grants that never resolved to a user).

        Live fixture cases seed pending bindIDs matching the synthetic
        prefix and restore them away; leftovers mean an interrupted run and
        --apply deletes exactly those rows. Anything else has an UNKNOWN
        origin — setup must not silently destroy it. Investigate, then
        clear deliberately (an empty setRepositoryPermissionsForUsers on
        the affected repo removes its pending rows).
        """
        prefix = str(self.config["permissionsHygiene"]["syntheticPendingBindIDPrefix"])
        if not SAFE_NAME_PATTERN.match(prefix):
            raise RuntimeError(f"unsafe syntheticPendingBindIDPrefix: {prefix!r}")
        pending = self.pending_bind_ids()
        unknown = sorted(bind_id for bind_id in pending if not bind_id.startswith(prefix))
        synthetic = sorted(bind_id for bind_id in pending if bind_id.startswith(prefix))
        self.record(
            "pending-permissions",
            not unknown,
            "none of unknown origin"
            if not unknown
            else f"{len(unknown)} pending bindID(s) of unknown origin: {unknown[:5]} — "
            "investigate before clearing (setup never deletes these)",
        )
        if not synthetic:
            return
        if not self.apply:
            self.record(
                "pending-permissions-synthetic",
                False,
                f"{len(synthetic)} synthetic leftover(s) from an interrupted live "
                f"run: {synthetic[:5]} (run with --apply)",
            )
            return
        self.sql(
            "DELETE FROM pending_repo_permissions "
            f"WHERE service_type = 'sourcegraph' AND bind_id LIKE '{prefix}%';"
        )
        still_synthetic = sorted(
            bind_id for bind_id in self.pending_bind_ids() if bind_id.startswith(prefix)
        )
        self.record(
            "pending-permissions-synthetic",
            not still_synthetic,
            f"deleted {len(synthetic)} synthetic leftover(s): {synthetic[:5]}"
            if not still_synthetic
            else f"delete did not stick; still pending: {still_synthetic[:5]}",
        )

    def pending_bind_ids(self) -> list[str]:
        return cast(
            "list[str]",
            cast("dict[str, Any]", self.client.graphql(PENDING_PERMISSIONS_QUERY))[
                "usersWithPendingPermissions"
            ],
        )

    def run(self) -> int:
        self.check_site_config()
        self.check_users_and_repos()
        self.check_emails()
        self.check_saml_accounts()
        self.check_permissions_hygiene()
        self.check_pending_permissions()
        failed = [outcome for outcome in self.outcomes if not outcome.ok]
        log.info(
            "Summary: %d ok, %d need attention.%s",
            len(self.outcomes) - len(failed),
            len(failed),
            "" if self.apply or not failed else " Re-run with --apply to converge.",
        )
        return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply", action="store_true", help="converge the instance (default: report only)"
    )
    arguments = parser.parse_args()

    environment = {key: value for key, value in dotenv_values(ENV_PATH).items() if value}
    endpoint = environment.get("SRC_ENDPOINT")
    token = environment.get("SRC_ACCESS_TOKEN")
    if not endpoint or not token:
        log.error("SRC_ENDPOINT / SRC_ACCESS_TOKEN missing from %s", ENV_PATH)
        return 1

    config = cast("dict[str, Any]", yaml.safe_load(SETUP_CONFIG_PATH.read_text()))
    client = src.SourcegraphClient(endpoint=endpoint, token=token, http=src.HTTPClient(timeout=60))
    log.info(
        "Converging %s to %s (%s)",
        endpoint,
        SETUP_CONFIG_PATH.name,
        "apply" if arguments.apply else "dry-run",
    )
    try:
        return Setup(config=config, client=client, apply=arguments.apply).run()
    finally:
        client.http.close()


if __name__ == "__main__":
    sys.exit(main())
