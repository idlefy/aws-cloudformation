import json
import uuid
from pathlib import Path

import pytest

from render import policy_documents, render

SNAPSHOTS = Path(__file__).resolve().parent / "snapshots"
ORG_ID = "9b546eb4-2394-48c0-adc7-7386ccd50422"
ISSUER_HOST = "app.idlefy.dev"
ORG_SUFFIX = uuid.UUID(ORG_ID).hex[:12]
# The dev identity pool and the account that holds it (Federation=cognito).
POOL_ID = "eu-central-1:3fff6a44-f400-4cdd-ac13-e1ad7a9264a3"
COGNITO_ACCOUNT_ID = "995603458290"
# The amr entry Cognito adds for a token from the org's issuer: names the org (manage) or
# the org's provision subject. The trust pins it, so the pool alone admits nobody.
MANAGE_PIN = f"arn:aws:iam::{COGNITO_ACCOUNT_ID}:oidc-provider/{ISSUER_HOST}:OIDC:{ORG_ID}"
PROVISION_PIN = MANAGE_PIN + ":provision"

MANAGE_PARAMS = {"OrgId": ORG_ID, "IssuerHost": ISSUER_HOST}
MANAGE_COGNITO_PARAMS = {
    **MANAGE_PARAMS,
    "Federation": "cognito",
    "IdentityPoolId": POOL_ID,
    "CognitoAccountId": COGNITO_ACCOUNT_ID,
}
PROVISION_PARAMS = {
    "OrgId": ORG_ID,
    "IssuerHost": ISSUER_HOST,
    "AllowedRegions": "eu-central-1,us-east-1",
    "AllowedInstanceTypes": "m7i.large,m7i.xlarge,g6.xlarge",
}


@pytest.fixture(scope="session")
def manage():
    return render("idlefy-manage.yaml", MANAGE_PARAMS)


@pytest.fixture(scope="session")
def manage_no_provider_no_metrics():
    return render(
        "idlefy-manage.yaml",
        {**MANAGE_PARAMS, "CreateOidcProvider": "false", "IncludeMetrics": "false"},
    )


@pytest.fixture(scope="session")
def manage_cognito():
    return render("idlefy-manage.yaml", MANAGE_COGNITO_PARAMS)


@pytest.fixture(scope="session")
def provision():
    return render("idlefy-provision.yaml", PROVISION_PARAMS)


@pytest.fixture(scope="session")
def provision_zone_move():
    return render("idlefy-provision.yaml", {**PROVISION_PARAMS, "AllowZoneMove": "true"})


def assert_snapshot(name: str, value, request):
    """Compare against tests/snapshots/<name>.json; `--snapshot-update` rewrites it."""
    path = SNAPSHOTS / f"{name}.json"
    rendered = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if request.config.getoption("--snapshot-update") or not path.exists():
        path.write_text(rendered)
    assert rendered == path.read_text(), f"snapshot {name} changed; run with --snapshot-update if intended"


def pytest_addoption(parser):
    parser.addoption("--snapshot-update", action="store_true", default=False)


__all__ = [
    "policy_documents", "render", "assert_snapshot", "ORG_ID", "ORG_SUFFIX", "ISSUER_HOST",
    "POOL_ID", "COGNITO_ACCOUNT_ID", "MANAGE_PIN", "PROVISION_PIN", "MANAGE_PARAMS", "MANAGE_COGNITO_PARAMS",
]
