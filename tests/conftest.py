import json
import uuid
from pathlib import Path

import pytest

from render import Renderer, load_template, policy_documents

SNAPSHOTS = Path(__file__).resolve().parent / "snapshots"
ORG_ID = "9b546eb4-2394-48c0-adc7-7386ccd50422"
ISSUER_HOST = "app.idlefy.dev"
ORG_SUFFIX = uuid.UUID(ORG_ID).hex[:12]

MANAGE_PARAMS = {"OrgId": ORG_ID, "IssuerHost": ISSUER_HOST}
PROVISION_PARAMS = {
    "OrgId": ORG_ID,
    "IssuerHost": ISSUER_HOST,
    "AllowedRegions": "eu-central-1,us-east-1",
    "AllowedInstanceTypes": "m7i.large,m7i.xlarge,g6.xlarge",
}


def render(name: str, params: dict) -> dict:
    return Renderer(load_template(name), params).resources()


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
def provision():
    return render("idlefy-provision.yaml", PROVISION_PARAMS)


def assert_snapshot(name: str, value, request):
    """Compare against tests/snapshots/<name>.json; `--snapshot-update` rewrites it."""
    path = SNAPSHOTS / f"{name}.json"
    rendered = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if request.config.getoption("--snapshot-update") or not path.exists():
        path.write_text(rendered)
    assert rendered == path.read_text(), f"snapshot {name} changed; run with --snapshot-update if intended"


def pytest_addoption(parser):
    parser.addoption("--snapshot-update", action="store_true", default=False)


__all__ = ["policy_documents", "assert_snapshot", "ORG_ID", "ORG_SUFFIX", "ISSUER_HOST"]
