"""Rendered-template snapshots and the core-api compatibility contract."""

import json

from conftest import ISSUER_HOST, ORG_ID, ORG_SUFFIX, assert_snapshot, policy_documents

ACCOUNT = "123456789012"


def test_manage_role_name_uses_12_hex_org_suffix(manage):
    assert manage["ManageRole"]["Properties"]["RoleName"] == f"IdlefyManage-{ORG_SUFFIX}"
    assert len(ORG_SUFFIX) == 12


def test_provision_role_and_policy_names(provision):
    assert provision["ProvisionRole"]["Properties"]["RoleName"] == f"IdlefyProvision-{ORG_SUFFIX}"
    assert provision["ProvisionPolicy"]["Properties"]["ManagedPolicyName"] == f"IdlefyProvisionPolicy-{ORG_SUFFIX}"


def test_manage_trust_policy(manage):
    trust = json.loads(manage["ManageRole"]["Properties"]["AssumeRolePolicyDocument"])
    (stmt,) = trust["Statement"]
    assert stmt["Action"] == "sts:AssumeRoleWithWebIdentity"
    assert stmt["Principal"]["Federated"] == "<ref:OidcProvider>"
    assert stmt["Condition"]["StringEquals"] == {
        f"{ISSUER_HOST}:aud": "sts.amazonaws.com",
        f"{ISSUER_HOST}:sub": ORG_ID,
    }


def test_manage_without_provider_points_at_existing_provider_arn(manage_no_provider_no_metrics):
    assert "OidcProvider" not in manage_no_provider_no_metrics
    trust = json.loads(manage_no_provider_no_metrics["ManageRole"]["Properties"]["AssumeRolePolicyDocument"])
    assert trust["Statement"][0]["Principal"]["Federated"] == (
        f"arn:aws:iam::{ACCOUNT}:oidc-provider/{ISSUER_HOST}"
    )


def test_provision_trust_policy_uses_provision_subject(provision):
    trust = json.loads(provision["ProvisionRole"]["Properties"]["AssumeRolePolicyDocument"])
    (stmt,) = trust["Statement"]
    assert stmt["Principal"]["Federated"] == f"arn:aws:iam::{ACCOUNT}:oidc-provider/{ISSUER_HOST}"
    assert stmt["Condition"]["StringEquals"][f"{ISSUER_HOST}:sub"] == f"{ORG_ID}:provision"
    assert stmt["Condition"]["StringEquals"][f"{ISSUER_HOST}:aud"] == "sts.amazonaws.com"


def test_provision_policy_is_attached_and_is_the_boundary(provision):
    role = provision["ProvisionRole"]["Properties"]
    assert role["ManagedPolicyArns"] == ["<ref:ProvisionPolicy>"]
    assert role["PermissionsBoundary"] == "<ref:ProvisionPolicy>"
    assert "Roles" not in provision["ProvisionPolicy"]["Properties"]


def test_manage_metrics_statement_is_conditional(manage, manage_no_provider_no_metrics):
    full = manage["ManageRole"]["Properties"]["Policies"][0]["PolicyDocument"]
    minimal = manage_no_provider_no_metrics["ManageRole"]["Properties"]["Policies"][0]["PolicyDocument"]
    sids = lambda doc: [s["Sid"] for s in doc["Statement"]]
    assert sids(full) == ["IdlefyCore", "IdlefyVMManagementLower", "IdlefyVMManagementUpper", "IdlefyPricing", "IdlefyMetrics"]
    assert sids(minimal) == sids(full)[:-1]


def test_session_durations(manage, provision):
    assert manage["ManageRole"]["Properties"]["MaxSessionDuration"] == 3600
    assert provision["ProvisionRole"]["Properties"]["MaxSessionDuration"] == 3600


def test_snapshot_manage(manage, request):
    assert_snapshot("idlefy-manage", policy_documents(manage), request)


def test_snapshot_manage_minimal(manage_no_provider_no_metrics, request):
    assert_snapshot("idlefy-manage-minimal", policy_documents(manage_no_provider_no_metrics), request)


def test_snapshot_provision(provision, request):
    assert_snapshot("idlefy-provision", policy_documents(provision), request)
