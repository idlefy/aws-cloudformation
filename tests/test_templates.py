"""Rendered-template snapshots and the core-api compatibility contract."""

import json

import pytest
from conftest import (
    COGNITO_ACCOUNT_ID,
    ISSUER_HOST,
    MANAGE_COGNITO_PARAMS,
    MANAGE_PARAMS,
    ORG_ID,
    ORG_SUFFIX,
    POOL_ID,
    PROVISION_COGNITO_PARAMS,
    PROVISION_PARAMS,
    SNAPSHOTS,
    assert_snapshot,
    policy_documents,
)
from render import Renderer, load_template, outputs, parse_template, render, rule_violations

ACCOUNT = "123456789012"
MANAGE = "idlefy-manage.yaml"
# OidcProviderArn as v1.7.0 renders it, by CreateOidcProvider.
V170_PROVIDER_ARN = {
    "true": "<ref:OidcProvider>",
    "false": f"arn:aws:iam::{ACCOUNT}:oidc-provider/{ISSUER_HOST}",
}


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


def test_properties_that_replace_a_named_iam_resource_never_change(provision, manage):
    # CloudFormation REPLACES a managed policy when its Description, name or path changes, and
    # a role when its name or path changes. Every one of these has a fixed name, so a
    # replacement collides with the resource it replaces ("already exists") and the stack
    # update rolls back. v1.4.0 reworded the policy description and could not update any
    # existing stack. These strings are frozen; changing one needs a new resource name.
    policy = provision["ProvisionPolicy"]["Properties"]
    assert policy["Description"] == (
        "Fence for the Idlefy provision role - tag-scoped create/mutate, allowlisted regions and instance types."
    )
    assert policy["ManagedPolicyName"] == f"IdlefyProvisionPolicy-{ORG_SUFFIX}"
    assert "Path" not in policy
    assert provision["ProvisionRole"]["Properties"]["RoleName"] == f"IdlefyProvision-{ORG_SUFFIX}"
    assert "Path" not in provision["ProvisionRole"]["Properties"]
    assert manage["ManageRole"]["Properties"]["RoleName"] == f"IdlefyManage-{ORG_SUFFIX}"
    assert "Path" not in manage["ManageRole"]["Properties"]


def test_provision_stack_reports_its_version():
    # The app reads this output to decide which actions the deployed role supports; the
    # publish workflow stamps the placeholder with the tag.
    outputs = load_template("idlefy-provision.yaml")["Outputs"]
    assert outputs["TemplateVersion"]["Value"] == "__TEMPLATE_VERSION__"


def test_snapshot_provision(provision, request):
    assert_snapshot("idlefy-provision", policy_documents(provision), request)


def test_snapshot_provision_zone_move(provision_zone_move, request):
    assert_snapshot("idlefy-provision-zone-move", policy_documents(provision_zone_move), request)


# -- Federation=cognito (manage) ---------------------------------------------------------


def _snapshot_text(value) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


@pytest.mark.parametrize(
    ("extra", "snapshot"),
    [
        ({}, "idlefy-manage"),
        ({"Federation": "oidc"}, "idlefy-manage"),
        ({"CreateOidcProvider": "false", "IncludeMetrics": "false"}, "idlefy-manage-minimal"),
    ],
)
def test_manage_defaults_match_v170_snapshot(extra, snapshot):
    # Read-only comparison (never rewrites the file): the oidc rendering is v1.7.0's, unchanged.
    rendered = render(MANAGE, {**MANAGE_PARAMS, **extra})
    assert _snapshot_text(policy_documents(rendered)) == (SNAPSHOTS / f"{snapshot}.json").read_text()
    expected = {"ManageRole"} | ({"OidcProvider"} if extra.get("CreateOidcProvider", "true") == "true" else set())
    assert set(rendered) == expected


@pytest.mark.parametrize("federation", [None, "oidc"])
@pytest.mark.parametrize("create", ["true", "false"])
def test_manage_oidc_outputs_match_v170(create, federation):
    params = {**MANAGE_PARAMS, "CreateOidcProvider": create}
    if federation:
        params["Federation"] = federation
    assert outputs(MANAGE, params) == {
        "RoleArn": "<getatt:ManageRole.Arn>",
        "OidcProviderArn": V170_PROVIDER_ARN[create],
    }


def test_manage_cognito_has_no_oidc_provider(manage_cognito):
    assert "OidcProvider" not in manage_cognito
    assert outputs(MANAGE, MANAGE_COGNITO_PARAMS) == {"RoleArn": "<getatt:ManageRole.Arn>"}


@pytest.mark.parametrize("create", ["true", "false"])
def test_manage_cognito_ignores_create_oidc_provider(create, manage_cognito):
    params = {**MANAGE_COGNITO_PARAMS, "CreateOidcProvider": create}
    rendered = render(MANAGE, params)
    assert "OidcProvider" not in rendered
    assert rendered == manage_cognito
    assert "OidcProviderArn" not in outputs(MANAGE, params)


def test_manage_cognito_changes_only_the_trust(manage, manage_cognito):
    # Same role name, permissions, tags and session length; only who may assume it differs.
    oidc_role = dict(manage["ManageRole"]["Properties"])
    cognito_role = dict(manage_cognito["ManageRole"]["Properties"])
    assert oidc_role.pop("AssumeRolePolicyDocument") != cognito_role.pop("AssumeRolePolicyDocument")
    assert cognito_role == oidc_role


def test_manage_cognito_rule_requires_pool():
    cognito = {**MANAGE_PARAMS, "Federation": "cognito"}
    no_pool = {**cognito, "IdentityPoolId": "", "CognitoAccountId": COGNITO_ACCOUNT_ID}
    no_account = {**cognito, "IdentityPoolId": POOL_ID, "CognitoAccountId": ""}
    both = {**cognito, "IdentityPoolId": POOL_ID, "CognitoAccountId": COGNITO_ACCOUNT_ID}
    oidc_empty = {**MANAGE_PARAMS, "Federation": "oidc", "IdentityPoolId": "", "CognitoAccountId": ""}
    assert rule_violations(MANAGE, no_pool) == ["CognitoNeedsPool"]
    assert rule_violations(MANAGE, no_account) == ["CognitoNeedsPool"]
    assert rule_violations(MANAGE, cognito) == ["CognitoNeedsPool"]
    assert rule_violations(MANAGE, both) == []
    assert rule_violations(MANAGE, oidc_empty) == []
    assert rule_violations(MANAGE, MANAGE_PARAMS) == []


def test_snapshot_manage_cognito(manage_cognito, request):
    assert_snapshot("idlefy-manage-cognito", policy_documents(manage_cognito), request)


# -- Federation=cognito (provision) ------------------------------------------------------

PROVISION = "idlefy-provision.yaml"
# The outputs as v1.7.0 renders them (the same for every parameter value).
V170_PROVISION_OUTPUTS = {
    "RoleArn": "<getatt:ProvisionRole.Arn>",
    "PolicyArn": "<ref:ProvisionPolicy>",
    "TemplateVersion": "__TEMPLATE_VERSION__",
}


@pytest.mark.parametrize(
    ("extra", "snapshot"),
    [
        ({}, "idlefy-provision"),
        ({"Federation": "oidc"}, "idlefy-provision"),
        ({"AllowZoneMove": "true"}, "idlefy-provision-zone-move"),
        ({"AllowZoneMove": "true", "Federation": "oidc"}, "idlefy-provision-zone-move"),
    ],
)
def test_provision_defaults_match_v170_snapshot(extra, snapshot):
    # Read-only comparison (never rewrites the file): the oidc rendering is v1.7.0's, unchanged.
    params = {**PROVISION_PARAMS, **extra}
    rendered = render(PROVISION, params)
    assert _snapshot_text(policy_documents(rendered)) == (SNAPSHOTS / f"{snapshot}.json").read_text()
    assert set(rendered) == {"ProvisionPolicy", "ProvisionRole"}
    assert outputs(PROVISION, params) == V170_PROVISION_OUTPUTS


def test_provision_cognito_outputs_are_unchanged():
    # TemplateVersion keeps its shape: the app reads it the same way for both kinds of stack.
    assert outputs(PROVISION, PROVISION_COGNITO_PARAMS) == V170_PROVISION_OUTPUTS


def test_provision_cognito_changes_only_the_trust(provision, provision_cognito):
    # Same fence policy, role name, limits, tags and session length; only who may assume it differs.
    assert set(provision_cognito) == {"ProvisionPolicy", "ProvisionRole"}
    assert provision_cognito["ProvisionPolicy"] == provision["ProvisionPolicy"]
    oidc_role = dict(provision["ProvisionRole"]["Properties"])
    cognito_role = dict(provision_cognito["ProvisionRole"]["Properties"])
    assert oidc_role.pop("AssumeRolePolicyDocument") != cognito_role.pop("AssumeRolePolicyDocument")
    assert cognito_role == oidc_role


def test_provision_cognito_rule_requires_pool():
    cognito = {**PROVISION_PARAMS, "Federation": "cognito"}
    no_pool = {**cognito, "IdentityPoolId": "", "CognitoAccountId": COGNITO_ACCOUNT_ID}
    no_account = {**cognito, "IdentityPoolId": POOL_ID, "CognitoAccountId": ""}
    both = {**cognito, "IdentityPoolId": POOL_ID, "CognitoAccountId": COGNITO_ACCOUNT_ID}
    oidc_empty = {**PROVISION_PARAMS, "Federation": "oidc", "IdentityPoolId": "", "CognitoAccountId": ""}
    assert rule_violations(PROVISION, no_pool) == ["CognitoNeedsPool"]
    assert rule_violations(PROVISION, no_account) == ["CognitoNeedsPool"]
    assert rule_violations(PROVISION, cognito) == ["CognitoNeedsPool"]
    assert rule_violations(PROVISION, both) == []
    assert rule_violations(PROVISION, oidc_empty) == []
    assert rule_violations(PROVISION, PROVISION_PARAMS) == []


def test_snapshot_provision_cognito(provision_cognito, request):
    assert_snapshot("idlefy-provision-cognito", policy_documents(provision_cognito), request)


# -- renderer ----------------------------------------------------------------------------

_RENDER_TPL = """
Parameters:
  A: {Type: String}
  B: {Type: String, Default: "no"}
Conditions:
  NotA: !Not [!Condition IsA]
  IsA: !Equals [!Ref A, "yes"]
  Both: !And [!Condition IsA, !Equals [!Ref B, "yes"]]
Resources:
  Always: {Type: AWS::SNS::Topic, Properties: {TopicName: !If [Both, both, not-both]}}
  OnlyA: {Type: AWS::SNS::Topic, Condition: IsA, Properties: {}}
Outputs:
  Always: {Value: !Ref A}
  OnlyA: {Condition: IsA, Value: !Ref OnlyA}
"""


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("yes", "yes", {"NotA": False, "IsA": True, "Both": True}),
        ("yes", "no", {"NotA": False, "IsA": True, "Both": False}),
        ("no", "yes", {"NotA": True, "IsA": False, "Both": False}),
    ],
)
def test_render_and_not(a, b, expected):
    # NotA refers to IsA before IsA is declared: conditions resolve by name, not by order.
    renderer = Renderer(parse_template(_RENDER_TPL), {"A": a, "B": b})
    assert renderer.conditions == expected
    topic = renderer.resources()["Always"]["Properties"]["TopicName"]
    assert topic == ("both" if expected["Both"] else "not-both")


def test_render_condition_drops_resource_and_output():
    on = Renderer(parse_template(_RENDER_TPL), {"A": "yes"})
    off = Renderer(parse_template(_RENDER_TPL), {"A": "no"})
    assert set(on.resources()) == {"Always", "OnlyA"}
    assert on.outputs() == {"Always": "yes", "OnlyA": "<ref:OnlyA>"}
    assert set(off.resources()) == {"Always"}
    assert off.outputs() == {"Always": "no"}


def test_render_raises_on_unknown_param():
    # A misspelt parameter would otherwise silently render the default.
    with pytest.raises(ValueError, match="Federaton"):
        render(MANAGE, {**MANAGE_PARAMS, "Federaton": "cognito"})
    with pytest.raises(ValueError, match="Bogus"):
        render("idlefy-provision.yaml", {"OrgId": ORG_ID, "IssuerHost": ISSUER_HOST, "Bogus": "x"})
