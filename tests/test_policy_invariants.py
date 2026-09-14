"""Fence invariants for the provision policy.

These fail CI when someone "just adds an action" without the tag/region fence.
"""

import fnmatch

import pytest

FENCE_TAG = "IdlefyManaged"
REQUEST_TAG = f"aws:RequestTag/{FENCE_TAG}"
RESOURCE_TAG = f"ec2:ResourceTag/{FENCE_TAG}"

# Actions that create resources: must be gated on the request tag (or, for
# child resources created inside a managed VPC, on the parent's resource tag).
CREATE_ACTIONS = {
    "ec2:CreateVpc", "ec2:CreateSubnet", "ec2:CreateInternetGateway", "ec2:CreateRouteTable",
    "ec2:CreateSecurityGroup", "ec2:AllocateAddress", "ec2:CreateVolume", "ec2:RunInstances",
}
# Actions that must never be allowed by this role, regardless of conditions.
FORBIDDEN_ALLOWS = {
    "iam:*", "iam:PassRole", "sts:*", "organizations:*",
    "ec2:ModifyInstanceAttribute", "ec2:DeleteTags",
    "ec2:AssociateIamInstanceProfile", "ec2:ReplaceIamInstanceProfileAssociation",
    "ec2:ModifyLaunchTemplate", "ec2:CreateLaunchTemplate",
}
REQUIRED_DENIES = {
    "iam:PassRole", "ec2:AssociateIamInstanceProfile", "ec2:ReplaceIamInstanceProfileAssociation",
    "ec2:ModifyInstanceAttribute", "ec2:DeleteTags", "sts:*", "organizations:*",
}
# Read-only prefixes that legitimately have no tag condition.
READ_ONLY = ("ec2:Describe", "ec2:GetConsoleOutput", "servicequotas:", "pricing:", "ssm:Get")


@pytest.fixture(scope="session")
def statements(provision):
    return provision["ProvisionPolicy"]["Properties"]["PolicyDocument"]["Statement"]


def _actions(stmt):
    a = stmt["Action"]
    return [a] if isinstance(a, str) else list(a)


def _cond_keys(stmt):
    return {k for op in stmt.get("Condition", {}).values() for k in op}


def _matches(action, patterns):
    return any(fnmatch.fnmatch(action, p) for p in patterns)


def test_every_allow_statement_has_a_sid(statements):
    assert all(s.get("Sid") for s in statements)


def test_mutating_actions_require_the_resource_tag(statements):
    for s in statements:
        if s["Effect"] != "Allow":
            continue
        for action in _actions(s):
            if action.startswith(READ_ONLY) or action in CREATE_ACTIONS or action == "ec2:CreateTags":
                continue
            assert RESOURCE_TAG in _cond_keys(s), f"{s['Sid']}: {action} lacks {RESOURCE_TAG}"


def test_create_actions_require_request_tag_or_managed_parent(statements):
    for s in statements:
        if s["Effect"] != "Allow":
            continue
        for action in _actions(s):
            if action not in CREATE_ACTIONS:
                continue
            keys = _cond_keys(s)
            resource = s["Resource"]
            resources = [resource] if isinstance(resource, str) else resource
            if REQUEST_TAG in keys:
                continue
            # RunInstances on referenced resources (subnet/SG/ENI/image/key-pair) and
            # child creates inside a managed VPC are gated differently.
            if action == "ec2:RunInstances" and all(r != "*" and "instance/" not in r and "volume/" not in r for r in resources):
                assert RESOURCE_TAG in keys or "ec2:Owner" in keys or "aws:RequestedRegion" in keys, s["Sid"]
                continue
            if all(r.endswith(":vpc/*") for r in resources):
                assert RESOURCE_TAG in keys, s["Sid"]
                continue
            pytest.fail(f"{s['Sid']}: {action} is not fenced by {REQUEST_TAG}")


def test_run_instances_on_instances_is_type_and_region_limited(statements):
    stmt = next(s for s in statements if s["Sid"] == "RunInstancesInstance")
    keys = _cond_keys(stmt)
    assert {"ec2:InstanceType", "aws:RequestedRegion", REQUEST_TAG} <= keys
    assert stmt["Condition"]["StringEquals"]["ec2:InstanceType"] == ["m7i.large", "m7i.xlarge", "g6.xlarge"]


def test_run_instances_volume_size_is_capped(statements):
    stmt = next(s for s in statements if s["Sid"] == "RunInstancesVolume")
    assert stmt["Condition"]["NumericLessThanEquals"]["ec2:VolumeSize"] == 1024


def test_run_instances_network_refs_require_managed_tag(statements):
    stmt = next(s for s in statements if s["Sid"] == "RunInstancesManagedNetwork")
    assert RESOURCE_TAG in _cond_keys(stmt)
    assert set(stmt["Resource"]) == {
        "arn:aws:ec2:*:*:subnet/*", "arn:aws:ec2:*:*:security-group/*", "arn:aws:ec2:*:*:network-interface/*",
    }


def test_images_limited_to_canonical_and_amazon(statements):
    stmt = next(s for s in statements if s["Sid"] == "RunInstancesImage")
    assert stmt["Condition"]["StringEquals"]["ec2:Owner"] == ["099720109477", "amazon"]


def test_create_tags_only_inside_create_actions(statements):
    stmt = next(s for s in statements if "ec2:CreateTags" in _actions(s) and s["Effect"] == "Allow")
    assert set(stmt["Condition"]["StringEquals"]["ec2:CreateAction"]) == {
        a.split(":")[1] for a in CREATE_ACTIONS
    }


def test_forbidden_actions_are_never_allowed(statements):
    for s in statements:
        if s["Effect"] != "Allow":
            continue
        for action in _actions(s):
            assert not _matches(action, FORBIDDEN_ALLOWS), f"{s['Sid']} allows {action}"
            # ec2:* style wildcards must not sneak in on the Allow side.
            assert action != "ec2:*" and not action.endswith(":*"), f"{s['Sid']} allows wildcard {action}"


def test_required_denies_present(statements):
    denied = {a for s in statements if s["Effect"] == "Deny" and "Condition" not in s for a in _actions(s)}
    assert REQUIRED_DENIES <= denied


def test_region_deny_covers_ec2_and_instance_connect(statements):
    stmt = next(s for s in statements if s["Sid"] == "DenyOutsideAllowedRegions")
    assert set(_actions(stmt)) == {"ec2:*", "ec2-instance-connect:*"}
    assert stmt["Condition"]["StringNotEquals"]["aws:RequestedRegion"] == ["eu-central-1", "us-east-1"]


def test_every_ec2_allow_is_region_or_tag_scoped(statements):
    for s in statements:
        if s["Effect"] != "Allow":
            continue
        if not any(a.startswith("ec2") for a in _actions(s)):
            continue
        keys = _cond_keys(s)
        assert keys & {"aws:RequestedRegion", RESOURCE_TAG, REQUEST_TAG, "ec2:Owner", "ec2:CreateAction"}, s["Sid"]


def test_fence_tag_key_is_distinct_from_manage_tag(statements, manage):
    manage_keys = {
        k
        for s in manage["ManageRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
        for op in s.get("Condition", {}).values()
        for k in op
    }
    assert manage_keys == {"ec2:ResourceTag/idlefy", "ec2:ResourceTag/Idlefy"}
    assert RESOURCE_TAG not in manage_keys
