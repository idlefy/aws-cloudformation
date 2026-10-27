"""Fence invariants for the provision policy.

These fail CI when someone "just adds an action" without the tag/region fence.
"""

import fnmatch
import json
import re
import uuid

import pytest
import yaml
from conftest import (
    COGNITO_ACCOUNT_ID,
    ISSUER_HOST,
    MANAGE_COGNITO_PARAMS,
    MANAGE_PARAMS,
    MANAGE_PIN,
    ORG_ID,
    POOL_ID,
    PROVISION_COGNITO_PARAMS,
    PROVISION_PARAMS,
    PROVISION_PIN,
    render,
)
from render import (  # tests/ is on sys.path (conftest already imports from render)
    ACCOUNT_ID,
    REGION,
    STACK_NAME,
    TEMPLATES,
    load_template,
)

FENCE_TAG = "IdlefyManaged"
REQUEST_TAG = f"aws:RequestTag/{FENCE_TAG}"
RESOURCE_TAG = f"ec2:ResourceTag/{FENCE_TAG}"
# v1.5.0: the tag a customer puts on a network of their own (VPC and subnets) to attach it.
ATTACHED_TAG = "ec2:ResourceTag/IdlefyAttached"
GROUPS_ATTRIBUTE = "ec2:Attribute/Groups"

# Actions that create resources: must be gated on the request tag (or, for
# child resources created inside a managed VPC, on the parent's resource tag).
CREATE_ACTIONS = {
    "ec2:CreateVpc", "ec2:CreateSubnet", "ec2:CreateInternetGateway", "ec2:CreateRouteTable",
    "ec2:CreateSecurityGroup", "ec2:AllocateAddress", "ec2:RunInstances",
    "ec2:CreateImage",
}
# Actions that must never be allowed by this role, regardless of conditions.
FORBIDDEN_ALLOWS = {
    "iam:*", "iam:PassRole", "sts:*", "organizations:*",
    "ec2:DeleteTags",
    "ec2:AssociateIamInstanceProfile", "ec2:ReplaceIamInstanceProfileAssociation",
    "ec2:ModifyLaunchTemplate", "ec2:CreateLaunchTemplate", "ec2:CreateFleet", "ec2:DeleteFleets",
    # A disk copy never leaves the account and is never read: no sharing, no copying, no
    # block-level reads.
    "ec2:ModifySnapshotAttribute", "ec2:ModifyImageAttribute", "ec2:CopySnapshot", "ec2:CopyImage",
    "ec2:CreateStoreImageTask", "ec2:ExportImage", "ec2:CreateInstanceExportTask",
    "ebs:*",
    # Idlefy manages boxes from the outside and never gets inside one. Matched with fnmatch,
    # so this also forbids allowing SendSSHPublicKey by name.
    "ec2-instance-connect:*",
    # Same rule, read side: the console output and screenshot are the guest's own output.
    "ec2:GetConsole*",
    # v1.7.0: so is the user data, and IAM cannot allow the other attributes without it.
    "ec2:DescribeInstanceAttribute",
}
REQUIRED_DENIES = {
    "iam:PassRole", "ec2:AssociateIamInstanceProfile", "ec2:ReplaceIamInstanceProfileAssociation",
    "ec2:DeleteTags", "sts:*", "organizations:*",
    "ec2-instance-connect:*", "ec2:GetConsole*", "ec2:DescribeInstanceAttribute",
    "ec2:ModifySnapshotAttribute", "ec2:ModifyImageAttribute", "ebs:*",
    "ec2:CopySnapshot", "ec2:CopyImage",
    "ec2:CreateStoreImageTask", "ec2:ExportImage", "ec2:CreateInstanceExportTask",
}
INSTANCE_TYPE_ATTRIBUTE = "ec2:Attribute/InstanceType"
# Granted only when the customer turns AllowZoneMove on (off by default).
ZONE_MOVE_ACTIONS = {"ec2:CreateImage", "ec2:DeregisterImage", "ec2:DeleteSnapshot"}
ALLOWED_WILDCARDS = {"kms:ReEncrypt*"}
# v1.7.0: the EC2 reads, by name. Exactly what core-api calls under the provision role; a new
# read is added here and to the template together, never as a wildcard.
DESCRIBE_ACTIONS = {
    "ec2:DescribeAddresses", "ec2:DescribeAvailabilityZones", "ec2:DescribeImages",
    "ec2:DescribeInstanceTypeOfferings", "ec2:DescribeInstanceTypes", "ec2:DescribeInstances",
    "ec2:DescribeInternetGateways", "ec2:DescribeNetworkInterfaces", "ec2:DescribeRouteTables",
    "ec2:DescribeSecurityGroups", "ec2:DescribeSnapshots", "ec2:DescribeSubnets",
    "ec2:DescribeVolumes", "ec2:DescribeVpcs",
}
IAM_MANAGED_POLICY_LIMIT = 6144   # non-whitespace characters
IAM_ROLE_INLINE_LIMIT = 10240     # non-whitespace characters, all inline policies of a role
# Read-only prefixes that legitimately have no tag condition.
READ_ONLY = (
    "ec2:Describe", "ec2:GetEbsEncryptionByDefault", "ec2:GetEbsDefaultKmsKeyId",
    "servicequotas:", "pricing:", "ssm:Get", "cloudformation:DescribeStacks",
)
# Creates whose call also names the parent VPC: the request tag may authorize only the
# new resource ARN, the VPC side must carry the fence tag (v1.1.0).
IN_VPC_CREATES = {"ec2:CreateSubnet", "ec2:CreateSecurityGroup", "ec2:CreateRouteTable"}
KMS_VIA_EC2 = "ec2.*.amazonaws.com"
# v1.6.0: the one KMS statement that is not a use of a key through EC2.
KEY_READ_SID = "DiskKeyRead"


@pytest.fixture(scope="session", params=[False, True], ids=["default", "zone-move"])
def zone_move(request):
    """Every invariant below holds for both renderings: AllowZoneMove off (default) and on."""
    return request.param


@pytest.fixture(scope="session")
def statements(zone_move, provision, provision_zone_move):
    resources = provision_zone_move if zone_move else provision
    return resources["ProvisionPolicy"]["Properties"]["PolicyDocument"]["Statement"]


def _limits(resources):
    (policy,) = resources["ProvisionRole"]["Properties"]["Policies"]
    assert policy["PolicyName"] == "IdlefyProvisionLimits"
    return policy["PolicyDocument"]["Statement"]


@pytest.fixture(scope="session")
def limits(provision):
    """The role's inline policy: the instance-type lists (v1.4.0) and the region list (v1.5.0), as explicit denies."""
    return _limits(provision)


@pytest.fixture(scope="session")
def role_denies(zone_move, provision, provision_zone_move):
    """The role's inline policy in the rendering `statements` is taken from."""
    return _limits(provision_zone_move if zone_move else provision)


def _actions(stmt):
    a = stmt["Action"]
    return [a] if isinstance(a, str) else list(a)


def _resources(stmt):
    r = stmt["Resource"]
    return [r] if isinstance(r, str) else list(r)


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
            if action.startswith("kms:"):
                if s["Sid"] == KEY_READ_SID:   # a read of the key's description, not a use of it
                    continue
                assert "kms:ViaService" in _cond_keys(s), f"{s['Sid']}: {action} lacks kms:ViaService"
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
            # The SOURCE of a disk copy is an existing instance: it must be a managed one.
            if action == "ec2:CreateImage" and resources == ["arn:aws:ec2:*:*:instance/*"]:
                assert RESOURCE_TAG in keys, s["Sid"]
                continue
            # RunInstances on referenced resources (subnet/SG/ENI/image/key-pair) and
            # child creates inside a managed VPC are gated differently.
            if action == "ec2:RunInstances" and all(r != "*" and "instance/" not in r and "volume/" not in r for r in resources):
                assert keys & {RESOURCE_TAG, ATTACHED_TAG, "ec2:Owner"}, s["Sid"]
                continue
            if all(r.endswith(":vpc/*") for r in resources):
                assert keys & {RESOURCE_TAG, ATTACHED_TAG}, s["Sid"]
                continue
            pytest.fail(f"{s['Sid']}: {action} is not fenced by {REQUEST_TAG}")


def test_run_instances_on_instances_requires_the_request_tag(statements):
    stmt = next(s for s in statements if s["Sid"] == "RunInstancesInstance")
    assert REQUEST_TAG in _cond_keys(stmt)


def test_instance_types_are_limited_by_explicit_denies_on_the_role(limits):
    # v1.4.0: the type lists moved out of the size-capped managed policy into the role's inline
    # policy, as DENIES — an explicit deny beats every allow, including one in a policy somebody
    # attaches to the role later.
    assert all(s["Effect"] == "Deny" for s in limits)
    launch = next(s for s in limits if s["Sid"] == "DenyLaunchOutsideAllowedTypes")
    assert _actions(launch) == ["ec2:RunInstances"]
    assert launch["Resource"] == "arn:aws:ec2:*:*:instance/*"
    assert launch["Condition"] == {"StringNotEquals": {"ec2:InstanceType": ["m7i.large", "m7i.xlarge", "g6.xlarge"]}}
    change = next(s for s in limits if s["Sid"] == "DenyTypeChangeOutsideAllowedTypes")
    assert _actions(change) == ["ec2:ModifyInstanceAttribute"]
    assert change["Resource"] == "*"
    assert change["Condition"] == {
        "StringNotEquals": {INSTANCE_TYPE_ATTRIBUTE: ["m7i.large", "m7i.xlarge", "g6.xlarge"]},
        "Null": {INSTANCE_TYPE_ATTRIBUTE: "false"},
    }
    assert {s["Sid"] for s in limits} == {
        "DenyLaunchOutsideAllowedTypes", "DenyTypeChangeOutsideAllowedTypes", "DenyOutsideAllowedRegions",
        "DenyEscalation", "DenyOwnImageNotAttached", "DenyOtherVolumeTypes", "DenyHighIops",
    }


def test_the_managed_policy_carries_no_instance_type_list(statements):
    assert not [s["Sid"] for s in statements if "ec2:InstanceType" in _cond_keys(s)]
    assert not [
        s["Sid"] for s in statements
        if isinstance(s.get("Condition", {}).get("StringEquals", {}).get(INSTANCE_TYPE_ATTRIBUTE), list)
    ]


def test_only_the_type_and_the_groups_of_a_managed_instance_can_be_changed(statements):
    # ModifyInstanceAttribute can also replace the user data (code that runs inside the box on its
    # next boot) and lift termination protection. Two attributes are opened, on a managed
    # instance: the machine type (v1.4.0) and the security-group list (v1.5.0); every other use
    # of the action is denied.
    allows = {
        s["Sid"]: s for s in statements if s["Effect"] == "Allow" and "ec2:ModifyInstanceAttribute" in _actions(s)
    }
    assert set(allows) == {"ChangeInstanceType", "SwitchToManagedGroups"}
    for allow in allows.values():
        assert _actions(allow) == ["ec2:ModifyInstanceAttribute"]
    change = allows["ChangeInstanceType"]
    assert change["Resource"] == "arn:aws:ec2:*:*:instance/*"
    assert change["Condition"] == {
        "StringEquals": {RESOURCE_TAG: "true"},
        "Null": {INSTANCE_TYPE_ATTRIBUTE: "false"},
    }
    # The groups named in the call are resources of the call: the tag condition holds for the
    # instance AND for every group, so only groups Idlefy created can be attached (verified
    # live 2026-10-09: a list naming an untagged group is denied on that group).
    switch = allows["SwitchToManagedGroups"]
    assert switch["Resource"] == ["arn:aws:ec2:*:*:instance/*", "arn:aws:ec2:*:*:security-group/*"]
    assert switch["Condition"] == {
        "StringEquals": {RESOURCE_TAG: "true"},
        "Null": {INSTANCE_TYPE_ATTRIBUTE: "true"},
    }
    denies = {
        s["Sid"]: s for s in statements if s["Effect"] == "Deny" and "ec2:ModifyInstanceAttribute" in _actions(s)
    }
    assert set(denies) == {"DenyOtherInstanceAttributes", "DenyUserDataChange"}
    for deny in denies.values():
        assert _actions(deny) == ["ec2:ModifyInstanceAttribute"]
    # Scoped to instances: the attribute keys exist only on the instance side of the call, so on
    # "*" this deny would match the security groups of a group change and deny it. Every call
    # names the instance, so nothing escapes it. Conditions AND: denied when the call carries
    # neither the type nor the groups.
    other = denies["DenyOtherInstanceAttributes"]
    assert other["Resource"] == "arn:aws:ec2:*:*:instance/*"
    assert other["Condition"] == {"Null": {INSTANCE_TYPE_ATTRIBUTE: "true", GROUPS_ATTRIBUTE: "true"}}
    # User data is code inside the box: denied by IAM whenever a call carries it, not only by
    # EC2's one-attribute-per-call rule.
    assert denies["DenyUserDataChange"]["Resource"] == "*"
    assert denies["DenyUserDataChange"]["Condition"] == {"Null": {"ec2:Attribute/UserData": "false"}}
    # The interface-level route to the same change is not granted at all.
    allowed = {a for s in statements if s["Effect"] == "Allow" for a in _actions(s)}
    assert "ec2:ModifyNetworkInterfaceAttribute" not in allowed


def test_a_disk_copy_is_made_from_a_managed_instance_and_removed_by_tag(statements, zone_move):
    allowed = {a for s in statements if s["Effect"] == "Allow" for a in _actions(s)}
    if not zone_move:
        # Off by default: nothing that touches the data on a box is granted.
        assert not allowed & ZONE_MOVE_ACTIONS
        assert "CopyDiskOfManagedInstance" not in {s["Sid"] for s in statements}
        return
    assert ZONE_MOVE_ACTIONS <= allowed
    source = next(s for s in statements if s["Sid"] == "CopyDiskOfManagedInstance")
    assert (_actions(source), source["Resource"]) == (["ec2:CreateImage"], "arn:aws:ec2:*:*:instance/*")
    assert source["Condition"] == {"StringEquals": {RESOURCE_TAG: "true"}}
    created = next(s for s in statements if s["Sid"] == "CreateTagged")
    assert "ec2:CreateImage" in _actions(created)   # the image and its snapshot: tagged at creation
    mutate = next(s for s in statements if s["Sid"] == "MutateManaged")
    assert {"ec2:DeregisterImage", "ec2:DeleteSnapshot"} <= set(_actions(mutate))
    assert not allowed & {"ec2:CreateSnapshot", "ec2:CreateSnapshots", "ec2:RegisterImage", "ec2:CopySnapshot"}


def test_regions_are_limited_by_the_deny_alone(statements, limits):
    # The list is rendered once: DenyOutsideAllowedRegions denies every ec2 call elsewhere. Since
    # v1.5.0 it lives in the role's inline policy (size budget of the managed one); a deny holds
    # from any policy of the role.
    assert not [s["Sid"] for s in statements if "aws:RequestedRegion" in _cond_keys(s)]
    assert [s["Sid"] for s in limits if "aws:RequestedRegion" in _cond_keys(s)] == ["DenyOutsideAllowedRegions"]


def _size(document) -> int:
    return len(json.dumps(document, separators=(",", ":")))


def test_policies_fit_the_iam_size_limits_at_the_largest_fence():
    # core-api accepts up to 20 regions and 50 instance types. v1.3.0 rendered 7381 characters
    # there and could not be deployed.
    regions = [f"ap-southeast-{i}" for i in range(1, 21)]            # the longest region names
    types = [f"m7i-flex.{i}xlarge" for i in range(10, 60)]           # 16 characters each
    resources = render(
        "idlefy-provision.yaml",
        {
            **PROVISION_PARAMS,
            "AllowedRegions": ",".join(regions),
            "AllowedInstanceTypes": ",".join(types),
            "AllowZoneMove": "true",   # the larger rendering
        },
    )
    managed = resources["ProvisionPolicy"]["Properties"]["PolicyDocument"]
    inline = {"Version": "2012-10-17", "Statement": _limits(resources)}
    assert _size(managed) <= IAM_MANAGED_POLICY_LIMIT, _size(managed)
    assert _size(inline) <= IAM_ROLE_INLINE_LIMIT, _size(inline)


def test_run_instances_volume_size_is_capped(statements):
    stmt = next(s for s in statements if s["Sid"] == "RunInstancesVolume")
    assert stmt["Condition"]["NumericLessThanEquals"]["ec2:VolumeSize"] == 1024


def test_run_instances_network_refs_require_managed_tag(statements):
    stmt = next(s for s in statements if s["Sid"] == "RunInstancesManagedNetwork")
    assert RESOURCE_TAG in _cond_keys(stmt)
    assert set(stmt["Resource"]) == {"arn:aws:ec2:*:*:subnet/*", "arn:aws:ec2:*:*:security-group/*"}


def test_run_instances_new_network_interface_requires_request_tag(statements):
    # The ENI is created by the call, so ec2:ResourceTag never matches it (v1.0.0 bug:
    # every launch was denied on network-interface/*).
    stmt = next(s for s in statements if s["Sid"] == "RunInstancesNetworkInterface")
    assert stmt["Resource"] == "arn:aws:ec2:*:*:network-interface/*"
    assert REQUEST_TAG in _cond_keys(stmt)
    assert RESOURCE_TAG not in _cond_keys(stmt)
    eni_allows = [
        s for s in statements
        if s["Effect"] == "Allow" and "ec2:RunInstances" in _actions(s)
        and any("network-interface/" in r for r in ([s["Resource"]] if isinstance(s["Resource"], str) else s["Resource"]))
    ]
    assert eni_allows == [stmt]


def test_reads_are_named_one_by_one(statements):
    # v1.7.0: ec2:Describe* also read launch-template user data, VPN pre-shared keys and the
    # user data of every instance in the account.
    stmt = next(s for s in statements if s["Sid"] == "Describe")
    assert set(_actions(stmt)) == DESCRIBE_ACTIONS
    described = {
        a for s in statements if s["Effect"] == "Allow" for a in _actions(s) if a.startswith("ec2:Describe")
    }
    assert described == DESCRIBE_ACTIONS


def test_an_image_of_the_account_is_launched_only_when_attached(role_denies, zone_move):
    # v1.7.0. The allow (RunInstancesImage) still names the account as an owner; this deny is
    # what narrows it, so it is pinned whole. The conditions AND together: own image, not
    # attached to this organization, and (zone move only) not a disk copy Idlefy made.
    stmt = next(s for s in role_denies if s["Sid"] == "DenyOwnImageNotAttached")
    assert stmt["Effect"] == "Deny"
    assert _actions(stmt) == ["ec2:RunInstances"]
    assert stmt["Resource"] == "arn:aws:ec2:*::image/*"
    assert "NotAction" not in stmt and "NotResource" not in stmt
    unless = {ATTACHED_TAG: ORG_ID}
    if zone_move:
        unless[RESOURCE_TAG] = "true"
    assert stmt["Condition"] == {"StringEquals": {"ec2:Owner": ACCOUNT_ID}, "StringNotEquals": unless}


def test_disks_are_gp3_and_not_above_16000_iops(role_denies):
    # v1.7.0. Two statements, not one: conditions in one statement AND together, and either
    # fact alone must deny the launch.
    volume = "arn:aws:ec2:*:*:volume/*"
    kind = next(s for s in role_denies if s["Sid"] == "DenyOtherVolumeTypes")
    assert (kind["Effect"], _actions(kind), kind["Resource"]) == ("Deny", ["ec2:RunInstances"], volume)
    assert kind["Condition"] == {"StringNotEquals": {"ec2:VolumeType": "gp3"}}
    iops = next(s for s in role_denies if s["Sid"] == "DenyHighIops")
    assert (iops["Effect"], _actions(iops), iops["Resource"]) == ("Deny", ["ec2:RunInstances"], volume)
    assert iops["Condition"] == {"NumericGreaterThan": {"ec2:VolumeIops": "16000"}}


def test_images_limited_to_known_publishers_and_this_account(statements):
    # Canonical, Amazon, Debian, and the account's own images (v1.3.0). Nothing shared in from
    # another account and no Marketplace: the list is exact, not a superset.
    stmt = next(s for s in statements if s["Sid"] == "RunInstancesImage")
    assert stmt["Resource"] == "arn:aws:ec2:*::image/*"
    assert stmt["Condition"] == {
        "StringEquals": {"ec2:Owner": ["099720109477", "amazon", "136693071363", ACCOUNT_ID]}
    }
    image_allows = [
        s for s in statements
        if s["Effect"] == "Allow" and "ec2:RunInstances" in _actions(s) and any("image/" in r for r in _resources(s))
    ]
    assert [s["Sid"] for s in image_allows] == ["RunInstancesImage"]


def test_image_lookup_reads_only_the_publishers_public_parameters(statements):
    stmt = next(s for s in statements if s["Sid"] == "ImageLookup")
    assert set(_actions(stmt)) == {"ssm:GetParameter"}
    assert _resources(stmt) == [
        "arn:aws:ssm:*::parameter/aws/service/canonical/ubuntu/*",
        "arn:aws:ssm:*::parameter/aws/service/debian/release/*",
    ]
    ssm_allows = [s["Sid"] for s in statements if s["Effect"] == "Allow" and any(a.startswith("ssm:") for a in _actions(s))]
    assert ssm_allows == ["ImageLookup"]


def test_cloudformation_access_is_one_read_of_this_stack(statements):
    # v1.3.0 (Idlefy ID-552): the role reads its own stack's parameters and nothing else in
    # CloudFormation. The ARN names the stack and ends in /*: a by-name call matches no other form.
    cfn_allows = [
        s for s in statements
        if s["Effect"] == "Allow" and any(a.lower().startswith("cloudformation:") for a in _actions(s))
    ]
    assert [s["Sid"] for s in cfn_allows] == ["ReadOwnStack"]
    stmt = cfn_allows[0]
    assert _actions(stmt) == ["cloudformation:DescribeStacks"]
    assert stmt["Resource"] == f"arn:aws:cloudformation:{REGION}:{ACCOUNT_ID}:stack/{STACK_NAME}/*"


def test_create_tags_only_inside_create_actions(statements, zone_move):
    stmt = next(s for s in statements if "ec2:CreateTags" in _actions(s) and s["Effect"] == "Allow")
    expected = CREATE_ACTIONS if zone_move else CREATE_ACTIONS - {"ec2:CreateImage"}
    assert set(stmt["Condition"]["StringEquals"]["ec2:CreateAction"]) == {a.split(":")[1] for a in expected}
    created = next(s for s in statements if s["Sid"] == "CreateTagged")
    assert ("ec2:CreateImage" in _actions(created)) is zone_move


def test_forbidden_actions_are_never_allowed(statements):
    for s in statements:
        if s["Effect"] != "Allow":
            continue
        for action in _actions(s):
            assert not _matches(action, FORBIDDEN_ALLOWS), f"{s['Sid']} allows {action}"
            # A wildcard on the Allow side grants actions nobody listed (ec2:Copy* would grant
            # CopySnapshot, which no deny covers): only these two are allowed to carry one.
            if "*" in action or "?" in action:
                assert action in ALLOWED_WILDCARDS, f"{s['Sid']} allows wildcard {action}"


def test_required_denies_present(role_denies):
    # Unconditional and on every resource: a condition or a narrower Resource would void it.
    # v1.7.0: they live on the role (the fence policy ran out of room); none of these actions
    # is allowed by the fence policy, which test_forbidden_actions_are_never_allowed holds.
    denied = {
        a
        for s in role_denies
        if s["Effect"] == "Deny" and "Condition" not in s and s["Resource"] == "*" and "NotAction" not in s
        for a in _actions(s)
    }
    assert REQUIRED_DENIES <= denied


def test_region_deny_covers_ec2_and_instance_connect(limits):
    stmt = next(s for s in limits if s["Sid"] == "DenyOutsideAllowedRegions")
    # Since v1.4.0 this statement is the ONLY region limit, so it is pinned whole: a narrower
    # Resource, a NotAction or a second condition (conditions AND together) would open every
    # region.
    assert stmt["Effect"] == "Deny"
    assert set(_actions(stmt)) == {"ec2:*", "ec2-instance-connect:*"}
    assert "NotAction" not in stmt and "NotResource" not in stmt
    assert stmt["Resource"] == "*"
    assert stmt["Condition"] == {"StringNotEquals": {"aws:RequestedRegion": ["eu-central-1", "us-east-1"]}}


def test_every_ec2_allow_is_region_or_tag_scoped(statements):
    for s in statements:
        if s["Effect"] != "Allow":
            continue
        if not any(a.startswith("ec2") for a in _actions(s)):
            continue
        if all(a.startswith(READ_ONLY) for a in _actions(s)):
            continue   # reads: the region deny is what limits them
        keys = _cond_keys(s)
        assert keys & {RESOURCE_TAG, REQUEST_TAG, ATTACHED_TAG, "ec2:Owner", "ec2:CreateAction"}, s["Sid"]


def test_fence_tag_key_is_distinct_from_manage_tag(statements, manage):
    manage_keys = {
        k
        for s in manage["ManageRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
        for op in s.get("Condition", {}).values()
        for k in op
    }
    assert manage_keys == {"ec2:ResourceTag/idlefy", "ec2:ResourceTag/Idlefy"}
    assert RESOURCE_TAG not in manage_keys


def test_the_role_can_never_get_inside_a_box(statements, role_denies):
    # Product rule, not a preference: Idlefy operates boxes from the outside — start, stop,
    # terminate, network — and never has access inside the guest. EC2 Instance Connect pushes a
    # caller-chosen SSH key onto a running instance, so it is denied unconditionally rather than
    # simply left out: an Allow added later, here or in another policy on this role, cannot
    # override a Deny. v1.0.0 and v1.0.1 granted SendSSHPublicKey; nothing ever used it.
    inside = ("ec2-instance-connect:", "ec2:GetConsole", "ec2:DescribeInstanceAttribute")
    assert not [
        s for s in statements
        if s["Effect"] == "Allow" and any(a.startswith(inside) for a in _actions(s))
    ]
    unconditional = {
        a for s in role_denies if s["Effect"] == "Deny" and "Condition" not in s for a in _actions(s)
    }
    assert {"ec2-instance-connect:*", "ec2:GetConsole*", "ec2:DescribeInstanceAttribute"} <= unconditional


def test_vpc_side_of_in_vpc_creates_requires_a_tag_on_the_vpc(statements):
    # This is the whole fence for "which VPC may Idlefy build in", and it does not depend on
    # the Resource ARN of the create statement: aws:RequestTag is in context only for the
    # resource being tagged, so a `Resource "*"` create statement never matches the vpc/* side.
    # Confirmed by DryRun against the deployed v1.0.1 role on 2026-09-16 — CreateSubnet into the
    # account's default VPC is denied on `.../vpc/<id>` with matchedStatements null. The test
    # therefore asserts the property that matters (the statements that authorize the VPC side
    # are exactly these two, and each keys on the VPC's own tag) rather than the shape of the
    # create statement.
    vpc_allows = [
        s for s in statements
        if s["Effect"] == "Allow" and IN_VPC_CREATES & set(_actions(s)) and any(r.endswith(":vpc/*") for r in _resources(s))
    ]
    assert [s["Sid"] for s in vpc_allows] == ["CreateInManagedVpc", "CreateGroupInAttachedVpc"]
    assert RESOURCE_TAG in _cond_keys(vpc_allows[0])
    assert REQUEST_TAG not in _cond_keys(vpc_allows[0])
    # v1.5.0: in a VPC the customer attached, the one thing Idlefy may create is its own group.
    assert _actions(vpc_allows[1]) == ["ec2:CreateSecurityGroup"]
    assert vpc_allows[1]["Condition"] == {"StringEquals": {ATTACHED_TAG: ORG_ID}}


def test_an_attached_network_is_never_changed_or_deleted(statements):
    # IdlefyAttached is a weaker mark than IdlefyManaged on purpose: it lets Idlefy create its own
    # group in the VPC and launch into a tagged subnet, and NOTHING else. A customer network must
    # never be given IdlefyManaged (MutateManaged would let the role delete it).
    keyed = {s["Sid"]: s for s in statements if ATTACHED_TAG in _cond_keys(s)}
    assert set(keyed) == {"CreateGroupInAttachedVpc", "RunInAttachedSubnet"}
    subnet = keyed["RunInAttachedSubnet"]
    assert subnet["Effect"] == "Allow"
    assert (_actions(subnet), subnet["Resource"]) == (["ec2:RunInstances"], "arn:aws:ec2:*:*:subnet/*")
    assert subnet["Condition"] == {"StringEquals": {ATTACHED_TAG: ORG_ID}}
    # The group of a launch must still be one Idlefy created, attached network or not.
    group_allows = [
        s["Sid"] for s in statements
        if s["Effect"] == "Allow" and "ec2:RunInstances" in _actions(s)
        and any("security-group/" in r for r in _resources(s))
    ]
    assert group_allows == ["RunInstancesManagedNetwork"]


def test_actions_nothing_uses_are_not_granted(statements):
    # v1.5.0 removed what was only "reserved": extra volumes, egress rules, the batch parameter read.
    allowed = {a for s in statements if s["Effect"] == "Allow" for a in _actions(s)}
    assert not allowed & {
        "ec2:CreateVolume", "ec2:DeleteVolume", "ec2:AuthorizeSecurityGroupEgress",
        "ec2:RevokeSecurityGroupEgress", "ssm:GetParameters",
    }


def test_ebs_encryption_defaults_are_readable(statements):
    stmt = next(s for s in statements if s["Sid"] == "EbsEncryptionDefaults")
    assert set(_actions(stmt)) == {"ec2:GetEbsEncryptionByDefault", "ec2:GetEbsDefaultKmsKeyId"}


def test_a_disk_key_can_be_described_and_nothing_more(statements):
    # v1.6.0. core-api asks whose key a disk is on before it takes a machine or creates a box
    # (a box on a customer-managed key cannot be started by the manage role). Outside EC2, the
    # role may read a key's description and do nothing else with it, and only for a key of this
    # account.
    stmt = next(s for s in statements if s["Sid"] == KEY_READ_SID)
    assert _actions(stmt) == ["kms:DescribeKey"]
    assert _resources(stmt) == [f"arn:aws:kms:*:{ACCOUNT_ID}:key/*"]
    assert "Condition" not in stmt
    direct = [
        action
        for s in statements
        if s["Effect"] == "Allow" and "kms:ViaService" not in _cond_keys(s)
        for action in _actions(s)
        if action.startswith("kms:")
    ]
    assert direct == ["kms:DescribeKey"]


def test_no_statement_allows_run_instances_on_a_key_pair(statements):
    # The provider never sends KeyName (cloud-init installs the keys), so the role has no
    # business naming a key pair at all. v1.0.0/v1.0.1 carried a RunInstancesKeyPair statement.
    assert not [s for s in statements if any("key-pair/" in r for r in _resources(s))]


def test_kms_is_usable_only_through_ec2(statements):
    # core-api refuses to launch below template v1.1.0 precisely because these two Sids are what
    # v1.1.0 adds (ProvisioningFenceError("template_version")); their existence is the contract.
    kms = [s for s in statements if s["Effect"] == "Allow" and any(a.startswith("kms:") for a in _actions(s))]
    assert {s["Sid"] for s in kms} == {"EbsEncryptionKms", "EbsEncryptionKmsGrant", KEY_READ_SID}
    kms = [s for s in kms if s["Sid"] != KEY_READ_SID]
    for s in kms:
        assert s["Condition"]["StringLike"]["kms:ViaService"] == KMS_VIA_EC2, s["Sid"]
        # The account-scoped Resource is what keeps this to the account's OWN keys. A
        # condition cannot do it: kms:CallerAccount matches the account of the caller, which
        # in a role policy is always this account, so it never excludes a key owned elsewhere
        # (AWS uses it in KEY policies, where the caller is the unknown). Without the ARN a
        # key shared into this account from another account would be usable through EC2.
        assert _resources(s) == [f"arn:aws:kms:*:{ACCOUNT_ID}:key/*"], s["Sid"]
        assert s["Condition"]["StringEquals"]["kms:CallerAccount"] == ACCOUNT_ID, s["Sid"]
    use = next(s for s in kms if s["Sid"] == "EbsEncryptionKms")
    assert set(_actions(use)) == {
        "kms:Decrypt", "kms:DescribeKey", "kms:GenerateDataKeyWithoutPlaintext", "kms:ReEncrypt*",
    }
    grant = next(s for s in kms if s["Sid"] == "EbsEncryptionKmsGrant")
    assert _actions(grant) == ["kms:CreateGrant"]
    assert grant["Condition"]["Bool"]["kms:GrantIsForAWSResource"] == "true"


def test_ipv6_blocks_can_be_added_to_managed_vpcs_and_subnets_only(statements):
    """v1.2.0: an owned network that predates dual-stack gets its Amazon-provided IPv6 blocks
    through Associate*CidrBlock — only on a VPC or subnet carrying the managed tag."""
    for action in ("ec2:AssociateVpcCidrBlock", "ec2:AssociateSubnetCidrBlock"):
        allows = [s for s in statements if s["Effect"] == "Allow" and action in _actions(s)]
        assert allows, f"{action} is not allowed"
        for s in allows:
            assert RESOURCE_TAG in _cond_keys(s), f"{s['Sid']}: {action} lacks {RESOURCE_TAG}"
            # Exactly "true": a value list such as ["true", "false"] is an OR and would let an
            # unmanaged (IdlefyManaged=false) VPC or subnet through.
            assert s["Condition"]["StringEquals"][RESOURCE_TAG] == "true", s["Sid"]


# -- trusts, Federation=cognito (both templates) ----------------------------------------

COGNITO = "cognito-identity.amazonaws.com"
MANAGE_TEMPLATE = "idlefy-manage.yaml"
PROVISION_TEMPLATE = "idlefy-provision.yaml"
TEMPLATE_NAMES = [MANAGE_TEMPLATE, PROVISION_TEMPLATE]
# Each template with its cognito parameters, its role and its OWN pin (never the other's).
COGNITO_RENDERS = {
    MANAGE_TEMPLATE: (MANAGE_COGNITO_PARAMS, "ManageRole", MANAGE_PIN),
    PROVISION_TEMPLATE: (PROVISION_COGNITO_PARAMS, "ProvisionRole", PROVISION_PIN),
}
# Characters that, inside a parameter substituted into the trust JSON (Fn::Sub), could close
# the string, escape, end the substitution, split a value or widen a match.
INJECTION_CHARS = ['"', "\\", "}", " ", "\t", "\n", "*"]
# Parameters substituted into the trust policies, with a value core-api sends.
SUBSTITUTED_PARAMS = {
    "OrgId": ORG_ID,
    "IssuerHost": ISSUER_HOST,
    "IdentityPoolId": POOL_ID,
    "CognitoAccountId": COGNITO_ACCOUNT_ID,
}


def _cognito_trust_statements(pin: str) -> list:
    return [
        {
            "Effect": "Allow",
            "Principal": {"Federated": COGNITO},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {f"{COGNITO}:aud": POOL_ID},
                "ForAnyValue:StringEquals": {f"{COGNITO}:amr": pin},
                "ForAllValues:StringEquals": {f"{COGNITO}:amr": ["authenticated", ISSUER_HOST, pin]},
            },
        }
    ]


def test_manage_cognito_trust(manage_cognito):
    """Exactly one statement: the pool as audience, the org's pin present, and no amr entry
    other than authenticated, the issuer and the pin. Never StringLike, IfExists, Null or
    sts:TagSession; never an aud-only trust."""
    trust = json.loads(manage_cognito["ManageRole"]["Properties"]["AssumeRolePolicyDocument"])
    assert trust["Version"] == "2012-10-17"
    assert trust["Statement"] == _cognito_trust_statements(MANAGE_PIN)


def test_provision_cognito_trust(provision_cognito):
    """As the manage trust, pinned to the org's provision subject: a manage token (whose pin
    lacks ":provision") cannot assume this role, and StringEquals keeps it from matching."""
    trust = json.loads(provision_cognito["ProvisionRole"]["Properties"]["AssumeRolePolicyDocument"])
    assert trust["Version"] == "2012-10-17"
    assert trust["Statement"] == _cognito_trust_statements(PROVISION_PIN)


@pytest.mark.parametrize("template", TEMPLATE_NAMES)
def test_cognito_trust_shape_invariant(template):
    params, role, pin = COGNITO_RENDERS[template]
    trust = json.loads(render(template, params)[role]["Properties"]["AssumeRolePolicyDocument"])
    (stmt,) = trust["Statement"]
    assert stmt["Effect"] == "Allow"
    assert stmt["Action"] == "sts:AssumeRoleWithWebIdentity"
    cond = stmt["Condition"]
    assert set(cond) == {"StringEquals", "ForAnyValue:StringEquals", "ForAllValues:StringEquals"}
    assert set(cond["StringEquals"]) == {f"{COGNITO}:aud"}
    # The pin is mandatory and is this template's own: a single string, never a list.
    assert cond["ForAnyValue:StringEquals"] == {f"{COGNITO}:amr": pin}
    assert isinstance(cond["ForAnyValue:StringEquals"][f"{COGNITO}:amr"], str)
    # No amr entry other than these three: a developer login or a second linked login fails.
    assert cond["ForAllValues:StringEquals"] == {f"{COGNITO}:amr": ["authenticated", ISSUER_HOST, pin]}
    for op in cond:
        assert not any(bad in op for bad in ("StringLike", "IfExists", "Null")), op
    assert "sts:TagSession" not in (TEMPLATES / template).read_text()
    assert "sts:TagSession" not in json.dumps(render(template, params))


@pytest.mark.parametrize(
    ("template", "extra"),
    [
        (MANAGE_TEMPLATE, {}),
        (MANAGE_TEMPLATE, {"CreateOidcProvider": "false"}),
        (MANAGE_TEMPLATE, {"Federation": "oidc"}),
        (MANAGE_TEMPLATE, {"Federation": "oidc", "CreateOidcProvider": "false"}),
        (PROVISION_TEMPLATE, {}),
        (PROVISION_TEMPLATE, {"AllowZoneMove": "true"}),
        (PROVISION_TEMPLATE, {"Federation": "oidc"}),
    ],
)
def test_oidc_renders_have_no_cognito_principal(template, extra):
    base = MANAGE_PARAMS if template == MANAGE_TEMPLATE else PROVISION_PARAMS
    assert "cognito-identity" not in json.dumps(render(template, {**base, **extra}))


def _parameter_nodes(template: str) -> dict:
    root = yaml.compose((TEMPLATES / template).read_text(), Loader=yaml.SafeLoader)
    (params,) = [v for k, v in root.value if k.value == "Parameters"]
    return {k.value: v for k, v in params.value}


def _assert_rejects_injection(template: str, name: str) -> None:
    pdef = load_template(template)["Parameters"][name]
    pattern = re.compile(pdef["AllowedPattern"])
    valid = SUBSTITUTED_PARAMS[name]
    assert pattern.fullmatch(valid), valid
    for ch in INJECTION_CHARS:
        for i in range(len(valid) + 1):
            bad = valid[:i] + ch + valid[i:]
            assert not pattern.fullmatch(bad), repr(bad)
    # Single-quoted in the YAML: no escape processing, so the pattern is exactly what is written.
    (style,) = [v.style for k, v in _parameter_nodes(template)[name].value if k.value == "AllowedPattern"]
    assert style == "'", f"{template} {name}: AllowedPattern must be a single-quoted scalar"


@pytest.mark.parametrize("name", sorted(SUBSTITUTED_PARAMS))
def test_manage_substituted_params_reject_injection(name):
    _assert_rejects_injection(MANAGE_TEMPLATE, name)


@pytest.mark.parametrize("name", sorted(SUBSTITUTED_PARAMS))
def test_provision_substituted_params_reject_injection(name):
    _assert_rejects_injection(PROVISION_TEMPLATE, name)


@pytest.mark.parametrize("template", TEMPLATE_NAMES)
def test_values_core_api_sends_still_match(template):
    params = load_template(template)["Parameters"]
    for host in ("app.idlefy.com", "app.idlefy.dev"):
        assert re.fullmatch(params["IssuerHost"]["AllowedPattern"], host)
    assert re.fullmatch(params["OrgId"]["AllowedPattern"], str(uuid.uuid4()))
    # Empty is allowed (Federation=oidc); the CognitoNeedsPool rule requires both for cognito.
    assert re.fullmatch(params["IdentityPoolId"]["AllowedPattern"], "")
    assert re.fullmatch(params["CognitoAccountId"]["AllowedPattern"], "")


@pytest.mark.parametrize("template", TEMPLATE_NAMES)
def test_federation_values(template):
    federation = load_template(template)["Parameters"]["Federation"]
    assert federation["AllowedValues"] == ["oidc", "cognito"]
    assert federation["Default"] == "oidc"


@pytest.mark.parametrize("rendering", ["manage", "manage_no_provider_no_metrics", "manage_cognito"])
def test_manage_reads_the_account_plan_and_nothing_else_of_free_tier(rendering, request):
    resources = request.getfixturevalue(rendering)
    statements = resources["ManageRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
    plan = [s for s in statements if s["Sid"] == "IdlefyAccountPlan"]
    assert plan == [{"Sid": "IdlefyAccountPlan", "Effect": "Allow",
                     "Action": ["freetier:GetAccountPlanState"], "Resource": "*"}]
    freetier = [a for s in statements for a in _actions(s) if a.lower().startswith("freetier:")]
    assert freetier == ["freetier:GetAccountPlanState"]
