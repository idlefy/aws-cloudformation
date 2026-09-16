"""Fence invariants for the provision policy.

These fail CI when someone "just adds an action" without the tag/region fence.
"""

import fnmatch

import pytest
from render import ACCOUNT_ID  # tests/ is on sys.path (conftest already imports from render)

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
    # Idlefy manages boxes from the outside and never gets inside one. Matched with fnmatch,
    # so this also forbids allowing SendSSHPublicKey by name.
    "ec2-instance-connect:*",
}
REQUIRED_DENIES = {
    "iam:PassRole", "ec2:AssociateIamInstanceProfile", "ec2:ReplaceIamInstanceProfileAssociation",
    "ec2:ModifyInstanceAttribute", "ec2:DeleteTags", "sts:*", "organizations:*",
    "ec2-instance-connect:*",
}
# Read-only prefixes that legitimately have no tag condition.
READ_ONLY = (
    "ec2:Describe", "ec2:GetConsoleOutput", "ec2:GetEbsEncryptionByDefault", "ec2:GetEbsDefaultKmsKeyId",
    "servicequotas:", "pricing:", "ssm:Get",
)
# Creates whose call also names the parent VPC: the request tag may authorize only the
# new resource ARN, the VPC side must carry the fence tag (v1.1.0).
IN_VPC_CREATES = {"ec2:CreateSubnet", "ec2:CreateSecurityGroup", "ec2:CreateRouteTable"}
KMS_VIA_EC2 = "ec2.*.amazonaws.com"


@pytest.fixture(scope="session")
def statements(provision):
    return provision["ProvisionPolicy"]["Properties"]["PolicyDocument"]["Statement"]


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
    assert set(stmt["Resource"]) == {"arn:aws:ec2:*:*:subnet/*", "arn:aws:ec2:*:*:security-group/*"}


def test_run_instances_new_network_interface_requires_request_tag(statements):
    # The ENI is created by the call, so ec2:ResourceTag never matches it (v1.0.0 bug:
    # every launch was denied on network-interface/*).
    stmt = next(s for s in statements if s["Sid"] == "RunInstancesNetworkInterface")
    assert stmt["Resource"] == "arn:aws:ec2:*:*:network-interface/*"
    assert {REQUEST_TAG, "aws:RequestedRegion"} <= _cond_keys(stmt)
    assert RESOURCE_TAG not in _cond_keys(stmt)
    eni_allows = [
        s for s in statements
        if s["Effect"] == "Allow" and "ec2:RunInstances" in _actions(s)
        and any("network-interface/" in r for r in ([s["Resource"]] if isinstance(s["Resource"], str) else s["Resource"]))
    ]
    assert eni_allows == [stmt]


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


def test_the_role_can_never_get_inside_a_box(statements):
    # Product rule, not a preference: Idlefy operates boxes from the outside — start, stop,
    # terminate, network — and never has access inside the guest. EC2 Instance Connect pushes a
    # caller-chosen SSH key onto a running instance, so it is denied unconditionally rather than
    # simply left out: an Allow added later, here or in another policy on this role, cannot
    # override a Deny. v1.0.0 and v1.0.1 granted SendSSHPublicKey; nothing ever used it.
    assert not [
        s for s in statements
        if s["Effect"] == "Allow" and any(a.startswith("ec2-instance-connect:") for a in _actions(s))
    ]
    unconditional = {
        a for s in statements if s["Effect"] == "Deny" and "Condition" not in s for a in _actions(s)
    }
    assert "ec2-instance-connect:*" in unconditional


def test_vpc_side_of_in_vpc_creates_requires_the_managed_tag(statements):
    # This is the whole fence for "which VPC may Idlefy build in", and it does not depend on
    # the Resource ARN of the create statement: aws:RequestTag is in context only for the
    # resource being tagged, so a `Resource "*"` create statement never matches the vpc/* side.
    # Confirmed by DryRun against the deployed v1.0.1 role on 2026-09-16 — CreateSubnet into the
    # account's default VPC is denied on `.../vpc/<id>` with matchedStatements null. The test
    # therefore asserts the property that matters (exactly one statement authorizes the VPC side,
    # and it keys on the VPC's own tag) rather than the shape of the create statement.
    vpc_allows = [
        s for s in statements
        if s["Effect"] == "Allow" and IN_VPC_CREATES & set(_actions(s)) and any(r.endswith(":vpc/*") for r in _resources(s))
    ]
    assert [s["Sid"] for s in vpc_allows] == ["CreateInManagedVpc"]
    assert RESOURCE_TAG in _cond_keys(vpc_allows[0])
    assert REQUEST_TAG not in _cond_keys(vpc_allows[0])


def test_ebs_encryption_defaults_are_readable_in_allowed_regions(statements):
    stmt = next(s for s in statements if s["Sid"] == "EbsEncryptionDefaults")
    assert set(_actions(stmt)) == {"ec2:GetEbsEncryptionByDefault", "ec2:GetEbsDefaultKmsKeyId"}
    # The rendered region list is whatever AllowedRegions the harness passed, so derive it from
    # a statement built from the same parameters instead of hard-coding the harness's value.
    describe = next(s for s in statements if s["Sid"] == "Describe")
    assert (
        stmt["Condition"]["StringEquals"]["aws:RequestedRegion"]
        == describe["Condition"]["StringEquals"]["aws:RequestedRegion"]
    )


def test_no_statement_allows_run_instances_on_a_key_pair(statements):
    # The provider never sends KeyName (cloud-init installs the keys), so the role has no
    # business naming a key pair at all. v1.0.0/v1.0.1 carried a RunInstancesKeyPair statement.
    assert not [s for s in statements if any("key-pair/" in r for r in _resources(s))]


def test_kms_is_usable_only_through_ec2(statements):
    # core-api refuses to launch below template v1.1.0 precisely because these two Sids are what
    # v1.1.0 adds (ProvisioningFenceError("template_version")); their existence is the contract.
    kms = [s for s in statements if s["Effect"] == "Allow" and any(a.startswith("kms:") for a in _actions(s))]
    assert {s["Sid"] for s in kms} == {"EbsEncryptionKms", "EbsEncryptionKmsGrant"}
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
