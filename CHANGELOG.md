# Changelog

## v1.5.0

- `idlefy-provision.yaml`: **hand an existing machine over to Idlefy.** Nothing new is needed
  for the machine itself: you tag it with the marks of a box Idlefy created and the existing
  statements apply. New for the network it lives in, which you tag `IdlefyAttached=<org id>`:
  `CreateGroupInAttachedVpc` (Idlefy's own security group in a tagged VPC) and
  `RunInAttachedSubnet` (launch into a tagged subnet, for a move to another zone). The tag
  grants nothing else; a network that carries it cannot be changed or deleted by the role.
- `idlefy-provision.yaml`: **switch a box to a security group Idlefy created.** New
  `SwitchToManagedGroups` allows `ec2:ModifyInstanceAttribute` for the group list of an
  instance tagged `IdlefyManaged=true`, and only to groups tagged `IdlefyManaged=true`: the
  groups named in the call are resources of the call, so IAM itself refuses a list that names
  a group of yours (verified against a live role). `DenyOtherInstanceAttributes` now denies a
  call that carries neither the type nor the group list, and is scoped to `instance/*` (on
  `*` it would also match the groups of a group change).
- `idlefy-provision.yaml`: `DenyOutsideAllowedRegions` moved from the fence policy to the
  role's inline policy `IdlefyProvisionLimits`, next to the instance-type denies, to keep the
  fence policy under IAM's 6,144 characters. It is still the only region limit and still an
  explicit deny on every EC2 call outside `AllowedRegions`. During the update of an existing
  stack CloudFormation changes the fence policy first and the role's inline policy second, so
  for the few seconds in between the region limit is not in force (the tag fence is).
- `idlefy-provision.yaml`: removed actions nothing ever used: `ec2:CreateVolume`,
  `ec2:DeleteVolume`, `ec2:AuthorizeSecurityGroupEgress`, `ec2:RevokeSecurityGroupEgress`,
  `ssm:GetParameters`.
- No new parameter. Updating an existing stack changes the policy document and the inline
  policy in place.

## v1.4.1

- `idlefy-provision.yaml`: **fixes the update from v1.3.0.** v1.4.0 reworded the
  `Description` of the fence policy. CloudFormation replaces a managed policy whose
  description changes, and a policy with a fixed name cannot be replaced, so every update of
  an existing stack failed with "A policy called IdlefyProvisionPolicy-... already exists"
  and rolled back (the stack stayed on its previous version, nothing was lost). The
  description is back to its v1.3.0 text and a test freezes it together with the other
  properties that would replace a named IAM resource.
- A stack CREATED from v1.4.0 cannot be updated to v1.4.1 for the same reason (its policy
  carries the v1.4.0 description): delete it and create it again from v1.4.1.
- No permission changes. Use v1.4.1 instead of v1.4.0.

## v1.4.0

- `idlefy-provision.yaml`: **change the machine type of a stopped dev box.** New
  `ChangeInstanceType` allows `ec2:ModifyInstanceAttribute` on an instance tagged
  `IdlefyManaged=true`, only when the request changes `InstanceType`. `DenyEscalation` no
  longer denies the action outright; new `DenyOtherInstanceAttributes` denies every call
  that does not change the type (user data, security groups, termination protection and the
  rest stay out of reach).
- `idlefy-provision.yaml`: **move a dev box to another zone, opt-in.** New parameter
  `AllowZoneMove`, `false` by default. Only when it is `true` the role gets `ec2:CreateImage`
  on a tagged instance (`CopyDiskOfManagedInstance`), with the image and its snapshot tagged
  at creation (`CreateTagged`, `CreateTagsOnCreate`), and `ec2:DeregisterImage` and
  `ec2:DeleteSnapshot` on tagged ones (`MutateManaged`). It is opt-in because it is the one
  ability that touches the data on a box: a role that can copy a disk and launch an instance
  from the copy could, in principle, boot that copy with a startup script of its choosing,
  and IAM cannot limit the user data of a launch. With the parameter off none of these
  actions is granted. See "Moving a box to another zone" in the README.
- `idlefy-provision.yaml`: `DenyEscalation` gains `ec2:ModifySnapshotAttribute`,
  `ec2:ModifyImageAttribute`, `ebs:*`, `ec2:CopySnapshot`, `ec2:CopyImage`,
  `ec2:CreateStoreImageTask`, `ec2:ExportImage` and `ec2:CreateInstanceExportTask`, with or
  without `AllowZoneMove`: an image or a snapshot can never be shared with another account,
  copied, exported to S3 or read block by block.
- `idlefy-provision.yaml`: new `DenyUserDataChange` denies any `ModifyInstanceAttribute` call
  that carries user data, so that protection does not rest on EC2's one-attribute-per-call
  rule alone.
- `idlefy-provision.yaml`: **the instance-type list moved to the role.** New inline policy
  `IdlefyProvisionLimits` on the role denies `ec2:RunInstances` and a type change outside
  `AllowedInstanceTypes`. `RunInstancesInstance` no longer carries the list.
- `idlefy-provision.yaml`: **the region list is stated once.** The allow statements no longer
  repeat `aws:RequestedRegion`; `DenyOutsideAllowedRegions` already denies every EC2 call
  elsewhere. Nothing becomes reachable that was not before.
- Fixes a deployment failure: v1.3.0 rendered a managed policy over IAM's 6,144-character
  limit with long lists (7,381 characters at 20 regions and 50 instance types). v1.4.0
  renders 5,862 there with `AllowZoneMove` on, and a test pins both policies under their
  limits.
- `idlefy-provision.yaml`: new stack output `TemplateVersion`. Idlefy reads it (through
  `ReadOwnStack`, v1.3.0) to know which version is deployed.
- Updating an existing stack in place was meant to be enough, but fails in v1.4.0 — see
  v1.4.1. The new parameter has a default. During the
  update CloudFormation replaces the fence policy first and adds `IdlefyProvisionLimits` to
  the role a few seconds later; between the two the role has no instance-type limit (tags,
  regions and every deny hold throughout).
- Verified against live IAM on a scratch role: launch and type change allowed only for listed
  types; a type change combined with any other attribute is rejected by EC2 itself ("The
  request must contain a single attribute"); `CreateImage` that names a snapshot Idlefy did
  not create is denied.

## v1.3.0

- `idlefy-provision.yaml`: **Debian images.** `RunInstancesImage` also allows images owned by
  Debian (`136693071363`), and `ImageLookup` (was `UbuntuAmiLookup`) also reads Debian's public
  parameters under `/aws/service/debian/release/*`.
- `idlefy-provision.yaml`: **your own images.** `RunInstancesImage` also allows images owned by
  the account the stack is deployed in (`ec2:Owner` = this account id). An image shared in from
  another account, a public image of another owner and a Marketplace image stay denied.
- `idlefy-provision.yaml`: **the role can read this stack.** New `ReadOwnStack` allows
  `cloudformation:DescribeStacks` on this one stack. Idlefy compares `AllowedRegions`,
  `AllowedInstanceTypes` and `MaxVolumeGiB` with what it has stored and warns when they differ.
  It is the only CloudFormation action the role has.

## v1.2.0

- `idlefy-provision.yaml`: **dual-stack (IPv6) dev boxes.** `MutateManaged` also allows
  `ec2:AssociateVpcCidrBlock` and `ec2:AssociateSubnetCidrBlock`, under the same
  `ec2:ResourceTag/IdlefyManaged = "true"` condition as every other change to the network.
  A network Idlefy built before IPv6 gets its Amazon-provided /56 (VPC) and a /64 per subnet
  through them. A network built from now on gets both blocks inside `CreateVpc` and
  `CreateSubnet`, which v1.1.0 already allows, so a fresh account works dual-stack on v1.1.0
  too; only upgrading an existing network needs v1.2.0. Amazon-provided blocks come from no
  customer pool, so no `ipv6pool-ec2` or IPAM resource is named. The `::/0` default route
  (`CreateRoute`), the instance's IPv6 address (`RunInstances` with `Ipv6AddressCount`) and
  IPv6 security-group rules use actions v1.1.0 already grants.
- The "bring your own network" consent statement moves to a later minor version.

## v1.1.0

- `idlefy-provision.yaml`: encrypted root volumes. `EbsEncryptionKms` and `EbsEncryptionKmsGrant`
  allow `kms:Decrypt`, `kms:DescribeKey`, `kms:GenerateDataKeyWithoutPlaintext`, `kms:ReEncrypt*`
  and `kms:CreateGrant` (grants for AWS resources only), solely through EC2
  (`kms:ViaService = ec2.*.amazonaws.com`) and only on keys in this account — both statements
  are scoped to `arn:aws:kms:*:<account>:key/*`, so a key shared in from another account cannot
  be used even if its key policy allows it. (`kms:CallerAccount` is kept as the documented
  pairing for `ViaService`, but it matches the *caller's* account and cannot restrict the key's
  owner; the ARN is what does.) Without these statements a launch with an encrypted root volume
  succeeded and the instance then terminated with `Client.InvalidKMSKey.*`. A customer-managed
  default EBS key still needs its key policy to allow the account.
- `idlefy-provision.yaml`: `EbsEncryptionDefaults` allows `ec2:GetEbsEncryptionByDefault` and
  `ec2:GetEbsDefaultKmsKeyId` in `AllowedRegions` (not covered by `ec2:Describe*`).
- `idlefy-provision.yaml`: `DescribeGlobal` also allows `servicequotas:GetAWSDefaultServiceQuota`.
  `GetServiceQuota` answers only for quotas the account has already changed, so without the
  default value every EC2 limit Idlefy reports on a fresh account would be unknown.
- `idlefy-provision.yaml`: **the role can no longer reach inside a box, or read what is inside
  it.** The `InstanceConnect` statement (`ec2-instance-connect:SendSSHPublicKey` on a managed
  instance) is removed, and so is `ec2:GetConsoleOutput`, which returns the guest's own boot
  log and kernel messages — including whatever cloud-init printed. Both are added to the
  unconditional `DenyEscalation`, as `ec2-instance-connect:*` and `ec2:GetConsole*` (the
  wildcard also covers `GetConsoleScreenshot`), so no later change can grant them back. Idlefy
  operates boxes from the outside only — start, stop, terminate, network. v1.0.0 and v1.0.1
  granted both permissions; nothing ever used either.
- `idlefy-provision.yaml`: the `RunInstancesKeyPair` statement is removed. Idlefy installs SSH
  keys through cloud-init and never sends `KeyName`, so the role has no reason to name a key
  pair. Actions kept for later stories (`CreateVolume`, `DeleteVolume`, `RebootInstances`,
  egress rules, `DeleteRoute`, `pricing:GetProducts`, `ssm:GetParameters`) now carry a
  "reserved for S3/S4" comment saying why they are there. EC2 Instance Connect and
  `GetConsoleOutput` were on that list and are not any more — see above.
- No change to which VPC the role may build in. A narrowing was drafted for this release on the
  assumption that `Resource "*"` on `CreateTagged` let the request tag authorize the parent VPC
  as well; a DryRun against the deployed v1.0.1 role disproved it. `aws:RequestTag` is in the
  request context only for the resource being tagged, so `CreateSubnet` into an untagged VPC is
  already denied on the `vpc/*` resource, with no statement matching it. `CreateInManagedVpc` is
  and was the only authority for the VPC side. An invariant test now pins that property.
- Unchanged by v1.1.0, restated because it is easy to misread: the launch statements already
  accept any subnet and security group tagged `IdlefyManaged=true`, whoever created them. What
  is missing for bring-your-own-network is the per-box security group Idlefy creates per box —
  creating one inside a VPC needs that VPC to carry the tag — so it needs one more statement, a
  separate consent tag, planned for v1.2.0 (Idlefy ID-541).
- Update the `Idlefy-Provision` stack in place; parameters and role names are unchanged.

## v1.0.1

- `idlefy-provision.yaml`: fix every `RunInstances` being denied on `network-interface/*`.
  The primary network interface is created by the call, so the `ec2:ResourceTag` condition it
  shared with subnets and security groups could never match. It now has its own statement,
  `RunInstancesNetworkInterface`, gated on `aws:RequestTag/IdlefyManaged=true` and
  `AllowedRegions`; callers must tag `network-interface` in `TagSpecifications`. Update the
  `Idlefy-Provision` stack in place; parameters and role names are unchanged.

## v1.0.0

- `idlefy-manage.yaml`: OIDC identity provider (optional via `CreateOidcProvider`) and role
  `IdlefyManage-<org12>` carrying the Idlefy manage policy (`IncludeMetrics` toggles the
  CloudWatch statement). Trust: `aud=sts.amazonaws.com`, `sub=<OrgId>`.
- `idlefy-provision.yaml`: role `IdlefyProvision-<org12>` with managed policy
  `IdlefyProvisionPolicy-<org12>` attached and set as permissions boundary. Fence tag
  `IdlefyManaged=true`; `AllowedRegions`, `AllowedInstanceTypes`, `MaxVolumeGiB` limits;
  explicit denies for privilege escalation and out-of-region EC2 calls. Trust:
  `sub=<OrgId>:provision`.
