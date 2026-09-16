# Changelog

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
