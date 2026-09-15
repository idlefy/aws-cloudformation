# Changelog

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
