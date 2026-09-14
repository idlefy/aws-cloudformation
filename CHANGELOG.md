# Changelog

## v1.0.0

- `idlefy-manage.yaml`: OIDC identity provider (optional via `CreateOidcProvider`) and role
  `IdlefyManage-<org12>` carrying the Idlefy manage policy (`IncludeMetrics` toggles the
  CloudWatch statement). Trust: `aud=sts.amazonaws.com`, `sub=<OrgId>`.
- `idlefy-provision.yaml`: role `IdlefyProvision-<org12>` with managed policy
  `IdlefyProvisionPolicy-<org12>` attached and set as permissions boundary. Fence tag
  `IdlefyManaged=true`; `AllowedRegions`, `AllowedInstanceTypes`, `MaxVolumeGiB` limits;
  explicit denies for privilege escalation and out-of-region EC2 calls. Trust:
  `sub=<OrgId>:provision`.
