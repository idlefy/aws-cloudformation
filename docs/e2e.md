# Live e2e: connect + enable provisioning against the Idlefy AWS account

Runs against account `995603458290` (Idlefy's own) from the **dev** environment
(`app.idlefy.dev`). Use a second dev organization, not the primary dev org: that one already
owns `IdlefyRole-a50adeec1a45` and the OIDC provider `app.idlefy.dev`, and its test
instances must keep working during the run.

Prerequisites: core-api on dev with `CFN_TEMPLATE_BASE_URL` and `CFN_TEMPLATE_VERSION` set
to a published version; you are OWNER of the second org; AWS console access to
`995603458290` as `aleksei` (MFA).

Calls are `https://app.idlefy.dev/api/v1/...` with the OWNER's bearer token. Cloudflare
rejects some default client user agents with `403 error code: 1010`; send a curl-like
`User-Agent`. Dev registration is closed, so the second org and its OWNER are created in a
core-api pod (`create_organization_with_owner`, `User.invited_name` must be set).

1. `POST /aws/cfn-setup` with `organization_id=<second org>`, `account_id=995603458290`,
   `region=us-east-1`, `oidc_provider_exists=true` (the provider already exists in this
   account). Open the returned `url`, tick the `CAPABILITY_NAMED_IAM` box, create the stack
   `Idlefy-Manage`. Expect CREATE_COMPLETE with only the role.
2. `POST /auth/organization/cloud-providers` with `provider_type: "AWS"` (upper case),
   a `provider_name` and `credentials` = the returned `credential_config` **plus
   `"regions": ["us-east-1"]`**, then `POST /auth/cloud-providers/{id}/credentials/verify`
   with body `{}` (the body is required). Expect `valid: true`,
   `extra_permissions_suspected: false`.
   `cfn-setup` does not return `regions` — the app collects them in the connect form — and
   verify refuses without them: `valid: false`, `AWS credentials must include non-empty
   'regions'`, every check unrun. If that happens, `PATCH /auth/cloud-providers/{id}` with
   `{"regions": ["us-east-1"]}` and verify again.
3. `POST /auth/cloud-providers/{id}/provisioning/cfn-url` with `region=us-east-1` (console
   region, required), `allowed_regions=["us-east-1"]`, `allowed_instance_types=["t3.micro"]`. Open the URL,
   create `Idlefy-Provision`. Expect CREATE_COMPLETE with the policy and the role.
4. `POST /auth/cloud-providers/{id}/provisioning/verify`. Expect `enabled: true`,
   `warnings: []`. (Verify only dry-runs a tagged `CreateVpc`; a dry-run launch needs a
   subnet and security group tagged `IdlefyManaged=true`, see the v1.0.1 changelog.)
5. Negative: save the provision role's trust policy (`aws iam get-role`), replace its `sub`
   with another value (`aws iam update-assume-role-policy`), run verify again. Expect 404
   `provisioning_role_not_found` and the stored block `enabled: false`,
   `last_error: provisioning_role_not_found`. Restore the saved document; verify is 200 again.
   After a template upgrade, re-run `cfn-url` first: the fence carries `template_version`, so
   the block resets to `enabled: false` until verify. Re-running it with an unchanged fence
   keeps `enabled: true`.
6. Delete the `Idlefy-Provision` stack. `provisioning/verify` → 404
   `provisioning_role_not_found`; `GET .../provisioning` still shows the stored block until
   `DELETE .../provisioning` clears it. Manage `credentials/verify` still `valid: true`.
7. Remove the cloud provider from the second org (`DELETE /auth/cloud-providers/{id}`)
   first, so no background job assumes a role that is about to disappear, then delete the
   `Idlefy-Manage` stack (it created no OIDC provider, so the primary dev org is unaffected:
   check `app.idlefy.dev` and `IdlefyRole-a50adeec1a45` still exist).
8. Clean-up of the legacy test instances `idlefy-test` and `idlefy-test-broken`
   (us-east-1, t3.micro) once the run is green — owner decision D12.

Record the run (date, template version, core-api version, outcome) in the Jira story. Expect
one Sentry event per AssumeRole denial in steps 5-6 (`Failed to assume role with web
identity`): known noise, not a failure.

## Runs

| Date | Templates | core-api | Outcome |
|---|---|---|---|
| 2026-09-15 | v1.0.0 | 2414a04f9 | Steps 1-4 green except a verify warning `run_instances: UnauthorizedOperation`: the created network interface was fenced with `ec2:ResourceTag` (fixed in v1.0.1). |
| 2026-09-15 | v1.0.1 (stack updated in place) | fbc3ca462 | All steps green; verify `warnings: []`; legacy t3.micros terminated. |
| 2026-09-17 | v1.1.0 (stack updated in place) | bc0ff7978 | S2 provisioning smoke PASS on the second attempt. Verify `enabled: true`, `warnings: []`; both DryRun probes `denied` (`create_subnet_default_vpc` 59df6337-9f0a-4323-a872-be6c311eee2b, `run_instances_denied_type` m5.large c4fca398-c665-46fc-b96c-2a6c29a396b6) — the fence denies as well as allows. All ten pinned quota codes answered live, each named by ListServiceQuotas: L-1216C47A Standard (A, C, D, H, I, M, R, T, Z), L-1945791B Inf, L-2C3B7624 Trn, L-417A185B P, L-43DA4232 High Memory, L-6E869C2A DL, L-7295265B X, L-74FC7D96 F, L-DB2E81BA G and VT, L-F7808C92 HPC — the last three were unknown before this release and were read back from Service Quotas for it. For the standard code the applied value (16.0) and the AWS default (5.0) came back side by side, which is what makes preflight's fallback to the default provably necessary. Encrypted root volume, network and instance adopted on repeat, stop / Elastic IP / start with the EIP as the public IP, `describe_managed` empty afterwards. The first attempt failed its network cleanup with `DisassociateRouteTable: UnauthorizedOperation` and stranded a VPC: core-api disassociated after deleting the subnets, and a tag-conditioned call on a resource AWS can no longer find fails closed rather than answering NotFound. Fixed in core-api (costpilot#329), not in the template. |
