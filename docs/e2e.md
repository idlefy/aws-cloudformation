# Live e2e: connect + enable provisioning against the Idlefy AWS account

Runs against account `995603458290` (Idlefy's own) from the **dev** environment
(`app.idlefy.dev`). Use a second dev organization, not the primary dev org: that one already
owns `IdlefyRole-a50adeec1a45` and the OIDC provider `app.idlefy.dev`, and its test
instances must keep working during the run.

Prerequisites: core-api on dev with `CFN_TEMPLATE_BASE_URL` and `CFN_TEMPLATE_VERSION` set
to a published version; you are OWNER of the second org; AWS console access to
`995603458290` as `aleksei` (MFA).

1. `POST /aws/cfn-setup` with `organization_id=<second org>`, `account_id=995603458290`,
   `region=us-east-1`, `oidc_provider_exists=true` (the provider already exists in this
   account). Open the returned `url`, tick the `CAPABILITY_NAMED_IAM` box, create the stack
   `Idlefy-Manage`. Expect CREATE_COMPLETE with only the role.
2. `POST /auth/organization/cloud-providers` with the returned `credential_config`, then
   `POST /auth/cloud-providers/{id}/credentials/verify`. Expect `valid: true`.
3. `POST /auth/cloud-providers/{id}/provisioning/cfn-url` with
   `allowed_regions=["us-east-1"]`, `allowed_instance_types=["t3.micro"]`. Open the URL,
   create `Idlefy-Provision`. Expect CREATE_COMPLETE with the policy and the role.
4. `POST /auth/cloud-providers/{id}/provisioning/verify`. Expect `enabled: true`, no
   warnings (the account has a default VPC, so the RunInstances probe passes too).
5. Negative: edit the provision role's trust policy `sub` in the console, run verify again.
   Expect 404 `provisioning_role_not_found`. Restore it (or delete/recreate the stack).
6. Delete the `Idlefy-Provision` stack. `provisioning/verify` → 404
   `provisioning_role_not_found`; `GET .../provisioning` still shows the stored block until
   `DELETE .../provisioning` clears it. Manage `credentials/verify` still `valid: true`.
7. Delete the `Idlefy-Manage` stack (it created no provider, so the primary dev org is
   unaffected). Remove the cloud provider from the second org.
8. Clean-up of the legacy test instances `idlefy-test` and `idlefy-test-broken`
   (us-east-1, t3.micro) once the run is green — owner decision D12.

Record the run (date, template version, core-api version, outcome) in the Jira story.
