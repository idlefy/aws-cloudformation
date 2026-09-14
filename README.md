# Idlefy CloudFormation templates

CloudFormation templates that connect an AWS account to [Idlefy](https://idlefy.com).
Published to a public S3 bucket and opened from the Idlefy app via "Launch Stack".

| Stack | Creates | Purpose |
|---|---|---|
| `idlefy-manage` | OIDC identity provider + role `IdlefyManage-<org>` | Read-only discovery and start/stop of VMs tagged `Idlefy=enabled`. Cannot create or terminate anything. |
| `idlefy-provision` | role `IdlefyProvision-<org>` | Opt-in. Creates dev boxes for you, fenced to resources tagged `Idlefy=managed` and to the regions and instance types you allow. Delete this stack to revoke provisioning. |

Both roles are assumed only through short-lived web-identity tokens issued by Idlefy for your organization. No access keys are ever created.

Status: in development, not yet published.
