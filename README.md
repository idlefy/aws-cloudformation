# Idlefy CloudFormation templates

CloudFormation templates that connect an AWS account to [Idlefy](https://idlefy.com).
The Idlefy app opens them for you with a "Launch Stack" link; this repository exists so you
can read exactly what gets created in your account before you click.

| Stack | Template | Creates | Purpose |
|---|---|---|---|
| `Idlefy-Manage` | `templates/idlefy-manage.yaml` | OIDC identity provider (optional) + role `IdlefyManage-<org>` | Discover and start/stop the EC2 instances you tag `Idlefy=enabled`. Cannot create, terminate or resize anything. |
| `Idlefy-Provision` | `templates/idlefy-provision.yaml` | role `IdlefyProvision-<org>` + managed policy `IdlefyProvisionPolicy-<org>` | Opt-in. Lets Idlefy create dev boxes for your organization inside a fence (below). Delete this stack to revoke provisioning; manage keeps working. |

Both roles are assumed only through short-lived web-identity tokens that Idlefy issues for
your organization (`AssumeRoleWithWebIdentity`, trust policy pinned to your organization
id). No access keys are created, nothing is pasted back into Idlefy.

Published templates: `https://idlefy-cfn-templates.s3.us-east-1.amazonaws.com/cfn/<version>/<template>.yaml`.
The app always links to an exact version, never to `cfn/latest/`.

## The provision fence

The provision role can only act on resources that carry the tag **`IdlefyManaged=true`**:

- Creating a VPC, subnet, security group, route table, internet gateway, Elastic IP, volume
  or instance is allowed only when the request tags it `IdlefyManaged=true`
  (`aws:RequestTag`), inside the regions you list (`AllowedRegions`), with an instance type
  from your list (`AllowedInstanceTypes`) and a volume no larger than `MaxVolumeGiB`.
- A subnet, security group or route table can only be created inside a VPC that already
  carries the tag; tagging the new resource alone is not enough.
- Stopping, starting, terminating, deleting, associating or modifying is allowed only on
  resources that already carry the tag (`ec2:ResourceTag`).
- Instances may only launch into a subnet and security group that carry the tag, from an
  image owned by Canonical or Amazon; the network interface created with the instance must
  be tagged at launch like the instance and its volume.
- KMS is usable only through EC2 (`kms:ViaService = ec2.*.amazonaws.com`; grants only for AWS
  resources) and only on keys in your own account (the statements are scoped to
  `arn:aws:kms:*:<your-account>:key/*`), which encrypted root volumes need. A key shared into
  your account from somewhere else is out of reach even if its key policy would allow it.
  If your account's default EBS key is a customer-managed key, its key policy must allow the
  account (the default key policy does).
  The role can also read the account's EBS encryption defaults and the AWS default value of an
  EC2 quota your account has never changed.
- The role can never name an EC2 key pair: Idlefy installs your SSH keys through cloud-init, so
  no key pair is ever attached to a box.
- **Idlefy can never get inside a box, or read what is inside it.** It starts, stops,
  terminates and networks your boxes from the outside; it has no way to open a shell, run a
  command, push an SSH key onto a running instance, or read the guest's own console output or
  screen. `ec2-instance-connect:*` and `ec2:GetConsole*` are explicitly denied, so no later
  policy change can grant them either. (v1.0.0 and v1.0.1 allowed `SendSSHPublicKey` and
  `GetConsoleOutput`; v1.1.0 removes and then denies both.)
- `ec2:CreateTags` works only as part of a create call; the role can never add or remove
  tags afterwards, so it cannot widen its own reach.
- Explicit `Deny` on `iam:PassRole`, instance-profile association, `ModifyInstanceAttribute`
  (which would bypass the instance-type list), `DeleteTags`, `sts:*`, `organizations:*`, and
  on any EC2 call outside `AllowedRegions`.
- The same policy is attached to the role **and** set as its permissions boundary, so a
  policy attached later by mistake cannot exceed it.

What the fence does not limit: the number of instances. That is bounded by Idlefy's own
rate limits and by your EC2 service quotas.

### Bring your own network

Tagging one of your existing subnets and a security group with `IdlefyManaged=true` is
consent for Idlefy to launch dev boxes there: the launch statements accept any subnet and
security group carrying the tag, whoever created them. Untagged resources are untouchable,
and the Idlefy app will not delete or modify a network it did not create even once you tag
it. (Feature planned.)

What is still missing for your own VPC is the per-box security group Idlefy creates for each
box: a security group, subnet or route table can only be created inside a VPC that itself
carries the tag — true since v1.0.0, unchanged here — so building in your VPC needs one more
statement, a separate consent tag, planned for v1.2.0.

## Compatibility contract with the Idlefy app

| Item | Value | Change requires |
|---|---|---|
| Role names | `IdlefyManage-<org12>`, `IdlefyProvision-<org12>` where `org12` = first 12 hex chars of the organization UUID (computed inside the template) | major version |
| Suggested stack names | `Idlefy-Manage`, `Idlefy-Provision` | minor |
| Parameters | manage: `OrgId`, `IssuerHost`, `CreateOidcProvider`, `IncludeMetrics`; provision: `OrgId`, `IssuerHost`, `AllowedRegions`, `AllowedInstanceTypes`, `MaxVolumeGiB` | major |
| Trust conditions | `<issuer>:aud = sts.amazonaws.com`; manage `sub = <OrgId>`, provision `sub = <OrgId>:provision` | major |
| Fence tag | `IdlefyManaged = true` | major |
| `CAPABILITY_NAMED_IAM` | required (roles have fixed names); the console shows an acknowledgement checkbox | major |
| Adding a permission statement | | minor |

## Things to know

- **One OIDC provider per account.** An AWS account can hold only one identity provider for
  a given issuer URL. If this account already has the Idlefy provider (another Idlefy
  organization, or a manual setup), launch the manage stack with `CreateOidcProvider=false`.
  Idlefy prefills this when it knows. Error `EntityAlreadyExists` means set it to `false`;
  `Invalid principal in policy` means set it to `true`.
- **Deleting the manage stack also deletes the OIDC provider** (when the stack created it),
  which silently breaks the provision role. Delete the provision stack first, or keep manage.
- The provision role's `MaxSessionDuration` is 3600 s (the IAM minimum); Idlefy requests
  900 s sessions.
- The manual CLI guide in the Idlefy app creates an equivalent role by hand; the provision
  stack works with either.

## Development

```bash
pip install -r requirements-dev.txt
cfn-lint templates/*.yaml
pytest            # renders both templates with fixed parameters, checks snapshots and fence invariants
pytest --snapshot-update   # after an intended policy change
```

Releases: tag `vX.Y.Z` on `main`. CI stamps the version into the templates and uploads them
to `cfn/vX.Y.Z/` and `cfn/latest/` in the public bucket via a GitHub OIDC role that can only
write there. See `CHANGELOG.md`.
