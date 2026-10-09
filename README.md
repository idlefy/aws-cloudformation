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

The provision role can only change resources that carry the tag **`IdlefyManaged=true`**. The
one other tag it reads is `IdlefyAttached`, which you may put on a network of your own (v1.5.0,
see "Handing an existing machine over" below):

- Creating a VPC, subnet, security group, route table, internet gateway, Elastic IP or
  instance (with its volume) is allowed only when the request tags it `IdlefyManaged=true`
  (`aws:RequestTag`), inside the regions you list (`AllowedRegions`), with an instance type
  from your list (`AllowedInstanceTypes`) and a volume no larger than `MaxVolumeGiB`.
- A subnet, security group or route table can only be created inside a VPC that already
  carries the tag; tagging the new resource alone is not enough. A security group, and
  nothing else, can also be created inside a VPC you tagged `IdlefyAttached=<org id>`.
- Stopping, starting, terminating, deleting, associating or modifying is allowed only on
  resources that already carry the tag (`ec2:ResourceTag`).
- Instances may only launch into a subnet that carries the tag (or one you tagged
  `IdlefyAttached=<org id>`) and with a security group that carries `IdlefyManaged`, from an
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
- `ModifyInstanceAttribute` has exactly two uses, both on an instance that carries the tag.
  **Changing the machine type of a stopped box** (v1.4.0): the new type must be in
  `AllowedInstanceTypes`. **Putting a box behind a security group Idlefy created** (v1.5.0):
  every group in the new list must carry `IdlefyManaged=true` itself, so the role can never
  attach a group of yours. Every other attribute (user data, termination and stop protection,
  source/dest check, the disks' delete-on-termination, ...) is explicitly denied, and a call
  that carries user data is denied whatever else it carries.
- **Moving a box to another zone** (v1.4.0) is off unless you set `AllowZoneMove` to `true`;
  see the section below. With or without it, the role can never share an image or a snapshot
  with another account (`ModifySnapshotAttribute` and `ModifyImageAttribute` are explicitly
  denied), never copy or export one (`CopySnapshot`, `CopyImage`, `CreateStoreImageTask`,
  `ExportImage`, `CreateInstanceExportTask` are explicitly denied) and never read a snapshot
  block by block (`ebs:*` is explicitly denied).
- Explicit `Deny` on `iam:PassRole`, instance-profile association, `DeleteTags`, `sts:*`,
  `organizations:*`, and on any EC2 call outside `AllowedRegions`.
- The fence policy is attached to the role **and** set as its permissions boundary, so a
  policy attached later by mistake cannot exceed it. The instance-type list and the region
  list are the two limits the boundary does not hold: they are the inline policy below, so do
  not delete that policy.
- The instance-type list and (since v1.5.0) the region list are enforced by explicit denies in
  the role's own inline policy `IdlefyProvisionLimits`: launching, or changing the type,
  outside `AllowedInstanceTypes`, and any EC2 call outside `AllowedRegions`. A deny holds
  whatever else is attached to the role. The lists live there because IAM caps a managed
  policy at 6,144 characters. Both policies fit their limits at 20 regions and 50 types, and a
  test keeps it so.

### Moving a box to another zone (`AllowZoneMove`, off by default)

When AWS has no capacity for a box in its zone, a person can ask Idlefy to move it. AWS cannot
move a disk between zones, so the move is: an image of the box, a new instance from that image
in another zone, then the image and its snapshot are deleted.

With `AllowZoneMove = true` the role can:

- make an image of an instance that carries the tag (`ec2:CreateImage`); the image and its
  snapshot must be tagged `IdlefyManaged=true` in the same call, and a snapshot Idlefy did
  not create cannot be pulled into the image;
- delete an image or a snapshot that carries the tag.

What that means, plainly: **this is the one setting that lets the Idlefy role touch the data
on a box.** The role can already launch instances with a user data of its choosing; with this
on it can also launch one from a copy of a box's disk, and IAM offers no condition on user
data. Idlefy starts the copy with a fixed user data that only keeps the box's SSH host keys,
and stops the box before copying it, but neither is something IAM can enforce. Every move
leaves `CreateImage` followed by `RunInstances` in your CloudTrail.

With `AllowZoneMove = false` (the default) none of these actions is granted, and "Idlefy can
never get inside a box, or read what is inside it" holds as a property of the role itself, for
every box Idlefy created. People can still retry, and switch to another allowed machine type.

What the fence does not limit: the number of instances. That is bounded by Idlefy's own
rate limits and by your EC2 service quotas.

### Handing an existing machine over to Idlefy (v1.5.0)

The role can never tag anything that already exists, so it can never reach a machine of yours
on its own. You hand one over by tagging it yourself with the marks of a box Idlefy created;
the Idlefy app shows the exact command:

- on the instance and (if it has one) its Elastic IP: `IdlefyManaged=true`,
  `IdlefyOrg=<your Idlefy organization id>`, `IdlefyResource=<the box id Idlefy shows>`;
- on the VPC and on each subnet Idlefy may use: `IdlefyAttached=<your Idlefy organization id>`.

From then on the machine **is** a dev box: Idlefy starts and stops it, changes its type,
manages who may connect to it, and **deletes it, with its disk and its Elastic IP, when the
box is deleted**. With `AllowZoneMove = true` it can also be moved to another zone, which
copies its disk as described above.

To take a machine back, remove `IdlefyManaged` from the instance and from its Elastic IP, and
switch the instance to security groups of your own. Removing the tag from the instance ends
the role's reach over the instance at once, but not over the security group Idlefy created:
while that group is attached, Idlefy still controls its inbound rules.

`IdlefyManaged=true` is not tied to one Idlefy organization by IAM: if two organizations have
a provision stack in the same AWS account, the role of either can act on a resource carrying
the tag. Idlefy itself checks `IdlefyOrg` and `IdlefyResource` before every change.

The disk goes with the machine only because AWS deletes it on termination: the role has no
permission to delete a volume and cannot change a disk's delete-on-termination setting. The
Idlefy app therefore accepts a machine only when its root disk is set to be deleted on
termination, and shows how to set it when it is not.

The two tags are deliberately different:

- `IdlefyManaged=true` means "Idlefy may change and delete this". Never put it on a VPC,
  subnet, route table or gateway of yours.
- `IdlefyAttached=<org id>` means "Idlefy may work inside this network" and grants exactly two
  things: creating Idlefy's own per-box security group in a tagged VPC, and launching an
  instance into a tagged subnet (used when a box is moved to another zone). No statement lets
  the role change or delete a network that carries it, and the security groups, routes and
  gateways of that network stay out of reach.

Access to a machine you hand over is put behind a security group Idlefy creates, with the
inbound rules your own groups had. Outbound traffic is not carried over: the new group allows
all of it, and the role has no permission to change outbound rules, so a machine whose groups
restricted outbound traffic loses that restriction. Your groups are never edited or deleted:
the role can only switch the machine to groups that carry `IdlefyManaged=true`.

## Compatibility contract with the Idlefy app

| Item | Value | Change requires |
|---|---|---|
| Role names | `IdlefyManage-<org12>`, `IdlefyProvision-<org12>` where `org12` = first 12 hex chars of the organization UUID (computed inside the template) | major version |
| Suggested stack names | `Idlefy-Manage`, `Idlefy-Provision` | minor |
| Parameters | manage: `OrgId`, `IssuerHost`, `CreateOidcProvider`, `IncludeMetrics`; provision: `OrgId`, `IssuerHost`, `AllowedRegions`, `AllowedInstanceTypes`, `MaxVolumeGiB`, `AllowZoneMove` (v1.4.0, default `false`) | major (removing or renaming); minor (adding one that has a default) |
| Trust conditions | `<issuer>:aud = sts.amazonaws.com`; manage `sub = <OrgId>`, provision `sub = <OrgId>:provision` | major |
| Fence tag | `IdlefyManaged = true` | major |
| Provision stack output `TemplateVersion` (since v1.4.0) | the deployed version, e.g. `v1.4.0`; the app reads it to decide which actions the role supports. A stack without it is older than v1.4.0 | major |
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
