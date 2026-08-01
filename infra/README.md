# Infrastructure — deployable NonProd template

This document records the **intended** AWS/GitHub OIDC provisioning for this
reference proof. **Nothing deploys automatically.** Both templates are explicit
later provisioning steps owned and rotated by the platform owner.

## GitHub OIDC deploy role

Deployments use short-lived credentials via GitHub OIDC — no long-lived AWS
keys. The IAM role trust must be scoped to **this repository and the `dev`
branch only**:

- Repository: `solveitsimply/simply360-reference-file-provider`
- Trusted subject: `repo:solveitsimply/simply360-reference-file-provider:ref:refs/heads/dev`
- OIDC provider: `token.actions.githubusercontent.com` (the org's existing
  provider is reused)

> Creating or promoting a `main` branch — and any `main`-scoped trust — is
> reserved for the Production/GA plan under fresh explicit authorization.

The GitHub deployment role, CloudFormation service role, ECS task execution
role, and cleanup-Lambda role are **bootstrap prerequisites** created once by
the platform owner from the separately validated
`reference-file-provider-dev-bootstrap.yaml` template. That template accepts
no repository, branch, role-name, OIDC-provider, or secret parameters. The
application stack deliberately does not try to create the role that must
already be assumed to deploy it. The OIDC trust uses this exact
`StringEquals` subject (not a parameter or wildcard):

```json
{
  "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
  "token.actions.githubusercontent.com:sub": "repo:solveitsimply/simply360-reference-file-provider:ref:refs/heads/dev"
}
```

The GitHub role needs only CloudFormation change-set/deploy/read actions for
this stack plus `iam:PassRole` for the fixed CloudFormation service role. The
CloudFormation service role owns the ECS, API Gateway, Cloud Map, EventBridge,
Lambda, logs, security-group, deterministic empty runtime-secret container,
and exact pass-role authority. The task role reads only that named secret; the
cleanup role can only update the deterministically named ECS service and write
its bounded log stream.

## NonProd stack and region

| Setting         | Value                               |
| --------------- | ----------------------------------- |
| Region          | `us-east-1`                         |
| Dedicated stack | `Simply360ReferenceFileProviderDev` |

The monorepo-owned dev evidence stack (`Simply360IntegrationMarketplaceEvidenceDev`)
is separate and not provisioned here. Deployment roles and Secrets Manager paths
are repository-scoped and owned/rotated by the platform owner.

## Intended NonProd topology (Proof A)

The file-provider stack exposes **only an API Gateway HTTPS origin**:

- **API Gateway HTTP API** → **VPC Link** → **Cloud Map** → an **ephemeral ECS
  Fargate task** containing the public-protocol gateway and a **MinIO sidecar**.
- The **MinIO port is not permitted by any public security-group rule**; MinIO
  is reachable only through task-localhost.
- **No ALB and no NAT gateway.** The task runs in a **public subnet with a
  public IP** for image/secret/log egress only; inbound permits only the
  VPC-link security group to the gateway port.
- Task sizing: **0.5 vCPU, 1 GiB memory, 20 GiB ephemeral synthetic-only
  storage**, **desired count 0** outside acceptance windows, **4-hour maximum
  runtime**, with scheduled/CI cleanup.
- Provider state is **disposable synthetic proof objects** and never customer
  data.
- ECS deployment configuration is fixed at maximum 100% / minimum 0%, so an
  update cannot add a second task. The acceptance launcher additionally
  refuses to start unless the service is idle with one completed deployment;
  the deploy workflow enforces the same idle-state precondition, so stack and
  service updates are rejected during the acceptance window.

## Cost guardrail

Ratified Direction 40: NonProd recurring cost is capped at **$25/month**
(expected $2–$10/month). Ephemeral Fargate/Cloud Map acceptance runs are
projected at less than $1/month. Re-estimate before provisioning and stop above
the cap.

## What is NOT here

No credentials, secret values, SSM references, or Simply360 internal
configuration are stored in this repository (Ratified Direction 9 / 21).

`reference-file-provider-dev.yaml` is a manually triggered dev template; its
ECS service starts at desired count `0` and creates the empty, deterministic
`simply360/reference-file-provider/dev/runtime` secret container. The owner
writes its six values out of band after deployment. The `deploy-dev` workflow
takes only existing VPC/public-subnet and digest-pinned image inputs through
repo/branch-scoped OIDC and never runs automatically. For an owner-approved
synthetic acceptance window, `run-acceptance-window.sh` starts exactly one task
and its exit trap restores desired count `0`. No local or CI command deploys
this stack.
