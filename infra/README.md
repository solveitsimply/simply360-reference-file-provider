# Infrastructure — intended provisioning (placeholder)

This document records the **intended** AWS/GitHub OIDC provisioning for this
reference proof. **No AWS resources are created by this repository.** Everything
below is a later provisioning step, owned and rotated by the platform owner.

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

## Cost guardrail

Ratified Direction 40: NonProd recurring cost is capped at **$25/month**
(expected $2–$10/month). Ephemeral Fargate/Cloud Map acceptance runs are
projected at less than $1/month. Re-estimate before provisioning and stop above
the cap.

## What is NOT here

No credentials, secret values, SSM references, or Simply360 internal
configuration are stored in this repository (Ratified Direction 9 / 21). No
CloudFormation/CDK/Terraform templates are provisioned; this file is
documentation of the later provisioning step only.
