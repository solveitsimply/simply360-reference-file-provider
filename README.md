# simply360-reference-file-provider

Public **reference proof**: a separately packaged, **MinIO-backed** gateway
that implements the **signed public primary-file-provider protocol** out of
process (Proof A).

> Status: **scaffold only.** No proof behavior is implemented yet. This
> repository is the foundation that **MKT-10** (S3/MinIO conformance plus
> out-of-process primary-file-provider gateway and forced-failure proof)
> builds on. See the plan's "Autonomous Proof Integrations — Proof A" and
> "Approved external targets and NonProd topology" for the authoritative
> requirements.

## Purpose

Prove that the Simply360 primary-file-provider protocol can be served by an
**independent, out-of-process gateway** — reachable only through a signed
public boundary — backed by MinIO. The gateway must cover:

upload, stream, head, checksum, immutable version, synthetic proof-object
deletion, copy/verify/switch/soak migration, failure, containment, and
recovery — **without provider-specific branches outside the adapter**, plus a
forced-failure proof.

Delete operations act **only on disposable synthetic proof objects**. This
proof does **not** authorize deleting a migration source, customer object, or
legal-hold/export evidence, a bring-your-own-bucket feature, or any recurring
paid provider cost.

## NonProd topology (intended; see `infra/README.md`)

Only an **API Gateway HTTP API** origin is public. It routes through a **VPC
Link + Cloud Map** to an **ephemeral ECS Fargate task** running the gateway
plus a **MinIO sidecar** whose port is never publicly reachable. **No ALB, no
NAT gateway.** Desired count is 0 outside acceptance windows; 4-hour max
runtime; synthetic-only storage.

## Boundary rules (non-negotiable)

- **Only public boundaries** (Ratified Direction 9 / 21): the signed public
  primary-file-provider protocol and the future `@simply360/integration-sdk`.
- **No** Simply360 internal package imports, database/VPC access, or SSM/E2E
  credentials. **No secrets** are committed here.
- The `@simply360/*` SDKs are **not yet published**; integration points are
  marked with `TODO(MKT-10)` in `src/index.ts`.

## Layout

```
.
├── .github/
│   ├── dependabot.yml          # npm + github-actions weekly updates (dev branch)
│   └── workflows/
│       ├── ci.yml              # build + test (pinned action SHAs)
│       └── security.yml        # dependency-review + SBOM + build provenance
├── infra/
│   └── README.md               # intended OIDC role + NonProd Fargate/MinIO topology (no AWS resources created)
├── src/
│   └── index.ts                # typed placeholder entry point + architecture sketch
├── test/
│   └── proof.test.js           # scaffold smoke test (node --test)
├── LICENSE                     # Apache-2.0
├── NOTICE
├── package.json                # public (private:false), Apache-2.0, Node 22, dev tooling only
└── tsconfig.json
```

## Develop

```bash
npm install      # dev tooling only (typescript, @types/node)
npm run type-check
npm run build
npm test
```

## CI / security posture

- `ci.yml` (build + test) and `security.yml` (dependency review, SPDX SBOM,
  build-provenance attestation) are committed with **all third-party actions
  pinned to a full commit SHA**.
- GitHub Actions is currently **billing-blocked account-wide**, so no run has
  executed yet. `dev` branch protection therefore does **not** require status
  checks until these workflows have a green baseline.
- Secret scanning and push protection are enabled on the repository.

## License

Apache-2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
