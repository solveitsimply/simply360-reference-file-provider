# simply360-reference-file-provider

Public **reference proof**: a separately packaged, **MinIO-backed** gateway
that implements the **signed public primary-file-provider protocol** out of
process (Proof A).

> Status: **runtime proof implemented locally.** The deployable gateway uses a
> dependency-free S3 Signature V4 adapter against task-local MinIO and a
> self-contained implementation of the public v1 contract while the public SDK
> remains unpublished. A live NonProd deployment still requires the separately
> authorized platform stack and OIDC role described in `infra/README.md`.

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
- `@simply360/integration-sdk` is **not yet published**: a registry check on
  2026-08-01 returned npm `E404`. To avoid an internal import or an unpinned
  Git dependency, `src/index.ts` implements the published v1 protocol contract
  directly. Replace it with an exact, version-pinned public package only after
  that package exists on npm and its contract vectors pass unchanged.

## Layout

```
.
├── .github/
│   ├── dependabot.yml          # npm + github-actions weekly updates (dev branch)
│   └── workflows/
│       ├── ci.yml              # build + test (pinned action SHAs)
│       ├── deploy-dev.yml      # manual, digest-only, idle-service dev deployment
│       └── security.yml        # dependency-review + SBOM + build provenance
├── infra/
│   ├── reference-file-provider-dev-bootstrap.yaml # one-time exact-repo IAM roles
│   ├── reference-file-provider-dev.yaml           # zero-idle bounded proof stack
│   ├── run-acceptance-window.sh                    # one-task/four-hour acceptance guard
│   └── README.md
├── scripts/run-minio-proof.mjs # pinned-image live adapter proof
├── src/
│   └── index.ts                # signed gateway, MinIO adapter, HTTP entry point
├── test/
│   └── proof.test.js           # contract, lifecycle, forced-failure, security tests
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

## Run the proof gateway

The gateway has no credentials or endpoint defaults. It refuses to start until
these values are supplied through the task's secret injection:

```bash
export S360_PLATFORM_KEY_ID='platform-ed25519-key-id'
export S360_PLATFORM_PUBLIC_KEY_PEM='-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----'
export S360_PROVIDER_KEY_ID='provider-ed25519-key-id'
export S360_PROVIDER_PRIVATE_KEY_PEM='-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----'
export MINIO_ENDPOINT='http://127.0.0.1:9000'
export MINIO_BUCKET='simply360-reference-proof'
export MINIO_ACCESS_KEY='injected-minio-access-key'
export MINIO_SECRET_KEY='injected-minio-secret-key'
npm run build && npm start
```

The container has no npm runtime dependencies:

```bash
docker build -t simply360-reference-file-provider .
docker run --rm -p 8080:8080 --env-file .env simply360-reference-file-provider
```

Only the gateway port is suitable for the VPC Link target. Configure MinIO as
a task-local sidecar and never publish its port. The gateway accepts only
canonical, signed, five-minute v1 requests and signs every successful response.
Provider object IDs must be `proof.*`, so permanent deletion cannot target a
customer, migration-source, legal-hold, or export object. Migration copy,
independent byte/hash verification, switch, and soak preserve the source.

`POST /v1/primary-file-provider/dev/failure` supports deterministic
`BEFORE_OBJECT_WRITE`, `AFTER_OBJECT_WRITE_BEFORE_COMMIT`, and `OBJECT_READ`
failures. The test suite proves failure injection, `READ_ONLY` containment,
explicit recovery, canonical golden vectors, and closed-schema rejection. A
local Docker/MinIO verification additionally exercises SigV4 bucket creation,
PUT/GET/HEAD/list/delete, and `:`, `=`, and `/` percent-encoded object names.

Every byte-changing request writes a bounded rollback fence to the task-local
MinIO sidecar before it touches object bytes. A failed control-state commit is
compensated immediately; if that compensation also fails, the same live task
returns an error but remains running, and its next request repairs the exact
prior bytes from the fence before serving. The zero-idle proof stack uses
ephemeral Fargate storage, so the fence is intentionally not claimed to survive
an ECS task replacement; the whole synthetic proof store is disposable with
that task. Archive/restore requires the exact live immutable version and
persists logical archive state. The outbox, committed
PUT set, archive set, active migrations, and permanently protected migration
sources all have explicit caps; deletes and completed soak operations retire
the state that is safe to retire. Usage reads paginate to completion rather
than silently truncating the object inventory.

## CI / security posture

- `ci.yml` (build + test) and `security.yml` (dependency review, SPDX SBOM,
  build-provenance attestation) are committed with **all third-party actions
  pinned to a full commit SHA**.
- CI workflow status is intentionally not asserted here; verify it from the
  repository's current GitHub Actions runs before relying on deployment gates.
- Secret scanning and push protection are enabled on the repository.

## License

Apache-2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
