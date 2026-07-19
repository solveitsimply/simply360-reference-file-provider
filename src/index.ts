/**
 * Simply360 Reference App — File Provider Gateway
 * Signed public primary-file-provider protocol proof (Proof A).
 *
 * SCAFFOLD ONLY — no proof behavior is implemented yet. This file establishes
 * the typed surface and the integration points that MKT-10 will build on.
 *
 * Architecture sketch (per plan Proof A + NonProd topology):
 *
 *   Simply360 platform ──HTTPS──▶ API Gateway (HTTP API, only public origin)
 *                                      │  VPC Link + Cloud Map
 *                                      ▼
 *                          ECS Fargate task (ephemeral, desired-count 0
 *                          outside acceptance windows, 4h max runtime)
 *                          ┌───────────────────────────────────────┐
 *                          │  primary-file-provider gateway         │
 *                          │      │ task-localhost only             │
 *                          │      ▼                                 │
 *                          │  MinIO sidecar (port NOT public)       │
 *                          └───────────────────────────────────────┘
 *
 *   No ALB. No NAT gateway. Public subnet + public IP for image/secret/log
 *   egress only; inbound permits only the VPC-link security group to the
 *   gateway port. Provider state is disposable synthetic proof objects.
 *
 * Protocol operations the gateway must implement (Proof A):
 *   upload, stream, head, checksum, immutable version, synthetic proof-object
 *   deletion, copy/verify/switch/soak migration, failure, containment, and
 *   recovery — with no provider-specific branches outside the adapter.
 *
 * Boundary rules (Ratified Direction 9 / 21):
 *   - Signed public primary-file-provider protocol only; no Simply360 internal
 *     package imports, database/VPC access, or SSM/E2E credentials.
 *   - Delete operates ONLY on disposable synthetic proof objects — never a
 *     migration source, customer object, or legal-hold/export evidence.
 */

/** Public primary-file-provider protocol operations this gateway must prove. */
export const PROTOCOL_OPERATIONS = [
  'upload',
  'stream',
  'head',
  'checksum',
  'immutable-version',
  'synthetic-delete',
  'migrate-copy-verify-switch-soak',
  'failure',
  'containment',
  'recovery',
] as const;

export type ProtocolOperation = (typeof PROTOCOL_OPERATIONS)[number];

export interface GatewayInfo {
  readonly name: string;
  /** Object-store backend proven behind the public protocol. */
  readonly backend: 'minio';
  /** Only public ingress; MinIO is never publicly reachable. */
  readonly publicOrigin: 'api-gateway-http-api';
  readonly operations: readonly ProtocolOperation[];
  /** Delete is restricted to disposable synthetic proof objects. */
  readonly syntheticProofObjectsOnly: true;
}

export const gateway: GatewayInfo = {
  name: 'simply360-reference-file-provider',
  backend: 'minio',
  publicOrigin: 'api-gateway-http-api',
  operations: PROTOCOL_OPERATIONS,
  syntheticProofObjectsOnly: true,
};

/**
 * Placeholder entry point. Returns the static gateway descriptor so the
 * scaffold type-checks, builds, and tests green before any runtime is wired.
 */
export function describeGateway(): GatewayInfo {
  // TODO(MKT-10): implement the signed public primary-file-provider protocol
  //   over MinIO via the future `@simply360/integration-sdk` protocol surface
  //   once published. Do not import Simply360 internal modules.
  // TODO(MKT-10): request/response signature verification, the MinIO adapter,
  //   and the conformance operations above (upload → recovery), plus the
  //   forced-failure proof.
  // TODO(MKT-10): keep provider-specific logic inside the adapter only; the
  //   protocol handler stays backend-neutral.
  return gateway;
}
