/**
 * Independently deployable reference gateway for the Simply360 primary-file-
 * provider v1 protocol.  It intentionally has no Simply360 runtime imports.
 *
 * The public SDK is not yet on npm.  This implementation is deliberately
 * self-contained, but follows its published v1 contract: canonical JSON,
 * Ed25519 request/response signatures, route/body binding, and exact-byte
 * hashes.  The only backend-specific code is the S3-compatible MinIO adapter.
 */
import {
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  sign,
  verify,
} from "node:crypto";
import { createServer } from "node:http";
import type { IncomingMessage, Server, ServerResponse } from "node:http";

export const PROTOCOL_OPERATIONS = [
  "HEALTH",
  "SETUP",
  "LIFECYCLE",
  "OUTBOX_LIST",
  "OUTBOX_ACK",
  "OBJECT_PUT",
  "OBJECT_GET",
  "OBJECT_HEAD",
  "OBJECT_CHECKSUM",
  "OBJECT_ARCHIVE",
  "OBJECT_RESTORE",
  "OBJECT_DELETE",
  "INVENTORY_LIST",
  "USAGE_GET",
  "CHANGES_LIST",
  "RECONCILE",
  "MIGRATION_COPY",
  "MIGRATION_VERIFY",
  "MIGRATION_SWITCH",
  "MIGRATION_SOAK",
  "FAILURE_INJECT",
] as const;
export type ProtocolOperation = (typeof PROTOCOL_OPERATIONS)[number];
type HttpMethod = "GET" | "HEAD" | "PUT" | "POST" | "DELETE";
type RoutingTarget =
  | "PRIMARY"
  | "MIGRATION_SOURCE"
  | "MIGRATION_TARGET"
  | "QUARANTINE";
type FailureMode =
  | "NONE"
  | "BEFORE_OBJECT_WRITE"
  | "AFTER_OBJECT_WRITE_BEFORE_COMMIT"
  | "OBJECT_READ";
type ContainmentState =
  | "NONE"
  | "BLOCK_NEW_INSTALLS"
  | "READ_ONLY"
  | "FULL_DISABLE_OR_QUARANTINE";

const routes: Record<
  ProtocolOperation,
  { method: HttpMethod; path: string; body: "empty" | "json" | "object" }
> = {
  HEALTH: {
    method: "GET",
    path: "/v1/primary-file-provider/health",
    body: "empty",
  },
  SETUP: {
    method: "POST",
    path: "/v1/primary-file-provider/setup",
    body: "json",
  },
  LIFECYCLE: {
    method: "POST",
    path: "/v1/primary-file-provider/lifecycle",
    body: "json",
  },
  OUTBOX_LIST: {
    method: "GET",
    path: "/v1/primary-file-provider/events",
    body: "empty",
  },
  OUTBOX_ACK: {
    method: "POST",
    path: "/v1/primary-file-provider/events/ack",
    body: "json",
  },
  OBJECT_PUT: {
    method: "PUT",
    path: "/v1/primary-file-provider/objects",
    body: "object",
  },
  OBJECT_GET: {
    method: "GET",
    path: "/v1/primary-file-provider/objects/content",
    body: "empty",
  },
  OBJECT_HEAD: {
    method: "HEAD",
    path: "/v1/primary-file-provider/objects",
    body: "empty",
  },
  OBJECT_CHECKSUM: {
    method: "GET",
    path: "/v1/primary-file-provider/objects/checksum",
    body: "empty",
  },
  OBJECT_ARCHIVE: {
    method: "POST",
    path: "/v1/primary-file-provider/objects/archive",
    body: "json",
  },
  OBJECT_RESTORE: {
    method: "POST",
    path: "/v1/primary-file-provider/objects/restore",
    body: "json",
  },
  OBJECT_DELETE: {
    method: "DELETE",
    path: "/v1/primary-file-provider/objects",
    body: "json",
  },
  INVENTORY_LIST: {
    method: "POST",
    path: "/v1/primary-file-provider/inventory",
    body: "json",
  },
  USAGE_GET: {
    method: "GET",
    path: "/v1/primary-file-provider/usage",
    body: "empty",
  },
  CHANGES_LIST: {
    method: "POST",
    path: "/v1/primary-file-provider/changes",
    body: "json",
  },
  RECONCILE: {
    method: "POST",
    path: "/v1/primary-file-provider/reconcile",
    body: "json",
  },
  MIGRATION_COPY: {
    method: "POST",
    path: "/v1/primary-file-provider/migration/copy",
    body: "json",
  },
  MIGRATION_VERIFY: {
    method: "POST",
    path: "/v1/primary-file-provider/migration/verify",
    body: "json",
  },
  MIGRATION_SWITCH: {
    method: "POST",
    path: "/v1/primary-file-provider/migration/switch",
    body: "json",
  },
  MIGRATION_SOAK: {
    method: "POST",
    path: "/v1/primary-file-provider/migration/soak",
    body: "empty",
  },
  FAILURE_INJECT: {
    method: "POST",
    path: "/v1/primary-file-provider/dev/failure",
    body: "json",
  },
};

export interface GatewayInfo {
  readonly name: string;
  readonly backend: "minio";
  readonly publicOrigin: "api-gateway-http-api";
  readonly operations: readonly ProtocolOperation[];
  readonly syntheticProofObjectsOnly: true;
}
export const gateway: GatewayInfo = {
  name: "simply360-reference-file-provider",
  backend: "minio",
  publicOrigin: "api-gateway-http-api",
  operations: PROTOCOL_OPERATIONS,
  syntheticProofObjectsOnly: true,
};
export const describeGateway = (): GatewayInfo => gateway;

export interface StoredObject {
  readonly body: Uint8Array;
  readonly sizeBytes: number;
  readonly contentSha256: string;
  readonly immutableProviderVersion: string;
}
export interface ObjectStore {
  put(objectId: string, body: Uint8Array): Promise<StoredObject>;
  get(objectId: string): Promise<StoredObject>;
  head(objectId: string): Promise<StoredObject>;
  copy(sourceObjectId: string, targetObjectId: string): Promise<StoredObject>;
  delete(objectId: string): Promise<void>;
  list(afterObjectId: string | null, limit: number): Promise<readonly string[]>;
}

/** Test-only in-memory store. Deployment uses MinioObjectStore. */
export class MemoryObjectStore implements ObjectStore {
  private readonly objects = new Map<string, StoredObject>();
  async put(objectId: string, body: Uint8Array): Promise<StoredObject> {
    const value = objectFor(body);
    this.objects.set(objectId, value);
    return value;
  }
  async get(objectId: string): Promise<StoredObject> {
    return this.require(objectId);
  }
  async head(objectId: string): Promise<StoredObject> {
    return this.require(objectId);
  }
  async copy(
    sourceObjectId: string,
    targetObjectId: string,
  ): Promise<StoredObject> {
    const value = await this.get(sourceObjectId);
    return this.put(targetObjectId, value.body);
  }
  async delete(objectId: string): Promise<void> {
    this.objects.delete(objectId);
  }
  async list(
    afterObjectId: string | null,
    limit: number,
  ): Promise<readonly string[]> {
    return [...this.objects.keys()]
      .sort()
      .filter((key) => afterObjectId === null || key > afterObjectId)
      .slice(0, limit);
  }
  private require(objectId: string): StoredObject {
    const value = this.objects.get(objectId);
    if (!value) throw new ProviderError(404, "OBJECT_NOT_FOUND");
    return value;
  }
}

export interface MinioObjectStoreOptions {
  readonly endpoint: string;
  readonly bucket: string;
  readonly accessKey: string;
  readonly secretKey: string;
  readonly region?: string;
  readonly requestTimeoutMs?: number;
}
/** Dependency-free AWS Signature v4 adapter for a task-local MinIO sidecar. */
export class MinioObjectStore implements ObjectStore {
  private readonly endpoint: URL;
  private readonly region: string;
  private readonly requestTimeoutMs: number;
  constructor(private readonly options: MinioObjectStoreOptions) {
    this.endpoint = new URL(options.endpoint);
    if (
      !["http:", "https:"].includes(this.endpoint.protocol) ||
      !options.bucket ||
      !options.accessKey ||
      !options.secretKey
    )
      throw new Error(
        "MINIO_ENDPOINT, MINIO_BUCKET, MINIO_ACCESS_KEY, and MINIO_SECRET_KEY are required",
      );
    this.region = options.region ?? "us-east-1";
    this.requestTimeoutMs = options.requestTimeoutMs ?? 10_000;
    if (
      !Number.isSafeInteger(this.requestTimeoutMs) ||
      this.requestTimeoutMs < 100 ||
      this.requestTimeoutMs > 60_000
    )
      throw new Error(
        "MINIO_REQUEST_TIMEOUT_MS must be an integer between 100 and 60000",
      );
  }
  async put(objectId: string, body: Uint8Array): Promise<StoredObject> {
    const response = await this.request("PUT", objectId, body);
    await this.requireOk(response);
    return objectFor(body);
  }
  /** Creates the disposable proof bucket; only used by the local MinIO integration test/provisioner. */
  async ensureBucket(): Promise<void> {
    const existing = await this.request("HEAD", "");
    if (existing.ok) return;
    if (existing.status !== 404) await this.requireOk(existing);
    const created = await this.request("PUT", "");
    if (created.ok || created.status === 409) return;
    await this.requireOk(created);
  }
  /** Bounded readiness probe for the task-local MinIO sidecar. */
  async waitUntilReady(maximumWaitMs = 30_000): Promise<void> {
    const deadline = Date.now() + maximumWaitMs;
    let lastError: unknown;
    while (Date.now() < deadline) {
      try {
        await this.ensureBucket();
        return;
      } catch (error) {
        lastError = error;
        await new Promise((resolve) => setTimeout(resolve, 250));
      }
    }
    throw new Error("MinIO sidecar did not become ready within 30 seconds", {
      cause: lastError,
    });
  }
  async get(objectId: string): Promise<StoredObject> {
    const response = await this.request("GET", objectId);
    await this.requireOk(response);
    return objectFor(new Uint8Array(await response.arrayBuffer()));
  }
  async head(objectId: string): Promise<StoredObject> {
    const response = await this.request("HEAD", objectId);
    await this.requireOk(response);
    const sizeBytes = Number(response.headers.get("content-length"));
    const contentSha256 = response.headers.get("x-amz-meta-s360-sha256");
    if (!Number.isSafeInteger(sizeBytes) || !contentSha256)
      return this.get(objectId);
    return {
      body: new Uint8Array(),
      sizeBytes,
      contentSha256,
      immutableProviderVersion: `sha256:${contentSha256}`,
    };
  }
  async copy(
    sourceObjectId: string,
    targetObjectId: string,
  ): Promise<StoredObject> {
    const source = await this.get(sourceObjectId);
    return this.put(targetObjectId, source.body);
  }
  async delete(objectId: string): Promise<void> {
    await this.requireOk(await this.request("DELETE", objectId));
  }
  async list(
    afterObjectId: string | null,
    limit: number,
  ): Promise<readonly string[]> {
    const query = new URLSearchParams({
      "list-type": "2",
      prefix: "proof.",
      "max-keys": String(limit),
    });
    if (afterObjectId) query.set("start-after", afterObjectId);
    const response = await this.request("GET", "", undefined, query);
    await this.requireOk(response);
    return [...(await response.text()).matchAll(/<Key>([^<]+)<\/Key>/g)].map(
      (match) => decodeXml(match[1]!),
    );
  }
  private async request(
    method: HttpMethod,
    objectId: string,
    body?: Uint8Array,
    query?: URLSearchParams,
  ): Promise<Response> {
    const objectPath = `/${this.options.bucket}${objectId ? `/${encodeS3Path(objectId)}` : ""}`;
    const now = new Date();
    const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
    const date = amzDate.slice(0, 8);
    const payload = body ?? new Uint8Array();
    const payloadHash = sha256(payload);
    const url = new URL(objectPath, this.endpoint);
    if (query) url.search = query.toString();
    const canonicalQuery = [...url.searchParams.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${rfc3986(k)}=${rfc3986(v)}`)
      .join("&");
    const host = url.host;
    const headers: Record<string, string> = {
      host,
      "x-amz-content-sha256": payloadHash,
      "x-amz-date": amzDate,
    };
    if (method === "PUT") headers["x-amz-meta-s360-sha256"] = payloadHash;
    const canonicalHeaders = Object.entries(headers)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}:${v}\n`)
      .join("");
    const signedHeaders = Object.keys(headers).sort().join(";");
    const canonicalRequest = `${method}\n${objectPath}\n${canonicalQuery}\n${canonicalHeaders}\n${signedHeaders}\n${payloadHash}`;
    const credentialScope = `${date}/${this.region}/s3/aws4_request`;
    const stringToSign = `AWS4-HMAC-SHA256\n${amzDate}\n${credentialScope}\n${sha256(Buffer.from(canonicalRequest))}`;
    const kDate = hmac(`AWS4${this.options.secretKey}`, date);
    const kRegion = hmac(kDate, this.region);
    const kService = hmac(kRegion, "s3");
    const signature = hmac(
      hmac(kService, "aws4_request"),
      stringToSign,
    ).toString("hex");
    headers.authorization = `AWS4-HMAC-SHA256 Credential=${this.options.accessKey}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.requestTimeoutMs);
    try {
      return await fetch(url, {
        method,
        headers,
        body: body ? Buffer.from(body) : undefined,
        signal: controller.signal,
      });
    } catch (error) {
      if (controller.signal.aborted)
        throw new ProviderError(504, "MINIO_TIMEOUT");
      throw error;
    } finally {
      clearTimeout(timeout);
    }
  }
  private async requireOk(response: Response): Promise<void> {
    if (!response.ok)
      throw new ProviderError(response.status, `MINIO_${response.status}`);
  }
}

export interface GatewayRequest {
  readonly method: string;
  readonly path: string;
  readonly headers: Readonly<Record<string, string | undefined>>;
  readonly body: Uint8Array;
}
export interface GatewayResponse {
  readonly statusCode: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: Uint8Array;
}
export interface GatewayConfig {
  readonly platformKeyId: string;
  readonly platformPublicKeyPem: string;
  readonly providerKeyId: string;
  readonly providerPrivateKeyPem: string;
  readonly objectStore: ObjectStore;
  readonly controlStateObjectId?: string;
  readonly now?: () => Date;
}
interface RequestEnvelope {
  readonly schemaVersion: "simply360.primary-file-provider-request/v1";
  readonly protocolVersion: 1;
  readonly keyPurpose: "PRIMARY_FILE_PROVIDER_REQUEST_V1";
  readonly direction: "SIMPLY360_TO_PROVIDER";
  readonly requestSimplyId: string;
  readonly method: HttpMethod;
  readonly normalizedPath: string;
  readonly bodySha256: string;
  readonly teamSimplyId: string;
  readonly teamIntegrationSimplyId: string;
  readonly integrationAppVersionSimplyId: string;
  readonly operation: ProtocolOperation;
  readonly fileSimplyId: string | null;
  readonly providerObjectId: string | null;
  readonly immutableProviderVersion: string | null;
  readonly routingTarget: RoutingTarget;
  readonly authorityRevision: number;
  readonly idempotencyKey: string;
  readonly nonce: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
}
interface Change {
  readonly sequence: number;
  readonly type: string;
  readonly objectId: string | null;
  readonly immutableProviderVersion: string | null;
}
interface MigrationState {
  readonly source: string;
  readonly target: string;
  readonly version: string;
  verified: boolean;
  soakUntil?: string;
}

interface MutableGatewayState {
  readonly containment: ContainmentState;
  readonly failureMode: FailureMode;
  readonly sequence: number;
  readonly acknowledgedThroughSequence: number;
  readonly changes: Change[];
  readonly migrations: MigrationState[];
  readonly committedPuts: [string, string][];
  readonly archivedObjects: [string, string][];
  readonly protectedMigrationSources: string[];
}

interface StorageMutationSnapshot {
  readonly objectId: string;
  readonly object: StoredObject | null;
}

interface StorageRollbackFence {
  readonly schemaVersion: "simply360.reference-file-provider-rollback/v1";
  readonly priorSequence: number;
  readonly objectId: string;
  readonly original: {
    readonly bodyBase64Url: string;
    readonly sizeBytes: number;
    readonly contentSha256: string;
    readonly immutableProviderVersion: string;
  } | null;
}

const MAXIMUM_REQUEST_BYTES = 8 * 1024 * 1024;
const CONTROL_STATE_OBJECT_ID = "proof.gateway-control-v1";
const STORAGE_ROLLBACK_FENCE_OBJECT_ID = "proof.gateway-rollback-fence-v1";
const MAXIMUM_OUTBOX_CHANGES = 1_000;
const MAXIMUM_TRACKED_OBJECTS = 1_000;
const MAXIMUM_TRACKED_MIGRATIONS = 100;
const MAXIMUM_USAGE_OBJECTS = 10_000;

export class PrimaryFileProviderGateway {
  private containment: ContainmentState = "NONE";
  private failureMode: FailureMode = "NONE";
  private sequence = 0;
  private acknowledgedThroughSequence = 0;
  private readonly changes: Change[] = [];
  private readonly migrations = new Map<string, MigrationState>();
  private readonly committedPuts = new Map<string, string>();
  private readonly archivedObjects = new Map<string, string>();
  private readonly protectedMigrationSources = new Set<string>();
  private initialization?: Promise<void>;
  private storageRecoveryRequired = false;
  private recoveryContainment: ContainmentState | null = null;
  private ambiguousPriorState: MutableGatewayState | null = null;
  private ambiguousIntendedStateBody: Uint8Array | null = null;
  private serializedRequests: Promise<void> = Promise.resolve();
  private readonly platformKey;
  private readonly providerKey;
  constructor(private readonly config: GatewayConfig) {
    this.platformKey = createPublicKey(config.platformPublicKeyPem);
    this.providerKey = createPrivateKey(config.providerPrivateKeyPem);
  }
  async handle(request: GatewayRequest): Promise<GatewayResponse> {
    if (request.body.length > MAXIMUM_REQUEST_BYTES) {
      return this.unsignedError(new ProviderError(413, "REQUEST_TOO_LARGE"));
    }
    let envelope: RequestEnvelope;
    try {
      envelope = this.verifyRequest(request);
    } catch (error) {
      return this.unsignedError(error);
    }
    try {
      return await this.serialize(async () => {
        await this.initialize();
        if (this.ambiguousPriorState) await this.resolveAmbiguousControlState();
        if (this.storageRecoveryRequired) await this.recoverStorageFence();
        this.assertEnvelopeFresh(envelope);
        const isMutating = this.isMutatingOperation(envelope.operation);
        const snapshot = isMutating ? this.snapshotState() : null;
        const storageSnapshot = isMutating
          ? await this.snapshotStorageMutation(envelope, request.body)
          : null;
        if (storageSnapshot)
          await this.prepareStorageFence(storageSnapshot, this.sequence);
        let response: GatewayResponse;
        try {
          response = await this.dispatch(envelope, request.body);
        } catch (error) {
          if (snapshot) await this.rollbackMutation(snapshot, storageSnapshot);
          throw error;
        }
        if (isMutating) {
          try {
            await this.persistState();
          } catch (error) {
            try {
              if (await this.currentStateIsDurable()) {
                await this.finishStorageFence(storageSnapshot);
                return response;
              }
            } catch {
              if (!snapshot)
                throw new ProviderError(500, "MUTATION_SNAPSHOT_MISSING");
              this.ambiguousPriorState = snapshot;
              this.ambiguousIntendedStateBody = this.stateBody();
              this.storageRecoveryRequired = storageSnapshot !== null;
              throw new ProviderError(503, "CONTROL_STATE_COMMIT_UNKNOWN");
            }
            if (snapshot)
              await this.rollbackMutation(snapshot, storageSnapshot);
            throw error;
          }
        }
        await this.finishStorageFence(storageSnapshot);
        return response;
      });
    } catch (error) {
      const statusCode =
        error instanceof ProviderError ? error.statusCode : 500;
      const code =
        error instanceof ProviderError ? error.code : "INTERNAL_ERROR";
      return this.respond(envelope, statusCode, { code }, null);
    }
  }
  private verifyRequest(request: GatewayRequest): RequestEnvelope {
    const headers = lowerHeaders(request.headers);
    const envelopeHeader = headers["x-s360-envelope"];
    const signature = headers["x-s360-signature"];
    if (
      headers["x-s360-key-id"] !== this.config.platformKeyId ||
      !envelopeHeader ||
      !signature
    )
      throw new ProviderError(401, "SIGNATURE_INVALID");
    const envelopeBytes = fromBase64Url(envelopeHeader);
    const text = new TextDecoder("utf-8", { fatal: true }).decode(
      envelopeBytes,
    );
    const parsed = parseStrictJson(text);
    if (canonicalize(parsed) !== text)
      throw new ProviderError(401, "ENVELOPE_NOT_CANONICAL");
    const envelope = assertRequestEnvelope(parsed);
    const signatureBytes = fromBase64Url(signature);
    if (
      signatureBytes.length !== 64 ||
      !verify(
        null,
        Buffer.concat([
          Buffer.from("simply360:primary-file-provider-request:v1\n"),
          Buffer.from(envelopeBytes),
        ]),
        this.platformKey,
        signatureBytes,
      )
    )
      throw new ProviderError(401, "SIGNATURE_INVALID");
    const route = routes[envelope.operation];
    if (
      !route ||
      route.method !== request.method ||
      route.path !== request.path ||
      envelope.method !== request.method ||
      envelope.normalizedPath !== request.path
    )
      throw new ProviderError(400, "REQUEST_BINDING_MISMATCH");
    this.assertEnvelopeFresh(envelope);
    if (sha256(request.body) !== envelope.bodySha256)
      throw new ProviderError(400, "BODY_DIGEST_MISMATCH");
    return envelope;
  }
  private async dispatch(
    envelope: RequestEnvelope,
    body: Uint8Array,
  ): Promise<GatewayResponse> {
    const id = envelope.providerObjectId;
    const json =
      routes[envelope.operation].body === "json"
        ? parseOperationBody(envelope.operation, body)
        : undefined;
    if (routes[envelope.operation].body === "empty" && body.length)
      throw new ProviderError(400, "BODY_NOT_EMPTY");
    if (
      this.containment === "FULL_DISABLE_OR_QUARANTINE" &&
      envelope.operation !== "LIFECYCLE" &&
      envelope.operation !== "HEALTH" &&
      envelope.operation !== "OUTBOX_LIST" &&
      envelope.operation !== "OUTBOX_ACK"
    )
      throw new ProviderError(423, "CONTAINED");
    if (
      this.containment === "READ_ONLY" &&
      [
        "OBJECT_PUT",
        "OBJECT_ARCHIVE",
        "OBJECT_RESTORE",
        "OBJECT_DELETE",
        "MIGRATION_COPY",
        "MIGRATION_VERIFY",
        "MIGRATION_SWITCH",
      ].includes(envelope.operation)
    )
      throw new ProviderError(423, "READ_ONLY");
    if (
      this.containment !== "NONE" &&
      envelope.operation === "SETUP" &&
      json!.action === "ACTIVATE"
    )
      throw new ProviderError(423, "SETUP_CONTAINED");
    if (envelope.operation === "HEALTH")
      return this.respond(
        envelope,
        200,
        { healthy: true, containment: this.containment },
        null,
      );
    if (envelope.operation === "SETUP")
      return this.respond(
        envelope,
        200,
        { state: json!.action === "ACTIVATE" ? "ACTIVE" : "VALIDATED" },
        null,
      );
    if (envelope.operation === "LIFECYCLE") {
      this.ensureOutboxCapacity();
      this.applyLifecycle(json!);
      return this.respond(
        envelope,
        200,
        { containment: this.containment },
        null,
      );
    }
    if (envelope.operation === "FAILURE_INJECT") {
      this.failureMode = json!.mode as FailureMode;
      return this.respond(envelope, 200, { mode: this.failureMode }, null);
    }
    if (envelope.operation === "OUTBOX_LIST")
      return this.respond(
        envelope,
        200,
        {
          changes: this.changes.filter(
            (change) => change.sequence > this.acknowledgedThroughSequence,
          ),
        },
        null,
      );
    if (envelope.operation === "OUTBOX_ACK") {
      const throughSequence = json!.throughSequence as number;
      if (throughSequence > this.sequence)
        throw new ProviderError(409, "OUTBOX_ACK_BEYOND_SEQUENCE");
      this.acknowledgedThroughSequence = Math.max(
        this.acknowledgedThroughSequence,
        throughSequence,
      );
      this.changes.splice(
        0,
        this.changes.findLastIndex(
          (change) => change.sequence <= this.acknowledgedThroughSequence,
        ) + 1,
      );
      return this.respond(
        envelope,
        200,
        { acknowledgedThroughSequence: this.acknowledgedThroughSequence },
        null,
      );
    }
    if (envelope.operation === "USAGE_GET") {
      const ids: string[] = [];
      let afterObjectId: string | null = null;
      while (true) {
        const page = await this.config.objectStore.list(afterObjectId, 100);
        if (page.length === 0) break;
        for (const objectId of page) {
          if (!this.isInternalObjectId(objectId)) ids.push(objectId);
          if (ids.length > MAXIMUM_USAGE_OBJECTS)
            throw new ProviderError(503, "USAGE_LIMIT_EXCEEDED");
        }
        const nextObjectId = page.at(-1)!;
        if (nextObjectId === afterObjectId)
          throw new ProviderError(500, "OBJECT_STORE_PAGINATION_STALLED");
        afterObjectId = nextObjectId;
        if (page.length < 100) break;
      }
      let sizeBytes = 0;
      for (const objectId of ids)
        sizeBytes += (await this.config.objectStore.head(objectId)).sizeBytes;
      return this.respond(
        envelope,
        200,
        { objectCount: ids.length, sizeBytes },
        null,
      );
    }
    if (envelope.operation === "CHANGES_LIST") {
      const changesBody = json as { afterSequence: number; limit: number };
      const changes = this.changes
        .filter((change) => change.sequence > changesBody.afterSequence)
        .slice(0, changesBody.limit);
      return this.respond(envelope, 200, { changes }, null);
    }
    if (envelope.operation === "INVENTORY_LIST") {
      const inventoryBody = json as {
        afterProviderObjectId: string | null;
        limit: number;
      };
      const objectIds: string[] = [];
      let scanAfterObjectId = inventoryBody.afterProviderObjectId;
      while (objectIds.length < inventoryBody.limit) {
        const pageStartAfterObjectId = scanAfterObjectId;
        const page = await this.config.objectStore.list(
          scanAfterObjectId,
          100,
        );
        if (page.length === 0) break;
        for (const objectId of page) {
          scanAfterObjectId = objectId;
          if (!this.isInternalObjectId(objectId)) objectIds.push(objectId);
          if (objectIds.length === inventoryBody.limit) break;
        }
        if (objectIds.length === inventoryBody.limit) break;
        const nextObjectId = page.at(-1)!;
        if (nextObjectId === pageStartAfterObjectId)
          throw new ProviderError(500, "OBJECT_STORE_PAGINATION_STALLED");
        if (page.length < 100) break;
      }
      return this.respond(envelope, 200, { objectIds }, null);
    }
    if (envelope.operation === "RECONCILE") {
      const reconcileBody = json as { providerObjectIds: string[] };
      reconcileBody.providerObjectIds.forEach((objectId) =>
        this.assertDataObjectId(objectId),
      );
      const objects = await Promise.all(
        reconcileBody.providerObjectIds.map(async (objectId) => ({
          objectId,
          exists: await this.exists(objectId),
        })),
      );
      return this.respond(envelope, 200, { objects }, null);
    }
    if (envelope.operation === "MIGRATION_SOAK") {
      const completed = [...this.migrations.values()].filter(
        (migration) =>
          migration.soakUntil &&
          Date.parse(migration.soakUntil) <=
            (this.config.now ?? (() => new Date()))().getTime(),
      );
      if (this.changes.length + completed.length > MAXIMUM_OUTBOX_CHANGES)
        throw new ProviderError(503, "OUTBOX_BACKPRESSURE");
      const newProtectedSources = new Set(
        completed
          .map((migration) => migration.source)
          .filter((source) => !this.protectedMigrationSources.has(source)),
      );
      if (
        this.protectedMigrationSources.size + newProtectedSources.size >
        MAXIMUM_TRACKED_OBJECTS
      )
        throw new ProviderError(503, "MIGRATION_SOURCE_STATE_BACKPRESSURE");
      for (const migration of completed) {
        this.protectedMigrationSources.add(migration.source);
        this.migrations.delete(migration.target);
        this.record(
          "MIGRATION_SOAK_COMPLETED",
          migration.target,
          migration.version,
        );
      }
      return this.respond(envelope, 200, { migrations: completed }, null);
    }
    if (
      !id &&
      !["MIGRATION_COPY", "MIGRATION_VERIFY", "MIGRATION_SWITCH"].includes(
        envelope.operation,
      )
    )
      throw new ProviderError(400, "PROVIDER_OBJECT_ID_REQUIRED");
    if (id) this.assertDataObjectId(id);
    switch (envelope.operation) {
      case "OBJECT_PUT":
        return this.put(envelope, id!, body);
      case "OBJECT_GET":
        return this.get(envelope, id!);
      case "OBJECT_HEAD":
        return this.metadata(envelope, id!, false);
      case "OBJECT_CHECKSUM":
        return this.metadata(envelope, id!, true);
      case "OBJECT_ARCHIVE": {
        const value = await this.requireImmutableVersion(envelope, id!);
        if (this.archivedObjects.get(id!) === value.immutableProviderVersion)
          return this.respond(envelope, 200, { archived: true }, value);
        if (
          !this.archivedObjects.has(id!) &&
          this.archivedObjects.size >= MAXIMUM_TRACKED_OBJECTS
        )
          throw new ProviderError(503, "ARCHIVE_STATE_BACKPRESSURE");
        this.ensureOutboxCapacity();
        this.archivedObjects.set(id!, value.immutableProviderVersion);
        this.record("ARCHIVED", id!, value.immutableProviderVersion);
        return this.respond(envelope, 200, { archived: true }, value);
      }
      case "OBJECT_RESTORE": {
        const value = await this.requireImmutableVersion(envelope, id!);
        if (this.archivedObjects.get(id!) !== value.immutableProviderVersion)
          throw new ProviderError(409, "OBJECT_NOT_ARCHIVED");
        this.ensureOutboxCapacity();
        this.archivedObjects.delete(id!);
        this.record("RESTORED", id!, value.immutableProviderVersion);
        return this.respond(envelope, 200, { restored: true }, value);
      }
      case "OBJECT_DELETE":
        if (this.containment !== "NONE")
          throw new ProviderError(423, "DELETE_CONTAINED");
        await this.requireImmutableVersion(envelope, id!);
        if (this.isProtectedMigrationObject(id!))
          throw new ProviderError(409, "MIGRATION_DELETE_FORBIDDEN");
        this.ensureOutboxCapacity();
        await this.config.objectStore.delete(id!);
        this.committedPuts.delete(id!);
        this.archivedObjects.delete(id!);
        this.record("DELETED", id!, envelope.immutableProviderVersion);
        return this.respond(envelope, 204, undefined, null);
      case "MIGRATION_COPY":
        return this.migrationCopy(envelope, json!);
      case "MIGRATION_VERIFY":
        return this.migrationVerify(envelope, json!);
      case "MIGRATION_SWITCH":
        return this.migrationSwitch(envelope, json!);
      default:
        throw new ProviderError(400, "OPERATION_UNSUPPORTED");
    }
  }
  private async put(
    envelope: RequestEnvelope,
    id: string,
    body: Uint8Array,
  ): Promise<GatewayResponse> {
    if (this.failureMode === "BEFORE_OBJECT_WRITE")
      throw new ProviderError(503, "INJECTED_BEFORE_OBJECT_WRITE");
    const existing = await this.findObject(id);
    if (existing) {
      if (
        existing.contentSha256 !== sha256(body) ||
        (envelope.immutableProviderVersion !== null &&
          envelope.immutableProviderVersion !==
            existing.immutableProviderVersion)
      )
        throw new ProviderError(409, "OBJECT_VERSION_CONFLICT");
      if (this.committedPuts.get(id) !== existing.immutableProviderVersion) {
        this.ensureTrackedObjectCapacity(id);
        this.ensureOutboxCapacity();
        this.record("PUT", id, existing.immutableProviderVersion);
        this.committedPuts.set(id, existing.immutableProviderVersion);
      }
      return this.respond(envelope, 200, { providerObjectId: id }, existing);
    }
    this.ensureTrackedObjectCapacity(id);
    this.ensureOutboxCapacity();
    const value = await this.config.objectStore.put(id, body);
    if (this.failureMode === "AFTER_OBJECT_WRITE_BEFORE_COMMIT")
      throw new ProviderError(503, "INJECTED_AFTER_OBJECT_WRITE_BEFORE_COMMIT");
    this.record("PUT", id, value.immutableProviderVersion);
    this.committedPuts.set(id, value.immutableProviderVersion);
    return this.respond(envelope, 201, { providerObjectId: id }, value);
  }
  private async get(
    envelope: RequestEnvelope,
    id: string,
  ): Promise<GatewayResponse> {
    if (this.failureMode === "OBJECT_READ")
      throw new ProviderError(503, "INJECTED_OBJECT_READ");
    const value = await this.requireImmutableVersion(envelope, id);
    return this.respond(
      envelope,
      200,
      (await this.config.objectStore.get(id)).body,
      value,
    );
  }
  private async metadata(
    envelope: RequestEnvelope,
    id: string,
    checksum: boolean,
  ): Promise<GatewayResponse> {
    const value = await this.requireImmutableVersion(envelope, id);
    if (!checksum) return this.respond(envelope, 200, undefined, value);
    return this.respond(
      envelope,
      200,
      {
        contentSha256: value.contentSha256,
        immutableProviderVersion: value.immutableProviderVersion,
      },
      value,
    );
  }
  private async migrationCopy(
    envelope: RequestEnvelope,
    body: Record<string, unknown>,
  ): Promise<GatewayResponse> {
    const source = asProofId(body.sourceProviderObjectId);
    const target = asProofId(body.targetProviderObjectId);
    this.assertDataObjectId(source);
    this.assertDataObjectId(target);
    if (source === target)
      throw new ProviderError(400, "MIGRATION_IDS_MUST_DIFFER");
    if (this.migrations.has(target) || (await this.findObject(target)))
      throw new ProviderError(409, "MIGRATION_TARGET_EXISTS");
    if (this.migrations.size >= MAXIMUM_TRACKED_MIGRATIONS)
      throw new ProviderError(503, "MIGRATION_STATE_BACKPRESSURE");
    this.ensureOutboxCapacity();
    const sourceObject = await this.config.objectStore.head(source);
    if (
      sourceObject.immutableProviderVersion !==
      body.sourceImmutableProviderVersion
    )
      throw new ProviderError(409, "SOURCE_VERSION_MISMATCH");
    const targetObject = await this.config.objectStore.copy(source, target);
    this.migrations.set(target, {
      source,
      target,
      version: targetObject.immutableProviderVersion,
      verified: false,
    });
    this.record(
      "MIGRATION_COPIED",
      target,
      targetObject.immutableProviderVersion,
    );
    return this.respond(
      {
        ...envelope,
        providerObjectId: target,
        immutableProviderVersion: targetObject.immutableProviderVersion,
      },
      201,
      { targetProviderObjectId: target },
      targetObject,
    );
  }
  private async migrationVerify(
    envelope: RequestEnvelope,
    body: Record<string, unknown>,
  ): Promise<GatewayResponse> {
    const source = asProofId(body.sourceProviderObjectId);
    const target = asProofId(body.targetProviderObjectId);
    this.assertDataObjectId(source);
    this.assertDataObjectId(target);
    const [sourceObject, targetObject] = await Promise.all([
      this.config.objectStore.get(source),
      this.config.objectStore.get(target),
    ]);
    if (
      sourceObject.immutableProviderVersion !== body.immutableProviderVersion ||
      sourceObject.contentSha256 !== targetObject.contentSha256 ||
      sourceObject.sizeBytes !== targetObject.sizeBytes
    )
      throw new ProviderError(409, "MIGRATION_VERIFY_FAILED");
    const migration = this.migrations.get(target);
    if (
      !migration ||
      migration.source !== source ||
      migration.version !== body.immutableProviderVersion
    )
      throw new ProviderError(409, "MIGRATION_COPY_REQUIRED");
    this.ensureOutboxCapacity();
    migration.verified = true;
    this.record(
      "MIGRATION_VERIFIED",
      target,
      targetObject.immutableProviderVersion,
    );
    return this.respond(
      {
        ...envelope,
        providerObjectId: target,
        immutableProviderVersion: targetObject.immutableProviderVersion,
      },
      200,
      { verified: true },
      targetObject,
    );
  }
  private async migrationSwitch(
    envelope: RequestEnvelope,
    body: Record<string, unknown>,
  ): Promise<GatewayResponse> {
    const target = asProofId(body.targetProviderObjectId);
    this.assertDataObjectId(asProofId(body.sourceProviderObjectId));
    this.assertDataObjectId(target);
    const migration = this.migrations.get(target);
    if (
      !migration ||
      migration.source !== body.sourceProviderObjectId ||
      migration.version !== body.immutableProviderVersion ||
      !migration.verified
    )
      throw new ProviderError(409, "MIGRATION_NOT_VERIFIED");
    this.ensureOutboxCapacity();
    migration.soakUntil = asTimestamp(body.soakUntil);
    this.record("MIGRATION_SWITCHED", target, migration.version);
    return this.respond(
      {
        ...envelope,
        providerObjectId: target,
        immutableProviderVersion: migration.version,
      },
      200,
      { switched: true, sourcePreserved: true, soakUntil: migration.soakUntil },
      await this.config.objectStore.head(target),
    );
  }
  private async requireImmutableVersion(
    envelope: RequestEnvelope,
    objectId: string,
  ): Promise<StoredObject> {
    const value = await this.config.objectStore.head(objectId);
    if (envelope.immutableProviderVersion !== value.immutableProviderVersion)
      throw new ProviderError(409, "OBJECT_VERSION_CONFLICT");
    return value;
  }
  private async findObject(objectId: string): Promise<StoredObject | null> {
    try {
      return await this.config.objectStore.head(objectId);
    } catch (error) {
      if (error instanceof ProviderError && error.statusCode === 404)
        return null;
      throw error;
    }
  }
  private isProtectedMigrationObject(objectId: string): boolean {
    if (this.protectedMigrationSources.has(objectId)) return true;
    const now = (this.config.now ?? (() => new Date()))().getTime();
    return [...this.migrations.values()].some((migration) => {
      if (migration.source === objectId) return true;
      return (
        migration.target === objectId &&
        (!migration.soakUntil || Date.parse(migration.soakUntil) > now)
      );
    });
  }
  private applyLifecycle(body: Record<string, unknown>): void {
    const action = body.action;
    if (action === "SET_CONTAINMENT")
      this.containment = body.containmentState as typeof this.containment;
    else if (action === "RECOVER") this.containment = "NONE";
    else if (action === "SUSPEND" || action === "UNINSTALL")
      this.containment = "FULL_DISABLE_OR_QUARANTINE";
    else if (action !== "UPGRADE_AUTHORITY")
      throw new ProviderError(400, "INVALID_LIFECYCLE");
    this.record(`LIFECYCLE_${action}`, null, null);
  }
  private record(
    type: string,
    objectId: string | null,
    immutableProviderVersion: string | null,
  ): void {
    this.ensureOutboxCapacity();
    this.changes.push({
      sequence: ++this.sequence,
      type,
      objectId,
      immutableProviderVersion,
    });
  }
  private ensureOutboxCapacity(): void {
    if (this.changes.length >= MAXIMUM_OUTBOX_CHANGES)
      throw new ProviderError(503, "OUTBOX_BACKPRESSURE");
  }
  private ensureTrackedObjectCapacity(objectId: string): void {
    if (
      !this.committedPuts.has(objectId) &&
      this.committedPuts.size >= MAXIMUM_TRACKED_OBJECTS
    )
      throw new ProviderError(503, "OBJECT_STATE_BACKPRESSURE");
  }
  private async exists(objectId: string): Promise<boolean> {
    try {
      await this.config.objectStore.head(objectId);
      return true;
    } catch (error) {
      if (error instanceof ProviderError && error.statusCode === 404)
        return false;
      throw error;
    }
  }
  private assertDataObjectId(objectId: string): void {
    assertProofObjectId(objectId);
    if (this.isInternalObjectId(objectId))
      throw new ProviderError(403, "CONTROL_STATE_OBJECT_RESERVED");
  }
  private async initialize(): Promise<void> {
    this.initialization ??= this.loadState();
    await this.initialization;
  }
  private async serialize<T>(operation: () => Promise<T>): Promise<T> {
    const previous = this.serializedRequests;
    let release: (() => void) | undefined;
    this.serializedRequests = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await operation();
    } finally {
      release?.();
    }
  }
  private isMutatingOperation(operation: ProtocolOperation): boolean {
    return ![
      "HEALTH",
      "OUTBOX_LIST",
      "OBJECT_GET",
      "OBJECT_HEAD",
      "OBJECT_CHECKSUM",
      "INVENTORY_LIST",
      "USAGE_GET",
      "CHANGES_LIST",
      "RECONCILE",
    ].includes(operation);
  }
  private async loadState(): Promise<void> {
    try {
      const stored = await this.config.objectStore.get(
        this.controlStateObjectId,
      );
      const state = parseStrictJson(
        new TextDecoder("utf-8", { fatal: true }).decode(stored.body),
      );
      if (!state || Array.isArray(state) || typeof state !== "object")
        throw new Error("Invalid control state");
      const control = state as Record<string, unknown>;
      if (
        ![
          "NONE",
          "BLOCK_NEW_INSTALLS",
          "READ_ONLY",
          "FULL_DISABLE_OR_QUARANTINE",
        ].includes(control.containment as string) ||
        ![
          "NONE",
          "BEFORE_OBJECT_WRITE",
          "AFTER_OBJECT_WRITE_BEFORE_COMMIT",
          "OBJECT_READ",
        ].includes(control.failureMode as string) ||
        !positiveBoundedInteger(control.sequence, 0, Number.MAX_SAFE_INTEGER) ||
        !positiveBoundedInteger(
          control.acknowledgedThroughSequence,
          0,
          Number.MAX_SAFE_INTEGER,
        ) ||
        !Array.isArray(control.changes) ||
        !Array.isArray(control.migrations) ||
        !Array.isArray(control.committedPuts) ||
        !Array.isArray(control.archivedObjects) ||
        !Array.isArray(control.protectedMigrationSources) ||
        control.changes.length > MAXIMUM_OUTBOX_CHANGES ||
        control.migrations.length > MAXIMUM_TRACKED_MIGRATIONS ||
        control.committedPuts.length > MAXIMUM_TRACKED_OBJECTS ||
        control.archivedObjects.length > MAXIMUM_TRACKED_OBJECTS ||
        control.protectedMigrationSources.length > MAXIMUM_TRACKED_OBJECTS
      )
        throw new Error("Invalid control state");
      this.containment = control.containment as ContainmentState;
      this.failureMode = control.failureMode as FailureMode;
      this.sequence = control.sequence;
      this.acknowledgedThroughSequence = control.acknowledgedThroughSequence;
      this.changes.push(...(control.changes as Change[]));
      for (const migration of control.migrations as MigrationState[]) {
        if (
          !migration ||
          typeof migration.target !== "string" ||
          typeof migration.source !== "string" ||
          typeof migration.version !== "string" ||
          typeof migration.verified !== "boolean"
        )
          throw new Error("Invalid migration control state");
        this.migrations.set(migration.target, migration);
      }
      for (const entry of control.committedPuts as unknown[]) {
        if (
          !Array.isArray(entry) ||
          entry.length !== 2 ||
          typeof entry[0] !== "string" ||
          typeof entry[1] !== "string" ||
          !/^sha256:[a-f0-9]{64}$/.test(entry[1])
        )
          throw new Error("Invalid committed PUT control state");
        this.committedPuts.set(entry[0], entry[1]);
      }
      for (const entry of control.archivedObjects as unknown[]) {
        if (
          !Array.isArray(entry) ||
          entry.length !== 2 ||
          typeof entry[0] !== "string" ||
          typeof entry[1] !== "string" ||
          !/^sha256:[a-f0-9]{64}$/.test(entry[1])
        )
          throw new Error("Invalid archived-object control state");
        this.archivedObjects.set(entry[0], entry[1]);
      }
      for (const source of control.protectedMigrationSources as unknown[]) {
        if (typeof source !== "string")
          throw new Error("Invalid protected migration source control state");
        this.assertDataObjectId(source);
        this.protectedMigrationSources.add(source);
      }
    } catch (error) {
      if (!(error instanceof ProviderError && error.statusCode === 404))
        throw error;
    }
    await this.recoverStorageFence();
  }
  private async persistState(): Promise<void> {
    await this.config.objectStore.put(
      this.controlStateObjectId,
      this.stateBody(),
    );
  }
  private stateBody(
    state: MutableGatewayState = this.snapshotState(),
  ): Uint8Array {
    return Buffer.from(
      canonicalize({
        containment: state.containment,
        failureMode: state.failureMode,
        sequence: state.sequence,
        acknowledgedThroughSequence: state.acknowledgedThroughSequence,
        changes: state.changes,
        migrations: state.migrations,
        committedPuts: state.committedPuts,
        archivedObjects: state.archivedObjects,
        protectedMigrationSources: state.protectedMigrationSources,
      }),
    );
  }
  private async currentStateIsDurable(): Promise<boolean> {
    try {
      const stored = await this.config.objectStore.get(
        this.controlStateObjectId,
      );
      return Buffer.from(stored.body).equals(Buffer.from(this.stateBody()));
    } catch (error) {
      if (error instanceof ProviderError && error.statusCode === 404)
        return false;
      throw error;
    }
  }
  private async resolveAmbiguousControlState(): Promise<void> {
    const prior = this.ambiguousPriorState;
    const intended = this.ambiguousIntendedStateBody;
    if (!prior || !intended)
      throw new Error(
        "Ambiguous control state is missing its comparison snapshots",
      );
    let stored: Uint8Array | null = null;
    try {
      stored = (await this.config.objectStore.get(this.controlStateObjectId))
        .body;
    } catch (error) {
      if (!(error instanceof ProviderError && error.statusCode === 404))
        throw error;
    }
    if (stored && Buffer.from(stored).equals(Buffer.from(intended))) {
      // The state commit succeeded and only its response was lost.
    } else if (
      stored === null ||
      Buffer.from(stored).equals(Buffer.from(this.stateBody(prior)))
    ) {
      this.restoreState(prior);
    } else {
      throw new Error(
        "Durable control state matches neither side of the pending commit",
      );
    }
    this.ambiguousPriorState = null;
    this.ambiguousIntendedStateBody = null;
  }
  private get controlStateObjectId(): string {
    return this.config.controlStateObjectId ?? CONTROL_STATE_OBJECT_ID;
  }
  private get storageRollbackFenceObjectId(): string {
    return STORAGE_ROLLBACK_FENCE_OBJECT_ID;
  }
  private isInternalObjectId(objectId: string): boolean {
    return (
      objectId === this.controlStateObjectId ||
      objectId === this.storageRollbackFenceObjectId
    );
  }
  private assertEnvelopeFresh(envelope: RequestEnvelope): void {
    const now = (this.config.now ?? (() => new Date()))().getTime();
    if (
      now < Date.parse(envelope.issuedAt) ||
      now >= Date.parse(envelope.expiresAt)
    )
      throw new ProviderError(401, "ENVELOPE_EXPIRED");
  }
  private snapshotState(): MutableGatewayState {
    return {
      containment: this.containment,
      failureMode: this.failureMode,
      sequence: this.sequence,
      acknowledgedThroughSequence: this.acknowledgedThroughSequence,
      changes: this.changes.map((change) => ({ ...change })),
      migrations: [...this.migrations.values()].map((migration) => ({
        ...migration,
      })),
      committedPuts: [...this.committedPuts.entries()],
      archivedObjects: [...this.archivedObjects.entries()],
      protectedMigrationSources: [...this.protectedMigrationSources],
    };
  }
  private async snapshotStorageMutation(
    envelope: RequestEnvelope,
    body: Uint8Array,
  ): Promise<StorageMutationSnapshot | null> {
    let objectId: string | null = null;
    if (
      envelope.operation === "OBJECT_PUT" ||
      envelope.operation === "OBJECT_DELETE"
    ) {
      objectId = envelope.providerObjectId;
    } else if (envelope.operation === "MIGRATION_COPY") {
      const operationBody = parseOperationBody(envelope.operation, body);
      objectId = asProofId(operationBody.targetProviderObjectId);
    }
    if (!objectId) return null;
    this.assertDataObjectId(objectId);
    return {
      objectId,
      object: await this.findFullObject(objectId),
    };
  }
  private async rollbackMutation(
    snapshot: MutableGatewayState,
    storageSnapshot: StorageMutationSnapshot | null,
  ): Promise<void> {
    try {
      if (storageSnapshot) await this.restoreStorageMutation(storageSnapshot);
      this.restoreState(snapshot);
      await this.finishStorageFence(storageSnapshot);
    } catch {
      this.restoreState(snapshot);
      this.recoveryContainment = snapshot.containment;
      this.containment = "FULL_DISABLE_OR_QUARANTINE";
      this.storageRecoveryRequired = storageSnapshot !== null;
      throw new ProviderError(500, "STORAGE_ROLLBACK_FAILED");
    }
  }
  private async finishStorageFence(
    snapshot: StorageMutationSnapshot | null,
  ): Promise<void> {
    if (!snapshot) return;
    try {
      await this.clearStorageFence();
    } catch {
      this.storageRecoveryRequired = true;
    }
  }
  private async prepareStorageFence(
    snapshot: StorageMutationSnapshot,
    priorSequence: number,
  ): Promise<void> {
    const fence: StorageRollbackFence = {
      schemaVersion: "simply360.reference-file-provider-rollback/v1",
      priorSequence,
      objectId: snapshot.objectId,
      original: snapshot.object
        ? {
            bodyBase64Url: Buffer.from(snapshot.object.body).toString(
              "base64url",
            ),
            sizeBytes: snapshot.object.sizeBytes,
            contentSha256: snapshot.object.contentSha256,
            immutableProviderVersion: snapshot.object.immutableProviderVersion,
          }
        : null,
    };
    await this.config.objectStore.put(
      this.storageRollbackFenceObjectId,
      Buffer.from(canonicalize(fence)),
    );
  }
  private async clearStorageFence(): Promise<void> {
    await this.config.objectStore.delete(this.storageRollbackFenceObjectId);
    this.storageRecoveryRequired = false;
  }
  private async recoverStorageFence(): Promise<void> {
    let stored: StoredObject;
    try {
      stored = await this.config.objectStore.get(
        this.storageRollbackFenceObjectId,
      );
    } catch (error) {
      if (error instanceof ProviderError && error.statusCode === 404) {
        this.storageRecoveryRequired = false;
        return;
      }
      throw error;
    }
    const value = parseStrictJson(
      new TextDecoder("utf-8", { fatal: true }).decode(stored.body),
    );
    if (!value || Array.isArray(value) || typeof value !== "object")
      throw new Error("Invalid storage rollback fence");
    const fence = value as Record<string, unknown>;
    if (
      Object.keys(fence).sort().join(",") !==
        "objectId,original,priorSequence,schemaVersion" ||
      fence.schemaVersion !== "simply360.reference-file-provider-rollback/v1" ||
      !positiveBoundedInteger(
        fence.priorSequence,
        0,
        Number.MAX_SAFE_INTEGER,
      ) ||
      typeof fence.objectId !== "string"
    )
      throw new Error("Invalid storage rollback fence");
    this.assertDataObjectId(fence.objectId);
    let original: StoredObject | null = null;
    if (fence.original !== null) {
      if (
        !fence.original ||
        Array.isArray(fence.original) ||
        typeof fence.original !== "object"
      )
        throw new Error("Invalid storage rollback fence object");
      const originalValue = fence.original as Record<string, unknown>;
      if (
        Object.keys(originalValue).sort().join(",") !==
          "bodyBase64Url,contentSha256,immutableProviderVersion,sizeBytes" ||
        typeof originalValue.bodyBase64Url !== "string" ||
        originalValue.bodyBase64Url.length >
          Math.ceil((MAXIMUM_REQUEST_BYTES * 4) / 3) + 4 ||
        !/^[A-Za-z0-9_-]*$/.test(originalValue.bodyBase64Url) ||
        !positiveBoundedInteger(
          originalValue.sizeBytes,
          0,
          MAXIMUM_REQUEST_BYTES,
        ) ||
        typeof originalValue.contentSha256 !== "string" ||
        !/^[a-f0-9]{64}$/.test(originalValue.contentSha256) ||
        originalValue.immutableProviderVersion !==
          `sha256:${originalValue.contentSha256}`
      )
        throw new Error("Invalid storage rollback fence object");
      const body = Buffer.from(originalValue.bodyBase64Url, "base64url");
      if (
        body.toString("base64url") !== originalValue.bodyBase64Url ||
        body.length !== originalValue.sizeBytes ||
        sha256(body) !== originalValue.contentSha256
      )
        throw new Error("Invalid storage rollback fence body");
      original = objectFor(body);
    }
    if (this.sequence < fence.priorSequence)
      throw new Error("Storage rollback fence sequence is ahead of state");
    if (this.sequence === fence.priorSequence)
      await this.restoreStorageMutation({
        objectId: fence.objectId,
        object: original,
      });
    await this.clearStorageFence();
    if (this.recoveryContainment !== null) {
      this.containment = this.recoveryContainment;
      this.recoveryContainment = null;
    }
  }
  private async findFullObject(objectId: string): Promise<StoredObject | null> {
    try {
      const object = await this.config.objectStore.get(objectId);
      return { ...object, body: new Uint8Array(object.body) };
    } catch (error) {
      if (error instanceof ProviderError && error.statusCode === 404)
        return null;
      throw error;
    }
  }
  private async restoreStorageMutation(
    snapshot: StorageMutationSnapshot,
  ): Promise<void> {
    const current = await this.findObject(snapshot.objectId);
    if (!snapshot.object) {
      if (current) await this.config.objectStore.delete(snapshot.objectId);
      return;
    }
    if (
      current?.immutableProviderVersion ===
        snapshot.object.immutableProviderVersion &&
      current.contentSha256 === snapshot.object.contentSha256 &&
      current.sizeBytes === snapshot.object.sizeBytes
    )
      return;
    const restored = await this.config.objectStore.put(
      snapshot.objectId,
      snapshot.object.body,
    );
    if (
      restored.immutableProviderVersion !==
        snapshot.object.immutableProviderVersion ||
      restored.contentSha256 !== snapshot.object.contentSha256 ||
      restored.sizeBytes !== snapshot.object.sizeBytes
    )
      throw new ProviderError(500, "STORAGE_ROLLBACK_VERSION_MISMATCH");
  }
  private restoreState(snapshot: MutableGatewayState): void {
    this.containment = snapshot.containment;
    this.failureMode = snapshot.failureMode;
    this.sequence = snapshot.sequence;
    this.acknowledgedThroughSequence = snapshot.acknowledgedThroughSequence;
    this.changes.splice(
      0,
      this.changes.length,
      ...snapshot.changes.map((change) => ({ ...change })),
    );
    this.migrations.clear();
    for (const migration of snapshot.migrations)
      this.migrations.set(migration.target, { ...migration });
    this.committedPuts.clear();
    for (const [objectId, version] of snapshot.committedPuts)
      this.committedPuts.set(objectId, version);
    this.archivedObjects.clear();
    for (const [objectId, version] of snapshot.archivedObjects)
      this.archivedObjects.set(objectId, version);
    this.protectedMigrationSources.clear();
    for (const objectId of snapshot.protectedMigrationSources)
      this.protectedMigrationSources.add(objectId);
  }
  private respond(
    envelope: RequestEnvelope,
    statusCode: number,
    value: unknown,
    object: StoredObject | null,
  ): GatewayResponse {
    const body =
      value === undefined
        ? new Uint8Array()
        : value instanceof Uint8Array
          ? value
          : Buffer.from(canonicalize(value));
    const now = (this.config.now ?? (() => new Date()))();
    const responseEnvelope = assertResponseEnvelope({
      schemaVersion: "simply360.primary-file-provider-response/v1",
      protocolVersion: 1,
      keyPurpose: "PRIMARY_FILE_PROVIDER_RESPONSE_V1",
      direction: "PROVIDER_TO_SIMPLY360",
      requestSimplyId: envelope.requestSimplyId,
      statusCode,
      bodySha256: sha256(body),
      teamSimplyId: envelope.teamSimplyId,
      teamIntegrationSimplyId: envelope.teamIntegrationSimplyId,
      integrationAppVersionSimplyId: envelope.integrationAppVersionSimplyId,
      operation: envelope.operation,
      fileSimplyId: envelope.fileSimplyId,
      providerObjectId: envelope.providerObjectId,
      immutableProviderVersion:
        object?.immutableProviderVersion ?? envelope.immutableProviderVersion,
      routingTarget: envelope.routingTarget,
      authorityRevision: envelope.authorityRevision,
      sizeBytes: object?.sizeBytes ?? null,
      contentSha256: object?.contentSha256 ?? null,
      nonce: toBase64Url(randomBytes(24)),
      issuedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + 5 * 60_000).toISOString(),
    });
    const envelopeBytes = Buffer.from(canonicalize(responseEnvelope));
    const signature = sign(
      null,
      Buffer.concat([
        Buffer.from("simply360:primary-file-provider-response:v1\n"),
        envelopeBytes,
      ]),
      this.providerKey,
    );
    return {
      statusCode,
      headers: {
        "x-s360-envelope": toBase64Url(envelopeBytes),
        "x-s360-key-id": this.config.providerKeyId,
        "x-s360-signature": toBase64Url(signature),
        ...(body.length
          ? {
              "content-type":
                value instanceof Uint8Array
                  ? "application/octet-stream"
                  : "application/json",
            }
          : {}),
      },
      body,
    };
  }
  private unsignedError(error: unknown): GatewayResponse {
    const statusCode = error instanceof ProviderError ? error.statusCode : 500;
    const code = error instanceof ProviderError ? error.code : "INTERNAL_ERROR";
    return {
      statusCode,
      headers: { "content-type": "application/json" },
      body: Buffer.from(canonicalize({ code })),
    };
  }
}

export const createGateway = (
  config: GatewayConfig,
): PrimaryFileProviderGateway => new PrimaryFileProviderGateway(config);
/** Explicitly provisions only the disposable MinIO proof bucket before serving traffic. */
export const bootstrapGatewayStorage = async (
  config: GatewayConfig,
): Promise<void> => {
  if (config.objectStore instanceof MinioObjectStore)
    await config.objectStore.waitUntilReady();
};
export const startGateway = (
  config: GatewayConfig,
  port = Number(process.env.PORT ?? 8080),
): Server => {
  const instance = createGateway(config);
  const server = createServer(async (request, response) => {
    try {
      writeHttp(response, await instance.handle(await readHttp(request)));
    } catch (error) {
      const statusCode =
        error instanceof ProviderError ? error.statusCode : 500;
      writeHttp(response, {
        statusCode,
        headers: { "content-type": "application/json" },
        body: Buffer.from(
          canonicalize({
            code:
              error instanceof ProviderError ? error.code : "INTERNAL_ERROR",
          }),
        ),
      });
    }
  });
  server.listen(port);
  return server;
};
/** Explicit deployment configuration; no credentials have defaults or are logged. */
export const createGatewayFromEnvironment = (
  environment: NodeJS.ProcessEnv = process.env,
): GatewayConfig => ({
  platformKeyId: required(environment, "S360_PLATFORM_KEY_ID"),
  platformPublicKeyPem: required(
    environment,
    "S360_PLATFORM_PUBLIC_KEY_PEM",
  ).replace(/\\n/g, "\n"),
  providerKeyId: required(environment, "S360_PROVIDER_KEY_ID"),
  providerPrivateKeyPem: required(
    environment,
    "S360_PROVIDER_PRIVATE_KEY_PEM",
  ).replace(/\\n/g, "\n"),
  objectStore: new MinioObjectStore({
    endpoint: required(environment, "MINIO_ENDPOINT"),
    bucket: required(environment, "MINIO_BUCKET"),
    accessKey: required(environment, "MINIO_ACCESS_KEY"),
    secretKey: required(environment, "MINIO_SECRET_KEY"),
    region: environment.MINIO_REGION,
    requestTimeoutMs: environment.MINIO_REQUEST_TIMEOUT_MS
      ? Number(environment.MINIO_REQUEST_TIMEOUT_MS)
      : undefined,
  }),
});

class ProviderError extends Error {
  constructor(
    readonly statusCode: number,
    readonly code: string,
  ) {
    super(code);
  }
}
const sha256 = (body: Uint8Array | Buffer): string =>
  createHash("sha256").update(body).digest("hex");
const objectFor = (body: Uint8Array): StoredObject => ({
  body: Uint8Array.from(body),
  sizeBytes: body.length,
  contentSha256: sha256(body),
  immutableProviderVersion: `sha256:${sha256(body)}`,
});
const hmac = (key: string | Buffer, value: string): Buffer =>
  createHmac("sha256", key).update(value).digest();
const rfc3986 = (value: string): string =>
  encodeURIComponent(value).replace(
    /[!'()*]/g,
    (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`,
  );
const encodeS3Path = (objectId: string): string =>
  objectId.split("/").map(rfc3986).join("/");
const decodeXml = (value: string): string =>
  value
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");
const toBase64Url = (value: Uint8Array): string =>
  Buffer.from(value).toString("base64url");
const fromBase64Url = (value: string): Uint8Array => {
  if (
    value.length < 1 ||
    value.length > 22_000 ||
    value.length % 4 === 1 ||
    !/^[A-Za-z0-9_-]+$/.test(value)
  ) {
    throw new ProviderError(401, "INVALID_BASE64URL");
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.toString("base64url") !== value)
    throw new ProviderError(401, "INVALID_BASE64URL");
  return decoded;
};
const lowerHeaders = (
  headers: Readonly<Record<string, string | undefined>>,
): Record<string, string | undefined> =>
  Object.fromEntries(
    Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value]),
  );
const required = (environment: NodeJS.ProcessEnv, name: string): string => {
  const value = environment[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
};
const asTimestamp = (value: unknown): string => {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value) ||
    Number.isNaN(Date.parse(value))
  )
    throw new ProviderError(400, "INVALID_TIMESTAMP");
  return value;
};
const asProofId = (value: unknown): string => {
  if (typeof value !== "string")
    throw new ProviderError(400, "INVALID_OBJECT_ID");
  assertProofObjectId(value);
  return value;
};
const assertProofObjectId = (value: string): void => {
  if (!/^proof\.[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/.test(value))
    throw new ProviderError(403, "SYNTHETIC_PROOF_OBJECT_REQUIRED");
};

const parseOperationBody = (
  operation: ProtocolOperation,
  body: Uint8Array,
): Record<string, unknown> => {
  let value: unknown;
  try {
    value = parseStrictJson(
      new TextDecoder("utf-8", { fatal: true }).decode(body),
    );
  } catch {
    throw new ProviderError(400, "INVALID_OPERATION_BODY");
  }
  if (!value || Array.isArray(value) || typeof value !== "object")
    throw new ProviderError(400, "INVALID_OPERATION_BODY");
  const object = value as Record<string, unknown>;
  const expected: Partial<Record<ProtocolOperation, readonly string[]>> = {
    SETUP: ["action"],
    LIFECYCLE: ["action", "containmentState"],
    OUTBOX_ACK: ["throughSequence"],
    OBJECT_ARCHIVE: ["reason"],
    OBJECT_RESTORE: ["reason"],
    OBJECT_DELETE: ["deletionMode", "reason"],
    INVENTORY_LIST: ["afterProviderObjectId", "limit"],
    CHANGES_LIST: ["afterSequence", "limit"],
    RECONCILE: ["providerObjectIds"],
    MIGRATION_COPY: [
      "sourceProviderObjectId",
      "sourceImmutableProviderVersion",
      "targetProviderObjectId",
    ],
    MIGRATION_VERIFY: [
      "sourceProviderObjectId",
      "targetProviderObjectId",
      "immutableProviderVersion",
    ],
    MIGRATION_SWITCH: [
      "sourceProviderObjectId",
      "targetProviderObjectId",
      "immutableProviderVersion",
      "soakUntil",
    ],
    FAILURE_INJECT: ["mode"],
  };
  const keys = expected[operation];
  if (
    !keys ||
    Object.keys(object).length !== keys.length ||
    keys.some((key) => !(key in object))
  )
    throw new ProviderError(400, "INVALID_OPERATION_BODY");
  if (
    (operation === "SETUP" &&
      !["VALIDATE", "ACTIVATE"].includes(object.action as string)) ||
    (operation === "FAILURE_INJECT" &&
      ![
        "NONE",
        "BEFORE_OBJECT_WRITE",
        "AFTER_OBJECT_WRITE_BEFORE_COMMIT",
        "OBJECT_READ",
      ].includes(object.mode as string))
  )
    throw new ProviderError(400, "INVALID_OPERATION_BODY");
  if (operation === "LIFECYCLE") {
    const action = object.action;
    const state = object.containmentState;
    if (
      ![
        "SUSPEND",
        "UNINSTALL",
        "SET_CONTAINMENT",
        "RECOVER",
        "UPGRADE_AUTHORITY",
      ].includes(action as string) ||
      (action === "SET_CONTAINMENT" &&
        ![
          "BLOCK_NEW_INSTALLS",
          "READ_ONLY",
          "FULL_DISABLE_OR_QUARANTINE",
        ].includes(state as string)) ||
      (action !== "SET_CONTAINMENT" && state !== null)
    )
      throw new ProviderError(400, "INVALID_OPERATION_BODY");
  }
  if (
    ["OBJECT_ARCHIVE", "OBJECT_RESTORE", "OBJECT_DELETE"].includes(operation) &&
    (typeof object.reason !== "string" ||
      !object.reason.trim() ||
      object.reason.length > 200)
  )
    throw new ProviderError(400, "INVALID_OPERATION_BODY");
  if (operation === "OBJECT_DELETE" && object.deletionMode !== "PERMANENT")
    throw new ProviderError(400, "INVALID_OPERATION_BODY");
  if (
    operation === "INVENTORY_LIST" &&
    ((object.afterProviderObjectId !== null &&
      typeof object.afterProviderObjectId !== "string") ||
      !positiveBoundedInteger(object.limit, 1, 100))
  )
    throw new ProviderError(400, "INVALID_OPERATION_BODY");
  if (operation === "INVENTORY_LIST" && object.afterProviderObjectId !== null)
    asProofId(object.afterProviderObjectId);
  if (
    operation === "CHANGES_LIST" &&
    (!positiveBoundedInteger(
      object.afterSequence,
      0,
      Number.MAX_SAFE_INTEGER,
    ) ||
      !positiveBoundedInteger(object.limit, 1, 100))
  )
    throw new ProviderError(400, "INVALID_OPERATION_BODY");
  if (
    operation === "OUTBOX_ACK" &&
    !positiveBoundedInteger(object.throughSequence, 0, Number.MAX_SAFE_INTEGER)
  )
    throw new ProviderError(400, "INVALID_OPERATION_BODY");
  if (
    operation === "RECONCILE" &&
    (!Array.isArray(object.providerObjectIds) ||
      object.providerObjectIds.length < 1 ||
      object.providerObjectIds.length > 100 ||
      new Set(object.providerObjectIds).size !==
        object.providerObjectIds.length ||
      object.providerObjectIds.some((id) => typeof id !== "string"))
  )
    throw new ProviderError(400, "INVALID_OPERATION_BODY");
  if (operation === "RECONCILE")
    (object.providerObjectIds as unknown[]).forEach(asProofId);
  if (operation.startsWith("MIGRATION_")) {
    asProofId(object.sourceProviderObjectId);
    asProofId(object.targetProviderObjectId);
    if (object.sourceProviderObjectId === object.targetProviderObjectId)
      throw new ProviderError(400, "INVALID_OPERATION_BODY");
    if (
      operation === "MIGRATION_COPY" &&
      (typeof object.sourceImmutableProviderVersion !== "string" ||
        !/^sha256:[a-f0-9]{64}$/.test(object.sourceImmutableProviderVersion))
    )
      throw new ProviderError(400, "INVALID_OPERATION_BODY");
    if (
      operation !== "MIGRATION_COPY" &&
      (typeof object.immutableProviderVersion !== "string" ||
        !/^sha256:[a-f0-9]{64}$/.test(object.immutableProviderVersion))
    )
      throw new ProviderError(400, "INVALID_OPERATION_BODY");
    if (operation === "MIGRATION_SWITCH") asTimestamp(object.soakUntil);
  }
  return object;
};
const positiveBoundedInteger = (
  value: unknown,
  min: number,
  max: number,
): value is number =>
  typeof value === "number" &&
  Number.isSafeInteger(value) &&
  value >= min &&
  value <= max;

const requestKeys = [
  "schemaVersion",
  "protocolVersion",
  "keyPurpose",
  "direction",
  "requestSimplyId",
  "method",
  "normalizedPath",
  "bodySha256",
  "teamSimplyId",
  "teamIntegrationSimplyId",
  "integrationAppVersionSimplyId",
  "operation",
  "fileSimplyId",
  "providerObjectId",
  "immutableProviderVersion",
  "routingTarget",
  "authorityRevision",
  "idempotencyKey",
  "nonce",
  "issuedAt",
  "expiresAt",
] as const;
const assertRequestEnvelope = (value: unknown): RequestEnvelope => {
  if (!value || Array.isArray(value) || typeof value !== "object")
    throw new ProviderError(401, "ENVELOPE_INVALID");
  const envelope = value as Record<string, unknown>;
  if (
    Object.keys(envelope).length !== requestKeys.length ||
    requestKeys.some((key) => !(key in envelope)) ||
    envelope.schemaVersion !== "simply360.primary-file-provider-request/v1" ||
    envelope.protocolVersion !== 1 ||
    envelope.keyPurpose !== "PRIMARY_FILE_PROVIDER_REQUEST_V1" ||
    envelope.direction !== "SIMPLY360_TO_PROVIDER" ||
    !["GET", "HEAD", "PUT", "POST", "DELETE"].includes(
      envelope.method as string,
    ) ||
    typeof envelope.normalizedPath !== "string" ||
    !/^\/v1\/primary-file-provider(?:\/[A-Za-z0-9._~-]+)*$/.test(
      envelope.normalizedPath,
    ) ||
    !PROTOCOL_OPERATIONS.includes(envelope.operation as ProtocolOperation) ||
    !["PRIMARY", "MIGRATION_SOURCE", "MIGRATION_TARGET", "QUARANTINE"].includes(
      envelope.routingTarget as string,
    ) ||
    !positiveBoundedInteger(
      envelope.authorityRevision,
      1,
      Number.MAX_SAFE_INTEGER,
    ) ||
    !isSha256(envelope.bodySha256) ||
    !isNullableObjectId(envelope.providerObjectId) ||
    !isNullableVersion(envelope.immutableProviderVersion) ||
    !isNullableSimplyId(envelope.fileSimplyId) ||
    !isSimplyId(envelope.requestSimplyId) ||
    !isSimplyId(envelope.teamSimplyId) ||
    !isSimplyId(envelope.teamIntegrationSimplyId) ||
    !isSimplyId(envelope.integrationAppVersionSimplyId) ||
    typeof envelope.idempotencyKey !== "string" ||
    !/^[\x21-\x7e]{1,128}$/.test(envelope.idempotencyKey) ||
    typeof envelope.nonce !== "string" ||
    !/^[A-Za-z0-9_-]{22,128}$/.test(envelope.nonce) ||
    !validWindow(envelope.issuedAt, envelope.expiresAt)
  )
    throw new ProviderError(401, "ENVELOPE_INVALID");
  return envelope as unknown as RequestEnvelope;
};
const responseKeys = [
  "schemaVersion",
  "protocolVersion",
  "keyPurpose",
  "direction",
  "requestSimplyId",
  "statusCode",
  "bodySha256",
  "teamSimplyId",
  "teamIntegrationSimplyId",
  "integrationAppVersionSimplyId",
  "operation",
  "fileSimplyId",
  "providerObjectId",
  "immutableProviderVersion",
  "routingTarget",
  "authorityRevision",
  "sizeBytes",
  "contentSha256",
  "nonce",
  "issuedAt",
  "expiresAt",
] as const;
const assertResponseEnvelope = (value: unknown): Record<string, unknown> => {
  if (!value || Array.isArray(value) || typeof value !== "object")
    throw new Error("Response envelope is not an object");
  const envelope = value as Record<string, unknown>;
  if (
    Object.keys(envelope).length !== responseKeys.length ||
    responseKeys.some((key) => !(key in envelope)) ||
    envelope.schemaVersion !== "simply360.primary-file-provider-response/v1" ||
    envelope.protocolVersion !== 1 ||
    envelope.keyPurpose !== "PRIMARY_FILE_PROVIDER_RESPONSE_V1" ||
    envelope.direction !== "PROVIDER_TO_SIMPLY360" ||
    !positiveBoundedInteger(envelope.statusCode, 100, 599) ||
    !isSha256(envelope.bodySha256) ||
    !isSimplyId(envelope.requestSimplyId) ||
    !isSimplyId(envelope.teamSimplyId) ||
    !isSimplyId(envelope.teamIntegrationSimplyId) ||
    !isSimplyId(envelope.integrationAppVersionSimplyId) ||
    !PROTOCOL_OPERATIONS.includes(envelope.operation as ProtocolOperation) ||
    !isNullableSimplyId(envelope.fileSimplyId) ||
    !isNullableObjectId(envelope.providerObjectId) ||
    !isNullableVersion(envelope.immutableProviderVersion) ||
    !["PRIMARY", "MIGRATION_SOURCE", "MIGRATION_TARGET", "QUARANTINE"].includes(
      envelope.routingTarget as string,
    ) ||
    !positiveBoundedInteger(
      envelope.authorityRevision,
      1,
      Number.MAX_SAFE_INTEGER,
    ) ||
    !isNullableNonnegativeInteger(envelope.sizeBytes) ||
    (envelope.contentSha256 !== null && !isSha256(envelope.contentSha256)) ||
    (envelope.sizeBytes === null) !== (envelope.contentSha256 === null) ||
    typeof envelope.nonce !== "string" ||
    !/^[A-Za-z0-9_-]{22,128}$/.test(envelope.nonce) ||
    !validWindow(envelope.issuedAt, envelope.expiresAt)
  )
    throw new Error("Response envelope does not satisfy the closed v1 schema");
  return envelope;
};
/** The public contract permits only canonical uppercase 4-4-4 Simply IDs. */
const isSimplyId = (value: unknown): value is string =>
  typeof value === "string" &&
  /^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(value);
const isNullableSimplyId = (value: unknown): boolean =>
  value === null || isSimplyId(value);
const isSha256 = (value: unknown): value is string =>
  typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
const isNullableObjectId = (value: unknown): boolean =>
  value === null ||
  (typeof value === "string" &&
    /^[A-Za-z0-9][A-Za-z0-9._~:/=-]{0,255}$/.test(value));
const isNullableVersion = (value: unknown): boolean =>
  value === null ||
  (typeof value === "string" && /^sha256:[a-f0-9]{64}$/.test(value));
const isNullableNonnegativeInteger = (value: unknown): boolean =>
  value === null || positiveBoundedInteger(value, 0, Number.MAX_SAFE_INTEGER);
const validWindow = (issuedAt: unknown, expiresAt: unknown): boolean => {
  try {
    const issued = asTimestamp(issuedAt);
    const expires = asTimestamp(expiresAt);
    return (
      Date.parse(expires) > Date.parse(issued) &&
      Date.parse(expires) - Date.parse(issued) <= 300_000
    );
  } catch {
    return false;
  }
};

/** Strict JSON parser: rejects duplicate keys and non-JSON values before canonical comparison. */
const parseStrictJson = (text: string): unknown => {
  if (text.charCodeAt(0) === 0xfeff) throw new Error("BOM");
  let cursor = 0;
  const ws = () => {
    while (/\s/.test(text[cursor] ?? "")) cursor++;
  };
  const value = (): unknown => {
    ws();
    const first = text[cursor];
    if (first === '"') return string();
    if (first === "{") return object();
    if (first === "[") return array();
    if (text.startsWith("true", cursor)) {
      cursor += 4;
      return true;
    }
    if (text.startsWith("false", cursor)) {
      cursor += 5;
      return false;
    }
    if (text.startsWith("null", cursor)) {
      cursor += 4;
      return null;
    }
    const match = text
      .slice(cursor)
      .match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/);
    if (!match) throw new Error("value");
    cursor += match[0].length;
    const number = Number(match[0]);
    if (!Number.isFinite(number)) throw new Error("number");
    return number;
  };
  const string = (): string => {
    const start = cursor++;
    let escaped = false;
    while (cursor < text.length) {
      const character = text[cursor++]!;
      if (character === '"' && !escaped) {
        const raw = text.slice(start, cursor);
        return JSON.parse(raw) as string;
      }
      if (character < " ") throw new Error("control");
      if (character === "\\" && !escaped) escaped = true;
      else escaped = false;
    }
    throw new Error("string");
  };
  const object = (): Record<string, unknown> => {
    cursor++;
    ws();
    const result: Record<string, unknown> = {};
    if (text[cursor] === "}") {
      cursor++;
      return result;
    }
    while (true) {
      ws();
      if (text[cursor] !== '"') throw new Error("key");
      const key = string();
      if (Object.prototype.hasOwnProperty.call(result, key))
        throw new Error("duplicate");
      ws();
      if (text[cursor++] !== ":") throw new Error("colon");
      result[key] = value();
      ws();
      const separator = text[cursor++];
      if (separator === "}") return result;
      if (separator !== ",") throw new Error("separator");
    }
  };
  const array = (): unknown[] => {
    cursor++;
    ws();
    const result: unknown[] = [];
    if (text[cursor] === "]") {
      cursor++;
      return result;
    }
    while (true) {
      result.push(value());
      ws();
      const separator = text[cursor++];
      if (separator === "]") return result;
      if (separator !== ",") throw new Error("separator");
    }
  };
  const result = value();
  ws();
  if (cursor !== text.length) throw new Error("trailing");
  return result;
};
const canonicalize = (value: unknown): string => {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "number" ||
    typeof value === "string"
  )
    return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (typeof value === "object")
    return `{${Object.keys(value as Record<string, unknown>)
      .sort()
      .map(
        (key) =>
          `${JSON.stringify(key)}:${canonicalize((value as Record<string, unknown>)[key])}`,
      )
      .join(",")}}`;
  throw new Error("Unsupported JSON value");
};
/** Self-contained public-contract compatibility helpers; replace with the published SDK once available. */
export const canonicalizePrimaryFileProviderRequestEnvelope = (
  value: unknown,
): string => canonicalize(assertRequestEnvelope(value));
export const canonicalizePrimaryFileProviderResponseEnvelope = (
  value: unknown,
): string => canonicalize(assertResponseEnvelope(value));
export const parseCanonicalPrimaryFileProviderRequestEnvelope = (
  input: string | Uint8Array,
): RequestEnvelope => {
  const text =
    typeof input === "string"
      ? input
      : new TextDecoder("utf-8", { fatal: true }).decode(input);
  const value = assertRequestEnvelope(parseStrictJson(text));
  if (canonicalize(value) !== text)
    throw new ProviderError(401, "ENVELOPE_NOT_CANONICAL");
  return value;
};
export const parseCanonicalPrimaryFileProviderResponseEnvelope = (
  input: string | Uint8Array,
): Record<string, unknown> => {
  const text =
    typeof input === "string"
      ? input
      : new TextDecoder("utf-8", { fatal: true }).decode(input);
  const value = assertResponseEnvelope(parseStrictJson(text));
  if (canonicalize(value) !== text)
    throw new ProviderError(401, "ENVELOPE_NOT_CANONICAL");
  return value;
};
export const primaryFileProviderRequestSigningPayloadSha256Hex = (
  value: unknown,
): string =>
  sha256(
    Buffer.from(
      `simply360:primary-file-provider-request:v1\n${canonicalizePrimaryFileProviderRequestEnvelope(value)}`,
    ),
  );
export const primaryFileProviderResponseSigningPayloadSha256Hex = (
  value: unknown,
): string =>
  sha256(
    Buffer.from(
      `simply360:primary-file-provider-response:v1\n${canonicalizePrimaryFileProviderResponseEnvelope(value)}`,
    ),
  );
const readHttp = async (request: IncomingMessage): Promise<GatewayRequest> => {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += bytes.length;
    if (size > MAXIMUM_REQUEST_BYTES)
      throw new ProviderError(413, "REQUEST_TOO_LARGE");
    chunks.push(bytes);
  }
  return {
    method: request.method ?? "",
    path: new URL(request.url ?? "/", "http://gateway").pathname,
    headers: Object.fromEntries(
      Object.entries(request.headers).map(([key, value]) => [
        key,
        Array.isArray(value) ? value[0] : value,
      ]),
    ),
    body: Buffer.concat(chunks),
  };
};
const writeHttp = (response: ServerResponse, result: GatewayResponse): void => {
  response.writeHead(result.statusCode, result.headers);
  response.end(result.body);
};

if (process.argv[1] && new URL(import.meta.url).pathname === process.argv[1]) {
  const config = createGatewayFromEnvironment();
  await bootstrapGatewayStorage(config);
  startGateway(config);
}
