import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign, verify } from "node:crypto";
import { test } from "node:test";

import {
  MemoryObjectStore,
  canonicalizePrimaryFileProviderRequestEnvelope,
  canonicalizePrimaryFileProviderResponseEnvelope,
  createGateway,
  describeGateway,
  parseCanonicalPrimaryFileProviderRequestEnvelope,
  parseCanonicalPrimaryFileProviderResponseEnvelope,
  primaryFileProviderRequestSigningPayloadSha256Hex,
  primaryFileProviderResponseSigningPayloadSha256Hex,
  startGateway,
} from "../dist/index.js";

const REQUEST_DOMAIN = "simply360:primary-file-provider-request:v1\n";
const RESPONSE_DOMAIN = "simply360:primary-file-provider-response:v1\n";
const routes = {
  HEALTH: ["GET", "/v1/primary-file-provider/health"],
  SETUP: ["POST", "/v1/primary-file-provider/setup"],
  LIFECYCLE: ["POST", "/v1/primary-file-provider/lifecycle"],
  OUTBOX_LIST: ["GET", "/v1/primary-file-provider/events"],
  OUTBOX_ACK: ["POST", "/v1/primary-file-provider/events/ack"],
  OBJECT_PUT: ["PUT", "/v1/primary-file-provider/objects"],
  OBJECT_GET: ["GET", "/v1/primary-file-provider/objects/content"],
  OBJECT_HEAD: ["HEAD", "/v1/primary-file-provider/objects"],
  OBJECT_CHECKSUM: ["GET", "/v1/primary-file-provider/objects/checksum"],
  OBJECT_ARCHIVE: ["POST", "/v1/primary-file-provider/objects/archive"],
  OBJECT_RESTORE: ["POST", "/v1/primary-file-provider/objects/restore"],
  OBJECT_DELETE: ["DELETE", "/v1/primary-file-provider/objects"],
  INVENTORY_LIST: ["POST", "/v1/primary-file-provider/inventory"],
  USAGE_GET: ["GET", "/v1/primary-file-provider/usage"],
  MIGRATION_COPY: ["POST", "/v1/primary-file-provider/migration/copy"],
  MIGRATION_VERIFY: ["POST", "/v1/primary-file-provider/migration/verify"],
  MIGRATION_SWITCH: ["POST", "/v1/primary-file-provider/migration/switch"],
  MIGRATION_SOAK: ["POST", "/v1/primary-file-provider/migration/soak"],
  FAILURE_INJECT: ["POST", "/v1/primary-file-provider/dev/failure"],
};
const canonical = (value) =>
  value === null || typeof value !== "object"
    ? JSON.stringify(value)
    : Array.isArray(value)
      ? `[${value.map(canonical).join(",")}]`
      : `{${Object.keys(value)
          .sort()
          .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
          .join(",")}}`;
const digest = (body) => createHash("sha256").update(body).digest("hex");
const goldenRequest = {
  schemaVersion: "simply360.primary-file-provider-request/v1",
  protocolVersion: 1,
  keyPurpose: "PRIMARY_FILE_PROVIDER_REQUEST_V1",
  direction: "SIMPLY360_TO_PROVIDER",
  requestSimplyId: "RQST-0000-0001",
  method: "GET",
  normalizedPath: "/v1/primary-file-provider/health",
  bodySha256:
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  teamSimplyId: "TEAM-0000-0001",
  teamIntegrationSimplyId: "TINT-0000-0001",
  integrationAppVersionSimplyId: "IAVR-0000-0001",
  operation: "HEALTH",
  fileSimplyId: null,
  providerObjectId: null,
  immutableProviderVersion: null,
  routingTarget: "PRIMARY",
  authorityRevision: 1,
  idempotencyKey: "contract-vector-health",
  nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  issuedAt: "2026-07-28T20:00:00.000Z",
  expiresAt: "2026-07-28T20:02:00.000Z",
};
const goldenResponse = {
  schemaVersion: "simply360.primary-file-provider-response/v1",
  protocolVersion: 1,
  keyPurpose: "PRIMARY_FILE_PROVIDER_RESPONSE_V1",
  direction: "PROVIDER_TO_SIMPLY360",
  requestSimplyId: "RQST-0000-0001",
  statusCode: 200,
  bodySha256:
    "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
  teamSimplyId: "TEAM-0000-0001",
  teamIntegrationSimplyId: "TINT-0000-0001",
  integrationAppVersionSimplyId: "IAVR-0000-0001",
  operation: "HEALTH",
  fileSimplyId: null,
  providerObjectId: null,
  immutableProviderVersion: null,
  routingTarget: "PRIMARY",
  authorityRevision: 1,
  sizeBytes: null,
  contentSha256: null,
  nonce: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
  issuedAt: "2026-07-28T20:00:01.000Z",
  expiresAt: "2026-07-28T20:02:01.000Z",
};

test("matches canonical SDK golden request and response vectors byte-for-byte", () => {
  const requestJson =
    canonicalizePrimaryFileProviderRequestEnvelope(goldenRequest);
  const responseJson =
    canonicalizePrimaryFileProviderResponseEnvelope(goldenResponse);
  assert.deepEqual(
    parseCanonicalPrimaryFileProviderRequestEnvelope(requestJson),
    goldenRequest,
  );
  assert.deepEqual(
    parseCanonicalPrimaryFileProviderResponseEnvelope(responseJson),
    goldenResponse,
  );
  assert.equal(
    primaryFileProviderRequestSigningPayloadSha256Hex(goldenRequest),
    "a4206fb0b90d614a0e9b8a5ae26bb077bb31308dcda14af644cbb52cca6cf385",
  );
  assert.equal(
    primaryFileProviderResponseSigningPayloadSha256Hex(goldenResponse),
    "29f5a533303e5426e063374c89b006d0f5c6e0977209103ff86b4c7f3f7a1122",
  );
});

test("canonical parsers reject duplicate keys, noncanonical JSON, and closed-schema drift", () => {
  const canonicalRequest =
    canonicalizePrimaryFileProviderRequestEnvelope(goldenRequest);
  const duplicateKey = canonicalRequest.replace(
    '"authorityRevision":1',
    '"authorityRevision":1,"authorityRevision":1',
  );

  assert.throws(() =>
    parseCanonicalPrimaryFileProviderRequestEnvelope(duplicateKey),
  );
  assert.throws(() =>
    parseCanonicalPrimaryFileProviderRequestEnvelope(` ${canonicalRequest}`),
  );
  assert.throws(() =>
    canonicalizePrimaryFileProviderRequestEnvelope({
      ...goldenRequest,
      internalTeamId: 7,
    }),
  );
  assert.throws(() =>
    canonicalizePrimaryFileProviderResponseEnvelope({
      ...goldenResponse,
      sizeBytes: 10,
      contentSha256: null,
    }),
  );
});

function fixture(objectStore = new MemoryObjectStore()) {
  const platform = generateKeyPairSync("ed25519");
  const provider = generateKeyPairSync("ed25519");
  let now = new Date("2026-08-01T12:00:00.000Z");
  const config = {
    platformKeyId: "platform-test-key",
    platformPublicKeyPem: platform.publicKey.export({
      type: "spki",
      format: "pem",
    }),
    providerKeyId: "provider-test-key",
    providerPrivateKeyPem: provider.privateKey.export({
      type: "pkcs8",
      format: "pem",
    }),
    objectStore,
    now: () => now,
  };
  const gateway = createGateway(config);
  const request = async (
    operation,
    body = new Uint8Array(),
    overrides = {},
    targetGateway = gateway,
  ) => {
    const [method, path] = routes[operation];
    const requestBody =
      body === undefined
        ? Buffer.alloc(0)
        : typeof body === "string"
          ? Buffer.from(body)
          : Buffer.from(body);
    const envelope = {
      schemaVersion: "simply360.primary-file-provider-request/v1",
      protocolVersion: 1,
      keyPurpose: "PRIMARY_FILE_PROVIDER_REQUEST_V1",
      direction: "SIMPLY360_TO_PROVIDER",
      requestSimplyId: "RQST-0000-0001",
      method,
      normalizedPath: path,
      bodySha256: digest(requestBody),
      teamSimplyId: "TEAM-0000-0001",
      teamIntegrationSimplyId: "TINT-0000-0001",
      integrationAppVersionSimplyId: "IAVR-0000-0001",
      operation,
      fileSimplyId: null,
      providerObjectId: null,
      immutableProviderVersion: null,
      routingTarget: "PRIMARY",
      authorityRevision: 1,
      idempotencyKey: `proof-${operation}`,
      nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      issuedAt: "2026-08-01T11:59:00.000Z",
      expiresAt: "2026-08-01T12:04:00.000Z",
      ...overrides,
    };
    const envelopeBytes = Buffer.from(canonical(envelope));
    const signature = sign(
      null,
      Buffer.concat([Buffer.from(REQUEST_DOMAIN), envelopeBytes]),
      platform.privateKey,
    ).toString("base64url");
    const result = await targetGateway.handle({
      method,
      path,
      headers: {
        "x-s360-envelope": envelopeBytes.toString("base64url"),
        "x-s360-key-id": "platform-test-key",
        "x-s360-signature": signature,
      },
      body: requestBody,
    });
    return {
      result,
      envelope,
      wireRequest: {
        method,
        path,
        body: requestBody,
        headers: {
          "x-s360-envelope": envelopeBytes.toString("base64url"),
          "x-s360-key-id": "platform-test-key",
          "x-s360-signature": signature,
        },
      },
    };
  };
  const verifyResponse = (result) => {
    const envelopeBytes = Buffer.from(
      result.headers["x-s360-envelope"],
      "base64url",
    );
    const signature = Buffer.from(
      result.headers["x-s360-signature"],
      "base64url",
    );
    assert.equal(result.headers["x-s360-key-id"], "provider-test-key");
    assert.equal(
      verify(
        null,
        Buffer.concat([Buffer.from(RESPONSE_DOMAIN), envelopeBytes]),
        provider.publicKey,
        signature,
      ),
      true,
    );
    const envelope = JSON.parse(envelopeBytes.toString("utf8"));
    assert.equal(envelope.bodySha256, digest(result.body));
    assert.equal(envelope.statusCode, result.statusCode);
    return envelope;
  };
  return {
    config,
    gateway,
    request,
    setNow: (value) => {
      now = new Date(value);
    },
    verifyResponse,
  };
}

class FailingControlStateStore extends MemoryObjectStore {
  failNextControlWrite = false;
  async put(objectId, body) {
    if (objectId === "proof.gateway-control-v1" && this.failNextControlWrite) {
      this.failNextControlWrite = false;
      throw new Error("injected control-state persistence failure");
    }
    return super.put(objectId, body);
  }
}

class FailingCompensationStore extends FailingControlStateStore {
  failNextDataWriteFor = null;
  async put(objectId, body) {
    if (objectId === this.failNextDataWriteFor) {
      this.failNextDataWriteFor = null;
      throw new Error("injected data compensation failure");
    }
    return super.put(objectId, body);
  }
}

class AmbiguousControlStateStore extends MemoryObjectStore {
  storeThenThrowNextControlWrite = false;
  async put(objectId, body) {
    const stored = await super.put(objectId, body);
    if (
      objectId === "proof.gateway-control-v1" &&
      this.storeThenThrowNextControlWrite
    ) {
      this.storeThenThrowNextControlWrite = false;
      throw new Error("injected lost control-state PUT response");
    }
    return stored;
  }
}

class BlockingInitializationStore extends MemoryObjectStore {
  #release;
  #started;
  #startedPromise;
  #releasePromise;
  constructor() {
    super();
    this.#startedPromise = new Promise((resolve) => {
      this.#started = resolve;
    });
    this.#releasePromise = new Promise((resolve) => {
      this.#release = resolve;
    });
  }
  async get(objectId) {
    if (objectId === "proof.gateway-control-v1") {
      this.#started();
      await this.#releasePromise;
    }
    return super.get(objectId);
  }
  async waitUntilBlocked() {
    await this.#startedPromise;
  }
  release() {
    this.#release();
  }
}

test("gateway descriptor declares only the public API origin and MinIO backend", () => {
  const info = describeGateway();
  assert.equal(info.backend, "minio");
  assert.equal(info.publicOrigin, "api-gateway-http-api");
  assert.equal(info.syntheticProofObjectsOnly, true);
});

test("HTTP HEAD sends no wire body and signs the empty body hash", async () => {
  const { config, request } = fixture();
  const body = Buffer.from("head proof");
  const version = `sha256:${digest(body)}`;
  await request("OBJECT_PUT", body, { providerObjectId: "proof.http-head" });
  const signedHead = await request("OBJECT_HEAD", undefined, {
    providerObjectId: "proof.http-head",
    immutableProviderVersion: version,
  });
  const server = startGateway(config, 0);
  await new Promise((resolve) => server.once("listening", resolve));
  try {
    const address = server.address();
    assert.ok(address && typeof address === "object");
    const response = await fetch(
      `http://127.0.0.1:${address.port}${signedHead.wireRequest.path}`,
      {
        method: "HEAD",
        headers: signedHead.wireRequest.headers,
      },
    );
    const wireBody = new Uint8Array(await response.arrayBuffer());
    assert.equal(response.status, 200);
    assert.equal(wireBody.length, 0);
    const envelope = JSON.parse(
      Buffer.from(
        response.headers.get("x-s360-envelope"),
        "base64url",
      ).toString("utf8"),
    );
    assert.equal(envelope.bodySha256, digest(wireBody));
    assert.equal(envelope.sizeBytes, body.length);
    assert.equal(envelope.contentSha256, digest(body));
  } finally {
    await new Promise((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  }
});

test("control state survives a gateway reconstruction over the same object store", async () => {
  const { config, request } = fixture();
  await request(
    "LIFECYCLE",
    JSON.stringify({
      action: "SET_CONTAINMENT",
      containmentState: "READ_ONLY",
    }),
  );
  const blocked = await request("OBJECT_PUT", Buffer.from("blocked"), {
    providerObjectId: "proof.restart-blocked",
  });
  const replacement = createGateway(config);
  const result = await replacement.handle({
    method: blocked.wireRequest.method,
    path: blocked.wireRequest.path,
    headers: blocked.wireRequest.headers,
    body: blocked.wireRequest.body,
  });
  assert.equal(result.statusCode, 423);
});

test("a failed control-state write rolls back containment before serving the next request", async () => {
  const store = new FailingControlStateStore();
  const { request } = fixture(store);
  let call = await request(
    "LIFECYCLE",
    JSON.stringify({
      action: "SET_CONTAINMENT",
      containmentState: "READ_ONLY",
    }),
  );
  assert.equal(call.result.statusCode, 200);

  store.failNextControlWrite = true;
  call = await request(
    "LIFECYCLE",
    JSON.stringify({ action: "RECOVER", containmentState: null }),
  );
  assert.equal(call.result.statusCode, 500);

  call = await request("OBJECT_PUT", Buffer.from("must remain blocked"), {
    providerObjectId: "proof.rollback-blocked",
  });
  assert.equal(call.result.statusCode, 423);
});

test("failed control-state persistence compensates delete and migration-copy bytes", async () => {
  const store = new FailingControlStateStore();
  const { request } = fixture(store);
  const source = "proof.persist-source";
  const target = "proof.persist-target";
  const bytes = Buffer.from("must survive failed control persistence");
  const version = `sha256:${digest(bytes)}`;
  let call = await request("OBJECT_PUT", bytes, { providerObjectId: source });
  assert.equal(call.result.statusCode, 201);

  store.failNextControlWrite = true;
  call = await request(
    "OBJECT_DELETE",
    JSON.stringify({ deletionMode: "PERMANENT", reason: "rollback proof" }),
    { providerObjectId: source, immutableProviderVersion: version },
  );
  assert.equal(call.result.statusCode, 500);
  call = await request("OBJECT_HEAD", undefined, {
    providerObjectId: source,
    immutableProviderVersion: version,
  });
  assert.equal(
    call.result.statusCode,
    200,
    "failed delete restores the exact bytes",
  );

  store.failNextControlWrite = true;
  call = await request(
    "MIGRATION_COPY",
    JSON.stringify({
      sourceProviderObjectId: source,
      sourceImmutableProviderVersion: version,
      targetProviderObjectId: target,
    }),
  );
  assert.equal(call.result.statusCode, 500);
  call = await request("OBJECT_HEAD", undefined, {
    providerObjectId: target,
    immutableProviderVersion: version,
  });
  assert.equal(
    call.result.statusCode,
    404,
    "failed copy removes its uncommitted target",
  );
  call = await request(
    "MIGRATION_COPY",
    JSON.stringify({
      sourceProviderObjectId: source,
      sourceImmutableProviderVersion: version,
      targetProviderObjectId: target,
    }),
  );
  assert.equal(call.result.statusCode, 201, "the exact copy remains retryable");
});

test("the live task repairs failed compensation before its next request", async () => {
  const store = new FailingCompensationStore();
  const { request } = fixture(store);
  const objectId = "proof.durable-rollback";
  const bytes = Buffer.from("recover on the live task");
  const version = `sha256:${digest(bytes)}`;
  let call = await request("OBJECT_PUT", bytes, { providerObjectId: objectId });
  assert.equal(call.result.statusCode, 201);

  store.failNextControlWrite = true;
  store.failNextDataWriteFor = objectId;
  call = await request(
    "OBJECT_DELETE",
    JSON.stringify({
      deletionMode: "PERMANENT",
      reason: "durable fence proof",
    }),
    { providerObjectId: objectId, immutableProviderVersion: version },
  );
  assert.equal(call.result.statusCode, 500);
  assert.equal(JSON.parse(call.result.body).code, "STORAGE_ROLLBACK_FAILED");
  await assert.rejects(() => store.head(objectId));

  call = await request(
    "OBJECT_HEAD",
    undefined,
    { providerObjectId: objectId, immutableProviderVersion: version },
  );
  assert.equal(call.result.statusCode, 200);
  assert.deepEqual(Buffer.from((await store.get(objectId)).body), bytes);
  await assert.rejects(() => store.head("proof.gateway-rollback-fence-v1"));
});

test("read-after-error recognizes an ambiguously successful control-state commit", async () => {
  const store = new AmbiguousControlStateStore();
  const { request } = fixture(store);
  const objectId = "proof.ambiguous-control-write";
  const bytes = Buffer.from("committed despite a lost PUT response");
  const version = `sha256:${digest(bytes)}`;
  store.storeThenThrowNextControlWrite = true;
  let call = await request("OBJECT_PUT", bytes, { providerObjectId: objectId });
  assert.equal(call.result.statusCode, 201);
  assert.deepEqual(Buffer.from((await store.get(objectId)).body), bytes);
  await assert.rejects(() => store.head("proof.gateway-rollback-fence-v1"));

  store.storeThenThrowNextControlWrite = true;
  call = await request(
    "OBJECT_DELETE",
    JSON.stringify({
      deletionMode: "PERMANENT",
      reason: "ambiguous commit proof",
    }),
    { providerObjectId: objectId, immutableProviderVersion: version },
  );
  assert.equal(call.result.statusCode, 204);
  await assert.rejects(() => store.head(objectId));
  const outbox = JSON.parse((await request("OUTBOX_LIST")).result.body).changes;
  assert.deepEqual(
    outbox
      .filter((change) => change.objectId === objectId)
      .map((change) => change.type),
    ["PUT", "DELETED"],
  );
});

test("archive and restore require an exact existing version and durable archive state", async () => {
  const { config, request } = fixture();
  const objectId = "proof.archive-state";
  const bytes = Buffer.from("archive proof");
  const version = `sha256:${digest(bytes)}`;
  let call = await request(
    "OBJECT_ARCHIVE",
    JSON.stringify({ reason: "nonexistent proof" }),
    { providerObjectId: objectId },
  );
  assert.equal(call.result.statusCode, 404);
  call = await request("OBJECT_PUT", bytes, { providerObjectId: objectId });
  assert.equal(call.result.statusCode, 201);
  call = await request(
    "OBJECT_RESTORE",
    JSON.stringify({ reason: "not archived" }),
    { providerObjectId: objectId, immutableProviderVersion: version },
  );
  assert.equal(call.result.statusCode, 409);
  call = await request(
    "OBJECT_ARCHIVE",
    JSON.stringify({ reason: "retention proof" }),
    { providerObjectId: objectId, immutableProviderVersion: version },
  );
  assert.equal(call.result.statusCode, 200);
  const replacement = createGateway(config);
  call = await request(
    "OBJECT_RESTORE",
    JSON.stringify({ reason: "retention complete" }),
    { providerObjectId: objectId, immutableProviderVersion: version },
    replacement,
  );
  assert.equal(call.result.statusCode, 200);
  call = await request(
    "OBJECT_RESTORE",
    JSON.stringify({ reason: "cannot restore twice" }),
    { providerObjectId: objectId, immutableProviderVersion: version },
    replacement,
  );
  assert.equal(call.result.statusCode, 409);
});

test("usage paginates through every synthetic object", async () => {
  const { request } = fixture();
  for (let index = 0; index < 101; index += 1) {
    const call = await request("OBJECT_PUT", Buffer.from("x"), {
      providerObjectId: `proof.usage-${String(index).padStart(3, "0")}`,
      requestSimplyId: `RQST-${String(index).padStart(4, "0")}-0002`,
    });
    assert.equal(call.result.statusCode, 201);
  }
  const call = await request("USAGE_GET");
  assert.deepEqual(JSON.parse(call.result.body), {
    objectCount: 101,
    sizeBytes: 101,
  });
});

test("inventory scans past internal control objects before returning a page", async () => {
  const { request } = fixture();
  const objectId = "proof.z-visible";
  let call = await request("OBJECT_PUT", Buffer.from("visible"), {
    providerObjectId: objectId,
  });
  assert.equal(call.result.statusCode, 201);

  call = await request(
    "INVENTORY_LIST",
    JSON.stringify({ afterProviderObjectId: null, limit: 1 }),
  );
  assert.equal(call.result.statusCode, 200);
  assert.deepEqual(JSON.parse(call.result.body).objectIds, [objectId]);
});

test("freshness is rechecked after a request waits for the serialized execution slot", async () => {
  const store = new BlockingInitializationStore();
  const { request, setNow } = fixture(store);
  const pending = request("HEALTH");
  await store.waitUntilBlocked();
  setNow("2026-08-01T12:04:00.000Z");
  store.release();
  const call = await pending;
  assert.equal(call.result.statusCode, 401);
  assert.equal(JSON.parse(call.result.body).code, "ENVELOPE_EXPIRED");
});

test("synthetic object lifecycle proves upload, immutable digest, migration verify/switch/soak, and safe delete", async () => {
  const { request, setNow, verifyResponse } = fixture();
  const source = "proof.source-001";
  const target = "proof.target-001";
  const bytes = Buffer.from("reference proof bytes");
  let call = await request("OBJECT_PUT", bytes, { providerObjectId: source });
  assert.equal(call.result.statusCode, 201);
  const version = `sha256:${digest(bytes)}`;
  verifyResponse(call.result);
  call = await request("OBJECT_HEAD", undefined, {
    providerObjectId: source,
    immutableProviderVersion: version,
  });
  assert.equal(call.result.statusCode, 200);
  assert.equal(call.result.body.length, 0);
  assert.equal(verifyResponse(call.result).immutableProviderVersion, version);
  call = await request("OBJECT_GET", undefined, {
    providerObjectId: source,
    immutableProviderVersion: `sha256:${"0".repeat(64)}`,
  });
  assert.equal(
    call.result.statusCode,
    409,
    "reads require the exact immutable version",
  );
  call = await request("OBJECT_PUT", Buffer.from("replacement bytes"), {
    providerObjectId: source,
  });
  assert.equal(
    call.result.statusCode,
    409,
    "same-key byte substitution is rejected",
  );
  call = await request("OBJECT_CHECKSUM", undefined, {
    providerObjectId: source,
    immutableProviderVersion: version,
  });
  assert.equal(JSON.parse(call.result.body).contentSha256, digest(bytes));
  call = await request(
    "MIGRATION_COPY",
    JSON.stringify({
      sourceProviderObjectId: source,
      sourceImmutableProviderVersion: version,
      targetProviderObjectId: target,
    }),
  );
  assert.equal(call.result.statusCode, 201);
  assert.equal(verifyResponse(call.result).providerObjectId, target);
  call = await request(
    "MIGRATION_COPY",
    JSON.stringify({
      sourceProviderObjectId: source,
      sourceImmutableProviderVersion: version,
      targetProviderObjectId: target,
    }),
  );
  assert.equal(
    call.result.statusCode,
    409,
    "a migration target can never be overwritten",
  );
  call = await request(
    "MIGRATION_SWITCH",
    JSON.stringify({
      sourceProviderObjectId: source,
      targetProviderObjectId: target,
      immutableProviderVersion: version,
      soakUntil: "2026-08-01T12:01:00.000Z",
    }),
  );
  assert.equal(
    call.result.statusCode,
    409,
    "copy cannot switch before independent verification",
  );
  call = await request(
    "MIGRATION_VERIFY",
    JSON.stringify({
      sourceProviderObjectId: source,
      targetProviderObjectId: target,
      immutableProviderVersion: version,
    }),
  );
  assert.equal(call.result.statusCode, 200);
  assert.equal(verifyResponse(call.result).providerObjectId, target);
  call = await request(
    "MIGRATION_SWITCH",
    JSON.stringify({
      sourceProviderObjectId: source,
      targetProviderObjectId: target,
      immutableProviderVersion: version,
      soakUntil: "2026-08-01T12:01:00.000Z",
    }),
  );
  assert.equal(call.result.statusCode, 200);
  assert.equal(verifyResponse(call.result).providerObjectId, target);
  assert.equal(JSON.parse(call.result.body).sourcePreserved, true);
  call = await request(
    "OBJECT_DELETE",
    JSON.stringify({
      deletionMode: "PERMANENT",
      reason: "Must remain protected during the soak window",
    }),
    { providerObjectId: target, immutableProviderVersion: version },
  );
  assert.equal(
    call.result.statusCode,
    409,
    "migration target remains protected through soak",
  );
  setNow("2026-08-01T12:01:00.000Z");
  call = await request("MIGRATION_SOAK");
  assert.equal(call.result.statusCode, 200);
  call = await request(
    "OBJECT_DELETE",
    JSON.stringify({
      deletionMode: "PERMANENT",
      reason: "Disposable synthetic proof cleanup",
    }),
    { providerObjectId: target, immutableProviderVersion: version },
  );
  assert.equal(call.result.statusCode, 204);
  verifyResponse(call.result);
  call = await request(
    "OBJECT_DELETE",
    JSON.stringify({
      deletionMode: "PERMANENT",
      reason: "Attempt to remove a migration source",
    }),
    { providerObjectId: source, immutableProviderVersion: version },
  );
  assert.equal(call.result.statusCode, 409);
  call = await request("OBJECT_HEAD", undefined, {
    providerObjectId: source,
    immutableProviderVersion: version,
  });
  assert.equal(
    call.result.statusCode,
    200,
    "completed soak retires migration details without authorizing source deletion",
  );
});

test("forced failure is deterministic, contained, and recoverable", async () => {
  const { request, verifyResponse } = fixture();
  const objectId = "proof.failure-001";
  const bytes = Buffer.from("recoverable");
  const version = `sha256:${digest(bytes)}`;
  let call = await request(
    "FAILURE_INJECT",
    JSON.stringify({ mode: "BEFORE_OBJECT_WRITE" }),
  );
  assert.equal(call.result.statusCode, 200);
  call = await request("OBJECT_PUT", bytes, { providerObjectId: objectId });
  assert.equal(call.result.statusCode, 503);
  assert.equal(
    JSON.parse(call.result.body).code,
    "INJECTED_BEFORE_OBJECT_WRITE",
  );
  verifyResponse(call.result);
  call = await request("FAILURE_INJECT", JSON.stringify({ mode: "NONE" }));
  assert.equal(call.result.statusCode, 200);
  call = await request("OBJECT_PUT", bytes, { providerObjectId: objectId });
  assert.equal(call.result.statusCode, 201);
  call = await request(
    "FAILURE_INJECT",
    JSON.stringify({ mode: "OBJECT_READ" }),
  );
  assert.equal(call.result.statusCode, 200);
  call = await request("OBJECT_GET", undefined, {
    providerObjectId: objectId,
    immutableProviderVersion: version,
  });
  assert.equal(call.result.statusCode, 503);
  verifyResponse(call.result);
  call = await request("FAILURE_INJECT", JSON.stringify({ mode: "NONE" }));
  assert.equal(call.result.statusCode, 200);
  call = await request(
    "LIFECYCLE",
    JSON.stringify({
      action: "SET_CONTAINMENT",
      containmentState: "READ_ONLY",
    }),
  );
  assert.equal(call.result.statusCode, 200);
  call = await request("OBJECT_PUT", bytes, {
    providerObjectId: "proof.blocked-001",
  });
  assert.equal(call.result.statusCode, 423);
  verifyResponse(call.result);
  call = await request(
    "LIFECYCLE",
    JSON.stringify({ action: "RECOVER", containmentState: null }),
  );
  assert.equal(call.result.statusCode, 200);
  call = await request("OBJECT_GET", undefined, {
    providerObjectId: objectId,
    immutableProviderVersion: version,
  });
  assert.equal(call.result.statusCode, 200);
  assert.deepEqual(Buffer.from(call.result.body), bytes);
});

test("retry after an injected post-write failure emits the PUT event exactly once", async () => {
  const { request } = fixture();
  const objectId = "proof.after-write-recovery";
  const bytes = Buffer.from("persisted before the injected failure");
  let call = await request(
    "FAILURE_INJECT",
    JSON.stringify({ mode: "AFTER_OBJECT_WRITE_BEFORE_COMMIT" }),
  );
  assert.equal(call.result.statusCode, 200);
  call = await request("OBJECT_PUT", bytes, { providerObjectId: objectId });
  assert.equal(call.result.statusCode, 503);
  call = await request("FAILURE_INJECT", JSON.stringify({ mode: "NONE" }));
  assert.equal(call.result.statusCode, 200);

  call = await request("OBJECT_PUT", bytes, { providerObjectId: objectId });
  assert.equal(call.result.statusCode, 201);
  call = await request("OBJECT_PUT", bytes, { providerObjectId: objectId });
  assert.equal(call.result.statusCode, 200);
  const outbox = await request("OUTBOX_LIST");
  const putEvents = JSON.parse(outbox.result.body).changes.filter(
    (change) => change.type === "PUT" && change.objectId === objectId,
  );
  assert.equal(putEvents.length, 1);
});

test("full outbox applies backpressure before storage mutation and advances only through explicit acknowledgement", async () => {
  const store = new MemoryObjectStore();
  const { request } = fixture(store);
  for (let index = 0; index < 1_000; index += 1) {
    const call = await request(
      "LIFECYCLE",
      JSON.stringify({ action: "UPGRADE_AUTHORITY", containmentState: null }),
      { requestSimplyId: `RQST-${String(index).padStart(4, "0")}-0001` },
    );
    assert.equal(call.result.statusCode, 200);
  }

  let call = await request("OBJECT_PUT", Buffer.from("must not be written"), {
    providerObjectId: "proof.outbox-backpressure",
  });
  assert.equal(call.result.statusCode, 503);
  assert.equal(JSON.parse(call.result.body).code, "OUTBOX_BACKPRESSURE");
  await assert.rejects(() => store.head("proof.outbox-backpressure"));

  call = await request(
    "OUTBOX_ACK",
    JSON.stringify({ throughSequence: 1_001 }),
  );
  assert.equal(call.result.statusCode, 409);
  call = await request("OUTBOX_ACK", JSON.stringify({ throughSequence: 1 }));
  assert.equal(call.result.statusCode, 200);
  assert.equal(JSON.parse(call.result.body).acknowledgedThroughSequence, 1);

  call = await request("OBJECT_PUT", Buffer.from("now admitted"), {
    providerObjectId: "proof.outbox-backpressure",
  });
  assert.equal(call.result.statusCode, 201);
});

test("security boundary rejects unsigned, noncanonical, and non-synthetic requests", async () => {
  const { gateway, request } = fixture();
  const unsigned = await gateway.handle({
    method: "GET",
    path: "/v1/primary-file-provider/health",
    headers: {},
    body: new Uint8Array(),
  });
  assert.equal(unsigned.statusCode, 401);
  const noncanonical = await gateway.handle({
    method: "GET",
    path: "/v1/primary-file-provider/health",
    headers: {
      "x-s360-key-id": "platform-test-key",
      "x-s360-envelope": Buffer.from('{ "schemaVersion": 1 }').toString(
        "base64url",
      ),
      "x-s360-signature":
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    },
    body: new Uint8Array(),
  });
  assert.equal(noncanonical.statusCode, 401);
  let call = await request("OBJECT_PUT", Buffer.from("nope"), {
    providerObjectId: "customer-object",
  });
  assert.equal(call.result.statusCode, 403);
  call = await request("HEALTH", Buffer.from("{}"));
  assert.equal(
    call.result.statusCode,
    400,
    "the closed health route accepts no body",
  );
  call = await request("OBJECT_PUT", Buffer.from("control-state overwrite"), {
    providerObjectId: "proof.gateway-control-v1",
  });
  assert.equal(
    call.result.statusCode,
    403,
    "the internal control-state object is outside the synthetic data namespace",
  );
});

test("closed contract rejects malformed IDs, nonce, time, idempotency, routing, and JSON body fields", async () => {
  const { request } = fixture();

  let call = await request("HEALTH", undefined, {
    teamSimplyId: "TEAM-0000-00001",
  });
  assert.equal(
    call.result.statusCode,
    401,
    "Simply IDs are exactly uppercase 4-4-4",
  );

  call = await request("HEALTH", undefined, { nonce: "short" });
  assert.equal(
    call.result.statusCode,
    401,
    "nonce is bounded canonical base64url",
  );

  call = await request("HEALTH", undefined, {
    expiresAt: "2026-08-01T11:59:00.000Z",
  });
  assert.equal(
    call.result.statusCode,
    401,
    "validity windows cannot be reversed",
  );

  call = await request("HEALTH", undefined, {
    idempotencyKey: "contains a space",
  });
  assert.equal(
    call.result.statusCode,
    401,
    "idempotency keys are printable non-space ASCII",
  );

  call = await request("HEALTH", undefined, { operation: "OBJECT_GET" });
  assert.equal(
    call.result.statusCode,
    400,
    "operation, method, and path are a closed binding",
  );

  call = await request(
    "FAILURE_INJECT",
    JSON.stringify({ mode: "NONE", extra: true }),
  );
  assert.equal(
    call.result.statusCode,
    400,
    "closed JSON operation bodies reject unknown fields",
  );

  call = await request(
    "FAILURE_INJECT",
    '{"mode":"NONE","mode":"OBJECT_READ"}',
  );
  assert.equal(
    call.result.statusCode,
    400,
    "strict JSON operation parsing rejects duplicate fields",
  );

  call = await request(
    "OBJECT_DELETE",
    JSON.stringify({ disposableSyntheticProof: true }),
    { providerObjectId: "proof.delete-001" },
  );
  assert.equal(
    call.result.statusCode,
    400,
    "delete requires the canonical deletionMode/reason body, never an alternate body",
  );
});
