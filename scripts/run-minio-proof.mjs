import assert from "node:assert/strict";
import { spawn } from "node:child_process";

import { MinioObjectStore } from "../dist/index.js";

const containerName = `s360-minio-proof-${process.pid}`;
const port = 19000 + (process.pid % 1000);

const run = (command, args) =>
  new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: "inherit" });
    child.once("error", reject);
    child.once("exit", (code) =>
      code === 0 ? resolve() : reject(new Error(`${command} exited ${code}`)),
    );
  });

try {
  await run("docker", [
    "run",
    "--detach",
    "--rm",
    "--name",
    containerName,
    "--publish",
    `${port}:9000`,
    "--env",
    "MINIO_ROOT_USER=minioadmin",
    "--env",
    "MINIO_ROOT_PASSWORD=minioadmin",
    "minio/minio@sha256:3f97c5651cb6662b880c787a232b6b34fec8d8922e08d6617b25d241a21164bb",
    "server",
    "/data",
  ]);
  const store = new MinioObjectStore({
    endpoint: `http://127.0.0.1:${port}`,
    bucket: "proof-bucket",
    accessKey: "minioadmin",
    secretKey: "minioadmin",
  });
  await store.waitUntilReady();
  const objectId = "proof.percent:equals=slash/one";
  const bytes = new TextEncoder().encode("MinIO proof");
  await store.put(objectId, bytes);
  assert.equal((await store.head(objectId)).sizeBytes, bytes.length);
  assert.deepEqual((await store.get(objectId)).body, bytes);
  assert.deepEqual(await store.list(null, 10), [objectId]);
  await store.delete(objectId);
  assert.deepEqual(await store.list(null, 10), []);
} finally {
  await run("docker", ["rm", "--force", containerName]).catch(() => undefined);
}
