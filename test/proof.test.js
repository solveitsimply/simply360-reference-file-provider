// Scaffold smoke test — verifies the placeholder descriptor is well-formed.
// Runs against the compiled ESM output in dist/ (npm test builds first).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { describeGateway, PROTOCOL_OPERATIONS } from '../dist/index.js';

test('gateway is MinIO-backed with only the API Gateway public origin', () => {
  const info = describeGateway();
  assert.equal(info.backend, 'minio');
  assert.equal(info.publicOrigin, 'api-gateway-http-api');
});

test('delete is restricted to disposable synthetic proof objects', () => {
  const info = describeGateway();
  assert.equal(info.syntheticProofObjectsOnly, true);
  assert.ok(PROTOCOL_OPERATIONS.includes('synthetic-delete'));
});
