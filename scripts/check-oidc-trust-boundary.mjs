#!/usr/bin/env node
/**
 * Fail-closed guard for the deploy role's OIDC trust boundary.
 *
 * The bootstrap role is assumable by whoever can present a GitHub OIDC token
 * matching its `sub` condition. That subject must be pinned to GitHub's
 * IMMUTABLE numeric organization and repository IDs:
 *
 *   repo:solveitsimply@67548625/simply360-reference-file-provider@1305919089:environment:dev
 *
 * The mutable `owner/name` form binds the role to a STRING. Deleting or
 * renaming this repository would let whoever next creates that name in the org
 * mint tokens that satisfy the condition and assume the deploy role. GitHub
 * never reuses the numeric IDs, so the pinned form cannot be squatted.
 *
 * `environment:dev` (rather than `ref:refs/heads/dev`) additionally forces the
 * job through the protected `dev` environment. That subject is only minted for
 * a workflow job that declares `environment: dev`, so the workflow assertion
 * below is part of the same boundary — dropping it breaks deploys closed
 * instead of widening trust.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const ORGANIZATION_ID = '67548625';
const REPOSITORY_ID = '1305919089';
const REPOSITORY_NAME = 'simply360-reference-file-provider';
const IMMUTABLE_SUBJECT = `repo:solveitsimply@${ORGANIZATION_ID}/${REPOSITORY_NAME}@${REPOSITORY_ID}:environment:dev`;

/** Every subject shape that must never appear: name-scoped, ref-scoped, or wildcarded. */
const FORBIDDEN_SUBJECTS = [
  [`repo:solveitsimply/${REPOSITORY_NAME}:environment:dev`, 'mutable name-scoped environment subject'],
  [`repo:solveitsimply/${REPOSITORY_NAME}:ref:refs/heads/dev`, 'mutable name-scoped branch subject'],
  [`repo:solveitsimply/${REPOSITORY_NAME}:*`, 'wildcard name-scoped subject'],
  [`repo:solveitsimply@${ORGANIZATION_ID}/${REPOSITORY_NAME}@${REPOSITORY_ID}:*`, 'wildcard immutable subject'],
];

const failures = [];

const read = (relativePath) => {
  const absolute = path.join(REPO_ROOT, relativePath);
  if (!fs.existsSync(absolute)) {
    failures.push(`MISSING: ${relativePath} does not exist; the trust boundary cannot be verified.`);
    return null;
  }
  return fs.readFileSync(absolute, 'utf8');
};

const bootstrap = read('infra/reference-file-provider-dev-bootstrap.yaml');
if (bootstrap !== null) {
  if (!bootstrap.includes(IMMUTABLE_SUBJECT)) {
    failures.push(`bootstrap template does not pin the immutable OIDC subject:\n    expected ${IMMUTABLE_SUBJECT}`);
  }
  for (const [subject, label] of FORBIDDEN_SUBJECTS) {
    if (bootstrap.includes(subject)) failures.push(`bootstrap template still carries the ${label}: ${subject}`);
  }
  // A wildcarded or absent condition is the same failure by another route.
  if (!bootstrap.includes('token.actions.githubusercontent.com:aud: sts.amazonaws.com')) {
    failures.push('bootstrap template does not pin the OIDC audience to sts.amazonaws.com.');
  }
  if (/token\.actions\.githubusercontent\.com:sub:\s*['"]?\*/u.test(bootstrap)) {
    failures.push('bootstrap template wildcards the OIDC subject.');
  }
  if (bootstrap.includes('StringLike')) {
    failures.push('bootstrap template uses StringLike for OIDC trust; the subject must be a StringEquals match.');
  }
}

const deployWorkflow = read('.github/workflows/deploy-dev.yml');
if (deployWorkflow !== null && !/^\s{4}environment:\s*dev\s*$/mu.test(deployWorkflow)) {
  failures.push(
    'deploy-dev.yml does not declare `environment: dev` on the deploy job; GitHub will not mint the ' +
      'environment-scoped subject the deploy role trusts.',
  );
}

const infraReadme = read('infra/README.md');
if (infraReadme !== null) {
  if (!infraReadme.includes(IMMUTABLE_SUBJECT)) {
    failures.push('infra/README.md does not document the immutable OIDC subject.');
  }
  for (const [subject, label] of FORBIDDEN_SUBJECTS) {
    if (infraReadme.includes(subject)) failures.push(`infra/README.md still documents the ${label}: ${subject}`);
  }
}

if (failures.length > 0) {
  process.stderr.write(`OIDC trust boundary check FAILED (${failures.length}):\n`);
  for (const failure of failures) process.stderr.write(`  - ${failure}\n`);
  process.exit(1);
}

process.stdout.write(`OIDC trust boundary OK — deploy role pinned to ${IMMUTABLE_SUBJECT}\n`);
