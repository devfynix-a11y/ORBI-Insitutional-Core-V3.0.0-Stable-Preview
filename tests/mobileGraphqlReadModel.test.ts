import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { join } from 'node:path';

const routeSource = readFileSync(
  join(process.cwd(), 'src/routes/public/mobileGraphql.ts'),
  'utf8',
);

test('mobile GraphQL is explicitly read-only', () => {
  assert.match(routeSource, /GRAPHQL_MUTATIONS_DISABLED/);
  assert.match(routeSource, /\\bmutation\\b/i);
  assert.equal(routeSource.includes("name: 'Mutation'"), false);
  assert.equal(routeSource.includes('name: "Mutation"'), false);
});

test('mobile GraphQL keeps mobile query limits capped', () => {
  assert.match(routeSource, /MAX_TRANSACTION_LIMIT = 100/);
  assert.match(routeSource, /MAX_ESCROW_LIMIT = 50/);
  assert.match(routeSource, /clampLimit/);
});

test('mobile snapshot isolates optional resolver failures and reports degradation', () => {
  assert.match(routeSource, /Promise\.allSettled/);
  assert.match(routeSource, /snapshot_resolver_degraded/);
  assert.match(routeSource, /degraded: \{ type: JsonScalar \}/);
});
