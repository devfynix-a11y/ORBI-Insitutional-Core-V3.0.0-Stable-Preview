import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const schedulerSource = readFileSync(
  new URL('../backend/payments/settlementScheduler.ts', import.meta.url),
  'utf8',
);

test('settlement health reports only active monetary work as backlog', () => {
  const healthCheck = schedulerSource.slice(schedulerSource.indexOf('async healthCheck'));

  assert.match(healthCheck, /\.eq\('status', 'ACTIVE'\)/);
  assert.match(healthCheck, /\.gt\('amount', 0\)/);
  assert.doesNotMatch(healthCheck, /SettlementPhase\.FAILED/);
});
