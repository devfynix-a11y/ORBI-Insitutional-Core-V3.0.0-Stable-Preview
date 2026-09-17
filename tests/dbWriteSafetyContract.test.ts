import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const runner = readFileSync(new URL('../scripts/run-db-financial-tests.mjs', import.meta.url), 'utf8');
const validator = readFileSync(new URL('./helpers/validateDbIntegrationEnv.ts', import.meta.url), 'utf8');
const mutation = readFileSync(new URL('./financialCoreDbMutation.test.ts', import.meta.url), 'utf8');

test('database write certification requires two explicit disposable-target assertions', () => {
  assert.match(runner, /--confirm-disposable-database/);
  assert.match(runner, /loadedEnv\.ORBI_DB_TEST_DISPOSABLE !== 'true'/);
  assert.match(runner, /'node_modules', 'npm', 'bin', 'npx-cli\.js'/);
  assert.match(runner, /shell: false/);
  assert.match(validator, /'ORBI_DB_TEST_DISPOSABLE'/);
});

test('treasury concurrency certification covers isolation, quorum, and single append', () => {
  assert.match(mutation, /TREASURY_APPROVER_ACCESS_DENIED/);
  assert.match(mutation, /TREASURY_MAKER_CHECKER_VIOLATION/);
  assert.match(mutation, /Promise\.all\(\[\s*client\.rpc\('approve_treasury_withdrawal_v1'/);
  assert.match(mutation, /APPEND_ALREADY_APPLIED/);
  assert.match(mutation, /originalGoalBalance - amount/);
  assert.match(mutation, /originalDestinationBalance \+ amount/);
});
