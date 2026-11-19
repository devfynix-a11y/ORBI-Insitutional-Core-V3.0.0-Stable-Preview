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

test('Windows financial test helper cannot point fixtures at the live database', () => {
  const helper = readFileSync(
    new URL('../ops/self-hosted/scripts/test-local-financial-db-windows.ps1', import.meta.url),
    'utf8',
  );
  const runner = readFileSync(
    new URL('../scripts/run-db-financial-tests.mjs', import.meta.url),
    'utf8',
  );

  assert.match(helper, /\.env\.test\.local/);
  assert.doesNotMatch(helper, /127\.0\.0\.1:5432\/\$\{database\}/);
  assert.match(runner, /orbi_treasury_certification/);
  assert.match(runner, /Write mode refused/);
});
