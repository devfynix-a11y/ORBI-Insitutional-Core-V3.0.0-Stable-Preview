import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

async function source(path: string) {
  return readFile(new URL(`../${path}`, import.meta.url), 'utf8');
}

test('admin account status contract requires audit reason metadata', async () => {
  const adminOps = await source('src/routes/public/adminOps.ts');
  const server = await source('backend/server.ts');

  assert.match(adminOps, /AccountStatusUpdateWithReasonSchema/);
  assert.match(adminOps, /reason:\s*z\.string\(\)\.trim\(\)\.min\(5/);
  assert.match(server, /ACCOUNT_STATUS_UPDATE/);
});

test('admin audit trail and risk alert explorers are exposed as read APIs', async () => {
  const adminOps = await source('src/routes/public/adminOps.ts');

  assert.match(adminOps, /v1\.get\('\/admin\/audit-trail'/);
  assert.match(adminOps, /v1\.get\('\/admin\/risk\/alerts'/);
  assert.match(adminOps, /getPendingAMLAlerts/);
  assert.match(adminOps, /getAnomalyReport/);
});

test('treasury approval and reconciliation run contracts require reason capture', async () => {
  const operations = await source('src/routes/public/operations.ts');
  const server = await source('backend/server.ts');
  const treasury = await source('backend/enterprise/treasuryService.ts');

  assert.match(operations, /TreasuryApprovalSchema/);
  assert.match(operations, /ReconciliationRunSchema/);
  assert.match(operations, /reason:\s*z\.string\(\)\.trim\(\)\.min\(5/);
  assert.match(server, /TREASURY_WITHDRAWAL_APPROVAL_REQUESTED/);
  assert.match(server, /RECONCILIATION_RUN_REQUESTED/);
  assert.match(treasury, /\.rpc\('approve_treasury_withdrawal_v1'/);
});
