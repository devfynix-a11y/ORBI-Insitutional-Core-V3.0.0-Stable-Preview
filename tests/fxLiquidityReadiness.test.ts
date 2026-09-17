import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const coreFinance = readFileSync(
  new URL('../src/routes/public/coreFinance.ts', import.meta.url),
  'utf8',
);
const settlementAccounts = readFileSync(
  new URL('../backend/ledger/SystemSettlementAccountService.ts', import.meta.url),
  'utf8',
);

test('locked FX quotes require the exact target-currency clearing liquidity', () => {
  assert.match(coreFinance, /systemSettlementAccounts\.requireAvailableBalance\(\s*'FX_CLEARING',\s*to,/);
  assert.match(coreFinance, /targetLiquidityRequired/);
  assert.match(coreFinance, /result\.finalAmount/);
  assert.match(coreFinance, /result\.spreadAmount/);
});

test('settlement liquidity rejects an unfunded or unavailable company account', () => {
  assert.match(settlementAccounts, /FX_SETTLEMENT_LIQUIDITY_UNAVAILABLE/);
  assert.match(settlementAccounts, /availableAmount < required/);
  assert.match(settlementAccounts, /this\.resolve\(role, code\)/);
});
