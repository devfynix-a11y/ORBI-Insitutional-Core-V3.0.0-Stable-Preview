import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const cardMigration = readFileSync(
  new URL('../database/migrations/20260928_strict_card_fee_settlement.sql', import.meta.url),
  'utf8',
);
const lifecycle = readFileSync(
  new URL('../backend/payments/settlementLifecycleManager.ts', import.meta.url),
  'utf8',
);
const ledger = readFileSync(
  new URL('../ledger/transactionService.ts', import.meta.url),
  'utf8',
);

test('card settlement accepts only the exact company service-revenue account', () => {
  assert.match(cardMigration, /system_settlement_accounts/);
  assert.match(cardMigration, /ssa\.role = 'SERVICE_REVENUE'/);
  assert.match(cardMigration, /CARD_FEE_ACCOUNT_MISMATCH/);
  assert.doesNotMatch(cardMigration, /fee_collector_wallets|v_fee_wallet|SYSTEM_FEE_WALLET/);
});

test('gateway settlement resolves company revenue by its exact currency', () => {
  assert.match(lifecycle, /systemSettlementAccounts\.resolve\('SERVICE_REVENUE', settlementCurrency\)/);
  assert.doesNotMatch(lifecycle, /SYSTEM_FEE_WALLET_ID/);
});

test('fee reporting reads the company settlement registry, never legacy aliases', () => {
  const start = ledger.indexOf('public async getFeeTransactions(');
  const end = ledger.indexOf('\n    public async reverseTransaction', start);
  const feeReporting = ledger.slice(start, end);
  assert.match(feeReporting, /system_settlement_accounts/);
  assert.doesNotMatch(feeReporting, /fee_collector_wallets/);
});
