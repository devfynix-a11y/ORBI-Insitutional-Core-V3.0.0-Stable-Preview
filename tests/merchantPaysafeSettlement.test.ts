import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const migration = readFileSync(
  new URL('../database/main.sql', import.meta.url),
  'utf8',
);
const escrowService = readFileSync(new URL('../ledger/escrowService.ts', import.meta.url), 'utf8');
const reportsService = readFileSync(
  new URL('../backend/features/b2b/MerchantSettlementReportsService.ts', import.meta.url),
  'utf8',
);

test('merchant PaySafe settlement is durable, balanced, and SQL-authoritative', () => {
  assert.match(migration, /Base PaySafe merchant release fee policy/);
  assert.match(migration, /'PAYSAFE_RELEASE'/);
  assert.match(migration, /'PAYSAFE'/);
  assert.match(migration, /CREATE TABLE IF NOT EXISTS public\.merchant_paysafe_settlements/);
  assert.match(migration, /merchant_paysafe_settlement_amounts_balance/);
  assert.match(migration, /CREATE OR REPLACE FUNCTION public\.settle_merchant_paysafe_v1/);
  assert.match(migration, /FROM public\.escrow_agreements[\s\S]*FOR UPDATE/);
  assert.match(migration, /FROM public\.merchant_wallets[\s\S]*FOR UPDATE/);
  assert.match(migration, /INSERT INTO public\.ledger_append_markers/);
  assert.match(migration, /PAYSAFE_MERCHANT_SETTLEMENT/);
  assert.match(migration, /v_gross[\s\S]*v_net[\s\S]*v_total_fee/);
});

test('merchant settlement posts gross debit, merchant net credit, and fee credit', () => {
  assert.match(migration, /PaySafe merchant settlement debit/);
  assert.match(migration, /PaySafe merchant net settlement/);
  assert.match(migration, /PaySafe merchant service revenue/);
  assert.match(migration, /PaySafe merchant statutory tax reserve/);
  assert.match(migration, /system_settlement_accounts/);
  assert.match(migration, /UPDATE public\.platform_vaults/);
  assert.match(migration, /UPDATE public\.merchant_wallets/);
  assert.match(migration, /INSERT INTO public\.merchant_paysafe_settlements/);
  assert.match(migration, /INSERT INTO public\.settlement_lifecycle/);
});

test('merchant PaySafe fees have no legacy fee-collector fallback', () => {
  const start = migration.indexOf('CREATE OR REPLACE FUNCTION public.settle_merchant_paysafe_v1(');
  const end = migration.indexOf('\n$$;', start);
  const settlement = migration.slice(start, end);
  assert.match(settlement, /ssa\.role = 'SERVICE_REVENUE'/);
  assert.match(settlement, /ssa\.role = 'TAX_RESERVE'/);
  assert.doesNotMatch(settlement, /fee_collector_wallets|v_fee_collector|PAYSAFE_FEE_COLLECTOR/);
});

test('merchant PaySafe settlement is service-role only and idempotent', () => {
  assert.match(migration, /escrow_agreement_id UUID NOT NULL UNIQUE/);
  assert.match(migration, /transaction_id UUID NOT NULL UNIQUE/);
  assert.match(migration, /paysafe:.*merchant_settlement:v1/);
  assert.match(migration, /REVOKE ALL ON FUNCTION public\.settle_merchant_paysafe_v1[\s\S]*FROM PUBLIC/);
  assert.match(migration, /GRANT EXECUTE ON FUNCTION public\.settle_merchant_paysafe_v1[\s\S]*TO service_role/);
  assert.match(migration, /'idempotent', TRUE/);
});

test('escrow service snapshots server-resolved fees and routes merchant releases to atomic RPC', () => {
  assert.match(escrowService, /platformFeeService\.resolveFee/);
  assert.match(escrowService, /merchant_fee_snapshot:\s*merchantFeeSnapshot/);
  assert.match(escrowService, /PAYSAFE_MERCHANT_RECIPIENT_MISMATCH/);
  assert.match(escrowService, /agreement\.merchant_id[\s\S]*settleMerchantEscrow/);
  assert.match(escrowService, /\.rpc\('settle_merchant_paysafe_v1'/);
});

test('merchant settlement reports use authoritative settlement records', () => {
  assert.match(reportsService, /\.from\('merchant_paysafe_settlements'\)/);
  assert.match(reportsService, /\.eq\('status', 'SETTLED'\)/);
  assert.match(reportsService, /row\.gross_amount/);
  assert.match(reportsService, /row\.fee_amount/);
  assert.match(reportsService, /row\.tax_amount/);
  assert.match(reportsService, /row\.net_amount/);
  assert.doesNotMatch(reportsService, /metadataNumber/);
});
