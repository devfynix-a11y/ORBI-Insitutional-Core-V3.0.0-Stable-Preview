import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const migration = readFileSync(
  new URL('../database/main.sql', import.meta.url),
  'utf8',
);
const finance = readFileSync(
  new URL('../src/routes/public/wealthSharedPotFinance.ts', import.meta.url),
  'utf8',
);
const routes = readFileSync(
  new URL('../src/routes/public/wealthSharedPotRoutes.ts', import.meta.url),
  'utf8',
);
const budgetRoutes = readFileSync(new URL('../src/routes/public/wealthSharedBudgetRoutes.ts', import.meta.url), 'utf8');

test('Shared Pot financial RPCs lock and authorize authoritative records', () => {
  assert.match(migration, /CREATE OR REPLACE FUNCTION public\.shared_pot_contribute_v1/);
  assert.match(migration, /CREATE OR REPLACE FUNCTION public\.shared_pot_withdraw_v1/);
  assert.match(migration, /FROM public\.shared_pots[\s\S]*FOR UPDATE/);
  assert.match(migration, /FROM public\.shared_pot_members[\s\S]*FOR UPDATE/);
  assert.match(migration, /v_member\.role NOT IN \('OWNER', 'MANAGER', 'CONTRIBUTOR'\)/);
  assert.match(migration, /v_member\.role NOT IN \('OWNER', 'MANAGER'\)/);
});

test('Shared Pot money movement is balanced, currency-safe, and replay-safe', () => {
  assert.match(migration, /SHARED_POT_CURRENCY_MISMATCH/);
  assert.match(migration, /SHARED_POT_IDEMPOTENCY_REQUIRED/);
  assert.match(migration, /SHARED_POT_REPLAY_MISMATCH/);
  assert.match(migration, /'OPERATING',[\s\S]*'DEBIT', 'DEBIT'/);
  assert.match(migration, /'GROWING',[\s\S]*'CREDIT', 'CREDIT'/);
  assert.match(migration, /'GROWING',[\s\S]*'DEBIT', 'DEBIT'/);
  assert.match(migration, /'OPERATING',[\s\S]*'CREDIT', 'CREDIT'/);
});

test('withdrawal does not inflate lifetime member contributions', () => {
  const withdrawal = migration.split(
    'CREATE OR REPLACE FUNCTION public.shared_pot_withdraw_v1',
  )[1];
  assert.ok(withdrawal);
  assert.doesNotMatch(withdrawal, /contributed_amount\s*=\s*COALESCE\(contributed_amount/);
  assert.doesNotMatch(withdrawal, /p_member_role|p_member_metadata/);
});

test('pot creation and invitation response are atomic', () => {
  assert.match(migration, /CREATE OR REPLACE FUNCTION public\.create_shared_pot_v1/);
  assert.match(migration, /INSERT INTO public\.shared_pots[\s\S]*INSERT INTO public\.shared_pot_members/);
  assert.match(migration, /CREATE OR REPLACE FUNCTION public\.respond_shared_pot_invitation_v1/);
  assert.match(migration, /INSERT INTO public\.shared_pot_members[\s\S]*UPDATE public\.shared_pot_invitations/);
  assert.match(routes, /\.rpc\('create_shared_pot_v1'/);
  assert.match(routes, /\.rpc\('respond_shared_pot_invitation_v1'/);
});

test('unsafe application fallback is removed and RPCs are service-role-only', () => {
  assert.doesNotMatch(finance, /contributeViaLegacyPath|withdrawViaLegacyPath/);
  assert.match(finance, /SHARED_POT_ATOMIC_RPC_UNAVAILABLE/);
  assert.doesNotMatch(finance, /p_member_role|p_member_metadata/);
  assert.match(migration, /REVOKE ALL ON FUNCTION public\.shared_pot_contribute_v1[\s\S]*FROM PUBLIC/);
  assert.match(migration, /GRANT EXECUTE ON FUNCTION public\.shared_pot_withdraw_v1[\s\S]*TO service_role/);
});

test('shared budget creation and invitation acceptance are atomic and replay safe', () => {
  assert.match(migration, /CREATE OR REPLACE FUNCTION public\.create_shared_budget_v1/);
  assert.match(migration, /INSERT INTO public\.shared_budgets[\s\S]*INSERT INTO public\.shared_budget_members/);
  assert.match(migration, /CREATE OR REPLACE FUNCTION public\.respond_shared_budget_invitation_v1/);
  assert.match(migration, /INSERT INTO public\.shared_budget_members[\s\S]*UPDATE public\.shared_budget_invitations/);
  assert.match(budgetRoutes, /requireIdempotencyKey[\s\S]*\.rpc\('create_shared_budget_v1'/);
  assert.match(budgetRoutes, /\.rpc\('respond_shared_budget_invitation_v1'/);
});

test('shared budget review reserves funds and enforces maker-checker claims', () => {
  const request = migration.split('CREATE OR REPLACE FUNCTION public.request_shared_budget_approval_v1')[1];
  const claim = migration.split('CREATE OR REPLACE FUNCTION public.claim_shared_budget_approval_v1')[1];
  assert.match(request, /FOR UPDATE/);
  assert.match(request, /status IN \('PENDING','PROCESSING'\)/);
  assert.match(request, /SHARED_BUDGET_FUNDS_RESERVED/);
  assert.match(request, /SHARED_BUDGET_MEMBER_LIMIT_RESERVED/);
  assert.match(claim, /p_reviewer_id=v_a\.requester_user_id/);
  assert.match(claim, /SHARED_BUDGET_MAKER_CHECKER_REQUIRED/);
  assert.match(claim, /processing_started_at>NOW\(\)-INTERVAL '15 minutes'/);
  assert.match(budgetRoutes, /\.rpc\('request_shared_budget_approval_v1'/);
  assert.match(budgetRoutes, /\.rpc\('claim_shared_budget_approval_v1'/);
  assert.match(budgetRoutes, /\.rpc\('finish_shared_budget_approval_v1'/);
});
