import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const migration = readFileSync(new URL('../database/main.sql', import.meta.url), 'utf8');
const service = readFileSync(
  new URL('../backend/enterprise/treasuryService.ts', import.meta.url),
  'utf8',
);
const reconciliation = readFileSync(
  new URL('../backend/ledger/reconciliationService.ts', import.meta.url),
  'utf8',
);

const approvalFunction = migration.split(
  'CREATE OR REPLACE FUNCTION public.approve_treasury_withdrawal_v1',
)[1];

test('treasury approval RPC serializes approval and execution claims', () => {
  assert.ok(approvalFunction);
  assert.match(approvalFunction, /FROM public\.transactions[\s\S]*FOR UPDATE/);
  assert.match(approvalFunction, /FROM public\.goals[\s\S]*FOR UPDATE/);
  assert.match(approvalFunction, /status = CASE WHEN v_fully_approved THEN 'processing'/);
  assert.match(approvalFunction, /'should_execute', v_fully_approved/);
});

test('treasury approval RPC enforces organization, active role, and maker-checker', () => {
  assert.match(approvalFunction, /TREASURY_MAKER_CHECKER_VIOLATION/);
  assert.match(approvalFunction, /v_admin\.organization_id IS DISTINCT FROM v_goal\.organization_id/);
  assert.match(approvalFunction, /v_admin\.account_status[\s\S]*<> 'ACTIVE'/);
  assert.match(approvalFunction, /v_admin\.org_role[\s\S]*NOT IN \('ADMIN', 'FINANCE'\)/);
  assert.match(approvalFunction, /TREASURY_APPROVAL_ALREADY_RECORDED/);
});

test('treasury approval RPC is service-role-only and has no application metadata fallback', () => {
  assert.match(migration, /REVOKE ALL ON FUNCTION public\.approve_treasury_withdrawal_v1\(UUID, UUID\) FROM PUBLIC/);
  assert.match(migration, /GRANT EXECUTE ON FUNCTION public\.approve_treasury_withdrawal_v1\(UUID, UUID\) TO service_role/);
  assert.match(service, /\.rpc\('approve_treasury_withdrawal_v1'/);
  assert.doesNotMatch(service, /metadata\.approved_by\.push/);
});

test('treasury execution uses an idempotent ledger append and does not debit the goal twice', () => {
  assert.match(service, /appendKey: `treasury-withdrawal:\$\{txId\}`/);
  assert.match(service, /appendPhase: 'TREASURY_WITHDRAWAL_EXECUTION'/);
  assert.doesNotMatch(service, /update\(\{ current: Math\.max/);
});

test('expired treasury execution leases can be reclaimed by one recovery worker', () => {
  assert.match(migration, /CREATE OR REPLACE FUNCTION public\.claim_treasury_withdrawal_execution_v1/);
  const claimFunction = migration.split(
    'CREATE OR REPLACE FUNCTION public.claim_treasury_withdrawal_execution_v1',
  )[1];
  assert.ok(claimFunction);
  assert.match(claimFunction, /FROM public\.transactions[\s\S]*FOR UPDATE/);
  assert.match(claimFunction, /v_lease_until > NOW\(\)/);
  assert.match(claimFunction, /'reason', 'LEASE_ACTIVE'/);
  assert.match(claimFunction, /'execution_token', v_execution_token::TEXT/);
  assert.match(migration, /GRANT EXECUTE ON FUNCTION public\.claim_treasury_withdrawal_execution_v1[\s\S]*TO service_role/);
});

test('reconciliation routes treasury processing rows through treasury recovery', () => {
  assert.match(reconciliation, /tx\.metadata\?\.is_treasury_withdrawal === true/);
  assert.match(reconciliation, /Treasury\.recoverClaimedWithdrawal\(tx\.id, 'system-treasury-reaper'\)/);
  assert.match(service, /const ledgerAlreadyApplied = existingLegs\.some/);
  assert.match(service, /if \(!ledgerAlreadyApplied\)[\s\S]*addLedgerEntries/);
});

test('treasury request is SQL-authoritative for resource, currency, balance, and policy limits', () => {
  assert.match(migration, /CREATE OR REPLACE FUNCTION public\.request_treasury_withdrawal_v1/);
  const requestFunction = migration.split(
    'CREATE OR REPLACE FUNCTION public.request_treasury_withdrawal_v1',
  )[1];
  assert.ok(requestFunction);
  assert.match(requestFunction, /FROM public\.goals[\s\S]*FOR UPDATE/);
  assert.match(requestFunction, /FROM public\.wallets[\s\S]*FOR UPDATE/);
  assert.match(requestFunction, /TREASURY_INSUFFICIENT_FUNDS/);
  assert.match(requestFunction, /TREASURY_DESTINATION_ACCESS_DENIED/);
  assert.match(requestFunction, /TREASURY_PER_TRANSACTION_LIMIT_EXCEEDED/);
  assert.match(requestFunction, /TREASURY_DAILY_LIMIT_EXCEEDED/);
  assert.match(requestFunction, /v_approvals_required := GREATEST\(2/);
  assert.match(service, /\.rpc\('request_treasury_withdrawal_v1'/);
});

test('autosweep uses explicit constrained goal columns', () => {
  assert.match(migration, /ADD COLUMN IF NOT EXISTS auto_sweep_enabled BOOLEAN NOT NULL DEFAULT FALSE/);
  assert.match(migration, /goals_sweep_threshold_nonnegative/);
  assert.match(service, /g\.auto_sweep_enabled === true/);
  assert.doesNotMatch(service, /metadata\.auto_sweep/);
});

test('treasury policy administration is versioned, admin-bound, and quorum-feasible', () => {
  assert.match(migration, /CREATE TABLE IF NOT EXISTS public\.treasury_policy_versions/);
  assert.match(migration, /CREATE OR REPLACE FUNCTION public\.upsert_treasury_policy_v1/);
  const policyFunction = migration.split('CREATE OR REPLACE FUNCTION public.upsert_treasury_policy_v1')[1];
  assert.match(policyFunction, /TREASURY_POLICY_ADMIN_REQUIRED/);
  assert.match(policyFunction, /TREASURY_POLICY_QUORUM_UNAVAILABLE/);
  assert.match(policyFunction, /p_daily_limit < p_max_amount_per_tx/);
  assert.match(policyFunction, /INSERT INTO public\.treasury_policy_versions/);
  assert.match(migration, /GRANT EXECUTE ON FUNCTION public\.upsert_treasury_policy_v1[\s\S]*TO service_role/);
});

test('treasury approver membership uses expiring dual-control changes and protects quorum', () => {
  assert.match(migration, /CREATE TABLE IF NOT EXISTS public\.treasury_approver_change_requests/);
  assert.match(migration, /expires_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT \(NOW\(\) \+ INTERVAL '24 hours'\)/);
  const requestChange = migration.split('CREATE OR REPLACE FUNCTION public.request_treasury_approver_change_v1')[1];
  const respondChange = migration.split('CREATE OR REPLACE FUNCTION public.respond_treasury_approver_change_v1')[1];
  assert.ok(requestChange);
  assert.ok(respondChange);
  assert.match(requestChange, /TREASURY_APPROVER_ADMIN_REQUIRED/);
  assert.match(respondChange, /p_reviewer_id=v_request\.requested_by/);
  assert.match(respondChange, /p_reviewer_id=v_request\.target_user_id/);
  assert.match(respondChange, /TREASURY_APPROVER_REMOVAL_BREAKS_QUORUM/);
  assert.match(migration, /GRANT EXECUTE ON FUNCTION public\.respond_treasury_approver_change_v1[\s\S]*TO service_role/);
});

test('treasury approvals and policy quorum require active explicit assignments', () => {
  assert.match(approvalFunction, /FROM public\.treasury_approvers[\s\S]*status='ACTIVE'/);
  const policyFunction = migration.split('CREATE OR REPLACE FUNCTION public.upsert_treasury_policy_v1')[1];
  assert.match(policyFunction, /FROM public\.treasury_approvers ta JOIN public\.users u/);
});

test('scheduled treasury changes require dual control and valid timezone settings', () => {
  const request = migration.split('CREATE OR REPLACE FUNCTION public.request_treasury_schedule_change_v1')[1];
  const review = migration.split('CREATE OR REPLACE FUNCTION public.respond_treasury_schedule_change_v1')[1];
  assert.match(request, /pg_timezone_names/);
  assert.match(request, /TREASURY_SCHEDULE_REQUESTER_DENIED/);
  assert.match(review, /p_reviewer_id=v_r\.requested_by/);
  assert.match(review, /sweep_schedule_version=sweep_schedule_version\+1/);
});

test('scheduled treasury claims are unique, concurrent-safe, and recover expired leases', () => {
  const claim = migration.split('CREATE OR REPLACE FUNCTION public.claim_due_treasury_sweeps_v1')[1];
  const reclaim = migration.split('CREATE OR REPLACE FUNCTION public.reclaim_treasury_schedule_executions_v1')[1];
  assert.match(migration, /UNIQUE\(goal_id,schedule_version,scheduled_for\)/);
  assert.match(claim, /FOR UPDATE SKIP LOCKED/);
  assert.match(claim, /AT TIME ZONE v_goal\.sweep_timezone/);
  assert.match(reclaim, /lease_until<=NOW\(\)/);
  assert.match(reclaim, /FOR UPDATE SKIP LOCKED/);
  assert.match(service, /reclaim_treasury_schedule_executions_v1/);
});

test('scheduled treasury notifications use every required channel and stable event identity', () => {
  assert.match(service, /push: true, sms: true, email: true, mandatory: true/);
  assert.match(service, /eventCode: `TREASURY_SCHEDULE_\$\{status\}`/);
  assert.match(service, /idempotencyKey: `treasury-schedule:\$\{execution\.id\}:\$\{status\}:\$\{recipient\.id\}`/);
});
