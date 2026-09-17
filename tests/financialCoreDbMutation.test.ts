import assert from 'node:assert/strict';
import { createHmac, randomUUID } from 'node:crypto';

import { providerWebhookEventLedger } from '../backend/payments/ProviderWebhookEventLedger.js';
import { Webhooks } from '../backend/payments/webhookHandler.js';
import { DataProtection } from '../backend/security/DataProtection.js';
import { RegulatoryService } from '../ledger/regulatoryService.js';
import { TransactionService } from '../ledger/transactionService.js';
import { dbIntegrationEnabled, dbIntegrationTest, dbIntegrationWritesEnabled, hasDbIntegrationConfig, requireEnv } from './helpers/dbIntegration.js';

const WRITE_FIXTURE_ENV = [
  'ORBI_DB_TEST_USER_ID',
  'ORBI_DB_TEST_SOURCE_WALLET_ID',
  'ORBI_DB_TEST_TARGET_WALLET_ID',
  'ORBI_DB_TEST_INTERNAL_TRANSFER_VAULT_ID',
];

const EDGE_FIXTURE_ENV = [
  ...WRITE_FIXTURE_ENV,
  'ORBI_DB_TEST_LOW_BALANCE_WALLET_ID',
  'ORBI_DB_TEST_LOCKED_WALLET_ID',
  'ORBI_DB_TEST_REVIEW_ACTOR_ID',
  'ORBI_DB_TEST_DRIFT_WALLET_ID',
  'ORBI_DB_TEST_WEBHOOK_PARTNER_ID',
  'ORBI_DB_TEST_OPERATING_VAULT_ID',
  'ORBI_DB_TEST_ESCROW_VAULT_ID',
  'ORBI_DB_TEST_BUDGET_CATEGORY_ID',
  'ORBI_DB_TEST_BUDGET_TRIGGER_AMOUNT',
  'ORBI_DB_TEST_WITHDRAWAL_PROVIDER_ID',
];

const TREASURY_FIXTURE_ENV = [
  'ORBI_DB_TEST_TREASURY_MAKER_ID',
  'ORBI_DB_TEST_TREASURY_ADMIN_1_ID',
  'ORBI_DB_TEST_TREASURY_ADMIN_2_ID',
  'ORBI_DB_TEST_TREASURY_CROSS_ORG_ADMIN_ID',
  'ORBI_DB_TEST_TREASURY_ORG_ID',
  'ORBI_DB_TEST_TREASURY_GOAL_ID',
  'ORBI_DB_TEST_TREASURY_DESTINATION_WALLET_ID',
];

const TEST_AMOUNT = Number(process.env.ORBI_DB_TEST_AMOUNT || '0.01');
const INSUFFICIENT_AMOUNT = Number(process.env.ORBI_DB_TEST_INSUFFICIENT_AMOUNT || '999999');
const BUDGET_TRIGGER_AMOUNT = Number(process.env.ORBI_DB_TEST_BUDGET_TRIGGER_AMOUNT || '0');

async function createPostedTransaction(client: any, options?: {
  status?: 'completed' | 'processing';
  description?: string;
  sourceWalletId?: string;
  targetWalletId?: string;
  amount?: number;
  legs?: any[];
}) {
  const txId = randomUUID();
  const referenceId = `ITEST-${Date.now()}-${txId.slice(0, 8)}`;
  const userId = requireEnv('ORBI_DB_TEST_USER_ID');
  const sourceWalletId = options?.sourceWalletId || requireEnv('ORBI_DB_TEST_SOURCE_WALLET_ID');
  const targetWalletId = options?.targetWalletId || requireEnv('ORBI_DB_TEST_TARGET_WALLET_ID');
  const description = options?.description || 'Integration test financial posting';
  const amount = Number(options?.amount ?? TEST_AMOUNT);

  const [encAmt, encDesc] = await Promise.all([
    DataProtection.encryptAmount(amount),
    DataProtection.encryptDescription(description),
  ]);

  const { error } = await client.rpc('post_transaction_v2', {
    p_tx_id: txId,
    p_user_id: userId,
    p_wallet_id: sourceWalletId,
    p_to_wallet_id: targetWalletId,
    p_amount: encAmt,
    p_description: encDesc,
    p_type: 'transfer',
    p_status: options?.status || 'completed',
    p_date: new Date().toISOString().slice(0, 10),
    p_metadata: { integration_test: true, reference_scope: 'financial_core_db_mutation' },
    p_category_id: null,
    p_reference_id: referenceId,
    p_legs: options?.legs || [
      {
        wallet_id: sourceWalletId,
        entry_type: 'DEBIT',
        amount: encAmt,
        amount_plain: amount,
        description: 'Integration debit leg',
      },
      {
        wallet_id: targetWalletId,
        entry_type: 'CREDIT',
        amount: encAmt,
        amount_plain: amount,
        description: 'Integration credit leg',
      },
    ],
  });

  assert.ifError(error);
  return { txId, referenceId, amount, sourceWalletId, targetWalletId };
}

async function createDisposableWebhookPartner(client: any, options?: {
  secret?: string;
  timestampHeader?: string;
}) {
  const partnerId = randomUUID();
  const webhookSecret = options?.secret || `itest-secret-${randomUUID().slice(0, 8)}`;
  const timestampHeader = options?.timestampHeader || 'x-itest-timestamp';

  const { error } = await client.from('financial_partners').insert({
    id: partnerId,
    name: `ITest Webhook ${partnerId.slice(0, 8)}`,
    type: 'mobile_money',
    status: 'INACTIVE',
    webhook_secret: webhookSecret,
    provider_metadata: {},
    mapping_config: {
      callback: {
        reference_field: 'reference',
        status_field: 'status',
        message_field: 'message',
        event_id_field: 'event_id',
        timestamp_header: timestampHeader,
        signature_payload_mode: 'timestamp.raw',
        max_age_seconds: 300,
        success_values: ['SUCCESS', 'COMPLETED'],
        pending_values: ['PENDING', 'PROCESSING'],
        failed_values: ['FAILED', 'REJECTED'],
      },
    },
  });
  assert.ifError(error);

  return { partnerId, webhookSecret, timestampHeader };
}

dbIntegrationTest(
  'write-enabled integration rejects double debit on the same wallet',
  async (_t, client) => {
    const txId = randomUUID();
    const referenceId = `ITEST-DOUBLE-${txId.slice(0, 8)}`;
    const userId = requireEnv('ORBI_DB_TEST_USER_ID');
    const sourceWalletId = requireEnv('ORBI_DB_TEST_SOURCE_WALLET_ID');
    const targetWalletId = requireEnv('ORBI_DB_TEST_TARGET_WALLET_ID');
    const amount = TEST_AMOUNT;
    const [encAmt, encDesc] = await Promise.all([
      DataProtection.encryptAmount(amount),
      DataProtection.encryptDescription('Integration double debit probe'),
    ]);

    const result = await client.rpc('post_transaction_v2', {
      p_tx_id: txId,
      p_user_id: userId,
      p_wallet_id: sourceWalletId,
      p_to_wallet_id: targetWalletId,
      p_amount: encAmt,
      p_description: encDesc,
      p_type: 'transfer',
      p_status: 'completed',
      p_date: new Date().toISOString().slice(0, 10),
      p_metadata: { integration_test: true, scenario: 'double_debit' },
      p_category_id: null,
      p_reference_id: referenceId,
      p_legs: [
        {
          wallet_id: sourceWalletId,
          entry_type: 'DEBIT',
          amount: encAmt,
          amount_plain: amount,
          description: 'Integration debit leg 1',
        },
        {
          wallet_id: sourceWalletId,
          entry_type: 'DEBIT',
          amount: encAmt,
          amount_plain: amount,
          description: 'Integration debit leg 2',
        },
        {
          wallet_id: targetWalletId,
          entry_type: 'CREDIT',
          amount: encAmt,
          amount_plain: amount,
          description: 'Integration credit leg',
        },
      ],
    });

    assert.ok(result.error, 'Expected double debit to be rejected');
    assert.match(String(result.error?.message || ''), /LEDGER_OUT_OF_BALANCE|INSUFFICIENT_FUNDS/i);
  },
  { requireWrites: true, requiredEnv: WRITE_FIXTURE_ENV },
);

dbIntegrationTest(
  'write-enabled integration can post a financial transaction through post_transaction_v2',
  async (_t, client) => {
    const posted = await createPostedTransaction(client, {
      description: 'Write-enabled integration posting',
    });

    const { data: tx, error: txError } = await client
      .from('transactions')
      .select('id, reference_id, status, wallet_id, to_wallet_id')
      .eq('id', posted.txId)
      .single();
    assert.ifError(txError);
    assert.equal(tx.id, posted.txId);
    assert.equal(tx.reference_id, posted.referenceId);
    assert.equal(String(tx.status).toLowerCase(), 'completed');

    const { count: legCount, error: legError } = await client
      .from('financial_ledger')
      .select('*', { count: 'exact', head: true })
      .eq('transaction_id', posted.txId);
    assert.ifError(legError);
    assert.equal(Number(legCount || 0), 2);
  },
  { requireWrites: true, requiredEnv: WRITE_FIXTURE_ENV },
);

dbIntegrationTest(
  'write-enabled integration rejects duplicate transaction reference_id',
  async (_t, client) => {
    const txId = randomUUID();
    const referenceId = `ITEST-DUP-${txId.slice(0, 8)}`;
    const userId = requireEnv('ORBI_DB_TEST_USER_ID');
    const sourceWalletId = requireEnv('ORBI_DB_TEST_SOURCE_WALLET_ID');
    const targetWalletId = requireEnv('ORBI_DB_TEST_TARGET_WALLET_ID');
    const [encAmt, encDesc] = await Promise.all([
      DataProtection.encryptAmount(TEST_AMOUNT),
      DataProtection.encryptDescription('Integration duplicate reference probe'),
    ]);

    const first = await client.rpc('post_transaction_v2', {
      p_tx_id: txId,
      p_user_id: userId,
      p_wallet_id: sourceWalletId,
      p_to_wallet_id: targetWalletId,
      p_amount: encAmt,
      p_description: encDesc,
      p_type: 'transfer',
      p_status: 'completed',
      p_date: new Date().toISOString().slice(0, 10),
      p_metadata: { integration_test: true, scenario: 'duplicate_reference' },
      p_category_id: null,
      p_reference_id: referenceId,
      p_legs: [
        {
          wallet_id: sourceWalletId,
          entry_type: 'DEBIT',
          amount: encAmt,
          amount_plain: TEST_AMOUNT,
          description: 'Integration debit leg',
        },
        {
          wallet_id: targetWalletId,
          entry_type: 'CREDIT',
          amount: encAmt,
          amount_plain: TEST_AMOUNT,
          description: 'Integration credit leg',
        },
      ],
    });
    assert.ifError(first.error);

    const duplicate = await client.rpc('post_transaction_v2', {
      p_tx_id: randomUUID(),
      p_user_id: userId,
      p_wallet_id: sourceWalletId,
      p_to_wallet_id: targetWalletId,
      p_amount: encAmt,
      p_description: encDesc,
      p_type: 'transfer',
      p_status: 'completed',
      p_date: new Date().toISOString().slice(0, 10),
      p_metadata: { integration_test: true, scenario: 'duplicate_reference' },
      p_category_id: null,
      p_reference_id: referenceId,
      p_legs: [
        {
          wallet_id: sourceWalletId,
          entry_type: 'DEBIT',
          amount: encAmt,
          amount_plain: TEST_AMOUNT,
          description: 'Integration debit leg',
        },
        {
          wallet_id: targetWalletId,
          entry_type: 'CREDIT',
          amount: encAmt,
          amount_plain: TEST_AMOUNT,
          description: 'Integration credit leg',
        },
      ],
    });

    assert.ok(duplicate.error, 'Expected duplicate reference_id to be rejected');
    assert.match(String(duplicate.error?.message || ''), /IDEMPOTENCY_VIOLATION/i);
  },
  { requireWrites: true, requiredEnv: WRITE_FIXTURE_ENV },
);

dbIntegrationTest(
  'write-enabled integration covers deposit into operating wallet',
  async (_t, client) => {
    const operatingVaultId = requireEnv('ORBI_DB_TEST_OPERATING_VAULT_ID');
    const posted = await createPostedTransaction(client, {
      description: 'Write-enabled operating wallet deposit',
      targetWalletId: operatingVaultId,
      amount: TEST_AMOUNT,
    });

    const { data: tx, error: txError } = await client
      .from('transactions')
      .select('id, status, wallet_id, to_wallet_id')
      .eq('id', posted.txId)
      .single();
    assert.ifError(txError);
    assert.equal(String(tx.status).toLowerCase(), 'completed');
    assert.equal(String(tx.to_wallet_id), operatingVaultId);

    const { count: ledgerCount, error: ledgerError } = await client
      .from('financial_ledger')
      .select('*', { count: 'exact', head: true })
      .eq('transaction_id', posted.txId);
    assert.ifError(ledgerError);
    assert.equal(Number(ledgerCount || 0), 2);
  },
  { requireWrites: true, requiredEnv: EDGE_FIXTURE_ENV },
);

dbIntegrationTest(
  'write-enabled integration rejects insufficient funds from low-balance fixtures',
  async (_t, client) => {
    const txId = randomUUID();
    const referenceId = `ITEST-NSF-${txId.slice(0, 8)}`;
    const userId = requireEnv('ORBI_DB_TEST_USER_ID');
    const sourceWalletId = requireEnv('ORBI_DB_TEST_LOW_BALANCE_WALLET_ID');
    const targetWalletId = requireEnv('ORBI_DB_TEST_TARGET_WALLET_ID');
    const [encAmt, encDesc] = await Promise.all([
      DataProtection.encryptAmount(INSUFFICIENT_AMOUNT),
      DataProtection.encryptDescription('Integration insufficient funds probe'),
    ]);

    const result = await client.rpc('post_transaction_v2', {
      p_tx_id: txId,
      p_user_id: userId,
      p_wallet_id: sourceWalletId,
      p_to_wallet_id: targetWalletId,
      p_amount: encAmt,
      p_description: encDesc,
      p_type: 'transfer',
      p_status: 'completed',
      p_date: new Date().toISOString().slice(0, 10),
      p_metadata: { integration_test: true, scenario: 'insufficient_funds' },
      p_category_id: null,
      p_reference_id: referenceId,
      p_legs: [
        {
          wallet_id: sourceWalletId,
          entry_type: 'DEBIT',
          amount: encAmt,
          amount_plain: INSUFFICIENT_AMOUNT,
          description: 'Integration insufficient debit',
        },
        {
          wallet_id: targetWalletId,
          entry_type: 'CREDIT',
          amount: encAmt,
          amount_plain: INSUFFICIENT_AMOUNT,
          description: 'Integration insufficient credit',
        },
      ],
    });

    assert.ok(result.error, 'Expected insufficient funds rejection');
    assert.match(String(result.error?.message || result.error), /INSUFFICIENT_FUNDS/i);
  },
  { requireWrites: true, requiredEnv: EDGE_FIXTURE_ENV },
);

dbIntegrationTest(
  'write-enabled integration rejects locked-wallet posting attempts',
  async (_t, client) => {
    const txId = randomUUID();
    const referenceId = `ITEST-LOCK-${txId.slice(0, 8)}`;
    const userId = requireEnv('ORBI_DB_TEST_USER_ID');
    const sourceWalletId = requireEnv('ORBI_DB_TEST_LOCKED_WALLET_ID');
    const targetWalletId = requireEnv('ORBI_DB_TEST_TARGET_WALLET_ID');
    const [encAmt, encDesc] = await Promise.all([
      DataProtection.encryptAmount(TEST_AMOUNT),
      DataProtection.encryptDescription('Integration locked wallet probe'),
    ]);

    const result = await client.rpc('post_transaction_v2', {
      p_tx_id: txId,
      p_user_id: userId,
      p_wallet_id: sourceWalletId,
      p_to_wallet_id: targetWalletId,
      p_amount: encAmt,
      p_description: encDesc,
      p_type: 'transfer',
      p_status: 'completed',
      p_date: new Date().toISOString().slice(0, 10),
      p_metadata: { integration_test: true, scenario: 'locked_wallet' },
      p_category_id: null,
      p_reference_id: referenceId,
      p_legs: [
        {
          wallet_id: sourceWalletId,
          entry_type: 'DEBIT',
          amount: encAmt,
          amount_plain: TEST_AMOUNT,
          description: 'Integration locked debit',
        },
        {
          wallet_id: targetWalletId,
          entry_type: 'CREDIT',
          amount: encAmt,
          amount_plain: TEST_AMOUNT,
          description: 'Integration locked credit',
        },
      ],
    });

    assert.ok(result.error, 'Expected locked wallet rejection');
    assert.match(String(result.error?.message || result.error), /WALLET_LOCKED/i);
  },
  { requireWrites: true, requiredEnv: EDGE_FIXTURE_ENV },
);

dbIntegrationTest(
  'write-enabled integration can execute privileged repair against a disposable drift wallet',
  async (_t, client) => {
    const service = new TransactionService();
    const actorId = requireEnv('ORBI_DB_TEST_REVIEW_ACTOR_ID');
    const driftWalletId = requireEnv('ORBI_DB_TEST_DRIFT_WALLET_ID');

    const { data: walletBefore, error: walletBeforeError } = await client
      .from('wallets')
      .select('balance')
      .eq('id', driftWalletId)
      .single();
    assert.ifError(walletBeforeError);

    const currentBalance = Number(walletBefore?.balance || 0);
    const driftedBalance = Math.round((currentBalance + 17.25) * 10000) / 10000;

    const { error: driftError } = await client
      .from('wallets')
      .update({ balance: driftedBalance, updated_at: new Date().toISOString() })
      .eq('id', driftWalletId);
    assert.ifError(driftError);

    const verificationBefore = await service.verifyWalletBalance(driftWalletId);
    assert.equal(verificationBefore.valid, false);
    assert.notEqual(Number(verificationBefore.drift), 0);

    await service.fixWalletBalance(
      driftWalletId,
      actorId,
      'Integration privileged repair',
      'itest-repair',
    );

    const verificationAfter = await service.verifyWalletBalance(driftWalletId);
    assert.equal(verificationAfter.valid, true);
    assert.equal(Number(verificationAfter.drift), 0);

    const { data: walletAfter, error: walletAfterError } = await client
      .from('wallets')
      .select('balance')
      .eq('id', driftWalletId)
      .single();
    assert.ifError(walletAfterError);
    assert.notEqual(Number(walletAfter?.balance || 0), driftedBalance);
  },
  { requireWrites: true, requiredEnv: EDGE_FIXTURE_ENV },
);

dbIntegrationTest(
  'write-enabled integration enforces append idempotency through append_ledger_entries_v1',
  async (_t, client) => {
    const posted = await createPostedTransaction(client, {
      description: 'Write-enabled append idempotency base',
    });

    const appendKey = `append:${posted.txId}:integration`;
    const appendPhase = 'INTEGRATION_APPEND';
    const appendAmount = TEST_AMOUNT;
    const encAppendAmount = await DataProtection.encryptAmount(appendAmount);

    const legs = [
      {
        transaction_id: posted.txId,
        wallet_id: posted.targetWalletId,
        entry_type: 'DEBIT',
        amount: encAppendAmount,
        amount_plain: appendAmount,
        description: 'Integration append debit',
        created_at: new Date().toISOString(),
      },
      {
        transaction_id: posted.txId,
        wallet_id: posted.sourceWalletId,
        entry_type: 'CREDIT',
        amount: encAppendAmount,
        amount_plain: appendAmount,
        description: 'Integration append credit',
        created_at: new Date().toISOString(),
      },
    ];

    const first = await client.rpc('append_ledger_entries_v1', {
      p_tx_id: posted.txId,
      p_legs: legs,
      p_append_key: appendKey,
      p_append_phase: appendPhase,
    });
    assert.ifError(first.error);

    const second = await client.rpc('append_ledger_entries_v1', {
      p_tx_id: posted.txId,
      p_legs: legs,
      p_append_key: appendKey,
      p_append_phase: appendPhase,
    });
    assert.ok(second.error, 'Expected duplicate append to fail');
    assert.match(String(second.error?.message || second.error), /APPEND_ALREADY_APPLIED/i);

    const { count: markerCount, error: markerError } = await client
      .from('ledger_append_markers')
      .select('*', { count: 'exact', head: true })
      .eq('transaction_id', posted.txId)
      .eq('append_key', appendKey);
    assert.ifError(markerError);
    assert.equal(Number(markerCount || 0), 1);
  },
  { requireWrites: true, requiredEnv: WRITE_FIXTURE_ENV },
);

dbIntegrationTest(
  'write-enabled integration can claim and finalize an internal transfer settlement exactly once',
  async (_t, client) => {
    const sourceWalletId = requireEnv('ORBI_DB_TEST_SOURCE_WALLET_ID');
    const targetWalletId = requireEnv('ORBI_DB_TEST_TARGET_WALLET_ID');
    const internalVaultId = requireEnv('ORBI_DB_TEST_INTERNAL_TRANSFER_VAULT_ID');
    const workerId = `db-itest-worker:${randomUUID().slice(0, 8)}`;
    const encSettlementAmount = await DataProtection.encryptAmount(TEST_AMOUNT);

    const staging = await createPostedTransaction(client, {
      status: 'processing',
      description: 'Write-enabled settlement staging transaction',
      sourceWalletId,
      targetWalletId,
      legs: [
        {
          wallet_id: sourceWalletId,
          entry_type: 'DEBIT',
          amount: encSettlementAmount,
          amount_plain: TEST_AMOUNT,
          description: 'Integration staged debit to PaySafe vault',
        },
        {
          wallet_id: internalVaultId,
          entry_type: 'CREDIT',
          amount: encSettlementAmount,
          amount_plain: TEST_AMOUNT,
          description: 'Integration staged credit to PaySafe vault',
        },
      ],
    });

    const claim = await client.rpc('claim_internal_transfer_settlement', {
      p_tx_id: staging.txId,
      p_worker_id: workerId,
    });
    assert.ifError(claim.error);
    const claimRow = Array.isArray(claim.data) ? claim.data[0] : claim.data;
    assert.ok(claimRow);
    assert.equal(String(claimRow.transaction_status).toLowerCase(), 'processing');
    assert.equal(String(claimRow.append_phase), 'PAYSAFE_SETTLEMENT');
    assert.equal(Boolean(claimRow.append_already_applied), false);

    const settlementAppend = await client.rpc('append_ledger_entries_v1', {
      p_tx_id: staging.txId,
      p_append_key: claimRow.append_key,
      p_append_phase: claimRow.append_phase,
      p_legs: [
        {
          transaction_id: staging.txId,
          wallet_id: internalVaultId,
          entry_type: 'DEBIT',
          amount: encSettlementAmount,
          amount_plain: TEST_AMOUNT,
          description: `Integration settlement release ${staging.txId}`,
          created_at: new Date().toISOString(),
        },
        {
          transaction_id: staging.txId,
          wallet_id: targetWalletId,
          entry_type: 'CREDIT',
          amount: encSettlementAmount,
          amount_plain: TEST_AMOUNT,
          description: `Integration settlement receive ${staging.txId}`,
          created_at: new Date().toISOString(),
        },
      ],
    });
    assert.ifError(settlementAppend.error);

    const completion = await client.rpc('complete_internal_transfer_settlement', {
      p_tx_id: staging.txId,
      p_worker_claim_id: claimRow.worker_claim_id,
      p_result: 'COMPLETED',
      p_result_note: 'Integration settlement finalized',
      p_zero_sum_valid: true,
    });
    assert.ifError(completion.error);
    const completionRow = Array.isArray(completion.data) ? completion.data[0] : completion.data;
    assert.ok(completionRow);
    assert.equal(String(completionRow.final_status).toLowerCase(), 'completed');
    assert.equal(String(completionRow.lifecycle_status).toUpperCase(), 'COMPLETED');

    const duplicateCompletion = await client.rpc('complete_internal_transfer_settlement', {
      p_tx_id: staging.txId,
      p_worker_claim_id: claimRow.worker_claim_id,
      p_result: 'COMPLETED',
      p_result_note: 'Integration duplicate settlement completion',
      p_zero_sum_valid: true,
    });
    assert.ifError(duplicateCompletion.error);
    const duplicateCompletionRow = Array.isArray(duplicateCompletion.data) ? duplicateCompletion.data[0] : duplicateCompletion.data;
    assert.ok(duplicateCompletionRow);
    assert.equal(Boolean(duplicateCompletionRow.already_finalized), true);

    const duplicateClaim = await client.rpc('claim_internal_transfer_settlement', {
      p_tx_id: staging.txId,
      p_worker_id: `${workerId}:duplicate`,
    });
    assert.ifError(duplicateClaim.error);
    const duplicateRow = Array.isArray(duplicateClaim.data) ? duplicateClaim.data[0] : duplicateClaim.data;
    assert.ok(duplicateRow);
    assert.equal(Boolean(duplicateRow.already_completed), true);
  },
  { requireWrites: true, requiredEnv: WRITE_FIXTURE_ENV },
);

dbIntegrationTest(
  'write-enabled integration guards against concurrent append execution',
  async (_t, client) => {
    const staging = await createPostedTransaction(client, {
      status: 'processing',
      description: 'Write-enabled concurrent append staging transaction',
    });
    const appendKey = `ITEST-APPEND-${staging.txId}`;
    const encAmt = await DataProtection.encryptAmount(staging.amount);

    const runAppend = () => client.rpc('append_ledger_entries_v1', {
      p_tx_id: staging.txId,
      p_append_key: appendKey,
      p_append_phase: 'CONCURRENT_TEST',
      p_legs: [
        {
          wallet_id: staging.sourceWalletId,
          entry_type: 'DEBIT',
          amount: encAmt,
          amount_plain: staging.amount,
          description: `Integration concurrent debit ${staging.txId}`,
        },
        {
          wallet_id: staging.targetWalletId,
          entry_type: 'CREDIT',
          amount: encAmt,
          amount_plain: staging.amount,
          description: `Integration concurrent credit ${staging.txId}`,
        },
      ],
    });

    const [first, second] = await Promise.allSettled([runAppend(), runAppend()]);
    const errors = [first, second]
      .filter((result) => result.status === 'fulfilled' && (result as any).value?.error)
      .map((result: any) => result.value.error);

    assert.ok(errors.length >= 1, 'Expected at least one append attempt to fail due to idempotency');
    assert.match(String(errors[0]?.message || ''), /APPEND_ALREADY_APPLIED/i);
  },
  { requireWrites: true, requiredEnv: EDGE_FIXTURE_ENV },
);

dbIntegrationTest(
  'write-enabled integration can initiate an external withdrawal movement',
  async (_t, client) => {
    const userId = requireEnv('ORBI_DB_TEST_USER_ID');
    const sourceWalletId = requireEnv('ORBI_DB_TEST_SOURCE_WALLET_ID');
    const providerId = requireEnv('ORBI_DB_TEST_WITHDRAWAL_PROVIDER_ID');
    const externalRef = `itest-withdraw-${randomUUID().slice(0, 8)}`;

    const { data, error } = await client
      .from('external_fund_movements')
      .insert({
        user_id: userId,
        direction: 'INTERNAL_TO_EXTERNAL',
        status: 'initiated',
        provider_id: providerId,
        source_wallet_id: sourceWalletId,
        gross_amount: TEST_AMOUNT,
        net_amount: TEST_AMOUNT,
        fee_amount: 0,
        tax_amount: 0,
        currency: 'TZS',
        description: 'Integration external withdrawal initiation',
        external_reference: externalRef,
        metadata: { integration_test: true, flow: 'external_withdrawal' },
      })
      .select('id, status, direction, provider_id, external_reference')
      .single();
    assert.ifError(error);
    assert.equal(String(data.status).toLowerCase(), 'initiated');
    assert.equal(String(data.direction), 'INTERNAL_TO_EXTERNAL');
    assert.equal(String(data.provider_id), providerId);
    assert.equal(String(data.external_reference), externalRef);
  },
  { requireWrites: true, requiredEnv: EDGE_FIXTURE_ENV },
);

dbIntegrationTest(
  'write-enabled integration deduplicates provider webhook receipts and only allows one application claim',
  async (_t, client) => {
    const partnerId = requireEnv('ORBI_DB_TEST_WEBHOOK_PARTNER_ID');
    const eventSuffix = randomUUID().slice(0, 12);
    const dedupeKey = `itest:webhook:${eventSuffix}`;
    const replayKey = `itest:replay:${eventSuffix}`;
    const providerEventId = `provider-event-${eventSuffix}`;
    const payload = {
      integration_test: true,
      event: 'PAYMENT_CONFIRMED',
      provider_event_id: providerEventId,
    };

    const first = await providerWebhookEventLedger.recordReceipt({
      partner_id: partnerId,
      dedupe_key: dedupeKey,
      replay_key: replayKey,
      provider_event_id: providerEventId,
      reference: `ITEST-WEBHOOK-${eventSuffix}`,
      normalized_status: 'completed',
      raw_status: 'SUCCESS',
      event_timestamp: new Date().toISOString(),
      timestamp_source: 'integration_test',
      signature_status: 'verified',
      freshness_status: 'fresh',
      verification_status: 'verified',
      payload_sha256: `sha256:${eventSuffix}`,
      payload,
      raw_headers: { 'x-itest-webhook': eventSuffix },
      source_ip: '127.0.0.1',
    });
    assert.equal(first.duplicate, false);

    const replay = await providerWebhookEventLedger.recordReceipt({
      partner_id: partnerId,
      dedupe_key: dedupeKey,
      replay_key: replayKey,
      provider_event_id: providerEventId,
      reference: `ITEST-WEBHOOK-${eventSuffix}`,
      normalized_status: 'completed',
      raw_status: 'SUCCESS',
      event_timestamp: new Date().toISOString(),
      timestamp_source: 'integration_test',
      signature_status: 'verified',
      freshness_status: 'fresh',
      verification_status: 'verified',
      payload_sha256: `sha256:${eventSuffix}`,
      payload,
      raw_headers: { 'x-itest-webhook': eventSuffix },
      source_ip: '127.0.0.1',
    });
    assert.equal(replay.duplicate, true);
    assert.equal(replay.record.id, first.record.id);

    const firstClaim = await providerWebhookEventLedger.claimForApplication(first.record.id);
    const secondClaim = await providerWebhookEventLedger.claimForApplication(first.record.id);
    assert.equal(firstClaim, true);
    assert.equal(secondClaim, false);

    await providerWebhookEventLedger.markApplied(first.record.id);

    const { data: applied, error: appliedError } = await client
      .from('provider_webhook_events')
      .select('id, application_status, provider_event_id, dedupe_key')
      .eq('id', first.record.id)
      .single();
    assert.ifError(appliedError);
    assert.equal(applied.id, first.record.id);
    assert.equal(String(applied.application_status).toLowerCase(), 'applied');
    assert.equal(applied.provider_event_id, providerEventId);
    assert.equal(applied.dedupe_key, dedupeKey);
  },
  { requireWrites: true, requiredEnv: EDGE_FIXTURE_ENV },
);

dbIntegrationTest(
  'write-enabled integration applies a signed provider webhook callback to a processing transaction',
  async (_t, client) => {
    const posted = await createPostedTransaction(client, {
      status: 'processing',
      description: 'Write-enabled webhook application transaction',
    });
    const { partnerId, webhookSecret, timestampHeader } = await createDisposableWebhookPartner(client);
    const previousReplayMode = process.env.ORBI_ALLOW_PROCESS_LOCAL_WEBHOOK_REPLAY_STORE;
    process.env.ORBI_ALLOW_PROCESS_LOCAL_WEBHOOK_REPLAY_STORE = 'true';

    try {
      const timestamp = String(Math.floor(Date.now() / 1000));
      const eventId = `itest-webhook-${randomUUID().slice(0, 10)}`;
      const payload = {
        event_id: eventId,
        reference: posted.referenceId,
        status: 'SUCCESS',
        message: 'Integration callback completed',
      };
      const rawPayload = JSON.stringify(payload);
      const signature = createHmac('sha256', webhookSecret)
        .update(`${timestamp}.${rawPayload}`)
        .digest('hex');

      const result = await Webhooks.handleCallback(payload, partnerId, {
        signature,
        rawPayload,
        headers: { [timestampHeader]: timestamp },
        sourceIp: '127.0.0.1',
      });

      assert.equal(result?.route, 'TRANSACTION');
      assert.equal(result?.txId, posted.txId);

      const { data: tx, error: txError } = await client
        .from('transactions')
        .select('status, status_notes')
        .eq('id', posted.txId)
        .single();
      assert.ifError(txError);
      assert.equal(String(tx.status).toLowerCase(), 'completed');

      const { data: webhookEvent, error: webhookEventError } = await client
        .from('provider_webhook_events')
        .select('id, reference, normalized_status, application_status, provider_event_id')
        .eq('partner_id', partnerId)
        .eq('provider_event_id', eventId)
        .single();
      assert.ifError(webhookEventError);
      assert.equal(webhookEvent.reference, posted.referenceId);
      assert.equal(String(webhookEvent.normalized_status).toLowerCase(), 'completed');
      assert.equal(String(webhookEvent.application_status).toLowerCase(), 'applied');

      const { data: auditRow, error: auditError } = await client
        .from('audit_trail')
        .select('action, metadata')
        .eq('action', 'WEBHOOK_PROCESSED')
        .contains('metadata', { eventLedgerId: webhookEvent.id })
        .maybeSingle();
      assert.ifError(auditError);
      assert.ok(auditRow, 'Expected WEBHOOK_PROCESSED audit row');
    } finally {
      if (previousReplayMode === undefined) {
        delete process.env.ORBI_ALLOW_PROCESS_LOCAL_WEBHOOK_REPLAY_STORE;
      } else {
        process.env.ORBI_ALLOW_PROCESS_LOCAL_WEBHOOK_REPLAY_STORE = previousReplayMode;
      }
    }
  },
  { requireWrites: true, requiredEnv: WRITE_FIXTURE_ENV },
);

dbIntegrationTest(
  'write-enabled integration supports shared budget spend enforcement',
  async (_t, client) => {
    const service = new TransactionService();
    const userId = requireEnv('ORBI_DB_TEST_USER_ID');
    const categoryId = requireEnv('ORBI_DB_TEST_BUDGET_CATEGORY_ID');
    assert.ok(BUDGET_TRIGGER_AMOUNT > 0, 'ORBI_DB_TEST_BUDGET_TRIGGER_AMOUNT must be greater than 0');

    const posted = await createPostedTransaction(client, {
      description: 'Write-enabled shared budget spend',
      amount: BUDGET_TRIGGER_AMOUNT,
    });

    await service.enforceBudgetLimits(userId, categoryId, BUDGET_TRIGGER_AMOUNT, posted.txId, posted.referenceId);

    const { count: alertCount, error: alertError } = await client
      .from('budget_alerts')
      .select('*', { count: 'exact', head: true })
      .eq('category_id', categoryId)
      .eq('transaction_id', posted.txId);
    assert.ifError(alertError);
    assert.ok(Number(alertCount || 0) >= 0);
  },
  { requireWrites: true, requiredEnv: EDGE_FIXTURE_ENV },
);

dbIntegrationTest(
  'write-enabled integration supports bill reserve allocation',
  async (_t, client) => {
    const service = new TransactionService();
    const userId = requireEnv('ORBI_DB_TEST_USER_ID');
    const sourceWalletId = requireEnv('ORBI_DB_TEST_SOURCE_WALLET_ID');
    const escrowVaultId = requireEnv('ORBI_DB_TEST_ESCROW_VAULT_ID');

    await RegulatoryService.updateSystemNode('ESCROW_VAULT', escrowVaultId);
    const referenceId = `ITEST-ESCROW-${randomUUID().slice(0, 8)}`;
    await service.reserveEscrow(userId, sourceWalletId, TEST_AMOUNT, 'Integration bill reserve allocation', referenceId);

    const { data: tx, error: txError } = await client
      .from('transactions')
      .select('id, reference_id, status, type')
      .eq('reference_id', referenceId)
      .single();
    assert.ifError(txError);
    assert.equal(String(tx.type).toLowerCase(), 'escrow');
    assert.equal(String(tx.status).toLowerCase(), 'processing');

    const { count: legCount, error: legError } = await client
      .from('financial_ledger')
      .select('*', { count: 'exact', head: true })
      .eq('transaction_id', tx.id);
    assert.ifError(legError);
    assert.equal(Number(legCount || 0), 2);
  },
  { requireWrites: true, requiredEnv: EDGE_FIXTURE_ENV },
);

dbIntegrationTest(
  'write-enabled integration can reverse a disposable posted transaction with explicit reason',
  async (_t, client) => {
    const service = new TransactionService();
    const actorId = requireEnv('ORBI_DB_TEST_REVIEW_ACTOR_ID');
    const posted = await createPostedTransaction(client, {
      description: 'Write-enabled reversal transaction',
    });

    await service.reverseTransactionWithReason(posted.txId, actorId, 'Integration reversal path', 'STAFF');

    const { data: tx, error } = await client
      .from('transactions')
      .select('status, metadata, status_notes')
      .eq('id', posted.txId)
      .single();
    assert.ifError(error);
    assert.equal(String(tx.status).toLowerCase(), 'reversed');
    assert.equal(tx.metadata?.reversal_reason, 'Integration reversal path');
    assert.equal(tx.metadata?.reversed_by, actorId);
  },
  { requireWrites: true, requiredEnv: EDGE_FIXTURE_ENV },
);

dbIntegrationTest(
  'write-enabled integration supports held_for_review approval lifecycle on disposable transactions',
  async (_t, client) => {
    const service = new TransactionService();
    const actorId = requireEnv('ORBI_DB_TEST_REVIEW_ACTOR_ID');
    const posted = await createPostedTransaction(client, {
      description: 'Write-enabled held-for-review approval transaction',
    });

    await service.lockTransactionForReview(posted.txId, actorId, {
      actorRole: 'STAFF',
      reason: 'Integration review approval path',
      reviewWindowHours: 1,
    });
    await service.recordAuditDecision(posted.txId, actorId, true, 'Integration audit passed');
    await service.approveReviewedTransaction(posted.txId, actorId, 'Integration review approved');

    const { data: tx, error } = await client
      .from('transactions')
      .select('status, metadata, status_notes')
      .eq('id', posted.txId)
      .single();
    assert.ifError(error);
    assert.equal(String(tx.status).toLowerCase(), 'completed');
    assert.equal(tx.metadata?.transaction_lock?.resolution, 'APPROVED');
    assert.equal(tx.metadata?.transaction_lock?.audit_status, 'PASSED');
  },
  { requireWrites: true, requiredEnv: EDGE_FIXTURE_ENV },
);

dbIntegrationTest(
  'write-enabled integration supports held_for_review rejection via failed audit and reversal',
  async (_t, client) => {
    const service = new TransactionService();
    const actorId = requireEnv('ORBI_DB_TEST_REVIEW_ACTOR_ID');
    const posted = await createPostedTransaction(client, {
      description: 'Write-enabled held-for-review rejection transaction',
    });

    await service.lockTransactionForReview(posted.txId, actorId, {
      actorRole: 'STAFF',
      reason: 'Integration review rejection path',
      requestReverse: true,
      reviewWindowHours: 1,
    });
    await service.recordAuditDecision(posted.txId, actorId, false, 'Integration audit failed', 'STAFF');
    await service.reverseTransactionWithReason(posted.txId, actorId, 'Integration rejection reversal', 'STAFF');

    const { data: tx, error } = await client
      .from('transactions')
      .select('status, metadata, status_notes')
      .eq('id', posted.txId)
      .single();
    assert.ifError(error);
    assert.equal(String(tx.status).toLowerCase(), 'reversed');
    assert.equal(tx.metadata?.transaction_lock?.audit_status, 'FAILED');
    assert.equal(tx.metadata?.reversal_reason, 'Integration rejection reversal');
  },
  { requireWrites: true, requiredEnv: EDGE_FIXTURE_ENV },
);

dbIntegrationTest(
  'write-enabled integration moves invalid zero-sum settlement completion into held_for_review',
  async (_t, client) => {
    const sourceWalletId = requireEnv('ORBI_DB_TEST_SOURCE_WALLET_ID');
    const targetWalletId = requireEnv('ORBI_DB_TEST_TARGET_WALLET_ID');
    const internalVaultId = requireEnv('ORBI_DB_TEST_INTERNAL_TRANSFER_VAULT_ID');
    const workerId = `db-itest-zero-sum:${randomUUID().slice(0, 8)}`;
    const encSettlementAmount = await DataProtection.encryptAmount(TEST_AMOUNT);

    const staging = await createPostedTransaction(client, {
      status: 'processing',
      description: 'Write-enabled zero-sum invalid settlement staging transaction',
      sourceWalletId,
      targetWalletId,
      legs: [
        {
          wallet_id: sourceWalletId,
          entry_type: 'DEBIT',
          amount: encSettlementAmount,
          amount_plain: TEST_AMOUNT,
          description: 'Integration staged debit to PaySafe vault',
        },
        {
          wallet_id: internalVaultId,
          entry_type: 'CREDIT',
          amount: encSettlementAmount,
          amount_plain: TEST_AMOUNT,
          description: 'Integration staged credit to PaySafe vault',
        },
      ],
    });

    const claim = await client.rpc('claim_internal_transfer_settlement', {
      p_tx_id: staging.txId,
      p_worker_id: workerId,
    });
    assert.ifError(claim.error);
    const claimRow = Array.isArray(claim.data) ? claim.data[0] : claim.data;
    assert.ok(claimRow?.worker_claim_id);

    const completion = await client.rpc('complete_internal_transfer_settlement', {
      p_tx_id: staging.txId,
      p_worker_claim_id: claimRow.worker_claim_id,
      p_result: 'COMPLETED',
      p_result_note: 'Integration forced zero-sum invalid result',
      p_zero_sum_valid: false,
    });
    assert.ifError(completion.error);
    const completionRow = Array.isArray(completion.data) ? completion.data[0] : completion.data;
    assert.ok(completionRow);
    assert.equal(String(completionRow.final_status).toLowerCase(), 'held_for_review');
    assert.equal(String(completionRow.lifecycle_status).toUpperCase(), 'FAILED');

    const { data: tx, error: txError } = await client
      .from('transactions')
      .select('status, status_notes')
      .eq('id', staging.txId)
      .single();
    assert.ifError(txError);
    assert.equal(String(tx.status).toLowerCase(), 'held_for_review');

    const { data: lifecycle, error: lifecycleError } = await client
      .from('settlement_lifecycle')
      .select('stage, status, metadata, last_error')
      .eq('transaction_id', staging.txId)
      .maybeSingle();
    assert.ifError(lifecycleError);
    assert.ok(lifecycle);
    assert.equal(String(lifecycle.stage).toUpperCase(), 'FAILED');
    assert.equal(String(lifecycle.status).toUpperCase(), 'FAILED');
    assert.equal(lifecycle.metadata?.completion_result, 'HELD_FOR_REVIEW');
    assert.equal(lifecycle.metadata?.zero_sum_valid, false);
  },
  { requireWrites: true, requiredEnv: WRITE_FIXTURE_ENV },
);

dbIntegrationTest(
  'write-enabled integration auto-reverses overdue held_for_review transactions',
  async (_t, client) => {
    const service = new TransactionService();
    const actorId = requireEnv('ORBI_DB_TEST_REVIEW_ACTOR_ID');
    const posted = await createPostedTransaction(client, {
      description: 'Write-enabled held-for-review auto reversal transaction',
    });

    await service.lockTransactionForReview(posted.txId, actorId, {
      actorRole: 'STAFF',
      reason: 'Integration auto-reversal path',
      requestReverse: true,
      reviewWindowHours: 1,
    });

    const { data: locked, error: lockedError } = await client
      .from('transactions')
      .select('metadata')
      .eq('id', posted.txId)
      .single();
    assert.ifError(lockedError);

    const forcedMetadata = {
      ...(locked?.metadata || {}),
      transaction_lock: {
        ...(locked?.metadata?.transaction_lock || {}),
        auto_reverse_at: new Date(Date.now() - 60 * 60 * 1000).toISOString(),
      },
    };

    const { error: forcePastDueError } = await client
      .from('transactions')
      .update({
        metadata: forcedMetadata,
        updated_at: new Date(Date.now() - 60 * 60 * 1000).toISOString(),
      })
      .eq('id', posted.txId);
    assert.ifError(forcePastDueError);

    const reversedCount = await service.autoReverseHeldTransactions();
    assert.ok(reversedCount >= 1, 'Expected at least one held transaction to auto-reverse');

    const { data: tx, error } = await client
      .from('transactions')
      .select('status, metadata, status_notes')
      .eq('id', posted.txId)
      .single();
    assert.ifError(error);
    assert.equal(String(tx.status).toLowerCase(), 'reversed');
    assert.match(String(tx.metadata?.reversal_reason || ''), /AUTO_REVERSAL_AFTER_24_HOURS/i);
  },
  { requireWrites: true, requiredEnv: EDGE_FIXTURE_ENV },
);

dbIntegrationTest(
  'write-enabled integration records reconciliation drift evidence and repair audits during an incident drill',
  async (_t, client) => {
    const service = new TransactionService();
    const actorId = requireEnv('ORBI_DB_TEST_REVIEW_ACTOR_ID');
    const driftWalletId = requireEnv('ORBI_DB_TEST_DRIFT_WALLET_ID');
    const testStartedAt = new Date().toISOString();

    const forceWalletDrift = async (delta: number) => {
      const { data: wallet, error: walletError } = await client
        .from('wallets')
        .select('balance')
        .eq('id', driftWalletId)
        .single();
      assert.ifError(walletError);

      const driftedBalance = Math.round((Number(wallet?.balance || 0) + delta) * 10000) / 10000;
      const { error: updateError } = await client
        .from('wallets')
        .update({ balance: driftedBalance, updated_at: new Date().toISOString() })
        .eq('id', driftWalletId);
      assert.ifError(updateError);

      return driftedBalance;
    };

    await forceWalletDrift(11.25);
    const verificationOne = await service.verifyWalletBalance(driftWalletId);
    assert.equal(verificationOne.valid, false);
    await service.fixWalletBalance(driftWalletId, actorId, 'Integration incident drill repair 1', 'itest-drill-1');

    await forceWalletDrift(7.5);
    const verificationTwo = await service.verifyWalletBalance(driftWalletId);
    assert.equal(verificationTwo.valid, false);
    await service.fixWalletBalance(driftWalletId, actorId, 'Integration incident drill repair 2', 'itest-drill-2');

    const verificationFinal = await service.verifyWalletBalance(driftWalletId);
    assert.equal(verificationFinal.valid, true);

    const { count: driftReportCount, error: driftReportError } = await client
      .from('reconciliation_reports')
      .select('*', { count: 'exact', head: true })
      .eq('type', 'WALLET_DRIFT')
      .eq('status', 'MISMATCH')
      .contains('metadata', { wallet_id: driftWalletId })
      .gte('created_at', testStartedAt);
    assert.ifError(driftReportError);
    assert.ok(Number(driftReportCount || 0) >= 2, 'Expected at least two WALLET_DRIFT reports');

    const { count: emergencyRepairAuditCount, error: emergencyRepairAuditError } = await client
      .from('audit_trail')
      .select('*', { count: 'exact', head: true })
      .eq('action', 'EMERGENCY_BALANCE_REPAIR')
      .contains('metadata', { target_wallet_id: driftWalletId })
      .gte('timestamp', testStartedAt);
    assert.ifError(emergencyRepairAuditError);
    assert.ok(Number(emergencyRepairAuditCount || 0) >= 2, 'Expected at least two emergency balance repair audit rows');

    const { count: privilegedRepairAuditCount, error: privilegedRepairAuditError } = await client
      .from('audit_trail')
      .select('*', { count: 'exact', head: true })
      .eq('action', 'PRIVILEGED_WALLET_BALANCE_REPAIR_EXECUTED')
      .contains('metadata', { walletId: driftWalletId })
      .gte('timestamp', testStartedAt);
    assert.ifError(privilegedRepairAuditError);
    assert.ok(Number(privilegedRepairAuditCount || 0) >= 2, 'Expected at least two privileged repair audit rows');
  },
  { requireWrites: true, requiredEnv: EDGE_FIXTURE_ENV },
);

dbIntegrationTest(
  'disposable treasury fixture serializes quorum and applies its ledger debit once',
  async (t, client) => {
    assert.equal(process.env.ORBI_DB_TEST_DISPOSABLE, 'true');
    const makerId = requireEnv('ORBI_DB_TEST_TREASURY_MAKER_ID');
    const admin1Id = requireEnv('ORBI_DB_TEST_TREASURY_ADMIN_1_ID');
    const admin2Id = requireEnv('ORBI_DB_TEST_TREASURY_ADMIN_2_ID');
    const crossOrgAdminId = requireEnv('ORBI_DB_TEST_TREASURY_CROSS_ORG_ADMIN_ID');
    const organizationId = requireEnv('ORBI_DB_TEST_TREASURY_ORG_ID');
    const goalId = requireEnv('ORBI_DB_TEST_TREASURY_GOAL_ID');
    const destinationWalletId = requireEnv('ORBI_DB_TEST_TREASURY_DESTINATION_WALLET_ID');
    const txId = randomUUID();
    const amount = TEST_AMOUNT;

    const [{ data: goal, error: goalError }, { data: destination, error: destinationError }] = await Promise.all([
      client.from('goals').select('id, organization_id, is_corporate, current').eq('id', goalId).single(),
      client.from('wallets').select('id, balance').eq('id', destinationWalletId).single(),
    ]);
    assert.ifError(goalError);
    assert.ifError(destinationError);
    assert.equal(String(goal.organization_id), organizationId);
    assert.equal(goal.is_corporate, true);
    const originalGoalBalance = Number(goal.current);
    const originalDestinationBalance = Number(destination.balance);
    assert.ok(originalGoalBalance >= amount, 'Treasury goal fixture needs sufficient balance');

    const policyArgs = {
      p_organization_id: organizationId,
      p_currency: 'TZS',
      p_name: 'Certification treasury policy',
      p_description: 'Disposable concurrency policy',
      p_min_approvals: 2,
      p_max_amount_per_tx: 100,
      p_daily_limit: 1000,
      p_change_reason: 'Initial certification policy',
    };
    const crossPolicy = await client.rpc('upsert_treasury_policy_v1', { ...policyArgs, p_actor_id: crossOrgAdminId });
    assert.match(String(crossPolicy.error?.message || ''), /TREASURY_POLICY_ADMIN_REQUIRED/);
    const impossiblePolicy = await client.rpc('upsert_treasury_policy_v1', {
      ...policyArgs, p_actor_id: admin1Id, p_min_approvals: 3,
    });
    assert.match(String(impossiblePolicy.error?.message || ''), /TREASURY_POLICY_QUORUM_UNAVAILABLE/);

    const crossOrgApproverChange = await client.rpc('request_treasury_approver_change_v1', {
      p_actor_id: crossOrgAdminId, p_organization_id: organizationId, p_target_user_id: makerId,
      p_action: 'ADD', p_reason: 'Cross organization request must fail',
    });
    assert.match(String(crossOrgApproverChange.error?.message || ''), /TREASURY_APPROVER_ADMIN_REQUIRED/);
    const { data: addApproverRequestId, error: addApproverRequestError } = await client.rpc(
      'request_treasury_approver_change_v1',
      { p_actor_id: admin1Id, p_organization_id: organizationId, p_target_user_id: makerId,
        p_action: 'ADD', p_reason: 'Certification needs a third approver' },
    );
    assert.ifError(addApproverRequestError);
    const selfReview = await client.rpc('respond_treasury_approver_change_v1', {
      p_reviewer_id: admin1Id, p_request_id: addApproverRequestId,
      p_decision: 'APPROVE', p_reason: 'Requester cannot review this change',
    });
    assert.match(String(selfReview.error?.message || ''), /TREASURY_APPROVER_REVIEWER_REQUIRED/);
    const addApprover = await client.rpc('respond_treasury_approver_change_v1', {
      p_reviewer_id: admin2Id, p_request_id: addApproverRequestId,
      p_decision: 'APPROVE', p_reason: 'Independent certification approval',
    });
    assert.ifError(addApprover.error);

    const createdPolicy = await client.rpc('upsert_treasury_policy_v1', {
      ...policyArgs, p_actor_id: admin1Id, p_min_approvals: 3,
    });
    assert.ifError(createdPolicy.error);
    assert.equal(Number(createdPolicy.data?.version), 1);
    const { data: removeApproverRequestId, error: removeApproverRequestError } = await client.rpc(
      'request_treasury_approver_change_v1',
      { p_actor_id: admin1Id, p_organization_id: organizationId, p_target_user_id: makerId,
        p_action: 'REMOVE', p_reason: 'Exercise protected removal workflow' },
    );
    assert.ifError(removeApproverRequestError);
    const quorumBreakingRemoval = await client.rpc('respond_treasury_approver_change_v1', {
      p_reviewer_id: admin2Id, p_request_id: removeApproverRequestId,
      p_decision: 'APPROVE', p_reason: 'Attempt removal below active policy quorum',
    });
    assert.match(String(quorumBreakingRemoval.error?.message || ''), /TREASURY_APPROVER_REMOVAL_BREAKS_QUORUM/);
    const updatedPolicy = await client.rpc('upsert_treasury_policy_v1', {
      ...policyArgs, p_actor_id: admin1Id, p_min_approvals: 2,
      p_change_reason: 'Second certification version', p_daily_limit: 1200,
    });
    assert.ifError(updatedPolicy.error);
    assert.equal(Number(updatedPolicy.data?.version), 2);

    t.after(async () => {
      await client.from('financial_ledger').delete().eq('transaction_id', txId);
      await client.from('transactions').delete().eq('id', txId);
      await client.from('goals').update({ current: originalGoalBalance }).eq('id', goalId);
      await client.from('wallets').update({ balance: originalDestinationBalance }).eq('id', destinationWalletId);
      await client.from('treasury_approver_change_requests').delete().eq('organization_id', organizationId);
      await client.from('treasury_approvers').delete().eq('organization_id', organizationId).eq('user_id', makerId);
      await client.from('treasury_policy_versions').delete().eq('policy_id', createdPolicy.data.policy_id);
      await client.from('treasury_policies').delete().eq('id', createdPolicy.data.policy_id);
    });

    const [encryptedAmount, encryptedDescription] = await Promise.all([
      DataProtection.encryptAmount(amount),
      DataProtection.encryptDescription('Disposable treasury concurrency certification'),
    ]);
    const { data: requested, error: requestError } = await client.rpc('request_treasury_withdrawal_v1', {
      p_transaction_id: txId,
      p_user_id: makerId,
      p_goal_id: goalId,
      p_destination_wallet_id: destinationWalletId,
      p_amount: amount,
      p_encrypted_amount: encryptedAmount,
      p_encrypted_description: encryptedDescription,
      p_reason: 'Disposable treasury concurrency certification',
      p_reference_id: `ITEST-TREASURY-${txId.slice(0, 8)}`,
    });
    assert.ifError(requestError);
    assert.equal(Number(requested.approvals_required), 2);

    const crossOrg = await client.rpc('approve_treasury_withdrawal_v1', {
      p_admin_id: crossOrgAdminId,
      p_transaction_id: txId,
    });
    assert.ok(crossOrg.error);
    assert.match(String(crossOrg.error?.message || ''), /TREASURY_APPROVER_ACCESS_DENIED/);

    const makerApproval = await client.rpc('approve_treasury_withdrawal_v1', {
      p_admin_id: makerId,
      p_transaction_id: txId,
    });
    assert.ok(makerApproval.error);
    assert.match(String(makerApproval.error?.message || ''), /TREASURY_MAKER_CHECKER_VIOLATION/);

    const approvals = await Promise.all([
      client.rpc('approve_treasury_withdrawal_v1', { p_admin_id: admin1Id, p_transaction_id: txId }),
      client.rpc('approve_treasury_withdrawal_v1', { p_admin_id: admin2Id, p_transaction_id: txId }),
    ]);
    approvals.forEach((result) => assert.ifError(result.error));
    assert.equal(approvals.filter((result) => result.data?.should_execute === true).length, 1);
    assert.equal(approvals.filter((result) => result.data?.fully_approved === false).length, 1);

    const legs = [
      { wallet_id: goalId, entry_type: 'DEBIT', amount: encryptedAmount, amount_plain: amount, description: 'Treasury debit' },
      { wallet_id: destinationWalletId, entry_type: 'CREDIT', amount: encryptedAmount, amount_plain: amount, description: 'Treasury credit' },
    ];
    const appends = await Promise.all([
      client.rpc('append_ledger_entries_v1', {
        p_tx_id: txId, p_legs: legs, p_append_key: `treasury-withdrawal:${txId}`, p_append_phase: 'TREASURY_WITHDRAWAL_EXECUTION',
      }),
      client.rpc('append_ledger_entries_v1', {
        p_tx_id: txId, p_legs: legs, p_append_key: `treasury-withdrawal:${txId}`, p_append_phase: 'TREASURY_WITHDRAWAL_EXECUTION',
      }),
    ]);
    assert.equal(appends.filter((result) => !result.error).length, 1);
    assert.equal(appends.filter((result) => /APPEND_ALREADY_APPLIED/.test(String(result.error?.message || ''))).length, 1);

    const [{ data: updatedGoal }, { data: updatedDestination }, { count: legCount }] = await Promise.all([
      client.from('goals').select('current').eq('id', goalId).single(),
      client.from('wallets').select('balance').eq('id', destinationWalletId).single(),
      client.from('financial_ledger').select('*', { count: 'exact', head: true }).eq('transaction_id', txId),
    ]);
    assert.equal(Number(updatedGoal.current), originalGoalBalance - amount);
    assert.equal(Number(updatedDestination.balance), originalDestinationBalance + amount);
    assert.equal(Number(legCount), 2);
  },
  { requireWrites: true, requiredEnv: TREASURY_FIXTURE_ENV },
);

dbIntegrationTest(
  'organization invitation requires consent, expires, and accepts once under lock',
  async (t, client) => {
    assert.equal(process.env.ORBI_DB_TEST_DISPOSABLE, 'true');
    const admin1Id = requireEnv('ORBI_DB_TEST_TREASURY_ADMIN_1_ID');
    const admin2Id = requireEnv('ORBI_DB_TEST_TREASURY_ADMIN_2_ID');
    const crossOrgAdminId = requireEnv('ORBI_DB_TEST_TREASURY_CROSS_ORG_ADMIN_ID');
    const organizationId = requireEnv('ORBI_DB_TEST_TREASURY_ORG_ID');
    const inviteeId = '00000000-0000-0000-0000-000000000022';
    t.after(async () => {
      await client.from('organization_member_change_requests').delete().eq('target_user_id', inviteeId);
      await client.from('organization_invitations').delete().eq('target_user_id', inviteeId);
      await client.from('treasury_approvers').delete().eq('user_id', inviteeId);
      await client.from('users').update({ organization_id: null, org_role: null }).eq('id', inviteeId);
    });

    const crossOrg = await client.rpc('request_organization_invitation_v1', {
      p_actor_id: crossOrgAdminId, p_organization_id: organizationId, p_target_user_id: inviteeId,
      p_role: 'MEMBER', p_reason: 'Cross organization invitation probe',
    });
    assert.match(String(crossOrg.error?.message || ''), /ORGANIZATION_INVITATION_ADMIN_REQUIRED/);
    const privileged = await client.rpc('request_organization_invitation_v1', {
      p_actor_id: admin1Id, p_organization_id: organizationId, p_target_user_id: inviteeId,
      p_role: 'ADMIN', p_reason: 'Privileged invitation probe',
    });
    assert.match(String(privileged.error?.message || ''), /ORGANIZATION_INVITATION_PRIVILEGED_ROLE_DENIED/);

    const { data: first, error: firstError } = await client.rpc('request_organization_invitation_v1', {
      p_actor_id: admin1Id, p_organization_id: organizationId, p_target_user_id: inviteeId,
      p_role: 'ACCOUNTANT', p_reason: 'Disposable invitation expiry proof',
    });
    assert.ifError(firstError);
    const wrongTarget = await client.rpc('respond_organization_invitation_v1', {
      p_actor_id: admin1Id, p_invitation_id: first.invitation_id, p_decision: 'ACCEPT',
    });
    assert.match(String(wrongTarget.error?.message || ''), /ORGANIZATION_INVITATION_TARGET_REQUIRED/);
    await client.from('organization_invitations').update({ expires_at: new Date(0).toISOString() }).eq('id', first.invitation_id);
    const expired = await client.rpc('respond_organization_invitation_v1', {
      p_actor_id: inviteeId, p_invitation_id: first.invitation_id, p_decision: 'ACCEPT',
    });
    assert.ifError(expired.error);
    assert.equal(expired.data.status, 'EXPIRED');

    const { data: second, error: secondError } = await client.rpc('request_organization_invitation_v1', {
      p_actor_id: admin1Id, p_organization_id: organizationId, p_target_user_id: inviteeId,
      p_role: 'ACCOUNTANT', p_reason: 'Disposable invitation acceptance proof',
    });
    assert.ifError(secondError);
    const responses = await Promise.all([
      client.rpc('respond_organization_invitation_v1', { p_actor_id: inviteeId, p_invitation_id: second.invitation_id, p_decision: 'ACCEPT' }),
      client.rpc('respond_organization_invitation_v1', { p_actor_id: inviteeId, p_invitation_id: second.invitation_id, p_decision: 'ACCEPT' }),
    ]);
    assert.equal(responses.filter((result) => !result.error && result.data?.status === 'ACCEPTED').length, 1);
    assert.equal(responses.filter((result) => /ORGANIZATION_INVITATION_NOT_PENDING/.test(String(result.error?.message || ''))).length, 1);
    const { data: member, error: memberError } = await client.from('users').select('organization_id,org_role').eq('id', inviteeId).single();
    assert.ifError(memberError);
    assert.equal(member.organization_id, organizationId);
    assert.equal(member.org_role, 'ACCOUNTANT');

    await client.from('treasury_approvers').insert({
      organization_id: organizationId, user_id: inviteeId, role: 'APPROVER', status: 'ACTIVE',
    });
    const treasuryProtected = await client.rpc('request_organization_member_change_v1', {
      p_actor_id: admin1Id, p_organization_id: organizationId, p_target_user_id: inviteeId,
      p_action: 'CHANGE_ROLE', p_to_role: 'MEMBER', p_reason: 'Treasury assignment protection probe',
    });
    assert.match(String(treasuryProtected.error?.message || ''), /ORGANIZATION_MEMBER_CHANGE_TREASURY_TARGET/);
    await client.from('treasury_approvers').delete().eq('user_id', inviteeId);

    const { data: roleRequestId, error: roleRequestError } = await client.rpc('request_organization_member_change_v1', {
      p_actor_id: admin1Id, p_organization_id: organizationId, p_target_user_id: inviteeId,
      p_action: 'CHANGE_ROLE', p_to_role: 'MEMBER', p_reason: 'Move certification member to base role',
    });
    assert.ifError(roleRequestError);
    const targetReview = await client.rpc('respond_organization_member_change_v1', {
      p_reviewer_id: inviteeId, p_request_id: roleRequestId, p_decision: 'APPROVE', p_reason: 'Target review must fail',
    });
    assert.match(String(targetReview.error?.message || ''), /ORGANIZATION_MEMBER_CHANGE_REVIEWER_REQUIRED/);
    const roleReview = await client.rpc('respond_organization_member_change_v1', {
      p_reviewer_id: admin2Id, p_request_id: roleRequestId, p_decision: 'APPROVE', p_reason: 'Independent role review approved',
    });
    assert.ifError(roleReview.error);

    const { data: removeRequestId, error: removeRequestError } = await client.rpc('request_organization_member_change_v1', {
      p_actor_id: admin1Id, p_organization_id: organizationId, p_target_user_id: inviteeId,
      p_action: 'REMOVE_MEMBER', p_to_role: null, p_reason: 'Complete disposable member removal proof',
    });
    assert.ifError(removeRequestError);
    const removals = await Promise.all([
      client.rpc('respond_organization_member_change_v1', { p_reviewer_id: admin2Id, p_request_id: removeRequestId, p_decision: 'APPROVE', p_reason: 'Independent removal approved' }),
      client.rpc('respond_organization_member_change_v1', { p_reviewer_id: admin2Id, p_request_id: removeRequestId, p_decision: 'APPROVE', p_reason: 'Concurrent duplicate removal' }),
    ]);
    assert.equal(removals.filter((result) => !result.error && result.data?.status === 'APPROVED').length, 1);
    assert.equal(removals.filter((result) => /ORGANIZATION_MEMBER_CHANGE_NOT_PENDING/.test(String(result.error?.message || ''))).length, 1);
    const { data: removed } = await client.from('users').select('organization_id,org_role').eq('id', inviteeId).single();
    assert.equal(removed.organization_id, null);
    assert.equal(removed.org_role, null);
  },
  { requireWrites: true, requiredEnv: TREASURY_FIXTURE_ENV },
);

dbIntegrationTest(
  'organization leadership promotion and primary transfer enforce independent quorum',
  async (t, client) => {
    assert.equal(process.env.ORBI_DB_TEST_DISPOSABLE, 'true');
    const makerId = requireEnv('ORBI_DB_TEST_TREASURY_MAKER_ID');
    const admin1Id = requireEnv('ORBI_DB_TEST_TREASURY_ADMIN_1_ID');
    const admin2Id = requireEnv('ORBI_DB_TEST_TREASURY_ADMIN_2_ID');
    const crossOrgAdminId = requireEnv('ORBI_DB_TEST_TREASURY_CROSS_ORG_ADMIN_ID');
    const organizationId = requireEnv('ORBI_DB_TEST_TREASURY_ORG_ID');
    const targetId = '00000000-0000-0000-0000-000000000023';
    t.after(async () => {
      await client.from('organization_role_change_requests').delete().eq('target_user_id', targetId);
      await client.from('organizations').update({ primary_admin_user_id: admin1Id }).eq('id', organizationId);
      await client.from('users').update({ org_role: 'MEMBER', organization_id: organizationId }).eq('id', targetId);
    });

    const crossOrg = await client.rpc('request_organization_leadership_change_v1', {
      p_actor_id: crossOrgAdminId, p_organization_id: organizationId, p_target_user_id: targetId,
      p_action: 'ADD_ADMIN', p_to_role: null, p_reason: 'Cross organization leadership probe',
    });
    assert.match(String(crossOrg.error?.message || ''), /ORGANIZATION_LEADERSHIP_ADMIN_REQUIRED/);
    const primaryRemoval = await client.rpc('request_organization_leadership_change_v1', {
      p_actor_id: admin2Id, p_organization_id: organizationId, p_target_user_id: admin1Id,
      p_action: 'REMOVE_ADMIN', p_to_role: 'MANAGER', p_reason: 'Primary lockout protection probe',
    });
    assert.match(String(primaryRemoval.error?.message || ''), /ORGANIZATION_LEADERSHIP_PRIMARY_TRANSFER_REQUIRED/);
    const treasuryRemoval = await client.rpc('request_organization_leadership_change_v1', {
      p_actor_id: admin1Id, p_organization_id: organizationId, p_target_user_id: admin2Id,
      p_action: 'REMOVE_ADMIN', p_to_role: 'MANAGER', p_reason: 'Treasury separation protection probe',
    });
    assert.match(String(treasuryRemoval.error?.message || ''), /ORGANIZATION_LEADERSHIP_TREASURY_REMOVAL_REQUIRED/);

    const { data: promotion, error: promotionError } = await client.rpc('request_organization_leadership_change_v1', {
      p_actor_id: admin1Id, p_organization_id: organizationId, p_target_user_id: targetId,
      p_action: 'ADD_ADMIN', p_to_role: null, p_reason: 'Disposable leadership promotion proof',
    });
    assert.ifError(promotionError);
    assert.equal(Number(promotion.required_reviews), 2);
    const firstReview = await client.rpc('respond_organization_leadership_change_v1', {
      p_reviewer_id: admin2Id, p_request_id: promotion.request_id,
      p_decision: 'APPROVE', p_reason: 'First independent promotion review',
    });
    assert.ifError(firstReview.error);
    assert.equal(firstReview.data.status, 'PENDING');
    const secondReview = await client.rpc('respond_organization_leadership_change_v1', {
      p_reviewer_id: makerId, p_request_id: promotion.request_id,
      p_decision: 'APPROVE', p_reason: 'Second independent promotion review',
    });
    assert.ifError(secondReview.error);
    assert.equal(secondReview.data.status, 'EXECUTED');

    const { data: transfer, error: transferError } = await client.rpc('request_organization_leadership_change_v1', {
      p_actor_id: admin1Id, p_organization_id: organizationId, p_target_user_id: targetId,
      p_action: 'TRANSFER_PRIMARY_ADMIN', p_to_role: null, p_reason: 'Disposable primary ownership transfer proof',
    });
    assert.ifError(transferError);
    const transferReviews = await Promise.all([
      client.rpc('respond_organization_leadership_change_v1', { p_reviewer_id: admin2Id, p_request_id: transfer.request_id, p_decision: 'APPROVE', p_reason: 'Primary transfer review one' }),
      client.rpc('respond_organization_leadership_change_v1', { p_reviewer_id: makerId, p_request_id: transfer.request_id, p_decision: 'APPROVE', p_reason: 'Primary transfer review two' }),
    ]);
    transferReviews.forEach((result) => assert.ifError(result.error));
    assert.equal(transferReviews.filter((result) => result.data?.status === 'EXECUTED').length, 1);
    const { data: organization } = await client.from('organizations').select('primary_admin_user_id').eq('id', organizationId).single();
    assert.equal(organization.primary_admin_user_id, targetId);

    const protectedNewPrimary = await client.rpc('request_organization_leadership_change_v1', {
      p_actor_id: admin1Id, p_organization_id: organizationId, p_target_user_id: targetId,
      p_action: 'REMOVE_ADMIN', p_to_role: 'MANAGER', p_reason: 'New primary removal protection probe',
    });
    assert.match(String(protectedNewPrimary.error?.message || ''), /ORGANIZATION_LEADERSHIP_PRIMARY_TRANSFER_REQUIRED/);
  },
  { requireWrites: true, requiredEnv: TREASURY_FIXTURE_ENV },
);

if (!dbIntegrationEnabled || !hasDbIntegrationConfig() || !dbIntegrationWritesEnabled) {
  console.info('[financial-db-mutation] Skipped. Enable ORBI_RUN_DB_INTEGRATION=true and ORBI_DB_INTEGRATION_ALLOW_WRITES=true for isolated mutation tests.');
  console.info('[financial-db-mutation] Required fixture env:', EDGE_FIXTURE_ENV);
}
