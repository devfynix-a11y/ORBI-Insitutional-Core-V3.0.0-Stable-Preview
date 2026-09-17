/**
 * SETTLEMENT LIFECYCLE MANAGER
 * ===========================
 * Two-phase settlement model for external gateway payments.
 */

import { getSupabase } from '../supabaseClient.js';
import { Audit } from '../security/audit.js';
import { UUID } from '../../services/utils.js';
import { platformFeeService } from './PlatformFeeService.js';
import { systemSettlementAccounts } from '../ledger/SystemSettlementAccountService.js';
import { TransactionService } from '../../ledger/transactionService.js';

export enum SettlementPhase {
  EXTERNAL_PENDING = 'EXTERNAL_PENDING',
  RECONCILIATION_RUNNING = 'RECONCILIATION_RUNNING',
  READY_FOR_INTERNAL_COMMIT = 'READY_FOR_INTERNAL_COMMIT',
  INTERNALLY_SETTLED = 'INTERNALLY_SETTLED',
  FAILED = 'SETTLEMENT_FAILED',
  DISPUTE_UNDER_REVIEW = 'DISPUTE_UNDER_REVIEW',
  REVERSED = 'REVERSED',
}

export enum SettlementFailureReason {
  RECONCILIATION_TRANSITION_DENIED = 'RECONCILIATION_TRANSITION_DENIED',
  RECONCILIATION_VERIFICATION_FAILED = 'RECONCILIATION_VERIFICATION_FAILED',
  PROVIDER_CONFIRMATION_REQUIRED = 'PROVIDER_CONFIRMATION_REQUIRED',
  PROVIDER_CONFIRMATION_ALREADY_APPLIED = 'PROVIDER_CONFIRMATION_ALREADY_APPLIED',
  INTERNAL_COMMIT_TRANSITION_DENIED = 'INTERNAL_COMMIT_TRANSITION_DENIED',
  INTERNAL_COMMIT_ALREADY_IN_PROGRESS = 'INTERNAL_COMMIT_ALREADY_IN_PROGRESS',
  INTERNAL_COMMIT_APPEND_ALREADY_APPLIED = 'INTERNAL_COMMIT_APPEND_ALREADY_APPLIED',
  INTERNAL_COMMIT_FAILED = 'INTERNAL_COMMIT_FAILED',
}

export interface SettlementLifecycle {
  settlementId: string;
  userId: string;
  orderId: string;
  amount: number;
  currency: string;
  currentPhase: SettlementPhase;
  phaseStartedAt: string;
  phaseCompletedAt?: string;
  externalSettlementId: string;
  providerId: string;
  financialTxId?: string;
  walletId: string;
  reconciliationId?: string;
  reconciliationResult?: {
    verified: boolean;
    discrepancy?: number;
    notes?: string;
  };
  autoSettleAfterMinutes: number;
  autoSettleAt?: string;
  autoSettleExecutedAt?: string;
  createdAt: string;
  updatedAt: string;
}

export class SettlementLifecycleManager {
  private sb = getSupabase();
  private ledger = new TransactionService();
  private static readonly internalCommitPhaseMarker = 'INTERNAL_COMMIT';
  private static readonly internalCommitAppendPhase = 'GATEWAY_INTERNAL_COMMIT';
  private static readonly providerConfirmationKeyPrefix = 'provider_confirmation';
  private static readonly allowedTransitions: Record<SettlementPhase, SettlementPhase[]> = {
    [SettlementPhase.EXTERNAL_PENDING]: [SettlementPhase.RECONCILIATION_RUNNING, SettlementPhase.FAILED],
    [SettlementPhase.RECONCILIATION_RUNNING]: [SettlementPhase.READY_FOR_INTERNAL_COMMIT, SettlementPhase.FAILED],
    [SettlementPhase.READY_FOR_INTERNAL_COMMIT]: [SettlementPhase.INTERNALLY_SETTLED, SettlementPhase.FAILED],
    [SettlementPhase.INTERNALLY_SETTLED]: [SettlementPhase.REVERSED],
    [SettlementPhase.FAILED]: [],
    [SettlementPhase.DISPUTE_UNDER_REVIEW]: [SettlementPhase.REVERSED, SettlementPhase.FAILED],
    [SettlementPhase.REVERSED]: [],
  };

  private get client() {
    this.sb = this.sb || getSupabase();
    if (!this.sb) throw new Error('DB_OFFLINE');
    return this.sb;
  }

  private getProviderConfirmationKey(settlement: any): string {
    return `${SettlementLifecycleManager.providerConfirmationKeyPrefix}:${settlement.provider_id}:${settlement.external_settlement_id}`;
  }

  private allowStubProviderReconciliation(): boolean {
    return process.env.NODE_ENV !== 'production' && process.env.ORBI_ALLOW_STUB_PROVIDER_RECONCILIATION === 'true';
  }

  private getTrustedProviderProof(settlement: any, providerConfirmationKey: string): { verified: boolean; source?: string; notes: string } {
    const metadata = settlement?.metadata || {};
    const source = String(
      metadata.provider_confirmation_source ||
        metadata.provider_proof_source ||
        metadata.trusted_gateway_event_source ||
        '',
    ).trim().toUpperCase();
    const trustedSources = new Set([
      'TRUSTED_GATEWAY',
      'VERIFIED_PROVIDER_WEBHOOK',
      'PROVIDER_API_RECONCILIATION',
      'ADMIN_DUAL_CONTROL',
    ]);
    const confirmationKey = String(metadata.provider_confirmation_key || '').trim();
    const keyMatches = !confirmationKey || confirmationKey === providerConfirmationKey;
    const hasTrustedTimestamp = Boolean(
      metadata.provider_confirmation_applied_at ||
        metadata.trusted_gateway_event_applied_at ||
        metadata.verified_provider_webhook_at ||
        metadata.provider_api_reconciled_at,
    );

    if (trustedSources.has(source) && keyMatches && hasTrustedTimestamp) {
      return {
        verified: true,
        source,
        notes: `Trusted provider proof accepted from ${source}.`,
      };
    }

    if (this.allowStubProviderReconciliation()) {
      return {
        verified: true,
        source: 'NON_PRODUCTION_STUB',
        notes: 'Non-production stub reconciliation override accepted.',
      };
    }

    return {
      verified: false,
      source: source || 'MISSING',
      notes:
        'Provider proof is required before internal ledger commit. Expected trusted gateway, verified provider webhook, provider API reconciliation, or admin dual-control confirmation metadata.',
    };
  }

  private buildInternalCommitReference(settlementId: string): string {
    return `SETTLEMENT:${settlementId}:${SettlementLifecycleManager.internalCommitPhaseMarker}`;
  }

  private buildInternalCommitAppendKey(settlementId: string): string {
    return `settlement:${settlementId}:${SettlementLifecycleManager.internalCommitAppendPhase}:v1`;
  }

  private async transitionLifecyclePhase(
    settlementId: string,
    fromPhase: SettlementPhase,
    toPhase: SettlementPhase,
    updates: Record<string, any>,
  ): Promise<any> {
    const allowed = SettlementLifecycleManager.allowedTransitions[fromPhase] || [];
    if (!allowed.includes(toPhase)) {
      throw new Error(
        `INVALID_SETTLEMENT_TRANSITION: ${fromPhase} -> ${toPhase} is not allowed for settlement ${settlementId}`,
      );
    }

    const timestamp = new Date().toISOString();
    const { data, error } = await this.client
      .from('settlement_lifecycle')
      .update({
        current_phase: toPhase,
        phase_started_at: timestamp,
        updated_at: timestamp,
        ...updates,
      })
      .eq('id', settlementId)
      .eq('current_phase', fromPhase)
      .select('*');

    if (error) throw error;
    if (!data || data.length === 0) {
      throw new Error(`INVALID_SETTLEMENT_TRANSITION: Settlement ${settlementId} is no longer in ${fromPhase}`);
    }

    await Audit.log('FINANCIAL', data[0].user_id || 'SYSTEM', 'SETTLEMENT_PHASE_TRANSITION', {
      settlementId,
      fromPhase,
      toPhase,
      providerId: data[0].provider_id || null,
      orderId: data[0].order_id || null,
      externalMovementId: data[0].external_movement_id || null,
      externalSettlementId: data[0].external_settlement_id || null,
      financialTxId: data[0].financial_tx_id || null,
    });

    return data[0];
  }

  private async recordFailure(
    settlementId: string,
    reason: SettlementFailureReason,
    error: unknown,
    extraMetadata: Record<string, any> = {},
  ): Promise<void> {
    const now = new Date().toISOString();
    const message = String((error as any)?.message || error || reason);
    const { data: settlement } = await this.client
      .from('settlement_lifecycle')
      .select('user_id, provider_id, order_id, external_movement_id, external_settlement_id, financial_tx_id, current_phase, metadata')
      .eq('id', settlementId)
      .single();

    const metadata = {
      ...(settlement?.metadata || {}),
      failure_reason: reason,
      failure_recorded_at: now,
      failure_details: {
        reason,
        message,
        ...extraMetadata,
      },
    };

    await this.client
      .from('settlement_lifecycle')
      .update({
        current_phase: SettlementPhase.FAILED,
        phase_completed_at: now,
        updated_at: now,
        last_error: reason,
        metadata,
      })
      .eq('id', settlementId);

    await Audit.log('SECURITY', settlement?.user_id || 'SYSTEM', 'SETTLEMENT_FAILURE_RECORDED', {
      settlementId,
      reason,
      message,
      providerId: settlement?.provider_id || null,
      orderId: settlement?.order_id || null,
      externalMovementId: settlement?.external_movement_id || null,
      externalSettlementId: settlement?.external_settlement_id || null,
      financialTxId: settlement?.financial_tx_id || null,
      failedFromPhase: settlement?.current_phase || null,
      failureDetails: extraMetadata,
    });
  }

  async recordExternalPayment(
    userId: string,
    orderId: string,
    externalSettlementId: string,
    providerId: string,
    amount: number,
    currency: string,
    walletId: string,
    autoSettleAfterMinutes: number = 5,
    externalMovementId?: string | null,
  ): Promise<SettlementLifecycle> {
    try {
      const settlementId = `settle_lifecycle_${UUID.generate()}`;
      const now = new Date().toISOString();
      const autoSettleAt = new Date(
        Date.now() + autoSettleAfterMinutes * 60 * 1000,
      ).toISOString();

      const { error: createError } = await this.client.from('settlement_lifecycle').insert({
        id: settlementId,
        user_id: userId,
        order_id: orderId,
        amount,
        currency,
        current_phase: SettlementPhase.EXTERNAL_PENDING,
        phase_started_at: now,
        external_settlement_id: externalSettlementId,
        provider_id: providerId,
        wallet_id: walletId,
        external_movement_id: externalMovementId || null,
        auto_settle_after_minutes: autoSettleAfterMinutes,
        auto_settle_at: autoSettleAt,
        created_at: now,
        updated_at: now,
      });

      if (createError) throw createError;

      if (externalMovementId) {
        const { error: movementError } = await this.client
          .from('external_fund_movements')
          .update({
            settlement_lifecycle_id: settlementId,
            updated_at: now,
          })
          .eq('id', externalMovementId);

        if (movementError) throw movementError;
      }

      await Audit.log('FINANCIAL', userId, 'SETTLEMENT_PHASE1_EXTERNAL_RECORDED', {
        settlementId,
        externalSettlementId,
        providerId,
        amount,
        autoSettleAt,
        externalMovementId: externalMovementId || null,
      });

      return {
        settlementId,
        userId,
        orderId,
        amount,
        currency,
        currentPhase: SettlementPhase.EXTERNAL_PENDING,
        phaseStartedAt: now,
        externalSettlementId,
        providerId,
        walletId,
        autoSettleAfterMinutes,
        autoSettleAt,
        createdAt: now,
        updatedAt: now,
      };
    } catch (error: any) {
      throw new Error(`Failed to record external payment: ${error.message}`);
    }
  }

  async startReconciliation(settlementId: string): Promise<boolean> {
    try {
      const { data: settlement } = await this.client
        .from('settlement_lifecycle')
        .select('*')
        .eq('id', settlementId)
        .single();

      if (!settlement) throw new Error('Settlement not found');
      const providerConfirmationKey = this.getProviderConfirmationKey(settlement);
      if (
        settlement.metadata?.provider_confirmation_key === providerConfirmationKey &&
        settlement.metadata?.provider_confirmation_applied_at
      ) {
        if (
          settlement.current_phase === SettlementPhase.READY_FOR_INTERNAL_COMMIT ||
          settlement.current_phase === SettlementPhase.INTERNALLY_SETTLED
        ) {
          return true;
        }
        await this.recordFailure(
          settlementId,
          SettlementFailureReason.PROVIDER_CONFIRMATION_ALREADY_APPLIED,
          new Error(`Provider confirmation already applied while settlement is in ${settlement.current_phase}`),
          { providerConfirmationKey, currentPhase: settlement.current_phase },
        );
        return false;
      }

      if (settlement.current_phase === SettlementPhase.READY_FOR_INTERNAL_COMMIT || settlement.current_phase === SettlementPhase.INTERNALLY_SETTLED) {
        return true;
      }

      if (settlement.current_phase !== SettlementPhase.EXTERNAL_PENDING) {
        throw new Error(`Cannot reconcile settlement in phase: ${settlement.current_phase}`);
      }

      const reconciliationId = `recon_${UUID.generate()}`;
      await this.transitionLifecyclePhase(
        settlementId,
        SettlementPhase.EXTERNAL_PENDING,
        SettlementPhase.RECONCILIATION_RUNNING,
        {
          reconciliation_id: reconciliationId,
          metadata: {
            ...(settlement.metadata || {}),
            reconciliation_started_at: new Date().toISOString(),
          },
        },
      );

      const reconciliationResult = await this.performReconciliation(settlement, providerConfirmationKey);

      const { error: reconError } = await this.client
        .from('settlement_lifecycle')
        .update({
          reconciliation_result: reconciliationResult,
          phase_completed_at: new Date().toISOString(),
        })
        .eq('id', settlementId);

      if (reconError) throw reconError;

      if (reconciliationResult.verified) {
        await this.transitionLifecyclePhase(
          settlementId,
          SettlementPhase.RECONCILIATION_RUNNING,
          SettlementPhase.READY_FOR_INTERNAL_COMMIT,
          {
            metadata: {
              ...(settlement.metadata || {}),
              provider_confirmation_key: providerConfirmationKey,
              provider_confirmation_source: reconciliationResult.source,
              reconciliation_verified_at: new Date().toISOString(),
            },
          },
        );

        await Audit.log(
          'FINANCIAL',
          settlement.user_id,
          'SETTLEMENT_RECONCILIATION_PASSED',
          {
            settlementId,
            reconciliationId,
            amount: settlement.amount,
          },
        );

        return true;
      }

      await this.recordFailure(
        settlementId,
        reconciliationResult.reason === SettlementFailureReason.PROVIDER_CONFIRMATION_REQUIRED
          ? SettlementFailureReason.PROVIDER_CONFIRMATION_REQUIRED
          : SettlementFailureReason.RECONCILIATION_VERIFICATION_FAILED,
        reconciliationResult.notes || 'Reconciliation verification failed',
        {
          discrepancy: reconciliationResult.discrepancy,
          reconciliationId,
          providerConfirmationKey,
          proofSource: reconciliationResult.source || null,
        },
      );

      await Audit.log('SECURITY', settlement.user_id, 'SETTLEMENT_RECONCILIATION_FAILED', {
        settlementId,
        reconciliationId,
        discrepancy: reconciliationResult.discrepancy,
        notes: reconciliationResult.notes,
      });

      return false;
    } catch (error: any) {
      console.error('[SettlementLifecycle] Reconciliation failed:', error.message);
      await this.recordFailure(
        settlementId,
        SettlementFailureReason.RECONCILIATION_TRANSITION_DENIED,
        error,
      ).catch(() => {});
      throw error;
    }
  }

  private async performReconciliation(
    settlement: any,
    providerConfirmationKey: string,
  ): Promise<{ verified: boolean; discrepancy?: number; notes?: string; source?: string; reason?: SettlementFailureReason }> {
    try {
      console.info(
        `[Reconciliation] Verifying ${settlement.provider_id} transaction ${settlement.external_settlement_id}`,
      );

      const providerProof = this.getTrustedProviderProof(settlement, providerConfirmationKey);
      if (!providerProof.verified) {
        return {
          verified: false,
          discrepancy: Number(settlement.amount || 0),
          notes: providerProof.notes,
          source: providerProof.source,
          reason: SettlementFailureReason.PROVIDER_CONFIRMATION_REQUIRED,
        };
      }

      return {
        verified: true,
        source: providerProof.source,
        notes: providerProof.notes,
      };
    } catch (error: any) {
      return {
        verified: false,
        discrepancy: Number(settlement?.amount || 0),
        notes: `Verification failed: ${error.message}`,
      };
    }
  }

  async commitToInternalLedger(
    settlementId: string,
    sourceWalletId?: string,
  ): Promise<{
    success: boolean;
    financialTxId: string;
    newWalletBalance: number;
  }> {
    try {
      const { data: settlement } = await this.client
        .from('settlement_lifecycle')
        .select('*')
        .eq('id', settlementId)
        .single();

      if (!settlement) throw new Error('Settlement not found');
      if (
        settlement.current_phase === SettlementPhase.INTERNALLY_SETTLED &&
        settlement.financial_tx_id
      ) {
        return {
          success: true,
          financialTxId: settlement.financial_tx_id,
          newWalletBalance: await this.ledger.calculateBalanceFromLedger(
            settlement.wallet_id,
          ),
        };
      }
      if (settlement.current_phase !== SettlementPhase.READY_FOR_INTERNAL_COMMIT) {
        throw new Error(`Cannot commit settlement in phase: ${settlement.current_phase}`);
      }

      const claimTimestamp = new Date().toISOString();
      const claimId = UUID.generate();
      const claimMetadata = {
        ...(settlement.metadata || {}),
        internal_commit_claim_id: claimId,
        internal_commit_claimed_at: claimTimestamp,
        internal_commit_append_phase: SettlementLifecycleManager.internalCommitAppendPhase,
        internal_commit_append_key: this.buildInternalCommitAppendKey(settlementId),
      };

      const { data: claimedRows, error: claimError } = await this.client
        .from('settlement_lifecycle')
        .update({
          phase_started_at: claimTimestamp,
          updated_at: claimTimestamp,
          metadata: claimMetadata,
        })
        .eq('id', settlementId)
        .eq('current_phase', SettlementPhase.READY_FOR_INTERNAL_COMMIT)
        .eq('phase_started_at', settlement.phase_started_at)
        .is('financial_tx_id', null)
        .select('id');

      if (claimError) throw claimError;
      if (!claimedRows || claimedRows.length === 0) {
        const { data: latestSettlement, error: latestSettlementError } = await this.client
          .from('settlement_lifecycle')
          .select('current_phase, financial_tx_id, wallet_id')
          .eq('id', settlementId)
          .single();
        if (latestSettlementError) throw latestSettlementError;
        if (
          latestSettlement?.current_phase === SettlementPhase.INTERNALLY_SETTLED &&
          latestSettlement.financial_tx_id
        ) {
          return {
            success: true,
            financialTxId: latestSettlement.financial_tx_id,
            newWalletBalance: await this.ledger.calculateBalanceFromLedger(
              latestSettlement.wallet_id,
            ),
          };
        }
        throw new Error('SETTLEMENT_COMMIT_ALREADY_IN_PROGRESS');
      }

      const { data: wallet } = await this.client
        .from('wallets')
        .select('*')
        .eq('id', settlement.wallet_id)
        .single();

      if (!wallet) throw new Error('Target wallet not found');

      const settlementSourceWalletId = String(
        sourceWalletId ||
          process.env.SETTLEMENT_SUSPENSE_WALLET_ID ||
          '',
      ).trim();
      if (!settlementSourceWalletId) {
        throw new Error('SETTLEMENT_SOURCE_WALLET_REQUIRED');
      }

      const financialTxId = UUID.generate();
      const settlementCurrency = String(settlement.currency || '').trim().toUpperCase();
      if (!settlementCurrency) throw new Error('SETTLEMENT_CURRENCY_REQUIRED');
      const timestamp = new Date().toISOString();
      const gatewayFee = await platformFeeService.resolveFee({
        flowCode: 'GATEWAY_SETTLEMENT',
        amount: Number(settlement.amount || 0),
        currency: settlementCurrency,
        providerId: settlement.provider_id || undefined,
        transactionType: 'GATEWAY_SETTLEMENT',
        metadata: {
          settlement_id: settlementId,
          external_settlement_id: settlement.external_settlement_id,
        },
      });
      const platformFee = gatewayFee.serviceFee;
      const feeWalletId = Number(platformFee || 0) > 0
        ? await systemSettlementAccounts.resolve('SERVICE_REVENUE', settlementCurrency)
        : null;

      const ledgerLegs = [
        {
          walletId: settlementSourceWalletId,
          type: 'DEBIT' as const,
          amount: Number(settlement.amount || 0) + Number(platformFee || 0),
          currency: settlementCurrency,
          description: `${settlement.provider_id} settlement debit for ${settlement.external_settlement_id}`,
          transactionId: financialTxId,
          timestamp,
        },
        {
          walletId: settlement.wallet_id,
          type: 'CREDIT' as const,
          amount: Number(settlement.amount || 0),
          currency: settlementCurrency,
          description: `Received via ${settlement.provider_id} payment gateway`,
          transactionId: financialTxId,
          timestamp,
        },
        ...(feeWalletId ? [{
          walletId: feeWalletId,
          type: 'CREDIT' as const,
          amount: Number(platformFee || 0),
          currency: settlementCurrency,
          description: `Gateway settlement fee from ${settlement.provider_id}`,
          transactionId: financialTxId,
          timestamp,
        }] : []),
      ];

      await this.ledger.postTransactionWithLedger(
        {
          id: financialTxId,
          referenceId: this.buildInternalCommitReference(settlementId),
          user_id: settlement.user_id,
          walletId: settlementSourceWalletId,
          toWalletId: settlement.wallet_id,
          amount: Number(settlement.amount || 0),
          currency: settlement.currency,
          description: `External ${settlement.provider_id} payment settlement`,
          type: 'deposit',
          status: 'completed',
          date: new Date().toISOString().split('T')[0],
          metadata: {
            settlement_lifecycle_id: settlementId,
            external_settlement_id: settlement.external_settlement_id,
            reconciliation_id: settlement.reconciliation_id,
            settlement_path: `GATEWAY_${settlement.provider_id}`,
            settlement_append_phase: SettlementLifecycleManager.internalCommitAppendPhase,
            settlement_append_key: this.buildInternalCommitAppendKey(settlementId),
          },
        },
        ledgerLegs,
      );

      const { error: lifecycleError } = await this.client
        .from('settlement_lifecycle')
        .update({
          current_phase: SettlementPhase.INTERNALLY_SETTLED,
          financial_tx_id: financialTxId,
          phase_completed_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
          metadata: {
            ...claimMetadata,
            internal_commit_completed_at: new Date().toISOString(),
            internal_commit_reference: this.buildInternalCommitReference(settlementId),
            internal_commit_result: 'COMPLETED',
          },
        })
        .eq('id', settlementId);

      if (lifecycleError) throw lifecycleError;

      await Audit.log(
        'FINANCIAL',
        settlement.user_id,
        'SETTLEMENT_PHASE2_INTERNALLY_COMMITTED',
        {
          settlementId,
          financialTxId,
          amount: settlement.amount,
          walletId: settlement.wallet_id,
          platformFee,
        },
      );

      return {
        success: true,
        financialTxId,
        newWalletBalance: await this.ledger.calculateBalanceFromLedger(settlement.wallet_id),
      };
    } catch (error: any) {
      const structuredReason =
        String(error?.message || '').includes('SETTLEMENT_COMMIT_ALREADY_IN_PROGRESS')
          ? SettlementFailureReason.INTERNAL_COMMIT_ALREADY_IN_PROGRESS
          : String(error?.message || '').includes('APPEND_ALREADY_APPLIED') ||
            String(error?.message || '').includes('IDEMPOTENCY_VIOLATION')
            ? SettlementFailureReason.INTERNAL_COMMIT_APPEND_ALREADY_APPLIED
            : String(error?.message || '').includes('Cannot commit settlement in phase')
              ? SettlementFailureReason.INTERNAL_COMMIT_TRANSITION_DENIED
              : SettlementFailureReason.INTERNAL_COMMIT_FAILED;

      await this.recordFailure(settlementId, structuredReason, error, {
        phase: 'INTERNAL_COMMIT',
      });

      await Audit.log('SECURITY', 'SYSTEM', 'SETTLEMENT_PHASE2_COMMIT_FAILED', {
        settlementId,
        error: error.message,
        reason: structuredReason,
      });

      throw error;
    }
  }

  async getLifecycleStatus(settlementId: string): Promise<SettlementLifecycle | null> {
    const { data } = await this.client
      .from('settlement_lifecycle')
      .select('*')
      .eq('id', settlementId)
      .single();

    return (data as SettlementLifecycle | null) || null;
  }

  private async calculateWalletBalance(walletId: string): Promise<string> {
    const { data: ledgerEntries } = await this.client
      .from('financial_ledger')
      .select('entry_type, amount')
      .eq('wallet_id', walletId);

    if (!ledgerEntries || ledgerEntries.length === 0) return '0';

    let balance = 0;
    for (const entry of ledgerEntries) {
      const amount = parseFloat(entry.amount) || 0;
      balance += entry.entry_type === 'CREDIT' ? amount : -amount;
    }

    return balance.toFixed(2);
  }
}

export const settlementLifecycleManager = new SettlementLifecycleManager();
