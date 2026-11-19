/**
 * SETTLEMENT SCHEDULER
 * ===================
 * Automatically advances external settlements through reconciliation and commit.
 */

import { getSupabase } from '../supabaseClient.js';
import { Audit } from '../security/audit.js';
import {
  settlementLifecycleManager,
  SettlementPhase,
} from './settlementLifecycleManager.js';
import { buildLifecycleFailureMetadata } from './providerFailureMetadata.js';

export class SettlementScheduler {
  private sb = getSupabase();
  private isRunning = false;
  private schedulerInterval?: ReturnType<typeof setInterval>;
  private checkIntervalMs = 60 * 1000;

  private get client() {
    this.sb = this.sb || getSupabase();
    if (!this.sb) throw new Error('DB_OFFLINE');
    return this.sb;
  }

  start(): void {
    if (this.isRunning) return;
    this.isRunning = true;

    this.processSettlements().catch((error) => {
      console.error('[SettlementScheduler] Initial processing error:', error.message);
    });

    this.schedulerInterval = setInterval(() => {
      this.processSettlements().catch((error) => {
        console.error('[SettlementScheduler] Processing error:', error.message);
      });
    }, this.checkIntervalMs);
  }

  stop(): void {
    if (this.schedulerInterval) {
      clearInterval(this.schedulerInterval);
      this.schedulerInterval = undefined;
    }
    this.isRunning = false;
  }

  private async processSettlements(): Promise<void> {
    await this.processAutoSettleTimeouts();
    await this.processStuckReconciliations();
    await this.processStuckExternalMovements();
    await this.retryFailedSettlements();
  }

  private async processAutoSettleTimeouts(): Promise<void> {
    const now = new Date().toISOString();

    const { data: settlements } = await this.client
      .from('settlement_lifecycle')
      .select('id,user_id,amount,provider_id,external_settlement_id,currency,auto_settle_at')
      .eq('current_phase', SettlementPhase.EXTERNAL_PENDING)
      .lte('auto_settle_at', now)
      .is('auto_settle_executed_at', null);

    for (const settlement of settlements || []) {
      try {
        const reconciliationPassed =
          await settlementLifecycleManager.startReconciliation(settlement.id);

        await this.client
          .from('settlement_lifecycle')
          .update({
            auto_settle_executed_at: new Date().toISOString(),
          })
          .eq('id', settlement.id);

        if (reconciliationPassed) {
          await settlementLifecycleManager.commitToInternalLedger(settlement.id);

          await Audit.log('FINANCIAL', settlement.user_id, 'SETTLEMENT_AUTO_COMMITTED', {
            settlementId: settlement.id,
            amount: settlement.amount,
            provider: settlement.provider_id,
          });
        }
      } catch (error: any) {
        console.error(
          `[SettlementScheduler] Error processing settlement ${settlement.id}:`,
          error.message,
        );

        await Audit.log('SECURITY', settlement.user_id, 'SETTLEMENT_AUTO_COMMIT_ERROR', {
          settlementId: settlement.id,
          error: error.message,
        });
      }
    }
  }

  private async processStuckReconciliations(): Promise<void> {
    const stuckBefore = new Date(Date.now() - 10 * 60 * 1000).toISOString();

    const { data: stuckSettlements } = await this.client
      .from('settlement_lifecycle')
      .select('id,user_id,amount,phase_started_at,metadata')
      .eq('current_phase', SettlementPhase.RECONCILIATION_RUNNING)
      .lt('phase_started_at', stuckBefore);

    for (const settlement of stuckSettlements || []) {
      await this.client
        .from('settlement_lifecycle')
        .update({
          current_phase: SettlementPhase.FAILED,
          phase_completed_at: new Date().toISOString(),
          metadata: {
            ...(settlement.metadata || {}),
            ...buildLifecycleFailureMetadata(
              'RECONCILIATION_TIMEOUT',
              'Reconciliation exceeded the allowed processing window.',
              {
                source: 'scheduler',
                previous_phase: SettlementPhase.RECONCILIATION_RUNNING,
                phase_started_at: settlement.phase_started_at,
              },
            ),
          },
        })
        .eq('id', settlement.id);

      await Audit.log('SECURITY', settlement.user_id, 'SETTLEMENT_RECONCILIATION_TIMEOUT', {
        settlementId: settlement.id,
        amount: settlement.amount,
        phaseStartedAt: settlement.phase_started_at,
      });
    }
  }

  private async retryFailedSettlements(): Promise<void> {
    const { data: failedSettlements } = await this.client
      .from('settlement_lifecycle')
      .select('id,user_id,retry_count,phase_completed_at,updated_at,created_at,metadata')
      .eq('current_phase', SettlementPhase.FAILED)
      .lt('retry_count', 3);

    for (const settlement of failedSettlements || []) {
      const retryCount = settlement.retry_count || 0;
      const failedAt = settlement.phase_completed_at || settlement.updated_at || settlement.created_at;
      const minutesSinceFailure = Math.floor(
        (Date.now() - new Date(failedAt).getTime()) / 60000,
      );
      const backoffMinutes = [1, 5, 30][retryCount] || 60;

      if (minutesSinceFailure < backoffMinutes) continue;

      await this.client
        .from('settlement_lifecycle')
        .update({
          current_phase: SettlementPhase.EXTERNAL_PENDING,
          phase_started_at: new Date().toISOString(),
          retry_count: retryCount + 1,
          auto_settle_at: new Date().toISOString(),
          metadata: {
            ...(settlement.metadata || {}),
            retry_requeued_at: new Date().toISOString(),
            retry_requeued_by: 'scheduler',
            retry_backoff_minutes: backoffMinutes,
            retry_attempt: retryCount + 1,
          },
        })
        .eq('id', settlement.id);

      await Audit.log('FINANCIAL', settlement.user_id, 'SETTLEMENT_RETRY_INITIATED', {
        settlementId: settlement.id,
        attempt: retryCount + 1,
      });
    }
  }

  private async processStuckExternalMovements(): Promise<void> {
    const initiatedBefore = new Date(Date.now() - 10 * 60 * 1000).toISOString();
    const processingBefore = new Date(Date.now() - 30 * 60 * 1000).toISOString();

    const selectFields =
      'id,user_id,direction,status,updated_at,created_at,metadata,external_reference,source_external_ref,target_external_ref';
    const [initiatedResult, processingResult] = await Promise.all([
      this.client
        .from('external_fund_movements')
        .select(selectFields)
        .is('transaction_id', null)
        .eq('status', 'initiated')
        .lt('updated_at', initiatedBefore),
      this.client
        .from('external_fund_movements')
        .select(selectFields)
        .is('transaction_id', null)
        .eq('status', 'processing')
        .lt('updated_at', processingBefore),
    ]);

    if (initiatedResult.error || processingResult.error) {
      throw new Error(
        initiatedResult.error?.message ||
          processingResult.error?.message ||
          'EXTERNAL_MOVEMENT_STUCK_QUERY_FAILED',
      );
    }

    const movements = [
      ...(initiatedResult.data || []),
      ...(processingResult.data || []),
    ];

    for (const movement of movements || []) {
      const now = new Date().toISOString();
      const timeoutReason =
        movement.status === 'processing'
          ? 'EXTERNAL_SETTLEMENT_TIMEOUT: Provider processing exceeded recovery window.'
          : 'EXTERNAL_SETTLEMENT_TIMEOUT: No provider confirmation received in time.';

      await this.client
        .from('external_fund_movements')
        .update({
          status: 'failed',
          updated_at: now,
          metadata: {
            ...(movement.metadata || {}),
            timeout_reaped_at: now,
            timeout_reason: timeoutReason,
            ...buildLifecycleFailureMetadata(
              'EXTERNAL_SETTLEMENT_TIMEOUT',
              timeoutReason,
              {
                source: 'scheduler',
                previous_status: movement.status,
              },
            ),
          },
        })
        .eq('id', movement.id);

      await Audit.log('SECURITY', movement.user_id, 'EXTERNAL_MOVEMENT_TIMEOUT_REAPED', {
        movementId: movement.id,
        direction: movement.direction,
        previousStatus: movement.status,
        timeoutReason,
        externalReference:
          movement.external_reference || movement.source_external_ref || movement.target_external_ref || null,
      });
    }
  }

  async settlementReceivedManually(settlementId: string): Promise<void> {
    const { data: settlement } = await this.client
      .from('settlement_lifecycle')
      .select('*')
      .eq('id', settlementId)
      .single();

    if (!settlement) throw new Error('Settlement not found');

    const reconciliationPassed =
      await settlementLifecycleManager.startReconciliation(settlementId);

    if (!reconciliationPassed) {
      throw new Error('Reconciliation check failed');
    }

    await settlementLifecycleManager.commitToInternalLedger(settlementId);

    await Audit.log('FINANCIAL', settlement.user_id, 'SETTLEMENT_MANUALLY_CONFIRMED', {
      settlementId,
      amount: settlement.amount,
    });
  }

  async disputeSettlement(
    settlementId: string,
    userId: string,
    reason: string,
  ): Promise<void> {
    const { data: settlement } = await this.client
      .from('settlement_lifecycle')
      .select('*')
      .eq('id', settlementId)
      .eq('user_id', userId)
      .single();

    if (!settlement) throw new Error('Settlement not found');

    await this.client
      .from('settlement_lifecycle')
      .update({
        current_phase: SettlementPhase.DISPUTE_UNDER_REVIEW,
        phase_started_at: new Date().toISOString(),
        metadata: {
          ...(settlement.metadata || {}),
          dispute_reason: reason,
          disputed_at: new Date().toISOString(),
        },
      })
      .eq('id', settlementId);

    await Audit.log('SECURITY', userId, 'SETTLEMENT_DISPUTED', {
      settlementId,
      amount: settlement.amount,
      reason,
      provider: settlement.provider_id,
    });
  }

  async resolveDispute(
    settlementId: string,
    adminId: string,
    resolution: 'APPROVE' | 'REJECT',
    notes?: string,
  ): Promise<void> {
    const { data: settlement } = await this.client
      .from('settlement_lifecycle')
      .select('*')
      .eq('id', settlementId)
      .single();

    if (!settlement) throw new Error('Settlement not found');

    if (resolution === 'APPROVE') {
      const reconciliationPassed =
        await settlementLifecycleManager.startReconciliation(settlementId);

      if (reconciliationPassed) {
        await settlementLifecycleManager.commitToInternalLedger(settlementId);
      }

      await Audit.log('FINANCIAL', settlement.user_id, 'SETTLEMENT_DISPUTE_APPROVED', {
        settlementId,
        resolvedBy: adminId,
        notes,
      });
      return;
    }

    await this.client
      .from('settlement_lifecycle')
      .update({
        current_phase: SettlementPhase.REVERSED,
        phase_completed_at: new Date().toISOString(),
      })
      .eq('id', settlementId);

    await Audit.log('SECURITY', settlement.user_id, 'SETTLEMENT_DISPUTE_REJECTED', {
      settlementId,
      resolvedBy: adminId,
      notes,
    });
  }

  async healthCheck(): Promise<{
    running: boolean;
    pendingCount: Record<string, number>;
  }> {
    const phases = [
      SettlementPhase.EXTERNAL_PENDING,
      SettlementPhase.RECONCILIATION_RUNNING,
      SettlementPhase.READY_FOR_INTERNAL_COMMIT,
      SettlementPhase.DISPUTE_UNDER_REVIEW,
    ];

    const pendingCount: Record<string, number> = {};
    for (const phase of phases) {
      const { count } = await this.client
        .from('settlement_lifecycle')
        .select('*', { count: 'exact', head: true })
        // A backlog represents work that can still move money. Completed,
        // failed, cancelled, and zero-value test rows are retained for audit
        // but must not make operational health look as if a live settlement is
        // waiting for execution.
        .eq('current_phase', phase)
        .eq('status', 'ACTIVE')
        .gt('amount', 0);

      pendingCount[phase] = count || 0;
    }

    return {
      running: this.isRunning,
      pendingCount,
    };
  }
}

export const settlementScheduler = new SettlementScheduler();
