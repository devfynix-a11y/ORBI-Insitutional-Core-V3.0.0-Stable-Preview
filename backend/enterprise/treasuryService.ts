import { getSupabase, getAdminSupabase } from '../supabaseClient.js';
import { TransactionService } from '../../ledger/transactionService.js';
import { UUID } from '../../services/utils.js';
import { DataVault } from '../security/encryption.js';
import { DataProtection } from '../security/DataProtection.js';
import { Audit } from '../security/audit.js';
import { Messaging } from '../features/MessagingService.js';

export class TreasuryService {

    private async executeClaimedWithdrawal(txId: string, actorId: string): Promise<boolean> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) throw new Error("Database connection required");
        const { data: tx, error: txError } = await sb.from('transactions').select('*').eq('id', txId).single();
        if (txError || !tx || tx.status !== 'processing' || tx.metadata?.is_treasury_withdrawal !== true) {
            throw new Error(txError?.message || 'TREASURY_EXECUTION_CLAIM_INVALID');
        }

        const amount = await DataProtection.decryptAmount(tx.amount);
        const txService = new TransactionService();
        const existingLegs = await txService.getLedgerEntries(txId);
        const ledgerAlreadyApplied = existingLegs.some((leg: any) =>
            String(leg.wallet_id) === String(tx.wallet_id) && String(leg.entry_type).toUpperCase() === 'DEBIT'
        ) && existingLegs.some((leg: any) =>
            String(leg.wallet_id) === String(tx.to_wallet_id) && String(leg.entry_type).toUpperCase() === 'CREDIT'
        );

        if (!ledgerAlreadyApplied) {
            await txService.addLedgerEntries(txId, [
                {
                    transactionId: txId,
                    walletId: tx.wallet_id,
                    type: 'DEBIT' as 'DEBIT',
                    amount,
                    currency: tx.currency,
                    description: 'Approved Treasury Withdrawal',
                    timestamp: new Date().toISOString(),
                },
                {
                    transactionId: txId,
                    walletId: tx.to_wallet_id,
                    type: 'CREDIT' as 'CREDIT',
                    amount,
                    currency: tx.currency,
                    description: 'Inbound Treasury Funds',
                    timestamp: new Date().toISOString(),
                },
            ], {
                appendKey: `treasury-withdrawal:${txId}`,
                appendPhase: 'TREASURY_WITHDRAWAL_EXECUTION',
            });
        }

        await txService.updateTransactionStatus(txId, 'completed', 'Fully Approved by Finance');
        await sb.from('transactions').update({
            metadata: {
                ...(tx.metadata || {}),
                execution_state: 'COMPLETED',
                execution_completed_at: new Date().toISOString(),
                execution_completed_by: actorId,
                execution_lease_until: null,
            },
        }).eq('id', txId).eq('status', 'completed');
        await Audit.log('FINANCIAL', actorId, 'TREASURY_WITHDRAWAL_EXECUTED', {
            txId,
            recovered: ledgerAlreadyApplied,
        });

        try {
            const { data: makerUser } = await sb.from('users').select('language').eq('id', tx.user_id).maybeSingle();
            const makerLang = makerUser?.language || 'en';
            const subject = makerLang === 'sw' ? 'Utoaji Fedha za Hazina Umeidhinishwa' : 'Treasury Withdrawal Approved';
            const body = makerLang === 'sw'
                ? `Ombi lako la kutoa fedha za hazina la ${amount} limeidhinishwa kikamilifu na fedha zimehamishiwa kwenye akaunti yako ya uendeshaji.`
                : `Your treasury withdrawal request for ${amount} has been fully approved and the funds have been transferred to your operating wallet.`;
            await Messaging.dispatch(tx.user_id, 'info', subject, body, {
                sms: true,
                email: true,
                template: 'Transactional_Message',
                variables: { body, amount: amount.toLocaleString(), currency: tx.currency },
            });
        } catch (notificationError: any) {
            console.warn(`[Treasury] Withdrawal ${txId} completed; notification deferred: ${notificationError.message}`);
        }
        return true;
    }

    /**
     * SWEEP ALL ORGANIZATIONS
     * Triggers auto-sweep for all organizations. Intended for background jobs.
     */
    public async sweepAllOrganizations(): Promise<void> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return;

        try {
            const workerId = `treasury-scheduler-${process.pid}`;
            const { data: reclaimed, error: reclaimError } = await sb.rpc('reclaim_treasury_schedule_executions_v1', {
                p_worker_id: workerId, p_limit: 25, p_lease_seconds: 120,
            });
            if (reclaimError) throw new Error(reclaimError.message);
            const { data: due, error } = await sb.rpc('claim_due_treasury_sweeps_v1', {
                p_worker_id: workerId, p_limit: 25, p_lease_seconds: 120,
            });
            if (error) throw new Error(error.message);
            const executions = [...(reclaimed || []), ...(due || [])];
            for (const execution of executions) {
                try {
                    const moved = await this.executeAutoSweep(execution.organization_id, execution.goal_id);
                    await sb.rpc('finish_treasury_schedule_execution_v1', {
                        p_execution_id: execution.id, p_worker_id: workerId,
                        p_status: moved ? 'COMPLETED' : 'SKIPPED', p_transaction_id: null,
                        p_error: moved ? null : 'NO_ELIGIBLE_EXCESS_LIQUIDITY',
                    });
                    try {
                        await this.notifyScheduleExecution(execution, moved ? 'COMPLETED' : 'SKIPPED');
                    } catch (notificationError: any) {
                        console.warn(`[Treasury] Schedule ${execution.id} finalized; notification queued delivery failed: ${notificationError.message}`);
                    }
                } catch (executionError: any) {
                    await sb.rpc('finish_treasury_schedule_execution_v1', {
                        p_execution_id: execution.id, p_worker_id: workerId, p_status: 'FAILED',
                        p_transaction_id: null, p_error: String(executionError?.message || executionError),
                    });
                    try {
                        await this.notifyScheduleExecution(execution, 'FAILED');
                    } catch (notificationError: any) {
                        console.warn(`[Treasury] Schedule ${execution.id} failed; notification queued delivery failed: ${notificationError.message}`);
                    }
                }
            }
        } catch (e: any) {
            console.error(`[Treasury] Global Auto-Sweep failed: ${e.message}`);
        }
    }

    /**
     * AUTO-SWEEPING ENGINE
     * Sweeps excess liquidity from operating vaults into Corporate Treasury Goals.
     */
    public async executeAutoSweep(organizationId: string, goalId?: string): Promise<boolean> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return false;

        try {
            // 1. Find all corporate goals for this organization that have auto-sweep enabled in metadata
            let goalsQuery = sb.from('goals')
                .select('*')
                .eq('organization_id', organizationId)
                .eq('is_corporate', true)
                .eq('status', 'ACTIVE');
            if (goalId) goalsQuery = goalsQuery.eq('id', goalId);
            const { data: goals } = await goalsQuery;

            if (!goals || goals.length === 0) return false;

            const sweepGoals = goals.filter(g => g.auto_sweep_enabled === true && Number(g.sweep_threshold) > 0);
            if (sweepGoals.length === 0) return false;

            // 2. Find the organization's primary operating vault
            // Assuming the organization has a primary admin user or a dedicated org vault
            // For now, let's find the operating vault of the ADMIN of this organization
            const { data: admins } = await sb.from('users')
                .select('id')
                .eq('organization_id', organizationId)
                .eq('org_role', 'ADMIN');

            if (!admins || admins.length === 0) return false;

            const adminId = admins[0].id;

            const { data: operatingVault } = await sb.from('platform_vaults')
                .select('id, balance')
                .eq('user_id', adminId)
                .eq('vault_role', 'OPERATING')
                .single();

            if (!operatingVault) return false;

            const txService = new TransactionService();
            let currentBalance = await txService.getLatestBalance(adminId, operatingVault.id);
            let moved = false;

            // 3. Execute Sweeps
            for (const goal of sweepGoals) {
                const threshold = Number(goal.sweep_threshold);
                
                if (currentBalance > threshold) {
                    const excess = currentBalance - threshold;
                    
                    // Cap the sweep to the remaining amount needed for the goal
                    const currentSaved = Number(goal.current) || 0;
                    const targetAmount = Number(goal.target) || 0;
                    const remainingNeeded = targetAmount - currentSaved;

                    if (remainingNeeded <= 0) continue; // Goal already met

                    const sweepAmount = Math.min(excess, remainingNeeded);

                    if (sweepAmount > 0) {
                        const txId = UUID.generate();
                        const legs = [
                            {
                                transactionId: txId,
                                walletId: operatingVault.id,
                                type: 'DEBIT' as 'DEBIT',
                                amount: sweepAmount,
                                currency: goal.currency,
                                description: `Auto-Sweep to Treasury: ${goal.name}`,
                                timestamp: new Date().toISOString()
                            },
                            {
                                transactionId: txId,
                                walletId: goal.id, // Assuming goal acts as a wallet or has a linked wallet
                                type: 'CREDIT' as 'CREDIT',
                                amount: sweepAmount,
                                currency: goal.currency,
                                description: `Inbound Auto-Sweep from Operating Vault`,
                                timestamp: new Date().toISOString()
                            }
                        ];

                        await txService.postTransactionWithLedger({
                            id: txId,
                            user_id: adminId,
                            amount: sweepAmount,
                            description: `Treasury Auto-Sweep: ${goal.name}`,
                            type: 'transfer',
                            status: 'completed',
                            walletId: operatingVault.id,
                            toWalletId: goal.id,
                            metadata: { is_auto_sweep: true, goal_id: goal.id }
                        }, legs);

                        // Update goal current
                        await sb.from('goals')
                            .update({ current: currentSaved + sweepAmount })
                            .eq('id', goal.id);

                        await Audit.log('FINANCIAL', adminId, 'TREASURY_AUTO_SWEEP', { goalId: goal.id, amount: sweepAmount });
                        currentBalance -= sweepAmount;
                        moved = true;
                    }
                }
            }

            return moved;

        } catch (e: any) {
            console.error(`[Treasury] Auto-Sweep failed for org ${organizationId}: ${e.message}`);
            throw e;
        }
    }

    /**
     * MAKER-CHECKER APPROVAL ENGINE
     * Requests approval for a withdrawal from a Corporate Treasury Goal.
     */
    public async requestWithdrawal(userId: string, goalId: string, amount: number, destinationWalletId: string, reason: string): Promise<string> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) throw new Error("Database connection required");

        const txId = UUID.generate();
        const { data: request, error } = await sb.rpc('request_treasury_withdrawal_v1', {
            p_transaction_id: txId,
            p_user_id: userId,
            p_goal_id: goalId,
            p_destination_wallet_id: destinationWalletId,
            p_amount: amount,
            p_encrypted_amount: await DataProtection.encryptAmount(amount),
            p_encrypted_description: await DataProtection.encryptDescription(`Treasury Withdrawal Request: ${reason}`),
            p_reason: reason,
            p_reference_id: `TREAS-${UUID.generateShortCode(8)}`,
        });
        if (error) throw new Error(`Failed to create withdrawal request: ${error.message}`);

        await Audit.log('SECURITY', userId, 'TREASURY_WITHDRAWAL_REQUESTED', { txId, goalId, amount });

        // Notify Finance/Admin users
        const { data: admins } = await sb.from('users')
            .select('id, language')
            .eq('organization_id', request.organization_id)
            .in('org_role', ['ADMIN', 'FINANCE']);
            
        if (admins) {
            for (const admin of admins) {
                if (admin.id !== userId) {
                    const language = admin.language || 'en';
                    const subject = language === 'sw' ? 'Ombi la Kutoa Fedha za Hazina' : 'Pending Treasury Withdrawal';
                    const body = language === 'sw' 
                        ? `Ombi jipya la kutoa fedha za hazina la ${amount} linahitaji idhini yako. Sababu: ${reason}` 
                        : `A new treasury withdrawal request for ${amount} requires your approval. Reason: ${reason}`;

                    await Messaging.dispatch(
                        admin.id,
                        'info',
                        subject,
                        body,
                        { 
                            sms: true,
                            email: true,
                            template: 'Treasury_Withdrawal_Request',
                            variables: {
                                amount: amount.toLocaleString(),
                                currency: 'TZS',
                                reason
                            }
                        }
                    );
                }
            }
        }

        return txId;
    }

    /**
     * APPROVE TREASURY WITHDRAWAL
     * Finance admins can approve pending withdrawals.
     */
    public async approveWithdrawal(adminId: string, txId: string): Promise<boolean> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) throw new Error("Database connection required");

        const { data: approval, error: approvalError } = await sb.rpc('approve_treasury_withdrawal_v1', {
            p_admin_id: adminId,
            p_transaction_id: txId,
        });
        if (approvalError) throw new Error(approvalError.message);
        if (!approval || approval.should_execute !== true) {
            return Boolean(approval?.fully_approved);
        }

        // Only the approver that atomically crossed quorum receives should_execute.
        if (approval.fully_approved === true) {
            return this.executeClaimedWithdrawal(txId, adminId);
        }

        return false;
    }

    private async notifyScheduleExecution(execution: any, status: 'COMPLETED' | 'SKIPPED' | 'FAILED'): Promise<void> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) throw new Error('Database connection required');
        const { data: recipients, error } = await sb.from('users').select('id, language')
            .eq('organization_id', execution.organization_id).eq('account_status', 'ACTIVE')
            .in('org_role', ['ADMIN', 'SIGNATORY']);
        if (error) throw new Error(error.message);
        for (const recipient of recipients || []) {
            const sw = recipient.language === 'sw';
            const copy = status === 'COMPLETED'
                ? { subject: sw ? 'Uhamisho wa Hazina Umekamilika' : 'Treasury sweep completed', body: sw ? 'Uhamisho wa fedha uliopangwa umekamilika salama.' : 'The scheduled treasury sweep completed successfully.' }
                : status === 'SKIPPED'
                    ? { subject: sw ? 'Uhamisho wa Hazina Umerukwa' : 'Treasury sweep skipped', body: sw ? 'Uhamisho uliopangwa haukufanyika kwa sababu hakukuwa na fedha za ziada zinazostahili.' : 'The scheduled sweep did not run because there was no eligible excess liquidity.' }
                    : { subject: sw ? 'Uhamisho wa Hazina Umeshindwa' : 'Treasury sweep failed', body: sw ? 'Uhamisho uliopangwa umeshindwa. Wasimamizi wanapaswa kukagua tukio hili.' : 'The scheduled treasury sweep failed and requires administrator review.' };
            await Messaging.dispatch(recipient.id, status === 'FAILED' ? 'security' : 'info', copy.subject, copy.body, {
                push: true, sms: true, email: true, mandatory: true, systemCustomBypass: true,
                eventCode: `TREASURY_SCHEDULE_${status}`,
                idempotencyKey: `treasury-schedule:${execution.id}:${status}:${recipient.id}`,
            });
        }
    }

    public async recoverClaimedWithdrawal(txId: string, workerId: string): Promise<boolean> {
        const sb = getAdminSupabase();
        if (!sb) return false;
        const { data: claim, error } = await sb.rpc('claim_treasury_withdrawal_execution_v1', {
            p_transaction_id: txId,
            p_worker_id: workerId,
            p_lease_seconds: 120,
        });
        if (error) throw new Error(error.message);
        if (claim?.claimed !== true) return false;
        return this.executeClaimedWithdrawal(txId, workerId);
    }
    /**
     * GET PENDING APPROVALS
     * Retrieves all pending treasury withdrawals for a specific organization.
     */
    public async getPendingApprovals(organizationId: string): Promise<any[]> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return [];
        
        // Find all goals for this org
        const { data: goals } = await sb.from('goals').select('id').eq('organization_id', organizationId);
        if (!goals || goals.length === 0) return [];
        const goalIds = goals.map(g => g.id);

        // Find transactions held for review targeting these goals
        const { data: txs } = await sb.from('transactions')
            .select('*')
            .eq('status', 'held_for_review')
            .in('wallet_id', goalIds);

        const userIds = Array.from(new Set((txs || []).map((tx: any) => String(tx.user_id || '')).filter(Boolean)));
        const usersById = new Map<string, any>();
        if (userIds.length > 0) {
            const { data: users, error: userError } = await sb.from('users')
                .select('id, full_name, email')
                .in('id', userIds);
            if (userError) throw new Error(userError.message);
            for (const user of users || []) {
                usersById.set(String(user.id), user);
            }
        }

        return (txs || []).map((tx: any) => ({
            ...tx,
            users: usersById.get(String(tx.user_id)) || null,
        }));
    }

    /**
     * CONFIGURE AUTO SWEEP
     * Updates the auto-sweep settings for a corporate goal.
     */
    public async requestAutoSweepChange(actorId: string, input: { goalId: string; enabled: boolean; threshold: number; frequency: string; timezone: string; nextRunAt: string; windowMinutes: number; reason: string }): Promise<string> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) throw new Error('Database connection required');
        const { data, error } = await sb.rpc('request_treasury_schedule_change_v1', {
            p_actor_id: actorId, p_goal_id: input.goalId, p_enabled: input.enabled,
            p_threshold: input.threshold, p_frequency: input.frequency, p_timezone: input.timezone,
            p_next_run_at: input.nextRunAt, p_window_minutes: input.windowMinutes, p_reason: input.reason,
        });
        if (error) throw new Error(error.message);
        await Audit.log('SECURITY', actorId, 'TREASURY_SCHEDULE_CHANGE_REQUESTED', { ...input, requestId: data }, data);
        const { data: goal } = await sb.from('goals').select('organization_id').eq('id', input.goalId).single();
        const { data: reviewers } = await sb.from('users').select('id, language').eq('organization_id', goal?.organization_id)
            .eq('account_status', 'ACTIVE').in('org_role', ['ADMIN', 'SIGNATORY']).neq('id', actorId);
        for (const reviewer of reviewers || []) {
            const sw = reviewer.language === 'sw';
            try { await Messaging.dispatch(reviewer.id, 'security', sw ? 'Ratiba ya Hazina Inahitaji Idhini' : 'Treasury schedule requires approval',
                sw ? 'Ombi la kubadili ratiba ya uhamisho wa hazina linasubiri ukaguzi wako.' : 'A treasury sweep schedule change is awaiting your independent review.', {
                    push: true, sms: true, email: true, mandatory: true, systemCustomBypass: true,
                    eventCode: 'TREASURY_SCHEDULE_CHANGE_REQUESTED',
                    idempotencyKey: `treasury-schedule-change:${data}:requested:${reviewer.id}`,
                }); } catch (notificationError: any) {
                console.warn(`[Treasury] Schedule request ${data} committed; reviewer notification deferred: ${notificationError.message}`);
            }
        }
        return data;
    }

    public async respondAutoSweepChange(actorId: string, requestId: string, decision: string, reason: string): Promise<any> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) throw new Error('Database connection required');
        const { data: request, error: requestError } = await sb.from('treasury_schedule_change_requests')
            .select('requested_by').eq('id', requestId).single();
        if (requestError || !request) throw new Error('TREASURY_SCHEDULE_REQUEST_NOT_FOUND');
        const { data, error } = await sb.rpc('respond_treasury_schedule_change_v1', {
            p_reviewer_id: actorId, p_request_id: requestId, p_decision: decision, p_reason: reason,
        });
        if (error) throw new Error(error.message);
        await Audit.log('SECURITY', actorId, 'TREASURY_SCHEDULE_CHANGE_REVIEWED', { requestId, decision, reason }, requestId);
        if (request?.requested_by) {
            const { data: requester } = await sb.from('users').select('language').eq('id', request.requested_by).single();
            const sw = requester?.language === 'sw';
            const result = String(data?.status || decision).toUpperCase();
            try { await Messaging.dispatch(request.requested_by, 'security', sw ? 'Ukaguzi wa Ratiba ya Hazina Umekamilika' : 'Treasury schedule review completed',
                sw ? `Ombi la ratiba ya hazina limekamilishwa kwa hali: ${result}.` : `The treasury schedule request review completed with status: ${result}.`, {
                    push: true, sms: true, email: true, mandatory: true, systemCustomBypass: true,
                    eventCode: 'TREASURY_SCHEDULE_CHANGE_REVIEWED',
                    idempotencyKey: `treasury-schedule-change:${requestId}:reviewed:${request.requested_by}`,
                }); } catch (notificationError: any) {
                console.warn(`[Treasury] Schedule review ${requestId} committed; requester notification deferred: ${notificationError.message}`);
            }
        }
        return data;
    }
}

export const Treasury = new TreasuryService();
