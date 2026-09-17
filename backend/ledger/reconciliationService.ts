
import { Transaction, LedgerEntry, TransactionStatus, ReconciliationReport } from '../../types.js';
import { getSupabase, getAdminSupabase } from '../../services/supabaseClient.js';
import { Audit } from '../security/audit.js';
import { DataVault } from '../security/encryption.js';
import { UUID } from '../../services/utils.js';
import { TransactionService } from '../../ledger/transactionService.js';
import { EscrowService } from '../../ledger/escrowService.js';
import { BankingEngine } from './transactionEngine.js';
import { ProviderFactory } from '../payments/providers/ProviderFactory.js';
import { resolveProviderCode } from '../payments/financialPartnerMetadata.js';
import { SocketRegistry } from '../infrastructure/SocketRegistry.js';
import { DataProtection } from '../security/DataProtection.js';
import { Treasury } from '../enterprise/treasuryService.js';
import { Messaging } from '../features/MessagingService.js';
// emailService and brevoSmsService removed as per user request.

/**
 * ORBI RECONCILIATION ENGINE (V6.0 Titanium)
 * ----------------------------------
 * Ensures integrity between the Transaction Header and the Ledger Legs.
 * Identifies 'Ghost Transactions' or 'Imbalanced Legs'.
 * Now handles 'Stuck Transaction' reaping for staged settlements.
 */
export class ReconciliationService {
    public async escalateOverdueExceptions(): Promise<number> {
        const sb=getAdminSupabase();if(!sb)return 0;
        const {data,error}=await sb.rpc('escalate_overdue_financial_exceptions_v1');if(error)throw new Error(error.message);
        const {data:recipients}=await sb.from('staff').select('id').eq('account_status','ACTIVE').in('role',['SUPER_ADMIN','ADMIN','AUDIT','RISK_OFFICER']);
        for(const item of data||[])for(const recipient of recipients||[]){try{await Messaging.dispatch(recipient.id,'security','Financial exception SLA breached',`Exception ${item.id} is overdue and requires immediate review.`,{push:true,sms:true,email:true,mandatory:true,systemCustomBypass:true,eventCode:'FINANCIAL_EXCEPTION_ESCALATED',idempotencyKey:`financial-exception:${item.id}:escalated:${recipient.id}`});}catch(e:any){console.warn(`[FinancialException] escalation notification deferred: ${e.message}`);}}
        return (data||[]).length;
    }
    private async resolvePartnerForVault(vault: any, partners: any[]): Promise<any | null> {
        const metadata = vault?.metadata && typeof vault.metadata === 'object' ? vault.metadata : {};
        const candidates = [
            metadata.partner_id,
            metadata.partnerId,
            metadata.provider_id,
            metadata.providerId,
            metadata.partner_code,
            metadata.partnerCode,
            metadata.provider_code,
            metadata.providerCode,
        ]
            .map((value) => String(value || '').trim())
            .filter(Boolean);

        if (!candidates.length) return null;

        for (const candidate of candidates) {
            const directMatch = partners.find((partner) => String(partner?.id || '').trim() === candidate);
            if (directMatch) return directMatch;

            const normalizedCandidate = candidate.toLowerCase();
            const codeMatch = partners.find((partner) => {
                const providerCode = resolveProviderCode(partner).trim().toLowerCase();
                return providerCode && providerCode === normalizedCandidate;
            });
            if (codeMatch) return codeMatch;

            const nameMatch = partners.find((partner) => String(partner?.name || '').trim().toLowerCase() === normalizedCandidate);
            if (nameMatch) return nameMatch;
        }

        return null;
    }
    
    /**
     * STUCK TRANSACTION REAPER
     * ------------------------
     * Finds transactions stuck in 'processing' state.
     * - If not in manual review: timeout after 5 minutes.
     * - If in manual review: timeout after 24 hours.
     */
    public async reapStuckTransactions() {
        console.info(`[ReconEngine] Starting stuck transaction reaper cycle...`);
        const sb = getAdminSupabase();
        if (!sb) return;

        try {
            const txService = new TransactionService();
            await txService.autoReverseHeldTransactions();
            await new EscrowService().autoRefundExpiredUnacceptedEscrows();
            const { data: stuckTxs, error } = await sb.from('transactions')
                .select('*')
                .eq('status', 'processing');

            if (error || !stuckTxs) return;

            const now = new Date();
            let reapedCount = 0;

            for (const tx of stuckTxs) {
                try {
                    if (tx.metadata?.is_treasury_withdrawal === true) {
                        const recovered = await Treasury.recoverClaimedWithdrawal(tx.id, 'system-treasury-reaper');
                        if (recovered) reapedCount++;
                        continue;
                    }
                    const createdAt = new Date(tx.created_at);
                    const ageMs = now.getTime() - createdAt.getTime();
                    const ageMinutes = ageMs / (1000 * 60);
                    const ageHours = ageMinutes / 60;

                    const isManualReview = tx.metadata?.manual_review === true || tx.status_notes?.includes('MANUAL_REVIEW');
                    
                    let shouldReverse = false;
                    let reason = '';

                    if (isManualReview) {
                        if (ageHours >= 24) {
                            shouldReverse = true;
                            reason = 'REAPER_TIMEOUT: Manual review exceeded 24hr limit.';
                        }
                    } else {
                        if (ageMinutes >= 5) {
                            shouldReverse = true;
                            reason = 'REAPER_TIMEOUT: Processing stuck for >5 minutes.';
                        }
                    }

                    if (shouldReverse) {
                        // Try to settle first if it's a transfer
                        if (tx.type === 'transfer') {
                            // Check if it's already effectively settled (Direct legs instead of Escrow)
                            const legs = await txService.getLedgerEntries(tx.id);
                            const hasDirectCredit = legs.some(l => l.wallet_id === tx.to_wallet_id && l.entry_type === 'CREDIT');
                            const hasEscrowCredit = legs.some(l => l.description?.includes('PaySafe Secure Lock'));

                            if (hasDirectCredit && !hasEscrowCredit) {
                                console.info(`[ReconEngine] Detected direct transfer mislabeled as processing: ${tx.id}. Marking as completed.`);
                                await txService.updateTransactionStatus(tx.id, 'completed', 'Mislabeled direct transfer finalized by reaper.');
                                reapedCount++;
                                continue;
                            }

                            const settled = await BankingEngine.completeSettlement(tx.id);
                            if (settled) {
                                console.info(`[ReconEngine] Successfully settled stuck transaction ${tx.id}.`);
                                reapedCount++;
                                continue;
                            }
                        }
                        
                        console.warn(`[ReconEngine] Reaping stuck transaction ${tx.id}. Reason: ${reason}`);
                        await txService.reverseTransaction(tx.id, 'SYSTEM_REAPER');
                        await txService.updateTransactionStatus(tx.id, 'failed', reason);
                        reapedCount++;
                    }
                } catch (txError: any) {
                    console.error(`[ReconEngine] Failed to process stuck transaction ${tx.id}: ${txError.message}`);
                }
            }

            if (reapedCount > 0) {
                await Audit.log('FINANCIAL', 'system-reaper', 'STUCK_TRANSACTIONS_REAPED', { count: reapedCount });
            }

        } catch (e: any) {
            console.error(`[ReconEngine] Reaper Fault: ${e.message}`);
        }
    }

    /**
     * INTERNAL RECONCILIATION
     * -----------------------
     * Compares Ledger Sums vs Wallet Balances.
     * If Ledger says User has 100 but Wallet says 90 -> Mismatch.
     */
    public async runInternalRecon() {
        console.info(`[ReconEngine] Starting Internal Reconciliation (Ledger vs Wallets)...`);
        const sb = getAdminSupabase();
        if (!sb) return;

        try {
            // 1. Fetch all wallets
            const { data: wallets } = await sb.from('wallets').select('id, balance, user_id');
            if (!wallets) return;

            let discrepancies = 0;

            for (const wallet of wallets) {
                // 2. Calculate Ledger Sum for this wallet
                const { data: legs } = await sb.from('financial_ledger')
                    .select('amount, entry_type')
                    .eq('wallet_id', wallet.id);

                let ledgerBalance = 0;
                if (legs) {
                    for (const leg of legs) {
                        const amt = await DataProtection.decryptAmount(leg.amount);
                        if (leg.entry_type === 'CREDIT') ledgerBalance += amt;
                        else ledgerBalance -= amt;
                    }
                }

                const walletBalance = Number(wallet.balance);
                const diff = Math.abs(ledgerBalance - walletBalance);

                if (diff > 0.01) {
                    discrepancies++;
                    console.error(`[ReconEngine] INTERNAL_MISMATCH: Wallet ${wallet.id}. Ledger: ${ledgerBalance}, Wallet: ${walletBalance}`);
                    
                    await this.saveReport({
                        type: 'INTERNAL',
                        expected_balance: ledgerBalance,
                        actual_balance: walletBalance,
                        difference: diff,
                        status: 'MISMATCH',
                        metadata: { walletId: wallet.id, userId: wallet.user_id }
                    });

                    await Audit.log('SECURITY', 'system-recon', 'RECON_INTERNAL_BALANCE_MISMATCH', {
                        walletId: wallet.id,
                        userId: wallet.user_id,
                        expected_balance: ledgerBalance,
                        actual_balance: walletBalance,
                        difference: diff,
                        notify_customer: false,
                    });
                }
            }

            await Audit.log('SECURITY', 'system-recon', 'INTERNAL_RECON_COMPLETE', { discrepancies });
        } catch (e: any) {
            console.error(`[ReconEngine] Internal Recon Fault: ${e.message}`);
        }
    }

    /**
     * SYSTEM RECONCILIATION
     * ---------------------
     * Compares Transaction Header vs Ledger Legs.
     * Every transaction must have matching credit/debit legs.
     */
    public async runSystemRecon() {
        console.info(`[ReconEngine] Starting System Reconciliation (Transactions vs Ledger)...`);
        const sb = getAdminSupabase();
        if (!sb) return;

        try {
            const { data: txs } = await sb.from('transactions')
                .select('*')
                .order('created_at', { ascending: false })
                .limit(500);

            if (!txs) return;

            let anomalies = 0;

            for (const tx of txs) {
                const { data: legs } = await sb.from('financial_ledger')
                    .select('amount, entry_type')
                    .eq('transaction_id', tx.id);

                if (!legs || legs.length === 0) {
                    if (tx.status === 'completed' || tx.status === 'processing') {
                        console.warn(`[ReconEngine] GHOST_TX: ${tx.id} has no ledger legs!`);
                        anomalies++;
                        const txAmount = await DataProtection.decryptAmount(tx.amount);
                        await this.saveReport({
                            type: 'SYSTEM',
                            expected_balance: txAmount,
                            actual_balance: 0,
                            difference: txAmount,
                            status: 'MISMATCH',
                            metadata: { txId: tx.id, issue: 'GHOST_TRANSACTION' }
                        });
                    }
                    continue;
                }

                // Verify double-entry balance for transfers
                if (tx.type === 'transfer') {
                    let sum = 0;
                    for (const leg of legs) {
                        const amt = await DataProtection.decryptAmount(leg.amount);
                        if (leg.entry_type === 'CREDIT') sum += amt;
                        else sum -= amt;
                    }
                    if (Math.abs(sum) > 0.01) {
                        console.error(`[ReconEngine] IMBALANCED_LEGS: TX ${tx.id} sum is ${sum}`);
                        anomalies++;
                    }
                }
            }

            await Audit.log('FINANCIAL', 'system-recon', 'SYSTEM_RECON_COMPLETE', { anomalies });
        } catch (e: any) {
            console.error(`[ReconEngine] System Recon Fault: ${e.message}`);
        }
    }

    private async saveReport(report: Partial<ReconciliationReport>) {
        const sb = getAdminSupabase();
        if (!sb) return;

        const fullReport = {
            id: UUID.generate(),
            type: report.type,
            expected_balance: report.expected_balance || 0,
            actual_balance: report.actual_balance || 0,
            difference: report.difference || 0,
            status: report.status || 'INVESTIGATING',
            metadata: report.metadata || {},
            created_at: new Date().toISOString()
        };

        await sb.from('reconciliation_reports').insert(fullReport);
        
        if (fullReport.status === 'MISMATCH') {
            const severity = Number(fullReport.difference || 0) >= 1_000_000 ? 'CRITICAL' : Number(fullReport.difference || 0) > 0 ? 'HIGH' : 'MEDIUM';
            const { error: exceptionError } = await sb.rpc('open_financial_exception_v1', {
                p_source_type: 'RECONCILIATION', p_source_id: fullReport.id,
                p_organization_id: (fullReport.metadata as any)?.organizationId || null,
                p_severity: severity, p_category: String(fullReport.type || 'RECONCILIATION_MISMATCH'),
                p_title: `Reconciliation mismatch: ${fullReport.type || 'UNKNOWN'}`,
                p_details: fullReport,
            });
            if (exceptionError) throw new Error(`FINANCIAL_EXCEPTION_OPEN_FAILED: ${exceptionError.message}`);
            // Trigger high-priority alerts
            await Audit.log('SECURITY', 'recon-engine', 'RECON_MISMATCH_DETECTED', fullReport);
        }
    }

    public async runDailyRecon(providerId: string = 'SYSTEM_DEFAULT') {
        console.info(`[ReconEngine] Starting integrity audit for provider: ${providerId}`);
        
        const sb = getAdminSupabase();
        if (!sb) return { status: 'SKIPPED', reason: 'CLOUD_OFFLINE' };

        try {
            // 1. Fetch recent transactions
            const { data: txs } = await sb.from('transactions')
                .select('id, amount')
                .order('created_at', { ascending: false })
                .limit(100);

            if (!txs) return { status: 'COMPLETED', anomalies: 0 };

            let anomalies = 0;

            // 2. Cross-reference with Ledger
            for (const tx of txs) {
                const { data: legs } = await sb.from('financial_ledger')
                    .select('amount, entry_type')
                    .eq('transaction_id', tx.id);

                if (!legs || legs.length === 0) {
                    console.warn(`[ReconEngine] GHOST_TX detected: ${tx.id}`);
                    anomalies++;
                    continue;
                }

                // Decrypt and sum
                const txAmount = await DataProtection.decryptAmount(tx.amount);
                let ledgerSum = 0;
                for (const leg of legs) {
                    const legAmt = await DataProtection.decryptAmount(leg.amount);
                    if (leg.entry_type === 'CREDIT') ledgerSum += legAmt;
                    else ledgerSum -= legAmt;
                }

                // In a double-entry system, the sum of legs for a single transaction 
                // (from the perspective of the system) should often be 0 if it's a transfer,
                // or match the header if it's a single-sided entry.
                // Here we just check if the legs are consistent.
                if (Math.abs(ledgerSum) > 0.01 && Math.abs(ledgerSum) !== txAmount) {
                    console.error(`[ReconEngine] IMBALANCED_LEGS in Daily Recon: TX ${tx.id} sum is ${ledgerSum}, expected 0 or ${txAmount}`);
                    anomalies++;
                }
            }

            await Audit.log('ADMIN', 'system-recon', 'RECON_CYCLE_COMPLETE', { anomalies });

            return {
                status: 'SUCCESS',
                timestamp: new Date().toISOString(),
                anomalies,
                integrityScore: anomalies === 0 ? 100 : Math.max(0, 100 - (anomalies * 5))
            };

        } catch (e: any) {
            console.error(`[ReconEngine] Audit Fault: ${e.message}`);
            return { status: 'FAILED', error: e.message };
        }
    }

    public async reconcileVaultsAgainstPartners() {
        console.info(`[ReconEngine] Starting partner reconciliation audit...`);
        
        const sb = getAdminSupabase();
        if (!sb) return { status: 'SKIPPED', reason: 'CLOUD_OFFLINE' };

        try {
            // Fetch active vaults
            const { data: vaults } = await sb.from('platform_vaults')
                .select('id, user_id, name, balance, metadata')
                .limit(50);

            if (!vaults || vaults.length === 0) return { status: 'COMPLETED', discrepancies: 0 };

            const { data: partners, error: partnersError } = await sb
                .from('financial_partners')
                .select('*')
                .eq('status', 'ACTIVE');
            if (partnersError) throw partnersError;
            if (!partners || partners.length === 0) {
                return { status: 'SKIPPED', reason: 'NO_ACTIVE_PARTNERS' };
            }

            let discrepancies = 0;
            const auditLogs = [];
            let totalChecked = 0;

            for (const vault of vaults) {
                const internalBalance = Number(vault.balance);
                
                // 1. Resolve Partner
                const partner = await this.resolvePartnerForVault(vault, partners);
                if (!partner) {
                    console.warn(`[ReconEngine] Skipping vault ${vault.id}: no configured partner mapping found in vault metadata.`);
                    await Audit.log('SECURITY', 'recon-engine', 'PARTNER_RECON_SKIPPED_UNMAPPED_VAULT', {
                        vaultId: vault.id,
                        vaultName: vault.name,
                    });
                    continue;
                }
                totalChecked++;

                // 2. Fetch External Balance
                const provider = ProviderFactory.getProvider(partner);
                let externalBalance = 0;
                try {
                    externalBalance = await provider.getBalance(partner);
                } catch (e) {
                    console.error(`[ReconEngine] Failed to fetch external balance for ${partner.name}:`, e);
                    continue;
                }

                const discrepancyAmount = internalBalance - externalBalance;

                if (Math.abs(discrepancyAmount) > 0.01) {
                    discrepancies++;
                    console.warn(`[ReconEngine] Partner Discrepancy detected for vault: ${vault.id}. Internal: ${internalBalance}, External: ${externalBalance}`);
                    
                    // Instant Alert (Push and Audit only - Email/SMS removed)
                    console.error(`[ReconEngine] CRITICAL: Partner Discrepancy detected for vault: ${vault.id}. Internal: ${internalBalance}, External: ${externalBalance}`);
                    
                    await Audit.log('SECURITY', 'recon-engine', 'PARTNER_DISCREPANCY_ALERT', {
                        vaultId: vault.id,
                        internalBalance,
                        externalBalance,
                        discrepancy: discrepancyAmount
                    });

                    // Real-time UI Alert
                    SocketRegistry.broadcast({
                        type: 'ALERT',
                        payload: {
                            title: 'Partner Discrepancy Detected',
                            message: `Discrepancy for vault ${vault.id}: ${discrepancyAmount}`,
                            severity: 'HIGH',
                            vaultId: vault.id,
                            internalBalance,
                            externalBalance
                        }
                    });

                    await this.saveReport({
                        type: 'EXTERNAL',
                        expected_balance: externalBalance,
                        actual_balance: internalBalance,
                        difference: discrepancyAmount,
                        status: 'MISMATCH',
                        metadata: { vaultId: vault.id, partnerId: partner.id }
                    });
                } else {
                    await this.saveReport({
                        type: 'EXTERNAL',
                        expected_balance: externalBalance,
                        actual_balance: internalBalance,
                        difference: discrepancyAmount,
                        status: 'MATCHED',
                        metadata: { vaultId: vault.id, partnerId: partner.id }
                    });
                }

                auditLogs.push({
                    id: UUID.generate(),
                    vault_id: vault.id,
                    partner_id: partner.id,
                    internal_balance: internalBalance,
                    external_balance: externalBalance,
                    discrepancy: discrepancyAmount,
                    status: Math.abs(discrepancyAmount) > 0.01 ? 'DISCREPANCY' : 'MATCHED',
                    created_at: new Date().toISOString()
                });
            }

            // Log to the new item_reconciliation_audit table
            if (auditLogs.length > 0) {
                const { error } = await sb.from('item_reconciliation_audit').insert(auditLogs);
                if (error) {
                    console.error(`[ReconEngine] Failed to insert audit logs: ${error.message}`);
                }
            }

            await Audit.log('ADMIN', 'system-recon', 'PARTNER_RECON_CYCLE_COMPLETE', { discrepancies, totalChecked });

            return {
                status: 'SUCCESS',
                timestamp: new Date().toISOString(),
                discrepancies,
                totalChecked
            };

        } catch (e: any) {
            console.error(`[ReconEngine] Partner Audit Fault: ${e.message}`);
            return { status: 'FAILED', error: e.message };
        }
    }

    public async runAllRecon() {
        console.info(`[ReconEngine] Starting FULL Reconciliation Cycle...`);
        await this.runInternalRecon();
        await this.runSystemRecon();
        await this.reconcileVaultsAgainstPartners();
        console.info(`[ReconEngine] FULL Reconciliation Cycle Complete.`);
    }
}

export const ReconEngine = new ReconciliationService();
