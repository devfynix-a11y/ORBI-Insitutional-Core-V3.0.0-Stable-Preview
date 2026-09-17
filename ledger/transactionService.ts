
import { Transaction, LedgerEntry, TransactionStatus, Wallet } from '../types.js';
import { getSupabase, getAdminSupabase } from '../services/supabaseClient.js';
import { DataProtection } from '../backend/security/DataProtection.js';
import { Audit } from '../backend/security/audit.js';
import { UUID } from '../services/utils.js';
import { RegulatoryService } from './regulatoryService.js';
import { Messaging } from '../backend/features/MessagingService.js';
import { SocketRegistry } from '../backend/infrastructure/SocketRegistry.js';
import { TransactionStateMachine } from '../backend/ledger/stateMachine.js';
import {
    assertReversalEligible,
    normalizeFinancialAuthorityError,
} from '../backend/ledger/financialInvariants.js';
import { RiskComplianceEngine } from '../backend/security/RiskComplianceEngine.js';
import { PerfMonitor } from '../backend/infrastructure/PerfMonitor.js';
import { logger } from '../backend/infrastructure/logger.js';
import { TransactionMovementClassifier } from '../backend/transactions/movement/TransactionMovementClassifier.js';
import { getOrbiDatabase } from '../services/orbiDatabase.js';

const ledgerLogger = logger.child({ component: 'transaction_service' });

/**
 * INSTITUTIONAL LEDGER SERVICE (V22.0 Titanium)
 * -------------------------------------------
 * The source of truth for the Sovereign Cluster.
 */
export class TransactionService {
    public normalizeFinancialAuthorityError(error: any, context: string = 'FINANCIAL_AUTHORITY'): Error {
        return normalizeFinancialAuthorityError(error, context);
    }

    public async getMobileTransactions(
        userId: string,
        limit: number = 50,
        offset: number = 0,
    ): Promise<any[]> {
        const safeLimit = Math.min(Math.max(Number(limit) || 50, 1), 200);
        const safeOffset = Math.max(Number(offset) || 0, 0);
        const result = await getOrbiDatabase().query(
            `
              WITH owned_transaction_ids AS (
                SELECT DISTINCT transaction_id
                FROM public.financial_ledger
                WHERE user_id = $1::uuid
                  AND transaction_id IS NOT NULL
              )
              SELECT
                t.id, t.reference_id, t.user_id, t.amount, t.currency,
                t.description, t.type, t.status, t.created_at,
                t.wallet_id, t.to_wallet_id, t.metadata, t.category_id
              FROM public.transactions t
              WHERE t.user_id = $1::uuid
                 OR EXISTS (
                   SELECT 1 FROM owned_transaction_ids owned
                   WHERE owned.transaction_id = t.id
                 )
              ORDER BY t.created_at DESC
              LIMIT $2 OFFSET $3
            `,
            [userId, safeLimit, safeOffset],
        );

        const rows = await this.decryptTransactionRows(result.rows || []);
        return rows.map((row: any) => {
            const isSender = String(row.user_id || '') === String(userId);
            const rawStatus = String(row.status || '').toLowerCase();
            const status = rawStatus === 'processing'
                ? 'processing'
                : ['failed', 'reversed', 'refunded', 'cancelled'].includes(rawStatus)
                  ? 'failed'
                  : ['created', 'pending', 'authorized'].includes(rawStatus)
                    ? 'initiated'
                    : 'completed';
            return {
                ...row,
                id: row.reference_id || row.id,
                internalId: row.id,
                referenceId: row.reference_id || row.id,
                direction: isSender ? 'DEBIT' : 'CREDIT',
                status,
            };
        });
    }

    private async decryptTransactionRows(rows: any[]): Promise<any[]> {
        return Promise.all((rows || []).map(async (row: any) => ({
            ...row,
            amount: row?.amount !== undefined ? await DataProtection.decryptAmount(row.amount, Number(row.amount || 0)) : row?.amount,
            description: row?.description !== undefined ? await DataProtection.decryptDescription(row.description, row.description || '') : row?.description,
            walletId: row?.wallet_id ?? row?.walletId,
            toWalletId: row?.to_wallet_id ?? row?.toWalletId,
            createdAt: row?.created_at ?? row?.createdAt,
            updatedAt: row?.updated_at ?? row?.updatedAt,
            statusNotes: row?.status_notes ?? row?.statusNotes,
            categoryId: row?.category_id ?? row?.categoryId,
        })));
    }

    private async getCachedBalanceSnapshot(walletId: string): Promise<number | null> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return null;

        const { data: wallet } = await sb.from('wallets').select('balance').eq('id', walletId).maybeSingle();
        if (wallet?.balance !== null && wallet?.balance !== undefined) {
            return Number(wallet.balance) || 0;
        }

        const { data: vault } = await sb.from('platform_vaults').select('balance').eq('id', walletId).maybeSingle();
        if (vault?.balance !== null && vault?.balance !== undefined) {
            return Number(vault.balance) || 0;
        }

        const { data: goal } = await sb.from('goals').select('current').eq('id', walletId).maybeSingle();
        if (goal?.current !== null && goal?.current !== undefined) {
            const numericGoalBalance = Number(goal.current);
            if (!Number.isNaN(numericGoalBalance)) {
                return numericGoalBalance;
            }

            try {
                return await DataProtection.decryptAmount(goal.current);
            } catch {
                return null;
            }
        }

        return null;
    }

    private firstDisplayText(values: any[]): string | undefined {
        for (const value of values) {
            const text = String(value ?? '').trim();
            if (text && text.toLowerCase() !== 'null' && text !== 'N/A') return text;
        }
        return undefined;
    }

    private walletDisplayName(wallet: any, fallback?: string): string | undefined {
        return this.firstDisplayText([
            wallet?.display_name,
            wallet?.wallet_name,
            wallet?.name,
            fallback,
        ]);
    }

    private isOperatingWalletRecord(wallet: any): boolean {
        const text = [
            wallet?.display_name,
            wallet?.wallet_name,
            wallet?.name,
            wallet?.type,
            wallet?.wallet_type,
            wallet?.bucket_type,
            wallet?.vault_role,
            wallet?.role,
            wallet?.management_tier,
        ].map((value) => String(value || '').toLowerCase()).join(' ');
        if (/(escrow|paysafe|pay safe|goal|saving|budget|mezani|pot|fungu|reserve|bill)/.test(text)) {
            return false;
        }
        return /(operating|main|internal vault|default|dilpesa|spendable|available)/.test(text);
    }

    private async resolveLedgerWalletOwners(walletIds: string[]): Promise<Map<string, string>> {
        const sb = getAdminSupabase() || getSupabase();
        const ownerByWalletId = new Map<string, string>();
        const ids = Array.from(new Set((walletIds || []).map((id) => String(id || '').trim()).filter(Boolean)));
        if (!sb || ids.length === 0) return ownerByWalletId;

        const [wallets, vaults, goals] = await Promise.all([
            sb.from('wallets').select('id,user_id').in('id', ids),
            sb.from('platform_vaults').select('id,user_id').in('id', ids),
            sb.from('goals').select('id,user_id').in('id', ids),
        ]);
        [...(wallets.data || []), ...(vaults.data || []), ...(goals.data || [])].forEach((row: any) => {
            const walletId = String(row?.id || '').trim();
            const ownerId = String(row?.user_id || '').trim();
            if (walletId && ownerId) ownerByWalletId.set(walletId, ownerId);
        });
        return ownerByWalletId;
    }

    private pickGeneralBalanceLeg(
        legs: any[],
        userId: string,
        ownedWalletIds: Set<string>,
        walletMap: Record<string, any>,
        transaction?: any,
    ): any {
        const ownedLegs = (legs || []).filter((leg: any) => {
            const walletId = String(leg?.wallet_id || '');
            const wallet = walletMap[walletId];
            if (wallet?.user_id) {
                return String(wallet.user_id) === String(userId);
            }
            return String(leg?.user_id || '') === String(userId) ||
                ownedWalletIds.has(walletId);
        });
        const operatingLegs = ownedLegs.filter((leg: any) =>
            this.isOperatingWalletRecord(walletMap[String(leg?.wallet_id || '')])
        );
        const preferredSide = this.preferredGeneralBalanceSide(transaction);
        if (preferredSide) {
            const preferredOperating = operatingLegs
                .filter((leg: any) => String(leg?.entry_side || leg?.entry_type || '').toUpperCase().includes(preferredSide))
                .sort(this.sortLedgerLegsNewestFirst)[0];
            if (preferredOperating) return preferredOperating;
        }
        return operatingLegs.sort(this.sortLedgerLegsNewestFirst)[0] || null;
    }

    private pickSourceLeg(legs: any[], transaction: any, walletMap: Record<string, any>, userId: string): any {
        const debitLegs = (legs || []).filter((leg: any) =>
            String(leg?.entry_side || leg?.entry_type || '').toUpperCase().includes('DEBIT')
        );
        const transactionSourceWalletId = String(transaction?.walletId || transaction?.wallet_id || '').trim();
        if (transactionSourceWalletId) {
            const exact = debitLegs.find((leg: any) => String(leg?.wallet_id || '') === transactionSourceWalletId);
            if (exact) return exact;
        }
        return debitLegs.find((leg: any) =>
            String(walletMap[String(leg?.wallet_id || '')]?.user_id || leg?.user_id || '') === String(userId) &&
            this.isOperatingWalletRecord(walletMap[String(leg?.wallet_id || '')])
        ) || debitLegs[0];
    }

    private pickDestinationLeg(legs: any[], transaction: any, walletMap: Record<string, any>, userId: string): any {
        const creditLegs = (legs || []).filter((leg: any) =>
            String(leg?.entry_side || leg?.entry_type || '').toUpperCase().includes('CREDIT')
        );
        const transactionTargetWalletId = String(transaction?.toWalletId || transaction?.to_wallet_id || '').trim();
        if (transactionTargetWalletId) {
            const exact = creditLegs.find((leg: any) => String(leg?.wallet_id || '') === transactionTargetWalletId);
            if (exact) return exact;
        }
        return creditLegs.find((leg: any) => {
            const wallet = walletMap[String(leg?.wallet_id || '')];
            return String(wallet?.user_id || leg?.user_id || '') !== String(userId) &&
                this.isOperatingWalletRecord(wallet);
        }) || creditLegs.find((leg: any) => {
            const wallet = walletMap[String(leg?.wallet_id || '')];
            return !String(wallet?.vault_role || wallet?.name || '').toLowerCase().includes('paysafe');
        }) || creditLegs[0];
    }

    private preferredGeneralBalanceSide(transaction?: any): 'CREDIT' | 'DEBIT' | null {
        const text = [
            transaction?.type,
            transaction?.transaction_type,
            transaction?.status,
            transaction?.description,
            transaction?.note,
            transaction?.metadata?.source_wallet_role,
            transaction?.metadata?.target_wallet_role,
            transaction?.metadata?.source_vault_id,
            transaction?.metadata?.target_vault_id,
            transaction?.metadata?.escrow_status,
        ].map((value) => String(value || '').toLowerCase()).join(' ');
        if (/(refund|refunded|reverse|reversed|deposit|withdrawal|withdraw|target_wallet_role.*operating|target vault|target_vault)/.test(text)) {
            return 'CREDIT';
        }
        if (/(contribution|hold|escrow|paysafe|source_wallet_role.*operating|source vault|source_vault)/.test(text)) {
            return 'DEBIT';
        }
        return null;
    }

    private sortLedgerLegsNewestFirst(a: any, b: any): number {
        const at = new Date(a?.created_at || 0).getTime();
        const bt = new Date(b?.created_at || 0).getTime();
        return bt - at;
    }

    private partyDisplayName(user: any, wallet: any, fallback?: string): string {
        return this.firstDisplayText([
            user?.full_name,
            user?.name,
            this.walletDisplayName(wallet),
            fallback,
        ]) || 'External Destination';
    }

    private async decryptLedgerLegRows(rows: any[]): Promise<any[]> {
        return Promise.all((rows || []).map(async (leg: any) => {
            let amount = leg?.amount;
            let balanceAfter = leg?.balance_after_encrypted || leg?.balance_after;

            try {
                amount = amount !== undefined && amount !== null
                    ? await DataProtection.decryptAmount(amount, Number(amount || 0))
                    : amount;
            } catch {
                amount = Number(amount || 0);
            }

            try {
                balanceAfter = balanceAfter !== undefined && balanceAfter !== null
                    ? await DataProtection.decryptAmount(balanceAfter, Number(balanceAfter || 0))
                    : balanceAfter;
            } catch {
                balanceAfter = Number(balanceAfter || 0);
            }

            return {
                ...leg,
                amount: Number(amount || 0),
                balance_after: balanceAfter !== undefined && balanceAfter !== null ? Number(balanceAfter || 0) : null,
            };
        }));
    }
     
    /**
     * CALCULATE BALANCE FROM LEDGER
     * Derives the current balance by summing all ledger entries for a wallet.
     * This is the ultimate source of truth for wallet balances.
     */
    public async calculateBalanceFromLedger(walletId: string): Promise<number> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return 0;

        try {
            const { data: legs, error } = await sb
                .from('financial_ledger')
                .select('amount, entry_side, entry_type')
                .eq('wallet_id', walletId);

            if (error) throw error;
            if (!legs || legs.length === 0) return 0;

            let balance = 0;
            for (const leg of legs) {
                const amount = await DataProtection.decryptAmount(leg.amount);
                const side = String(leg.entry_side || leg.entry_type || '').toUpperCase();
                if (side === 'CREDIT' || side === 'DEPOSIT' || side === 'REFUND') {
                    balance += amount;
                } else if (side === 'DEBIT' || side === 'WITHDRAWAL' || side === 'PAYMENT') {
                    balance -= amount;
                } else {
                    ledgerLogger.warn('ledger.unknown_entry_side_ignored', { wallet_id: walletId, entry_side: leg.entry_side, entry_type: leg.entry_type });
                }
            }

            return Math.round(balance * 10000) / 10000;
        } catch (e: any) {
            ledgerLogger.error('ledger.balance_calculation_failed', { wallet_id: walletId }, e);
            throw new Error(`LEDGER_BALANCE_UNAVAILABLE:${walletId}`);
        }
    }

    public async getLatestBalance(userId: string, walletId: string | null): Promise<number> {
        if (!walletId) throw new Error('SOURCE_WALLET_REQUIRED_FOR_BALANCE');
        const ledgerBalance = await this.calculateBalanceFromLedger(walletId);
        const cachedBalance = await this.getCachedBalanceSnapshot(walletId);
        if (cachedBalance !== null && Math.abs(cachedBalance - ledgerBalance) > 0.01) {
            ledgerLogger.warn('ledger.balance_drift_detected', { wallet_id: walletId, actor_id: userId, cached_balance: cachedBalance, ledger_balance: ledgerBalance });
        }
        if (ledgerBalance === null || ledgerBalance === undefined || isNaN(ledgerBalance)) {
            ledgerLogger.error('ledger.invalid_balance_result', { wallet_id: walletId, actor_id: userId, ledger_balance: ledgerBalance });
            throw new Error(`LEDGER_BALANCE_INVALID:${walletId}`);
        }
        return ledgerBalance;
    }

    /**
     * BUDGET ENFORCEMENT ENGINE
     * Checks if a transaction exceeds a corporate hard budget.
     */
    public async enforceBudgetLimits(userId: string, categoryId: string, amount: number, txId: string, referenceId?: string): Promise<void> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb || !categoryId) return;

        try {
            const { data: category } = await sb.from('categories')
                .select('*')
                .eq('id', categoryId)
                .single();

            if (!category) return;

            const target = await this.resolveBudgetTarget(category);
            if (target <= 0) return;

            const startDate = this.resolveBudgetPeriodStart(category.period);

            const { data: txs } = await sb.from('transactions')
                .select('amount')
                .eq('category_id', categoryId)
                .gte('created_at', startDate.toISOString())
                .neq('status', 'failed')
                .neq('status', 'reversed');

            let totalSpent = 0;
            if (txs) {
                for (const tx of txs) {
                    totalSpent += await DataProtection.decryptAmount(tx.amount);
                }
            }

            const newTotal = totalSpent + amount;
            const isCorporate = category.is_corporate === true;
            const isHardLimit = isCorporate && category.hard_limit === true;
            const budgetCurrency = category.currency || 'TZS';

            if (newTotal > target) {
                if (isHardLimit) {
                    await sb.from('budget_alerts').insert({
                        category_id: categoryId,
                        user_id: userId,
                        organization_id: category.organization_id,
                        transaction_id: txId,
                        amount: amount,
                        alert_type: 'EXCEEDED_BLOCKED'
                    });
                    
                    this.notifyAdmins(category.organization_id, 'Budget Exceeded (Blocked)', `A transaction of ${amount} ${budgetCurrency} for ${category.name} was blocked because it exceeded the hard limit.`);
                    
                    throw new Error(`BUDGET_EXCEEDED: Transaction blocked. Enterprise hard limit of ${target} ${budgetCurrency} for ${category.name} exceeded.`);
                } else {
                    await sb.from('budget_alerts').insert({
                        category_id: categoryId,
                        user_id: userId,
                        organization_id: category.organization_id || null,
                        transaction_id: txId,
                        amount: amount,
                        alert_type: isCorporate ? 'EXCEEDED_WARNING' : 'PERSONAL_BUDGET_EXCEEDED'
                    });

                    if (isCorporate && category.organization_id) {
                        this.notifyAdmins(category.organization_id, 'Budget Exceeded (Warning)', `A transaction of ${amount} ${budgetCurrency} for ${category.name} exceeded the budget target.`);
                    }
                }
            } else if (newTotal >= target * 0.8 && totalSpent < target * 0.8) {
                await sb.from('budget_alerts').insert({
                    category_id: categoryId,
                    user_id: userId,
                    organization_id: category.organization_id || null,
                    transaction_id: txId,
                    amount: amount,
                    alert_type: isCorporate ? 'WARNING_80_PERCENT' : 'PERSONAL_WARNING_80_PERCENT'
                });
                
                if (isCorporate && category.organization_id) {
                    this.notifyAdmins(
                        category.organization_id, 
                        'Budget Warning (80%)', 
                        `Spending for ${category.name} has reached 80% of the budget target.`,
                        'Onyo la Bajeti (80%)',
                        `Matumizi ya ${category.name} yamefikia 80% ya lengo la bajeti.`
                    );
                }
            }
        } catch (e: any) {
            if (e.message.includes('BUDGET_EXCEEDED')) throw e;
            ledgerLogger.error('ledger.budget_enforcement_failed', { actor_id: userId, category_id: categoryId, transaction_id: txId }, e);
        }
    }

    private async notifyAdmins(orgId: string, subjectEn: string, bodyEn: string, subjectSw?: string, bodySw?: string) {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return;
        const { data: admins } = await sb.from('users')
            .select('id, language')
            .eq('organization_id', orgId)
            .in('org_role', ['ADMIN', 'FINANCE']);
            
        if (admins) {
            for (const admin of admins) {
                const language = admin.language || 'en';
                const subject = language === 'sw' && subjectSw ? subjectSw : subjectEn;
                const body = language === 'sw' && bodySw ? bodySw : bodyEn;
                await Messaging.dispatch(admin.id, 'info', subject, body, { sms: true });
            }
        }
    }

    private resolveBudgetPeriodStart(period?: string): Date {
        const now = new Date();
        if (period === 'QUARTERLY') {
            const quarter = Math.floor(now.getMonth() / 3);
            return new Date(now.getFullYear(), quarter * 3, 1);
        }
        if (period === 'ANNUAL') {
            return new Date(now.getFullYear(), 0, 1);
        }
        return new Date(now.getFullYear(), now.getMonth(), 1);
    }

    private async resolveBudgetTarget(category: any): Promise<number> {
        if (category?.target_amount !== undefined && category?.target_amount !== null) {
            const value = typeof category.target_amount === 'string'
                ? await DataProtection.decryptAmount(category.target_amount)
                : Number(category.target_amount);
            if (!isNaN(value) && value > 0) return value;
        }
        if (category?.budget !== undefined && category?.budget !== null) {
            const value = typeof category.budget === 'string'
                ? await DataProtection.decryptAmount(category.budget)
                : Number(category.budget);
            if (!isNaN(value) && value > 0) return value;
        }
        return 0;
    }

    private async emitFinancialEvent(eventType: string, aggregateId: string, payload: any, actor: string = 'system') {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return;

        try {
            await sb.from('financial_events').insert({
                event_type: eventType,
                aggregate_id: aggregateId,
                payload,
                actor
            });
        } catch (e: any) {
            ledgerLogger.error('ledger.financial_event_emit_failed', { event_type: eventType, aggregate_id: aggregateId }, e);
        }
    }

    private async buildBudgetSnapshot(categoryId: string): Promise<any | null> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return null;

        const { data: category } = await sb.from('categories')
            .select('*')
            .eq('id', categoryId)
            .maybeSingle();
        if (!category) return null;

        const target = await this.resolveBudgetTarget(category);
        if (target <= 0) return null;

        const startDate = this.resolveBudgetPeriodStart(category.period);
        const { data: txs } = await sb.from('transactions')
            .select('amount')
            .eq('category_id', categoryId)
            .gte('created_at', startDate.toISOString())
            .neq('status', 'failed')
            .neq('status', 'reversed');

        let spent = 0;
        if (txs) {
            for (const tx of txs) {
                spent += await DataProtection.decryptAmount(tx.amount);
            }
        }

        const remaining = Math.max(target - spent, 0);
        return {
            category_id: categoryId,
            category_name: category.name,
            is_corporate: category.is_corporate === true,
            target_amount: target,
            spent_amount: Math.round(spent * 10000) / 10000,
            remaining_amount: Math.round(remaining * 10000) / 10000,
            utilization_ratio: target > 0 ? Math.round((spent / target) * 10000) / 10000 : 0,
            period_start: startDate.toISOString(),
            period_type: category.period || 'MONTHLY'
        };
    }

    private async emitPurposeLifecycleEvents(txId: string, t: Partial<Transaction>, referenceId: string) {
        const amount = Number(t.amount || 0);
        const metadata = t.metadata || {};
        const categoryId = t.categoryId ? String(t.categoryId) : '';
        const goalId = metadata?.goal_id ? String(metadata.goal_id) : '';
        const movement = metadata?.movement ? String(metadata.movement).toLowerCase() : '';

        if (categoryId) {
            const snapshot = await this.buildBudgetSnapshot(categoryId);
            if (snapshot) {
                await this.emitFinancialEvent('BUDGET_BUCKET_UPDATED', categoryId, {
                    ...snapshot,
                    transaction_id: txId,
                    transaction_type: t.type || 'expense',
                    amount,
                    reference_id: referenceId
                });
            }
        }

        if (goalId && movement === 'allocate_to_goal') {
            await this.emitFinancialEvent('GOAL_FUNDS_LOCKED', goalId, {
                goal_id: goalId,
                transaction_id: txId,
                amount,
                reference_id: referenceId,
                state: 'SAVED_LOCKED',
                source_wallet_id: metadata?.source_wallet_id || t.walletId || null
            });
        }

        if (goalId && movement === 'withdraw_from_goal') {
            await this.emitFinancialEvent('GOAL_FUNDS_RELEASED', goalId, {
                goal_id: goalId,
                transaction_id: txId,
                amount,
                reference_id: referenceId,
                state: 'RELEASED',
                destination_wallet_id: metadata?.destination_wallet_id || t.toWalletId || null,
                security_verification: metadata?.security_verification || null
            });
        }
    }

    /**
     * POST TRANSACTION WITH ATOMIC LEDGER LEGS
     * Enforces double-entry consistency across all mapped vaults using a single DB transaction.
     */
    async postTransactionWithLedger(t: Partial<Transaction>, ledgerEntries: LedgerEntry[]) {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) throw new Error("LEDGER_FAULT: Cloud connectivity required for atomic commits.");
        
        const txId = t.id ? String(t.id) : UUID.generate();
        const referenceId = t.referenceId || `REF-${UUID.generateShortCode(12)}`;

        // 1. Encrypt PII Metadata
        const [encAmt, encDesc] = await Promise.all([
            DataProtection.encryptAmount(Number(t.amount || 0)), 
            DataProtection.encryptDescription(String(t.description || 'Sovereign Transaction'))
        ]);

        // 2. Prepare legs for SQL-authoritative posting.
        const walletIds = Array.from(new Set((ledgerEntries || []).map(l => l.walletId).filter((id): id is string => !!id)));
        const ownerByWalletId = await this.resolveLedgerWalletOwners(walletIds);
        const preparedLegs = [];
        const internalWalletIds = new Set<string>();
        if (walletIds.length > 0) {
            const [wallets, vaults, goals] = await Promise.all([
                sb.from('wallets').select('id').in('id', walletIds),
                sb.from('platform_vaults').select('id').in('id', walletIds),
                sb.from('goals').select('id').in('id', walletIds),
            ]);
            (wallets.data || []).forEach((w: any) => internalWalletIds.add(String(w.id)));
            (vaults.data || []).forEach((w: any) => internalWalletIds.add(String(w.id)));
            (goals.data || []).forEach((w: any) => internalWalletIds.add(String(w.id)));
        }
        if (walletIds.length > 0 && internalWalletIds.size === 0) {
            throw new Error('INTERNAL_WALLET_REQUIRED: Ledger commits must involve ORBI internal wallets.');
        }
        for (const leg of ledgerEntries) {
            const walletId = leg.walletId;
            if (!walletId) continue;
            if (!Number.isFinite(Number(leg.amount)) || Number(leg.amount) <= 0) {
                throw new Error(`LEG_AMOUNT_INVALID: Leg for ${walletId} must have a positive numeric amount.`);
            }

            const eAmt = await DataProtection.encryptAmount(Number(leg.amount || 0));

            preparedLegs.push({
                wallet_id: walletId,
                user_id: leg.userId || ownerByWalletId.get(String(walletId)) || t.user_id || null,
                entry_type: leg.type,
                currency: leg.currency,
                amount: eAmt,
                amount_plain: leg.amount,
                description: leg.description
            });
        }

        const finalLegs = preparedLegs;

        // 3. Atomic Commit via V2 RPC
        const { error: rpcError } = await sb.rpc('post_transaction_v2', {
            p_tx_id: txId,
            p_user_id: t.user_id,
            p_wallet_id: t.walletId || null,
            p_to_wallet_id: t.toWalletId || null,
            p_amount: encAmt,
            p_description: encDesc,
            p_type: t.type || 'expense',
            p_status: t.status || 'completed',
            p_date: t.date || new Date().toISOString().split('T')[0],
            p_metadata: t.metadata || {},
            p_category_id: t.categoryId || null,
            p_legs: finalLegs,
            p_reference_id: referenceId
        });

        if (rpcError) {
            ledgerLogger.error('ledger.atomic_commit_failed', {
                transaction_id: txId,
                reference_id: referenceId,
                actor_id: t.user_id,
                error_message: rpcError.message,
            }, rpcError);
            throw this.normalizeFinancialAuthorityError(rpcError, 'LEDGER_COMMIT_FAULT');
        }

        // 3.5 Log initial 'created' event
        await this.logTransactionEvent(txId, null, 'created', 'system', { initial_status: t.status || 'completed' });

        // 3.7 EVENT SOURCING: Emit to financial_events
        await this.emitFinancialEvent('TRANSACTION_POSTED', txId, {
            amount: t.amount,
            type: t.type,
            wallet_id: t.walletId,
            to_wallet_id: t.toWalletId,
            reference_id: referenceId
        });
        await this.emitPurposeLifecycleEvents(txId, t, referenceId);

        // 4. Trigger AML Risk Monitoring
        try {
            const txForMonitor: Transaction = {
                id: txId,
                user_id: t.user_id || 'system',
                amount: t.amount || 0,
                currency: t.currency || 'TZS',
                description: t.description || 'Sovereign Transaction',
                type: t.type || 'expense',
                status: t.status || 'completed',
                date: t.date || new Date().toISOString().split('T')[0],
                createdAt: t.createdAt || new Date().toISOString(),
                status_history: t.status_history || [],
                walletId: t.walletId || 'UNKNOWN',
                toWalletId: t.toWalletId,
                categoryId: t.categoryId,
                referenceId: t.referenceId,
                metadata: t.metadata
            };
            await RiskComplianceEngine.monitorTransaction(txForMonitor);
        } catch (e) {
            ledgerLogger.error('ledger.aml_monitoring_failed', { transaction_id: txId }, e);
            // Non-blocking error
        }
    }

    /**
     * ADD LEDGER ENTRIES (APPEND-ONLY)
     * Adds new legs to an existing transaction and updates wallet balances.
     */
    async addLedgerEntries(
        txId: string,
        ledgerEntries: LedgerEntry[],
        options?: { appendKey?: string; appendPhase?: string },
    ) {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) throw new Error("LEDGER_FAULT: Cloud connectivity required.");

        // 1. Prepare legs for SQL-authoritative append
        const preparedLegs = [];
        const internalWalletIds = new Set<string>();
        const walletIds = Array.from(new Set((ledgerEntries || []).map(l => l.walletId).filter((id): id is string => !!id)));
        const ownerByWalletId = await this.resolveLedgerWalletOwners(walletIds);
        if (walletIds.length > 0) {
            const [wallets, vaults, goals] = await Promise.all([
                sb.from('wallets').select('id').in('id', walletIds),
                sb.from('platform_vaults').select('id').in('id', walletIds),
                sb.from('goals').select('id').in('id', walletIds),
            ]);
            (wallets.data || []).forEach((w: any) => internalWalletIds.add(String(w.id)));
            (vaults.data || []).forEach((w: any) => internalWalletIds.add(String(w.id)));
            (goals.data || []).forEach((w: any) => internalWalletIds.add(String(w.id)));
        }
        if (walletIds.length > 0 && internalWalletIds.size === 0) {
            throw new Error('INTERNAL_WALLET_REQUIRED: Ledger updates must involve ORBI internal wallets.');
        }
        for (const leg of ledgerEntries) {
            const walletId = leg.walletId;
            if (!walletId) continue;
            if (!Number.isFinite(Number(leg.amount)) || Number(leg.amount) <= 0) {
                throw new Error(`LEG_AMOUNT_INVALID: Leg for ${walletId} must have a positive numeric amount.`);
            }
            const eAmt = await DataProtection.encryptAmount(Number(leg.amount || 0));

            preparedLegs.push({
                transaction_id: txId,
                wallet_id: walletId,
                user_id: leg.userId || ownerByWalletId.get(String(walletId)) || null,
                entry_type: leg.type,
                currency: leg.currency,
                amount: eAmt,
                amount_plain: leg.amount,
                description: leg.description,
                created_at: new Date().toISOString()
            });
        }

        // 2. Atomic Commit via RPC
        const { error: rpcError } = await sb.rpc('append_ledger_entries_v1', {
            p_tx_id: txId,
            p_legs: preparedLegs,
            p_append_key: options?.appendKey || null,
            p_append_phase: options?.appendPhase || null,
        });

        if (rpcError) {
            ledgerLogger.error('ledger.append_legs_failed', { transaction_id: txId, error_message: rpcError.message }, rpcError);
            throw this.normalizeFinancialAuthorityError(rpcError, 'LEDGER_APPEND_FAULT');
        }
    }

    /**
     * VERIFY WALLET BALANCE
     * Compares the cached balance in the wallets table with the sum of ledger entries.
     * Triggers a reconciliation event if a mismatch is detected.
     */
    public async verifyWalletBalance(walletId: string): Promise<{ valid: boolean, drift: number }> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return { valid: false, drift: 0 };

        try {
            // 1. Get cached balance
            const { data: wallet } = await sb.from('wallets').select('balance').eq('id', walletId).single();
            const cachedBalance = Number(wallet?.balance || 0);

            // 2. Calculate from ledger
            const ledgerBalance = await this.calculateBalanceFromLedger(walletId);

            const drift = Math.round((cachedBalance - ledgerBalance) * 10000) / 10000;
            const isValid = Math.abs(drift) < 0.0001;

            if (!isValid) {
                ledgerLogger.warn('ledger.balance_drift_verified', { wallet_id: walletId, cached_balance: cachedBalance, ledger_balance: ledgerBalance, drift });
                
                // Log reconciliation event
                await sb.from('reconciliation_reports').insert({
                    type: 'WALLET_DRIFT',
                    expected_balance: ledgerBalance,
                    actual_balance: cachedBalance,
                    difference: drift,
                    status: 'MISMATCH',
                    metadata: { wallet_id: walletId }
                });
            }

            return { valid: isValid, drift };
        } catch (e: any) {
            ledgerLogger.error('ledger.balance_verification_failed', { wallet_id: walletId }, e);
            return { valid: false, drift: 0 };
        }
    }

    public async updateTransactionStatus(id: string, status: TransactionStatus, notes?: string) {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return;

        // 1. Fetch transaction to check current status and get user_id
        const { data: tx } = await sb.from('transactions').select('*').eq('id', id).single();
        if (!tx) return;

        const oldStatus = tx.status as TransactionStatus;

        // 2. Validate transition
        if (!TransactionStateMachine.isValidTransition(oldStatus, status)) {
            ledgerLogger.warn('ledger.invalid_state_transition', { transaction_id: id, old_status: oldStatus, next_status: status });
            return;
        }

        // 3. Update the status in the database
        await sb.from('transactions').update({ 
            status, 
            status_notes: notes 
        }).eq('id', id);

        // 4. Log the event for audit trail
        await this.logTransactionEvent(id, oldStatus, status, 'system', { notes });
        await Audit.log('FINANCIAL', tx.user_id || 'SYSTEM', 'TRANSACTION_STATUS_CHANGED', {
            transactionId: id,
            oldStatus,
            newStatus: status,
            notes: notes || null,
        }, id);

        // 5. Notify the user via the Nexus Stream (WebSocket)
        SocketRegistry.notifyTransactionUpdate(tx.user_id, { ...tx, status, status_notes: notes });
        
        // If it's a settlement confirmation, also notify about balance update
        if (status === 'completed' || status === 'settled') {
            const balance = await this.calculateBalanceFromLedger(tx.wallet_id);
            SocketRegistry.notifyBalanceUpdate(tx.user_id, tx.wallet_id, balance);

            if (oldStatus !== 'completed' && oldStatus !== 'settled') {
                try {
                    const { BankingEngine } = await import('../backend/ledger/transactionEngine.js');
                    await BankingEngine.sendTransferNotifications(id, { ...tx, status, status_notes: notes });
                } catch (e: any) {
                    ledgerLogger.error('ledger.participant_notification_failed', { transaction_id: id }, e);
                }
            }
        }

        try {
            const { ServiceActorOps } = await import('../backend/features/ServiceActorOps.js');
            await ServiceActorOps.handleTransactionStatusChange(id, status);
        } catch (e: any) {
            ledgerLogger.error('ledger.service_actor_post_status_sync_failed', { transaction_id: id }, e);
        }
    }

    /**
     * LOG TRANSACTION EVENT
     * Records a state transition in the transaction_events table.
     */
    public async logTransactionEvent(transactionId: string, oldState: string | null, newState: string, actor: string = 'system', metadata: any = {}) {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return;

        try {
            await sb.from('transaction_events').insert({
                transaction_id: transactionId,
                old_state: oldState,
                new_state: newState,
                actor,
                metadata
            });
        } catch (e: any) {
            ledgerLogger.error('ledger.transaction_event_log_failed', { transaction_id: transactionId }, e);
        }
    }

    public async getLatestTransactions(userId: string, limit: number = 50, offset: number = 0): Promise<any[]> {
        // Use Admin Client to bypass RLS policies for aggregated views (Incoming + Outgoing)
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) {
            ledgerLogger.error('ledger.transaction_retrieval_db_offline');
            return [];
        }

        return await PerfMonitor.track(`Ledger.getLatestTransactions:${userId}:${limit}:${offset}`, async () => {
            try {
            // Resolve identity-owned containers, ledger references and direct
            // transactions in parallel. financial_ledger.user_id is assigned
            // by the wallet-owner trigger, so it is the authoritative indexed
            // path for incoming as well as outgoing transaction references.
            const transactionSelectFields = 'id, reference_id, user_id, amount, currency, description, type, status, created_at, wallet_id, to_wallet_id, metadata, category_id';
            const [
                { data: wallets },
                { data: vaults },
                { data: ownedLedgerRefs, error: ownedLedgerRefError },
                { data: directTransactions, error: directTransactionError },
            ] = await Promise.all([
                sb.from('wallets').select('id').eq('user_id', userId),
                sb.from('platform_vaults').select('id').eq('user_id', userId),
                sb.from('financial_ledger')
                    .select('transaction_id')
                    .eq('user_id', userId)
                    .order('created_at', { ascending: false })
                    .range(offset, offset + Math.max(limit * 4, limit) - 1),
                sb.from('transactions')
                    .select(transactionSelectFields)
                    .eq('user_id', userId)
                    .order('created_at', { ascending: false })
                    .range(offset, offset + limit - 1),
            ]);
            
            const walletIds = [
                ...(wallets?.map(w => w.id) || []),
                ...(vaults?.map(v => v.id) || [])
            ];
            const ownedWalletIdSet = new Set(walletIds.map(String));

            ledgerLogger.info('ledger.transactions_fetch_started', { actor_id: userId, wallet_count: walletIds.length });

            if (ownedLedgerRefError) {
                ledgerLogger.warn('ledger.owned_ledger_transaction_lookup_failed', {
                    actor_id: userId,
                    error_message: ownedLedgerRefError.message,
                });
            }
            const ledgerTransactionIds = Array.from(new Set(
                (ownedLedgerRefs || [])
                    .map((row: any) => String(row?.transaction_id || '').trim())
                    .filter(Boolean)
            ));

            if (directTransactionError) {
                ledgerLogger.error('ledger.transactions_query_failed', { actor_id: userId, error_message: directTransactionError.message }, directTransactionError);
                throw directTransactionError;
            }
            
            const transactionRowsById = new Map<string, any>();
            (directTransactions || []).forEach((row: any) => {
                if (row?.id) transactionRowsById.set(String(row.id), row);
            });

            if (ledgerTransactionIds.length > 0) {
                const missingLedgerTransactionIds = ledgerTransactionIds.filter((id) => !transactionRowsById.has(id));
                const chunkSize = 100;
                for (let i = 0; i < missingLedgerTransactionIds.length; i += chunkSize) {
                    const chunk = missingLedgerTransactionIds.slice(i, i + chunkSize);
                    const { data: ledgerTransactionRows, error: ledgerTransactionError } = await sb
                        .from('transactions')
                        .select(transactionSelectFields)
                        .in('id', chunk);
                    if (ledgerTransactionError) {
                        ledgerLogger.warn('ledger.owned_ledger_transaction_rows_failed', {
                            actor_id: userId,
                            error_message: ledgerTransactionError.message,
                        });
                        continue;
                    }
                    (ledgerTransactionRows || []).forEach((row: any) => {
                        if (row?.id) transactionRowsById.set(String(row.id), row);
                    });
                }
            }
            const mergedRows = Array.from(transactionRowsById.values())
                .sort((a: any, b: any) => new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime())
                .slice(0, limit);
            if (!mergedRows.length) return [];

            const translated = await this.decryptTransactionRows(mergedRows);

            const { data: movementRows } = await sb
                .from('external_fund_movements')
                .select('id, direction, status, gross_amount, currency, description, created_at, source_wallet_id, target_wallet_id, provider_id, external_reference, metadata')
                .eq('user_id', userId)
                .order('created_at', { ascending: false })
                .range(offset, offset + limit - 1);
            
            const transactionIds = translated
                .map((tx: any) => String(tx.id || '').trim())
                .filter(Boolean);
            const { data: rawLedgerRows, error: ledgerLegError } = transactionIds.length
                ? await sb
                    .from('financial_ledger')
                    .select('id, transaction_id, user_id, wallet_id, entry_side, entry_type, amount, balance_after, balance_after_encrypted, description, created_at')
                    .in('transaction_id', transactionIds)
                : { data: [] as any[], error: null };
            if (ledgerLegError) {
                ledgerLogger.warn('ledger.transaction_legs_enrichment_failed', { actor_id: userId, error_message: ledgerLegError.message });
            }
            const ledgerRows = await this.decryptLedgerLegRows(rawLedgerRows || []);
            const legsByTransaction: Record<string, any[]> = {};
            ledgerRows.forEach((leg: any) => {
                const transactionId = String(leg.transaction_id || '').trim();
                if (!transactionId) return;
                if (!legsByTransaction[transactionId]) legsByTransaction[transactionId] = [];
                legsByTransaction[transactionId].push(leg);
            });

            // 3. ENRICHMENT: Fetch Wallet Names and User Details for both sides
            const allWalletIds = new Set<string>();
            const allUserIds = new Set<string>();

            translated.forEach((tx: any) => {
                if (tx.walletId) allWalletIds.add(tx.walletId);
                if (tx.toWalletId) allWalletIds.add(tx.toWalletId);
                if (tx.user_id) allUserIds.add(tx.user_id);
            });
            ledgerRows.forEach((leg: any) => {
                if (leg.wallet_id) allWalletIds.add(String(leg.wallet_id));
                if (leg.user_id) allUserIds.add(String(leg.user_id));
            });
            (movementRows || []).forEach((mv: any) => {
                if (mv.source_wallet_id) allWalletIds.add(String(mv.source_wallet_id));
                if (mv.target_wallet_id) allWalletIds.add(String(mv.target_wallet_id));
            });
            const sharedPotIds = Array.from(new Set(
                translated
                    .map((tx: any) => String(tx?.metadata?.shared_pot_id || '').trim())
                    .filter(Boolean)
            ));

            const walletIdList = Array.from(allWalletIds);
            const { data: walletNames } = walletIdList.length
                ? await sb.from('wallets').select('id, name, type, management_tier, is_primary, user_id').in('id', walletIdList)
                : { data: [] as any[] };
            const { data: vaultNames } = walletIdList.length
                ? await sb.from('platform_vaults').select('id, name, vault_role, user_id').in('id', walletIdList)
                : { data: [] as any[] };
            const { data: goalNames } = walletIdList.length
                ? await sb.from('goals').select('id, name, user_id').in('id', walletIdList)
                : { data: [] as any[] };
            
            const walletMap: Record<string, any> = {};
            [...(walletNames || []), ...(vaultNames || []), ...(goalNames || [])].forEach(w => {
                walletMap[w.id] = w;
                if (w.user_id) allUserIds.add(w.user_id);
            });

            const userIdList = Array.from(allUserIds);
            const { data: userDetails } = userIdList.length
                ? await sb.from('users').select('id, full_name, customer_id').in('id', userIdList)
                : { data: [] as any[] };
            const userMap: Record<string, any> = {};
            (userDetails || []).forEach(u => userMap[u.id] = u);
            const { data: sharedPots } = sharedPotIds.length
                ? await sb.from('shared_pots').select('id,name').in('id', sharedPotIds)
                : { data: [] as any[] };
            const sharedPotMap: Record<string, any> = {};
            (sharedPots || []).forEach((pot: any) => sharedPotMap[String(pot.id)] = pot);

            const movementItems = (movementRows || []).map((mv: any) => {
                const direction = String(mv.direction || '').toUpperCase();
                const movementStatusRaw = String(mv.status || '').toLowerCase();
                const movementStatus =
                    ['initiated', 'processing', 'completed', 'failed'].includes(movementStatusRaw)
                        ? movementStatusRaw
                        : movementStatusRaw === 'pending'
                          ? 'initiated'
                          : movementStatusRaw;
                const txDirection =
                    direction === 'EXTERNAL_TO_INTERNAL'
                        ? 'CREDIT'
                        : direction === 'INTERNAL_TO_EXTERNAL'
                          ? 'DEBIT'
                          : 'DEBIT';
                const sourceWallet = walletMap[String(mv.source_wallet_id || '')];
                const targetWallet = walletMap[String(mv.target_wallet_id || '')];
                return {
                    id: mv.external_reference || mv.id,
                    internalId: mv.id,
                    referenceId: mv.external_reference || mv.id,
                    user_id: userId,
                    amount: Number(mv.gross_amount || 0),
                    currency: mv.currency,
                    description: mv.description || 'External transfer',
                    type:
                        direction === 'INTERNAL_TO_EXTERNAL'
                            ? 'withdrawal'
                            : direction === 'EXTERNAL_TO_INTERNAL'
                              ? 'deposit'
                              : 'external_transfer',
                    status: movementStatus,
                    created_at: mv.created_at,
                    walletId: mv.source_wallet_id,
                    toWalletId: mv.target_wallet_id,
                    metadata: {
                        ...(mv.metadata || {}),
                        external_movement_id: mv.id,
                        external_reference: mv.external_reference,
                        provider_id: mv.provider_id,
                        settlement_path: 'EXTERNAL_ROUTING',
                    },
                    direction: txDirection,
                    sourceWalletName: sourceWallet?.name || 'External Source',
                    targetWalletName: targetWallet?.name || 'External Destination',
                    counterparty: {
                        label: txDirection === 'DEBIT' ? 'To' : 'From',
                        name: mv.provider_id || 'External',
                    },
                };
            });

            // 4. MAP TO TWO-SIDED VIEW
            const ledgerItems = translated.map((tx: any) => {
                const txLegs = legsByTransaction[String(tx.id || '')] || [];
                const debitLeg = this.pickSourceLeg(txLegs, tx, walletMap, userId);
                const creditLeg = this.pickDestinationLeg(txLegs, tx, walletMap, userId);
                const movementClassification = TransactionMovementClassifier.classify({
                    transaction: tx,
                    legs: txLegs,
                    walletMap,
                    userId,
                });
                const isSender = tx.user_id === userId;
                const sourceWallet = walletMap[String((debitLeg?.wallet_id || tx.walletId || ''))];
                const targetWallet = walletMap[String((creditLeg?.wallet_id || tx.toWalletId || ''))];
                 
                const senderUserId = debitLeg?.user_id || sourceWallet?.user_id || tx.user_id;
                const receiverUserId = creditLeg?.user_id || targetWallet?.user_id || tx.metadata?.recipient_snapshot?.id;
                const senderUser = userMap[senderUserId];
                const receiverUser = userMap[receiverUserId];

                const balanceLeg = this.pickGeneralBalanceLeg(txLegs, userId, ownedWalletIdSet, walletMap, tx);
                const balanceSide = String(balanceLeg?.entry_side || balanceLeg?.entry_type || '').toUpperCase();
                const direction = balanceSide.includes('CREDIT')
                    ? 'CREDIT'
                    : balanceSide.includes('DEBIT')
                      ? 'DEBIT'
                      : isSender ? 'DEBIT' : 'CREDIT';
                const statusRaw = String(tx.status || '').toLowerCase();
                const normalizedStatus =
                    statusRaw === 'processing'
                        ? 'processing'
                        : statusRaw === 'failed' || statusRaw === 'reversed' || statusRaw === 'refunded' || statusRaw === 'cancelled'
                          ? 'failed'
                          : statusRaw === 'created' || statusRaw === 'pending' || statusRaw === 'authorized'
                            ? 'initiated'
                            : 'completed';
                
                const sourceWalletName = this.walletDisplayName(sourceWallet, tx.sourceWalletName || 'Orbi Vault') || 'Orbi Vault';
                const targetWalletName = this.walletDisplayName(targetWallet, tx.targetWalletName || 'External Destination') || 'External Destination';
                let senderName = this.partyDisplayName(senderUser, sourceWallet, sourceWalletName);
                let receiverName = this.firstDisplayText([
                    tx.metadata?.recipient_snapshot?.name,
                    tx.metadata?.recipient_name,
                    tx.recipient_name,
                ]) || this.partyDisplayName(
                    receiverUser,
                    targetWallet,
                    targetWalletName,
                );
                const sharedPot = sharedPotMap[String(tx?.metadata?.shared_pot_id || '')];
                const sharedPotLabel = sharedPot?.name ? `Fungu: ${sharedPot.name}` : undefined;
                if (sharedPotLabel) {
                    if (direction === 'DEBIT') receiverName = sharedPotLabel;
                    if (direction === 'CREDIT') senderName = sharedPotLabel;
                }
                const balanceAfter = balanceLeg?.balance_after ?? tx.balance_after ?? tx.balanceAfter ?? null;

                return {
                    ...tx,
                    id: tx.reference_id || tx.id, // Overwrite ID with reference_id for frontend
                    internalId: tx.id, // Keep original UUID as internalId
                    referenceId: tx.reference_id || tx.id,
                    direction,
                    status: normalizedStatus,
                    movement_family: movementClassification.movement_family,
                    movement_code: movementClassification.movement_code,
                    movement_group: movementClassification.movement_group,
                    movement_classification: movementClassification,
                    metadata: {
                        ...(tx.metadata || {}),
                        movement_family: movementClassification.movement_family,
                        movement_code: movementClassification.movement_code,
                        movement_group: movementClassification.movement_group,
                        movement_classification: movementClassification,
                    },
                    balance_after: balanceAfter,
                    balanceAfter,
                    running_balance: balanceAfter,
                    balance_scope: 'OPERATING_WALLET',
                    ledger: {
                        id: balanceLeg?.id,
                        transaction_id: balanceLeg?.transaction_id || tx.id,
                        user_id: balanceLeg?.user_id || userId,
                        wallet_id: balanceLeg?.wallet_id || null,
                        entry_side: balanceLeg?.entry_side || balanceLeg?.entry_type || null,
                        entry_type: balanceLeg?.entry_type || balanceLeg?.entry_side || null,
                        balance_after: balanceAfter,
                        balance_scope: 'OPERATING_WALLET',
                    },
                    ledger_legs: txLegs.map((leg: any) => ({
                        id: leg.id,
                        transaction_id: leg.transaction_id,
                        user_id: leg.user_id,
                        wallet_id: leg.wallet_id,
                        entry_side: leg.entry_side || leg.entry_type,
                        entry_type: leg.entry_type,
                        amount: leg.amount,
                        balance_after: leg.balance_after,
                    })),
                    source_wallet_id: debitLeg?.wallet_id || tx.walletId || null,
                    destination_wallet_id: creditLeg?.wallet_id || tx.toWalletId || null,
                    source_wallet_name: sourceWalletName,
                    destination_wallet_name: targetWalletName,
                    sourceWalletName,
                    targetWalletName,
                    from_display_name: senderName,
                    to_display_name: receiverName,
                    source_display_name: senderName,
                    destination_display_name: receiverName,
                    sender: {
                        id: senderUserId || tx.user_id,
                        name: senderName,
                        customerId: senderUser?.customer_id || 'N/A'
                    },
                    receiver: {
                        id: receiverUserId || 'N/A',
                        name: receiverName,
                        customerId: receiverUser?.customer_id || 'N/A'
                    },
                    // Generic "Counterparty" for simplified UI display
                    counterparty: isSender ? {
                        label: 'To',
                        name: receiverName,
                        id: receiverUser?.customer_id || 'N/A'
                    } : {
                        label: 'From',
                        name: senderName,
                        id: senderUser?.customer_id || 'N/A'
                    }
                };
            });
            const combined = [...ledgerItems, ...movementItems];
            combined.sort((a: any, b: any) => {
                const aTime = new Date(a.created_at || a.createdAt || 0).getTime();
                const bTime = new Date(b.created_at || b.createdAt || 0).getTime();
                return bTime - aTime;
            });
            return combined;
            } catch (e: any) {
                ledgerLogger.error('ledger.forensic_fetch_failed', undefined, e);
                return [];
            }
        });
    }

    public async getTransactionForUser(userId: string, transactionId: string): Promise<any | null> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) {
            throw new Error('LEDGER_OFFLINE: Transaction status is unavailable.');
        }

        const identifier = String(transactionId || '').trim();
        if (!identifier) return null;

        const [{ data: wallets }, { data: vaults }] = await Promise.all([
            sb.from('wallets').select('id').eq('user_id', userId),
            sb.from('platform_vaults').select('id').eq('user_id', userId),
        ]);
        const ownedWalletIds = new Set<string>([
            ...(wallets || []).map((wallet: any) => String(wallet.id)),
            ...(vaults || []).map((vault: any) => String(vault.id)),
        ]);

        let row: any = null;
        const { data: referenceMatch, error: referenceError } = await sb
            .from('transactions')
            .select('id, reference_id, user_id, amount, currency, description, type, status, created_at, wallet_id, to_wallet_id, metadata, category_id')
            .eq('reference_id', identifier)
            .maybeSingle();
        if (referenceError) throw referenceError;
        row = referenceMatch;

        if (!row && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(identifier)) {
            const { data: idMatch, error: idError } = await sb
                .from('transactions')
                .select('id, reference_id, user_id, amount, currency, description, type, status, created_at, wallet_id, to_wallet_id, metadata, category_id')
                .eq('id', identifier)
                .maybeSingle();
            if (idError) throw idError;
            row = idMatch;
        }

        if (!row) return null;
        const { data: rawLedgerRows, error: ledgerLegError } = await sb
            .from('financial_ledger')
            .select('id, transaction_id, user_id, wallet_id, entry_side, entry_type, amount, balance_after, balance_after_encrypted, description, created_at')
            .eq('transaction_id', row.id);
        if (ledgerLegError) throw ledgerLegError;
        const ledgerRows = await this.decryptLedgerLegRows(rawLedgerRows || []);

        const canView =
            String(row.user_id || '') === userId ||
            ownedWalletIds.has(String(row.wallet_id || '')) ||
            ownedWalletIds.has(String(row.to_wallet_id || '')) ||
            ledgerRows.some((leg: any) =>
                String(leg.user_id || '') === String(userId) ||
                ownedWalletIds.has(String(leg.wallet_id || ''))
            );
        if (!canView) return null;

        const [transaction] = await this.decryptTransactionRows([row]);
        if (!transaction) return null;
        const walletIdList = Array.from(new Set(
            ledgerRows
                .map((leg: any) => String(leg.wallet_id || '').trim())
                .filter(Boolean)
        ));
        const [{ data: walletNames }, { data: vaultNames }, { data: goalNames }] = await Promise.all([
            walletIdList.length
                ? sb.from('wallets').select('id, name, type, management_tier, is_primary, user_id').in('id', walletIdList)
                : Promise.resolve({ data: [] as any[] }),
            walletIdList.length
                ? sb.from('platform_vaults').select('id, name, vault_role, user_id').in('id', walletIdList)
                : Promise.resolve({ data: [] as any[] }),
            walletIdList.length
                ? sb.from('goals').select('id, name, user_id').in('id', walletIdList)
                : Promise.resolve({ data: [] as any[] }),
        ]);
        const walletMap: Record<string, any> = {};
        const userIds = new Set<string>();
        [...(walletNames || []), ...(vaultNames || []), ...(goalNames || [])].forEach((wallet: any) => {
            walletMap[String(wallet.id)] = wallet;
            if (wallet.user_id) userIds.add(String(wallet.user_id));
        });
        const debitLeg = this.pickSourceLeg(ledgerRows, transaction, walletMap, userId);
        const creditLeg = this.pickDestinationLeg(ledgerRows, transaction, walletMap, userId);
        ledgerRows.forEach((leg: any) => {
            if (leg.user_id) userIds.add(String(leg.user_id));
        });
        if (transaction.user_id) userIds.add(String(transaction.user_id));
        const { data: userDetails } = userIds.size
            ? await sb.from('users').select('id, full_name, customer_id').in('id', Array.from(userIds))
            : { data: [] as any[] };
        const userMap: Record<string, any> = {};
        (userDetails || []).forEach((user: any) => userMap[String(user.id)] = user);

        const sourceWallet = walletMap[String(debitLeg?.wallet_id || transaction.walletId || '')];
        const targetWallet = walletMap[String(creditLeg?.wallet_id || transaction.toWalletId || '')];
        const senderUserId = debitLeg?.user_id || sourceWallet?.user_id || transaction.user_id;
        const receiverUserId = creditLeg?.user_id || targetWallet?.user_id || transaction.metadata?.recipient_snapshot?.id;
        const senderUser = userMap[String(senderUserId || '')];
        const receiverUser = userMap[String(receiverUserId || '')];
        const sourceWalletName = this.walletDisplayName(sourceWallet, transaction.sourceWalletName || 'Orbi Vault') || 'Orbi Vault';
        const targetWalletName = this.walletDisplayName(targetWallet, transaction.targetWalletName || 'External Destination') || 'External Destination';
        let senderName = this.partyDisplayName(senderUser, sourceWallet, sourceWalletName);
        let receiverName = this.firstDisplayText([
            transaction.metadata?.recipient_snapshot?.name,
            transaction.metadata?.recipient_name,
            transaction.recipient_name,
        ]) || this.partyDisplayName(
            receiverUser,
            targetWallet,
            targetWalletName,
        );
        const balanceLeg = this.pickGeneralBalanceLeg(ledgerRows, userId, ownedWalletIds, walletMap, transaction);
        const balanceAfter = balanceLeg?.balance_after ?? transaction.balance_after ?? transaction.balanceAfter ?? null;
        const sharedPotId = String(transaction?.metadata?.shared_pot_id || '').trim();
        if (sharedPotId) {
            const { data: sharedPot } = await sb.from('shared_pots').select('name').eq('id', sharedPotId).maybeSingle();
            const sharedPotLabel = sharedPot?.name ? `Fungu: ${sharedPot.name}` : undefined;
            const balanceSide = String(balanceLeg?.entry_side || balanceLeg?.entry_type || '').toUpperCase();
            if (sharedPotLabel && balanceSide.includes('DEBIT')) receiverName = sharedPotLabel;
            if (sharedPotLabel && balanceSide.includes('CREDIT')) senderName = sharedPotLabel;
        }
        const movementClassification = TransactionMovementClassifier.classify({
            transaction,
            legs: ledgerRows,
            walletMap,
            userId,
        });

        return {
            ...transaction,
            id: transaction.reference_id || transaction.id,
            internalId: transaction.id,
            referenceId: transaction.reference_id || transaction.id,
            status: String(transaction.status || '').toLowerCase(),
            movement_family: movementClassification.movement_family,
            movement_code: movementClassification.movement_code,
            movement_group: movementClassification.movement_group,
            movement_classification: movementClassification,
            metadata: {
                ...(transaction.metadata || {}),
                movement_family: movementClassification.movement_family,
                movement_code: movementClassification.movement_code,
                movement_group: movementClassification.movement_group,
                movement_classification: movementClassification,
            },
            balance_after: balanceAfter,
            balanceAfter,
            running_balance: balanceAfter,
            balance_scope: 'OPERATING_WALLET',
            ledger: {
                id: balanceLeg?.id,
                transaction_id: balanceLeg?.transaction_id || transaction.id,
                user_id: balanceLeg?.user_id || userId,
                wallet_id: balanceLeg?.wallet_id || null,
                entry_side: balanceLeg?.entry_side || balanceLeg?.entry_type || null,
                entry_type: balanceLeg?.entry_type || balanceLeg?.entry_side || null,
                balance_after: balanceAfter,
                balance_scope: 'OPERATING_WALLET',
            },
            ledger_legs: ledgerRows.map((leg: any) => ({
                id: leg.id,
                transaction_id: leg.transaction_id,
                user_id: leg.user_id,
                wallet_id: leg.wallet_id,
                entry_side: leg.entry_side || leg.entry_type,
                entry_type: leg.entry_type,
                amount: leg.amount,
                balance_after: leg.balance_after,
            })),
            source_wallet_id: debitLeg?.wallet_id || transaction.walletId || null,
            destination_wallet_id: creditLeg?.wallet_id || transaction.toWalletId || null,
            source_wallet_name: sourceWalletName,
            destination_wallet_name: targetWalletName,
            sourceWalletName,
            targetWalletName,
            from_display_name: senderName,
            to_display_name: receiverName,
            source_display_name: senderName,
            destination_display_name: receiverName,
            sender: {
                id: senderUserId || transaction.user_id,
                name: senderName,
                customerId: senderUser?.customer_id || 'N/A',
            },
            receiver: {
                id: receiverUserId || 'N/A',
                name: receiverName,
                customerId: receiverUser?.customer_id || 'N/A',
            },
        };
    }

    /**
     * FORENSIC / AUDIT FETCH
     * Retrieves all transactions across the platform for staff/auditors.
     */
    public async getAllTransactions(limit: number = 100, offset: number = 0): Promise<any[]> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) {
            ledgerLogger.error('ledger.global_transaction_retrieval_db_offline');
            return [];
        }

        return await PerfMonitor.track(`Ledger.getAllTransactions:${limit}:${offset}`, async () => {
            try {
                const { data, error } = await sb
                    .from('transactions')
                    .select('id, reference_id, user_id, amount, currency, description, type, status, created_at, wallet_id, to_wallet_id, metadata, category_id')
                    .order('created_at', { ascending: false })
                    .range(offset, offset + limit - 1);

                if (error) throw error;
                if (!data) return [];

                const translated = await this.decryptTransactionRows(data);

            // Enrichment for Global View
            const allWalletIds = new Set<string>();
            const allUserIds = new Set<string>();

            translated.forEach((tx: any) => {
                if (tx.walletId) allWalletIds.add(tx.walletId);
                if (tx.toWalletId) allWalletIds.add(tx.toWalletId);
                if (tx.user_id) allUserIds.add(tx.user_id);
            });

                const walletIdList = Array.from(allWalletIds);
                const { data: walletNames } = walletIdList.length
                    ? await sb.from('wallets').select('id, name, user_id').in('id', walletIdList)
                    : { data: [] as any[] };
                const { data: vaultNames } = walletIdList.length
                    ? await sb.from('platform_vaults').select('id, name, user_id').in('id', walletIdList)
                    : { data: [] as any[] };
            
            const walletMap: Record<string, any> = {};
            [...(walletNames || []), ...(vaultNames || [])].forEach(w => {
                walletMap[w.id] = w;
                if (w.user_id) allUserIds.add(w.user_id);
            });

                const userIdList = Array.from(allUserIds);
                const { data: userDetails } = userIdList.length
                    ? await sb.from('users').select('id, full_name, customer_id').in('id', userIdList)
                    : { data: [] as any[] };
            const userMap: Record<string, any> = {};
            (userDetails || []).forEach(u => userMap[u.id] = u);

                return translated.map((tx: any) => {
                const sourceWallet = walletMap[tx.walletId];
                const targetWallet = walletMap[tx.toWalletId];
                const senderUser = userMap[tx.user_id];
                const receiverUserId = targetWallet?.user_id || tx.metadata?.recipient_snapshot?.id;
                const receiverUser = userMap[receiverUserId];

                return {
                    ...tx,
                    id: tx.reference_id || tx.id, // Overwrite ID with reference_id for frontend
                    internalId: tx.id, // Keep original UUID as internalId
                    referenceId: tx.reference_id || tx.id,
                    sourceWalletName: sourceWallet?.name || 'Orbi Vault',
                    targetWalletName: targetWallet?.name || 'External Destination',
                    sender: {
                        id: tx.user_id,
                        name: senderUser?.full_name || 'System',
                        customerId: senderUser?.customer_id || 'N/A'
                    },
                    receiver: {
                        id: receiverUserId || 'N/A',
                        name: receiverUser?.full_name || tx.metadata?.recipient_snapshot?.name || 'External Recipient',
                        customerId: receiverUser?.customer_id || 'N/A'
                    }
                };
                });
            } catch (e: any) {
                ledgerLogger.error('ledger.global_forensic_fetch_failed', undefined, e);
                return [];
            }
        });
    }

    /**
     * LEDGER FORENSICS
     * Retrieves all ledger legs for a specific transaction.
     */
    public async getLedgerEntries(transactionId: string): Promise<any[]> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return [];

        try {
            const { data, error } = await sb
                .from('financial_ledger')
                .select('*')
                .eq('transaction_id', transactionId);

            if (error) throw error;
            
            // Decrypt amounts and balances for forensic view
            return await Promise.all((data || []).map(async (leg: any) => {
                const amount = await DataProtection.decryptAmount(leg.amount);
                const balanceAfter = await DataProtection.decryptAmount(leg.balance_after_encrypted || leg.balance_after);
                
                return {
                    ...leg,
                    amount: Number(amount),
                    balance_after: Number(balanceAfter)
                };
            }));
        } catch (e: any) {
            ledgerLogger.error('ledger.forensic_leg_fetch_failed', { transaction_id: transactionId }, e);
            return [];
        }
    }

    /**
     * GET DAILY NET MOVEMENTS
     * Aggregates net asset movements (CREDIT - DEBIT) per day, optionally grouped by category.
     */
    public async getDailyNetMovements(startDate: string, endDate: string): Promise<any[]> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return [];

        try {
            const { data, error } = await sb
                .from('financial_ledger')
                .select(`
                    amount,
                    entry_type,
                    created_at,
                    transactions (
                        category_id
                    )
                `)
                .gte('created_at', startDate)
                .lte('created_at', endDate);

            if (error) throw error;

            const movements: Record<string, Record<string, number>> = {};

            for (const leg of (data || [])) {
                const amount = await DataProtection.decryptAmount(leg.amount);
                const date = leg.created_at.split('T')[0];
                const categoryId = leg.transactions?.[0]?.category_id || 'uncategorized';

                if (!movements[date]) movements[date] = {};
                if (!movements[date][categoryId]) movements[date][categoryId] = 0;

                if (leg.entry_type === 'CREDIT') {
                    movements[date][categoryId] += amount;
                } else {
                    movements[date][categoryId] -= amount;
                }
            }

            return Object.entries(movements).map(([date, categories]) => ({
                date,
                categories
            }));
        } catch (e: any) {
            ledgerLogger.error('ledger.daily_movements_failed', undefined, e);
            return [];
        }
    }

    /**
     * GET AGGREGATED WALLET BALANCES
     * Aggregates total balances for wallets with specific names (e.g., 'Orbi', 'PaySafe').
     */
    public async getAggregatedWalletBalances(walletNames: string[]): Promise<Record<string, number>> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return {};

        try {
            const { data, error } = await sb
                .from('wallets')
                .select('name, balance')
                .in('name', walletNames);

            if (error) throw error;

            const aggregation: Record<string, number> = {};
            walletNames.forEach(name => aggregation[name] = 0);

            (data || []).forEach(wallet => {
                if (aggregation[wallet.name] !== undefined) {
                    aggregation[wallet.name] += Number(wallet.balance) || 0;
                }
            });

            return aggregation;
        } catch (e: any) {
            ledgerLogger.error('ledger.aggregation_failed', undefined, e);
            return {};
        }
    }

    /**
     * GET FEE TRANSACTIONS
     * Retrieves all ledger entries associated with fee collector wallets.
     */
    public async getWalletHistory(walletId: string, limit: number = 50, offset: number = 0): Promise<any[]> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return [];

        try {
            const { data, error } = await sb
                .from('financial_ledger')
                .select('*, transactions(*)')
                .eq('wallet_id', walletId)
                .order('created_at', { ascending: false })
                .range(offset, offset + limit - 1);

            if (error) throw error;
            if (!data) return [];

            return await Promise.all(data.map(async (leg: any) => {
                const amount = await DataProtection.decryptAmount(leg.amount);
                const balanceAfter = await DataProtection.decryptAmount(leg.balance_after_encrypted || leg.balance_after);
                
                return {
                    ...leg,
                    amount: Number(amount),
                    balance_after: Number(balanceAfter),
                    transaction: leg.transactions
                };
            }));
        } catch (e: any) {
            ledgerLogger.error('ledger.wallet_history_failed', { wallet_id: walletId }, e);
            return [];
        }
    }

    /**
     * RECONCILE ALL WALLETS
     * Runs a full integrity check across all wallets in the system.
     */
    public async reconcileAllWallets(): Promise<{ total: number, valid: number, invalid: number }> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return { total: 0, valid: 0, invalid: 0 };

        const { data: wallets } = await sb.from('wallets').select('id');
        const { data: vaults } = await sb.from('platform_vaults').select('id');

        const allIds = [...(wallets?.map(w => w.id) || []), ...(vaults?.map(v => v.id) || [])];
        
        let valid = 0;
        let invalid = 0;

        for (const id of allIds) {
            const result = await this.verifyWalletBalance(id);
            if (result.valid) valid++;
            else invalid++;
        }

        return { total: allIds.length, valid, invalid };
    }

    /**
     * EMERGENCY REPAIR ONLY
     * Forces the cached balance to match the independently verified ledger sum.
     * Never call this from customer-facing or normal financial flow.
     */
    public async fixWalletBalance(walletId: string, actorId: string, repairReason?: string, incidentReference?: string): Promise<void> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) throw new Error("VAULT_OFFLINE");

        const ledgerBalance = await this.calculateBalanceFromLedger(walletId);
        const encryptedBalance = await DataProtection.encryptAmount(ledgerBalance);

        await sb.rpc('repair_wallet_balance_emergency', {
            target_wallet_id: walletId,
            new_balance: ledgerBalance,
            new_encrypted: encryptedBalance,
            repair_actor_id: actorId,
            repair_reason: repairReason || `Ledger reconciliation repair for wallet ${walletId}`
        });

        await Audit.log('SECURITY', actorId, 'PRIVILEGED_WALLET_BALANCE_REPAIR_EXECUTED', {
            walletId,
            authoritativeBalance: ledgerBalance,
            repairReason: repairReason || `Ledger reconciliation repair for wallet ${walletId}`,
            incidentReference: incidentReference || null,
            tool: 'repair_wallet_balance_emergency',
        });
    }

    public async getSystemBalance(): Promise<{ total: number, breakdown: Record<string, number> }> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return { total: 0, breakdown: {} };

        const { data: vaults } = await sb.from('platform_vaults').select('vault_role, balance');
        
        let total = 0;
        const breakdown: Record<string, number> = {};

        if (vaults) {
            vaults.forEach(v => {
                const bal = Number(v.balance || 0);
                total += bal;
                breakdown[v.vault_role] = (breakdown[v.vault_role] || 0) + bal;
            });
        }

        return { total, breakdown };
    }

    /**
     * GET AUDIT LOG
     * Retrieves security and financial audit trails for a specific entity.
     */
    public async getAuditLog(entityId: string, limit: number = 100): Promise<any[]> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return [];

        const { data } = await sb
            .from('audit_trail')
            .select('*')
            .or(`actor_id.eq.${entityId},metadata->>target_id.eq.${entityId}`)
            .order('timestamp', { ascending: false })
            .limit(limit);

        return data || [];
    }

    public async getFeeTransactions(feeType?: string): Promise<any[]> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return [];

        try {
            // 1. Resolve company settlement accounts. Legacy fee-collector aliases
            // are deliberately excluded so reporting cannot resurrect an old vault.
            const roleByFeeType: Record<string, string> = {
                SERVICE_FEE: 'SERVICE_REVENUE',
                PLATFORM_FEE: 'SERVICE_REVENUE',
                MERCHANT_FEE: 'SERVICE_REVENUE',
                GOV_TAX: 'TAX_RESERVE',
                TAX: 'TAX_RESERVE',
            };
            let query = sb.from('system_settlement_accounts').select('role, vault_id').eq('status', 'ACTIVE');
            if (feeType) {
                const role = roleByFeeType[String(feeType).trim().toUpperCase()];
                if (!role) throw new Error(`FEE_REPORT_ROLE_UNSUPPORTED:${feeType}`);
                query = query.eq('role', role);
            }
            const { data: feeWallets, error: walletError } = await query;
            if (walletError || !feeWallets) return [];
            
            const targetVaultIds = (feeWallets || []).map(w => w.vault_id);

            // 2. Query financial_ledger for these wallet IDs
            const { data, error } = await sb
                .from('financial_ledger')
                .select('*, transactions(*)')
                .in('wallet_id', targetVaultIds)
                .order('created_at', { ascending: false });
            
            if (error) throw error;
            
            // 3. Decrypt and return
            return await Promise.all((data || []).map(async (leg: any) => ({
                ...leg,
                amount: await DataProtection.decryptAmount(leg.amount),
                balance_after: await DataProtection.decryptAmount(leg.balance_after_encrypted || leg.balance_after)
            })));
        } catch (e: any) {
            ledgerLogger.error('ledger.fee_transaction_fetch_failed', undefined, e);
            return [];
        }
    }

    public async reverseTransaction(txId: string, actorId: string): Promise<void> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) throw new Error("VAULT_OFFLINE");

        const { data: tx } = await sb.from('transactions').select('*').eq('id', txId).single();
        const { data: legs } = await sb.from('financial_ledger').select('*').eq('transaction_id', txId);

        if (!tx || !legs) throw new Error("FORENSIC_VOID: Transaction history not found.");

        const reversalTxId = UUID.generate();
        const reversalLegs: LedgerEntry[] = await Promise.all((legs || []).map(async (leg: any) => {
            const amount = await DataProtection.decryptAmount(leg.amount);
            return {
                transactionId: reversalTxId,
                walletId: leg.wallet_id,
                type: leg.entry_type === 'CREDIT' ? 'DEBIT' : 'CREDIT',
                amount,
                currency: leg.currency || tx.currency || 'TZS',
                description: `FORENSIC_REVERSAL: Ref ${txId.substring(0,8)}`,
                timestamp: new Date().toISOString()
            };
        }));

        await this.postTransactionWithLedger({
            id: reversalTxId,
            user_id: tx.user_id,
            amount: await DataProtection.decryptAmount(tx.amount),
            description: `Auto-Reversal of ${txId.substring(0,8)}`,
            type: 'transfer',
            status: 'completed'
        }, reversalLegs);

        await this.updateTransactionStatus(txId, 'reversed', `Authorized by forensic agent: ${actorId}`);
    }

    public async lockTransactionForReview(
        txId: string,
        actorId: string,
        options: {
            actorRole: 'USER' | 'STAFF' | 'SYSTEM';
            reason: string;
            requestReverse?: boolean;
            userLock?: boolean;
            reviewWindowHours?: number;
        }
    ): Promise<any> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) throw new Error('VAULT_OFFLINE');

        const { data: tx } = await sb.from('transactions').select('*').eq('id', txId).single();
        if (!tx) throw new Error('TRANSACTION_NOT_FOUND');
        assertReversalEligible(tx.status);

        if (options.actorRole === 'USER') {
            if (tx.user_id !== actorId) throw new Error('ACCESS_DENIED');
            if (String(tx.type || '').toLowerCase() !== 'transfer') {
                throw new Error('USER_LOCK_TRANSFER_ONLY');
            }
            const ageMs = Date.now() - new Date(tx.created_at || tx.date || Date.now()).getTime();
            if (ageMs > 60 * 60 * 1000) {
                throw new Error('USER_LOCK_WINDOW_EXPIRED');
            }
        }

        const lockAt = new Date().toISOString();
        const reviewWindowHours = Math.max(1, Number(options.reviewWindowHours || 24));
        const autoReverseAt = new Date(Date.now() + reviewWindowHours * 60 * 60 * 1000).toISOString();
        const metadata = {
            ...(tx.metadata || {}),
            transaction_lock: {
                locked: true,
                lock_type: options.userLock ? 'USER_TRANSFER_RECALL' : 'ADMIN_REVIEW_LOCK',
                locked_by: actorId,
                locked_role: options.actorRole,
                previous_status: tx.status,
                locked_at: lockAt,
                reason: options.reason,
                request_reverse: options.requestReverse === true,
                auto_reverse_after_hours: reviewWindowHours,
                auto_reverse_at: autoReverseAt,
                audit_status: 'PENDING',
            },
            manual_review: true,
            issue_reported_at: lockAt,
            issue_reason: options.reason,
        };

        const currentStatus = String(tx.status || '').toLowerCase();
        const nextStatus = currentStatus === 'held_for_review' ? 'held_for_review' : 'held_for_review';
        if (currentStatus !== 'held_for_review') {
            await this.updateTransactionStatus(txId, 'held_for_review', options.reason);
        }

        const { data: updated, error } = await sb
            .from('transactions')
            .update({
                status: nextStatus,
                status_notes: options.reason,
                metadata,
                updated_at: new Date().toISOString(),
            })
            .eq('id', txId)
            .select('*')
            .single();
        if (error) throw error;

        await this.logTransactionEvent(txId, tx.status, 'held_for_review', actorId, {
            reason: options.reason,
            actor_role: options.actorRole,
            request_reverse: options.requestReverse === true,
            user_lock: options.userLock === true,
            auto_reverse_at: autoReverseAt,
        });

        await this.notifyTransactionIssueStakeholders(updated || tx, {
            issueType: options.userLock ? 'USER_TRANSFER_RECALL_REQUESTED' : 'TRANSACTION_LOCKED_FOR_REVIEW',
            reason: options.reason,
            actorId,
            actorRole: options.actorRole,
            autoReverseAt,
        });

        return updated || { ...tx, status: 'held_for_review', metadata };
    }

    public async recordAuditDecision(
        txId: string,
        actorId: string,
        passed: boolean,
        notes: string,
        actorRole: 'STAFF' | 'SYSTEM' = 'STAFF'
    ): Promise<any> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) throw new Error('VAULT_OFFLINE');

        const { data: tx } = await sb.from('transactions').select('*').eq('id', txId).single();
        if (!tx) throw new Error('TRANSACTION_NOT_FOUND');
        if (String(tx.status || '').toLowerCase() !== 'held_for_review') {
            throw new Error('TRANSACTION_NOT_UNDER_REVIEW');
        }

        const metadata = {
            ...(tx.metadata || {}),
            transaction_lock: {
                ...(tx.metadata?.transaction_lock || {}),
                audit_status: passed ? 'PASSED' : 'FAILED',
                audit_passed: passed,
                audited_by: actorId,
                audited_by_role: actorRole,
                audited_at: new Date().toISOString(),
                audit_notes: notes,
            },
        };

        const { data: updated, error } = await sb
            .from('transactions')
            .update({
                metadata,
                status_notes: notes,
                updated_at: new Date().toISOString(),
            })
            .eq('id', txId)
            .select('*')
            .single();
        if (error) throw error;

        await this.logTransactionEvent(txId, tx.status, tx.status, actorId, {
            audit_status: passed ? 'PASSED' : 'FAILED',
            audit_notes: notes,
            actor_role: actorRole,
        });

        await this.notifyTransactionIssueStakeholders(updated || tx, {
            issueType: passed ? 'TRANSACTION_AUDIT_PASSED' : 'TRANSACTION_AUDIT_FAILED',
            reason: notes,
            actorId,
            actorRole,
            autoReverseAt: metadata.transaction_lock?.auto_reverse_at,
        });

        return updated || { ...tx, metadata };
    }

    public async approveReviewedTransaction(txId: string, actorId: string, notes: string): Promise<any> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) throw new Error('VAULT_OFFLINE');

        const { data: tx } = await sb.from('transactions').select('*').eq('id', txId).single();
        if (!tx) throw new Error('TRANSACTION_NOT_FOUND');
        if (String(tx.status || '').toLowerCase() !== 'held_for_review') {
            throw new Error('TRANSACTION_NOT_UNDER_REVIEW');
        }

        const auditStatus = String(tx.metadata?.transaction_lock?.audit_status || '').toUpperCase();
        if (auditStatus !== 'PASSED') {
            throw new Error('AUDIT_PASS_REQUIRED');
        }

        const previousStatus = String(tx.metadata?.transaction_lock?.previous_status || '').toLowerCase();
        const nextStatus: TransactionStatus =
            previousStatus === 'pending' ? 'pending'
            : previousStatus === 'authorized' ? 'authorized'
            : 'completed';

        const metadata = {
            ...(tx.metadata || {}),
            transaction_lock: {
                ...(tx.metadata?.transaction_lock || {}),
                locked: false,
                resolved_by: actorId,
                resolved_at: new Date().toISOString(),
                resolution: 'APPROVED',
                resolution_notes: notes,
            },
            manual_review: false,
        };

        if (previousStatus === 'processing' && String(tx.type || '').toLowerCase() === 'transfer') {
            try {
                const { BankingEngine } = await import('../backend/ledger/transactionEngine.js');
                await BankingEngine.completeSettlement(txId, tx);
            } catch (e: any) {
                throw new Error(`APPROVAL_SETTLEMENT_FAILED: ${e.message}`);
            }
        } else {
            await this.updateTransactionStatus(txId, nextStatus, notes);
        }

        const { data: updated, error } = await sb
            .from('transactions')
            .update({
                metadata,
                updated_at: new Date().toISOString(),
                status_notes: notes,
            })
            .eq('id', txId)
            .select('*')
            .single();
        if (error) throw error;

        await this.logTransactionEvent(txId, 'held_for_review', updated?.status || nextStatus, actorId, {
            approval_notes: notes,
            approved_by: actorId,
        });

        await this.notifyTransactionIssueStakeholders(updated || tx, {
            issueType: 'TRANSACTION_REVIEW_APPROVED',
            reason: notes,
            actorId,
            actorRole: 'STAFF',
        });

        return updated || { ...tx, metadata, status: nextStatus };
    }

    public async approveAllAuditPassedTransactions(actorId: string, notes: string): Promise<{ approved: number; failed: number; approvedIds: string[]; failedItems: any[]; }> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) throw new Error('VAULT_OFFLINE');

        const { data: held } = await sb
            .from('transactions')
            .select('*')
            .eq('status', 'held_for_review');

        const candidates = (held || []).filter((tx: any) =>
            String(tx.metadata?.transaction_lock?.audit_status || '').toUpperCase() === 'PASSED'
        );

        const approvedIds: string[] = [];
        const failedItems: any[] = [];

        for (const tx of candidates) {
            try {
                await this.approveReviewedTransaction(tx.id, actorId, notes);
                approvedIds.push(String(tx.id));
            } catch (e: any) {
                failedItems.push({ id: tx.id, error: e.message });
            }
        }

        await Audit.log('ADMIN', actorId, 'BULK_APPROVE_AUDIT_PASSED_TRANSACTIONS', {
            approved: approvedIds.length,
            failed: failedItems.length,
            approvedIds,
        });

        return {
            approved: approvedIds.length,
            failed: failedItems.length,
            approvedIds,
            failedItems,
        };
    }

    public async reverseTransactionWithReason(
        txId: string,
        actorId: string,
        reason: string,
        actorRole: 'USER' | 'STAFF' | 'SYSTEM' = 'STAFF'
    ): Promise<void> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) throw new Error('VAULT_OFFLINE');

        const { data: tx } = await sb.from('transactions').select('*').eq('id', txId).single();
        if (!tx) throw new Error('TRANSACTION_NOT_FOUND');
        assertReversalEligible(tx.status);

        await this.reverseTransaction(txId, actorId);

        const metadata = {
            ...(tx.metadata || {}),
            reversal_reason: reason,
            reversed_at: new Date().toISOString(),
            reversed_by: actorId,
            reversed_by_role: actorRole,
        };

        await sb.from('transactions').update({
            metadata,
            status_notes: reason,
            updated_at: new Date().toISOString(),
        }).eq('id', txId);

        await this.notifyTransactionIssueStakeholders({ ...tx, metadata, status: 'reversed' }, {
            issueType: 'TRANSACTION_REVERSED',
            reason,
            actorId,
            actorRole,
        });
    }

    public async autoReverseHeldTransactions(): Promise<number> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return 0;

        const nowIso = new Date().toISOString();
        const { data: held } = await sb
            .from('transactions')
            .select('*')
            .eq('status', 'held_for_review');

        let reversedCount = 0;
        for (const tx of held || []) {
            try {
                const autoReverseAt = tx.metadata?.transaction_lock?.auto_reverse_at;
                const lockedAt = tx.metadata?.transaction_lock?.locked_at || tx.updated_at || tx.created_at;
                const dueAt = autoReverseAt || new Date(new Date(lockedAt).getTime() + 24 * 60 * 60 * 1000).toISOString();
                if (new Date(dueAt).getTime() > Date.now()) continue;

                await this.reverseTransactionWithReason(
                    tx.id,
                    'SYSTEM_TIMEOUT',
                    'AUTO_REVERSAL_AFTER_24_HOURS: Transaction remained under review beyond permitted window.',
                    'SYSTEM'
                );
                reversedCount++;
            } catch (e: any) {
                ledgerLogger.error('ledger.held_transaction_auto_reversal_failed', { transaction_id: tx.id }, e);
            }
        }

        if (reversedCount > 0) {
            await Audit.log('SECURITY', 'SYSTEM_TIMEOUT', 'HELD_TRANSACTIONS_AUTO_REVERSED', {
                count: reversedCount,
                processed_at: nowIso,
            });
        }

        return reversedCount;
    }

    private async notifyTransactionIssueStakeholders(tx: any, details: {
        issueType: string;
        reason: string;
        actorId: string;
        actorRole: string;
        autoReverseAt?: string;
    }) {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return;

        const amount = tx.amount ? await DataProtection.decryptAmount(tx.amount, Number(tx.amount || 0)) : 0;
        const reference = tx.reference_id || tx.referenceId || tx.id;
        const subject = `Transaction Issue: ${details.issueType}`;
        const body = [
            `Transaction ${reference} requires attention.`,
            `Reason: ${details.reason}`,
            `Actor: ${details.actorRole}`,
            details.autoReverseAt ? `Auto-reverse at: ${details.autoReverseAt}` : null,
        ].filter(Boolean).join(' ');

        const { data: staff } = await sb
            .from('staff')
            .select('id')
            .in('role', ['ADMIN', 'SUPER_ADMIN', 'CUSTOMER_CARE', 'AUDIT'])
            .eq('account_status', 'active');

        await Promise.all((staff || []).map(async (member: any) => {
            try {
                await Messaging.dispatch(member.id, 'security', subject, body, { push: true, sms: false, email: true });
            } catch (e: any) {
                ledgerLogger.error('ledger.staff_issue_notification_failed', { actor_id: member.id, transaction_id: tx.id }, e);
            }
        }));

        try {
            await Messaging.dispatch(
                tx.user_id,
                'security',
                subject,
                `Reference ${reference}. ${details.reason}${details.autoReverseAt ? ` Funds remain under review until ${details.autoReverseAt}.` : ''}`,
                { push: true, sms: true, email: true }
            );
        } catch (e: any) {
            ledgerLogger.error('ledger.user_issue_notification_failed', { actor_id: tx.user_id, transaction_id: tx.id }, e);
        }

        await Audit.log('SECURITY', details.actorId, details.issueType, {
            txId: tx.id,
            reference,
            reason: details.reason,
            actorRole: details.actorRole,
            amount,
            autoReverseAt: details.autoReverseAt || null,
        });
    }

    public async reserveEscrow(userId: string, walletId: string, amount: number, description: string, referenceId: string): Promise<void> {
        const escrowNode = await RegulatoryService.resolveSystemNode('ESCROW_VAULT');
        const transactionId = UUID.generate();
        const legs: LedgerEntry[] = [
            { transactionId, walletId, type: 'DEBIT', amount, currency: 'TZS', description: `Escrow Hold: ${description}`, timestamp: new Date().toISOString() },
            { transactionId, walletId: escrowNode, type: 'CREDIT', amount, currency: 'TZS', description: `Inbound Escrow: ${description}`, timestamp: new Date().toISOString() }
        ];

        await this.postTransactionWithLedger({
            id: transactionId,
            referenceId,
            user_id: userId,
            amount: amount,
            currency: 'TZS',
            description: `Compliance Escrow: ${description}`,
            type: 'escrow',
            status: 'processing',
            walletId
        }, legs);
    }
}
