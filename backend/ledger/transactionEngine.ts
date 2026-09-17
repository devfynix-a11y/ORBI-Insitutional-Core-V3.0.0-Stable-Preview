
import { User, Transaction, LedgerEntry, Wallet, TransactionStatus } from '../../types.js';
import { UUID } from '../../services/utils.js';
import { getSupabase, getAdminSupabase } from '../supabaseClient.js';
import { Audit } from '../security/audit.js';
import { DataProtection } from '../security/DataProtection.js';
import { logger } from '../infrastructure/logger.js';

import { RegulatoryService } from './regulatoryService.js';
import { systemSettlementAccounts } from './SystemSettlementAccountService.js';
import { TransactionService } from '../../ledger/transactionService.js';
import {
    assertSettlementEligible,
    buildInternalTransferSettlementAppendKey,
    createBalancePreview,
    FINANCIAL_INVARIANTS,
    normalizeFinancialAuthorityError,
} from './financialInvariants.js';
import { TransactionStateMachine } from './stateMachine.js';
import { ReconciliationEngine } from './reconciliationEngine.js';
import { MonitoringService } from '../infrastructure/MonitoringService.js';

import { Messaging } from '../features/MessagingService.js';
import { SocketRegistry } from '../infrastructure/SocketRegistry.js';
import { GlobalTimeResolver } from '../utils/GlobalTimeResolver.js';

/**
 * ORBI ATOMIC BANKING ENGINE (V12.0 Titanium)
 * -------------------------------------------
 * Orchestrates multi-leg transactions with ACID-like consistency
 * in a distributed cloud environment.
 */
const bankingLogger = logger.child({ component: 'banking_engine' });

function isValidTimeZone(timeZone: string): boolean {
    try {
        new Intl.DateTimeFormat('en-US', { timeZone }).format(new Date());
        return true;
    } catch {
        return false;
    }
}

function resolveProfileTimeZone(profile: any, authUser?: any): string {
    const metadata = profile?.metadata && typeof profile.metadata === 'object' ? profile.metadata : {};
    const authMetadata = authUser?.user_metadata && typeof authUser.user_metadata === 'object' ? authUser.user_metadata : {};
    const explicit = [
        metadata.timezone,
        metadata.timeZone,
        metadata.preferred_timezone,
        metadata.preferredTimeZone,
        authMetadata.timezone,
        authMetadata.timeZone,
        authMetadata.preferred_timezone,
        authMetadata.preferredTimeZone,
    ]
        .map((value) => String(value || '').trim())
        .find(Boolean);

    if (explicit && isValidTimeZone(explicit)) return explicit;

    // Financial audit rule: do not infer timezone from country, phone, or IP.
    // If the client/profile did not explicitly provide timezone, display UTC.
    return 'UTC';
}

function timeZoneLabel(date: Date, timeZone: string): string {
    if (timeZone === 'UTC') return 'UTC';
    if (['Africa/Dar_es_Salaam', 'Africa/Nairobi', 'Africa/Kampala'].includes(timeZone)) return 'EAT';
    if (timeZone === 'Africa/Johannesburg') return 'SAST';
    try {
        const parts = new Intl.DateTimeFormat('en-US', { timeZone, timeZoneName: 'short' }).formatToParts(date);
        return parts.find((part) => part.type === 'timeZoneName')?.value || timeZone;
    } catch {
        return timeZone;
    }
}

function formatOffsetLabel(offsetMinutes: number): string {
    if (!Number.isFinite(offsetMinutes) || offsetMinutes === 0) return 'UTC';
    const sign = offsetMinutes < 0 ? '-' : '+';
    const absolute = Math.abs(Math.trunc(offsetMinutes));
    const hours = String(Math.floor(absolute / 60)).padStart(2, '0');
    const minutes = String(absolute % 60).padStart(2, '0');
    return `UTC${sign}${hours}:${minutes}`;
}

function formatClockWithOffset(date: Date, offsetMinutes: number): string {
    const shifted = new Date(date.getTime() + offsetMinutes * 60_000);
    const hours = String(shifted.getUTCHours()).padStart(2, '0');
    const minutes = String(shifted.getUTCMinutes()).padStart(2, '0');
    return `${hours}:${minutes}`;
}

function explicitOffsetMinutes(metadata: any): number | null {
    const ctx = metadata?.clientTimeContext || metadata?.client_time_context || {};
    const raw = ctx.timezone_offset_minutes ?? ctx.timeZoneOffsetMinutes ?? metadata?.timezone_offset_minutes;
    const parsed = typeof raw === 'number' ? raw : Number(raw);
    return Number.isFinite(parsed) ? parsed : null;
}

function explicitTimeZone(metadata: any): string | null {
    const ctx = metadata?.clientTimeContext || metadata?.client_time_context || {};
    const value = String(ctx.timezone || ctx.timeZone || metadata?.timezone || metadata?.timeZone || '').trim();
    return value && isValidTimeZone(value) ? value : null;
}

function formatMessageTime(occurredAtUtc: string, profile: any, authUser: any, language: string, metadata: any = {}): { display: string; timezone: string; canonicalUtc: string } {
    const resolved = GlobalTimeResolver.resolve({
        occurredAtUtc,
        profile,
        authUser,
        language,
        metadata,
    });
    return {
        display: resolved.displayTimestamp,
        timezone: resolved.timeZone,
        canonicalUtc: resolved.canonicalUtc,
    };
}

export class BankingEngineService {
    
    public async process(user: User, intent: any): Promise<{ success: boolean, transaction?: Transaction, error?: string }> {
        if (intent.isSimulation) {
            throw new Error('LEDGER_SIMULATION_NOT_SUPPORTED');
        }

        const { amount, currency, description, type, sourceWalletId, targetWalletId, categoryId, statusOverride } = intent;
        const txService = new TransactionService();
        
        bankingLogger.info('banking.process_started', { actor_id: user.id, transaction_type: type, source_wallet_id: sourceWalletId, target_wallet_id: targetWalletId, reference_id: intent.referenceId || intent.reference_id });

        try {
            const txId = UUID.generate();
            const referenceId = intent.referenceId || `REF-${UUID.generateShortCode(12)}`;
            intent.referenceId = referenceId;
            const timestamp = new Date().toISOString();

            // 1. STATE: CREATED
            let currentStatus: TransactionStatus = 'created';

            // 2. Calculate Regulatory Fees
            const fees = type === 'FX_CONVERSION'
                ? { vat: 0, fee: 0, gov_fee: 0, total: 0, rate: 0 }
                : await RegulatoryService.calculateFees(
                    amount,
                    type,
                    currency || intent.currency,
                    { metadata: intent.metadata, category: intent.category },
                );

            // 3. Resolve Ledger Legs (Only if not held for review)
            const shouldSkipLegs = statusOverride === 'held_for_review';
            
            // STATE: PENDING (Resolving legs and checking balance)
            TransactionStateMachine.transition(txId, currentStatus, 'pending', { fees });
            currentStatus = 'pending';
            const { legs, balanceHint } = shouldSkipLegs ? { legs: [], balanceHint: 0 } : await this.deriveLegs(user.id, intent, txId, fees);

            // STATE: AUTHORIZED (legs resolved; SQL remains final balance authority)
            TransactionStateMachine.transition(txId, currentStatus, 'authorized', { balance_hint: balanceHint });
            currentStatus = 'authorized';

            // Re-extract potentially auto-resolved fields from intent
            const resolvedSourceWalletId = intent.sourceWalletId || sourceWalletId;
            const resolvedTargetWalletId = intent.targetWalletId || targetWalletId;

            // Determine final initial status
            let initialStatus: TransactionStatus = statusOverride || 'completed';
            
            // Only use 'processing' if it's a transfer that will be settled via PaySafe escrow
            const isTransfer = type === 'INTERNAL_TRANSFER' || type === 'PEER_TRANSFER';
            const usedEscrow = legs.some(l => l.description?.includes('PaySafe Secure Lock'));
            
            if (!statusOverride && isTransfer && usedEscrow) {
                initialStatus = 'processing';
            }

            // --- ENTERPRISE BUDGET ENFORCEMENT ---
            if (categoryId) {
                await txService.enforceBudgetLimits(user.id, categoryId, amount, txId, referenceId);
            }

            // 4. STATE: PROCESSING (Committing to DB)
            TransactionStateMachine.transition(txId, currentStatus, 'processing', { initialStatus });
            currentStatus = 'processing';

            // Atomic Commit via Supabase RPC or Local Simulation
            const sb = getAdminSupabase() || getSupabase();
            if (sb) {
                // In production, this would be a single database transaction/RPC
                await this.commitToCloud(user.id, txId, intent, legs, initialStatus);
                
                // --- OPTIMIZATION: Background non-critical post-transaction tasks ---
                
                // Attempt internal settlement before responding. The append key and
                // lifecycle claim make this safe if a recovery worker races us.
                if (initialStatus === 'processing' && statusOverride !== 'held_for_review') {
                    try {
                        await this.completeSettlement(txId, undefined, `engine:auto:${txId}`);
                    } catch (err) {
                        bankingLogger.error(
                            'banking.inline_settlement_failed',
                            { transaction_id: txId, actor_id: user.id },
                            err,
                        );
                    }

                    const { data: settlementState, error: settlementStateError } = await sb
                        .from('transactions')
                        .select('status')
                        .eq('id', txId)
                        .maybeSingle();
                    if (settlementStateError) {
                        bankingLogger.error(
                            'banking.settlement_status_reload_failed',
                            { transaction_id: txId, actor_id: user.id },
                            settlementStateError,
                        );
                    } else if (settlementState?.status) {
                        initialStatus = settlementState.status as TransactionStatus;
                    }
                } else if (initialStatus === 'completed') {
                    // Direct settlement - send participant notifications in background
                    this.sendTransferNotifications(txId).catch(err => 
                        bankingLogger.error('banking.background_notification_failed', { transaction_id: txId, actor_id: user.id }, err)
                    );
                }
                
                // 3. POST-TRANSACTION MULTI-LEDGER AUDIT (Background)
                this.verifyLedgerIntegrity(txId).then(integrity => {
                    if (!integrity.valid) {
                        Audit.log('SECURITY', user.id, 'LEDGER_INTEGRITY_VIOLATION', { txId, failures: integrity.failures });
                        bankingLogger.error('banking.integrity_violation_detected', { transaction_id: txId, actor_id: user.id, failures: integrity.failures });
                    }
                }).catch(err => bankingLogger.error('banking.integrity_check_failed', { transaction_id: txId, actor_id: user.id }, err));
            } else {
                await this.commitToLocal(user.id, txId, intent, legs);
            }

            // Background Audit Log
            Audit.log('FINANCIAL', user.id, 'TRANSACTION_COMMITTED', { txId, type, amount }).catch(() => {});

            const transaction = {
                id: txId,
                user_id: user.id,
                amount,
                description,
                type: (type === 'INTERNAL_TRANSFER' || type === 'PEER_TRANSFER') ? 'transfer' : 
                      (type === 'DEPOSIT') ? 'deposit' : 
                      (type === 'WITHDRAWAL') ? 'withdrawal' : 'expense',
                currency: currency || intent.currency,
                status: initialStatus,
                status_history: [
                    { status: 'created' as TransactionStatus, timestamp },
                    { status: 'pending' as TransactionStatus, timestamp },
                    { status: 'authorized' as TransactionStatus, timestamp },
                    { status: initialStatus, timestamp }
                ],
                date: timestamp,
                createdAt: timestamp,
                walletId: resolvedSourceWalletId,
                toWalletId: resolvedTargetWalletId,
                referenceId: intent.referenceId,
                categoryId: categoryId,
                metadata: intent.metadata,
                tax_info: { 
                    vat: fees.vat, 
                    fee: fees.fee, 
                    gov_fee: fees.gov_fee,
                    rate: fees.rate 
                }
            };

            // REAL-TIME: Notify user about the new transaction and balance update
            SocketRegistry.notifyTransactionUpdate(user.id, transaction);
            if (intent.sourceWalletId) {
                SocketRegistry.send(user.id, { type: 'REFRESH_WALLETS', payload: { walletId: intent.sourceWalletId } });
            }

            // Verify transaction integrity against intent
            this.verifyTransaction(intent, transaction);

            return {
                success: true,
                transaction
            };

        } catch (e: any) {
            const mappedError = normalizeFinancialAuthorityError(e, 'BANKING_ENGINE_PROCESS');
            bankingLogger.error('banking.process_failed', { actor_id: user.id, transaction_type: type, source_wallet_id: sourceWalletId, target_wallet_id: targetWalletId, error_message: mappedError.message }, mappedError);
            return { success: false, error: mappedError.message };
        }
    }

    private async deriveLegs(userId: string, intent: any, txId: string, fees: any): Promise<{ legs: LedgerEntry[], balanceHint: number }> {
        let { amount, sourceWalletId, targetWalletId, type, recipientId, recipient_customer_id } = intent;
        const legs: LedgerEntry[] = [];

        const sb = getAdminSupabase() || getSupabase();

        // Resolve recipientId from customer_id if provided
        if (!recipientId && recipient_customer_id && (type === 'INTERNAL_TRANSFER' || type === 'PEER_TRANSFER')) {
            const adminSb = getAdminSupabase();
            if (adminSb) {
                let recipientData: any = null;
                
                const { data: userData } = await adminSb.from('users')
                    .select('id')
                    .ilike('customer_id', recipient_customer_id.trim())
                    .maybeSingle();
                
                recipientData = userData;

                if (!recipientData) {
                    // Try staff table
                    const { data: staffData } = await adminSb.from('staff')
                        .select('id')
                        .ilike('customer_id', recipient_customer_id.trim())
                        .maybeSingle();
                    recipientData = staffData;
                }

                if (recipientData) {
                    recipientId = recipientData.id;
                    intent.recipientId = recipientId;
                } else {
                    throw new Error(`RECIPIENT_NOT_FOUND: Customer ID ${recipient_customer_id} does not exist.`);
                }
            }
        }

        // Resolve sender's operating vault if sourceWalletId is missing
        if (!sourceWalletId) {
            if (type === 'DEPOSIT') {
                // Use System Faucet Wallet
                sourceWalletId = '00000000-0000-0000-0000-000000000000';
                intent.sourceWalletId = sourceWalletId;
            } else if (sb) {
                const { data } = await sb.from('platform_vaults')
                    .select('id')
                    .eq('user_id', userId)
                    .eq('vault_role', 'OPERATING')
                    .maybeSingle();
                if (data) {
                    sourceWalletId = data.id;
                    intent.sourceWalletId = sourceWalletId;
                }
            }
        }

        // Resolve recipient's operating vault if targetWalletId is missing but recipientId is present
        if (!targetWalletId && recipientId && (type === 'INTERNAL_TRANSFER' || type === 'PEER_TRANSFER')) {
            if (sb) {
                const { data } = await sb.from('platform_vaults')
                    .select('id')
                    .eq('user_id', recipientId)
                    .eq('vault_role', 'OPERATING')
                    .maybeSingle();
                if (data) {
                    targetWalletId = data.id;
                    intent.targetWalletId = targetWalletId;
                }
            }
        }

        // --- BALANCE PREVIEW ---
        // App-side balance checks are UX hints only; SQL/ledger remain the final authority.
        const totalDebit = amount + fees.total;
        const txService = new TransactionService();
        
        let balanceHint = 0;
        let walletName = intent.metadata?.sub_wallet_type || 'Operating Wallet';

        const sourceCurrency = intent.metadata?.source_currency || intent.currency;
        const targetCurrency = intent.metadata?.target_currency || intent.currency;
        const isCrossCurrency = intent.metadata?.cross_currency === true;
        const fxDetails = intent.metadata?.fx_details;

        // Skip preview balance lookup for DEPOSIT type (Faucet/External Source)
        if (type !== 'DEPOSIT') {
            balanceHint = await txService.getLatestBalance(userId, sourceWalletId);
            
            // Try to get wallet name for better error message
            const sb = getAdminSupabase() || getSupabase();
            if (sb) {
                const { data: w } = await sb.from('wallets').select('name').eq('id', sourceWalletId).maybeSingle();
                if (w) walletName = w.name;
                else {
                    const { data: v } = await sb.from('platform_vaults').select('name').eq('id', sourceWalletId).maybeSingle();
                    if (v) walletName = v.name;
                }
            }

            intent.metadata = {
                ...(intent.metadata || {}),
                balance_preview: createBalancePreview({
                    available: balanceHint,
                    required: totalDebit,
                    walletName,
                    walletId: sourceWalletId,
                }),
            };

            if (balanceHint < totalDebit) {
                bankingLogger.warn('banking.balance_preview_insufficient', { actor_id: userId, wallet_id: sourceWalletId, required_amount: totalDebit, available_preview_balance: balanceHint, sql_authority: true });
            }
        } else {
            balanceHint = Number.MAX_SAFE_INTEGER;
        }

        // --- SUB-WALLET SHIFT (Goal/Budget -> Operating) ---
        if (intent.metadata?.is_sub_wallet_transfer && intent.metadata?.intermediate_operating_wallet) {
            const operatingWalletId = intent.metadata.intermediate_operating_wallet;
            const subWalletId = sourceWalletId;
            
            // 1. Shift from Sub-wallet to Operating
            legs.push({
                transactionId: txId,
                walletId: subWalletId,
                type: 'DEBIT',
                amount: totalDebit,
                currency: 'USD',
                description: `Shift from ${intent.metadata.sub_wallet_type}: ${intent.description}`,
                timestamp: new Date().toISOString()
            });

            legs.push({
                transactionId: txId,
                walletId: operatingWalletId,
                type: 'CREDIT',
                amount: totalDebit,
                currency: 'USD',
                description: `Shift Inbound from ${intent.metadata.sub_wallet_type}: ${txId}`,
                timestamp: new Date().toISOString()
            });

            // Update sourceWalletId to Operating for the subsequent legs (PaySafe or Direct)
            sourceWalletId = operatingWalletId;
        }

        if ((type === 'INTERNAL_TRANSFER' || type === 'PEER_TRANSFER') && targetWalletId) {
            // Fetch the user's PaySafe Vault (Sender's Escrow)
            let internalVaultId = intent.metadata?.source_internal_vault_id;
            
            if (!internalVaultId && sb) {
                const { data } = await sb.from('platform_vaults')
                    .select('id')
                    .eq('user_id', userId)
                    .eq('vault_role', 'INTERNAL_TRANSFER')
                    .maybeSingle();
                if (data) internalVaultId = data.id;
            }

            if (internalVaultId) {
                // 1. Debit Source Operating (Total Amount: Base + Fees)
                legs.push({
                    transactionId: txId,
                    walletId: sourceWalletId,
                    type: 'DEBIT',
                    amount: totalDebit,
                    currency: sourceCurrency,
                    description: `PaySafe Transfer Lock: ${intent.description}`,
                    timestamp: new Date().toISOString()
                });

                // 2. Handle Cross-Currency Clearing if needed
                if (isCrossCurrency && fxDetails) {
                    const sourceFxClearingId = await systemSettlementAccounts.resolve('FX_CLEARING', sourceCurrency);
                    const targetFxClearingId = await systemSettlementAccounts.resolve('FX_CLEARING', targetCurrency);
                    
                    // Credit FX Clearing in Source Currency
                    legs.push({
                        transactionId: txId,
                        walletId: sourceFxClearingId,
                        type: 'CREDIT',
                        amount: amount,
                        currency: sourceCurrency,
                        description: `FX Clearing (Source): ${sourceCurrency} -> ${targetCurrency}`,
                        timestamp: new Date().toISOString()
                    });

                    // Debit FX Clearing in Target Currency
                    legs.push({
                        transactionId: txId,
                        walletId: targetFxClearingId,
                        type: 'DEBIT',
                        amount: Number((Number(fxDetails.finalAmount) + Number(fxDetails.spreadAmount || 0) + Number(fxDetails.feeInTargetCurrency || fxDetails.fee || 0)).toFixed(4)),
                        currency: targetCurrency,
                        description: `FX Clearing (Target): ${sourceCurrency} -> ${targetCurrency}`,
                        timestamp: new Date().toISOString()
                    });

                    // 3. Credit PaySafe (Converted Amount: Escrow Lock)
                    legs.push({
                        transactionId: txId,
                        walletId: internalVaultId,
                        type: 'CREDIT',
                        amount: fxDetails.finalAmount,
                        currency: targetCurrency,
                        description: `PaySafe Secure Lock (Converted): ${intent.description}`,
                        timestamp: new Date().toISOString()
                    });

                    await this.addFxSpreadLegs(legs, txId, fxDetails, targetCurrency);

                    // 4. Credit company service revenue (FX fee in target currency)
                    const fxFeeTargetAmount = fxDetails.feeInTargetCurrency || fxDetails.fee || 0;
                    if (this.isPositiveAmount(fxFeeTargetAmount)) {
                        const feeCollectorId = await systemSettlementAccounts.resolve('SERVICE_REVENUE', targetCurrency);
                        legs.push({
                            transactionId: txId,
                            walletId: feeCollectorId,
                            type: 'CREDIT',
                            amount: fxFeeTargetAmount,
                            currency: targetCurrency,
                            description: `FX Fee Collection: ${txId}`,
                            timestamp: new Date().toISOString()
                        });
                    }
                } else {
                    // Standard single-currency PaySafe lock
                    legs.push({
                        transactionId: txId,
                        walletId: internalVaultId,
                        type: 'CREDIT',
                        amount: amount,
                        currency: sourceCurrency,
                        description: `PaySafe Secure Lock: ${intent.description}`,
                        timestamp: new Date().toISOString()
                    });
                }

                await this.addRegulatoryFeeLegs(legs, txId, fees, sourceCurrency);

                return { legs, balanceHint };
            } else {
                // If no internal vault, we MUST fail if it's an internal transfer 
                // to prevent direct settlement which the user said is unsafe.
                throw new Error("INFRASTRUCTURE_ERROR: PaySafe (INTERNAL_TRANSFER) vault not found. Secure escrow is required for this operation.");
            }
        }

        // Standard direct legs for external or if internal vault not found
        legs.push({
            transactionId: txId,
            walletId: sourceWalletId,
            type: 'DEBIT',
            amount: totalDebit,
            currency: sourceCurrency,
            description: `Settlement: ${intent.description}`,
            timestamp: new Date().toISOString()
        });

        if (targetWalletId) {
            if (isCrossCurrency && fxDetails) {
                const sourceFxClearingId = await systemSettlementAccounts.resolve('FX_CLEARING', sourceCurrency);
                const targetFxClearingId = await systemSettlementAccounts.resolve('FX_CLEARING', targetCurrency);
                
                // Credit FX Clearing in Source Currency
                legs.push({
                    transactionId: txId,
                    walletId: sourceFxClearingId,
                    type: 'CREDIT',
                    amount: amount,
                    currency: sourceCurrency,
                    description: `FX Clearing (Source): ${sourceCurrency} -> ${targetCurrency}`,
                    timestamp: new Date().toISOString()
                });

                // Debit FX Clearing in Target Currency
                legs.push({
                    transactionId: txId,
                    walletId: targetFxClearingId,
                    type: 'DEBIT',
                    amount: Number((Number(fxDetails.finalAmount) + Number(fxDetails.spreadAmount || 0) + Number(fxDetails.feeInTargetCurrency || fxDetails.fee || 0)).toFixed(4)),
                    currency: targetCurrency,
                    description: `FX Clearing (Target): ${sourceCurrency} -> ${targetCurrency}`,
                    timestamp: new Date().toISOString()
                });

                // Credit Target Wallet (Converted Amount)
                legs.push({
                    transactionId: txId,
                    walletId: targetWalletId,
                    type: 'CREDIT',
                    amount: fxDetails.finalAmount,
                    currency: targetCurrency,
                    description: `Inbound (Converted): ${intent.description}`,
                    timestamp: new Date().toISOString()
                });

                await this.addFxSpreadLegs(legs, txId, fxDetails, targetCurrency);

                // Credit company service revenue (FX fee in target currency)
                const fxFeeTargetAmount = fxDetails.feeInTargetCurrency || fxDetails.fee || 0;
                if (this.isPositiveAmount(fxFeeTargetAmount)) {
                        const feeCollectorId = await systemSettlementAccounts.resolve('SERVICE_REVENUE', targetCurrency);
                    legs.push({
                        transactionId: txId,
                        walletId: feeCollectorId,
                        type: 'CREDIT',
                        amount: fxFeeTargetAmount,
                        currency: targetCurrency,
                        description: `FX Fee Collection: ${txId}`,
                        timestamp: new Date().toISOString()
                    });
                }
            } else {
                legs.push({
                    transactionId: txId,
                    walletId: targetWalletId,
                    type: 'CREDIT',
                    amount: amount,
                    currency: sourceCurrency,
                    description: `Inbound: ${intent.description}`,
                    timestamp: new Date().toISOString()
                });
            }
        }

        await this.addRegulatoryFeeLegs(legs, txId, fees, sourceCurrency);

        return { legs, balanceHint };
    }

    private async addRegulatoryFeeLegs(legs: LedgerEntry[], txId: string, fees: any, currency: string) {
        const serviceAmount = Number(fees.fee || 0);
        const taxComponents = Number(fees.vat || 0) + Number(fees.gov_fee || 0) + Number(fees.stamp_duty || 0);
        const taxAmount = Number((Number(fees.total || 0) - serviceAmount).toFixed(4));
        if (taxAmount < 0 || Math.abs(taxAmount - taxComponents) > 0.00021) {
            throw new Error('FEE_COMPONENTS_NOT_BALANCED');
        }
        if (this.isPositiveAmount(serviceAmount)) {
            const walletId = await systemSettlementAccounts.resolve('SERVICE_REVENUE', currency);
            legs.push({ transactionId: txId, walletId, type: 'CREDIT', amount: serviceAmount,
                currency, description: `ORBI service revenue: ${txId}`, timestamp: new Date().toISOString() });
        }
        if (this.isPositiveAmount(taxAmount)) {
            const walletId = await systemSettlementAccounts.resolve('TAX_RESERVE', currency);
            legs.push({ transactionId: txId, walletId, type: 'CREDIT', amount: taxAmount,
                currency, description: `Statutory tax reserve: ${txId}`, timestamp: new Date().toISOString() });
        }
    }

    private async addFxSpreadLegs(legs: LedgerEntry[], txId: string, fxDetails: any, currency: string) {
        const spread = Number(fxDetails.spreadAmount || 0);
        if (!Number.isFinite(spread) || spread < 0) throw new Error('FX_SPREAD_INVALID');
        if (!this.isPositiveAmount(spread)) return;
        const riskAmount = Math.min(spread, Math.max(0, Number(fxDetails.quotedRiskBufferAmount || 0)));
        const marginAmount = Number((spread - riskAmount).toFixed(4));
        if (this.isPositiveAmount(marginAmount)) {
            const walletId = await systemSettlementAccounts.resolve('FX_SPREAD_REVENUE', currency);
            legs.push({ transactionId: txId, walletId, type: 'CREDIT', amount: marginAmount,
                currency, description: `FX spread margin: ${txId}`, timestamp: new Date().toISOString() });
        }
        if (this.isPositiveAmount(riskAmount)) {
            const walletId = await systemSettlementAccounts.resolve('FX_RISK_RESERVE', currency);
            legs.push({ transactionId: txId, walletId, type: 'CREDIT', amount: riskAmount,
                currency, description: `FX risk reserve: ${txId}`, timestamp: new Date().toISOString() });
        }
    }

    private isPositiveAmount(value: unknown): boolean {
        const amount = Number(value);
        return Number.isFinite(amount) && amount > 0;
    }

    private async commitToCloud(userId: string, txId: string, intent: any, legs: LedgerEntry[], status: TransactionStatus = 'completed') {
        const txService = new TransactionService();
        await txService.postTransactionWithLedger({
            id: txId,
            referenceId: intent.referenceId,
            user_id: userId,
            amount: intent.amount,
            description: intent.description,
            type: (intent.type.toLowerCase() === 'internal_transfer' || intent.type.toLowerCase() === 'peer_transfer') ? 'transfer' : 
                  (intent.type.toLowerCase() === 'deposit') ? 'deposit' : 
                  (intent.type.toLowerCase() === 'withdrawal') ? 'withdrawal' : 'expense',
            currency: intent.currency,
            status: status,
            walletId: intent.sourceWalletId,
            toWalletId: intent.targetWalletId,
            categoryId: intent.categoryId,
            date: new Date().toISOString(),
            metadata: intent.metadata
        }, legs);
    }

    /**
     * SETTLEMENT ENGINE (V2.0)
     * ------------------------
     * Finalizes a staged internal transfer by moving funds from the 
     * internal transaction wallet to the target operating wallet.
     */
    private async claimInternalTransferSettlement(txId: string, workerId: string) {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) {
            throw new Error('LEDGER_FAULT: Cloud connectivity required.');
        }

        const workerClaimId = UUID.generate();
        const { data, error } = await sb.rpc('claim_internal_transfer_settlement', {
            p_tx_id: txId,
            p_worker_id: workerId,
            p_worker_claim_id: workerClaimId,
        });

        if (error) {
            throw normalizeFinancialAuthorityError(error, 'SETTLEMENT_CLAIM');
        }

        const claim = Array.isArray(data) ? data[0] : data;
        if (!claim) {
            throw new Error(`INVALID_SETTLEMENT_STATE: Settlement claim for ${txId} did not return lifecycle data.`);
        }

        return {
            appendAlreadyApplied: claim.append_already_applied === true,
            alreadyCompleted: claim.already_completed === true,
            appendKey: String(claim.append_key || buildInternalTransferSettlementAppendKey(txId)),
            appendPhase: String(claim.append_phase || FINANCIAL_INVARIANTS.internalTransferSettlementAppendPhase),
            workerClaimId: String(claim.worker_claim_id || workerClaimId),
            transactionStatus: String(claim.transaction_status || ''),
        };
    }

    private async finalizeInternalTransferSettlement(
        txId: string,
        workerClaimId: string,
        result: 'COMPLETED' | 'HELD_FOR_REVIEW',
        note: string,
        zeroSumValid: boolean,
    ) {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) {
            throw new Error('LEDGER_FAULT: Cloud connectivity required.');
        }

        const { data, error } = await sb.rpc('complete_internal_transfer_settlement', {
            p_tx_id: txId,
            p_worker_claim_id: workerClaimId,
            p_result: result,
            p_result_note: note,
            p_zero_sum_valid: zeroSumValid,
        });

        if (error) {
            throw normalizeFinancialAuthorityError(error, 'SETTLEMENT_FINALIZE');
        }

        const completion = Array.isArray(data) ? data[0] : data;
        if (!completion) {
            throw new Error(`INVALID_SETTLEMENT_STATE: Settlement completion for ${txId} did not return status data.`);
        }

        return {
            previousStatus: String(completion.previous_status || ''),
            finalStatus: String(completion.final_status || ''),
            lifecycleStage: String(completion.lifecycle_stage || ''),
            lifecycleStatus: String(completion.lifecycle_status || ''),
            alreadyFinalized: completion.already_finalized === true,
        };
    }

    private async emitSettlementStatusEffects(txId: string, tx: any, previousStatus: string, finalStatus: TransactionStatus, note: string) {
        const txService = new TransactionService();
        await txService.logTransactionEvent(txId, previousStatus || tx?.status || null, finalStatus, 'settlement_worker', { notes: note });

        if (tx?.user_id) {
            SocketRegistry.notifyTransactionUpdate(tx.user_id, { ...tx, status: finalStatus, status_notes: note });
        }

        if (finalStatus === 'completed') {
            TransactionStateMachine.transition(txId, previousStatus as TransactionStatus || 'processing', 'completed', { settlement: true });
            Audit.log('FINANCIAL', tx?.user_id, 'TRANSACTION_SETTLED', { txId }).catch(() => {});
            if (tx?.user_id && tx?.wallet_id) {
                const txServiceForBalance = new TransactionService();
                const balance = await txServiceForBalance.calculateBalanceFromLedger(tx.wallet_id);
                SocketRegistry.notifyBalanceUpdate(tx.user_id, tx.wallet_id, balance);
            }
            await this.sendTransferNotifications(txId, { ...tx, status: finalStatus, status_notes: note });
        }
    }

    public async completeSettlement(txId: string, txData?: any, workerId?: string): Promise<boolean> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return false;

        try {
            const txService = new TransactionService();
            const settlementWorkerId = workerId || `engine:settlement:${txId}`;
            
            // Use provided txData or fetch from DB
            let tx = txData;
            if (!tx) {
                const { data } = await sb.from('transactions').select('*').eq('id', txId).single();
                tx = data;
            }

            const claim = await this.claimInternalTransferSettlement(txId, settlementWorkerId);
            if (claim.alreadyCompleted) {
                bankingLogger.info('banking.settlement_already_completed', { transaction_id: txId, worker_id: settlementWorkerId });
                return true;
            }
            assertSettlementEligible({ txId, txExists: !!tx, status: claim.transactionStatus || tx?.status });

            const amount = await DataProtection.decryptAmount(tx.amount);
            const targetWalletId = tx.to_wallet_id;
            const currency = tx.currency;
            const targetCurrency = tx.metadata?.target_currency || currency;
            const targetAmount = tx.metadata?.fx_details?.finalAmount || amount;
            
            // Resolve Internal Vault
            const { data: internalVault } = await sb.from('platform_vaults')
                .select('id')
                .eq('user_id', tx.user_id)
                .eq('vault_role', 'INTERNAL_TRANSFER')
                .maybeSingle();

            assertSettlementEligible({ txId, txExists: true, status: tx.status, hasInternalVault: !!internalVault });
            const settlementVaultId = internalVault!.id;

            if (!targetWalletId) throw new Error("SETTLEMENT_ERROR: Missing target wallet.");

            const legs: LedgerEntry[] = [
                {
                    transactionId: txId,
                    walletId: settlementVaultId,
                    type: 'DEBIT',
                    amount: targetAmount,
                    currency: targetCurrency,
                    description: `PaySafe Release: ${txId}`,
                    timestamp: new Date().toISOString()
                },
                {
                    transactionId: txId,
                    walletId: targetWalletId,
                    type: 'CREDIT',
                    amount: targetAmount,
                    currency: targetCurrency,
                    description: `PaySafe Settlement: ${txId}`,
                    timestamp: new Date().toISOString()
                }
            ];

            if (!claim.appendAlreadyApplied) {
                try {
                    await txService.addLedgerEntries(txId, legs, {
                        appendKey: claim.appendKey,
                        appendPhase: claim.appendPhase,
                    });
                } catch (e: any) {
                    const mappedAppendError = normalizeFinancialAuthorityError(e, 'SETTLEMENT_APPEND');
                    if (mappedAppendError.message.startsWith('IDEMPOTENCY_VIOLATION')) {
                        bankingLogger.info('banking.settlement_append_already_applied', { transaction_id: txId, append_key: claim.appendKey, worker_id: settlementWorkerId });
                    } else {
                        throw mappedAppendError;
                    }
                }
            } else {
                bankingLogger.info('banking.settlement_append_marker_exists', { transaction_id: txId, append_key: claim.appendKey, worker_id: settlementWorkerId });
            }
            
            // 5. FORENSIC VERIFICATION (Zero-Sum Check)
            const reconResult = await ReconciliationEngine.verifyZeroSum(txId);
            const isValid = reconResult.isValid === true;
            const sum = reconResult.sum || 0;
            
            if (!isValid) {
                bankingLogger.error('banking.zero_sum_violation_detected', { transaction_id: txId, residual: sum, actor_id: tx.user_id });
                
                // Trigger Real-time Alert
                await MonitoringService.notifyCritical('ZERO_SUM_VIOLATION', {
                    transactionId: txId,
                    residual: sum,
                    userId: tx.user_id
                });

                await this.finalizeInternalTransferSettlement(
                    txId,
                    claim.workerClaimId,
                    'HELD_FOR_REVIEW',
                    `Zero-sum violation detected: ${sum}`,
                    false,
                );
                return false;
            }

            const completion = await this.finalizeInternalTransferSettlement(
                txId,
                claim.workerClaimId,
                'COMPLETED',
                'Settlement finalized by processor.',
                true,
            );

            if (!completion.alreadyFinalized) {
                await this.emitSettlementStatusEffects(
                    txId,
                    tx,
                    completion.previousStatus || claim.transactionStatus || 'processing',
                    'completed',
                    'Settlement finalized by processor.',
                );
            }
            return true;
        } catch (e: any) {
            const mappedError = normalizeFinancialAuthorityError(e, 'SETTLEMENT');
            bankingLogger.error('banking.settlement_failed', { transaction_id: txId, worker_id: workerId, error_message: mappedError.message }, mappedError);
            
            // Determine if error is transient
            const isTransient = mappedError.message.includes('CONCURRENCY_CONFLICT') ||
                                mappedError.message.includes('LEDGER_FAULT') || 
                                mappedError.message.includes('LEDGER_COMMIT_FAULT') ||
                                mappedError.message.includes('LEDGER_APPEND_FAULT') ||
                                mappedError.message.includes('timeout') ||
                                mappedError.message.includes('fetch failed');
            
            if (isTransient) {
                throw mappedError; // Throw transient errors so the reaper doesn't incorrectly reverse the transaction
            }

            if (mappedError.message.startsWith('INVALID_SETTLEMENT_STATE')) {
                throw mappedError;
            }

            return false;
        }
    }

    /**
     * Sends notifications to both sender and recipient for a successful transfer.
     */
    public async sendTransferNotifications(txId: string, txData?: any, decryptedAmount?: number): Promise<void> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return;

        try {
            let tx = txData;
            if (!tx) {
                const { data } = await sb.from('transactions').select('*').eq('id', txId).single();
                tx = data;
            }
            if (!tx) return;

            const amount = decryptedAmount || await DataProtection.decryptAmount(tx.amount);
            const targetAmount = tx.metadata?.fx_details?.finalAmount || amount;
            const targetWalletId = tx.to_wallet_id;
            const fromWalletId = tx.from_wallet_id || tx.walletId;
            const senderId = tx.user_id;

            // Resolve Recipient User ID
            let recipientId = null;
            const { data: wallet } = await sb.from('wallets').select('user_id, account_number').eq('id', targetWalletId).maybeSingle();
            if (wallet) recipientId = wallet.user_id;
            
            if (!recipientId) {
                const { data: vault } = await sb.from('platform_vaults').select('user_id').eq('id', targetWalletId).maybeSingle();
                if (vault) recipientId = vault.user_id;
            }

            // Fetch Sender Details
            const { data: senderProfile } = await sb.from('users').select('full_name, customer_id, language, nationality, phone, metadata').eq('id', senderId).maybeSingle();
            const { data: senderAuth } = await sb.auth.admin.getUserById(senderId);
            const { data: senderWallet } = await sb.from('wallets').select('account_number').eq('id', fromWalletId).maybeSingle();
            
            // Fetch Recipient Details
            let recipientProfile = null;
            let recipientAuth = null;
            if (recipientId) {
                const { data: rp } = await sb.from('users').select('full_name, customer_id, language, nationality, phone, metadata').eq('id', recipientId).maybeSingle();
                recipientProfile = rp;
                const { data: ra } = await sb.auth.admin.getUserById(recipientId);
                recipientAuth = ra;
            }

            const senderName = senderProfile?.full_name || senderAuth?.user?.user_metadata?.full_name || 'Customer';
            const senderAccount = senderWallet?.account_number || senderProfile?.customer_id || 'Orbi Account';
            const recipientName = recipientProfile?.full_name || recipientAuth?.user?.user_metadata?.full_name || 'Customer';
            const recipientAccount = wallet?.account_number || recipientProfile?.customer_id || 'Orbi Account';
            
            const currency = tx.currency;
            const targetCurrency = tx.metadata?.target_currency || currency;
            const isFxConversion =
                tx.type === 'FX_CONVERSION' ||
                tx.transaction_type === 'FX_CONVERSION' ||
                tx.metadata?.transaction_type === 'FX_CONVERSION' ||
                Boolean(tx.metadata?.fx_details);
            const occurredAtUtc = tx.created_at || tx.createdAt || tx.date || new Date().toISOString();
            const refId = tx.reference_id || tx.referenceId || txId;

            bankingLogger.info('banking.transfer_notifications_resolved', { transaction_id: txId, actor_id: senderId, recipient_id: recipientId, reference_id: refId });

            const promises = [];
            
            // Notification for Recipient
            if (recipientId && !isFxConversion) {
                 const recipientLang = recipientProfile?.language || 'en';
                 const isSw = recipientLang === 'sw';
                 const recipientTime = formatMessageTime(occurredAtUtc, recipientProfile, recipientAuth?.user, recipientLang, tx.metadata);
                 const footer = isSw 
                    ? "Asante kwa kuichagua ORBI, tunathamini imani yako. Timu ya Kifedha ya ORBI"
                    : "Thank you For choosing ORBI, We value your trust. The ORBI Financial Team";
                 const isSalary = tx.type === 'salary';
                 const isEscrow = tx.type === 'escrow';
                 const month = new Date().toLocaleString(isSw ? 'sw-TZ' : 'en-US', { month: 'long' });
                 
                 let subject = isSw ? 'Fedha Zimepokelewa' : 'Funds Received';
                 if (isSalary) subject = isSw ? 'Mshahara Umepokelewa' : 'Salary Received';
                 if (isEscrow) subject = isSw ? 'Ombi la Orbi PaySafe' : 'Orbi PaySafe request';
                 
                 let recipientMsg = '';
                 let templateName = 'Transfer_Received';
                 let variables: any = {
                     amount: targetAmount.toLocaleString(),
                     currency: targetCurrency,
                     timestamp: recipientTime.display,
                     occurred_at_utc: recipientTime.canonicalUtc,
                     display_timezone: recipientTime.timezone,
                     refId
                 };

                 if (isSalary) {
                     templateName = 'Salary_Received';
                     variables.employeeName = recipientName;
                     variables.month = month;
                     recipientMsg = isSw
                        ? `Ndugu ${recipientName}, mshahara wako wa mwezi ${month} kiasi cha ${targetCurrency} ${targetAmount.toLocaleString()} umeingia kwenye akaunti yako ya ORBI saa ${recipientTime.display}. Kumbukumbu ${refId}. ${footer}`
                        : `Dear ${recipientName}, your salary for ${month} of ${targetCurrency} ${targetAmount.toLocaleString()} has been credited to your ORBI account at ${recipientTime.display}. Reference ${refId}. ${footer}`;
                 } else if (isEscrow) {
                     templateName = 'Escrow_Request_Received';
                     variables = {
                         senderName,
                         recipientName,
                         currency: targetCurrency,
                         amount: targetAmount.toLocaleString(),
                         refId
                     };
                     recipientMsg = isSw
                        ? `${senderName} ametengeneza ombi la Orbi PaySafe la ${targetCurrency} ${targetAmount.toLocaleString()} kwa ajili yako. Fedha ziko salama hadi release ithibitishwe. Kumbukumbu ${refId}.`
                        : `${senderName} created an Orbi PaySafe request of ${targetCurrency} ${targetAmount.toLocaleString()} for you. Funds are safe until release is confirmed. Reference ${refId}.`;
                 } else {
                     variables.recipientName = recipientName;
                     variables.senderName = senderName;
                     recipientMsg = isSw
                        ? `Ndugu ${recipientName} umefanikiwa kupokea ${targetCurrency} ${targetAmount.toLocaleString()}/= kwenye akaunti yako ya ORBI kutoka kwa ${senderName} saa ${recipientTime.display}. Kumbukumbu ${refId} . ${footer}`
                        : `Dear ${recipientName} you have successfully received ${targetCurrency} ${targetAmount.toLocaleString()}/= on your ORBI account from ${senderName} at ${recipientTime.display}. Reference ${refId} . ${footer}`;
                 }
                 
                 promises.push(Messaging.dispatch(recipientId, 'info', subject, recipientMsg, { 
                     push: true,
                     sms: true,
                     email: true,
                     template: templateName,
                     variables
                 }));
                 
                 // REAL-TIME: Notify recipient about the new transaction and balance update
                 SocketRegistry.notifyTransactionUpdate(recipientId, { ...tx, status: 'completed' });
                 if (targetWalletId) {
                     const txService = new TransactionService();
                     const newBalance = await txService.getLatestBalance(recipientId, targetWalletId);
                     SocketRegistry.notifyBalanceUpdate(recipientId, targetWalletId, newBalance);
                     SocketRegistry.send(recipientId, { type: 'REFRESH_WALLETS', payload: { walletId: targetWalletId } });
                 }
            }

            // Notification for Sender
            const senderLang = senderProfile?.language || 'en';
            const isSenderSw = senderLang === 'sw';
            const senderTime = formatMessageTime(occurredAtUtc, senderProfile, senderAuth?.user, senderLang, tx.metadata);
            const senderFooter = isSenderSw 
                ? "Asante kwa kuichagua ORBI, tunathamini imani yako. Timu ya Kifedha ya ORBI"
                : "Thank you For choosing ORBI, We value your trust. The ORBI Financial Team";
            const senderIsEscrow = tx.type === 'escrow';
            const senderSubject = isFxConversion
                ? (isSenderSw ? 'Fedha Zimebadilishwa' : 'Currency Converted')
                : senderIsEscrow
                ? (isSenderSw ? 'Orbi PaySafe imeundwa' : 'Orbi PaySafe created')
                : (isSenderSw ? 'Uhamisho Umekamilika' : 'Transfer Completed');
            const senderMsg = isFxConversion
                ? (isSenderSw
                    ? `Ndugu ${senderName}, umefanikiwa kubadilisha ${currency} ${amount.toLocaleString()}/= kuwa ${targetCurrency} ${targetAmount.toLocaleString()} saa ${senderTime.display}. Kumbukumbu ${refId}. ${senderFooter}`
                    : `Dear ${senderName}, you have successfully converted ${currency} ${amount.toLocaleString()} to ${targetCurrency} ${targetAmount.toLocaleString()} at ${senderTime.display}. Reference ${refId}. ${senderFooter}`)
                : senderIsEscrow
                ? (isSenderSw
                    ? `Ndugu ${senderName}, umeunda Orbi PaySafe ya ${currency} ${amount.toLocaleString()}/= kwa ${recipientName}. Fedha ziko salama hadi uthibitishe release. Kumbukumbu ${refId}. ${senderFooter}`
                    : `Dear ${senderName}, you created an Orbi PaySafe of ${currency} ${amount.toLocaleString()}/= for ${recipientName}. Money is safe until you confirm release. Reference ${refId}. ${senderFooter}`)
                : (isSenderSw
                    ? `Ndugu ${senderName} umefanikiwa kutuma ${currency} ${amount.toLocaleString()}/= kutoka kwenye akaunti yako ya ORBI kwenda kwa ${recipientName} saa ${senderTime.display}. Kumbukumbu ${refId} . ${senderFooter}`
                    : `Dear ${senderName} you have successfully sent ${currency} ${amount.toLocaleString()}/= from your ORBI account to ${recipientName} at ${senderTime.display}. Reference ${refId} . ${senderFooter}`);
            
            promises.push(Messaging.dispatch(senderId, 'info', senderSubject, senderMsg, { 
                push: true,
                sms: true,
                email: true,
                template: isFxConversion ? 'Transactional_Message' : senderIsEscrow ? 'Escrow_Created' : 'Transfer_Sent',
                variables: {
                    senderName,
                    amount: amount.toLocaleString(),
                    currency,
                    targetAmount: targetAmount.toLocaleString(),
                    targetCurrency,
                    recipientName,
                    timestamp: senderTime.display,
                    occurred_at_utc: senderTime.canonicalUtc,
                    display_timezone: senderTime.timezone,
                    body: senderMsg,
                    refId
                }
            }));

            await Promise.all(promises);

        } catch (e: any) {
            bankingLogger.warn('banking.notification_dispatch_failed', { transaction_id: txId, error_message: e.message });
        }
    }

    private async commitToLocal(userId: string, txId: string, intent: any, legs: LedgerEntry[]) {
        throw new Error('LOCAL_LEDGER_COMMIT_FALLBACK_DISABLED');
    }

    private async verifyLedgerIntegrity(txId: string): Promise<{ valid: boolean, failures: string[] }> {
        const txService = new TransactionService();
        const legs = await txService.getLedgerEntries(txId);
        
        if (legs.length === 0) return { valid: false, failures: ['NO_LEGS_FOUND'] };

        let sum = 0;
        const failures: string[] = [];

        for (const leg of legs) {
            if (leg.entry_type === 'CREDIT') sum += leg.amount;
            else sum -= leg.amount;
        }

        // Double-entry bookkeeping must sum to zero
        if (Math.abs(sum) > 0.0001) {
            failures.push(`BALANCE_MISMATCH: Sum is ${sum}`);
        }

        return { valid: failures.length === 0, failures };
    }

    public async getHistory(userId: string, limit: number = 50): Promise<any[]> {
        const txService = new TransactionService();
        return await txService.getLatestTransactions(userId, limit);
    }

    private verifyTransaction(intent: any, tx: any) {
        if (Number(tx.amount) !== Number(intent.amount)) throw new Error(`VERIFICATION_FAILURE: Amount mismatch. Expected ${intent.amount}, got ${tx.amount}`);
        if (tx.currency !== intent.currency) throw new Error(`VERIFICATION_FAILURE: Currency mismatch. Expected ${intent.currency}, got ${tx.currency}`);
        // Only verify if walletId is present in tx (it might not be for some transaction types or if not returned)
        if (tx.walletId && tx.walletId !== intent.sourceWalletId) throw new Error(`VERIFICATION_FAILURE: Source wallet mismatch. Expected ${intent.sourceWalletId}, got ${tx.walletId}`);
        // Only verify if toWalletId is present in tx
        if (tx.toWalletId && tx.toWalletId !== intent.targetWalletId) throw new Error(`VERIFICATION_FAILURE: Target wallet mismatch. Expected ${intent.targetWalletId}, got ${tx.toWalletId}`);
    }
}

export const BankingEngine = new BankingEngineService();
