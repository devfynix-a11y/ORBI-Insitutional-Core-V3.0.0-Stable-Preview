import { User } from '../../../types.js';
import { UUID } from '../../../services/utils.js';
import { SecurityRules } from '../../../ledger/rulesEngine.js';
import { Identity } from '../../../iam/identityService.js';
import { WalletResolverService } from '../../wealth/WalletResolver.js';
import { ConfigClient } from '../../infrastructure/RulesConfigClient.js';
import { getSupabase, getAdminSupabase } from '../../supabaseClient.js';

import { OTPService } from '../../security/otpService.js';
import { IdempotencyLayer } from '../infrastructure/IdempotencyLayer.js';
import { LockManager } from '../infrastructure/LockManager.js';
import { EventBus } from '../infrastructure/EventBus.js';
import { VaultRegistry } from '../ledger/VaultRegistry.js';
import { BankingEngine } from '../../ledger/transactionEngine.js';
import { SecurityService } from '../../../iam/securityService.js';
import { FXEngine } from '../../ledger/FXEngine.js';
import { resolveLockedFxConversion, type LockedFxQuote } from '../../ledger/FXLockedQuote.js';
import { Messaging } from '../../features/MessagingService.js';

export interface EntPaymentIntent {
    idempotencyKey: string;
    referenceId?: string;
    sourceWalletId?: string;
    targetWalletId?: string;
    recipientId?: string;
    recipient_customer_id?: string;
    amount: number;
    currency: string;
    description: string;
    type: 'INTERNAL_TRANSFER' | 'EXTERNAL_PAYMENT' | 'DEPOSIT' | 'WITHDRAWAL' | 'Internal' | 'External';
    walletType?: 'internal_vault' | 'External' | 'GOAL' | 'BUDGET';
    category?: 'Pay' | 'Transfer' | 'Topup' | 'Send' | string;
    categoryId?: string;
    device?: any;
    metadata?: any;
}

/**
 * Enterprise Payment Processor (V2)
 * Orchestrates the full enterprise transaction lifecycle:
 * Idempotency -> Validation -> Risk Audit -> Distributed Lock -> Atomic Commit -> Event Publish
 */
export class EnterprisePaymentProcessor {
    private rules = SecurityRules;

    public async process(user: User, intent: EntPaymentIntent, serverFxQuote?: LockedFxQuote): Promise<any> {
        console.log(`[EntProcessor] Starting process for user: ${user.id || 'N/A'}, customer_id: ${(user as any).customer_id || 'N/A'}`);

        if ((intent as any).dryRun) {
            throw new Error('TRANSACTION_DRY_RUN_NOT_SUPPORTED');
        }

        // 1. IDEMPOTENCY CHECK (Critical for Enterprise)
        // Ensure we have a user ID for idempotency check
        if (!user.id && (user as any).customer_id) {
            const profile = await Identity.lookupUser((user as any).customer_id);
            if (profile) {
                user.id = profile.id;
            }
        }
        
        if (!user.id) throw new Error("VALIDATION_ERROR: Sender identity could not be resolved for idempotency check.");

        const { isDuplicate, cachedResponse } = await IdempotencyLayer.checkOrRegister(
            intent.idempotencyKey, 
            user.id, 
            '/v2/transactions/process'
        );

        if (isDuplicate) {
            console.log(`[EntProcessor] Idempotency hit for key: ${intent.idempotencyKey}`);
            return cachedResponse;
        }

        const referenceId = intent.referenceId || `REF-${UUID.generateShortCode(12)}`;
        intent.referenceId = referenceId;

        try {
            // Normalize type if sent as Internal/External
            if ((intent.type as string) === 'Internal') intent.type = 'INTERNAL_TRANSFER';
            if ((intent.type as string) === 'External') intent.type = 'EXTERNAL_PAYMENT';

            // 2. PRE-FLIGHT VALIDATION & RESOLUTION
            this.validateIntent(intent);

            // Resolve Sender Identity if user.id is missing (e.g. if only customer_id was provided)
            if (!user.id && (user as any).customer_id) {
                const profile = await Identity.lookupUser((user as any).customer_id);
                if (profile) {
                    user.id = profile.id;
                    if (!(user as any).full_name) (user as any).full_name = profile.full_name;
                }
            }
            
            if (!user.id) throw new Error("VALIDATION_ERROR: Sender identity could not be resolved.");
            console.log(`[EntProcessor] Sender resolved: ${user.id}`);

            // KYC-based Transaction Limits
            const config = await ConfigClient.getRuleConfig();
            
            let kycStatus = user.user_metadata?.kyc_status;
            let accountCurrency = user.user_metadata?.currency;
            if (!kycStatus) {
                const sb = getSupabase();
                // Try admin client first for reliable lookup
                const adminSb = (await import('../../supabaseClient.js')).getAdminSupabase();
                const client = adminSb || sb;
                
                if (client) {
                    const { data } = await client
                        .from('users')
                        .select('kyc_status, currency')
                        .eq('id', user.id)
                        .maybeSingle();
                    kycStatus = data?.kyc_status;
                    accountCurrency = data?.currency || accountCurrency;
                }
            }

            accountCurrency = typeof accountCurrency === 'string'
                ? accountCurrency.trim().toUpperCase()
                : '';
            if (!accountCurrency) {
                throw new Error("CURRENCY_REQUIRED: Sender account has no assigned currency. Transfers are blocked until the profile is fixed.");
            }
            
            if (kycStatus !== 'verified') {
                const limit = 2000000; // TSH 2,000,000
                const dailyLimit = 15; // 15 transactions per day

                if (intent.amount > limit) {
                    throw new Error(`VALIDATION_ERROR: Transaction amount exceeds limit for non-verified KYC users (Max TSH ${limit.toLocaleString()}).`);
                }

                const history = await BankingEngine.getHistory(user.id, 100);
                const today = new Date().toDateString();
                const transactionsToday = history.filter(tx => new Date(tx.date).toDateString() === today);
                if (transactionsToday.length >= dailyLimit) {
                    throw new Error(`VALIDATION_ERROR: Daily transaction limit exceeded for non-verified KYC users (Max ${dailyLimit} transactions per day).`);
                }
            }

            // Resolve Source Wallet (Dynamic Vault mapping if needed)
            const isInternalVault = intent.walletType === 'internal_vault' || !intent.walletType;
            const isSubWallet = intent.walletType === 'GOAL' || intent.walletType === 'BUDGET';
            
            if (!intent.sourceWalletId || isSubWallet) {
                // Pass user.id directly to resolveWallet, as it expects an identifier that can be a user ID
                const resolvedSender = await WalletResolverService.resolveWallet(user.id, 'OPERATING');
                const operatingWalletId = resolvedSender?.walletId;

                if (isSubWallet) {
                    if (!intent.sourceWalletId) throw new Error("VALIDATION_ERROR: Sub-wallet ID is required for Goal/Budget transfers.");
                    if (!operatingWalletId) throw new Error("INFRASTRUCTURE_ERROR: Operating wallet not found for fund shift.");
                    
                    // Store the intermediate operating wallet in metadata for the BankingEngine
                    intent.metadata = { 
                        ...intent.metadata, 
                        intermediate_operating_wallet: operatingWalletId,
                        is_sub_wallet_transfer: true,
                        sub_wallet_type: intent.walletType,
                        transfer_category: intent.category || 'Transfer'
                    };
                } else if (!intent.sourceWalletId) {
                    if (intent.type === 'DEPOSIT') {
                        intent.sourceWalletId = await VaultRegistry.getVaultId('OPERATING');
                    } else if (isInternalVault) {
                        if (operatingWalletId) {
                            intent.sourceWalletId = operatingWalletId;
                        } else {
                            throw new Error("VALIDATION_ERROR: No operating wallet found for this user. Genesis provisioning may be incomplete.");
                        }
                    } else if (intent.walletType === 'External') {
                        // For external wallets, we expect the ID to be provided
                        throw new Error("VALIDATION_ERROR: External source wallet ID must be provided when walletType is 'External'.");
                    }
                }
            }

            // Resolve Source PaySafe (INTERNAL_TRANSFER) for escrow flow
            if (intent.type === 'INTERNAL_TRANSFER' || (intent.type as any) === 'PEER_TRANSFER') {
                const resolvedPaySafe = await WalletResolverService.resolveWallet(user.id, 'INTERNAL_TRANSFER');
                if (resolvedPaySafe) {
                    intent.metadata = { 
                        ...intent.metadata, 
                        source_internal_vault_id: resolvedPaySafe.walletId,
                        source_internal_vault_name: resolvedPaySafe.walletName
                    };
                } else {
                    throw new Error("INFRASTRUCTURE_ERROR: PaySafe (INTERNAL_TRANSFER) vault not found for sender. Secure escrow is required.");
                }
            }

            // Resolve Recipient Identity & Target Wallet
            const recipientIdentifier = intent.recipientId || intent.recipient_customer_id;
            if (recipientIdentifier) {
                const resolvedRecipient = await WalletResolverService.resolveWallet(recipientIdentifier);
                if (!resolvedRecipient) throw new Error("RECIPIENT_NOT_FOUND");
                
                // Ensure intent has the resolved ID
                intent.recipientId = resolvedRecipient.userId;
                
                intent.metadata = { ...intent.metadata, recipient_snapshot: { id: resolvedRecipient.userId, name: resolvedRecipient.profile.full_name } };
                
                // Auto-resolve target wallet if missing for transfers
                if (!intent.targetWalletId && (intent.type === 'INTERNAL_TRANSFER' || (intent.type as any) === 'PEER_TRANSFER')) {
                    intent.targetWalletId = resolvedRecipient.walletId;
                    console.log(`[EntProcessor] Auto-resolved target wallet: ${intent.targetWalletId}`);
                }
            } else if (intent.targetWalletId && (intent.type === 'INTERNAL_TRANSFER' || (intent.type as any) === 'PEER_TRANSFER')) {
                // If targetWalletId is provided directly, verify it exists using WalletResolver
                const resolvedTarget = await WalletResolverService.resolveByWalletId(intent.targetWalletId);
                if (!resolvedTarget) {
                    throw new Error(`VALIDATION_ERROR: Target wallet ID ${intent.targetWalletId} does not exist or is not registered.`);
                }
                
                // Enrich metadata with recipient snapshot for audit trail
                intent.metadata = { 
                    ...intent.metadata, 
                    recipient_snapshot: { 
                        id: resolvedTarget.userId, 
                        name: resolvedTarget.profile.full_name 
                    } 
                };
                
                // Also set recipientId if missing
                if (!intent.recipientId) intent.recipientId = resolvedTarget.userId;
            }

            if (!intent.targetWalletId) {
                if (intent.type === 'WITHDRAWAL') {
                    intent.targetWalletId = await VaultRegistry.getVaultId('SETTLEMENT');
                } else {
                    throw new Error("VALIDATION_ERROR: Target wallet ID is required.");
                }
            }

            await this.assertWalletUnlocked(intent.sourceWalletId, 'source');
            if (intent.targetWalletId) {
                await this.assertWalletUnlocked(intent.targetWalletId, 'target');
            }
            const intermediateWallet = intent.metadata?.intermediate_operating_wallet;
            if (intermediateWallet) {
                await this.assertWalletUnlocked(intermediateWallet, 'operating');
            }
            const internalVault = intent.metadata?.source_internal_vault_id;
            if (internalVault) {
                await this.assertWalletUnlocked(internalVault, 'internal');
            }

            // --- CROSS-CURRENCY RESOLUTION ---
            const sb = getAdminSupabase() || getSupabase();
            let sourceCurrency = intent.currency;
            let targetCurrency = intent.currency;

            // Fetch source wallet currency if not explicitly provided or to verify
            if (intent.sourceWalletId && sb) {
                const { data: sourceWallet } = await sb.from('platform_vaults').select('currency').eq('id', intent.sourceWalletId).maybeSingle();
                if (sourceWallet?.currency) {
                    sourceCurrency = sourceWallet.currency;
                } else {
                    const { data: sw } = await sb.from('wallets').select('currency').eq('id', intent.sourceWalletId).maybeSingle();
                    if (sw?.currency) sourceCurrency = sw.currency;
                }
            }

            // Fetch target wallet currency
            if (intent.targetWalletId && sb) {
                const { data: targetWallet } = await sb.from('platform_vaults').select('currency').eq('id', intent.targetWalletId).maybeSingle();
                if (targetWallet?.currency) {
                    targetCurrency = targetWallet.currency;
                } else {
                    const { data: tw } = await sb.from('wallets').select('currency').eq('id', intent.targetWalletId).maybeSingle();
                    if (tw?.currency) targetCurrency = tw.currency;
                }
            }

            // Perform Conversion if currencies differ
            let conversionData = null;
            if (String(intent.type).toUpperCase() === 'FX_CONVERSION' && !serverFxQuote) {
                throw new Error('FX_LOCKED_QUOTE_REQUIRED');
            }
            if (String(intent.type).toUpperCase() === 'FX_CONVERSION' && sourceCurrency.toUpperCase() === targetCurrency.toUpperCase()) {
                throw new Error('FX_QUOTE_WALLET_CURRENCY_MISMATCH');
            }
            if (sourceCurrency && targetCurrency && sourceCurrency.toUpperCase() !== targetCurrency.toUpperCase()) {
                console.log(`[EntProcessor] Cross-currency detected: ${sourceCurrency} -> ${targetCurrency}`);
                conversionData = serverFxQuote
                    ? resolveLockedFxConversion(serverFxQuote, intent.amount, sourceCurrency, targetCurrency)
                    : await FXEngine.processConversion(intent.amount, sourceCurrency, targetCurrency);
                
                // Update intent metadata with conversion details for BankingEngine and Audit
                intent.metadata = {
                    ...intent.metadata,
                    cross_currency: true,
                    fx_details: conversionData,
                    source_currency: sourceCurrency,
                    target_currency: targetCurrency,
                    original_amount: intent.amount
                };

                // The 'amount' in intent for BankingEngine should be the source amount (what is debited)
                // But we need to tell BankingEngine what the target amount (what is credited) is.
                // We'll use metadata for this.
            }

            // 3. NEURAL RISK AUDIT (Fraud Engine)
            const report = await this.rules.evaluate(user, intent as any, []);
            
            if (report.decision === 'BLOCK') {
                const reasons = (report.results || []).filter((r: any) => !r.passed).map((r: any) => r.message).join('; ');
                await EventBus.publish('fintech.fraud.alert_triggered', '/core/risk', { userId: user.id, reasons });
                throw new Error(`SECURITY_BLOCK: Transaction rejected by Risk Engine: ${reasons}`);
            }

            if (report.decision === 'CHALLENGE') {
                // Check for recent verification to avoid loop
                const security = new SecurityService();
                const activities = await security.getUserActivity(user.id);
                const recentVerification = activities.find(a => 
                    a.activity_type === 'SENSITIVE_ACTION_VERIFIED' && 
                    (a.status === 'success' || (a.status as any) === 'VERIFIED') &&
                    (Date.now() - new Date(a.created_at).getTime()) < 5 * 60 * 1000 // 5 minutes
                );

                if (recentVerification) {
                    console.log(`[EntProcessor] Challenge bypassed due to recent verification: ${recentVerification.id}`);
                } else {
                    let contact = user.email || user.phone;
                    
                    if (!contact) {
                        const sb = getAdminSupabase();
                        if (sb) {
                            const { data } = await sb.auth.admin.getUserById(user.id);
                            if (data?.user?.email) {
                                contact = data.user.email;
                            } else if (data?.user?.phone) {
                                contact = data.user.phone;
                            }
                        }
                    }

                    if (!contact) {
                        throw new Error("SECURITY_ERROR: No contact method (email or phone) available for transaction verification.");
                    }

                    const type = contact.includes('@') ? 'email' : 'sms';
                    const deviceName =
                        intent?.device?.deviceName ||
                        intent?.device?.device_name ||
                        intent?.device?.deviceModel ||
                        intent?.device?.model ||
                        intent?.metadata?.deviceName ||
                        intent?.metadata?.device_name ||
                        user.user_metadata?.device_name ||
                        'ORBI Mobile';
                    const { requestId, code, deliveryType } = await OTPService.generateAndSend(user.id, contact, 'transaction_verification', type as any, deviceName);
                    
                    const challengeResponse = {
                        success: false,
                        error: 'SECURITY_CHALLENGE',
                        message: `2FA required via ${deliveryType || type}`,
                        requestId,
                        controlId: referenceId,
                        // DEV ONLY: Return code in API response
                        dev_otp_code: code 
                    };

                    // A security challenge is not a terminal financial response. Keeping the
                    // key as COMPLETED would replay the challenge after OTP verification and
                    // prevent the real settlement from continuing.
                    await IdempotencyLayer.clearKey(intent.idempotencyKey, user.id, '/v2/transactions/process');
                    return challengeResponse;
                }
            }

            // 4. DISTRIBUTED LOCKING & ATOMIC COMMIT (via BankingEngine)
            const lockIds = [...new Set([
                intent.sourceWalletId,
                intent.targetWalletId,
                intent.metadata?.intermediate_operating_wallet,
                intent.metadata?.source_internal_vault_id,
            ].filter((id): id is string => !!id))];
            const result = await LockManager.withLock(
                lockIds, 
                async () => {
                    const txResult = await BankingEngine.process(user, { ...intent, categoryId: intent.categoryId } as any);
                    if (txResult.success && txResult.transaction) {
                        this.verifyTransaction(intent, txResult.transaction);
                    }
                    return txResult;
                }
            );

            if (!result.success || !result.transaction) {
                throw new Error(`LEDGER_COMMIT_FAILED: ${result.error}`);
            }

            const finalTx = result.transaction;
            const details = {
                transactionId: finalTx.id,
                sourceWallet: finalTx.walletId,
                destinationWallet: finalTx.toWalletId,
                transactionTimestamp: finalTx.createdAt
            };

            const responsePayload = {
                success: true,
                controlId: referenceId,
                transaction: {
                    ...finalTx,
                    id: referenceId, // Overwrite ID for frontend
                    internalId: finalTx.id, // Keep UUID
                    referenceId: referenceId,
                    toWalletId: intent.targetWalletId,
                    peerContact: intent.recipientId
                },
                details,
                breakdown: {
                    base: intent.amount,
                    tax: finalTx.tax_info?.vat || 0,
                    fee: finalTx.tax_info?.fee || 0,
                    gov_fee: finalTx.tax_info?.gov_fee || 0,
                    fx_fee: intent.metadata?.fx_details?.fee || 0,
                    exchange_rate: intent.metadata?.fx_details?.exchangeRate || 1,
                    converted_amount: intent.metadata?.fx_details?.finalAmount || intent.amount,
                    target_currency: intent.metadata?.target_currency || intent.currency,
                    total: (intent.amount) + (finalTx.tax_info?.vat || 0) + (finalTx.tax_info?.fee || 0) + (finalTx.tax_info?.gov_fee || 0),
                    available_balance: finalTx.metadata?.available_balance
                },
                status: finalTx.status || 'processing',
                metadata: {
                    security_score: report.score,
                    decision: report.decision
                }
            };

            // 6. EVENT PUBLISHING (Async Ecosystem)
            const finalStatus = String(finalTx.status || 'processing').toLowerCase();
            const lifecycleEvent =
                finalStatus === 'completed' || finalStatus === 'settled'
                    ? 'fintech.transaction.settled'
                    : 'fintech.transaction.processing';
            await EventBus.publish(lifecycleEvent as any, '/core/ledger', responsePayload);

            // 7. SAVE IDEMPOTENCY RESPONSE
            await IdempotencyLayer.saveResponse(intent.idempotencyKey, user.id, '/v2/transactions/process', 200, responsePayload);

            // 8. SEND SECURITY & THANK YOU MESSAGES (Only for non-transfers, as BankingEngine handles transfers)
            if (intent.type !== 'INTERNAL_TRANSFER' && (intent.type as any) !== 'PEER_TRANSFER') {
                const timestamp = new Date().toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', hour12: true }).toLowerCase();
                const refId = referenceId || responsePayload.transaction?.id || intent.idempotencyKey || 'N/A';
                const amountStr = typeof intent.amount === 'number' ? intent.amount.toLocaleString() : intent.amount;
                
                const sb = getAdminSupabase();
                let language = 'en';
                let userName = user.user_metadata?.full_name;
                
                if (sb) {
                    const { data: profile } = await sb.from('users').select('full_name, language').eq('id', user.id).maybeSingle();
                    if (profile) {
                        userName = profile.full_name || userName;
                        language = profile.language || 'en';
                    }
                }
                
                const isSw = language === 'sw';
                userName = userName || (isSw ? 'Mteja' : 'Customer');
                const footer = isSw 
                    ? "Asante kwa kuichagua ORBI, tunathamini imani yako. Timu ya Kifedha ya ORBI"
                    : "Thank you For choosing ORBI, We value your trust. The ORBI Financial Team";
                
                let msg = '';
                let subject = isSw ? 'Muamala Umekamilika' : 'Transaction Successful';

                if (intent.type === 'DEPOSIT') {
                    msg = isSw 
                        ? `Ndugu ${userName} umefanikiwa kupokea ${intent.currency} ${amountStr}/= kwenye akaunti yako ya ORBI saa ${timestamp}. Kumbukumbu ${refId} . ${footer}`
                        : `Dear ${userName} you have successfully received ${intent.currency} ${amountStr}/= on your ORBI account at ${timestamp}. Reference ${refId} . ${footer}`;
                } else if (intent.type === 'WITHDRAWAL') {
                    msg = isSw
                        ? `Ndugu ${userName} umefanikiwa kutoa ${intent.currency} ${amountStr}/= kutoka kwenye akaunti yako ya ORBI saa ${timestamp}. Kumbukumbu ${refId} . ${footer}`
                        : `Dear ${userName} you have successfully withdrawn ${intent.currency} ${amountStr}/= from your ORBI account at ${timestamp}. Reference ${refId} . ${footer}`;
                } else {
                    const typeLabel = isSw ? 'ombi lako' : `your ${intent.type.toLowerCase()} request`;
                    msg = isSw
                        ? `Ndugu ${userName} ${typeLabel} la ${intent.currency} ${amountStr}/= limekamilika kwa mafanikio saa ${timestamp}. Kumbukumbu ${refId} . ${footer}`
                        : `Dear ${userName} ${typeLabel} of ${intent.currency} ${amountStr}/= has been processed successfully at ${timestamp}. Reference ${refId} . ${footer}`;
                }
                
                // Message to Sender (Debit/Deposit/Withdrawal) via Push & SMS
                await Messaging.dispatch(
                    user.id, 
                    'info', 
                    subject, 
                    msg,
                    { sms: true, email: true }
                );
            }

            return responsePayload;

        } catch (error: any) {
            // Handle Failure
            const errorPayload = { success: false, error: error.message, status: 'failed', controlId: referenceId };
            
            // Determine if error is transient
            const isTransient = error.message.includes('LOCK_TIMEOUT') || 
                                error.message.includes('LEDGER_COMMIT_FAILED') || 
                                error.message.includes('LEDGER_FAULT') ||
                                error.message.includes('INFRASTRUCTURE_ERROR');
            
            if (isTransient) {
                console.warn(`[EntProcessor] Transient error encountered, clearing idempotency key for retry. Error: ${error.message}`);
                await IdempotencyLayer.clearKey(intent.idempotencyKey, user.id, '/v2/transactions/process');
            } else {
                // Save permanent errors to idempotency cache
                await IdempotencyLayer.saveResponse(intent.idempotencyKey, user.id, '/v2/transactions/process', 400, errorPayload);
            }
            return errorPayload;
        }
    }

    public async settleProcessingTransactions() {
        const { getSupabase } = await import('../../supabaseClient.js');
        const sb = getSupabase();
        if (!sb) return;

        // Find transactions in 'processing' state older than 1 minute
        const { data: transactions } = await sb
            .from('transactions')
            .select('id')
            .eq('status', 'processing')
            .lt('created_at', new Date(Date.now() - 60000).toISOString());

        if (!transactions || transactions.length === 0) return;

        console.info(`[EntProcessor Settlement] Found ${transactions.length} transactions pending settlement.`);

        for (const tx of transactions) {
            try {
                await BankingEngine.completeSettlement(tx.id);
            } catch (e: any) {
                console.error(`[EntProcessor Settlement] Failed to settle ${tx.id}: ${e.message}`);
            }
        }
    }

    private looksLocked(value?: string | null): boolean {
        if (!value) return false;
        const normalized = value.trim().toLowerCase();
        return normalized.includes('lock') ||
            normalized.includes('freeze') ||
            normalized.includes('blocked') ||
            normalized.includes('suspend');
    }

    private async assertWalletUnlocked(walletId?: string, label: string = 'wallet') {
        if (!walletId) return;
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return;

        const { data: vault } = await sb
            .from('platform_vaults')
            .select('id, status, is_locked, locked_at, lock_reason, metadata')
            .eq('id', walletId)
            .maybeSingle();

        const record = vault || (await sb
            .from('wallets')
            .select('id, status, is_locked, locked_at, lock_reason, metadata')
            .eq('id', walletId)
            .maybeSingle()).data;

        if (!record) return;

        const meta = record.metadata || {};
        const isLocked = Boolean(record.is_locked) ||
            this.looksLocked(record.status) ||
            this.looksLocked(meta.status) ||
            Boolean(meta.is_locked) ||
            Boolean(meta.isLocked) ||
            Boolean(meta.locked) ||
            Boolean(meta.is_frozen) ||
            Boolean(meta.isFrozen);

        if (isLocked) {
            const reason = record.lock_reason || meta.lock_reason || meta.lockReason || 'Wallet is locked.';
            throw new Error(`WALLET_LOCKED: ${label} wallet is locked. ${reason}`);
        }
    }

    private validateIntent(intent: EntPaymentIntent) {
        if (!intent.idempotencyKey) throw new Error("VALIDATION_ERROR: Idempotency key required.");
        if (intent.amount <= 0 || isNaN(intent.amount)) throw new Error("VALIDATION_ERROR: Invalid amount.");
        if (!intent.currency || !intent.currency.trim()) {
            throw new Error("CURRENCY_REQUIRED: Transaction currency is required.");
        }
        if (intent.sourceWalletId && intent.sourceWalletId === intent.targetWalletId) {
            throw new Error("VALIDATION_ERROR: Source and target wallets cannot be the same.");
        }
    }

    private verifyTransaction(intent: EntPaymentIntent, tx: any) {
        // Use a small epsilon for float comparison if necessary, but here we use integer amounts in TZS usually.
        if (tx.amount !== intent.amount) throw new Error(`VERIFICATION_FAILURE: Amount mismatch. Expected ${intent.amount}, got ${tx.amount}`);
        if (tx.currency !== intent.currency) throw new Error(`VERIFICATION_FAILURE: Currency mismatch. Expected ${intent.currency}, got ${tx.currency}`);
        if (tx.walletId !== intent.sourceWalletId) throw new Error(`VERIFICATION_FAILURE: Source wallet mismatch. Expected ${intent.sourceWalletId}, got ${tx.walletId}`);
        if (tx.toWalletId !== intent.targetWalletId) throw new Error(`VERIFICATION_FAILURE: Target wallet mismatch. Expected ${intent.targetWalletId}, got ${tx.toWalletId}`);
    }
}

export const EntProcessor = new EnterprisePaymentProcessor();
