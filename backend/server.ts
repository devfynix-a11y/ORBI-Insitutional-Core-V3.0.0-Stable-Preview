
import { getSupabase, getAdminSupabase } from './supabaseClient.js';
import { AuthService } from '../iam/authService.js';
import { OrbiAuthService } from '../iam/orbiAuthService.js';
import { KeycloakAuthService } from '../iam/keycloakAuthService.js';
import { TransactionService } from '../ledger/transactionService.js';
import { WalletService } from '../wealth/walletService.js';
import { GoalService } from '../strategy/goalService.js';
import { CategoryService } from '../strategy/categoryService.js';
import { TaskService } from '../strategy/taskService.js';
import { Audit } from './security/audit.js';
import { 
    AppData, Transaction, Wallet, Goal, StaffMember, UserRole, 
    FinancialOverview, ForensicReport, DisputeCase, PricingRule, 
    RegisteredApp, SystemMessage, UserMessage, UserActivity, 
    SupportTicket, RegulatoryConfig 
} from '../types.js';
import { SecurityService } from '../iam/securityService.js';
import { RegulatoryService } from '../ledger/regulatoryService.js';
import { DisputeService } from '../ledger/disputeService.js';
import { EscrowService } from '../ledger/escrowService.js';
import { RevenueService } from '../wealth/revenueService.js';
import { InfraPersistence } from './persistence/infraPersistence.js';
import { AssetLifecycle } from './features/AssetLifecycle.js';
import { Sentinel } from './security/sentinel.js';
import { ConfigClient } from './infrastructure/RulesConfigClient.js';
import { DEFAULT_INSTITUTIONAL_APP_ORIGIN } from './config/appIdentity.js';
import { CONFIG } from '../services/config.js';
import { FinancialLogic } from '../services/financialLogic.js';
import { VaultAuditor } from './security/vaultAuditor.js';
import { Messaging } from './features/MessagingService.js';
import { orbiTalkGatewayService } from './infrastructure/orbiTalkGatewayService.js';
import { ReconEngine } from './ledger/reconciliationService.js';
import { OTPService } from './security/otpService.js';
import { InternalBroker } from '../BROKER/index.js';
import { UUID, IdentityGenerator } from '../services/utils.js';
// emailService removed as per user request.

import { SystemPilot } from './infrastructure/AutonomousCore.js';
import { HealthMonitor } from './infrastructure/HealthMonitor.js';
import { DataVault } from './security/encryption.js';
import { ProviderAnomalyTracker } from './security/ProviderAnomalyTracker.js';
import { Identity } from '../iam/identityService.js';
import { KYCService } from '../iam/kycService.js';
import { DeviceService } from '../iam/deviceService.js';
import { DocumentService } from '../iam/documentService.js';
import { Merchants } from '../wealth/merchantService.js';
import { MerchantAccounts } from './wealth/merchantAccountService.js';
import { FinancialCore } from './core/FinancialCoreEngine.js';
import { SettlementEngine } from './core/SettlementEngine.js';
import { EntProcessor } from './enterprise/wealth/EnterprisePaymentProcessor.js';
import { Treasury } from './enterprise/treasuryService.js';
import { RiskComplianceEngine } from './security/RiskComplianceEngine.js';
import { PartnerRegistry } from './admin/partnerRegistry.js';
import { ServiceActorOps } from './features/ServiceActorOps.js';
import { institutionalFundsService } from './payments/InstitutionalFundsService.js';
import { platformFeeService } from './payments/PlatformFeeService.js';
import { listRegistryBackedBillProviders } from './payments/billProviderRegistry.js';
import { transactionQuoteService } from './payments/TransactionQuoteService.js';
import { offlineGatewayService } from './offline/OfflineGatewayService.js';
import { buildPostgrestOrFilter } from './security/postgrest.js';
import { canAccessOrganizationResource } from './security/ecosystemAuthorization.js';
import bcrypt from 'bcryptjs';
import { getOrbiDatabase } from '../services/orbiDatabase.js';

const internalBackgroundJobsEnabled =
    process.env.ORBI_ENABLE_INTERNAL_BACKGROUND_JOBS === 'true';

class OrbiServer {
// ...
    async submitKYC(userId: string, data: any) { 
        const result = await KYCService.submitKYC(userId, data); 
        // Push a task to the internal broker for background validation
        await InternalBroker.push('AI_REPORT_GEN', { userId, kycData: data });
        return result;
    }
    async getKYCStatus(userId: string) { return KYCService.getKYCStatus(userId); }
    async scanKYC(imageBuffer: Buffer, mimeType: string) { return KYCService.scanKYC(imageBuffer, mimeType); }
    async uploadKYCDocument(userId: string, file: Buffer, fileName: string, contentType: string) {
        return KYCService.uploadDocument(userId, file, fileName, contentType);
    }
    async reviewKYC(requestId: string, adminId: string, decision: any, reason?: string) { 
        const result = await KYCService.reviewKYC(requestId, adminId, decision, reason); 
        return result;
    }
    async getKYCRequests(status?: string, limit?: number, offset?: number) { return KYCService.getKYCRequests(status, limit, offset); }
    
    // --- RISK & COMPLIANCE ---
    async getPendingAMLAlerts() { return RiskComplianceEngine.getPendingAlerts(); }
    async updateAMLAlertStatus(alertId: string, status: 'INVESTIGATING' | 'CLEARED' | 'BLOCKED') { return RiskComplianceEngine.updateAlertStatus(alertId, status); }
    async generateRegulatoryReport(startDate: string, endDate: string) { return RiskComplianceEngine.generateRegulatoryReport(startDate, endDate); }

    // --- DEVICES ---
    async registerDevice(userId: string, data: any) { return DeviceService.registerDevice(userId, data); }
    async getUserDevices(userId: string) { return DeviceService.getUserDevices(userId); }
    async removeDevice(userId: string, deviceId: string) { return DeviceService.removeDevice(userId, deviceId); }
    async getAllDevices(limit?: number, offset?: number) { return DeviceService.getAllDevices(limit, offset); }
    async updateDeviceStatus(deviceId: string, data: any) { return DeviceService.updateDeviceStatus(deviceId, data); }

    // --- DOCUMENTS ---
    async uploadDocument(userId: string, data: any) { return DocumentService.uploadDocument(userId, data); }
    async getUserDocuments(userId: string) { return DocumentService.getUserDocuments(userId); }
    async removeDocument(userId: string, documentId: string) { return DocumentService.removeDocument(userId, documentId); }
    async getAllDocuments(limit?: number, offset?: number) { return DocumentService.getAllDocuments(limit, offset); }
    async verifyDocument(documentId: string, adminId: string, data: any) { return DocumentService.verifyDocument(documentId, adminId, data); }

    constructor() {
        // Start Autonomous Systems
        SystemPilot.start();
        HealthMonitor.start();

        // Start External Broker Listener (Worker Mode)
        // Note: InternalBroker now handles its own internal polling and heartbeat.

        // Start Background Jobs only when this process is explicitly promoted to
        // a worker role. The gateway runtime already runs its own scheduler.
        if (internalBackgroundJobsEnabled) {
            let backgroundJobRunning = false;
            setInterval(async () => {
                if (backgroundJobRunning) {
                    return;
                }
                backgroundJobRunning = true;
                try {
                    await ReconEngine.reapStuckTransactions();
                    await EntProcessor.settleProcessingTransactions();
                    await Treasury.sweepAllOrganizations();
                    await ReconEngine.escalateOverdueExceptions();
                } catch (e) {
                    console.error("[BackgroundJob] Cycle failed:", e);
                } finally {
                    backgroundJobRunning = false;
                }
            }, CONFIG.BACKGROUND_JOB_INTERVAL); // Run every configured interval
        }
    }

    async warmup() {
        console.info("[OrbiServer] Warming up critical services...");
        // Startup must never mutate financial state. Settlement and reconciliation
        // are owned by the explicitly enabled worker schedulers after readiness.
        SystemPilot.start();
        console.info("[OrbiServer] Critical services warmed up.");
    }
    private auth = new AuthService();
    private orbiAuth = new OrbiAuthService();
    private keycloakAuth = new KeycloakAuthService();
    private authProvider = String(process.env.ORBI_AUTH_PROVIDER || 'supabase').trim().toLowerCase();
    private ledger = new TransactionService();
    private wallet = new WalletService();
    private goal = new GoalService();
    private category = new CategoryService();
    private task = new TaskService();
    private security = new SecurityService();
    private escrow = new EscrowService();

    // --- IAM & IDENTITY ---
    async login(e: string | undefined, p: string, metadata?: any) {
        if (this.authProvider === 'keycloak') return this.keycloakAuth.login(e || '', p, metadata);
        if (this.authProvider === 'local') return this.orbiAuth.login(e || '', p, metadata);
        return this.auth.login(e || '', p, metadata);
    }
    async signUp(email: string | undefined, password: string, metadata?: any, appId?: string) { 
        const signupMetadata = { ...metadata, app_origin: metadata?.app_origin || appId };
        if (this.authProvider === 'keycloak') return this.keycloakAuth.signUp(email || '', password, signupMetadata);
        if (this.authProvider === 'local') return this.orbiAuth.signUp(email || '', password, signupMetadata);
        return this.auth.signUp(email || '', password, signupMetadata);
    }
    async getSession(token?: string) {
        if (this.authProvider === 'keycloak') return this.keycloakAuth.getSession(token);
        if (this.authProvider === 'local') return this.orbiAuth.getSession(token);
        return this.auth.getSession(token);
    }
    async refreshSession(refreshToken: string, metadata?: any) {
        if (this.authProvider === 'keycloak') return this.keycloakAuth.refreshSession(refreshToken, metadata);
        if (this.authProvider === 'local') return this.orbiAuth.refreshSession(refreshToken, metadata);
        return this.auth.refreshSession(refreshToken, metadata);
    }
    async logout(token?: string, refreshToken?: string) {
        if (this.authProvider === 'keycloak') return this.keycloakAuth.logout(token, refreshToken);
        if (this.authProvider === 'local') return this.orbiAuth.logout(token, refreshToken);
        return this.auth.logout(token, refreshToken);
    }
    async lookupUser(query: string) { return Identity.lookupUser(query); }
    
    async updatePassword(password: string) { return this.auth.updatePassword(password); }
    async completePasswordReset(password: string) { return this.auth.completePasswordReset(password); }
    async completePasswordResetWithOtp(identifier: string, requestId: string, code: string, password: string) {
        if (this.authProvider === 'keycloak') {
            return this.keycloakAuth.completePasswordReset(password, identifier, requestId, code);
        }
        return this.auth.completePasswordReset(password, identifier, requestId, code);
    }
    async initiatePasswordReset(identifier: string) {
        if (this.authProvider === 'keycloak') return this.keycloakAuth.initiatePasswordReset(identifier);
        return this.auth.initiatePasswordReset(identifier);
    }
    async initiateAccountConfirmation(identifier: string, replacementContact?: string, preferredRegistryType?: string) {
        if (this.authProvider === 'keycloak') {
            return this.keycloakAuth.initiateAccountConfirmation(identifier, replacementContact);
        }
        return this.auth.initiateAccountConfirmation(identifier, replacementContact, preferredRegistryType);
    }
    async confirmAccount(identifier: string, requestId: string, code: string, preferredRegistryType?: string) {
        if (this.authProvider === 'keycloak') {
            return this.keycloakAuth.confirmAccount(identifier, requestId, code);
        }
        return this.auth.confirmAccount(identifier, requestId, code, preferredRegistryType);
    }
    async cleanupExpiredUnconfirmedAccounts() { return this.auth.cleanupExpiredUnconfirmedAccounts(); }
    async deleteAccount() { return this.auth.deleteAccount(); }
    async initiatePhoneLogin(phone: string) { return this.auth.initiatePhoneLogin(phone); }
    async verifyPhoneLogin(phone: string, token: string) { return this.auth.verifyPhoneLogin(phone, token); }
    async completeProfile(phone: string, updates: any) { return this.auth.completeProfile(phone, updates); }
    async getUserProfile(userId: string) {
        if (this.authProvider === 'keycloak') return this.keycloakAuth.getUserProfile(userId);
        if (this.authProvider === 'local') return this.orbiAuth.getUserProfile(userId);
        return this.auth.getUserProfile(userId);
    }
    async registerBiometric(userId: string, credential: any) { return this.auth.registerBiometric(userId, credential); }
    async generateSecureConnection(token?: string) { return { status: 'SECURE', node: 'DPS-PRIMARY-RELAY', ts: Date.now() }; }

    // --- DIAGNOSTICS ---
    async testEmail(to: string) {
        console.info(`[OrbiServer] Email test requested for ${to} via ORBI Talk Gateway.`);
        const success = await orbiTalkGatewayService.sendEmail(
            to,
            'ORBI Talk Gateway Test',
            'This is a test email from the ORBI Sovereign Node via ORBI Talk Gateway.',
            undefined,
            'en',
            undefined,
            undefined,
            `test-${Date.now()}`
        );
        return { success };
    }

    async verifyEmailConfig() {
        console.info(`[OrbiServer] Email config verification via ORBI Talk Gateway.`);
        return orbiTalkGatewayService.getEmailHealth();
    }

    // --- SENSITIVE ACTIONS & OTP ---
    async initiateSensitiveAction(userId: string, contact: string, action: string, type?: 'sms' | 'email' | 'push' | 'whatsapp', deviceName: string = 'Unknown Device') {
        const resolvedType = type || (contact.includes('@') ? 'email' : 'sms');
        const result = await OTPService.generateAndSend(userId, contact, action, resolvedType, deviceName);
        if (result.requestId === 'ERROR_NO_CONTACT') {
            throw new Error("No contact method provided for verification.");
        }
        if (result.requestId === 'THROTTLED') {
            throw new Error("Too many requests. Please wait 60 seconds.");
        }
        return result;
    }

    async verifySensitiveAction(requestId: string, code: string, userId: string) {
        const isValid = await OTPService.verify(requestId, code, userId);
        if (isValid) {
            await this.security.logActivity(userId, 'SENSITIVE_ACTION_VERIFIED', 'success', `Action verified via OTP`);
            return { success: true };
        }
        await this.security.logActivity(userId, 'SENSITIVE_ACTION_FAILED', 'failure', `OTP verification failed`);
        return { success: false, error: 'INVALID_OTP' };
    }

    // --- BOOTSTRAP ---
    async getBootstrapData(
        token?: string,
        prefetchedTransactions?: Promise<any> | any
    ): Promise<AppData> {
        const session = await this.getSession(token);
        if (!session) throw new Error("IDENTITY_REQUIRED");

        // Recent ledger history is useful, but it must never hold the entire
        // application bootstrap hostage. The dedicated transactions endpoint
        // continues loading the full history after the shell is visible.
        const transactionSource = prefetchedTransactions === undefined
            ? this.ledger.getMobileTransactions(session.sub, 20, 0)
            : Promise.resolve(prefetchedTransactions);
        let transactionTimer: NodeJS.Timeout | undefined;
        const boundedTransactions = Promise.race<any[]>([
            transactionSource,
            new Promise<any[]>((resolve) => {
                transactionTimer = setTimeout(() => resolve([]), 1500);
            }),
        ]).finally(() => {
            if (transactionTimer) clearTimeout(transactionTimer);
        });
        
        const [transactions, wallets, goals, categories, tasks, messages] = await Promise.all([
            boundedTransactions,
            this.wallet.fetchForUser(session.sub),
            this.goal.fetchForUser(session.sub, token || session.access_token),
            this.category.fetchForUser(session.sub),
            this.task.fetchForUser(session.sub),
            this.getUserMessages(session.sub)
        ]);

        return {
            transactions,
            wallets,
            financialGoals: goals,
            categories,
            tasks,
            userProfile: {
                ...session.user.user_metadata,
                kyc_status: session.user.user_metadata?.kyc_status || 'unverified',
                first_name: session.user.user_metadata?.full_name?.split(' ')[0] || 'Customer'
            },
            goalAllocations: [],
            messages,
            systemMessages: await this.getSystemMessages()
        };
    }

    // --- PAGINATED LEDGER ---
    async getTransactionsPaginated(userId: string, limit: number, offset: number) {
        return this.ledger.getMobileTransactions(userId, limit, offset);
    }

    async getTransactionForUser(userId: string, transactionId: string) {
        return this.ledger.getTransactionForUser(userId, transactionId);
    }

    async requestTransactionRecall(userId: string, txId: string, reason: string) {
        return this.ledger.lockTransactionForReview(txId, userId, {
            actorRole: 'USER',
            reason,
            requestReverse: true,
            userLock: true,
            reviewWindowHours: 24,
        });
    }

    async lockTransactionForAdmin(actorId: string, txId: string, reason: string) {
        return this.ledger.lockTransactionForReview(txId, actorId, {
            actorRole: 'STAFF',
            reason,
            requestReverse: false,
            userLock: false,
            reviewWindowHours: 24,
        });
    }

    async reverseTransactionForAdmin(actorId: string, txId: string, reason: string) {
        return this.ledger.reverseTransactionWithReason(txId, actorId, reason, 'STAFF');
    }

    async recordTransactionAuditDecision(actorId: string, txId: string, passed: boolean, notes: string) {
        return this.ledger.recordAuditDecision(txId, actorId, passed, notes, 'STAFF');
    }

    async approveReviewedTransaction(actorId: string, txId: string, notes: string) {
        return this.ledger.approveReviewedTransaction(txId, actorId, notes);
    }

    async approveAllAuditPassedTransactions(actorId: string, notes: string) {
        return this.ledger.approveAllAuditPassedTransactions(actorId, notes);
    }

    // --- TRANSACTION PREVIEW ---
    async getTransactionPreview(userId: string, payload: any) {
        return transactionQuoteService.quote({ userId, payload });
    }

    async bindSettlementQuote(userId: string, payload: any, idempotencyKey: string) {
        return transactionQuoteService.bindSettlementQuote({ userId, payload, idempotencyKey });
    }

    async markSettlementQuoteResult(userId: string, quoteId: string | null | undefined, result: any) {
        return transactionQuoteService.markQuoteSettlementResult({ userId, quoteId, result });
    }

    // --- WEALTH & SETTLEMENT ---
    async calculateSettlementBreakdown(payload: any) {
        throw new Error('SETTLEMENT_BREAKDOWN_PROVIDER_NOT_CONFIGURED');
    }

    async processSecurePayment(payload: any, user?: any, serverFxQuote?: Record<string, unknown>) {
        const sessionUser = user || (await this.auth.getSession())?.user;
        if (!sessionUser) throw new Error("IDENTITY_REQUIRED");
        const requestCurrency = typeof payload?.currency === 'string'
            ? payload.currency.trim().toUpperCase()
            : '';
        if (!requestCurrency) {
            throw new Error("CURRENCY_REQUIRED: Secure payment requires an explicit currency.");
        }
        
        const result = await EntProcessor.process(sessionUser as any, {
            idempotencyKey: payload.idempotencyKey || `tx-${Date.now()}-${UUID.generate()}`,
            referenceId: payload.referenceId,
            sourceWalletId: payload.sourceWalletId,
            targetWalletId: payload.targetWalletId,
            recipientId: payload.recipientId,
            recipient_customer_id: payload.recipient_customer_id,
            amount: payload.amount,
            currency: requestCurrency,
            description: payload.description || 'Secure Payment',
            type: payload.type || 'INTERNAL_TRANSFER',
            walletType: payload.walletType,
            category: payload.category,
            categoryId: payload.categoryId,
            metadata: payload.metadata
        } as any, serverFxQuote);

        if (result?.success && result.transaction) {
            await ServiceActorOps.handleTransactionPosted(sessionUser, payload, result.transaction);

            const sourceTransactionId = String(result.transaction.internalId || result.transaction.id || '');
            const normalizedType = String(payload?.type || '').trim().toUpperCase();
            const cashDirection = String(payload?.metadata?.cash_direction || '').trim().toLowerCase();
            const triggerType =
                normalizedType === 'SALARY'
                    ? 'SALARY'
                    : normalizedType === 'DEPOSIT' && cashDirection === 'deposit'
                        ? 'AGENT_CASH_DEPOSIT'
                        : normalizedType === 'DEPOSIT'
                            ? 'DEPOSIT'
                            : null;

            if (sourceTransactionId && triggerType) {
                try {
                    await this.goal.runAutoAllocationsForCredit({
                        userId: String(sessionUser.id),
                        sourceTransactionId,
                        sourceReferenceId: result.transaction.referenceId || result.transaction.id || null,
                        sourceWalletId: result.transaction.toWalletId || payload?.targetWalletId || null,
                        sourceAmount: Number(payload?.amount || result.transaction.amount || 0),
                        currency: payload?.currency || result.transaction.currency || null,
                        triggerType,
                        metadata: {
                            source: 'secure_payment',
                            payment_type: normalizedType,
                            service_context: payload?.metadata?.service_context || null,
                        },
                    });
                } catch (autoAllocationError: any) {
                    console.error('[GoalAutoAllocation] Secure payment trigger failed:', autoAllocationError?.message || autoAllocationError);
                }
            }
        }

        return result;
    }

    async postWallet(p: any) { 
        const session = await this.auth.getSession();
        if (!session) throw new Error("IDENTITY_REQUIRED");
        return this.wallet.createLinkedWallet(p.userId || session.sub, p); 
    }
    
    async updateWallet(p: any) { return this.wallet.updateWallet(p.id, p); }
    async getWallets(uid: string) { return this.wallet.fetchForUser(uid); }
    async deleteWallet(userId: string, id: string) {
        return this.wallet.deleteWallet(id, 'linked', userId);
    }

    private async verifyTransactionPin(userId: string, pin?: string): Promise<boolean> {
        if (!pin || !pin.trim()) return false;
        const sb = getAdminSupabase();
        if (!sb) throw new Error('DB_OFFLINE');
        const { data: profile } = await sb
            .from('users')
            .select('security_tx_pin_hash, security_tx_pin_enabled')
            .eq('id', userId)
            .maybeSingle();
        if (!profile?.security_tx_pin_enabled || !profile.security_tx_pin_hash) {
            throw new Error('PIN_NOT_SET');
        }
        const hash = String(profile.security_tx_pin_hash || '');
        if (hash.startsWith('$2')) {
            return await bcrypt.compare(pin.trim(), hash);
        }
        return pin.trim() === hash;
    }

    private async resolveWalletRecord(walletId: string) {
        const sb = getAdminSupabase();
        if (!sb) throw new Error('DB_OFFLINE');
        const { data: vault } = await sb
            .from('platform_vaults')
            .select('id, user_id, status, is_locked, locked_at, lock_reason, metadata')
            .eq('id', walletId)
            .maybeSingle();
        if (vault) return { table: 'platform_vaults', record: vault };

        const { data: wallet } = await sb
            .from('wallets')
            .select('id, user_id, status, is_locked, locked_at, lock_reason, metadata')
            .eq('id', walletId)
            .maybeSingle();
        if (wallet) return { table: 'wallets', record: wallet };
        return null;
    }

    private isHardBlockedStatus(status?: string | null) {
        if (!status) return false;
        return status.trim().toLowerCase() === 'blocked';
    }

    private shouldForceUnlockStatus(status?: string | null) {
        if (!status) return false;
        const normalized = status.trim().toLowerCase();
        return ['locked', 'frozen', 'suspended', 'blocked'].includes(normalized);
    }

    async lockWallet(
        actorUserId: string,
        walletId: string,
        opts: { reason?: string; pin?: string; force?: boolean; isAdmin?: boolean } = {}
    ) {
        const sb = getAdminSupabase();
        if (!sb) throw new Error('DB_OFFLINE');

        const resolved = await this.resolveWalletRecord(walletId);
        if (!resolved) throw new Error('WALLET_NOT_FOUND');

        const { table, record } = resolved;
        const isOwner = record.user_id === actorUserId;
        if (!opts.isAdmin && !isOwner) throw new Error('ACCESS_DENIED');

        if (!opts.isAdmin && opts.pin) {
            const ok = await this.verifyTransactionPin(actorUserId, opts.pin);
            if (!ok) throw new Error('INVALID_PIN');
        }

        const reason = opts.reason || (opts.isAdmin ? 'Admin lock' : 'User lock');
        const lockedAt = new Date().toISOString();
        const metadata = record.metadata && typeof record.metadata === 'object' ? record.metadata : {};
        const updatePayload: any = {
            is_locked: true,
            status: 'locked',
            locked_at: lockedAt,
            lock_reason: reason,
            metadata: {
                ...metadata,
                last_lock_reason: reason,
                last_lock_at: lockedAt,
                last_lock_by: actorUserId,
                last_lock_source: opts.isAdmin ? 'admin' : 'user',
            },
        };

        const { error } = await sb.from(table).update(updatePayload).eq('id', record.id);
        if (error) throw error;

        return { ...record, ...updatePayload, table };
    }

    async unlockWallet(
        actorUserId: string,
        walletId: string,
        opts: { reason?: string; pin?: string; force?: boolean; isAdmin?: boolean } = {}
    ) {
        const sb = getAdminSupabase();
        if (!sb) throw new Error('DB_OFFLINE');

        const resolved = await this.resolveWalletRecord(walletId);
        if (!resolved) throw new Error('WALLET_NOT_FOUND');

        const { table, record } = resolved;
        const isOwner = record.user_id === actorUserId;
        if (!opts.isAdmin && !isOwner) throw new Error('ACCESS_DENIED');

        if (!opts.isAdmin) {
            const ok = await this.verifyTransactionPin(actorUserId, opts.pin);
            if (!ok) throw new Error('INVALID_PIN');
            if (this.isHardBlockedStatus(record.status)) {
                throw new Error('WALLET_BLOCKED');
            }
        }

        const nextStatus = (opts.isAdmin || this.shouldForceUnlockStatus(record.status))
            ? 'active'
            : record.status;
        const unlockedAt = new Date().toISOString();
        const unlockReason = opts.reason || (opts.isAdmin ? 'Admin unlock' : 'User unlock');
        const metadata = record.metadata && typeof record.metadata === 'object' ? record.metadata : {};
        const lockHistory = Array.isArray(metadata.lock_history) ? metadata.lock_history : [];
        const updatePayload: any = {
            is_locked: false,
            status: nextStatus,
            locked_at: null,
            lock_reason: null,
            metadata: {
                ...metadata,
                last_unlock_reason: unlockReason,
                last_unlock_at: unlockedAt,
                last_unlock_by: actorUserId,
                lock_history: [
                    ...lockHistory.slice(-24),
                    {
                        locked_at: record.locked_at || null,
                        lock_reason: record.lock_reason || null,
                        unlocked_at: unlockedAt,
                        unlock_reason: unlockReason,
                        unlocked_by: actorUserId,
                        previous_status: record.status || null,
                        next_status: nextStatus,
                    },
                ],
            },
        };

        const { error } = await sb.from(table).update(updatePayload).eq('id', record.id);
        if (error) throw error;

        return { ...record, ...updatePayload, table };
    }

    // --- ESCROW & TRUSTLESS COMMERCE ---
    async createEscrow(userId: string, recipientCustomerId: string, amount: number, description: string, conditions: any) {
        return this.escrow.createEscrow(userId, recipientCustomerId, amount, description, conditions);
    }
    async getEscrows(userId: string) {
        return this.escrow.getEscrows(userId);
    }
    async getEscrow(referenceId: string, actorId: string) {
        return this.escrow.getEscrow(referenceId, actorId);
    }
    async releaseEscrow(referenceId: string, actorId: string) {
        return this.escrow.releaseEscrow(referenceId, actorId);
    }
    async acceptEscrow(referenceId: string, actorId: string) {
        return this.escrow.acceptEscrow(referenceId, actorId);
    }
    async disputeEscrow(referenceId: string, userId: string, reason: string) {
        return this.escrow.disputeEscrow(referenceId, userId, reason);
    }
    async refundEscrow(referenceId: string, actorId: string, reason?: string) {
        return this.escrow.refundEscrow(referenceId, actorId, reason);
    }

    // --- RECONCILIATION ---
    async triggerManualRecon(providerId: string) {
        return ReconEngine.runDailyRecon(providerId);
    }

    // --- STRATEGY & PLANNING ---
    async postGoal(p: any, token?: string) { return this.goal.postGoal(p, token); }
    async updateGoal(p: any, token?: string) { return this.goal.updateGoal(p, token); }
    async allocateToGoal(goalId: string, amount: number, walletId: string, token?: string) {
        return this.goal.allocateFunds(goalId, amount, walletId, token);
    }
    async runGoalAutoAllocationsForCredit(payload: {
        userId: string;
        sourceTransactionId: string;
        sourceReferenceId?: string | null;
        sourceWalletId?: string | null;
        sourceAmount: number;
        currency?: string | null;
        triggerType: string;
        metadata?: Record<string, any>;
    }) {
        return this.goal.runAutoAllocationsForCredit(payload);
    }
    async replayGoalAutoAllocations(userId: string, sourceTransactionId: string, token?: string) {
        return this.goal.replayAutoAllocationsForTransaction(userId, sourceTransactionId, token);
    }
    async withdrawFromGoal(goalId: string, amount: number, walletId: string, verification?: any, token?: string) {
        return this.goal.withdrawFunds(goalId, amount, walletId, verification, token);
    }
    async deleteGoal(id: string, token?: string) { return this.goal.deleteGoal(id, token); }
    async getGoals(userId: string, token?: string) { return this.goal.fetchForUser(userId, token); }
    async postCategory(p: any, token?: string) { return this.category.postCategory(p, token); }
    async getCategories(userId: string, token?: string) { return this.category.fetchForUser(userId, token); }
    async updateCategory(p: any, token?: string) { return this.category.updateCategory(p, token); }
    async deleteCategory(id: string, token?: string) { return this.category.deleteCategory(id, token); }
    async postTask(p: any) { return this.task.postTask(p); }
    async getTasks(userId: string) { return this.task.fetchForUser(userId); }
    async updateTask(p: any) { return this.task.updateTask(p); }
    async deleteTask(id: string) { return this.task.deleteTask(id); }

    // --- INFRASTRUCTURE & METRICS ---
    async testConnection() { return { status: 'ONLINE', ts: Date.now() }; }
    async getSystemMetrics() {
        return { throughput: '4.2k TPS', uptime: '99.999%', active_nodes: 12, health: 'OPTIMAL' };
    }
    async persistInfraSnapshot(snapshot: any) { return InfraPersistence.saveSnapshot(snapshot.actorId || 'system', snapshot); }
    async getApps() { return RegulatoryService.getApps(); }
    async registerApp(name: string, tier: string) { return RegulatoryService.registerApp(name, tier); }
    async verifyAppNode(id: string, token: string) { return RegulatoryService.verifyAppNode(id, token); }

    // --- GOVERNANCE & STAFF ---
    async getAllStaff(): Promise<StaffMember[]> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return [];
        const { data } = await sb.from('staff').select('*').order('created_at', { ascending: false });
        return (data || []).map((staff: any) => ({
            ...staff,
            effective_permissions: this.auth.describePermissionsForRole(
                String(staff.role || 'USER').toUpperCase() as any,
                String(staff.account_status || 'active').toLowerCase(),
            ),
        }));
    }
    async getAllConsumers(): Promise<any[]> {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return [];
        const { data } = await sb.from('users').select('*');
        return data || [];
    }
    async getBootstrapState() {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return { staffCount: 0, bootstrapRequired: true };
        const timeoutMs = Number(process.env.ORBI_BOOTSTRAP_STATE_TIMEOUT_MS || 3500);
        const timeout = new Promise<never>((_, reject) => {
            setTimeout(() => reject(new Error('BOOTSTRAP_STATE_TIMEOUT')), Number.isFinite(timeoutMs) ? timeoutMs : 3500);
        });
        const { count } = await Promise.race([
            sb.from('staff').select('id', { count: 'exact', head: true }),
            timeout,
        ]);
        const staffCount = count || 0;
        return {
            staffCount,
            bootstrapRequired: staffCount === 0
        };
    }
    async createStaff(payload: any, actorId: string) {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return { error: 'DB_OFFLINE' };

        const normalizedOrigin = String(payload?.app_origin || DEFAULT_INSTITUTIONAL_APP_ORIGIN).trim();
        const normalizedRole = String(payload?.role || 'ADMIN').trim().toUpperCase();
        const normalizedLanguage = String(payload?.language || 'en').trim().toLowerCase() || 'en';
        const normalizedEmail = String(payload?.email || '').trim().toLowerCase();

        if (!normalizedEmail) {
            return { error: 'EMAIL_REQUIRED' };
        }

        const { data: existingUserEmail } = await sb
            .from('users')
            .select('id')
            .ilike('email', normalizedEmail)
            .maybeSingle();
        if (existingUserEmail) {
            return { error: 'IDENTITY_REGISTRY_CONFLICT: This email is already registered as a consumer/mobile identity.' };
        }

        const { data: existingStaffEmail } = await sb
            .from('staff')
            .select('id')
            .ilike('email', normalizedEmail)
            .maybeSingle();
        if (existingStaffEmail) {
            return { error: 'ACCOUNT_ALREADY_EXISTS: This email is already linked to a staff identity.' };
        }

        if (payload?.phone) {
            const { data: existingUser } = await sb
                .from('users')
                .select('id')
                .eq('phone', payload.phone)
                .maybeSingle();
            if (existingUser) {
                return { error: 'PHONE_ALREADY_IN_USE: This phone number is already linked to another account.' };
            }

            const { data: existingStaff } = await sb
                .from('staff')
                .select('id')
                .eq('phone', payload.phone)
                .maybeSingle();
            if (existingStaff) {
                return { error: 'PHONE_ALREADY_IN_USE: This phone number is already linked to another account.' };
            }
        }
        
        // 1. Create Auth User
        const { data: authData, error: authError } = await sb.auth.admin.createUser({
            email: normalizedEmail,
            password: payload.password,
            user_metadata: {
                full_name: payload.full_name,
                role: normalizedRole,
                registry_type: 'STAFF',
                account_status: 'active',
                app_origin: normalizedOrigin,
                language: normalizedLanguage
            },
            email_confirm: true
        });

        if (authError) return { error: authError.message };
        if (!authData.user) return { error: 'USER_CREATION_FAILED' };

        // 2. Create Staff Profile
        const { error: profileError } = await sb.from('staff').insert({
            id: authData.user.id,
            email: normalizedEmail,
            full_name: payload.full_name,
            role: normalizedRole,
            phone: payload.phone,
            nationality: payload.nationality,
            avatar_url: payload.avatar_url,
            address: payload.address,
            language: normalizedLanguage,
            account_status: 'active',
            customer_id: IdentityGenerator.generateCustomerID('STF')
        });

        if (profileError) {
            // Rollback auth user
            await sb.auth.admin.deleteUser(authData.user.id);
            return { error: profileError.message };
        }

        await this.security.logActivity(actorId, 'STAFF_CREATION', 'success', `Created staff member ${payload.email} with role ${payload.role}`);
        return { success: true, data: { id: authData.user.id } };
    }
    async createManagedIdentity(payload: any, actorId: string) {
        const publicRoleRegistryMap: Record<string, 'CONSUMER' | 'MERCHANT' | 'AGENT'> = {
            CONSUMER: 'CONSUMER',
            USER: 'CONSUMER',
            MERCHANT: 'MERCHANT',
            AGENT: 'AGENT',
        };
        const targetRegistryType = publicRoleRegistryMap[String(payload.role || '').toUpperCase()];
        if (targetRegistryType) {
            const result = await this.signUp(payload.email || '', payload.password, {
                full_name: payload.full_name,
                phone: payload.phone,
                nationality: payload.nationality,
                address: payload.address,
                currency: payload.currency || 'USD',
                language: payload.language || 'en',
                role: payload.role,
                registry_type: targetRegistryType,
                app_origin: DEFAULT_INSTITUTIONAL_APP_ORIGIN,
                created_via_admin_portal: true
            });
            if (result?.error) return { error: result.error.message || result.error };
            await this.security.logActivity(
                actorId,
                'IDENTITY_CREATION',
                'success',
                `Created managed ${targetRegistryType.toLowerCase()} ${payload.email} with role ${payload.role}`,
            );
            return { success: true, data: result.data };
        }
        return this.createStaff(payload, actorId);
    }
    async bootstrapAdmin(payload: any) {
        const state = await this.getBootstrapState();
        if (!state.bootstrapRequired) {
            return { error: 'BOOTSTRAP_ALREADY_COMPLETED' };
        }
        return this.createStaff({
            ...payload,
            role: 'SUPER_ADMIN'
        }, 'bootstrap-admin');
    }

    async adminUpdateStaffProfile(staffId: string, updates: any, actorId: string) {
        const sb = getAdminSupabase();
        if (!sb) return { error: 'DB_OFFLINE' };

        const { data: authUserResult, error: authUserError } = await sb.auth.admin.getUserById(staffId);
        if (authUserError || !authUserResult?.user) {
            return { error: authUserError?.message || 'STAFF_NOT_FOUND' };
        }

        const currentMetadata = authUserResult.user.user_metadata || {};
        const metadataUpdates: Record<string, unknown> = { ...currentMetadata };
        const staffUpdates: Record<string, unknown> = {};

        const assignField = (key: string) => {
            if (updates[key] !== undefined) {
                metadataUpdates[key] = updates[key];
                staffUpdates[key] = updates[key];
            }
        };

        assignField('full_name');
        assignField('phone');
        assignField('nationality');
        assignField('address');
        assignField('language');
        assignField('avatar_url');

        if (updates.role !== undefined) {
            metadataUpdates.role = String(updates.role).trim().toUpperCase();
            staffUpdates.role = String(updates.role).trim().toUpperCase();
        }

        if (updates.account_status !== undefined) {
            const normalizedStatus = String(updates.account_status).trim().toLowerCase();
            const statusReason = String(updates.status_reason || updates.reason || `Staff status changed to ${normalizedStatus}`).trim();
            const reasonCode = String(updates.status_reason_code || 'STAFF_STATUS_UPDATE').trim().toUpperCase();
            const changedAt = new Date().toISOString();
            metadataUpdates.account_status = normalizedStatus;
            metadataUpdates.status_reason = statusReason;
            metadataUpdates.status_reason_code = reasonCode;
            metadataUpdates.status_changed_at = changedAt;
            metadataUpdates.status_changed_by = actorId;
            staffUpdates.account_status = normalizedStatus;
            staffUpdates.status_reason = statusReason;
            staffUpdates.status_reason_code = reasonCode;
            staffUpdates.status_changed_at = changedAt;
            staffUpdates.status_changed_by = actorId;
        }

        const { error: authUpdateError } = await sb.auth.admin.updateUserById(staffId, {
            user_metadata: metadataUpdates,
        });
        if (authUpdateError) {
            return { error: authUpdateError.message };
        }

        if (Object.keys(staffUpdates).length > 0) {
            const { error: staffError } = await sb
                .from('staff')
                .update(staffUpdates)
                .eq('id', staffId);
            if (staffError) {
                return { error: staffError.message };
            }
        }

        await this.security.logActivity(actorId, 'STAFF_PROFILE_UPDATE', 'success', `Updated staff ${staffId}`);
        return { success: true };
    }

    async adminResetStaffPassword(staffId: string, password: string, actorId: string) {
        const sb = getAdminSupabase();
        if (!sb) return { error: 'DB_OFFLINE' };

        const { error } = await sb.auth.admin.updateUserById(staffId, { password });
        if (error) {
            return { error: error.message };
        }

        await this.security.logActivity(actorId, 'STAFF_PASSWORD_RESET', 'success', `Reset password for staff ${staffId}`);
        return { success: true };
    }

    async adminUpdateUserProfile(targetUserId: string, updates: any, actorId: string) {
        const sb = getAdminSupabase();
        if (!sb) return { error: 'DB_OFFLINE' };

        // 1. Get current metadata to merge
        const { data: user, error: getError } = await sb.auth.admin.getUserById(targetUserId);
        const currentMetadata = user?.user?.user_metadata || {};
        const profileUpdates = { ...updates };
        if (profileUpdates.account_status !== undefined) {
            const normalizedStatus = String(profileUpdates.account_status).trim().toLowerCase();
            const statusReason = String(profileUpdates.status_reason || profileUpdates.reason || `User status changed to ${normalizedStatus}`).trim();
            profileUpdates.account_status = normalizedStatus;
            profileUpdates.status_reason = statusReason;
            profileUpdates.status_reason_code = String(profileUpdates.status_reason_code || 'USER_STATUS_UPDATE').trim().toUpperCase();
            profileUpdates.status_changed_at = new Date().toISOString();
            profileUpdates.status_changed_by = actorId;
            delete profileUpdates.reason;
        }

        // 2. Update public profile
        const { error: dbError } = await sb.from('users').update(profileUpdates).eq('id', targetUserId);
        if (dbError) return { error: dbError.message };

        // 3. Update Auth Metadata if needed (for critical fields)
        if (profileUpdates.full_name || profileUpdates.kyc_level || profileUpdates.kyc_status || profileUpdates.role || profileUpdates.account_status) {
            await sb.auth.admin.updateUserById(targetUserId, {
                user_metadata: { ...currentMetadata, ...profileUpdates }
            });
        }

        await this.security.logActivity(actorId, 'ADMIN_PROFILE_UPDATE', 'success', `Updated profile for user ${targetUserId}`);
        return { success: true };
    }

    async updateAccountStatus(userId: string, status: string, actorId: string, reason?: string) {
        const sb = getAdminSupabase();
        if (!sb) return;

        const normalizedStatus = String(status || '').trim().toLowerCase();
        const normalizedReason = String(reason || '').trim() || `Status changed to ${normalizedStatus}`;
        const reasonCode = normalizedStatus === 'active'
            ? 'STATUS_REACTIVATED'
            : normalizedStatus === 'frozen'
                ? 'ACCOUNT_FROZEN'
                : normalizedStatus === 'blocked'
                    ? 'ACCOUNT_BLOCKED'
                    : normalizedStatus === 'pending'
                        ? 'ACCOUNT_PENDING_REVIEW'
                        : 'STATUS_CHANGED';
        const statusPatch = {
            account_status: normalizedStatus,
            status_reason: normalizedReason,
            status_reason_code: reasonCode,
            status_changed_at: new Date().toISOString(),
            status_changed_by: actorId,
        };

        // 1. Update public tables
        await sb.from('staff').update(statusPatch).eq('id', userId);
        await sb.from('users').update(statusPatch).eq('id', userId);

        // 2. Update Auth Metadata for immediate enforcement
        const { data: user } = await sb.auth.admin.getUserById(userId);
        if (user?.user) {
            await sb.auth.admin.updateUserById(userId, {
                user_metadata: {
                    ...user.user.user_metadata,
                    account_status: normalizedStatus,
                    status_reason: normalizedReason,
                    status_reason_code: reasonCode,
                    status_changed_at: statusPatch.status_changed_at,
                    status_changed_by: actorId,
                }
            });
        }

        await this.security.logActivity(actorId, 'GOVERNANCE_STATUS_UPDATE', 'success', `Node ${userId} rotated to ${normalizedStatus}: ${normalizedReason}`);
        await Audit.log('ADMIN', actorId, 'ACCOUNT_STATUS_UPDATE', {
            targetUserId: userId,
            status: normalizedStatus,
            reason: normalizedReason,
            reasonCode,
        });
    }
    async getForensicState(): Promise<ForensicReport> { return VaultAuditor.getForensicReport(); }
    async getDetailedUserActivity(uid: string) { return this.security.getUserActivity(uid); }

    // --- DISPUTE RESOLUTION ---
    async getDisputes() { return DisputeService.getAllCases(); }
    async resolveDispute(caseId: string, action: string, notes: string) { return DisputeService.resolveCase(caseId, action as any, notes, 'system'); }

    // --- REVENUE & FISCAL ---
    async getPricingRules() { return RevenueService.getRules(); }
    async rotatePricingRule(id: string, updates: any) { return RevenueService.rotateRule(id, updates, 'system'); }
    async getRegulatoryConfig() { return RegulatoryService.getActiveRegistry(); }
    async updateRegulatoryConfig(config: any) { return RegulatoryService.updateRegistry(config, 'system'); }
    async getSystemNodeMappings() { return RegulatoryService.getSystemNodeMappings(); }
    async updateSystemNode(role: string, walletId: string) { return RegulatoryService.updateSystemNode(role as any, walletId); }

    async getMerchants(category?: any) { return Merchants.getMerchants(category); }
    async getMerchantCategories() { return Merchants.getCategories(); }

    // --- MULTI-TENANT MERCHANT ACCOUNTS ---
    async createMerchantAccount(userId: string, data: any) { return MerchantAccounts.createMerchant(userId, data); }
    async getUserMerchantAccounts(userId: string) { return MerchantAccounts.getUserMerchants(userId); }
    async getMerchantAccountById(merchantId: string, actorUserId: string, privileged = false) {
        return MerchantAccounts.getMerchantById(merchantId, { actorUserId, privileged });
    }
    async updateMerchantSettlement(merchantId: string, data: any, actorUserId: string, privileged = false) {
        return MerchantAccounts.updateSettlementInfo(merchantId, data, { actorUserId, privileged });
    }
    async getMerchantTransactions(userId: string, limit: number = 50, offset: number = 0) {
        const transactions = await ServiceActorOps.getMerchantTransactions(userId, limit, offset);
        if (transactions.length > 0) {
            return transactions;
        }
        const fallback = await this.ledger.getLatestTransactions(userId, limit, offset);
        return fallback.filter((tx: any) => {
            const metadata = tx?.metadata || {};
            return metadata.service_context === 'MERCHANT' || metadata.merchant_id;
        });
    }
    async getAgentTransactions(userId: string, limit: number = 50, offset: number = 0) {
        const transactions = await ServiceActorOps.getAgentTransactions(userId, limit, offset);
        if (transactions.length > 0) {
            return transactions;
        }
        const fallback = await this.ledger.getLatestTransactions(userId, limit, offset);
        return fallback.filter((tx: any) => {
            const metadata = tx?.metadata || {};
            return metadata.service_context === 'AGENT_CASH';
        });
    }
    async getMerchantWallets(userId: string) { return ServiceActorOps.getMerchantWallets(userId); }
    async getAgentWallets(userId: string) { return ServiceActorOps.getAgentWallets(userId); }
    async lookupAgentByCode(query: string) { return ServiceActorOps.lookupAgentByCode(query); }
    async registerCustomerByServiceActor(actor: any, actorRole: 'MERCHANT' | 'AGENT', payload: any) {
        return ServiceActorOps.registerCustomerByActor(actor, actorRole, payload, this.auth);
    }
    async getServiceLinkedCustomers(actorUserId?: string, actorRole?: string) {
        return ServiceActorOps.getLinkedCustomers(actorUserId, actorRole);
    }
    async getServiceCommissions(actorUserId?: string, actorRole?: string) {
        return ServiceActorOps.getServiceCommissions(actorUserId, actorRole);
    }
    async processMerchantPayment(payload: any, user: any) {
        return this.processSecurePayment({
            ...payload,
            type: payload.type || 'EXTERNAL_PAYMENT',
            metadata: {
                ...(payload.metadata || {}),
                service_context: 'MERCHANT',
                merchant_actor_id: user?.id,
                merchant_role: user?.role || user?.user_metadata?.role || 'MERCHANT',
            },
        }, user);
    }
    async previewOrbiPayPayment(userId: string, payload: any) {
        return this.getTransactionPreview(userId, {
            ...payload,
            type: payload.type || 'MERCHANT_PAYMENT',
            metadata: {
                ...(payload.metadata || {}),
                service_context: 'MERCHANT',
                payment_channel: payload.channel || 'ORBI_PAY',
                merchant_pay_number: payload.merchantPayNumber,
                merchant_reference: payload.reference,
                merchant_name: payload.merchantName,
            },
        });
    }
    async processOrbiPayPayment(payload: any, user: any) {
        return this.processSecurePayment({
            ...payload,
            type: payload.type || 'MERCHANT_PAYMENT',
            metadata: {
                ...(payload.metadata || {}),
                service_context: 'MERCHANT',
                payment_channel: payload.channel || 'ORBI_PAY',
                merchant_pay_number: payload.merchantPayNumber,
                merchant_reference: payload.reference,
                merchant_name: payload.merchantName,
                initiated_by_consumer: true,
                payer_user_id: user?.id,
            },
        }, user);
    }
    async previewBillPayment(userId: string, payload: any) {
        return this.getTransactionPreview(userId, {
            ...payload,
            type: payload.type || 'BILL_PAYMENT',
            metadata: {
                ...(payload.metadata || {}),
                service_context: 'BILL_PAYMENT',
                bill_provider: payload.provider,
                bill_category: payload.billCategory,
                bill_reference: payload.reference,
            },
        });
    }
    async processBillPayment(payload: any, user: any) {
        return this.processSecurePayment({
            ...payload,
            type: payload.type || 'BILL_PAYMENT',
            metadata: {
                ...(payload.metadata || {}),
                service_context: 'BILL_PAYMENT',
                payment_channel: payload.channel || 'ORBI_BILL_PAY',
                bill_provider: payload.provider,
                bill_category: payload.billCategory,
                bill_reference: payload.reference,
                initiated_by_consumer: true,
                payer_user_id: user?.id,
            },
        }, user);
    }
    async getBillPaymentProviders() {
        const sb = getAdminSupabase();
        if (!sb) return [];
        return listRegistryBackedBillProviders(sb);
    }
    async processAgentCashOperation(payload: any, user: any, direction: 'deposit' | 'withdrawal') {
        const normalizedType = direction === 'deposit' ? 'DEPOSIT' : 'WITHDRAWAL';
        return this.processSecurePayment({
            ...payload,
            type: normalizedType,
            metadata: {
                ...(payload.metadata || {}),
                service_context: 'AGENT_CASH',
                cash_direction: direction,
                agent_actor_id: user?.id,
                agent_role: user?.role || user?.user_metadata?.role || 'AGENT',
            },
        }, user);
    }

    // --- FINANCIAL CORE ENGINE (MULTI-TENANT) ---
    async createTenant(userId: string, data: any) { return FinancialCore.createTenant(userId, data); }
    async getUserTenants(userId: string) { return FinancialCore.getUserTenants(userId); }
    async generateTenantApiKeys(userId: string, tenantId: string, type: 'test' | 'live' = 'test') { return FinancialCore.generateApiKeys(userId, tenantId, type); }
    async getTenantApiKeys(userId: string, tenantId: string) { return FinancialCore.getApiKeys(userId, tenantId); }
    async revokeTenantApiKey(userId: string, tenantId: string, keyId: string) { return FinancialCore.revokeApiKey(userId, tenantId, keyId); }
    async getTenantWallets(userId: string, tenantId: string) { return FinancialCore.getTenantWallets(userId, tenantId); }

    // --- SETTLEMENT ENGINE ---
    async getTenantSettlementConfig(userId: string, tenantId: string) { return SettlementEngine.getSettlementConfig(userId, tenantId); }
    async updateTenantSettlementConfig(userId: string, tenantId: string, config: any) { return SettlementEngine.updateSettlementConfig(userId, tenantId, config); }
    async getTenantPendingSettlement(tenantId: string) { return SettlementEngine.calculatePendingSettlement(tenantId); }
    async triggerTenantPayout(userId: string, tenantId: string) { return SettlementEngine.triggerPayout(userId, tenantId); }
    async getTenantPayoutHistory(userId: string, tenantId: string) { return SettlementEngine.getPayoutHistory(userId, tenantId); }

    async registerMerchant(payload: any) { return RegulatoryService.registerMerchant(payload); }

    async getPartners() { return PartnerRegistry.listPartners(); }
    async registerPartner(payload: any, actorId: string) {
        return PartnerRegistry.addPartner({
            ...payload,
            provider_metadata: payload.provider_metadata || payload.metadata || {},
            connection_secret:
                payload.connection_secret ||
                payload.client_secret ||
                payload.connection ||
                '',
            logic_type: payload.logic_type || 'REGISTRY',
        });
    }

    async getInstitutionalPaymentAccounts(filters?: any) {
        return institutionalFundsService.listInstitutionalAccounts(filters);
    }

    async getPlatformFeeConfigs(filters?: any) {
        return platformFeeService.listConfigs(filters);
    }

    async upsertPlatformFeeConfig(payload: any, actorId: string, configId?: string) {
        return platformFeeService.upsertConfig(payload, actorId, configId);
    }

    async upsertInstitutionalPaymentAccount(payload: any, actorId: string, accountId?: string) {
        return institutionalFundsService.upsertInstitutionalAccount(payload, actorId, accountId);
    }

    async previewExternalFundMovement(userId: string, payload: any) {
        return institutionalFundsService.previewMovement(userId, payload);
    }

    async createIncomingDepositIntent(userId: string, payload: any) {
        return institutionalFundsService.createIncomingDepositIntent(userId, payload);
    }

    async processExternalFundMovement(userId: string, payload: any) {
        return institutionalFundsService.processMovement(userId, payload);
    }

    async getUserExternalFundMovements(userId: string, limit?: number, offset?: number) {
        return institutionalFundsService.listMovements(userId, limit, offset);
    }

    async getUserExternalFundMovementById(userId: string, movementId: string) {
        return institutionalFundsService.getMovementById(userId, movementId);
    }

    async processOfflineGatewayRequest(payload: any) {
        return offlineGatewayService.handleInboundRequest(payload);
    }

    async processOfflineGatewayConfirmation(payload: any) {
        return offlineGatewayService.handleConfirmation(payload);
    }

    // --- DATA & MESSAGING ---
    async updateUserProfile(userId: string, updates: any, currentMetadata: any) {
        const safeUpdates = updates && typeof updates === 'object' ? updates : {};
        const safeCurrentMetadata =
            currentMetadata && typeof currentMetadata === 'object' ? currentMetadata : {};
        const isVerified = safeCurrentMetadata?.kyc_status === 'verified';
        
        // Define allowed fields based on status
        // Verified: Only avatar and settings (identity is locked)
        // Unverified: full_name, phone, address, nationality, avatar_url, metadata, currency, and settings
        const settingsFields = [
            'language', 'notif_push', 'notif_email', 'notif_security', 'notif_financial', 'notif_budget', 'notif_marketing',
            'security_tx_pin_hash', 'security_tx_pin_enabled', 'security_biometric_enabled', 'fcm_token'
        ];

        const allowedFields = isVerified 
            ? ['avatar_url', 'avatar', ...settingsFields] 
            : ['full_name', 'phone', 'address', 'nationality', 'avatar_url', 'metadata', 'currency', ...settingsFields];

        const attemptedFields = Object.keys(safeUpdates);
        const forbiddenFields = attemptedFields.filter(f => !allowedFields.includes(f));
        
        if (forbiddenFields.length > 0) {
            return { 
                error: `SECURITY_RESTRICTION: You cannot update the following fields: ${forbiddenFields.join(', ')}. ${isVerified ? 'Verified accounts are locked.' : ''}` 
            };
        }

        const sb = getSupabase();
        const adminSb = getAdminSupabase();
        
        if (!sb || !adminSb) {
            return { error: 'DB_CONNECTION_ERROR: Database service unavailable.' };
        }

        try {
            // 1. Update Auth Metadata (for fields that live there)
            // We must merge with current metadata to avoid losing fields like role, registry_type, etc.
            const metadataUpdates: any = { ...safeCurrentMetadata };
            if (safeUpdates.full_name) metadataUpdates.full_name = safeUpdates.full_name;
            if (safeUpdates.phone) metadataUpdates.phone = safeUpdates.phone;
            if (safeUpdates.nationality) metadataUpdates.nationality = safeUpdates.nationality;
            if (safeUpdates.address) metadataUpdates.address = safeUpdates.address;
            if (safeUpdates.avatar_url) metadataUpdates.avatar_url = safeUpdates.avatar_url;
            if (safeUpdates.currency) metadataUpdates.currency = safeUpdates.currency;
            if (safeUpdates.language) metadataUpdates.language = safeUpdates.language;
            
            // Sync settings to metadata for immediate access in auth-based logic
            settingsFields.forEach(field => {
                if (safeUpdates[field] !== undefined) metadataUpdates[field] = safeUpdates[field];
            });

            if (safeUpdates.metadata && typeof safeUpdates.metadata === 'object') {
                Object.assign(metadataUpdates, safeUpdates.metadata);
            }

            if (Object.keys(metadataUpdates).length > 0) {
                const { error } = await adminSb.auth.admin.updateUserById(userId, { user_metadata: metadataUpdates });
                if (error) throw error;
            }
            
            // 2. Update Public Tables (users/staff)
            const tableUpdates = { ...safeUpdates };
            delete tableUpdates.metadata; 
            delete tableUpdates.avatar; 

            if (Object.keys(tableUpdates).length > 0) {
                // Use admin client to ensure update succeeds regardless of RLS (server-side authoritative update)
                const { error: userError } = await adminSb.from('users').update(tableUpdates).eq('id', userId);
                if (userError) console.warn(`[UserProfile] User table update warning: ${userError.message}`);
                
                // Try updating 'staff' table (if user is staff)
                if (safeCurrentMetadata?.registry_type === 'STAFF') {
                    const { error: staffError } = await adminSb.from('staff').update(tableUpdates).eq('id', userId);
                    if (staffError) console.warn(`[UserProfile] Staff table update warning: ${staffError.message}`);
                }
            }
            
            Messaging.invalidateUserProfile(userId);
            await this.security.logActivity(userId, 'PROFILE_UPDATE', 'success', `Updated fields: ${attemptedFields.join(', ')}`);
            return { success: true };
        } catch (e: any) {
            console.error(`[UserProfile] Update failed: ${e.message}`);
            return { error: `UPDATE_FAILED: ${e.message}` };
        }
    }

    async updateLoginInfo(userId: string, email?: string, password?: string) {
        const sb = getSupabase();
        const adminSb = getAdminSupabase();
        
        if (!sb || !adminSb) return { error: 'DB_OFFLINE' };

        const updates: any = {};
        if (email) updates.email = email;
        if (password) updates.password = password;

        if (Object.keys(updates).length === 0) return { error: 'NO_CHANGES_REQUESTED' };

        // Use Admin API to update without requiring old password (assuming session authentication is sufficient for this scope)
        // In a stricter environment, we would require old_password verification before calling this.
        const { error } = await adminSb.auth.admin.updateUserById(userId, updates);
        
        if (error) return { error: error.message };

        // If email changed, we should probably update the public users table too
        if (email) {
            await sb.from('users').update({ email }).eq('id', userId);
            await sb.from('staff').update({ email }).eq('id', userId);
        }

        await this.security.logActivity(userId, 'LOGIN_INFO_UPDATE', 'success', `Updated login info: ${Object.keys(updates).join(', ')}`);
        return { success: true };
    }

    async uploadAvatar(userId: string, file: any, contentType?: string, oldUrl?: string) {
        const avatarUrl = await AssetLifecycle.commit(userId, file, contentType);
        if (!avatarUrl) return avatarUrl;

        try {
            const usesSelfHostedAuth =
                ['local', 'keycloak'].includes(
                    String(process.env.ORBI_AUTH_PROVIDER || 'supabase').trim().toLowerCase(),
                );

            if (usesSelfHostedAuth) {
                const client = await getOrbiDatabase().connect();
                try {
                    await client.query('BEGIN');
                    const result = await client.query<{ registry_type: string | null }>(
                        `UPDATE auth.users
                         SET raw_user_meta_data =
                               COALESCE(raw_user_meta_data, '{}'::jsonb) ||
                               jsonb_build_object('avatar_url', $2::text),
                             updated_at = NOW()
                         WHERE id = $1
                         RETURNING raw_user_meta_data->>'registry_type' AS registry_type`,
                        [userId, avatarUrl],
                    );
                    if (result.rowCount !== 1) throw new Error('IDENTITY_NOT_FOUND');

                    await client.query(
                        `UPDATE public.users SET avatar_url = $2 WHERE id = $1`,
                        [userId, avatarUrl],
                    );
                    if (String(result.rows[0]?.registry_type || '').toUpperCase() === 'STAFF') {
                        await client.query(
                            `UPDATE public.staff SET avatar_url = $2 WHERE id = $1`,
                            [userId, avatarUrl],
                        );
                    }
                    await client.query('COMMIT');
                } catch (error) {
                    await client.query('ROLLBACK');
                    throw error;
                } finally {
                    client.release();
                }
            } else {
                const adminSb = getAdminSupabase();
                if (!adminSb) throw new Error('DB_OFFLINE');

                const { data: authUserResult, error: authUserError } =
                    await adminSb.auth.admin.getUserById(userId);
                if (authUserError) throw new Error(authUserError.message);

                const currentMetadata = authUserResult?.user?.user_metadata || {};
                const { error: authUpdateError } = await adminSb.auth.admin.updateUserById(userId, {
                    user_metadata: {
                        ...currentMetadata,
                        avatar_url: avatarUrl,
                    },
                });
                if (authUpdateError) throw new Error(authUpdateError.message);

                const profileUpdate = { avatar_url: avatarUrl };
                const { error: userUpdateError } =
                    await adminSb.from('users').update(profileUpdate).eq('id', userId);
                if (userUpdateError) {
                    console.warn(`[Avatar] users update warning: ${userUpdateError.message}`);
                }

                if (String(currentMetadata?.registry_type || '').toUpperCase() === 'STAFF') {
                    const { error: staffUpdateError } =
                        await adminSb.from('staff').update(profileUpdate).eq('id', userId);
                    if (staffUpdateError) {
                        console.warn(`[Avatar] staff update warning: ${staffUpdateError.message}`);
                    }
                }
            }
        } catch (error) {
            await AssetLifecycle.decommission(avatarUrl, userId).catch(() => {});
            throw error;
        }

        if (oldUrl && oldUrl !== avatarUrl) {
            await AssetLifecycle.decommission(oldUrl, userId).catch((error) => {
                console.warn('[Avatar] Previous asset cleanup deferred:', error);
            });
        }

        return avatarUrl;
    }
    async getUserMessages(userId: string, limit: number = 50, offset: number = 0): Promise<UserMessage[]> {
        return Messaging.getMessages(userId, limit, offset);
    }
    async getSystemMessages(): Promise<SystemMessage[]> {
        return []; 
    }
    async markMessageRead(userId: string, id: string) {
        return Messaging.markAsRead(userId, id);
    }
    async markAllMessagesRead(userId: string) { 
        return Messaging.markAllAsRead(userId);
    }
    async deleteMessage(userId: string, id: string) {
        return Messaging.deleteMessage(userId, id);
    }
    async getSecurityPulse() { return Sentinel.inspectOperation(null, 'PULSE_CHECK', {}); }
    async getAnomalyReport(days: number = 7) { return ProviderAnomalyTracker.generateReport(days); }

    // --- AUDIT & SECURITY LOGS ---
    async getAuditTrail() { return Audit.getLogs(); }
    async getGlobalAuditLogs() { return Audit.getLogs(); }
    async getAllTransactions(filters?: {
        limit?: number;
        offset?: number;
        status?: string;
        type?: string;
        currency?: string;
        query?: string;
        dateFrom?: string;
        dateTo?: string;
    }) {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) throw new Error('DB_OFFLINE');

        const limit = Number(filters?.limit ?? 100);
        const offset = Number(filters?.offset ?? 0);

        let query = sb
            .from('transactions')
            .select('*', { count: 'exact' })
            .order('date', { ascending: false })
            .range(offset, offset + Math.max(limit, 1) - 1);

        if (filters?.status) query = query.eq('status', String(filters.status));
        if (filters?.type) query = query.eq('type', String(filters.type));
        if (filters?.currency) query = query.eq('currency', String(filters.currency).toUpperCase());
        if (filters?.dateFrom) query = query.gte('date', filters.dateFrom);
        if (filters?.dateTo) query = query.lte('date', filters.dateTo);
        if (filters?.query) {
            const q = String(filters.query).trim();
            query = query.or(buildPostgrestOrFilter([
                { column: 'reference_id', operator: 'ilike', value: q },
                { column: 'description', operator: 'ilike', value: q },
                { column: 'status', operator: 'ilike', value: q },
                { column: 'type', operator: 'ilike', value: q },
            ]));
        }

        const { data, error, count } = await query;
        if (error) throw new Error(error.message);

        return {
            items: data || [],
            total: count || 0,
        };
    }

    async getTransactionVolumeSummary(filters?: {
        status?: string;
        type?: string;
        currency?: string;
        query?: string;
        dateFrom?: string;
        dateTo?: string;
    }) {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) throw new Error('DB_OFFLINE');

        let query = sb
            .from('transactions')
            .select('id, amount, currency, status, type, date');

        if (filters?.status) query = query.eq('status', String(filters.status));
        if (filters?.type) query = query.eq('type', String(filters.type));
        if (filters?.currency) query = query.eq('currency', String(filters.currency).toUpperCase());
        if (filters?.dateFrom) query = query.gte('date', filters.dateFrom);
        if (filters?.dateTo) query = query.lte('date', filters.dateTo);
        if (filters?.query) {
            const q = String(filters.query).trim();
            query = query.or(buildPostgrestOrFilter([
                { column: 'reference_id', operator: 'ilike', value: q },
                { column: 'description', operator: 'ilike', value: q },
                { column: 'status', operator: 'ilike', value: q },
                { column: 'type', operator: 'ilike', value: q },
            ]));
        }

        const { data, error } = await query;
        if (error) throw new Error(error.message);

        const rows = data || [];
        const totalByCurrency: Record<string, number> = {};
        const completedByCurrency: Record<string, number> = {};
        let count = 0;
        let completedCount = 0;
        let totalAmountBase = 0;

        for (const tx of rows as any[]) {
            const amount = Number(tx.amount || 0);
            if (!Number.isFinite(amount)) continue;
            const currency = String(tx.currency || 'TZS').toUpperCase();
            totalByCurrency[currency] = (totalByCurrency[currency] || 0) + amount;
            totalAmountBase += amount;
            count += 1;

            if (String(tx.status || '').toLowerCase() === 'completed') {
                completedByCurrency[currency] = (completedByCurrency[currency] || 0) + amount;
                completedCount += 1;
            }
        }

        return {
            count,
            completedCount,
            totalByCurrency,
            completedByCurrency,
            averageTicket: count ? totalAmountBase / count : 0,
        };
    }
    async getLedgerEntries(transactionId: string) { return this.ledger.getLedgerEntries(transactionId); }
    async getUserActivity(token?: string) {
        const session = await this.getSession(token);
        if (!session) return [];
        return this.security.getUserActivity(session.sub);
    }
    async logActivity(userId: string, type: string, status: string, details: string, fingerprint?: string) {
        return this.security.logActivity(userId, type, status, details, undefined, fingerprint);
    }
    async approveTransaction(txId: string, notes: string) { return this.ledger.updateTransactionStatus(txId, 'completed', notes); }
    async rejectTransaction(txId: string, notes: string) { return this.ledger.updateTransactionStatus(txId, 'failed', notes); }
    async getTransactionLimits() { return ConfigClient.getRuleConfig(); }
    async rotateTransactionLimits(newLimits: any) { return ConfigClient.saveConfig(newLimits); }

    // --- STAFF MESSAGING (Nexus Chat) ---
    async sendStaffMessage(content: string, options: any) {
        const sb = getSupabase();
        if (!sb) return;
        const { data: { session } } = await sb.auth.getSession();
        if (!session) return;
        
        await sb.from('staff_messages').insert({
            sender_id: session.user.id,
            sender_name: session.user.user_metadata?.full_name || 'Staff Node',
            content,
            type: 'staff',
            target_role: options.targetRole,
            recipient_id: options.recipientId,
            created_at: new Date().toISOString()
        });
    }
    async getStaffChatHistory() {
        const sb = getSupabase();
        if (!sb) return [];
        const { data } = await sb.from('staff_messages').select('*').order('created_at', { ascending: true });
        return data || [];
    }
    async flagStaffMessage(messageId: string) {
        const sb = getSupabase();
        if (sb) await sb.from('staff_messages').update({ is_flagged: true }).eq('id', messageId);
    }
    async purgeStaffChatHistory(actorId: string) {
        const sb = getSupabase();
        if (sb) await sb.from('staff_messages').delete().neq('id', '0'); 
    }

    public calculateOverview(transactions: Transaction[], wallets: Wallet[], goals: Goal[]): FinancialOverview {
        return FinancialLogic.calculateOverview(transactions, wallets, goals);
    }

    // --- ENTERPRISE B2B & TREASURY ---
    private normalizeOrgRole(role: string) {
        const normalized = String(role || 'MEMBER').trim().toUpperCase().replace(/\s+/g, '_');
        const aliases: Record<string, string> = {
            FINANCE: 'ACCOUNTANT',
            MHASIBU: 'ACCOUNTANT',
            MENEJA: 'MANAGER',
            SAINI: 'SIGNATORY',
            SIGNER: 'SIGNATORY',
        };
        return aliases[normalized] || normalized;
    }

    private canLeadOrganization(role: string) {
        return ['ADMIN', 'SIGNATORY'].includes(this.normalizeOrgRole(role));
    }

    private async countOrganizationAdmins(orgId: string) {
        const sb = getAdminSupabase();
        if (!sb) return 0;
        const { count } = await sb
            .from('users')
            .select('id', { count: 'exact', head: true })
            .eq('organization_id', orgId)
            .eq('org_role', 'ADMIN');
        return Number(count || 0);
    }

    private async notifyOrganizationUsers(userIds: string[], subject: string, body: string, variables: Record<string, any>) {
        const sb = getAdminSupabase();
        if (!sb) throw new Error('DB_OFFLINE: Governance notifications require durable delivery state.');
        const eventCode = String(variables.eventCode || '').trim().toUpperCase();
        const eventId = String(variables.eventId || variables.requestId || variables.caseId || '').trim();
        if (!eventCode || !eventId) throw new Error('NOTIFICATION_EVENT_REQUIRED: eventCode and eventId are required.');
        await Promise.all([...new Set(userIds.filter(Boolean))].map((userId) =>
            Messaging.dispatch(userId, 'security', subject, body, {
                push: true,
                sms: true,
                email: true,
                systemCustomBypass: true,
                mandatory: true,
                eventCode,
                idempotencyKey: `${eventCode}:${eventId}`,
                variables,
                localized: variables.localized,
                metadata: { organizationId: variables.orgId, eventId, eventCode },
            }).catch(async (error: any) => {
                try {
                    await sb.rpc('finish_notification_delivery_v1', {
                        p_event_key: `${eventCode}:${eventId}`,
                        p_recipient_user_id: userId,
                        p_status: 'FAILED',
                        p_error: String(error?.message || error),
                    });
                } catch {
                    // Preserve the original delivery failure as the actionable signal.
                }
                console.warn('[Organization] Governance notification deferred', {
                    userId, eventCode, eventId, code: String(error?.code || error?.message || ''),
                });
            })
        ));
    }

    private async notifyOrganizationMembers(orgId: string, subject: string, body: string, variables: Record<string, any> = {}) {
        const sb = getAdminSupabase();
        if (!sb) return;
        const { data: members } = await sb
            .from('users')
            .select('id')
            .eq('organization_id', orgId)
            .eq('account_status', 'active');
        await this.notifyOrganizationUsers((members || []).map((member: any) => String(member.id)), subject, body, {
            ...variables, orgId,
        });
    }

    private async ensureOrganizationRoleDefinitions(orgId: string, actorId: string) {
        const sb = getAdminSupabase();
        if (!sb) return;
        const defaults = [
            { role_key: 'ADMIN', role_name: 'Admin', permissions: ['organization.manage', 'members.invite', 'roles.assign', 'fungu.manage'] },
            { role_key: 'MANAGER', role_name: 'Manager', permissions: ['members.invite', 'fungu.manage'] },
            { role_key: 'ACCOUNTANT', role_name: 'Mhasibu', permissions: ['finance.view', 'reports.export', 'fungu.view'] },
            { role_key: 'SIGNATORY', role_name: 'Signatory', permissions: ['approvals.sign', 'admin.removal.approve', 'fungu.approve'] },
            { role_key: 'MEMBER', role_name: 'Member', permissions: ['fungu.view'] },
        ];
        for (const role of defaults) {
            await sb.from('organization_role_definitions').upsert({
                organization_id: orgId,
                role_key: role.role_key,
                role_name: role.role_name,
                permissions: role.permissions,
                is_system: true,
                created_by: actorId,
                updated_at: new Date().toISOString(),
            }, { onConflict: 'organization_id,role_key' });
        }
    }

    async createOrganization(payload: any, actorId: string) {
        const sb = getAdminSupabase();
        if (!sb) return { error: 'DB_OFFLINE' };
        
        // 1. Create the Organization
        const baseCurrency = typeof payload?.base_currency === 'string'
            ? payload.base_currency.trim().toUpperCase()
            : '';
        if (!baseCurrency) {
            throw new Error("CURRENCY_REQUIRED: Organization base currency is required.");
        }

        const { data, error } = await sb.from('organizations').insert({
            name: payload.name,
            creator_user_id: actorId,
            primary_admin_user_id: actorId,
            owner_type: payload.owner_type || 'ORGANIZATION',
            owner_label: payload.owner_label || payload.name,
            registration_number: payload.registration_number,
            tax_id: payload.tax_id,
            country: payload.country,
            base_currency: baseCurrency,
            metadata: payload.metadata || {}
        }).select().single();

        if (error) return { error: error.message };
        await this.ensureOrganizationRoleDefinitions(data.id, actorId);

        // 2. Auto-assign the creator as the Organization ADMIN
        await sb.from('users').update({ 
            organization_id: data.id, 
            org_role: 'ADMIN' 
        }).eq('id', actorId);

        await this.security.logActivity(actorId, 'ORG_CREATED', 'success', `Created organization ${payload.name} and assumed ADMIN role`);
        await this.notifyOrganizationMembers(
            data.id,
            'Organization created',
            `${payload.name} organization profile was created and governance roles are ready.`,
            { orgId: data.id, orgName: payload.name, actorId, eventId: data.id, eventCode: 'ORGANIZATION_CREATED' },
        );
        return { success: true, data };
    }

    async getOrganizations(userId: string) {
        const sb = getAdminSupabase();
        if (!sb) return [];
        const { data } = await sb.from('users').select('organization_id, organizations(*)').eq('id', userId).single();
        if (!data || !data.organization_id) return [];
        return [data.organizations];
    }

    async linkUserToOrganization(userId: string, orgId: string, role: string, actorId: string, reason = 'Organization membership invitation requested') {
        const sb = getAdminSupabase();
        if (!sb) return { error: 'DB_OFFLINE' };
        const normalizedRole = this.normalizeOrgRole(role);
        const { data, error } = await sb.rpc('request_organization_invitation_v1', {
            p_actor_id: actorId, p_organization_id: orgId, p_target_user_id: userId,
            p_role: normalizedRole, p_reason: reason,
        });
        if (error) return { error: error.message };
        await Audit.log('SECURITY', actorId, 'ORGANIZATION_INVITATION_REQUESTED', {
            organizationId: orgId, targetUserId: userId, role: normalizedRole,
            invitationId: data?.invitation_id,
        }, data?.invitation_id);
        await this.notifyOrganizationUsers(
            [userId],
            'Organization invitation',
            `You were invited to join an organization as ${normalizedRole}. Review this invitation before it expires.`,
            {
                orgId, role: normalizedRole, actorId, requestId: data?.invitation_id,
                eventCode: 'ORGANIZATION_INVITATION_REQUESTED',
                localized: { sw: { subject: 'Mwaliko wa shirika', body: `Umealikwa kujiunga na shirika kama ${normalizedRole}. Kagua mwaliko huu kabla muda wake haujaisha.` } },
            },
        );
        return { success: true, data };
    }

    async inviteUserByEmail(email: string, orgId: string, role: string, actorId: string, reason = 'Organization membership invitation requested') {
        const sb = getAdminSupabase();
        if (!sb) return { error: 'DB_OFFLINE' };

        const normalizedRole = this.normalizeOrgRole(role);
        const { data: targetUser } = await sb.from('users').select('id').eq('email', email).single();
        if (!targetUser) {
            return { error: 'USER_NOT_FOUND: No Orbi account found with this email. They must register first.' };
        }
        const result = await this.linkUserToOrganization(targetUser.id, orgId, normalizedRole, actorId, reason);
        if (result.error) return result;
        return { ...result, userId: targetUser.id };
    }

    async respondOrganizationInvitation(invitationId: string, decision: 'ACCEPT' | 'DECLINE', actorId: string) {
        const sb = getAdminSupabase();
        if (!sb) return { error: 'DB_OFFLINE' };
        const { data, error } = await sb.rpc('respond_organization_invitation_v1', {
            p_actor_id: actorId, p_invitation_id: invitationId, p_decision: decision,
        });
        if (error) return { error: error.message };
        await Audit.log('SECURITY', actorId, 'ORGANIZATION_INVITATION_RESPONDED', {
            invitationId, decision, status: data?.status, organizationId: data?.organization_id,
        }, invitationId);
        if (data?.organization_id) await this.notifyOrganizationMembers(
            data.organization_id,
            'Organization invitation updated',
            `An organization invitation was ${decision === 'ACCEPT' ? 'accepted' : 'declined'}.`,
            {
                requestId: invitationId, eventCode: 'ORGANIZATION_INVITATION_RESPONDED', decision,
                localized: { sw: { subject: 'Mwaliko wa shirika umebadilishwa', body: `Mwaliko wa shirika ${decision === 'ACCEPT' ? 'umekubaliwa' : 'umekataliwa'}.` } },
            },
        );
        return { success: true, data };
    }

    async requestOrganizationMemberChange(orgId: string, input: {
        targetUserId: string; action: 'CHANGE_ROLE' | 'REMOVE_MEMBER';
        toRole?: 'MEMBER' | 'MANAGER' | 'ACCOUNTANT' | null; reason: string;
    }, actorId: string) {
        const sb = getAdminSupabase();
        if (!sb) return { error: 'DB_OFFLINE' };
        const { data, error } = await sb.rpc('request_organization_member_change_v1', {
            p_actor_id: actorId, p_organization_id: orgId, p_target_user_id: input.targetUserId,
            p_action: input.action, p_to_role: input.toRole || null, p_reason: input.reason,
        });
        if (error) return { error: error.message };
        await Audit.log('SECURITY', actorId, 'ORGANIZATION_MEMBER_CHANGE_REQUESTED', {
            requestId: data, organizationId: orgId, ...input,
        }, data);
        await this.notifyOrganizationMembers(
            orgId,
            'Member change requires review',
            `A request to ${input.action === 'REMOVE_MEMBER' ? 'remove a member' : 'change a member role'} is awaiting an independent review.`,
            {
                requestId: data, targetUserId: input.targetUserId, action: input.action,
                eventCode: 'ORGANIZATION_MEMBER_CHANGE_REQUESTED',
                localized: { sw: { subject: 'Mabadiliko ya mwanachama yanahitaji uhakiki', body: `Ombi la ${input.action === 'REMOVE_MEMBER' ? 'kumwondoa mwanachama' : 'kubadili nafasi ya mwanachama'} linasubiri uhakiki wa mtu mwingine.` } },
            },
        );
        return { success: true, data: { requestId: data } };
    }

    async respondOrganizationMemberChange(requestId: string, input: {
        decision: 'APPROVE' | 'REJECT'; reason: string;
    }, actorId: string) {
        const sb = getAdminSupabase();
        if (!sb) return { error: 'DB_OFFLINE' };
        const { data, error } = await sb.rpc('respond_organization_member_change_v1', {
            p_reviewer_id: actorId, p_request_id: requestId,
            p_decision: input.decision, p_reason: input.reason,
        });
        if (error) return { error: error.message };
        await Audit.log('SECURITY', actorId, 'ORGANIZATION_MEMBER_CHANGE_REVIEWED', {
            requestId, decision: input.decision, reason: input.reason, status: data?.status,
        }, requestId);
        const { data: memberRequest } = await sb.from('organization_role_change_requests')
            .select('organization_id').eq('id', requestId).maybeSingle();
        if (memberRequest?.organization_id) await this.notifyOrganizationMembers(
            memberRequest.organization_id,
            'Member change reviewed',
            `A member change request was ${String(data?.status || input.decision).toLowerCase()}.`,
            {
                requestId, decision: input.decision, status: data?.status,
                eventCode: 'ORGANIZATION_MEMBER_CHANGE_REVIEWED',
                localized: { sw: { subject: 'Mabadiliko ya mwanachama yamehakikiwa', body: `Ombi la mabadiliko ya mwanachama sasa lina hali ya ${String(data?.status || input.decision)}.` } },
            },
        );
        return { success: true, data };
    }

    async createOrganizationRole(orgId: string, payload: any, actorId: string) {
        const sb = getAdminSupabase();
        if (!sb) return { error: 'DB_OFFLINE' };
        const { data: actor } = await sb.from('users').select('organization_id, org_role').eq('id', actorId).single();
        if (!actor || actor.organization_id !== orgId || this.normalizeOrgRole(actor.org_role) !== 'ADMIN') {
            return { error: 'UNAUTHORIZED: Only Organization Admins can create roles.' };
        }
        const roleKey = this.normalizeOrgRole(payload.role_key || payload.name);
        const { data, error } = await sb.from('organization_role_definitions').upsert({
            organization_id: orgId,
            role_key: roleKey,
            role_name: payload.role_name || payload.name || roleKey,
            permissions: Array.isArray(payload.permissions) ? payload.permissions : [],
            is_system: false,
            created_by: actorId,
            updated_at: new Date().toISOString(),
        }, { onConflict: 'organization_id,role_key' }).select('*').single();
        if (error) return { error: error.message };
        await this.notifyOrganizationMembers(
            orgId,
            'Organization role updated',
            `A role named ${data.role_name} was added or updated.`,
            { orgId, role: roleKey, actorId, eventId: data.id, eventCode: 'ORGANIZATION_ROLE_UPDATED' },
        );
        return { success: true, data };
    }

    async requestOrganizationAdminChange(orgId: string, payload: any, actorId: string) {
        const sb = getAdminSupabase();
        if (!sb) return { error: 'DB_OFFLINE' };
        const action = String(payload.action || '').trim().toUpperCase();
        const targetUserId = String(payload.targetUserId || payload.target_user_id || '');
        const { data, error } = await sb.rpc('request_organization_leadership_change_v1', {
            p_actor_id: actorId, p_organization_id: orgId, p_target_user_id: targetUserId,
            p_action: action, p_to_role: payload.toRole || payload.to_role || null,
            p_reason: payload.reason,
        });
        if (error) return { error: error.message };
        await Audit.log('SECURITY', actorId, 'ORGANIZATION_LEADERSHIP_CHANGE_REQUESTED', {
            requestId: data?.request_id, organizationId: orgId, targetUserId, action,
            requiredReviews: data?.required_reviews, reason: payload.reason,
        }, data?.request_id);
        await this.notifyOrganizationMembers(
            orgId,
            'Leadership change requires approval',
            `A protected leadership change (${action}) is awaiting independent approvals.`,
            {
                requestId: data?.request_id, targetUserId, action,
                eventCode: 'ORGANIZATION_LEADERSHIP_CHANGE_REQUESTED',
                localized: { sw: { subject: 'Badiliko la uongozi linahitaji idhini', body: `Badiliko la uongozi lililolindwa (${action}) linasubiri idhini huru.` } },
            },
        );
        return { success: true, data };
    }
    async respondOrganizationAdminChange(requestId: string, payload: any, actorId: string) {
        const sb = getAdminSupabase();
        if (!sb) return { error: 'DB_OFFLINE' };
        const decision = String(payload.decision || payload.action || '').trim().toUpperCase();
        const reason = String(payload.reason || payload.note || '').trim();
        const { data, error } = await sb.rpc('respond_organization_leadership_change_v1', {
            p_reviewer_id: actorId, p_request_id: requestId, p_decision: decision, p_reason: reason,
        });
        if (error) return { error: error.message };
        await Audit.log('SECURITY', actorId, 'ORGANIZATION_LEADERSHIP_CHANGE_REVIEWED', {
            requestId, decision, reason, status: data?.status,
        }, requestId);
        const { data: leadershipRequest } = await sb.from('organization_role_change_requests')
            .select('organization_id').eq('id', requestId).maybeSingle();
        if (leadershipRequest?.organization_id) await this.notifyOrganizationMembers(
            leadershipRequest.organization_id,
            'Leadership change reviewed',
            `A protected leadership change now has status ${String(data?.status || decision)}.`,
            {
                requestId, decision, status: data?.status,
                eventCode: 'ORGANIZATION_LEADERSHIP_CHANGE_REVIEWED',
                localized: { sw: { subject: 'Badiliko la uongozi limehakikiwa', body: `Badiliko la uongozi lililolindwa sasa lina hali ya ${String(data?.status || decision)}.` } },
            },
        );
        return { success: true, data };
    }

    async requestOrganizationRecovery(orgId: string, input: any, actorId: string) {
        const sb = getAdminSupabase();
        if (!sb) return { error: 'DB_OFFLINE' };
        const { data, error } = await sb.rpc('request_organization_recovery_v1', {
            p_actor_id: actorId, p_organization_id: orgId, p_beneficiary_id: input.beneficiaryUserId,
            p_incident_reference: input.incidentReference, p_reason: input.reason,
            p_evidence: input.evidence || {},
        });
        if (error) return { error: error.message };
        await Audit.log('SECURITY', actorId, 'ORGANIZATION_RECOVERY_REQUESTED', {
            caseId: data, organizationId: orgId, beneficiaryUserId: input.beneficiaryUserId,
            incidentReference: input.incidentReference,
        }, data);
        const [{ data: leaders }, { data: externalReviewers }] = await Promise.all([
            sb.from('users').select('id').eq('organization_id', orgId).eq('account_status', 'active').in('org_role', ['ADMIN', 'SIGNATORY']),
            sb.from('users').select('id').eq('role', 'SUPER_ADMIN').eq('account_status', 'active'),
        ]);
        await this.notifyOrganizationUsers(
            [...(leaders || []).map((u: any) => String(u.id)), ...(externalReviewers || []).map((u: any) => String(u.id)), String(input.beneficiaryUserId)],
            'Critical organization recovery requested',
            `Recovery case ${data} is cooling down and requires an external review. Do not approve it unless you independently verified the incident.`,
            {
                orgId, caseId: data, beneficiaryUserId: input.beneficiaryUserId,
                eventCode: 'ORGANIZATION_RECOVERY_REQUESTED',
                localized: { sw: { subject: 'Urejeshaji muhimu wa shirika umeombwa', body: `Kesi ya urejeshaji ${data} iko kwenye muda wa kusubiri na inahitaji uhakiki wa nje. Usiidhinishe bila kuthibitisha tukio kwa njia huru.` } },
            },
        );
        return { success: true, data: { caseId: data } };
    }

    async requestOrganizationRecoveryContact(orgId: string, input: any, actorId: string) {
        const sb = getAdminSupabase();
        if (!sb) return { error: 'DB_OFFLINE' };
        const { data, error } = await sb.rpc('request_organization_recovery_contact_v1', {
            p_actor_id: actorId, p_organization_id: orgId, p_contact_user_id: input.contactUserId,
            p_contact_type: input.contactType, p_reason: input.reason,
        });
        if (error) return { error: error.message };
        await Audit.log('SECURITY', actorId, 'ORGANIZATION_RECOVERY_CONTACT_REQUESTED', {
            organizationId: orgId, contactId: data, contactUserId: input.contactUserId, contactType: input.contactType,
        }, data);
        const { data: reviewers } = await sb.from('users').select('id').eq('role', 'SUPER_ADMIN').eq('account_status', 'active');
        await this.notifyOrganizationUsers(
            [String(input.contactUserId), ...(reviewers || []).map((u: any) => String(u.id))],
            'Recovery contact verification required',
            'A recovery contact enrollment requires independent verification before it can protect the organization.',
            { orgId, eventId: data, contactUserId: input.contactUserId, eventCode: 'ORGANIZATION_RECOVERY_CONTACT_REQUESTED', localized: { sw: { subject: 'Uthibitishaji wa mawasiliano ya urejeshaji unahitajika', body: 'Usajili wa mawasiliano ya urejeshaji unahitaji uthibitishaji huru kabla haujaanza kulinda shirika.' } } },
        );
        return { success: true, data: { contactId: data } };
    }

    async requestOrganizationRecoveryContactRevocation(contactId: string, reason: string, actorId: string) {
        const sb = getAdminSupabase();
        if (!sb) return { error: 'DB_OFFLINE' };
        const { data, error } = await sb.rpc('request_organization_recovery_contact_revocation_v1', {
            p_actor_id: actorId, p_contact_id: contactId, p_reason: reason,
        });
        if (error) return { error: error.message };
        const { data: contact } = await sb.from('organization_recovery_contacts').select('organization_id,contact_user_id').eq('id', contactId).single();
        const { data: reviewers } = await sb.from('users').select('id').eq('role', 'SUPER_ADMIN').eq('account_status', 'active');
        await Audit.log('SECURITY', actorId, 'ORGANIZATION_RECOVERY_CONTACT_REVOCATION_REQUESTED', { contactId, organizationId: contact?.organization_id }, contactId);
        await this.notifyOrganizationUsers(
            [...(reviewers || []).map((u: any) => String(u.id)), String(contact?.contact_user_id || '')],
            'Recovery contact revocation requires review',
            'A verified recovery contact revocation is awaiting independent review.',
            { orgId: contact?.organization_id, eventId: data, contactId, eventCode: 'ORGANIZATION_RECOVERY_CONTACT_REVOCATION_REQUESTED', localized: { sw: { subject: 'Kuondoa mawasiliano ya urejeshaji kunahitaji uhakiki', body: 'Ombi la kuondoa mawasiliano ya urejeshaji yaliyothibitishwa linasubiri uhakiki huru.' } } },
        );
        return { success: true, data: { contactId: data } };
    }

    async respondOrganizationRecoveryContact(contactId: string, input: any, actorId: string) {
        const sb = getAdminSupabase();
        if (!sb) return { error: 'DB_OFFLINE' };
        const { data, error } = await sb.rpc('respond_organization_recovery_contact_v1', {
            p_reviewer_id: actorId, p_contact_id: contactId, p_decision: input.decision, p_reason: input.reason,
        });
        if (error) return { error: error.message };
        await Audit.log('SECURITY', actorId, 'ORGANIZATION_RECOVERY_CONTACT_REVIEWED', { contactId, decision: input.decision, status: data?.status }, contactId);
        await this.notifyOrganizationUsers(
            [String(data?.contact_user_id || ''), String(data?.requested_by || ''), String(data?.revocation_requested_by || '')],
            'Recovery contact reviewed',
            `Recovery contact ${contactId} now has status ${String(data?.status)}.`,
            { orgId: data?.organization_id, eventId: contactId, contactId, status: data?.status, eventCode: 'ORGANIZATION_RECOVERY_CONTACT_REVIEWED', localized: { sw: { subject: 'Mawasiliano ya urejeshaji yamehakikiwa', body: `Mawasiliano ya urejeshaji ${contactId} sasa yana hali ya ${String(data?.status)}.` } } },
        );
        return { success: true, data };
    }

    async requestOrganizationReactivation(orgId: string, input: any, actorId: string) {
        const sb = getAdminSupabase();
        if (!sb) return { error: 'DB_OFFLINE' };
        const { data, error } = await sb.rpc('request_organization_reactivation_v1', {
            p_actor_id: actorId, p_organization_id: orgId, p_target_user_id: input.targetUserId,
            p_reason: input.reason, p_evidence: input.evidence,
        });
        if (error) return { error: error.message };
        const { data: reviewers } = await sb.from('users').select('id').eq('role', 'SUPER_ADMIN').eq('account_status', 'active');
        await Audit.log('SECURITY', actorId, 'ORGANIZATION_REACTIVATION_REQUESTED', { organizationId: orgId, caseId: data, targetUserId: input.targetUserId }, data);
        await this.notifyOrganizationUsers(
            [String(input.targetUserId), ...(reviewers || []).map((u: any) => String(u.id))],
            'Account reactivation requires external review',
            `Reactivation case ${data} is cooling down. Approval requires independent verification of identity, credentials, and incident closure.`,
            { orgId, caseId: data, targetUserId: input.targetUserId, eventCode: 'ORGANIZATION_REACTIVATION_REQUESTED', localized: { sw: { subject: 'Kuwasha akaunti kunahitaji uhakiki wa nje', body: `Kesi ya kuwasha akaunti ${data} iko kwenye muda wa kusubiri. Idhini inahitaji uthibitishaji huru wa utambulisho, credentials na kufungwa kwa tukio.` } } },
        );
        return { success: true, data: { caseId: data } };
    }

    async respondOrganizationReactivation(caseId: string, input: any, actorId: string) {
        const sb = getAdminSupabase();
        if (!sb) return { error: 'DB_OFFLINE' };
        const { data, error } = await sb.rpc('respond_organization_reactivation_v1', {
            p_reviewer_id: actorId, p_case_id: caseId, p_decision: input.decision, p_reason: input.reason,
        });
        if (error) return { error: error.message };
        const { data: reactivation } = await sb.from('organization_reactivation_cases').select('organization_id,requested_by,target_user_id').eq('id', caseId).single();
        await Audit.log('SECURITY', actorId, 'ORGANIZATION_REACTIVATION_REVIEWED', { caseId, decision: input.decision, status: data?.status }, caseId);
        await this.notifyOrganizationUsers(
            [String(reactivation?.requested_by || ''), String(reactivation?.target_user_id || '')],
            'Account reactivation reviewed',
            `Reactivation case ${caseId} now has status ${String(data?.status || input.decision)}.`,
            { orgId: reactivation?.organization_id, caseId, status: data?.status, eventCode: 'ORGANIZATION_REACTIVATION_REVIEWED', localized: { sw: { subject: 'Kuwasha akaunti kumehakikiwa', body: `Kesi ya kuwasha akaunti ${caseId} sasa ina hali ya ${String(data?.status || input.decision)}.` } } },
        );
        return { success: true, data };
    }

    async respondOrganizationRecovery(caseId: string, input: any, actorId: string) {
        const sb = getAdminSupabase();
        if (!sb) return { error: 'DB_OFFLINE' };
        const { data, error } = await sb.rpc('respond_organization_recovery_v1', {
            p_reviewer_id: actorId, p_case_id: caseId,
            p_decision: input.decision, p_reason: input.reason,
        });
        if (error) return { error: error.message };
        await Audit.log('SECURITY', actorId, 'ORGANIZATION_RECOVERY_REVIEWED', {
            caseId, decision: input.decision, status: data?.status,
        }, caseId);
        const { data: recoveryCase } = await sb.from('organization_recovery_cases')
            .select('organization_id,requester_id,beneficiary_user_id').eq('id', caseId).maybeSingle();
        if (recoveryCase) await this.notifyOrganizationUsers(
            [String(recoveryCase.requester_id), String(recoveryCase.beneficiary_user_id)],
            'Organization recovery reviewed',
            `Recovery case ${caseId} now has status ${String(data?.status || input.decision)}.`,
            {
                orgId: recoveryCase.organization_id, caseId, status: data?.status, decision: input.decision,
                eventCode: 'ORGANIZATION_RECOVERY_REVIEWED',
                localized: { sw: { subject: 'Urejeshaji wa shirika umehakikiwa', body: `Kesi ya urejeshaji ${caseId} sasa ina hali ya ${String(data?.status || input.decision)}.` } },
            },
        );
        return { success: true, data };
    }
    async requestTreasuryWithdrawal(userId: string, goalId: string, amount: number, destinationWalletId: string, reason: string) {
        try {
            const txId = await Treasury.requestWithdrawal(userId, goalId, amount, destinationWalletId, reason);
            return { success: true, txId };
        } catch (e: any) {
            return { error: e.message };
        }
    }

    async approveTreasuryWithdrawal(adminId: string, txId: string, reason?: string) {
        await Audit.log('FINANCIAL', adminId, 'TREASURY_WITHDRAWAL_APPROVAL_REQUESTED', {
            txId,
            reason: reason || 'No reason supplied',
        }, txId);
        const isFullyApproved = await Treasury.approveWithdrawal(adminId, txId);
        await Audit.log('FINANCIAL', adminId, 'TREASURY_WITHDRAWAL_APPROVAL_RECORDED', {
            txId,
            reason: reason || 'No reason supplied',
            isFullyApproved,
        }, txId);
        return { isFullyApproved };
    }

    private async assertOrganizationAccess(
        actorId: string,
        orgId: string,
        options: { privileged?: boolean; allowedOrgRoles?: string[] } = {},
    ) {
        const sb = getAdminSupabase();
        if (!sb) throw new Error('DB_OFFLINE');
        const { data: actor, error } = await sb
            .from('users')
            .select('organization_id, org_role, account_status')
            .eq('id', actorId)
            .maybeSingle();
        if (error) throw new Error(error.message);
        if (!canAccessOrganizationResource(actor, orgId, options)) {
            throw new Error('ORGANIZATION_ACCESS_DENIED');
        }
    }

    async getOrganizationDetails(orgId: string, actorId: string, privileged = false) {
        const sb = getAdminSupabase();
        if (!sb) return { error: 'DB_OFFLINE' };
        await this.assertOrganizationAccess(actorId, orgId, { privileged });
        
        const { data: org } = await sb.from('organizations').select('*').eq('id', orgId).single();
        if (!org) return { error: 'NOT_FOUND' };
        await this.ensureOrganizationRoleDefinitions(orgId, String(org.creator_user_id || org.primary_admin_user_id || ''));

        const { data: members } = await sb.from('users').select('id, full_name, email, org_role, account_status').eq('organization_id', orgId);
        const { data: goals } = await sb.from('goals').select('*').eq('organization_id', orgId).eq('is_corporate', true);
        const { data: roles } = await sb.from('organization_role_definitions').select('*').eq('organization_id', orgId).order('is_system', { ascending: false }).order('role_name', { ascending: true });
        const { data: adminChangeRequests } = await sb
            .from('organization_role_change_requests')
            .select('*')
            .eq('organization_id', orgId)
            .order('created_at', { ascending: false })
            .limit(50);
        
        return { success: true, data: { ...org, members: members || [], goals: goals || [], roles: roles || [], admin_change_requests: adminChangeRequests || [] } };
    }

    async getPendingApprovals(orgId: string, actorId: string, privileged = false) {
        await this.assertOrganizationAccess(actorId, orgId, {
            privileged,
            allowedOrgRoles: ['ADMIN', 'FINANCE', 'ACCOUNTANT', 'SIGNATORY'],
        });
        const data = await Treasury.getPendingApprovals(orgId);
        return { success: true, data };
    }

    async getTreasuryPolicy(orgId: string, currency: string, actorId: string) {
        await this.assertOrganizationAccess(actorId, orgId);
        const sb = getAdminSupabase();
        if (!sb) return { error: 'DB_OFFLINE' };
        const { data, error } = await sb.from('treasury_policies').select('*')
            .eq('organization_id', orgId).eq('currency', currency).eq('is_active', true).maybeSingle();
        if (error) throw new Error(error.message);
        return { success: true, data };
    }

    async upsertTreasuryPolicy(input: {
        organizationId: string; currency: string; name: string; description?: string | null;
        minApprovals: number; maxAmountPerTx?: number | null; dailyLimit?: number | null; reason: string;
    }, actorId: string) {
        const sb = getAdminSupabase();
        if (!sb) throw new Error('DB_OFFLINE');
        const { data, error } = await sb.rpc('upsert_treasury_policy_v1', {
            p_actor_id: actorId, p_organization_id: input.organizationId, p_currency: input.currency,
            p_name: input.name, p_description: input.description || null,
            p_min_approvals: input.minApprovals, p_max_amount_per_tx: input.maxAmountPerTx ?? null,
            p_daily_limit: input.dailyLimit ?? null, p_change_reason: input.reason,
        });
        if (error) throw new Error(error.message);
        await Audit.log('SECURITY', actorId, 'TREASURY_POLICY_UPDATED', {
            organizationId: input.organizationId, currency: input.currency,
            policyId: data?.policy_id, version: data?.version, reason: input.reason,
        }, data?.policy_id);
        return { success: true, data };
    }

    async requestTreasuryApproverChange(input: { organizationId:string; targetUserId:string; action:'ADD'|'REMOVE'; reason:string }, actorId:string) {
        const sb=getAdminSupabase(); if(!sb) throw new Error('DB_OFFLINE');
        const {data,error}=await sb.rpc('request_treasury_approver_change_v1',{p_actor_id:actorId,p_organization_id:input.organizationId,p_target_user_id:input.targetUserId,p_action:input.action,p_reason:input.reason});
        if(error) throw new Error(error.message);
        await Audit.log('SECURITY',actorId,'TREASURY_APPROVER_CHANGE_REQUESTED',{requestId:data,organizationId:input.organizationId,targetUserId:input.targetUserId,action:input.action,reason:input.reason},data);
        return {success:true,data:{requestId:data}};
    }

    async respondTreasuryApproverChange(requestId:string,input:{decision:'APPROVE'|'REJECT';reason:string},actorId:string) {
        const sb=getAdminSupabase(); if(!sb) throw new Error('DB_OFFLINE');
        const {data,error}=await sb.rpc('respond_treasury_approver_change_v1',{p_reviewer_id:actorId,p_request_id:requestId,p_decision:input.decision,p_reason:input.reason});
        if(error) throw new Error(error.message);
        await Audit.log('SECURITY',actorId,'TREASURY_APPROVER_CHANGE_REVIEWED',{requestId,decision:input.decision,reason:input.reason},requestId);
        return {success:true,data};
    }

    async configureAutoSweep(input: {goalId:string;enabled:boolean;threshold:number;frequency:string;timezone:string;nextRunAt:string;windowMinutes:number;reason:string}, actorId: string, privileged = false) {
        const sb = getAdminSupabase();
        if (!sb) return { error: 'DB_OFFLINE' };
        const { data: goal, error } = await sb
            .from('goals')
            .select('id, organization_id, is_corporate')
            .eq('id', input.goalId)
            .maybeSingle();
        if (error) throw new Error(error.message);
        if (!goal || !goal.is_corporate || !goal.organization_id) throw new Error('ORGANIZATION_RESOURCE_NOT_FOUND');
        await this.assertOrganizationAccess(actorId, goal.organization_id, {
            privileged,
            allowedOrgRoles: ['ADMIN'],
        });
        const requestId = await Treasury.requestAutoSweepChange(actorId, input);
        return { success: true, data: { requestId, status: 'PENDING' } };
    }

    async respondAutoSweepChange(requestId:string,input:{decision:'APPROVE'|'REJECT';reason:string},actorId:string) {
        const data = await Treasury.respondAutoSweepChange(actorId, requestId, input.decision, input.reason);
        return { success: true, data };
    }

    async generateOrganizationStatement(orgId:string,input:{periodStart:string;periodEnd:string;timezone:string;reason:string},actorId:string) {
        const sb=getAdminSupabase(); if(!sb) throw new Error('DB_OFFLINE');
        await this.assertOrganizationAccess(actorId,orgId,{allowedOrgRoles:['ADMIN','FINANCE','ACCOUNTANT','SIGNATORY']});
        const {data,error}=await sb.rpc('generate_organization_statement_v1',{p_actor_id:actorId,p_organization_id:orgId,p_period_start:input.periodStart,p_period_end:input.periodEnd,p_timezone:input.timezone,p_reason:input.reason});
        if(error) throw new Error(error.message);
        await Audit.log('FINANCIAL',actorId,'ORGANIZATION_STATEMENT_GENERATED',{organizationId:orgId,periodStart:input.periodStart,periodEnd:input.periodEnd,statementId:data?.statement_id,contentHash:data?.content_hash,replayed:data?.replayed},data?.statement_id);
        try {
            const {data:user}=await sb.from('users').select('language').eq('id',actorId).single();
            const sw=user?.language==='sw';
            await Messaging.dispatch(actorId,'info',sw?'Taarifa ya Fedha Imetengenezwa':'Organization statement ready',sw?'Taarifa ya fedha ya shirika lako imetengenezwa na iko tayari kukaguliwa.':'Your organization financial statement has been generated and is ready for review.',{push:true,sms:true,email:true,mandatory:true,systemCustomBypass:true,eventCode:'ORGANIZATION_STATEMENT_READY',idempotencyKey:`organization-statement:${data.statement_id}:ready:${actorId}`});
        } catch(notificationError:any) { console.warn(`[OrganizationStatement] ${data?.statement_id} committed; notification deferred: ${notificationError.message}`); }
        return {success:true,data};
    }

    async listOrganizationStatements(orgId:string,actorId:string) {
        const sb=getAdminSupabase(); if(!sb) throw new Error('DB_OFFLINE');
        await this.assertOrganizationAccess(actorId,orgId,{allowedOrgRoles:['ADMIN','FINANCE','ACCOUNTANT','SIGNATORY']});
        const {data,error}=await sb.from('organization_statements').select('*').eq('organization_id',orgId).order('period_start',{ascending:false}).limit(100);
        if(error) throw new Error(error.message); return {success:true,data:data||[]};
    }

    async getOrganizationStatement(statementId:string,actorId:string,offset=0,limit=100) {
        const sb=getAdminSupabase(); if(!sb) throw new Error('DB_OFFLINE');
        const safeOffset=Math.max(0,Math.trunc(offset)); const safeLimit=Math.min(500,Math.max(1,Math.trunc(limit)));
        const {data:statement,error}=await sb.from('organization_statements').select('*').eq('id',statementId).maybeSingle();
        if(error) throw new Error(error.message); if(!statement) throw new Error('ORGANIZATION_STATEMENT_NOT_FOUND');
        await this.assertOrganizationAccess(actorId,statement.organization_id,{allowedOrgRoles:['ADMIN','FINANCE','ACCOUNTANT','SIGNATORY']});
        const {data:lines,error:lineError}=await sb.from('organization_statement_lines').select('*').eq('statement_id',statementId).order('sequence_number',{ascending:true}).range(safeOffset,safeOffset+safeLimit-1);
        if(lineError) throw new Error(lineError.message);
        await Audit.log('FINANCIAL',actorId,'ORGANIZATION_STATEMENT_VIEWED',{statementId,organizationId:statement.organization_id,offset:safeOffset,limit:safeLimit},statementId);
        return {success:true,data:{statement,lines:lines||[],page:{offset:safeOffset,limit:safeLimit,total:statement.line_count}}};
    }

    async getBudgetAlerts(orgId: string, limit: number = 50) {
        const sb = getAdminSupabase();
        if (!sb) return [];
        const { data } = await sb.from('budget_alerts')
            .select('*, categories(name, currency), users(full_name)')
            .eq('organization_id', orgId)
            .order('created_at', { ascending: false })
            .limit(limit);
        return data || [];
    }

    // --- RECONCILIATION ENGINE ---
    async runFullReconciliation(actorId?: string, reason?: string) {
        await Audit.log('ADMIN', actorId || 'SYSTEM', 'RECONCILIATION_RUN_REQUESTED', {
            reason: reason || 'No reason supplied',
        });
        const result = await ReconEngine.runAllRecon();
        await Audit.log('ADMIN', actorId || 'SYSTEM', 'RECONCILIATION_RUN_COMPLETED', {
            reason: reason || 'No reason supplied',
        });
        return result;
    }

    async getReconciliationReports(limit: number = 50) {
        const sb = getAdminSupabase();
        if (!sb) return [];
        const { data } = await sb.from('reconciliation_reports')
            .select('*')
            .order('created_at', { ascending: false })
            .limit(limit);
        return data || [];
    }
}

export const Server = new OrbiServer();

