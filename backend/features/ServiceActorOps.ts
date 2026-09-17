import { getAdminSupabase, getSupabase } from '../supabaseClient.js';
import { ConfigClient } from '../infrastructure/RulesConfigClient.js';
import { DataVault } from '../security/encryption.js';
import { systemSettlementAccounts } from '../ledger/SystemSettlementAccountService.js';
import { platformFeeService } from '../payments/PlatformFeeService.js';
import { UUID } from '../../services/utils.js';
import { PerfMonitor } from '../infrastructure/PerfMonitor.js';
import type { AuthService } from '../../iam/authService.js';
import type { User, UserRole } from '../../types.js';
import { Messaging } from './MessagingService.js';
import { createHash } from 'crypto';
import { DEFAULT_INSTITUTIONAL_APP_ORIGIN, DEFAULT_MOBILE_APP_ORIGIN, TRUSTED_MOBILE_APP_ORIGINS } from '../config/appIdentity.js';
import { DataProtection } from '../security/DataProtection.js';
import { buildPostgrestOrFilter } from '../security/postgrest.js';

type ServiceActorRole = 'MERCHANT' | 'AGENT';

class ServiceActorOperations {
    private getDb() {
        return getAdminSupabase() || getSupabase();
    }

    private normalizeRole(role?: string): ServiceActorRole | null {
        const normalized = String(role || '').toUpperCase();
        if (normalized === 'MERCHANT' || normalized === 'AGENT') {
            return normalized;
        }
        return null;
    }

    private isSettledStatus(status?: string) {
        return ['completed', 'settled'].includes(String(status || '').toLowerCase());
    }

    private isFailedStatus(status?: string) {
        const normalized = String(status || '').toLowerCase();
        return (
            normalized.includes('fail') ||
            normalized.includes('reject') ||
            normalized.includes('declin') ||
            normalized.includes('cancel') ||
            normalized.includes('reverse') ||
            normalized.includes('error')
        );
    }

    private async resolveDisplayName(userId?: string | null) {
        const sb = this.getDb();
        if (!sb || !userId) return null;

        const { data: user } = await sb
            .from('users')
            .select('full_name, customer_id')
            .eq('id', userId)
            .maybeSingle();

        if (user?.full_name || user?.customer_id) {
            return user.full_name || user.customer_id;
        }

        const { data: staff } = await sb
            .from('staff')
            .select('full_name, email')
            .eq('id', userId)
            .maybeSingle();

        return staff?.full_name || staff?.email || null;
    }

    private async resolveActorNotificationBrand(userId: string, role: ServiceActorRole) {
        const sb = this.getDb();
        if (!sb) return { displayName: '', senderEmail: '' };

        if (role === 'MERCHANT') {
            const { data } = await sb
                .from('merchants')
                .select('business_name, metadata')
                .eq('owner_user_id', userId)
                .maybeSingle();
            const metadata = data?.metadata && typeof data.metadata === 'object' ? data.metadata : {};
            return {
                displayName: String(data?.business_name || '').trim(),
                senderEmail: String(
                    metadata.notification_sender_email ||
                    metadata.sender_email ||
                    metadata.business_email ||
                    '',
                ).trim(),
            };
        }

        const { data } = await sb
            .from('agents')
            .select('display_name, metadata')
            .eq('user_id', userId)
            .maybeSingle();
        const metadata = data?.metadata && typeof data.metadata === 'object' ? data.metadata : {};
        return {
            displayName: String(data?.display_name || '').trim(),
            senderEmail: String(metadata.notification_sender_email || metadata.sender_email || '').trim(),
        };
    }

    private deriveNumericCode(seed: string, totalLength: number, prefix: string) {
        const hash = createHash('sha256').update(seed).digest('hex');
        let digits = '';
        for (let i = 0; i < hash.length && digits.length < totalLength - prefix.length; i += 2) {
            digits += String(parseInt(hash.slice(i, i + 2), 16) % 10);
        }
        return `${prefix}${digits}`.slice(0, totalLength);
    }

    private async generateUniqueBusinessId(
        table: 'merchants' | 'agents',
        seed: string,
        prefix: string,
        totalLength = 12,
    ) {
        const sb = this.getDb();
        if (!sb) throw new Error('DB_OFFLINE');

        for (let attempt = 0; attempt < 8; attempt++) {
            const candidate = this.deriveNumericCode(`${seed}:business:${attempt}`, totalLength, prefix);
            const { data: existing } = await sb
                .from(table)
                .select('id')
                .contains('metadata', { business_id: candidate })
                .maybeSingle();

            if (!existing?.id) {
                return candidate;
            }
        }

        throw new Error(`${table.toUpperCase()}_BUSINESS_ID_GENERATION_FAILED`);
    }

    private async generateUniqueAgentNumber(
        column: 'service_pay_number' | 'cash_withdraw_till',
        seed: string,
        totalLength: number,
        prefix: string,
    ) {
        const sb = this.getDb();
        if (!sb) throw new Error('DB_OFFLINE');

        for (let attempt = 0; attempt < 8; attempt++) {
            const candidate = this.deriveNumericCode(`${seed}:${column}:${attempt}`, totalLength, prefix);
            const { data: existing } = await sb
                .from('agents')
                .select('id')
                .eq(column, candidate)
                .maybeSingle();

            if (!existing?.id) {
                return candidate;
            }
        }

        throw new Error(`AGENT_${column.toUpperCase()}_GENERATION_FAILED`);
    }

    private async ensureAgentOperationalIdentity(
        agentId: string,
        userId: string,
        primaryWalletId?: string | null,
    ) {
        const sb = this.getDb();
        if (!sb) throw new Error('DB_OFFLINE');

        const { data: agent } = await sb
            .from('agents')
            .select('id,user_id,service_pay_number,cash_withdraw_till,service_wallet_id,commission_wallet_id,metadata')
            .eq('id', agentId)
            .maybeSingle();
        if (!agent) throw new Error('AGENT_PROFILE_NOT_FOUND');

        const { data: user } = await sb
            .from('users')
            .select('customer_id,metadata')
            .eq('id', userId)
            .maybeSingle();

        const identitySeed = `${userId}:${user?.customer_id || agentId}`;
        const servicePayNumber =
            agent.service_pay_number ||
            (await this.generateUniqueAgentNumber('service_pay_number', identitySeed, 10, '52'));
        const cashWithdrawTill =
            agent.cash_withdraw_till ||
            (await this.generateUniqueAgentNumber('cash_withdraw_till', identitySeed, 8, '71'));
        const serviceWalletId = agent.service_wallet_id || primaryWalletId || null;
        const commissionWalletId = agent.commission_wallet_id || primaryWalletId || null;
        const agentMetadata = {
            ...(agent.metadata || {}),
            operational_numbers: {
                service_pay_number: servicePayNumber,
                cash_withdraw_till: cashWithdrawTill,
            },
            wallet_links: {
                service_wallet_id: serviceWalletId,
                commission_wallet_id: commissionWalletId,
            },
        };

        const { error: updateAgentError } = await sb
            .from('agents')
            .update({
                service_pay_number: servicePayNumber,
                cash_withdraw_till: cashWithdrawTill,
                service_wallet_id: serviceWalletId,
                commission_wallet_id: commissionWalletId,
                metadata: agentMetadata,
                updated_at: new Date().toISOString(),
            })
            .eq('id', agentId);
        if (updateAgentError) {
            throw new Error(`AGENT_OPERATIONAL_IDENTITY_UPDATE_FAILED: ${updateAgentError.message}`);
        }

        const adminSb = getAdminSupabase();
        if (adminSb) {
            const { data: authUserResult, error: authUserError } = await adminSb.auth.admin.getUserById(userId);
            if (authUserError) throw new Error(authUserError.message);

            const currentMetadata = authUserResult?.user?.user_metadata || {};
            const updatedUserMetadata = {
                ...(user?.metadata || {}),
                service_actor_identity: {
                    ...(user?.metadata?.service_actor_identity || {}),
                    agent: {
                        service_pay_number: servicePayNumber,
                        cash_withdraw_till: cashWithdrawTill,
                        service_wallet_id: serviceWalletId,
                        commission_wallet_id: commissionWalletId,
                    },
                },
            };

            await sb.from('users').update({ metadata: updatedUserMetadata }).eq('id', userId);

            const { error: updateAuthError } = await adminSb.auth.admin.updateUserById(userId, {
                user_metadata: {
                    ...currentMetadata,
                    agent_service_pay_number: servicePayNumber,
                    agent_cash_withdraw_till: cashWithdrawTill,
                    agent_service_wallet_id: serviceWalletId,
                    agent_commission_wallet_id: commissionWalletId,
                },
            });
            if (updateAuthError) throw new Error(updateAuthError.message);
        }

        return {
            servicePayNumber,
            cashWithdrawTill,
            serviceWalletId,
            commissionWalletId,
        };
    }

    private async notifyServiceCustomerRegistration(actorId: string, actorRole: ServiceActorRole, customerUserId: string) {
        const customerName = (await this.resolveDisplayName(customerUserId)) || 'Customer';
        const actorBrand = await this.resolveActorNotificationBrand(actorId, actorRole);

        await Promise.allSettled([
            Messaging.dispatchServiceActivity(
                actorId,
                'SERVICE_CUSTOMER_REGISTERED',
                {
                    actorLabel: actorBrand.displayName,
                    senderEmail: actorBrand.senderEmail,
                    customerName,
                },
                'info',
            ),
            Messaging.dispatchServiceActivity(
                customerUserId,
                'SERVICE_CUSTOMER_ONBOARDED',
                {
                    actorLabel: actorBrand.displayName,
                    senderEmail: actorBrand.senderEmail,
                    customerName,
                },
                'info',
            ),
        ]);
    }

    private async notifyTransactionLifecycle(transaction: any, status: string) {
        const metadata = transaction?.metadata || {};
        const serviceContext = metadata.service_context;
        const actorUserId = metadata.merchant_actor_id || metadata.agent_actor_id;
        if (!actorUserId || !serviceContext) return;

        const counterpartyUserId = await this.resolveCounterpartyUserId(transaction, actorUserId);

        const amount =
            Number(
                typeof transaction.amount === 'string'
                    ? await DataProtection.decryptAmount(transaction.amount)
                    : transaction.amount || 0,
            ) || 0;

        if (serviceContext === 'MERCHANT') {
            const storedBrand = await this.resolveActorNotificationBrand(actorUserId, 'MERCHANT');
            const actorLabel =
                String(metadata.merchant_name || metadata.business_name || '').trim() ||
                storedBrand.displayName;
            const senderEmail =
                String(metadata.notification_sender_email || metadata.sender_email || metadata.business_email || '').trim() ||
                storedBrand.senderEmail;
            const event = this.isSettledStatus(status)
                ? 'MERCHANT_PAYMENT_COMPLETED'
                : this.isFailedStatus(status)
                  ? 'MERCHANT_PAYMENT_FAILED'
                  : 'MERCHANT_PAYMENT_PENDING';

            await Messaging.dispatchServiceActivity(actorUserId, event, {
                actorLabel,
                senderEmail,
                amount,
                currency: transaction.currency || 'TZS',
                status,
                refId: transaction.reference_id || transaction.referenceId || transaction.id,
            });

            if (counterpartyUserId && counterpartyUserId !== actorUserId) {
                const customerEvent = this.isSettledStatus(status)
                    ? 'MERCHANT_CUSTOMER_PAYMENT_COMPLETED'
                    : this.isFailedStatus(status)
                      ? 'MERCHANT_CUSTOMER_PAYMENT_FAILED'
                      : 'MERCHANT_CUSTOMER_PAYMENT_PENDING';
                await Messaging.dispatchServiceActivity(counterpartyUserId, customerEvent, {
                    actorLabel,
                    senderEmail,
                    amount,
                    currency: transaction.currency || 'TZS',
                    status,
                    refId: transaction.reference_id || transaction.referenceId || transaction.id,
                });
            }
            return;
        }

        if (serviceContext === 'AGENT_CASH') {
            const storedBrand = await this.resolveActorNotificationBrand(actorUserId, 'AGENT');
            const actorLabel =
                String(metadata.agent_name || metadata.display_name || '').trim() ||
                storedBrand.displayName;
            const senderEmail =
                String(metadata.notification_sender_email || metadata.sender_email || '').trim() ||
                storedBrand.senderEmail;
            const event = this.isSettledStatus(status)
                ? 'AGENT_CASH_COMPLETED'
                : this.isFailedStatus(status)
                  ? 'AGENT_CASH_FAILED'
                  : 'AGENT_CASH_PENDING';

            await Messaging.dispatchServiceActivity(actorUserId, event, {
                actorLabel,
                senderEmail,
                amount,
                currency: transaction.currency || 'TZS',
                direction: metadata.cash_direction || 'deposit',
                status,
                refId: transaction.reference_id || transaction.referenceId || transaction.id,
            });

            if (counterpartyUserId && counterpartyUserId !== actorUserId) {
                const customerEvent = this.isSettledStatus(status)
                    ? 'AGENT_CUSTOMER_CASH_COMPLETED'
                    : this.isFailedStatus(status)
                      ? 'AGENT_CUSTOMER_CASH_FAILED'
                      : 'AGENT_CUSTOMER_CASH_PENDING';
                await Messaging.dispatchServiceActivity(counterpartyUserId, customerEvent, {
                    actorLabel,
                    senderEmail,
                    amount,
                    currency: transaction.currency || 'TZS',
                    direction: metadata.cash_direction || 'deposit',
                    status,
                    refId: transaction.reference_id || transaction.referenceId || transaction.id,
                });
            }
        }
    }

    private async resolveCounterpartyUserId(transaction: any, actorUserId: string) {
        const sb = this.getDb();
        if (!sb) return null;

        const candidateWalletIds = [transaction?.to_wallet_id, transaction?.wallet_id, transaction?.from_wallet_id]
            .filter((value, index, arr) => Boolean(value) && arr.indexOf(value) === index);

        if (candidateWalletIds.length === 0) {
            return null;
        }

        const { data: wallets } = await sb
            .from('wallets')
            .select('id,user_id')
            .in('id', candidateWalletIds);

        const walletMap = new Map((wallets || []).map((wallet: any) => [wallet.id, wallet.user_id]));
        for (const walletId of candidateWalletIds) {
            const userId = walletMap.get(walletId);
            if (userId && userId !== actorUserId) return userId;
        }
        return null;
    }

    private async resolvePrimaryWallet(userId: string) {
        const sb = this.getDb();
        if (!sb) return null;

        const { data } = await sb
            .from('wallets')
            .select('id,currency')
            .eq('user_id', userId)
            .eq('status', 'active')
            .order('is_primary', { ascending: false })
            .order('created_at', { ascending: true })
            .limit(1);

        return data?.[0] || null;
    }

    private async ensureMerchantProfile(actor: any) {
        const sb = this.getDb();
        if (!sb) throw new Error('DB_OFFLINE');

        const actorId = actor?.id || actor?.sub;
        const businessName =
            actor?.user_metadata?.business_name ||
            actor?.user_metadata?.merchant_name ||
            actor?.full_name ||
            actor?.user_metadata?.full_name ||
            'Merchant Account';

        const { data: existing } = await sb
            .from('merchants')
            .select('id,business_name,status,metadata,created_at,updated_at')
            .eq('owner_user_id', actorId)
            .maybeSingle();

        const businessId =
            existing?.metadata?.business_id ||
            (await this.generateUniqueBusinessId('merchants', `${actorId}:${businessName}`, '31'));

        if (existing) {
            const nextMetadata = {
                ...(existing.metadata || {}),
                actor_role: 'MERCHANT',
                business_type: actor?.user_metadata?.business_type || existing.metadata?.business_type || 'general',
                business_id: businessId,
            };

            const nextBusinessName = existing.business_name || businessName;
            const nextStatus = existing.status || 'active';

            if (
                JSON.stringify(nextMetadata) !== JSON.stringify(existing.metadata || {}) ||
                nextBusinessName !== existing.business_name ||
                nextStatus !== existing.status
            ) {
                const { data: updated, error: updateError } = await sb
                    .from('merchants')
                    .update({
                        business_name: nextBusinessName,
                        status: nextStatus,
                        metadata: nextMetadata,
                        updated_at: new Date().toISOString(),
                    })
                    .eq('id', existing.id)
                    .select('id,business_name,status,metadata,created_at,updated_at')
                    .single();
                if (updateError) throw new Error(`MERCHANT_PROFILE_UPDATE_FAILED: ${updateError.message}`);
                return updated;
            }

            return {
                ...existing,
                business_name: nextBusinessName,
                status: nextStatus,
                metadata: nextMetadata,
            };
        }

        const payload = {
            business_name: businessName,
            owner_user_id: actorId,
            status: 'active',
            metadata: {
                actor_role: 'MERCHANT',
                business_type: actor?.user_metadata?.business_type || 'general',
                business_id: businessId,
            },
        };

        const { data, error } = await sb
            .from('merchants')
            .insert(payload)
            .select('id,business_name,status,metadata,created_at,updated_at')
            .single();
        if (error) throw new Error(`MERCHANT_PROFILE_CREATE_FAILED: ${error.message}`);
        return data;
    }

    private async ensureAgentProfile(actor: any) {
        const sb = this.getDb();
        if (!sb) throw new Error('DB_OFFLINE');

        const actorId = actor?.id || actor?.sub;
        const displayName =
            actor?.user_metadata?.agency_name ||
            actor?.full_name ||
            actor?.user_metadata?.full_name ||
            'Agent Operator';

        const { data: existing } = await sb
            .from('agents')
            .select('id,user_id,display_name,status,service_pay_number,cash_withdraw_till,service_wallet_id,commission_wallet_id,metadata,created_at,updated_at')
            .eq('user_id', actorId)
            .maybeSingle();

        const businessId =
            existing?.metadata?.business_id ||
            (await this.generateUniqueBusinessId('agents', `${actorId}:${displayName}`, '41'));

        if (existing) {
            const nextMetadata = {
                ...(existing.metadata || {}),
                actor_role: 'AGENT',
                branch: actor?.user_metadata?.branch || existing.metadata?.branch || null,
                business_id: businessId,
            };
            if (JSON.stringify(nextMetadata) !== JSON.stringify(existing.metadata || {})) {
                const { data: updated, error: updateError } = await sb
                    .from('agents')
                    .update({
                        metadata: nextMetadata,
                        updated_at: new Date().toISOString(),
                    })
                    .eq('id', existing.id)
                    .select('id,user_id,display_name,status,service_pay_number,cash_withdraw_till,service_wallet_id,commission_wallet_id,metadata,created_at,updated_at')
                    .single();
                if (updateError) throw new Error(`AGENT_PROFILE_UPDATE_FAILED: ${updateError.message}`);
                return updated;
            }
            return {
                ...existing,
                metadata: nextMetadata,
            };
        }

        const { data, error } = await sb
            .from('agents')
            .insert({
                user_id: actorId,
                display_name: displayName,
                status: 'active',
                commission_enabled: true,
                service_pay_number: null,
                cash_withdraw_till: null,
                service_wallet_id: null,
                commission_wallet_id: null,
                metadata: {
                    actor_role: 'AGENT',
                    branch: actor?.user_metadata?.branch || null,
                    business_id: businessId,
                },
            })
            .select('id,user_id,display_name,status,service_pay_number,cash_withdraw_till,service_wallet_id,commission_wallet_id,metadata,created_at,updated_at')
            .single();

        if (error) throw new Error(`AGENT_PROFILE_CREATE_FAILED: ${error.message}`);
        return data;
    }

    private async syncMerchantWallets(userId: string) {
        const sb = this.getDb();
        if (!sb) return [];

        const merchant = await this.ensureMerchantProfile({ id: userId });
        const { data: baseWallets } = await sb
            .from('wallets')
            .select('id,name,type,is_primary,balance,currency,status,management_tier')
            .eq('user_id', userId)
            .eq('status', 'active');

        for (const wallet of baseWallets || []) {
            const { data: existing } = await sb
                .from('merchant_wallets')
                .select('id')
                .eq('merchant_id', merchant.id)
                .eq('base_wallet_id', wallet.id)
                .maybeSingle();

            const payload = {
                merchant_id: merchant.id,
                owner_user_id: userId,
                base_wallet_id: wallet.id,
                name: wallet.name,
                wallet_type: wallet.type || 'operating',
                is_primary: wallet.is_primary === true,
                balance: Number(wallet.balance || 0),
                currency: wallet.currency || 'TZS',
                status: wallet.status || 'active',
                metadata: {
                    management_tier: wallet.management_tier,
                    source_wallet_id: wallet.id,
                },
                updated_at: new Date().toISOString(),
            };

            if (existing?.id) {
                await sb.from('merchant_wallets').update(payload).eq('id', existing.id);
            } else {
                await sb.from('merchant_wallets').insert(payload);
            }
        }

        const { data } = await sb
            .from('merchant_wallets')
            .select('*')
            .eq('owner_user_id', userId)
            .order('is_primary', { ascending: false })
            .order('created_at', { ascending: true });

        return data || [];
    }

    private async syncAgentWallets(userId: string) {
        const sb = this.getDb();
        if (!sb) return [];

        const agent = await this.ensureAgentProfile({ id: userId });
        const { data: baseWallets } = await sb
            .from('wallets')
            .select('id,name,type,is_primary,balance,currency,status,management_tier')
            .eq('user_id', userId)
            .eq('status', 'active');

        const primaryBaseWallet =
            (baseWallets || []).find((wallet: any) => wallet.is_primary === true) ||
            (baseWallets || [])[0] ||
            null;
        const operationalIdentity = await this.ensureAgentOperationalIdentity(
            agent.id,
            userId,
            primaryBaseWallet?.id || null,
        );

        for (const wallet of baseWallets || []) {
            const { data: existing } = await sb
                .from('agent_wallets')
                .select('id')
                .eq('agent_id', agent.id)
                .eq('base_wallet_id', wallet.id)
                .maybeSingle();

            const payload = {
                agent_id: agent.id,
                owner_user_id: userId,
                base_wallet_id: wallet.id,
                name: wallet.name,
                wallet_type: wallet.type || 'operating',
                is_primary: wallet.is_primary === true,
                balance: Number(wallet.balance || 0),
                currency: wallet.currency || 'TZS',
                status: wallet.status || 'active',
                metadata: {
                    management_tier: wallet.management_tier,
                    source_wallet_id: wallet.id,
                    service_pay_number: operationalIdentity.servicePayNumber,
                    cash_withdraw_till: operationalIdentity.cashWithdrawTill,
                    wallet_link_role:
                        wallet.id === operationalIdentity.serviceWalletId ? 'agent_service_float' : 'linked',
                    handles_commissions: wallet.id === operationalIdentity.commissionWalletId,
                },
                updated_at: new Date().toISOString(),
            };

            if (existing?.id) {
                await sb.from('agent_wallets').update(payload).eq('id', existing.id);
            } else {
                await sb.from('agent_wallets').insert(payload);
            }
        }

        const { data } = await sb
            .from('agent_wallets')
            .select('*')
            .eq('owner_user_id', userId)
            .order('is_primary', { ascending: false })
            .order('created_at', { ascending: true });

        return (data || []).map((wallet: any) => ({
            ...wallet,
            service_pay_number: operationalIdentity.servicePayNumber,
            cash_withdraw_till: operationalIdentity.cashWithdrawTill,
            service_wallet_id: operationalIdentity.serviceWalletId,
            commission_wallet_id: operationalIdentity.commissionWalletId,
        }));
    }

    public async getMerchantWallets(userId: string) {
        return this.syncMerchantWallets(userId);
    }

    public async getAgentWallets(userId: string) {
        return this.syncAgentWallets(userId);
    }

    public async lookupAgentByCode(query: string) {
        const sb = this.getDb();
        if (!sb) throw new Error('DB_OFFLINE');

        const normalized = String(query || '').replace(/\D/g, '').trim();
        if (normalized.length < 4) {
            throw new Error('AGENT_LOOKUP_MIN_4_DIGITS');
        }

        const { data: agents, error } = await sb
            .from('agents')
            .select('id,user_id,display_name,status,service_pay_number,cash_withdraw_till,metadata')
            .eq('status', 'active')
            .or(buildPostgrestOrFilter([
                { column: 'cash_withdraw_till', operator: 'ilike', value: normalized },
                { column: 'service_pay_number', operator: 'ilike', value: normalized },
            ]))
            .limit(12);
        if (error) throw new Error(error.message);

        const items = agents || [];
        if (items.length == 0) throw new Error('AGENT_NOT_FOUND');

        let bestMatch: any = null;
        let bestScore = -1;
        for (const agent of items) {
            const till = String(agent.cash_withdraw_till || '');
            const serviceNo = String(agent.service_pay_number || '');
            let score = 0;
            if (till === normalized) score += 500;
            if (serviceNo === normalized) score += 450;
            if (till.startsWith(normalized)) score += 320;
            if (serviceNo.startsWith(normalized)) score += 300;
            if (till.endsWith(normalized)) score += 240;
            if (serviceNo.endsWith(normalized)) score += 220;
            if (till.includes(normalized)) score += 160;
            if (serviceNo.includes(normalized)) score += 150;
            if (score > bestScore) {
                bestMatch = agent;
                bestScore = score;
            }
        }

        if (!bestMatch) throw new Error('AGENT_NOT_FOUND');

        const { data: user } = await sb
            .from('users')
            .select('full_name,customer_id')
            .eq('id', bestMatch.user_id)
            .maybeSingle();

        return {
            agent_id: bestMatch.id,
            display_name:
                bestMatch.display_name ||
                user?.full_name ||
                user?.customer_id ||
                'ORBI Agent',
            status: bestMatch.status || 'active',
            service_pay_number: bestMatch.service_pay_number || '',
            cash_withdraw_till: bestMatch.cash_withdraw_till || '',
            branch: bestMatch?.metadata?.branch || '',
            matched_query: normalized,
        };
    }

    public async provisionApprovedActorAccess(userId: string, actorRole: ServiceActorRole, actorContext: any = {}) {
        if (actorRole === 'MERCHANT') {
            const merchant = await this.ensureMerchantProfile({
                id: userId,
                user_metadata: {
                    business_name: actorContext.business_name || actorContext.businessName,
                    merchant_name: actorContext.business_name || actorContext.businessName,
                    business_type: actorContext.business_type || actorContext.businessType,
                    ...(actorContext.metadata || {}),
                },
            });
            const wallets = await this.syncMerchantWallets(userId);
            const primaryWallet =
                wallets.find((wallet: any) => wallet.is_primary) ||
                wallets[0] ||
                null;
            return {
                actor_role: 'MERCHANT',
                merchant_id: merchant.id,
                business_name: merchant.business_name || 'Merchant Account',
                business_id: merchant.metadata?.business_id || null,
                status: merchant.status || 'active',
                primary_wallet_id: primaryWallet?.id || null,
                base_wallet_id: primaryWallet?.base_wallet_id || null,
                merchant_wallet_ids: wallets.map((wallet: any) => wallet.id).filter(Boolean),
                created_at: merchant.created_at || null,
                updated_at: merchant.updated_at || null,
            };
        }

        const agent = await this.ensureAgentProfile({ id: userId });
        const wallets = await this.syncAgentWallets(userId);
        const primaryWallet =
            wallets.find((wallet: any) => wallet.is_primary) ||
            wallets[0] ||
            null;
        const operationalIdentity = await this.ensureAgentOperationalIdentity(
            agent.id,
            userId,
            primaryWallet?.base_wallet_id || primaryWallet?.id || null,
        );

        return {
            actor_role: 'AGENT',
            agent_id: agent.id,
            display_name: agent.display_name || 'Agent Operator',
            business_id: agent.metadata?.business_id || null,
            status: agent.status || 'active',
            service_pay_number: operationalIdentity.servicePayNumber,
            cash_withdraw_till: operationalIdentity.cashWithdrawTill,
            service_wallet_id: operationalIdentity.serviceWalletId,
            commission_wallet_id: operationalIdentity.commissionWalletId,
            created_at: agent.created_at || null,
            updated_at: agent.updated_at || null,
        };
    }

    public async getMerchantTransactions(userId: string, limit = 50, offset = 0) {
        const sb = this.getDb();
        if (!sb) return [];

        return await PerfMonitor.track(`ServiceActorOps.getMerchantTransactions:${userId}:${limit}:${offset}`, async () => {
            const { data } = await sb
                .from('merchant_transactions')
                .select('*')
                .eq('owner_user_id', userId)
                .order('created_at', { ascending: false })
                .range(offset, offset + limit - 1);

            return data || [];
        });
    }

    public async getAgentTransactions(userId: string, limit = 50, offset = 0) {
        const sb = this.getDb();
        if (!sb) return [];

        return await PerfMonitor.track(`ServiceActorOps.getAgentTransactions:${userId}:${limit}:${offset}`, async () => {
            const { data } = await sb
                .from('agent_transactions')
                .select('*')
                .eq('owner_user_id', userId)
                .order('created_at', { ascending: false })
                .range(offset, offset + limit - 1);

            return data || [];
        });
    }

    public async registerCustomerByActor(
        actor: any,
        actorRole: ServiceActorRole,
        payload: any,
        auth: AuthService,
    ) {
        const sb = this.getDb();
        if (!sb) throw new Error('DB_OFFLINE');

        const actorId = actor?.id || actor?.sub;
        const actorMetadata = actor?.user_metadata || {};
        const appOrigin =
            TRUSTED_MOBILE_APP_ORIGINS.includes(String(actorMetadata.app_origin || '').trim())
                ? DEFAULT_MOBILE_APP_ORIGIN
                : DEFAULT_INSTITUTIONAL_APP_ORIGIN;

        const result = await auth.signUp(payload.email || '', payload.password, {
            full_name: payload.full_name,
            phone: payload.phone,
            nationality: payload.nationality,
            address: payload.address,
            currency: payload.currency || 'TZS',
            language: payload.language || 'en',
            role: 'USER',
            registry_type: 'CONSUMER',
            app_origin: appOrigin,
            created_by_actor_id: actorId,
            created_by_actor_role: actorRole,
            created_via_service_actor: true,
        });

        if (result?.error) {
            throw new Error(result.error.message || result.error);
        }

        const createdUserId = result?.data?.user?.id;
        if (!createdUserId) {
            throw new Error('CUSTOMER_REGISTRATION_FAILED');
        }

        const { data: createdProfile } = await sb
            .from('users')
            .select('id, customer_id')
            .eq('id', createdUserId)
            .single();

        const commissionConfig = await this.getCommissionConfig();
        const referralDays = Number(commissionConfig.agent_referral?.duration_days || 0);
        const commissionExpiry =
            actorRole === 'AGENT' && referralDays > 0
                ? new Date(Date.now() + referralDays * 86400000).toISOString()
                : null;

        await sb.from('service_actor_customer_links').upsert(
            {
                actor_user_id: actorId,
                actor_role: actorRole,
                actor_registry_type: actorRole,
                customer_user_id: createdUserId,
                customer_customer_id: createdProfile?.customer_id || null,
                relationship_type: actorRole === 'AGENT' ? 'agent_registered_customer' : 'merchant_registered_customer',
                status: 'active',
                commission_enabled: actorRole === 'AGENT',
                commission_started_at: new Date().toISOString(),
                commission_expires_at: commissionExpiry,
                metadata: {
                    created_from_role: actorRole,
                    channel: 'service_actor_registration',
                },
                created_by: actorId,
                updated_at: new Date().toISOString(),
            },
            { onConflict: 'actor_user_id,customer_user_id' },
        );

        await this.notifyServiceCustomerRegistration(actorId, actorRole, createdUserId);

        return {
            user: result.data.user,
            session: result.data.session || null,
            linked_customer: createdProfile,
            commission_expires_at: commissionExpiry,
        };
    }

    public async getLinkedCustomers(actorUserId?: string, actorRole?: string) {
        const sb = this.getDb();
        if (!sb) return [];

        let query = sb
            .from('service_actor_customer_links')
            .select('*')
            .order('created_at', { ascending: false });

        if (actorUserId) {
            query = query.eq('actor_user_id', actorUserId);
        }
        if (actorRole) {
            query = query.eq('actor_role', actorRole);
        }

        const { data: links } = await query;
        const customerIds = [...new Set((links || []).map((link: any) => link.customer_user_id).filter(Boolean))];
        const { data: customers } =
            customerIds.length > 0
                ? await sb.from('users').select('id,full_name,email,phone,customer_id,account_status,kyc_status').in('id', customerIds)
                : { data: [] as any[] };

        const customerMap = new Map((customers || []).map((customer: any) => [customer.id, customer]));
        return (links || []).map((link: any) => ({
            ...link,
            customer: customerMap.get(link.customer_user_id) || null,
        }));
    }

    public async getServiceCommissions(actorUserId?: string, actorRole?: string) {
        const sb = this.getDb();
        if (!sb) return [];

        let query = sb
            .from('service_commissions')
            .select('*')
            .order('created_at', { ascending: false });

        if (actorUserId) {
            query = query.eq('actor_user_id', actorUserId);
        }
        if (actorRole) {
            query = query.eq('actor_role', actorRole);
        }

        const { data } = await query;
        return data || [];
    }

    private async getCommissionConfig() {
        const config = await ConfigClient.getRuleConfig();
        return config?.commission_programs || {};
    }

    public async handleTransactionPosted(actor: any, payload: any, transaction: any) {
        try {
            await this.syncOperationalTables(transaction);
            await this.stageTransactionCommissions(actor, payload, transaction);
        } catch (e: any) {
            console.error(`[ServiceActorOps] Post-transaction hook failed for ${transaction?.id}: ${e.message}`);
        }
    }

    public async handleTransactionStatusChange(txId: string, status: string) {
        const sb = this.getDb();
        if (!sb) return;

        const { data: tx } = await sb.from('transactions').select('*').eq('id', txId).maybeSingle();
        if (!tx) return;

        await this.syncOperationalTables(tx);
        await this.notifyTransactionLifecycle(tx, status);

        if (!this.isSettledStatus(status)) {
            return;
        }

        await this.finalizePendingCommissions(tx);
    }

    private async syncOperationalTables(transaction: any) {
        const serviceContext = transaction?.metadata?.service_context;
        if (serviceContext === 'MERCHANT') {
            await this.upsertMerchantTransaction(transaction);
        }
        if (serviceContext === 'AGENT_CASH') {
            await this.upsertAgentTransaction(transaction);
        }
    }

    private async upsertMerchantTransaction(transaction: any) {
        const sb = this.getDb();
        if (!sb) return;

        const ownerUserId = transaction?.metadata?.merchant_actor_id || transaction?.user_id;
        if (!ownerUserId) return;

        const merchant = await this.ensureMerchantProfile({ id: ownerUserId });
        const wallets = await this.syncMerchantWallets(ownerUserId);
        const primaryWallet =
            wallets.find((wallet: any) => wallet.base_wallet_id === transaction.wallet_id) ||
            wallets.find((wallet: any) => wallet.is_primary) ||
            wallets[0];

        await sb.from('merchant_transactions').upsert(
            {
                transaction_id: transaction.id,
                merchant_id: merchant.id,
                owner_user_id: ownerUserId,
                merchant_wallet_id: primaryWallet?.id || null,
                customer_user_id: transaction.user_id,
                direction:
                    transaction.type === 'withdrawal' || transaction.type === 'expense' ? 'outbound' : 'inbound',
                amount: await DataProtection.decryptAmount(transaction.amount || 0),
                currency: transaction.currency || 'TZS',
                status: transaction.status,
                service_type: 'merchant_payment',
                metadata: transaction.metadata || {},
                updated_at: new Date().toISOString(),
            },
            { onConflict: 'transaction_id' },
        );
    }

    private async upsertAgentTransaction(transaction: any) {
        const sb = this.getDb();
        if (!sb) return;

        const ownerUserId = transaction?.metadata?.agent_actor_id || transaction?.user_id;
        if (!ownerUserId) return;

        const agent = await this.ensureAgentProfile({ id: ownerUserId });
        const wallets = await this.syncAgentWallets(ownerUserId);
        const primaryWallet =
            wallets.find((wallet: any) => wallet.base_wallet_id === transaction.wallet_id) ||
            wallets.find((wallet: any) => wallet.is_primary) ||
            wallets[0];

        await sb.from('agent_transactions').upsert(
            {
                transaction_id: transaction.id,
                agent_id: agent.id,
                owner_user_id: ownerUserId,
                agent_wallet_id: primaryWallet?.id || null,
                customer_user_id: transaction.user_id,
                direction: transaction?.metadata?.cash_direction === 'withdrawal' ? 'outbound' : 'inbound',
                amount: await DataProtection.decryptAmount(transaction.amount || 0),
                currency: transaction.currency || 'TZS',
                status: transaction.status,
                service_type:
                    transaction?.metadata?.cash_direction === 'withdrawal'
                        ? 'agent_cash_withdrawal'
                        : 'agent_cash_deposit',
                metadata: transaction.metadata || {},
                updated_at: new Date().toISOString(),
            },
            { onConflict: 'transaction_id' },
        );
    }

    private async stageTransactionCommissions(actor: any, payload: any, transaction: any) {
        const actorRole = this.normalizeRole(actor?.role || actor?.user_metadata?.role);
        const serviceContext = payload?.metadata?.service_context || transaction?.metadata?.service_context;

        if (serviceContext === 'AGENT_CASH' && actorRole === 'AGENT') {
            await this.createOrFinalizeCommission(transaction, actor.id, 'AGENT', 'AGENT_CASH');
            return;
        }

        const referralLink = await this.getActiveReferralLink(transaction?.user_id);
        if (!referralLink) {
            return;
        }

        await this.createOrFinalizeCommission(transaction, referralLink.actor_user_id, 'AGENT', 'AGENT_REFERRAL', referralLink);
    }

    private async getActiveReferralLink(customerUserId?: string) {
        const sb = this.getDb();
        if (!sb || !customerUserId) return null;

        const now = new Date().toISOString();
        const { data } = await sb
            .from('service_actor_customer_links')
            .select('*')
            .eq('customer_user_id', customerUserId)
            .eq('actor_role', 'AGENT')
            .eq('status', 'active')
            .eq('commission_enabled', true)
            .or(`commission_expires_at.is.null,commission_expires_at.gte.${now}`)
            .order('created_at', { ascending: true })
            .limit(1);

        return data?.[0] || null;
    }

    private async createOrFinalizeCommission(
        transaction: any,
        actorUserId: string,
        actorRole: ServiceActorRole,
        commissionMode: 'AGENT_REFERRAL' | 'AGENT_CASH',
        referralLink?: any,
    ) {
        const sb = this.getDb();
        if (!sb) return;

        const existing = await sb
            .from('service_commissions')
            .select('*')
            .eq('source_transaction_id', transaction.id)
            .eq('actor_user_id', actorUserId)
            .eq('commission_type', commissionMode)
            .maybeSingle();

        const sourceAmount = Number(
            typeof transaction.amount === 'string' ? await DataProtection.decryptAmount(transaction.amount) : transaction.amount || 0,
        );
        let rate = 0;
        let fixedAmount = 0;
        let effectiveUntil: string | null = null;
        const txCurrency = String(transaction.currency || '').trim().toUpperCase();
        if (!txCurrency) {
            throw new Error(`COMMISSION_CURRENCY_REQUIRED:${transaction.id}`);
        }
        const cashDirection =
            transaction?.metadata?.cash_direction === 'withdrawal' ? 'withdrawal' : 'deposit';
        const commissionFlowCode =
            commissionMode === 'AGENT_REFERRAL' ? 'AGENT_REFERRAL_COMMISSION' : 'AGENT_CASH_COMMISSION';

        if (commissionMode === 'AGENT_REFERRAL') {
            effectiveUntil = referralLink?.commission_expires_at || null;
        }

        const feeResult = await platformFeeService.resolveFee({
            flowCode: commissionFlowCode,
            amount: sourceAmount,
            currency: txCurrency,
            direction: cashDirection,
            transactionType: String(transaction?.type || '').trim().toUpperCase(),
            metadata: {
                service_context: transaction?.metadata?.service_context || null,
                source_transaction_id: transaction.id,
                commission_mode: commissionMode,
            },
        });

        rate = feeResult.percentageRate;
        fixedAmount = feeResult.fixedAmount;
        const commissionAmount = Math.max(0, Number(feeResult.totalFee.toFixed(2)));
        if (commissionAmount <= 0) {
            return;
        }

        const payload = {
            actor_user_id: actorUserId,
            actor_role: actorRole,
            customer_user_id: referralLink?.customer_user_id || transaction.user_id || null,
            source_transaction_id: transaction.id,
            commission_type: commissionMode,
            amount: commissionAmount,
            currency: txCurrency,
            rate,
            fixed_amount: fixedAmount,
            status: this.isSettledStatus(transaction.status) ? 'ready_for_payout' : 'pending_source_settlement',
            effective_from: new Date().toISOString(),
            effective_until: effectiveUntil,
            metadata: {
                source_transaction_status: transaction.status,
                source_transaction_type: transaction.type,
                source_context: transaction?.metadata?.service_context || null,
                referral_link_id: referralLink?.id || null,
                fee_config_id: feeResult.configId || null,
                fee_flow_code: feeResult.flowCode,
            },
            updated_at: new Date().toISOString(),
        };

        const commission = existing.data?.id
            ? (
                  await sb
                      .from('service_commissions')
                      .update(payload)
                      .eq('id', existing.data.id)
                      .select('*')
                      .single()
              ).data
            : (
                  await sb
                      .from('service_commissions')
                      .insert(payload)
                      .select('*')
                      .single()
              ).data;

        if (this.isSettledStatus(transaction.status) && commission) {
            await this.payoutCommission(commission);
        }
    }

    private async finalizePendingCommissions(transaction: any) {
        const sb = this.getDb();
        if (!sb) return;

        const { data: pending } = await sb
            .from('service_commissions')
            .select('*')
            .eq('source_transaction_id', transaction.id)
            .in('status', ['pending_source_settlement', 'ready_for_payout']);

        for (const commission of pending || []) {
            await this.payoutCommission(commission);
        }
    }

    private async payoutCommission(commission: any) {
        const sb = this.getDb();
        if (!sb) return;

        if (commission?.payout_transaction_id || commission?.status === 'paid') {
            return;
        }

        const actorWallet = await this.resolvePrimaryWallet(commission.actor_user_id);
        if (!actorWallet) {
            await sb
                .from('service_commissions')
                .update({
                    status: 'awaiting_wallet',
                    updated_at: new Date().toISOString(),
                })
                .eq('id', commission.id);
            return;
        }

        const commissionCurrency = String(commission.currency || actorWallet.currency || '').trim().toUpperCase();
        if (String(actorWallet.currency || '').trim().toUpperCase() !== commissionCurrency) {
            throw new Error(`COMMISSION_WALLET_CURRENCY_MISMATCH:${commissionCurrency}`);
        }
        const feeCollectorId = await systemSettlementAccounts.resolve('COMMISSION_RESERVE', commissionCurrency);
        const txReference = `COMM-${UUID.generateShortCode(12)}`;
        const { TransactionService } = await import('../../ledger/transactionService.js');
        const txService = new TransactionService();

        await txService.postTransactionWithLedger(
            {
                referenceId: txReference,
                user_id: commission.actor_user_id,
                walletId: feeCollectorId,
                toWalletId: actorWallet.id,
                amount: Number(commission.amount),
                currency: commission.currency || actorWallet.currency || 'TZS',
                description: `Service commission payout for ${commission.commission_type}`,
                type: 'fee',
                status: 'completed',
                date: new Date().toISOString(),
                metadata: {
                    service_context: 'SERVICE_COMMISSION',
                    commission_id: commission.id,
                    commission_type: commission.commission_type,
                    source_transaction_id: commission.source_transaction_id,
                    payout_to_user_id: commission.actor_user_id,
                },
            },
            [
                {
                    transactionId: txReference,
                    walletId: feeCollectorId,
                    type: 'DEBIT',
                    amount: Number(commission.amount),
                    currency: commission.currency || actorWallet.currency || 'TZS',
                    description: `Commission reserve release: ${commission.id}`,
                    timestamp: new Date().toISOString(),
                },
                {
                    transactionId: txReference,
                    walletId: actorWallet.id,
                    type: 'CREDIT',
                    amount: Number(commission.amount),
                    currency: commission.currency || actorWallet.currency || 'TZS',
                    description: `Commission payout credit: ${commission.id}`,
                    timestamp: new Date().toISOString(),
                },
            ],
        );

        const { data: payoutTx } = await sb
            .from('transactions')
            .select('id')
            .eq('reference_id', txReference)
            .maybeSingle();

        await sb
            .from('service_commissions')
            .update({
                payout_transaction_id: payoutTx?.id || null,
                status: 'paid',
                updated_at: new Date().toISOString(),
            })
            .eq('id', commission.id);

        await Messaging.dispatchServiceActivity(
            commission.actor_user_id,
            'AGENT_COMMISSION_PAID',
            {
                actorLabel: (await this.resolveActorNotificationBrand(commission.actor_user_id, 'AGENT')).displayName,
                amount: Number(commission.amount || 0),
                currency: commission.currency || actorWallet.currency || 'TZS',
            },
            'info',
        );
    }
}

export const ServiceActorOps = new ServiceActorOperations();
