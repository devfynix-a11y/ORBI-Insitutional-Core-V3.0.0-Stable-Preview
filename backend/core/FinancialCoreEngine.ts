import crypto from 'node:crypto';
import { getAdminSupabase, getSupabase } from '../supabaseClient.js';
import { Messaging } from '../features/MessagingService.js';

export class FinancialCoreEngineService {
    
    /**
     * Create a new Tenant (Individual, Merchant, Marketplace, Partner)
     */
    async createTenant(userId: string, data: { name: string, type: 'individual' | 'merchant' | 'marketplace' | 'partner' }) {
        const sb = getSupabase();
        if (!sb) throw new Error("Database not connected");

        // 1. Create Tenant
        const { data: tenant, error: tenantError } = await sb
            .from('tenants')
            .insert({
                name: data.name,
                type: data.type,
                status: 'ACTIVE'
            })
            .select()
            .single();

        if (tenantError || !tenant) {
            throw new Error(`Failed to create tenant: ${tenantError?.message}`);
        }

        // 2. Link User to Tenant as 'owner'
        const { error: linkError } = await sb
            .from('tenant_users')
            .insert({
                tenant_id: tenant.id,
                user_id: userId,
                role: 'owner'
            });

        if (linkError) {
            console.error("Failed to link user to tenant", linkError);
        }

        // 3. Create Default Tenant Wallet
        const { error: walletError } = await sb
            .from('wallets')
            .insert({
                user_id: userId, // Legacy compatibility
                tenant_id: tenant.id,
                owner_type: data.type === 'individual' ? 'user' : 'merchant',
                name: `${data.name} Primary Wallet`,
                currency: 'TZS',
                balance: 0,
                status: 'active'
            });

        if (walletError) {
            console.error("Failed to create tenant wallet", walletError);
        }

        return tenant;
    }

    /**
     * Get all tenants for a user
     */
    async getUserTenants(userId: string) {
        const sb = getSupabase();
        if (!sb) return [];

        const { data, error } = await sb
            .from('tenant_users')
            .select('role, tenants(*)')
            .eq('user_id', userId);

        if (error) throw new Error(error.message);
        return data.map(d => ({ ...d.tenants, role: d.role }));
    }

    /**
     * Generate API Keys for a Tenant
     */
    async generateApiKeys(userId: string, tenantId: string, type: 'test' | 'live' = 'test') {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) throw new Error("Database not connected");

        // Verify user is owner or admin
        const { data: link } = await sb
            .from('tenant_users')
            .select('role')
            .eq('tenant_id', tenantId)
            .eq('user_id', userId)
            .single();

        if (!link || !['owner', 'admin'].includes(link.role)) {
            throw new Error("Unauthorized to generate API keys for this tenant");
        }

        const environment = type === 'test' ? 'sandbox' : 'live';
        const serviceCode = `tenant:${tenantId}`;
        const { data: service } = await sb.from('pay_gateway_developer_services').select('status,environments,scopes_granted').eq('service_code', serviceCode).maybeSingle();
        if (environment === 'live' && (!service || service.status !== 'active' || !service.environments?.includes('live') || !service.scopes_granted?.includes('wallets:read'))) {
            throw new Error('LIVE_API_ACCESS_NOT_APPROVED');
        }
        if (!service && environment === 'sandbox') {
            const { error: serviceError } = await sb.from('pay_gateway_developer_services').insert({ service_code: serviceCode, display_name: `Tenant ${tenantId}`, status: 'active', environments: ['sandbox'], scopes_granted: ['wallets:read'], metadata: { provisionedBy: 'tenant_api_key' } });
            if (serviceError) throw new Error(serviceError.message);
        }
        const publicKey = `pk_${type}_${crypto.randomBytes(16).toString('hex')}`;
        const secretKey = `sk_${type}_${crypto.randomBytes(32).toString('base64url')}`;
        const secretHash = crypto.createHash('sha256').update(secretKey, 'utf8').digest('hex');

        const { data: keys, error } = await sb
            .from('api_keys')
            .insert({
                tenant_id: tenantId,
                public_key: publicKey,
                secret_key: null,
                secret_hash: secretHash,
                secret_fingerprint: secretHash.slice(0, 16),
                environment,
                audience: 'orbi-core',
                service_code: serviceCode,
                scopes: ['wallets:read'],
                issued_by: userId
            })
            .select()
            .single();

        if (error) throw new Error(error.message);
        try { await Messaging.dispatch(userId, 'security', 'API credential issued', `A ${environment} API credential was issued for your tenant.`, { push: true, sms: true, email: true, mandatory: true, systemCustomBypass: true, eventCode: 'API_CREDENTIAL_ISSUED', idempotencyKey: `api-credential:${keys.id}:issued:${userId}` }); } catch (notificationError: any) { console.warn(`[FinancialCore] key ${keys.id} issued; notification deferred: ${notificationError.message}`); }
        return { ...keys, secret_hash: undefined, secretKey };
    }

    /**
     * Get API Keys for a Tenant
     */
    async getApiKeys(userId: string, tenantId: string) {
        const sb = getSupabase();
        if (!sb) return [];

        // Verify access (owner/admin only)
        const { data: link } = await sb
            .from('tenant_users')
            .select('role')
            .eq('tenant_id', tenantId)
            .eq('user_id', userId)
            .single();

        if (!link || !['owner', 'admin'].includes(link.role)) {
            throw new Error("Unauthorized to view API keys for this tenant");
        }

        const { data, error } = await sb
            .from('api_keys')
            .select('id, public_key, secret_fingerprint, environment, audience, scopes, status, created_at, expires_at, last_used_at, revoked_at')
            .eq('tenant_id', tenantId);

        if (error) throw new Error(error.message);
        return data;
    }

    /**
     * Revoke an API Key
     */
    async revokeApiKey(userId: string, tenantId: string, apiKeyId: string) {
        const sb = getSupabase();
        if (!sb) throw new Error("Database not connected");

        // Verify access (owner/admin only)
        const { data: link } = await sb
            .from('tenant_users')
            .select('role')
            .eq('tenant_id', tenantId)
            .eq('user_id', userId)
            .single();

        if (!link || !['owner', 'admin'].includes(link.role)) {
            throw new Error("Unauthorized to revoke API keys for this tenant");
        }

        const { error } = await sb
            .from('api_keys')
            .update({ status: 'REVOKED', revoked_at: new Date().toISOString() })
            .eq('id', apiKeyId)
            .eq('tenant_id', tenantId);

        if (error) throw new Error(error.message);
        try { await Messaging.dispatch(userId, 'security', 'API credential revoked', 'An API credential for your tenant was revoked.', { push: true, sms: true, email: true, mandatory: true, systemCustomBypass: true, eventCode: 'API_CREDENTIAL_REVOKED', idempotencyKey: `api-credential:${apiKeyId}:revoked:${userId}` }); } catch (notificationError: any) { console.warn(`[FinancialCore] key ${apiKeyId} revoked; notification deferred: ${notificationError.message}`); }
        return { success: true };
    }

    /**
     * Validate an API Key (Middleware usage)
     */
    async validateApiKey(secretKey: string, context: { environment: string; audience: string; requiredScopes: string[]; subjectUserId?: string; purpose?: string }) {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) throw new Error("Database not connected");

        const secretHash = crypto.createHash('sha256').update(secretKey, 'utf8').digest('hex');
        const { data, error } = await sb.rpc('authorize_external_api_request_v1', {
            p_secret_hash: secretHash, p_environment: context.environment,
            p_audience: context.audience, p_required_scopes: context.requiredScopes,
            p_subject_user_id: context.subjectUserId || null, p_purpose: context.purpose || null,
        });
        if (error || !data) return null;
        return data as { keyId: string; tenantId: string; serviceCode?: string; environment: string; audience: string; scopes: string[]; subjectUserId?: string };
    }

    /**
     * Get Tenant Wallets
     */
    async getTenantWallets(userId: string, tenantId: string) {
        const sb = getSupabase();
        if (!sb) return [];

        // Verify access
        const { data: link } = await sb
            .from('tenant_users')
            .select('role')
            .eq('tenant_id', tenantId)
            .eq('user_id', userId)
            .single();

        if (!link) throw new Error("Unauthorized");

        const { data, error } = await sb
            .from('wallets')
            .select('*')
            .eq('tenant_id', tenantId);

        if (error) throw new Error(error.message);
        return data;
    }
}

export const FinancialCore = new FinancialCoreEngineService();
