
import { RegulatoryConfig, TransferTaxRule, DigitalMerchant, RegisteredApp, FinancialPartner, RegulatoryReport, PricingRule } from '../types.js';
import { getSupabase } from '../services/supabaseClient.js';
import { DataVault } from '../backend/security/encryption.js';
import { UUID } from '../services/utils.js';
import { Storage } from '../backend/storage.js';
import { providerSecretVault } from '../backend/payments/providers/ProviderSecretVault.js';
import crypto from 'crypto';

export type SystemNodeRole = 'GOV_TAX' | 'SERVICE_FEE' | 'ESCROW_VAULT' | 'BANK_POOL' | 'OPERATIONAL_RESERVE';

class RegulatoryControl {
    private readonly STORAGE_KEY = 'orbi_regulatory_node_v13';
    private readonly RULES_KEY = 'orbi_tax_rules_v13';
    
    private readonly GENESIS_NODES: Record<SystemNodeRole, string> = {
        GOV_TAX: '00000000-0000-0000-0000-000000000001',
        SERVICE_FEE: '00000000-0000-0000-0000-000000000002',
        ESCROW_VAULT: '00000000-0000-0000-0000-000000000003',
        BANK_POOL: '00000000-0000-0000-0000-000000000004',
        OPERATIONAL_RESERVE: '00000000-0000-0000-0000-000000000006'
    };

    private defaultRegistry: RegulatoryConfig = {
        id: 'reg_master_v13',
        vat_rate: 0.18,        
        service_fee_rate: 0.01, 
        gov_fee_rate: 0.005,
        stamp_duty_fixed: 0.00,
        is_active: true,
        updated_at: new Date().toISOString()
    };

    public async resolveSystemNode(role: SystemNodeRole): Promise<string> {
        const sb = getSupabase();
        if (!sb) return this.GENESIS_NODES[role];
        try {
            const { data } = await sb.from('system_nodes').select('vault_id').eq('node_type', role).maybeSingle();
            if (!data) return this.GENESIS_NODES[role];
            return data.vault_id;
        } catch (e) { 
            return this.GENESIS_NODES[role]; 
        }
    }

    public async updateSystemNode(role: SystemNodeRole, vaultId: string): Promise<void> {
        const sb = getSupabase();
        if (!sb) throw new Error("CLOUD_NODE_OFFLINE");
        await sb.from('system_nodes').upsert({ node_type: role, vault_id: vaultId, updated_at: new Date().toISOString() });
    }

    public async getSystemNodeMappings(): Promise<Record<SystemNodeRole, string | null>> {
        const sb = getSupabase();
        const defaultMap: Record<SystemNodeRole, string | null> = { ...this.GENESIS_NODES };
        if (!sb) return defaultMap;
        try {
            const { data } = await sb.from('system_nodes').select('*');
            if (data && data.length > 0) {
                data.forEach((row: any) => { 
                    defaultMap[row.node_type as SystemNodeRole] = row.vault_id; 
                });
            }
        } catch (e) {}
        return defaultMap;
    }

    public async getActiveRegistry(): Promise<RegulatoryConfig> {
        const sb = getSupabase();
        if (sb) {
            try {
                const { data } = await sb.from('regulatory_config').select('*, users(full_name)').eq('is_active', true).order('updated_at', { ascending: false }).limit(1).maybeSingle();
                if (data) {
                    return { 
                        ...data, 
                        updated_by_name: (data as any).users?.full_name || (typeof data.updated_by === 'string' ? data.updated_by : 'System')
                    } as RegulatoryConfig;
                }
            } catch (e) {
                try {
                    const { data } = await sb.from('regulatory_config').select('*').eq('is_active', true).order('updated_at', { ascending: false }).limit(1).maybeSingle();
                    if (data) return data as RegulatoryConfig;
                } catch (inner) {}
            }
        }
        const local = Storage.getItem(this.STORAGE_KEY);
        return local ? JSON.parse(local) : this.defaultRegistry;
    }

    public async updateRegistry(config: Partial<RegulatoryConfig>, userId: string): Promise<void> {
        const sb = getSupabase();
        const active = await this.getActiveRegistry();
        const updated = { ...active, ...config, updated_at: new Date().toISOString(), updated_by: userId };
        
        if (sb) {
            await sb.from('regulatory_config').upsert({
                id: updated.id, vat_rate: updated.vat_rate, service_fee_rate: updated.service_fee_rate,
                gov_fee_rate: updated.gov_fee_rate, stamp_duty_fixed: updated.stamp_duty_fixed,
                is_active: updated.is_active, updated_at: updated.updated_at, updated_by: updated.updated_by
            });
        }
        Storage.setItem(this.STORAGE_KEY, JSON.stringify(updated));
    }

    public async getPricingRules(): Promise<PricingRule[]> {
        const sb = getSupabase();
        if (!sb) return [];
        const { data } = await sb.from('platform_configs').select('config_data').eq('config_key', 'PRICING_MATRIX').maybeSingle();
        return (data?.config_data || []) as PricingRule[];
    }

    public async updatePricingRule(ruleId: string, updates: Partial<PricingRule>, userId: string): Promise<void> {
        const sb = getSupabase();
        if (!sb) throw new Error("VAULT_OFFLINE");
        
        const currentRules = await this.getPricingRules();
        const newRules = currentRules.map(r => r.id === ruleId ? { ...r, ...updates, updatedAt: new Date().toISOString() } : r);
        
        await sb.from('platform_configs').upsert({
            config_key: 'PRICING_MATRIX',
            config_data: newRules,
            updated_at: new Date().toISOString(),
            updated_by: userId
        });
    }

    public async getTaxRules(): Promise<TransferTaxRule[]> {
        const sb = getSupabase();
        if (sb) {
            try {
                const { data } = await sb.from('transfer_tax_rules').select('*').eq('is_active', true);
                if (data) return data as TransferTaxRule[];
            } catch (e) {}
        }
        const local = Storage.getItem(this.RULES_KEY);
        return local ? JSON.parse(local) : [];
    }

    public async getMerchants(): Promise<DigitalMerchant[]> {
        const sb = getSupabase();
        if (!sb) return [];
        try {
            const { data } = await sb.from('digital_merchants').select('*');
            return data || [];
        } catch (e) { return []; }
    }

    public async registerMerchant(payload: any): Promise<DigitalMerchant> {
        const sb = getSupabase();
        if (!sb) throw new Error("CLOUD_NODE_OFFLINE");
        const newMerchant: DigitalMerchant = {
            id: UUID.generate(), ...payload, status: 'ACTIVE', created_at: new Date().toISOString()
        };
        await sb.from('digital_merchants').insert(newMerchant);
        return newMerchant;
    }

    public async getPartners(): Promise<FinancialPartner[]> {
        const sb = getSupabase();
        if (!sb) return [];
        try {
            const { data } = await sb.from('financial_partners').select('*');
            return data || [];
        } catch (e) { return []; }
    }

    public async registerPartner(name: string, type: string, icon: string, color: string, connection: string, metadata?: any): Promise<FinancialPartner> {
        const sb = getSupabase();
        if (!sb) throw new Error("CLOUD_NODE_OFFLINE");
        const encryptedSecret = await providerSecretVault.wrapSecret(connection, 'connection_secret', {
            domain: 'REGULATORY_PARTNER',
            partnerName: name,
        });
        const newPartner: Partial<FinancialPartner> = {
            id: UUID.generate(), name, type: type as any, icon, color,
            connection_secret: encryptedSecret, provider_metadata: metadata || {},
            status: 'ACTIVE', created_at: new Date().toISOString()
        };
        await sb.from('financial_partners').insert(newPartner);
        return newPartner as FinancialPartner;
    }

    public async getApps(): Promise<RegisteredApp[]> {
        const sb = getSupabase();
        if (!sb) return [];
        try {
            const { data } = await sb.from('app_registry').select('*');
            return data || [];
        } catch (e) { return []; }
    }

    public async registerApp(name: string, tier: string): Promise<RegisteredApp> {
        const sb = getSupabase();
        if (!sb) throw new Error("CLOUD_NODE_OFFLINE");
        
        const sessionResponse = await sb.auth.getSession();
        const userId = sessionResponse.data.session?.user?.id;

        const newApp: RegisteredApp = {
            id: UUID.generate(),
            name,
            app_id: `fnx-app-${crypto.randomBytes(8).toString('hex').toUpperCase()}`,
            app_token: `tk_${crypto.randomBytes(32).toString('hex')}`,
            tier: tier as any,
            status: 'ACTIVE',
            developer_id: userId || 'system',
            created_at: new Date().toISOString()
        };
        
        const { error } = await sb.from('app_registry').insert(newApp);
        if (error) throw error;
        
        return newApp;
    }

    public async verifyAppNode(id: string, token: string): Promise<RegisteredApp | null> {
        const sb = getSupabase();
        if (!sb) return null;
        try {
            const { data } = await sb.from('app_registry').select('*').eq('app_id', id).eq('app_token', token).eq('status', 'ACTIVE').maybeSingle();
            return data || null;
        } catch (e) { return null; }
    }
}

export const RegulatoryService = new RegulatoryControl();
export const SYSTEM_NODES = {
    SERVICE_FEE: 'SERVICE_FEE' as SystemNodeRole,
    TAX_ESCROW: 'GOV_TAX' as SystemNodeRole,
    ESCROW_VAULT: 'ESCROW_VAULT' as SystemNodeRole,
    OPERATIONAL_RESERVE: 'OPERATIONAL_RESERVE' as SystemNodeRole
};
