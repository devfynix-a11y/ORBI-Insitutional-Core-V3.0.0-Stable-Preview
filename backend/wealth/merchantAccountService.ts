import { getSupabase } from '../supabaseClient.js';
import { UUID } from '../../services/utils.js';
import {
    canAccessMerchantResource,
    type MerchantResourceAccess,
} from '../security/ecosystemAuthorization.js';

export class MerchantAccountService {
    
    /**
     * Create a new Merchant Account for a User
     */
    async createMerchant(userId: string, data: { business_name: string }) {
        const sb = getSupabase();
        if (!sb) throw new Error("Database not connected");

        // 1. Create Merchant
        const { data: merchant, error: merchantError } = await sb
            .from('merchants')
            .insert({
                business_name: data.business_name,
                owner_user_id: userId,
                status: 'pending'
            })
            .select()
            .single();

        if (merchantError || !merchant) {
            throw new Error(`Failed to create merchant: ${merchantError?.message}`);
        }

        const { data: ownerProfile } = await sb
            .from('users')
            .select('currency')
            .eq('id', userId)
            .maybeSingle();
        const ownerCurrency = String(ownerProfile?.currency || '').trim().toUpperCase() || null;

        // 2. Create Merchant Wallet
        const { error: walletError } = await sb
            .from('merchant_wallets')
            .insert({
                merchant_id: merchant.id,
                name: `${data.business_name} Operating Wallet`,
                ...(ownerCurrency ? { currency: ownerCurrency } : {}),
                balance: 0,
                status: 'active'
            });

        if (walletError) {
            console.error("Failed to create merchant wallet", walletError);
        }

        // 3. Create Default Fees Configuration
        const { error: feesError } = await sb
            .from('merchant_fees')
            .insert({
                merchant_id: merchant.id,
                transaction_fee_percent: 0,
                fixed_fee: 0,
                ...(ownerCurrency ? { currency: ownerCurrency } : {})
            });

        if (feesError) {
            console.error("Failed to create merchant fees", feesError);
        }

        return merchant;
    }

    /**
     * Get all merchants owned by a user
     */
    async getUserMerchants(userId: string) {
        const sb = getSupabase();
        if (!sb) return [];

        const { data, error } = await sb
            .from('merchants')
            .select('*, merchant_wallets(*), merchant_settlements(*), merchant_fees(*)')
            .eq('owner_user_id', userId);

        if (error) throw new Error(error.message);
        return data || [];
    }

    /**
     * Get a specific merchant by ID
     */
    async getMerchantById(merchantId: string, access: MerchantResourceAccess) {
        const sb = getSupabase();
        if (!sb) return null;

        const { data, error } = await sb
            .from('merchants')
            .select('*, merchant_wallets(*), merchant_settlements(*), merchant_fees(*)')
            .eq('id', merchantId)
            .maybeSingle();

        if (error) throw new Error(error.message);
        if (!data) throw new Error('MERCHANT_NOT_FOUND');
        if (!canAccessMerchantResource(data, access)) throw new Error('ACCESS_DENIED');
        return data;
    }

    /**
     * Update Merchant Settlement Info
     */
    async updateSettlementInfo(
        merchantId: string,
        data: { bank_name: string, bank_account: string, settlement_schedule?: string },
        access: MerchantResourceAccess,
    ) {
        const sb = getSupabase();
        if (!sb) throw new Error("Database not connected");

        const { data: merchant, error: merchantError } = await sb
            .from('merchants')
            .select('id, owner_user_id, status')
            .eq('id', merchantId)
            .maybeSingle();
        if (merchantError) throw new Error(merchantError.message);
        if (!merchant) throw new Error('MERCHANT_NOT_FOUND');
        if (!canAccessMerchantResource(merchant, access)) throw new Error('ACCESS_DENIED');

        // Check if settlement info exists
        const { data: existing } = await sb.from('merchant_settlements').select('id').eq('merchant_id', merchantId).single();

        if (existing) {
            const { data: updated, error } = await sb
                .from('merchant_settlements')
                .update({
                    bank_name: data.bank_name,
                    bank_account: data.bank_account,
                    settlement_schedule: data.settlement_schedule || 'daily',
                    updated_at: new Date().toISOString()
                })
                .eq('merchant_id', merchantId)
                .select()
                .single();
            
            if (error) throw new Error(error.message);
            return updated;
        } else {
            const { data: inserted, error } = await sb
                .from('merchant_settlements')
                .insert({
                    merchant_id: merchantId,
                    bank_name: data.bank_name,
                    bank_account: data.bank_account,
                    settlement_schedule: data.settlement_schedule || 'daily'
                })
                .select()
                .single();
            
            if (error) throw new Error(error.message);
            return inserted;
        }
    }
}

export const MerchantAccounts = new MerchantAccountService();
