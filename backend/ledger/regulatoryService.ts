
import { RegulatoryConfig, User } from '../../types.js';
import { getSupabase } from '../../services/supabaseClient.js';
import { platformFeeService } from '../payments/PlatformFeeService.js';
import { transactionFeeClassifier } from '../payments/TransactionFeeClassifier.js';

/**
 * ORBI REGULATORY & COMPLIANCE NODE (V8.2)
 * -----------------------------------------
 * Manages tax jurisdictions, reporting thresholds, and system vault mapping.
 */
export class RegulatoryServiceNode {
    
    public async getActiveConfig(): Promise<RegulatoryConfig> {
        const sb = getSupabase();
        if (sb) {
            const { data } = await sb.from('regulatory_config').select('*').eq('is_active', true).maybeSingle();
            if (data) return data;
        }

        throw new Error('REGULATORY_CONFIG_NOT_CONFIGURED');
    }

    /**
     * RESOLVE SYSTEM NODE
     * Maps logical system roles (like ESCROW) to physical wallet/vault IDs.
     */
    public async resolveSystemNode(role: 'ESCROW_VAULT' | 'TAX_RESERVE' | 'FX_CLEARING'): Promise<string> {
        const sb = getSupabase();
        
        if (sb) {
            try {
                const { data } = await sb.from('system_nodes').select('vault_id').eq('node_type', role).maybeSingle();
                if (data) return data.vault_id;
            } catch (e) {
                // Fallback to platform_vaults if system_nodes fails
                const { data: vault } = await sb.from('platform_vaults').select('id').eq('vault_role', role).maybeSingle();
                if (vault) return vault.id;
            }
        }
        
        throw new Error(`SYSTEM_NODE_NOT_CONFIGURED:${role}`);
    }

    public async calculateFees(
        amount: number,
        type: string,
        currency: string,
        context?: { metadata?: Record<string, any>; category?: string },
    ): Promise<{ vat: number, fee: number, gov_fee: number, stamp_duty: number, total: number, rate: number }> {
        const normalizedType = String(type || '').trim().toUpperCase();
        const normalizedCurrency = String(currency || '').trim().toUpperCase();
        if (!normalizedCurrency) {
            throw new Error(`FEE_CURRENCY_REQUIRED:${normalizedType || 'CORE_TRANSACTION'}`);
        }
        const metadata = context?.metadata || {};
        const classification = transactionFeeClassifier.classify({
            type: normalizedType,
            category: context?.category,
            categoryId: metadata.category_id || metadata.categoryId,
            metadata,
            channel: metadata.channel,
            rail: metadata.rail,
            operation: metadata.operation || metadata.operation_code,
        });

        const feeResult = await platformFeeService.resolveFee({
            flowCode: classification.flowCode,
            amount,
            currency: normalizedCurrency,
            rail: classification.rail,
            channel: classification.channel,
            direction: classification.direction,
            transactionModel: classification.transactionModel,
            categoryCode: classification.categoryCode,
            categoryId: classification.categoryId,
            operationType: classification.operationType,
            transactionType: classification.transactionType,
            metadata,
        });

        return {
            vat: feeResult.taxAmount,
            fee: feeResult.serviceFee,
            gov_fee: feeResult.govFeeAmount,
            stamp_duty: feeResult.stampDutyFixed,
            total: feeResult.totalFee,
            rate: feeResult.taxRate
        };
    }
}

export const RegulatoryService = new RegulatoryServiceNode();
