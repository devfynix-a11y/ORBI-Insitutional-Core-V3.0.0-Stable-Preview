import { getAdminSupabase } from '../supabaseClient.js';

export type SettlementAccountRole =
  | 'SERVICE_REVENUE'
  | 'TAX_RESERVE'
  | 'FX_CLEARING'
  | 'FX_SPREAD_REVENUE'
  | 'FX_RISK_RESERVE'
  | 'COMMISSION_RESERVE';

const normalizeCurrency = (value: string) => String(value || '').trim().toUpperCase();

/** Resolves a company account with an exact role and denomination. Never falls back across currencies. */
export class SystemSettlementAccountService {
  async resolve(role: SettlementAccountRole, currency: string): Promise<string> {
    const code = normalizeCurrency(currency);
    if (!/^[A-Z]{3}$/.test(code)) throw new Error(`SETTLEMENT_CURRENCY_INVALID:${currency}`);
    const sb = getAdminSupabase();
    if (!sb) throw new Error('SETTLEMENT_ACCOUNT_STORE_UNAVAILABLE');
    const { data, error } = await sb
      .from('system_settlement_accounts')
      .select('vault_id, status')
      .eq('role', role)
      .eq('currency', code)
      .eq('status', 'ACTIVE')
      .maybeSingle();
    if (error) throw new Error(`SETTLEMENT_ACCOUNT_LOOKUP_FAILED:${error.message}`);
    if (!data?.vault_id) throw new Error(`SETTLEMENT_ACCOUNT_NOT_CONFIGURED:${role}:${code}`);
    const { data: vault, error: vaultError } = await sb
      .from('platform_vaults')
      .select('id, currency, is_locked, status')
      .eq('id', data.vault_id)
      .maybeSingle();
    if (vaultError) throw new Error(`SETTLEMENT_VAULT_LOOKUP_FAILED:${vaultError.message}`);
    if (!vault || normalizeCurrency(vault.currency) !== code || vault.is_locked || String(vault.status).toLowerCase() !== 'active') {
      throw new Error(`SETTLEMENT_ACCOUNT_INVALID:${role}:${code}`);
    }
    return String(vault.id);
  }
}

export const systemSettlementAccounts = new SystemSettlementAccountService();
