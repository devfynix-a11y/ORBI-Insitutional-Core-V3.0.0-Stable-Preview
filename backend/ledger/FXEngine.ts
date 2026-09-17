import { liquidityProviderRegistry } from '../fx/LiquidityProviderAdapter.js';
import { getAdminSupabase, getSupabase } from '../supabaseClient.js';

export class FXEngine {
    private static DEFAULT_LOCK_SECONDS = 45;
    private static DEFAULT_MARGIN_BPS = 75; // 0.75%
    private static DEFAULT_RISK_BUFFER_BPS = 25; // 0.25%

    private static parseBps(value: unknown, fallback: number) {
        const parsed = Number(value);
        if (!Number.isFinite(parsed) || parsed < 0) return fallback;
        return Math.min(parsed, 2500);
    }

    private static defaultQuoteRiskPolicy() {
        return {
            lockSeconds: Math.max(Number(process.env.ORBI_FX_QUOTE_LOCK_SECONDS || this.DEFAULT_LOCK_SECONDS), 15),
            spreadMode: 'BPS',
            fixedPips: 0,
            marginBps: this.parseBps(process.env.ORBI_FX_MARGIN_BPS, this.DEFAULT_MARGIN_BPS),
            riskBufferBps: this.parseBps(process.env.ORBI_FX_RISK_BUFFER_BPS, this.DEFAULT_RISK_BUFFER_BPS),
        };
    }

    private static async quoteRiskPolicy(fromCurrency: string, toCurrency: string, amount: number) {
        const defaults = this.defaultQuoteRiskPolicy();
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return defaults;

        try {
            const { data, error } = await sb
                .from('fx_margin_policies')
                .select('spread_mode, fixed_pips, margin_bps, risk_buffer_bps, quote_lock_seconds, min_amount, max_amount, status')
                .eq('from_currency', fromCurrency)
                .eq('to_currency', toCurrency)
                .maybeSingle();
            if (error || !data || data.status !== 'ACTIVE') return defaults;
            const minAmount = Number(data.min_amount || 0);
            const maxAmount = Number(data.max_amount || 0);
            if (minAmount > 0 && amount < minAmount) throw new Error(`FX_AMOUNT_BELOW_MINIMUM:${fromCurrency}:${toCurrency}`);
            if (maxAmount > 0 && amount > maxAmount) throw new Error(`FX_AMOUNT_ABOVE_MAXIMUM:${fromCurrency}:${toCurrency}`);
            return {
                lockSeconds: Math.max(Number(data.quote_lock_seconds || defaults.lockSeconds), 15),
                spreadMode: String(data.spread_mode || defaults.spreadMode).toUpperCase(),
                fixedPips: Math.max(Number(data.fixed_pips || 0), 0),
                marginBps: this.parseBps(data.margin_bps, defaults.marginBps),
                riskBufferBps: this.parseBps(data.risk_buffer_bps, defaults.riskBufferBps),
            };
        } catch (error: any) {
            if (String(error?.message || '').startsWith('FX_AMOUNT_')) throw error;
            return defaults;
        }
    }

    /**
     * Get the exchange rate from one currency to another.
     */
    static async getRate(fromCurrency: string, toCurrency: string): Promise<number> {
        const from = fromCurrency.toUpperCase();
        const to = toCurrency.toUpperCase();

        if (from === to) return 1;
        const snapshot = await liquidityProviderRegistry.getRate({ fromCurrency: from, toCurrency: to });
        return snapshot.rate;
    }

    /**
     * Convert an amount to USD for standardized AML and Risk checks.
     */
    static async convertToUSD(amount: number, currency: string): Promise<number> {
        const rate = await this.getRate(currency, 'USD');
        return amount * rate;
    }

    /**
     * Process a real currency conversion using provider rates plus ORBI spread policy.
     * This is used for actual user transactions/pricing.
     */
    static async processConversion(amount: number, fromCurrency: string, toCurrency: string) {
        const normalizedFromCurrency = fromCurrency.toUpperCase();
        const normalizedToCurrency = toCurrency.toUpperCase();
        const liquiditySnapshot = await liquidityProviderRegistry.getRate({
            fromCurrency: normalizedFromCurrency,
            toCurrency: normalizedToCurrency,
            amount,
        });
        const baseRate = liquiditySnapshot.rate;
        const riskPolicy = await this.quoteRiskPolicy(normalizedFromCurrency, normalizedToCurrency, amount);
        const protectionBps = riskPolicy.marginBps + riskPolicy.riskBufferBps;
        const spreadMultiplier = protectionBps / 10000;
        const fixedSpread = ['PIPS', 'FIXED_UNIT'].includes(riskPolicy.spreadMode)
            ? riskPolicy.fixedPips
            : 0;
        const bidRate = Number(Math.max(baseRate * (1 - spreadMultiplier) - fixedSpread, 0).toFixed(8));
        const askRate = Number((baseRate * (1 + spreadMultiplier) + fixedSpread).toFixed(8));
        const customerRate = bidRate;
        if (customerRate <= 0) throw new Error(`FX_RATE_INVALID:${normalizedFromCurrency}:${normalizedToCurrency}`);
        const marketConvertedAmount = amount * baseRate;
        const rawConvertedAmount = amount * customerRate;
        const spreadAmountInTargetCurrency = marketConvertedAmount - rawConvertedAmount;
        const quotedMarginAmount = marketConvertedAmount * riskPolicy.marginBps / 10000 + amount * fixedSpread;
        const quotedRiskBufferAmount = marketConvertedAmount * riskPolicy.riskBufferBps / 10000;
        const bidAskSpread = askRate - bidRate;
        const fee = 0;
        const feeInTargetCurrency = 0;
        const finalAmount = rawConvertedAmount;
        if (finalAmount <= 0) throw new Error(`FX_FINAL_AMOUNT_INVALID:${normalizedFromCurrency}:${normalizedToCurrency}`);
        const quotedAt = new Date();
        const expiresAt = new Date(quotedAt.getTime() + riskPolicy.lockSeconds * 1000);

        return {
            originalAmount: amount,
            fromCurrency: normalizedFromCurrency,
            toCurrency: normalizedToCurrency,
            exchangeRate: customerRate,
            baseRate,
            marketRate: baseRate,
            customerRate,
            bidRate,
            askRate,
            bidAskSpread: Number(bidAskSpread.toFixed(8)),
            marginBps: riskPolicy.marginBps,
            riskBufferBps: riskPolicy.riskBufferBps,
            protectionBps,
            spreadAmount: Number(spreadAmountInTargetCurrency.toFixed(4)),
            quotedMarginAmount: Number(quotedMarginAmount.toFixed(4)),
            quotedRiskBufferAmount: Number(quotedRiskBufferAmount.toFixed(4)),
            spreadCurrency: normalizedToCurrency,
            spreadModel: riskPolicy.spreadMode === 'BPS' ? 'PERCENTAGE_BPS' : riskPolicy.spreadMode,
            fixedPips: riskPolicy.fixedPips,
            fee: Number(fee.toFixed(4)),
            feeCurrency: normalizedFromCurrency,
            feeInTargetCurrency: Number(feeInTargetCurrency.toFixed(4)),
            finalAmount: Number(finalAmount.toFixed(4)),
            quotedAt: quotedAt.toISOString(),
            expiresAt: expiresAt.toISOString(),
            expiresInSeconds: riskPolicy.lockSeconds,
            lockedRate: true,
            liquidityProvider: {
                providerCode: liquiditySnapshot.providerCode,
                source: liquiditySnapshot.source,
                asOf: liquiditySnapshot.asOf,
                expiresAt: liquiditySnapshot.expiresAt,
                corridorId: liquiditySnapshot.corridorId,
                settlementMode: liquiditySnapshot.settlementMode,
            },
        };
    }
}
