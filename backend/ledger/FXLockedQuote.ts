import { createHmac, timingSafeEqual } from 'node:crypto';

export type LockedFxQuote = Record<string, unknown>;

const currency = (value: unknown) => String(value || '').trim().toUpperCase();
const positive = (value: unknown) => Number.isFinite(Number(value)) && Number(value) > 0;

const snapshotFields = (quote: LockedFxQuote, quoteId: string, userId: string) => JSON.stringify([
  quoteId, userId, String(quote.expiresAt || ''), Number(quote.originalAmount),
  currency(quote.fromCurrency), currency(quote.toCurrency), Number(quote.exchangeRate),
  Number(quote.finalAmount), Number(quote.marketRate), Number(quote.spreadAmount || 0),
  Number(quote.quotedMarginAmount || 0), Number(quote.quotedRiskBufferAmount || 0),
  Number(quote.fee || 0),
]);

export function signLockedFxSnapshot(quote: LockedFxQuote, quoteId: string, userId: string, secret: string) {
  if (!secret) throw new Error('FX_QUOTE_SIGNING_SECRET_REQUIRED');
  return createHmac('sha256', secret).update(snapshotFields(quote, quoteId, userId)).digest('hex');
}

export function verifyLockedFxSnapshot(quote: LockedFxQuote, quoteId: string, userId: string, secret: string) {
  const stored = String(quote.fxSnapshotSignature || '');
  if (!/^[a-f0-9]{64}$/.test(stored)) throw new Error('FX_QUOTE_SNAPSHOT_SIGNATURE_MISSING');
  const expected = signLockedFxSnapshot(quote, quoteId, userId, secret);
  if (!timingSafeEqual(Buffer.from(stored, 'hex'), Buffer.from(expected, 'hex'))) {
    throw new Error('FX_QUOTE_SNAPSHOT_SIGNATURE_INVALID');
  }
}

/** Only call this with the server-loaded, signed quote snapshot. */
export function resolveLockedFxConversion(
  quote: LockedFxQuote,
  amount: number,
  sourceCurrency: string,
  targetCurrency: string,
) {
  const from = currency(sourceCurrency);
  const to = currency(targetCurrency);
  if (from === to || from !== currency(quote.fromCurrency) || to !== currency(quote.toCurrency)) {
    throw new Error('FX_QUOTE_WALLET_CURRENCY_MISMATCH');
  }
  if (!positive(amount) || !positive(quote.originalAmount) || Number(quote.originalAmount) !== amount) {
    throw new Error('FX_QUOTE_AMOUNT_MISMATCH');
  }
  if (!positive(quote.exchangeRate) || !positive(quote.finalAmount)) {
    throw new Error('FX_QUOTE_SNAPSHOT_INVALID');
  }
  const expected = amount * Number(quote.exchangeRate) - Number(quote.fee || 0);
  // Rates have eight decimals and target amounts four, so allow only their rounding error.
  const roundingTolerance = amount * 0.000000005 + 0.00011;
  if (Math.abs(expected - Number(quote.finalAmount)) > roundingTolerance) {
    throw new Error('FX_QUOTE_RESULT_MISMATCH');
  }
  return {
    ...quote,
    originalAmount: amount,
    fromCurrency: from,
    toCurrency: to,
    exchangeRate: Number(quote.exchangeRate),
    finalAmount: Number(quote.finalAmount),
    fee: Number(quote.fee || 0),
    feeInTargetCurrency: Number(quote.feeInTargetCurrency || 0),
  };
}
