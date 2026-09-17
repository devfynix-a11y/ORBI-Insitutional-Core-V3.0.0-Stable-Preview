import assert from 'node:assert/strict';
import test from 'node:test';
import { resolveLockedFxConversion, signLockedFxSnapshot, verifyLockedFxSnapshot } from '../backend/ledger/FXLockedQuote.js';

const snapshot = {
  originalAmount: 100,
  fromCurrency: 'USD',
  toCurrency: 'TZS',
  exchangeRate: 2574,
  finalAmount: 257400,
  marketRate: 2600,
  spreadAmount: 2600,
  marginBps: 75,
  riskBufferBps: 25,
  fee: 0,
};

test('settlement uses the signed quote amount and rate without repricing', () => {
  const settled = resolveLockedFxConversion(snapshot, 100, 'USD', 'TZS');
  assert.equal(settled.finalAmount, 257400);
  assert.equal(settled.exchangeRate, 2574);
  assert.equal(settled.spreadAmount, 2600);
});

test('settlement rejects a wallet pair that differs from the locked quote', () => {
  assert.throws(() => resolveLockedFxConversion(snapshot, 100, 'USD', 'KES'), /FX_QUOTE_WALLET_CURRENCY_MISMATCH/);
});

test('settlement rejects changed source amounts and inconsistent quote amounts', () => {
  assert.throws(() => resolveLockedFxConversion(snapshot, 101, 'USD', 'TZS'), /FX_QUOTE_AMOUNT_MISMATCH/);
  assert.throws(() => resolveLockedFxConversion({ ...snapshot, finalAmount: 250000 }, 100, 'USD', 'TZS'), /FX_QUOTE_RESULT_MISMATCH/);
});

test('signed quote snapshot rejects changes to the customer rate or spread', () => {
  const signed = { ...snapshot, expiresAt: '2026-09-15T10:00:00Z' } as Record<string, unknown>;
  signed.fxSnapshotSignature = signLockedFxSnapshot(signed, 'fx_123', 'user_123', 'test-secret');
  verifyLockedFxSnapshot(signed, 'fx_123', 'user_123', 'test-secret');
  assert.throws(() => verifyLockedFxSnapshot({ ...signed, exchangeRate: 2600 }, 'fx_123', 'user_123', 'test-secret'), /FX_QUOTE_SNAPSHOT_SIGNATURE_INVALID/);
  assert.throws(() => verifyLockedFxSnapshot({ ...signed, spreadAmount: 0 }, 'fx_123', 'user_123', 'test-secret'), /FX_QUOTE_SNAPSHOT_SIGNATURE_INVALID/);
});
