# FX Settlement and Company Revenue Runbook

This runbook is the operational contract for ORBI FX pricing, locked quotes,
company revenue, treasury liquidity, and reconciliation.

## Financial ownership

Every currency has its own company accounts in `system_settlement_accounts`.
There is no shared multi-currency fee collector. The account role and wallet
currency must match every ledger leg.

| Role | Receives | Owner / use |
| :--- | :--- | :--- |
| `SERVICE_REVENUE` | Service charge excluding taxes | ORBI operating revenue |
| `TAX_RESERVE` | VAT, government fee, stamp duty | Funds held for statutory remittance |
| `FX_CLEARING` | The source or target leg of a conversion | Treasury liquidity, not revenue |
| `FX_SPREAD_REVENUE` | FX margin after risk allocation | ORBI FX revenue |
| `FX_RISK_RESERVE` | FX risk buffer | Treasury reserve, not revenue |
| `COMMISSION_RESERVE` | Commission funding | Agent, merchant, and referral payout reserve |

## Strict routing

No transaction may fall back to `FEE_COLLECTOR`, an environment variable, or an arbitrary wallet identifier. A missing, paused, locked, or incorrectly denominated company settlement account must reject the transaction. Legacy fee-collector data remains historical evidence only and is never used for routing or fee reporting.

## FX transaction lifecycle

1. The customer requests a quote for a permitted active corridor.
2. ORBI obtains a provider rate and applies the corridor margin policy.
3. The server saves the quote with its customer rate, market rate, spread,
   risk buffer, final amount, source and target wallets, and expiry.
4. The server signs the snapshot. The client cannot alter it.
5. At settlement, ORBI verifies the quote owner, quote state, expiry,
   idempotency key, payload hash, and FX snapshot signature.
6. The ledger uses the stored quote exactly. It must not fetch a new rate.
7. In the target currency, the ledger credits the customer final amount,
   `FX_SPREAD_REVENUE`, `FX_RISK_RESERVE`, and any separately configured FX fee.
8. Reconciliation moves from `PENDING` to `MATCHED` only after settlement.

The displayed FX spread is an estimate until a conversion has settled. It is
not booked as realized revenue while the quote is pending, expired, failed, or
reversed.

## Treasury funding gate

Before enabling an FX corridor in production, Treasury must fund the target
currency `FX_CLEARING` account sufficiently for conversion settlement and
configure a net exposure limit for that currency. A zero-balance clearing
account is valid only before that corridor is enabled.

For each enabled currency, Finance must verify:

- the six company accounts exist and are `ACTIVE`;
- `FX_CLEARING` has approved liquidity and settlement-provider cover;
- `FX_RISK_RESERVE` and `TAX_RESERVE` are excluded from operating cash;
- `SERVICE_REVENUE` and `FX_SPREAD_REVENUE` are included in the revenue report;
- the corridor, provider health, and treasury exposure limit are active.

## Required migrations and rollout

Apply these migrations to sandbox first, then live in the same release as the
backend code:

1. `20260925_system_settlement_accounts.sql`
2. `20260926_currency_balanced_ledger.sql`
3. `20260927_remove_legacy_fee_collector_fallback.sql`
4. `20260928_strict_card_fee_settlement.sql`

After applying them, query `system_settlement_accounts` and confirm one active
account for each role/currency pair. Do not enable a new currency merely
because an account was provisioned; funding and Treasury approval are required.

## Daily reconciliation

Finance reviews `fx_reconciliation_events` and the FX exposure endpoint daily.
For every `MATCHED` FX conversion, reconcile the quote amount and ledger legs:

- source wallet debit equals source-currency clearing credit;
- target-currency clearing debit equals customer amount plus spread, risk
  reserve, and explicit FX fee;
- each target company account received the amount assigned by the signed quote;
- every currency independently has equal ledger debits and credits;
- provider settlement evidence and treasury position agree with ORBI clearing.

Escalate `PENDING` conversions that pass their operational SLA, all `FAILED`
conversions with partial external settlement, and any account whose balance
breaches its configured exposure or liquidity threshold.
