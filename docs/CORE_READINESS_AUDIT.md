# ORBI Core Readiness Audit

Status: controlled-production foundation, not 100% final certification  
Reviewed: 2026-08-02  
Scope: ORBI Core backend, ledger authority, PaySafe, shared finance, gateway
handoff, security controls, notifications, reconciliation, and deployment
readiness.

For merchant, agent, organization, developer, and third-party launch readiness,
use [ORBI Ecosystem Readiness And Remaining Slices](./ECOSYSTEM_READINESS_AND_REMAINING_SLICES.md).

## Executive Verdict

ORBI Core is a strong working financial-core foundation. It should not yet be
called 100% complete or fully certified.

The current codebase builds successfully and the normal automated test suite
passes. The remaining gap is not basic functionality; it is production-grade
evidence across database-backed mutation tests, restore drills, observability,
long-running workers, and formal operational gates.

## Validation Evidence

Commands executed during this review:

```powershell
npm run build
npm test
```

Observed result:

- TypeScript build passed.
- Test suite passed: 136 passing, 24 skipped, 0 failing.
- Skipped tests are DB-backed financial integration and mutation tests that
  require an isolated configured database fixture.
- Development warnings were observed for optional local services/secrets such
  as KMS master secret, Supabase/socket registry, and ORBI Talk gateway envs.
  They did not fail the suite, but production readiness requires those envs to
  be configured and verified.

DB-backed certification should use a dedicated uncommitted env file:

```powershell
Copy-Item .env.test.example .env.test.local
npm run test:db:financial:env
npm run test:db:financial:write:env
```

Write mode is valid only for isolated disposable fixtures.

For release evidence, use:

```powershell
npm run certify:core
node scripts/core-certification.mjs --db-env .env.test.local
node scripts/core-certification.mjs --db-env .env.test.local --include-db-write
```

The certification runner writes evidence under `artifacts/certification/`
without storing secrets.

Local DB certification loads `.env` first for runtime dependencies such as KMS
and Valkey, then overlays `.env.test.local` for disposable fixture targeting.

## Readiness Matrix

| Area | Status | Notes |
| :--- | :--- | :--- |
| Build health | Done | `npm run build` passes. |
| Unit and source-regression tests | Done | Normal `npm test` passes. |
| P2P transfer foundation | Do Not Touch | Treat as protected unless a specific defect is proven. |
| PaySafe / escrow lifecycle | Strong, Needs DB evidence | State machine, balanced legs, party authorization, merchant linkage, and side-effect-safe notification tests pass. Isolated DB lifecycle validation remains required. |
| Merchant PaySafe / gateway handoff | Strong, Needs operational drills | Durable intent/challenge/result outbox foundations exist. Worker retry, callback recovery, and staging drills remain important. |
| Shared Pot / Fungu | Strong, Needs DB concurrency evidence | Atomic RPC and source assertions exist. Disposable DB concurrency validation remains required before declaring final. |
| Shared Budget / Meza | Risk / Needs Test | Docs still identify atomic lifecycle and concurrency gates as unfinished or needing deeper validation. |
| Ledger authority | Strong, Do Not Touch | SQL-authoritative posting, idempotency, append-only markers, locked-wallet and insufficient-funds errors are covered. Any change requires review. |
| Transaction history / movement classification | Do Not Touch | Current architecture separates ledger truth from UI/report wording. Do not change ledger writes for display fixes. |
| Reconciliation | Needs operational evidence | Reconciliation docs and tests exist, but production readiness needs scheduled runs, alert evidence, and restore-drill reconciliation. |
| Notifications / messaging | Partially hardened | Organization governance events now use a durable per-recipient claim ledger, stable provider request IDs, bilingual copy, mandatory Push/SMS/email routing when recipient endpoints exist, duplicate suppression, and stale/failed reclaim. A scheduled retry worker and delivery dashboard remain required across every financial domain. |
| WebSocket / realtime | Needs operational monitoring | Socket registry warnings in local test are expected without Supabase/env. Production needs heartbeat, reconnect, and delivery dashboards. |
| Security/auth | Strong, Needs env verification | Authorization, WAF, internal worker HMAC/mTLS, KMS lifecycle, and route guards are tested. Production requires real secrets, KMS readiness, token revocation coverage, and audit-chain checks. |
| Backup/restore | Not complete | Readiness checklist still requires automated restore test with production-like data. |
| Observability/SLOs | Not complete | Metrics exist in pieces, but distributed tracing, SLOs, dashboards, and alert runbooks are not complete. |
| Load/chaos testing | Not complete | 10x launch traffic load testing and chaos testing remain open. |

## Protected Core Services

These areas are considered completed enough that they should not be casually
edited:

- P2P send and settlement path.
- Current transaction history and receipt interpretation.
- SQL-authoritative ledger posting and append markers.
- PaySafe lifecycle logic unless a specific PaySafe defect is reproduced.
- Movement classification rules separating P2P, external, and self-service
  internal movements.

Any change in these areas must include:

- a failing test or audit finding;
- a minimal patch;
- ledger invariant check;
- idempotency/retry check;
- reconciliation impact note.

## Blocking Gaps Before “100% Core”

1. **Run DB-backed financial integration tests**
   - Use isolated disposable database only.
   - Enable read-only and write-enabled suites from `FINANCIAL_CORE_TEST_PLAN.md`.
   - Required for double-debit, concurrency, reversal, shared budget, bill
     reserve, webhook, and reconciliation mutation proof.

2. **Complete shared budget atomic lifecycle evidence**
   - Confirm allocate, spend, withdraw, invited member limits, owner controls,
     and auto-allocation are SQL-authoritative and replay-safe.
   - Add concurrency tests for overspend and duplicate approval claims.

3. **Finish durable notification/outbox workers**
   - PaySafe, shared pot, shared budget, contribution, withdrawal, invitation,
     and merchant checkout events must not depend on synchronous push/SMS/email.
   - Failed delivery must retry with backoff and appear in operations.

4. **Backup and restore drill**
   - Restore a production-like backup into an isolated machine.
   - Reconcile user counts, wallets, ledger totals, transactions, PaySafe,
     shared pots, shared budgets, audit chain, and gateway intents.

5. **Production observability**
   - Add dashboards for latency, success rate, provider failures, webhook
     failures, stuck transactions, settlement backlog, reconciliation drift,
     websocket health, and notification delivery.
   - Define SLOs and alerts.

6. **Security environment verification**
   - Verify KMS master secret, signing keys, worker HMAC, mTLS mode, token
     revocation, session expiry, audit signing, and secrets backup in the real
     self-hosted environment.

7. **Load and chaos testing**
   - Run 10x launch traffic load test.
   - Simulate network timeout, gateway restart, worker restart, DB retry,
     duplicate request, webhook replay, and delayed notification conditions.

## Recommended Next Execution Order

1. Prepare isolated financial DB fixture environment.
2. Run `npm run test:db:financial`.
3. Run `npm run test:db:financial:write`.
4. Fix only failures proven by those tests.
5. Complete shared budget concurrency tests.
6. Add notification outbox worker and dashboard evidence.
7. Perform restore drill and reconciliation report.
8. Only then reassess whether Core can be promoted from controlled-production
   foundation to final production certification candidate.

## Final Position

Core is not fragile, but it is not yet 100%.

The responsible label today is:

**“ORBI Core: strong controlled-production financial foundation with remaining
certification, DB mutation, restore, observability, and operational evidence
gates.”**
