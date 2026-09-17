# Ecosystem Authorization Inventory

Status: Slice 1 working inventory
Reviewed: 2026-09-10
Parent plan: [ORBI Ecosystem Readiness And Remaining Slices](./ECOSYSTEM_READINESS_AND_REMAINING_SLICES.md)

## Policy

Every request must pass all applicable checks:

```text
valid session or worker identity
-> active actor status
-> actor role or explicit permission
-> resource ownership / membership / tenant binding
-> operation-specific policy and limits
-> immutable audit for sensitive decisions
```

Path, query, and body identifiers are untrusted. A broad role does not grant
access to every resource belonging to that role family. Administrative access
must use an explicit permission and must be audited.

## Initial Route Inventory

| Surface | Route family | Existing boundary | Required resource boundary | Initial verdict |
| :--- | :--- | :--- | :--- | :--- |
| Business identity | `GET /v1/business/me` | Session subject | Subject-only profile | Acceptable baseline; add lifecycle tests |
| Business application | `POST /v1/business/registrations` | Session subject and role normalization | Subject-only request plus active-state transition rules | Acceptable baseline; needs full onboarding state machine |
| Service access | `/v1/service-access/requests*` | Session subject | Subject-only creation/list; permission-gated review | Verify with route and DB tests |
| Merchant discovery | `GET /v1/merchants*` | Authenticated user | Only public/active merchant projection | Needs response-field and status tests |
| Merchant account creation | `POST /v1/merchants/accounts` | Merchant/admin role | Owner must be session subject unless explicit staff permission | Needs authorization tests |
| Merchant account list | `GET /v1/merchants/accounts/my` | Merchant/admin role | Subject-owned accounts only | Acceptable shape; needs DB proof |
| Merchant account read | `GET /v1/merchants/accounts/:id` | Owner check in service; explicit audited staff branch | Account owner/merchant member or explicit audited staff permission | Code boundary added; route/DB proof pending |
| Merchant settlement update | `PATCH /v1/merchants/accounts/:id/settlement` | Owner check before settlement lookup/update; explicit audited staff branch | Owner plus challenge/approval for destination change; explicit staff permission | Ownership boundary added; change challenge and DB proof pending |
| Merchant transactions/wallets | `GET /v1/merchant/{transactions,wallets}` | Role plus session subject | Active merchant identity bound to returned rows | Verify service query and DB isolation |
| Merchant customers | `/v1/merchant/customers*` | Role plus session subject | Active merchant relationship only; consent and minimised fields | Verify consent and isolation |
| Merchant payment preview/settle | `/v1/merchant/payments/*` | Role, preview binding, idempotency on settle | Active merchant, owned source/destination, approved service scope and limits | Strong baseline; needs negative DB tests |
| Agent lookup | `GET /v1/agent/lookup` | Authenticated allowed role | Public active-agent projection only | Needs response-field/status tests |
| Agent transactions/wallets | `GET /v1/agent/{transactions,wallets}` | Role plus session subject | Active agent identity bound to rows | Verify service query and DB isolation |
| Agent customers | `/v1/agent/customers*` | Role plus session subject | Active agent relationship, consent, purpose and minimised fields | Verify consent and isolation |
| Agent commissions | `GET /v1/agent/commissions` | Role plus session subject | Agent-owned accruals or explicit audited staff permission | Verify staff/owner branching |
| Agent cash preview/settle | `/v1/agent/cash/*` | Role, preview binding, idempotency on settle | Active agent/till/device, customer consent, float and limits | **P0 certification gap** |
| Organization list | `GET /v1/enterprise/organizations` | Session subject | Active memberships only | Acceptable shape; needs DB proof |
| Organization create | `POST /v1/enterprise/organizations` | Authenticated user | Eligibility, duplicate prevention, lifecycle and provisioning policy | Needs onboarding hardening |
| Organization details | `GET /v1/enterprise/organizations/:id` | Active membership check in service; explicit audited staff branch | Active membership or explicit audited staff permission | Code boundary added; route/DB proof pending |
| Organization roles | `POST /v1/enterprise/organizations/:id/roles` | Service-level admin check | Organization admin plus permission and protected-role rules | Verify and add negative DB tests |
| Organization leadership | `/v1/enterprise/*admin-change*` | Service-level leadership checks | Membership, quorum, no self-approval, concurrency and expiry | Strong baseline; needs DB concurrency proof |
| Organization member link/invite | `/v1/enterprise/users/{link,invite}` | Service-level admin check | Active admin, target validation, invite expiry and least privilege | Needs lifecycle and abuse tests |
| Treasury withdrawal | `/v1/enterprise/treasury/withdraw/*` | SQL-authoritative request validates active organization resources, destination, currency, balance and policy; approval is serialized with maker-checker and duplicate checks | Organization membership, maker-checker, limits and resource ownership | Local request/quorum/ledger concurrency certification passed; staging proof remains |
| Treasury approvals list | `GET /v1/enterprise/treasury/approvals?orgId=` | Active membership and finance-role check in service; explicit audited staff branch | Active organization membership or explicit audited staff permission | Code boundary added; route/DB proof pending |
| Treasury autosweep | `POST /v1/enterprise/treasury/autosweep` | Validated input; actor-bound active organization admin check; explicit constrained goal columns | Admin/treasury permission, owned goal, limits and audit | Schema drift fixed; execution lifecycle certification pending |
| Tenant creation/list | `/v1/core/tenants*` | Session subject | Tenant owner/member lifecycle | Verify DB isolation |
| Tenant API keys | `/v1/core/tenants/:id/api-keys*` | Session subject passed to service | Tenant admin, environment binding, one-time secret, rotation/revocation audit | Verify all branches and DB tests |
| Tenant wallets | `GET /v1/core/tenants/:id/wallets` | Middleware tenant context plus session | Tenant membership and scoped wallet projection | Verify middleware cannot be bypassed |
| Tenant settlement | `/v1/core/tenants/:id/settlement/*` | Mixed service signatures | Tenant treasury permission, configuration challenge, payout idempotency and limits | Full route/service audit required |
| External service reads/actions | Developer and Gateway route families | Keys/workers/scopes in partial paths | Audience, environment, service state, scope, consent, subject and resource binding | **P0 before broad external access** |
| Provider webhooks | `POST /v1/webhooks/:partnerId` | Signature/replay verification | Partner binding, timestamp, event idempotency and durable application | Strong baseline; needs staging/recovery proof |
| Internal Gateway-to-Core | `/internal/*` | Worker authentication and scopes | Route-specific worker scope, request signature, replay protection and resource binding | Strong baseline; needs end-to-end certification |

## First Remediation Batch

The first code batch should be small and security-focused:

1. Add shared merchant, agent, organization, and tenant access resolvers that
   return a verified resource context rather than a boolean role result.
2. Patch merchant account read and settlement update to use verified merchant
   ownership or explicit staff permissions.
3. Patch organization detail, treasury approval listing, and autosweep to use a
   verified organization context.
4. Add route tests proving same-role cross-owner access is rejected.
5. Add isolated DB tests proving direct identifier substitution cannot bypass
   the service checks.
6. Audit and log permitted staff access and denied sensitive mutations without
   leaking protected resource data.

## Completion Evidence

Slice 1 cannot be marked complete until the repository contains:

- a route inventory with no unclassified ecosystem resource endpoints;
- shared, reviewed access-context helpers;
- negative tests for every P0 row above;
- disposable DB evidence for row ownership and concurrent mutations;
- stable `401`, `403`, `404`, and conflict error semantics that do not disclose
  another actor's resource existence;
- audit evidence for sensitive privileged access;
- updated OpenAPI/SDK contracts and release notes.

## Remediation Progress — 2026-09-10

The first authorization batch now rejects cross-owner merchant reads and
settlement updates, cross-organization detail and approval-list reads, and
cross-organization autosweep configuration. Treasury withdrawal approval also
resolves the withdrawal's corporate goal and requires an active `ADMIN` or
`FINANCE` actor in that same organization. Pure authorization tests and the
repository TypeScript/full test suites pass.

The treasury approval counter and transition from `held_for_review` to
`processing` are now owned by the service-role-only
`approve_treasury_withdrawal_v1` SQL function. It locks the withdrawal, goal,
and approver rows; enforces active same-organization `ADMIN` or `FINANCE`
membership; rejects maker self-approval and duplicate approval; and returns the
execution claim only to the call that crosses quorum.

This is code-level evidence only. Settlement destination step-up approval,
ledger posting plus goal reduction inside a recoverable execution boundary,
stable non-disclosing error contracts, and disposable database concurrency
tests remain release blockers.

Treasury execution now relies on the ledger RPC as the sole owner of the goal
balance reduction and supplies a stable append key and phase. This removes the
previous second application-level goal decrement and makes repeated ledger
append attempts detectable. Approval creates a two-minute execution lease, and
the existing reconciliation reaper uses a service-role-only, row-locked claim
function to recover expired leases. It detects already-posted debit/credit legs
and finalizes the transaction without posting them again. Local database
concurrency certification passed; remote staging and deliberate worker-kill
recovery remain required.

A write-enabled treasury concurrency scenario is now part of
`financialCoreDbMutation.test.ts`. It checks cross-organization denial,
maker-checker denial, two simultaneous approvals with exactly one execution
claim, two simultaneous ledger appends with exactly one successful append, two
ledger legs, and single balance movement. The write runner now requires both an
explicit `--confirm-disposable-database` flag and
`ORBI_DB_TEST_DISPOSABLE=true` inside the dedicated env file. The scenario is
passed on 2026-09-10 against a fresh local PostgreSQL database named
`orbi_treasury_certification`, built from the canonical schema and guarded
fixtures. Concurrent approvals produced one execution claim; concurrent ledger
appends produced one append and one idempotency rejection; the test observed
two ledger legs and one goal debit/destination credit before restoring fixture
balances.

The treasury request path now uses `request_treasury_withdrawal_v1`. The SQL
boundary locks the goal, requester and destination wallet; requires active
same-organization ownership and matching currency; checks available balance;
applies the active policy's per-transaction and daily limits; and derives the
approval quorum from policy with a minimum of two. The same live disposable
scenario passed after creating the withdrawal through this RPC. Autosweep state
now uses constrained `goals.auto_sweep_enabled` and `goals.sweep_threshold`
columns instead of the nonexistent `goals.metadata` field.

Treasury policy administration now exposes authenticated read and update APIs.
The service-role-only update RPC requires an active same-organization `ADMIN`,
validates currency and limit ordering, requires a meaningful change reason, and
rejects a quorum larger than the active `ADMIN`/`FINANCE` population. One active
policy is allowed per organization and currency. Every resulting policy state
is stored in `treasury_policy_versions`, and sensitive updates emit an audit
event. The fresh local database scenario passed cross-organization denial,
infeasible quorum rejection, versions 1 and 2, and policy use by a withdrawal.
