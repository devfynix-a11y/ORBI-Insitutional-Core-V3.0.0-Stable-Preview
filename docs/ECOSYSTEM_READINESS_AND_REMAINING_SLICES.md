# ORBI Ecosystem Readiness And Remaining Slices

Status: active delivery plan; external ecosystem launch is blocked
Reviewed: 2026-09-10
Scope: merchants, agents, organizations, developers, external services, and the
operational controls required to run them safely on ORBI Core.

## 1. Decision

ORBI has a substantial controlled-production foundation, but it is not ready
for unrestricted merchant, agent, organization, or third-party onboarding.

The ledger, PaySafe, provider boundary, business registration baseline,
merchant and agent operations, organization governance, developer contracts,
and administrative controls already exist in code. The remaining work is
mainly tenant isolation, complete lifecycle enforcement, database-backed proof,
durable asynchronous delivery, operational evidence, and self-service surfaces.

No ecosystem actor should receive live financial access merely because an HTTP
route or database table exists. Live access requires all gates for that actor in
this document to pass.

## 2. Evidence Reviewed

This assessment is based on the current implementation, including:

- `src/routes/public/business.ts`
- `src/routes/public/commerce.ts`
- `src/routes/public/operations.ts`
- `src/routes/public/coreFinance.ts`
- `src/routes/public/adminOps.ts`
- `src/routes/internal/index.ts`
- `backend/business/BusinessIdentityService.ts`
- `backend/server.ts`
- `backend/features/b2b/`
- `backend/wealth/`
- `database/main.sql` and `database/reset_schema.sql`
- the automated tests under `tests/`
- the canonical architecture, registration, BaaS, security, recovery, and
  production-readiness documents listed in `DOCUMENTATION_INDEX.md`

Documented contracts without an enforced code path and a passing test are
classified as planned. Source-level tests without isolated database execution
are classified as implemented but uncertified.

## 3. Readiness Matrix

| Capability | Current level | Launch decision | Main missing proof or control |
| :--- | :--- | :--- | :--- |
| Consumer financial core | Controlled production foundation | Limited | DB mutation, load, recovery, and operational certification |
| Merchant identity and approval | Implemented baseline | Pilot only | End-to-end KYB, approval provisioning, suspension, and ownership tests |
| Merchant wallets and transactions | Implemented baseline | Blocked | Consistent object-level ownership and tenant isolation enforcement |
| Merchant checkout and PaySafe | Strong baseline | Controlled pilot | Full gateway/core staging drill, settlement reporting, retry and recovery evidence |
| Agent identity and approval | Implemented baseline | Pilot only | KYA/KYB evidence, activation controls, limits, float certification, and lifecycle tests |
| Agent cash operations | Implemented baseline | Blocked | Database-backed double-spend, float, cash-in/cash-out, reversal, and concurrency proof |
| Agent commissions | Implemented baseline | Pilot only | Accrual/finalization/reversal reconciliation and dispute lifecycle evidence |
| Organization membership and roles | Implemented baseline | Blocked | Object-level authorization, membership isolation, invitation expiry, and role-change concurrency proof |
| Organization treasury | Controlled pilot foundation | Pilot only | Shared budget/scheduled-operation certification, statements, exception workflow, and operations sign-off |
| Developer applications and keys | Contract/store baseline | Sandbox pilot | Self-service UI, live approval ceremony, key rotation drill, and package release |
| OAuth/OIDC consent | Partial | Blocked for broad third-party reads | Shared runtime scope enforcement, complete consent UI/audit, renewal and revocation proof |
| Webhook delivery | Partial | Controlled pilot | Durable production retry worker, backoff, ordering, DLQ, alerting, and recovery drill |
| Reconciliation and reporting | Partial | Blocked for scaled settlement | Actor reports, scheduled reconciliation, exception workflow, exports, and sign-off evidence |
| Operations and observability | Partial | Blocked for scale | SLOs, traces, dashboards, alerts, worker health, and incident exercises |
| Backup and disaster recovery | Documented, uncertified | Blocked for final certification | Successful production-like restore drill and financial reconciliation evidence |

## 4. Confirmed Foundations

### Merchant

- Authenticated merchant discovery, accounts, wallets, transactions, customer
  registration, payment preview, and idempotent settlement routes exist.
- PaySafe merchant settlement uses an atomic, balanced, SQL-authoritative path.
- Merchant linkage, merchant wallet roles, fees, gateway intents, hosted
  challenges, and guest checkout controls exist in the Core/Gateway boundary.
- Service-access requests provide a controlled upgrade path from consumer to
  merchant identity.

### Agent

- Authenticated agent lookup, wallets, transactions, linked customers,
  commissions, and cash deposit/withdraw preview and settlement routes exist.
- Settlement routes require idempotency keys and use the transaction preview
  binding.
- Administrative float controls, commission disputes, and B2B risk dashboards
  exist as operational foundations.

### Organization

- Organization creation, membership linking/invitation, role definitions,
  multi-leader admin changes, treasury approvals, limits, and shared-finance
  organization access models exist.
- Organization role and leadership logic contains explicit governance checks in
  several service methods.

### Developer and external services

- Service applications, scope requests, allowlists, one-time key and webhook
  secret issuance, sandbox/live profiles, webhook logs/replay, integration
  health, an OpenAPI bootstrap, CLI tooling, and a TypeScript SDK baseline are
  documented and partially implemented.
- Internal Gateway-to-Core routes use worker authentication boundaries and
  persist durable intent/challenge/result state.

## 5. Launch-Blocking Findings

### P0: object-level authorization is not uniform

Authentication and broad role checks are present, but several resource routes
do not carry the authenticated actor into the final resource lookup or update.
Examples in the current route layer include:

- reading a merchant account by arbitrary account ID;
- updating merchant settlement details by arbitrary merchant ID;
- reading organization details by arbitrary organization ID;
- listing treasury approvals from a caller-supplied organization ID;
- configuring treasury autosweep without an actor-bound organization check.

Every resource read and mutation must enforce ownership, organization
membership, tenant membership, or an explicit staff permission at the same
database boundary that selects or mutates the record. A role such as
`MERCHANT`, `AGENT`, or `ADMIN` is not sufficient proof of access to a specific
merchant, agent, organization, wallet, settlement profile, or customer.

### P0: financial lifecycle certification is incomplete

Agent cash operations, organization treasury, shared budgets, commission
reversals, merchant settlement, webhook application, and recovery paths require
isolated database mutation and concurrency evidence. Source inspection and
mocked unit tests cannot certify double-entry integrity or lock behavior.

### P0: business onboarding is not a complete regulated lifecycle

The service-access request baseline exists, but production onboarding still
needs a single enforced state machine covering KYB/KYA evidence, beneficial
owners where applicable, risk tier, product scopes, transaction limits,
settlement configuration, wallet provisioning, approval separation,
activation, suspension, termination, and reactivation.

### P1: asynchronous delivery is not operationally complete

Organization governance notifications now have durable per-recipient claims,
stable request identifiers, bilingual Push/SMS/email delivery, and duplicate
suppression. Merchant webhooks and the remaining business notifications still need durable claim/retry workers,
exponential backoff with jitter, ordering rules, dead-letter handling, replay
authorization, alerting, retention, and reconciliation from ORBI truth.

### P1: schema change discipline needs consolidation

The repository currently relies heavily on `database/main.sql` and
`database/reset_schema.sql`; the migrations directory does not provide a clear
ordered history for the ecosystem capabilities reviewed. Production rollout
needs immutable, ordered, forward-only migrations with checksums, rollback or
forward-fix instructions, and schema-version evidence.

### P1: operations evidence is incomplete

Actor-specific SLOs, traces, dashboards, alerts, settlement exception queues,
security-event review, backup restore evidence, load tests, chaos exercises, and
partner certification packs remain required.

## 6. Delivery Slices

Each slice must leave a deployable, reviewable system. A slice is complete only
when its route contracts, authorization, persistence, audit, tests, operations,
and documentation agree.

### Slice 1: ecosystem authorization boundary

Priority: P0
Goal: prevent cross-merchant, cross-agent, cross-organization, and cross-tenant
access.

- Inventory every ecosystem route and classify its resource owner.
- Introduce shared actor-context and resource-authorization helpers.
- Bind merchant account reads/updates to owner or explicit staff permission.
- Bind agent resources and linked customers to the active agent identity.
- Bind organization reads, approvals, treasury actions, roles, invitations,
  limits, and autosweep to active membership plus permission.
- Bind tenant API keys, wallets, settlement configuration, and payouts to
  tenant membership.
- Reject inactive, suspended, blocked, expired, or unapproved actor identities.
- Add negative integration tests for horizontal and vertical privilege
  escalation and audit denied sensitive actions.

Definition of done: an authenticated actor cannot access another actor's
resource by changing a path, query, or body identifier; privileged staff access
is explicit, permission-gated, and audited.

The working endpoint matrix and first remediation batch are maintained in
[Ecosystem Authorization Inventory](./ECOSYSTEM_AUTHORIZATION_INVENTORY.md).

### Slice 2: canonical business onboarding and lifecycle

Priority: P0
Goal: create one authoritative merchant, agent, and organization activation
workflow.

- Define canonical actor and application states and permitted transitions.
- Validate required identity, KYB/KYA, ownership, contact, settlement, and risk
  evidence by actor type and jurisdiction.
- Separate applicant, reviewer, approver, and provisioner duties.
- Provision registry identity, wallets, limits, scopes, organization membership,
  and settlement policy atomically or through a recoverable saga.
- Add suspension, termination, reactivation, and periodic-review flows.
- Make every transition idempotent and append an immutable audit event.

Definition of done: approval produces a transaction-ready actor or a clearly
recoverable failed-provisioning state; no manual database edit is required.

### Slice 3: merchant operating plane

Priority: P0
Goal: support a merchant from onboarding through reconciliation.

- Complete checkout, PaySafe, refund, dispute, settlement and payout scenarios.
- Enforce settlement destination ownership and change approval/challenge.
- Add merchant users, roles, branches/stores, terminal/service identities, and
  least-privilege permissions where required by product scope.
- Produce merchant transaction, fee, escrow, refund, dispute, settlement, and
  payout reports from authoritative records.
- Add idempotency, duplicate callback, delayed settlement, and provider outage
  tests.

Definition of done: a pilot merchant can accept, reconcile, refund or dispute,
and settle payments without engineering or database access.

### Slice 4: agent operating plane

Priority: P0
Goal: operate cash services without float leakage or untraceable commission.

- Enforce agent status, location/branch, device, till, float, velocity, and
  transaction limits.
- Certify cash-in and cash-out posting, reversal, timeout, duplicate request,
  offline/retry, and insufficient-float behavior against a disposable DB.
- Make commission accrual, pending settlement, finalization, reversal, payout,
  tax/withholding metadata, reconciliation, and disputes explicit.
- Add daily till close and float reconciliation workflows.

Definition of done: every unit of agent cash and electronic value reconciles,
and a failed or replayed request cannot create value or duplicate commission.

### Slice 5: organization governance and treasury

Priority: P0
Goal: provide secure multi-user institutional money control.

- Complete organization membership, invitation expiry, role assignment, custom
  permissions, removal, and account recovery.
- Define maker-checker matrices by amount, operation, risk, and organization
  policy.
- Enforce transaction limits, approval quorum, segregation of duties, and
  self-approval prohibition at the database transaction boundary.
- Certify treasury withdrawal, autosweep, shared pot/budget, and scheduled
  operations for concurrency and replay safety.
- Add organization statements, approval history, audit exports, and exception
  handling.

Definition of done: organization funds cannot move outside the configured
policy even if clients race, retry, or manipulate identifiers.

Implemented and certified on the disposable PostgreSQL target as of
2026-09-11:

- SQL-authoritative treasury withdrawal creation, per-transaction and daily
  limits, maker-checker enforcement, concurrent quorum, and idempotent ledger
  execution;
- versioned organization/currency treasury policy administration;
- explicit active approver assignments with expiring add/remove requests,
  independent administrator review, target self-review prevention, and a
  database guard that prevents removal below active policy quorum;
- consent-based organization invitations with 72-hour expiry, target-bound
  acceptance, concurrent-response locking, and denial of privileged roles;
- the legacy direct-link endpoint now creates an invitation instead of writing
  organization membership immediately;
- regular member role changes and removal use expiring dual-control requests;
  the database prevents requester/target review and protects primary admins,
  privileged roles, and active treasury approvers from this lower-trust path;
- privileged admin promotion, removal, and primary-admin transfer now execute
  under row lock with a feasible one-or-two independent reviewer quorum;
  leadership changes expire, reject duplicate reviews, preserve at least one
  administrator, require primary transfer before removal, and require treasury
  assignment removal through its own dual-control workflow;
- organization recovery requires two verified contacts, a 24-hour cooling
  period, an external super-admin reviewer, and separation between requester,
  old primary, and beneficiary; execution revokes old-primary sessions,
  suspends the compromised identity, and preserves treasury quorum;
- recovery contacts are now bound to active external ORBI identities, store a
  one-way contact hash, and require primary-admin enrollment plus independent
  super-admin verification or revocation review;
- post-recovery reactivation now requires recorded identity re-verification,
  credential reset, incident closure, a 24-hour cooling period, and external
  approval; old sessions remain revoked and the restored identity returns with
  the least-privileged `MEMBER` role;
- service-role-only RPC exposure, actor-bound HTTP routes, and security audit
  events for policy and approver changes;
- a clean `reset_schema.sql` rebuild followed by live lifecycle, access,
  concurrency, quorum, and single-ledger-append proof.

Shared Pot and Shared Budget now have live disposable-database evidence for
atomic creation, membership, balanced movement, concurrent reservation limits,
maker-checker approval claims, replay protection, and least-authority access.
Financial activity notifications use stable event identities across available
Push, SMS, and email channels to suppress duplicate delivery.

Scheduled treasury operations now use independently approved, expiring schedule
change requests. Due occurrences have unique database identities, concurrent
workers claim rows with `SKIP LOCKED`, expired worker leases are recoverable,
and calendar intervals preserve the configured local wall time across timezone
offset changes. Every terminal execution produces an audited status and a
stable notification event across Push, SMS, and email, preventing duplicate
messages during worker recovery.

Organization statements now snapshot SQL-authoritative ledger entries into
immutable, ordered lines for a bounded closed period. Generation validates the
organization finance role and IANA timezone, rejects malformed ledger data,
deduplicates identical periods under a database lock, records currency totals,
and seals the result with a SHA-256 content hash. Read APIs use bounded
pagination and produce audited access events; readiness notifications use a
stable identity across Push, SMS, and email.

Audit evidence exports now require a bounded 90-day scope, explicit purpose,
stable request identity, and independent privileged review. Approval snapshots
up to 25,000 ordered signed audit entries into a sealed package with a SHA-256
manifest hash. Packages expire after seven days and allow three downloads;
download claims are party-bound, row-locked, counted, and idempotent. JSON and
formula-injection-safe CSV delivery both expose the package integrity hash.
Request, review, and first-download events are audited, while Push, SMS, and
email notifications use stable event identities.

Financial exceptions now enter a canonical queue from reconciliation
mismatches with a stable source identity, severity, explicit ownership, and
severity-based SLA. Overdue cases escalate automatically. Resolution requires
an assigned officer, a typed disposition, structured evidence, and an expiring
request approved by a different privileged officer. Assignment, escalation,
resolution request, and review use audited events plus stable Push, SMS, and
email notifications.

Slice 5 implementation is complete. Production promotion still requires the
actor certification and operations sign-off defined in Slice 8.

### Slice 6: consented external APIs and developer platform

Priority: P1
Goal: expose useful APIs without giving third parties ambient financial access.

- Finish OAuth/OIDC authorization and consent UI.
- Enforce audience, environment, service status, scopes, active consent,
  purpose, subject, and resource ownership on every external request.
- Complete sandbox isolation and deterministic lifecycle simulation.
- Publish versioned OpenAPI and SDK packages from source contracts.
- Complete self-service application, allowlist, key, secret, logs, replay,
  health, and live-access workflows.

Definition of done: an approved developer can integrate entirely through the
portal and sandbox; live credentials are issued only after automated and human
gates pass.

The external-request authorization foundation is now implemented. Tenant API
secrets use cryptographically random material, are returned once, and only a
SHA-256 verifier plus a short fingerprint is stored. The runtime guard binds
each request to its environment, audience, least-privilege scopes, active
service approval, and, whenever a customer subject is supplied, an active,
unexpired, scope- and purpose-bound payment-profile consent. The RPC is
service-role-only and records credential use. Sandbox isolation, OAuth/OIDC
consent UX, portal lifecycle gates, and generated public contracts remain in
Slice 6.

### Slice 7: reliable events, reconciliation, and operations

Priority: P1
Goal: make outages visible and recoverable without corrupting financial truth.

- Implement production outbox workers, webhook retries, ordering, DLQ, replay,
  and delivery alerts.
- Schedule ledger, provider, PaySafe, merchant, agent, commission, settlement,
  and organization reconciliation.
- Add OpenTelemetry traces, actor-specific metrics, SLOs, alert thresholds, and
  runbooks.
- Complete backup/restore, worker restart, provider timeout, duplicate event,
  delayed callback, load, and chaos drills.

Definition of done: operators can detect, explain, retry, reconcile, and close
an incident using supported controls and signed evidence.

### Slice 8: certification and controlled launch

Priority: P1
Goal: turn implementation evidence into a repeatable live-partner gate.

- Create actor-specific certification suites and evidence bundles.
- Require security, finance, operations, compliance, and business sign-off.
- Run a limited pilot with explicit limits and rollback triggers.
- Review SLO/error budget, reconciliation, complaints, fraud, settlement, and
  recovery evidence before increasing limits or actor count.

Definition of done: every live actor and product scope has an owner, approved
configuration, passed test evidence, monitored SLO, runbook, and revocation
path.

## 7. Required Test Layers

Every ecosystem slice must include:

1. Contract tests for validation, stable errors, idempotency, and versioning.
2. Authorization tests for unauthenticated, wrong role, wrong owner, wrong
   organization, wrong tenant, inactive actor, and permitted staff access.
3. Isolated DB tests for constraints, transactions, row locks, concurrent
   requests, replay, rollback, and ledger balance.
4. Gateway/Core tests for signatures, timeouts, retries, callbacks, and recovery.
5. Operational tests for metrics, audit events, alerts, reconciliation, backup,
   restore, and worker restart.
6. Load and chaos tests against production-like staging.

## 8. Immediate Execution Order

1. Complete Slice 1 route and resource authorization inventory.
2. Fix and test all P0 object-level authorization findings.
3. Establish ordered schema migrations for the affected controls.
4. Build the disposable DB certification environment and run financial mutation
   tests.
5. Complete the canonical onboarding state machine.
6. Certify merchant, agent, and organization operating planes in that order.
7. Finish consent, sandbox, developer self-service, webhook workers,
   reconciliation, observability, and recovery.
8. Run controlled partner certification and pilot gates.

This execution order protects the existing ledger foundation while closing the
access-control and evidence gaps that currently prevent safe ecosystem scale.

Sandbox payment isolation is also implemented through a separate, service-role-only simulation store. Explicit success, decline, timeout, and authorization scenarios are deterministic and replay safe; sandbox requests exit before every live customer, merchant, wallet, ledger, provider, OTP, and notification path.
