# Financial Core Engine (Core Banking Architecture)

**Classification**: INSTITUTIONAL / CORE ARCHITECTURE  
**Version**: 2.0.0  
**Last Updated**: 2026-03-11

---

## 1. Executive Summary
The **Financial Core Engine** elevates ORBI from a simple wallet application to a full-fledged **Banking-as-a-Service (BaaS) / Fintech Platform**. By introducing a true **Multi-Tenant Architecture**, the system can now natively host and isolate different types of financial entities on the same infrastructure.

This is the exact architecture used by modern Core Banking Systems to manage accounts, balances, transactions, clearing, and settlement across multiple distinct businesses.

---

## 2. Multi-Tenant Architecture

### 2.1 The `tenants` Entity
A Tenant is any distinct entity operating on the platform.
- **`individual`**: A standard retail user.
- **`merchant`**: A business accepting payments.
- **`marketplace`**: A platform hosting multiple sub-merchants.
- **`partner`**: A B2B partner integrating via API.
- **`system`**: Internal ORBI operational accounts (e.g., fee collection, treasury).

### 2.2 Tenant Users (`tenant_users`)
Users are no longer strictly tied to personal wallets. A single user (via `auth.users`) can belong to multiple tenants with different roles:
- **`owner`**: Full control, can generate API keys.
- **`admin`**: Can manage operations and staff.
- **`staff`**: Can view transactions and perform daily operations.
- **`viewer`**: Read-only access.

### 2.3 Wallet Ownership Isolation
Wallets are now strictly bound to a `tenant_id`.
- **`owner_type`**: Defines if the wallet belongs to a `user`, `merchant`, or `system`.
- **`tenant_id`**: Ensures strict data isolation. A marketplace cannot see a merchant's wallet unless explicitly authorized.

### 2.4 Transaction Isolation
Every transaction in the `transactions` table is now tagged with a `tenant_id`. This guarantees that when a tenant queries their ledger, they only see their own financial movements, enforced at the database level via Row Level Security (RLS).

### 2.5 API Keys & Integration (`api_keys`)
Tenants (like Merchants and Partners) can generate API keys to integrate their external systems with the ORBI Financial Core.
- **`public_key`**: Used for client-side integrations (e.g., checkout forms).
- **`secret_key`**: Used for server-to-server API calls.

---

## 3. API Endpoints

All endpoints are protected and require a valid user session.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/v1/enterprise/organizations` | Create a new Organization (Tenant). |
| `GET` | `/v1/enterprise/organizations` | List all Organizations the current user belongs to. |
| `GET` | `/v1/enterprise/organizations/:id` | Get details of a specific organization. |
| `POST` | `/v1/core/tenants/:id/api-keys` | Generate new API keys for a specific tenant. |
| `GET` | `/v1/core/tenants/:id/api-keys` | List all API keys for a specific tenant. |
| `DELETE` | `/v1/core/tenants/:id/api-keys/:keyId` | Revoke a specific API key. |
| `GET` | `/v1/wallets` | List all wallets (filtered by organization context if applicable). |

---

## 4. Programmatic Access (External API)
Tenants use a secret API key for server-to-server access. Raw secrets are shown once and never persisted. Requests must include `x-api-environment` and `x-api-audience`; every endpoint enforces its required scopes. Customer-subject requests also require `x-orbi-subject` and `x-orbi-purpose`, backed by active, unexpired consent.

### 4.1 Authentication Header
All programmatic requests must include the `x-api-key` header:
```http
GET /v1/external/wallets
x-api-key: sk_live_...
```

### 4.2 External API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/v1/external/wallets` | Fetch all wallets belonging to the tenant associated with the API key. |

---

## 5. Security & Row Level Security (RLS)

The Financial Core Engine relies heavily on PostgreSQL RLS to ensure absolute data isolation:
1. **Tenant Visibility**: A user can only `SELECT` from `tenants` if their `user_id` exists in `tenant_users` for that tenant.
2. **API Key Security**: Only users with the `owner` or `admin` role in `tenant_users` can view or generate API keys.
3. **Ledger Isolation**: Transactions are strictly filtered by `tenant_id`.

---

## 6. Settlement Engine
The Settlement Engine is responsible for moving funds from the ORBI platform to the tenant's external financial accounts (Bank, Mobile Money, etc.).

### 6.1 Settlement Lifecycle
1. **Transaction Completion**: A customer pays a tenant. The transaction is marked as `settlement_status = 'PENDING'`.
2. **Net Position Calculation**: The engine sums all pending credits and debits for the tenant.
3. **Payout Creation**: A `settlement_payouts` record is created, deducting platform fees.
4. **External Transfer**: The engine triggers an external transfer to the tenant's configured destination.
5. **Reconciliation**: Once the external transfer is confirmed, the payout is marked as `COMPLETED` and the linked transactions are marked as `SETTLED`.

### 6.2 Settlement API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/v1/core/tenants/:id/settlement/config` | Get bank/mobile money payout details. |
| `PATCH` | `/v1/core/tenants/:id/settlement/config` | Update payout destination and schedule. |
| `GET` | `/v1/core/tenants/:id/settlement/pending` | Get total amount waiting to be settled. |
| `POST` | `/v1/core/tenants/:id/settlement/payout` | Manually trigger a payout. |
| `GET` | `/v1/core/tenants/:id/settlement/history` | List all previous payout events. |

---

## 7. Next-Generation Security Architecture (Titanium Hardened V26)

The ORBI Financial Core implements a 9-layer security pipeline designed to protect institutional assets and user data, achieving a true Zero-Trust model.

### Layer 1: Passkeys Authentication (WebAuthn)
**File**: `/backend/src/modules/passkey/passkey.service.ts`  
Replaces legacy passwords and OTPs with FIDO2-compliant Passkeys. Uses public-key cryptography to eliminate phishing and credential stuffing.

### Layer 2: Device Fingerprinting
**File**: `/backend/src/services/fingerprint.service.ts`  
Generates a unique SHA-256 hash based on hardware, OS, browser, and IP characteristics. Detects when a user logs in from an unrecognized or high-risk device.

### Layer 3: Behavioral Biometrics
**File**: `/backend/src/services/behavior.service.ts`  
Analyzes user interaction patterns (typing speed, swipe velocity, touch pressure). Calculates an anomaly score to detect bots or unauthorized human users even if they have the correct credentials.

### Layer 4: Deterministic Risk Scoring Engine
**File**: `/backend/src/services/risk.service.ts`  
Calculates a real-time **Risk Score (0-100)** for every request based on:
- **Velocity**: Too many transactions in a short window.
- **Location**: IP address mismatch or impossible travel speed (e.g., login from NY, then London 5 minutes later).
- **Amount**: Unusually large transaction volumes compared to historical data.

### Layer 5: AI Fraud Detection Engine
**File**: `/backend/src/modules/fraud/ai-fraud.service.ts`  
An ML inference pipeline (Isolation Forest / Gradient Boosting) that evaluates complex, non-linear features (login time, device age, behavioral patterns) to calculate an AI-driven risk score.

### Layer 6: Account Takeover (ATO) Detection
**File**: `/backend/src/services/fraud.service.ts`  
Correlates signals from Layers 2, 3, and 4 to detect Account Takeovers. Automatically freezes accounts or triggers step-up authentication if an ATO is suspected.

### Layer 7: Zero-Trust API Architecture
**File**: `/server.ts` & `/backend/src/middleware/session-monitor.middleware.ts`  
Every API request is authenticated, throttled by the WAF, and evaluated by the Risk Engine before reaching core business logic. No internal network trust is assumed.

### 7.1 Transaction Service & Ledger Integrity
**File**: `/ledger/transactionService.ts`  
The `TransactionService` is the primary interface for all ledger operations, ensuring atomic commits and proactive integrity checks.
- **Atomic Ledger Updates**: Uses `append_ledger_entries_v1` RPC to commit multiple ledger legs and update wallet balances in a single database transaction.
- **Proactive Verification**: Calls `verifyWalletBalance` after transactions to compare cached balances with ledger sums.
- **System Reconciliation**: Provides `reconcileAllWallets` for periodic system-wide integrity audits.
- **Forensic Reversal**: Implements `reverseTransaction` for secure, audited rollback of completed transactions.
- **Audit Integration**: All sensitive operations (reversals, balance adjustments) are logged to the `audit_trail` via the `Audit` service.

### Layer 8: Hardware Security Modules (HSM) & Secure Enclave
**Files**: `/backend/src/modules/security/hsm.service.ts` & `/backend/src/modules/transaction/signing.service.ts`  
- **HSM**: Simulates secure hardware for generating RS256 JWT session tokens.
- **Secure Enclave**: Verifies cryptographic signatures generated by a mobile device's Secure Enclave (Apple) or Titan M chip (Android) before processing high-value transactions. Also verifies device integrity via Attestation Tokens (Play Integrity/DeviceCheck).

### Layer 9: Continuous Session Monitoring
**File**: `/backend/src/middleware/session-monitor.middleware.ts`  
Continuously monitors active sessions for drastic IP changes or device fingerprint alterations mid-session, invalidating compromised sessions in real-time.

---

## 8. Content Sanitization & WAF
**File**: `/backend/security/sanitizer.ts`  
Protects against XSS (Cross-Site Scripting) by deeply sanitizing all incoming JSON payloads. It strips malicious HTML/JS tags before they reach the database or business logic.

- **Input Analysis**: Malicious patterns detected by WAF.
- **Velocity Signals**: Request frequency from a specific IP.
- **Device Trust**: Verification of the client application origin.
- **AI Anomalies**: Behavioral insights from Sentinel AI.

**Enforcement Rules**:
- **0-60**: Allow request.
- **60-80**: Challenge (Requires Step-up verification/OTP).
- **80-100**: Hard Block.

### 8.1 Transaction Guard / Policy Engine
**File**: `/backend/ledger/PolicyEngine.ts`  
A financial control layer that enforces institutional rules before ledger execution:
- **Transaction Limits**: Maximum amount per single operation.
- **Daily Limits**: Cumulative spending/transfer limits per 24-hour window.
- **Velocity Guard**: Prevents rapid-fire transactions (e.g., max 50/hour).
- **Account Freeze**: Automatically places security holds on accounts violating policies.

### 7.4 Security Pipeline Flow
`Request` → `WAF` → `Sanitizer` → `Risk Engine` → `Auth` → `Policy Engine` → `Ledger`

---

## 9. Escrow & TrustBridge Services
The **TrustBridge** is a conditional payment layer integrated into the Core Banking Engine. It allows for secure P2P and B2B transactions where funds are held in a specialized `PaySafe` vault until specific conditions are met.

### 9.1 Escrow Lifecycle
1.  **Initiation**: A buyer creates an escrow agreement, and funds are moved from their wallet to a system-controlled `PaySafe` vault.
2.  **Notification**: The seller is notified of the locked funds.
3.  **Fulfillment**: The seller delivers the goods/services.
4.  **Release**: Upon buyer confirmation or logistics verification, funds are moved from `PaySafe` to the seller's wallet.
5.  **Dispute**: If a dispute is raised, funds remain locked until a resolution is reached via the **Dispute Management** workflow.

### 9.2 Escrow API Endpoints
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/v1/escrow` | Create a new escrow agreement. |
| `GET` | `/v1/escrow` | List all escrow agreements for the current user/organization. |
| `GET` | `/v1/escrow/:id` | Get details of a specific escrow agreement. |
| `POST` | `/v1/escrow/:id/release` | Release funds to the beneficiary. |
| `POST` | `/v1/escrow/:id/dispute` | Raise a dispute on an escrow agreement. |
| `POST` | `/v1/escrow/:id/refund` | Refund funds to the sender (requires approval or cancellation). |

---

## 10. Treasury & Liquidity Management
For Enterprise tenants, the Core Banking Engine provides advanced treasury tools to manage liquidity across multiple departmental accounts.

### 10.1 Auto-Sweep Logic
The **Treasury Service** can be configured to monitor operating wallets and automatically "sweep" excess funds into a high-yield or long-term treasury goal once a specific balance threshold is reached.

### 10.2 Multi-Sig Approval Workflow
High-value withdrawals from treasury accounts or goals require multi-signature approval.
- **Request**: A staff member initiates a withdrawal request.
- **Approval**: One or more authorized admins must approve the request via the Treasury dashboard.
- **Execution**: Once the required number of approvals is met, the ledger executes the transaction.

### 10.3 Treasury API Endpoints
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/v1/enterprise/treasury/sweep/config` | Configure auto-sweep rules for an organization. |
| `POST` | `/v1/enterprise/treasury/withdrawals/request` | Initiate a multi-sig withdrawal request. |
| `POST` | `/v1/enterprise/treasury/withdrawals/:id/approve` | Approve a pending withdrawal request. |
| `GET` | `/v1/enterprise/treasury/withdrawals/pending` | List all pending withdrawal requests. |

---

## 11. Messaging & Notification Routing
**File**: `/backend/features/MessagingService.ts` & `/backend/security/otpService.ts`

ORBI implements an intelligent, multi-channel messaging router designed for high reliability and real-time engagement.

### 11.1 Messaging Dispatcher (`MessagingService.dispatch`)
The `MessagingService.dispatch` method is the central hub for all outgoing communications. It supports:
- **Direct-to-App Notifications**: Real-time delivery via WebSockets (`nexus-stream`) if the user is currently online.
- **Multi-Channel Fallback**: If the user is offline or the direct-to-app delivery fails, the system automatically routes the message through secondary channels (Push, SMS, WhatsApp, Email) based on user preferences and regional specialization.
- **Transactional Reference Numbers (`refId`)**: Every transactional message (OTP, Security Alert, Payment Confirmation) is automatically assigned a unique 8-character reference ID for tracking and auditing.
- **Device Identification**: Notifications include the specific device name (e.g., "iPhone 15", "Android Device") extracted from the User-Agent or user metadata to provide better security context.

### 11.2 Channel Prioritization Logic
The system evaluates user metadata (Country, FCM Tokens, Phone, Email) to select the optimal delivery path:

1.  **Direct-to-App (WebSocket)**: Highest priority for active sessions.
2.  **SMS (Primary Fallback)**: Prioritized for all users if a phone number is available, ensuring delivery in low-data environments.
3.  **Push Notifications (Secondary Fallback)**: Used if an FCM token is present.
4.  **WhatsApp (Enterprise)**: Used for high-priority transactional alerts in supported regions.
5.  **Email (Tertiary Fallback)**: Used for long-form regulatory communications or when other channels are unavailable.

### 11.3 Regional Specialization (Tanzania)
For users with a Tanzanian country code (`TZ` / `+255`), the system enforces **Strict SMS Prioritization** for critical security events (like OTPs) to ensure 99.9% delivery success across local mobile networks (Vodacom, Tigo, Airtel, Halotel).

## 12. Cross-Currency Transactions & FX Engine
The **FX Engine** enables seamless cross-border payments by automatically converting funds between different currencies (e.g., KES to TZS) before settlement.

### 12.1 Currency Conversion Logic
1.  **Detection**: The `EnterprisePaymentProcessor` identifies if the source and target wallets use different currencies.
2.  **Corridor Check**: ORBI checks `fx_corridors` to confirm the currency pair is active, amount limits are valid, and the configured rate provider is allowed for that corridor.
3.  **Rate Fetching**: The `FXEngine` requests a market rate from the formal `LiquidityProviderAdapter`. Manual/admin-entered market rates are not used in the transaction path.
4.  **Spread Policy**: ORBI applies spread, pips, risk buffer, and quote-lock rules from `fx_margin_policies`. There is no separate FX fee.
5.  **Fail-Closed Protection**: If the corridor or liquidity provider cannot supply a valid rate, the quote fails instead of silently using stale or manual fallback rates.
6.  **Locked Snapshot**: The server stores and signs the amount, currency pair, customer rate, market rate, spread, final amount, and expiry. Settlement verifies that snapshot and uses it directly; it never re-prices a locked quote.

### 12.1.1 International FX Corridors
International FX is controlled by `fx_corridors`:
- **Currency Pair**: `from_currency` and `to_currency` define the permitted exchange direction.
- **Rate Provider**: `rate_provider_code` selects the adapter such as `OPEN_ER_API`, future `OANDA`, `XE`, `WISE`, `CURRENCYCLOUD`, or a bank treasury adapter.
- **Settlement Mode**: `INTERNAL_LEDGER` supports internal multi-currency wallet conversions. `EXTERNAL_LP` and `HYBRID` are reserved for contracted liquidity-provider settlement.
- **Limits**: `min_amount` and `max_amount` protect each corridor from invalid transaction sizes.
- **Status**: Only `ACTIVE` corridors can produce quotes.

### 12.1.2 User Multi-Currency Wallets
Users can hold multiple ORBI operating wallets under the same identity, one per supported currency:
- **Opening Rule**: A currency wallet can be opened only when that currency appears in at least one `ACTIVE` FX corridor.
- **Wallet Source**: Currency wallets are stored in `platform_vaults` with `vault_role = 'OPERATING'`, encrypted zero balance, and `metadata.wallet_family = 'orbi_multi_currency'`.
- **No Linked-Wallet Fallback**: FX target wallets must be real ORBI vaults. If a target currency wallet does not exist, the client must call `POST /v1/wallets/currency` before locking a conversion quote.
- **Ledger Rule**: Conversions between currency wallets always use a signed, unexpired locked quote and double-entry ledger movement through currency-specific `FX_CLEARING` accounts.

### 12.2 Multi-Currency Ledger, Company Revenue, and FX Clearing
To maintain ledger integrity across different currencies, the system uses a separate **`FX_CLEARING`** company account for each currency:
- **Debit Source**: Funds are debited from the sender's wallet in the source currency.
- **Credit Source Clearing**: The source amount is credited to the source-currency `FX_CLEARING` account.
- **Debit Target Clearing**: The target-currency `FX_CLEARING` account is debited for the converted customer amount, FX spread, and any explicitly configured FX fee.
- **Credit Target**: The final amount is credited to the recipient's wallet in their local currency.
- **Spread Accounting**: The quoted spread is credited to `FX_SPREAD_REVENUE`; the configured risk-buffer portion is credited to `FX_RISK_RESERVE`. They are separate accounts and are never treated as customer balances.

All company-owned funds are segregated by role and currency in `system_settlement_accounts`:

| Account role | Purpose |
| :--- | :--- |
| `SERVICE_REVENUE` | ORBI service charges after settlement. |
| `TAX_RESERVE` | VAT, government fees, and stamp duty retained pending remittance. |
| `FX_CLEARING` | Treasury liquidity used to settle each currency leg of an FX conversion. |
| `FX_SPREAD_REVENUE` | Realized ORBI FX margin, recorded in the target currency. |
| `FX_RISK_RESERVE` | Quoted FX risk buffer, retained separately from revenue. |
| `COMMISSION_RESERVE` | Funds reserved for merchant, agent, and referral commission payouts. |

The ledger rejects a posting when a leg's currency differs from the wallet denomination, and it requires debits and credits to balance independently for every currency. This prevents apparent numerical balance that hides a cross-currency loss.

### 12.3 Global Policy Enforcement
All transaction limits and risk assessments are normalized to **USD** using the `FXEngine` before being evaluated by the `PolicyEngine`. This ensures consistent enforcement of institutional rules regardless of the transaction currency.

### 12.4 FX Operations Control Plane
FX is operated through controlled admin endpoints rather than manual database edits:
- `GET /v1/admin/config/fx/corridors`: review active and paused FX corridors.
- `PUT /v1/admin/config/fx/corridors`: create or update a corridor using an idempotency key.
- `GET /v1/admin/config/fx/margins`: review spread, pips, risk buffer, quote lock, and amount-limit policies.
- `PUT /v1/admin/config/fx/margins`: update customer pricing protection for a currency pair using an idempotency key.
- `GET /v1/admin/config/fx/providers/health`: review configured liquidity providers and current health snapshots.
- `GET /v1/admin/config/fx/exposure`: review 24-hour currency exposure and configured treasury limits.
- `PUT /v1/admin/config/fx/exposure-limits`: update currency exposure limits using an idempotency key.
- `GET /v1/admin/config/fx/reconciliation`: review FX reconciliation events by status.

Every locked FX quote creates a reconciliation event with the quote id, source amount, target amount, customer rate, market rate, spread amount, provider code, and settlement mode. When the quote settles, the reconciliation event moves to `MATCHED`; if settlement fails, it moves to `FAILED`. This keeps customer conversion, treasury exposure, and ledger audit aligned without exposing internal pricing internals to the mobile user.

## 13. Future Capabilities Unlocked
By implementing this architecture, ORBI is now capable of:
- **White-labeling**: Partners can launch their own branded wallets on our infrastructure.
- **Complex Marketplaces**: Platforms can onboard their own merchants, and ORBI handles the split-routing and settlement.
- **TrustBridge Escrow**: Marketplaces can use the conditional escrow system to protect buyers and sellers, holding funds in `PaySafe` until delivery is confirmed.
- **B2B SaaS**: Companies can use ORBI to manage their internal departmental budgets (Cost Centers as Tenants).
