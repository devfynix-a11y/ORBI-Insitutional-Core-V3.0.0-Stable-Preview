# ORBI Banking Engine V3.0: Atomic Ledger & TrustBridge Architecture
**Classification**: INSTITUTIONAL / CORE ARCHITECTURE  
**Version**: 3.0.0 (Titanium Hardened)  
**Last Updated**: 2026-03-14

---

## 1. Executive Summary
The **ORBI Banking Engine V2.0** is a professional-grade, institutional ledger system designed for high-frequency, multi-leg financial operations. It implements a **Dual-Vault Architecture**, **Atomic Multi-Leg Commits**, and **Enterprise B2B Multi-Tenancy** to ensure zero data loss, absolute consistency, and forensic auditability.

---

## 2. Core Architecture: Dual-Vault Model
To ensure segregation of duties and enhanced security, every user is provisioned with two distinct vaults:

### 2.1 DilPesa (Sovereign Operating Vault)
The **DilPesa** vault is the primary user-facing operating account. It represents the liquid "Sovereign Balance" and is provisioned with a **DilPesa Virtual Master** card profile.

**Technical Metadata Schema:**
- `id`: UUID (Primary Key)
- `name`: `"DilPesa"`
- `vault_role`: `"OPERATING"`
- `management_tier`: `"sovereign"` (Indicates a native system-managed vault)
- `metadata`:
    - `linked_customer_id`: Institutional ID (e.g., `OB26-XXXX-XXXX`)
    - `display_name`: Full name of the identity owner.
    - `card_type`: `"Virtual Master"`
    - `product_name`: `"DilPesa"`

### 2.2 PaySafe (Internal Transfer Vault)
The **PaySafe** vault acts as a temporary escrow for multi-leg settlements. 
- **Purpose**: A hidden, internal escrow vault used exclusively for P2P (Peer-to-Peer) transfers.
- **Slogan**: "PaySafe" - Secure internal transfers.
- **Visibility**: **HIDDEN** from the user. It acts as a transit point for internal liquidity.
- **Role**: `vault_role: INTERNAL_TRANSFER`
- **Internal Name**: `"PaySafe"`
- **Management Tier**: `"sovereign"`

### 2.3 Management Tiers
The system classifies all wallets into two tiers:
- **`sovereign`**: Native system-managed vaults (Operating, PaySafe, Tax). Funds are settled instantly on the internal ledger.
- **`linked`**: External accounts (Bank, Mobile Money) connected via API. Settlement depends on external provider availability.

---

## 3. Atomic Multi-Leg Transaction Flow
ORBI uses a **Double-Entry Bookkeeping** model. Every transaction is composed of multiple "Ledger Legs" that must sum to zero.

### 3.1 Multi-Currency & FX Engine
The Banking Engine natively supports cross-currency transactions through the integrated **FXEngine**.
- **Live Rates**: Exchange rates are fetched in real-time from trusted global APIs (cached for 1 hour).
- **Normalized Compliance**: All transaction amounts are converted to USD in real-time before being evaluated by the **Risk & Compliance Engine (AML)** to ensure consistent global rule enforcement (e.g., $10,000 reporting thresholds).
- **Spread-Based Pricing**: ORBI does not apply a separate FX fee. Customer pricing is produced from the provider market rate plus the configured spread/risk policy.
- **Locked Settlement**: A signed, unexpired quote snapshot is settled at its stored customer rate; a conversion is rejected if its amount, wallet currencies, rate, spread, or expiry no longer match the quote.
- **Segregated Accounting**: FX clearing, spread revenue, and risk reserve accounts are separated by currency. The SQL ledger validates wallet denomination and balances each currency independently.

### 3.2 P2P Transfer (Strict Escrow Flow)
The engine enforces a **Strict Escrow Flow** for all internal and peer transfers. This ensures that funds are never moved directly between operating vaults, mitigating risks from network failures or security challenges.

### 3.3 Orbi TrustBridge (Conditional Escrow)
The **TrustBridge** extends the strict escrow flow by adding conditional logic and multi-party release mechanisms.

**Escrow Lifecycle**:
1.  **Creation**: Funds are DEBITED from the sender's `OPERATING` vault and CREDITED to the sender's `PaySafe` (INTERNAL_TRANSFER) vault. The transaction is marked as `authorized`.
2.  **Locking**: The funds are locked in `PaySafe` with a `referenceId` and `conditions` (e.g., "Item Received").
3.  **Release**: Upon condition fulfillment (e.g., sender confirmation), funds are DEBITED from `PaySafe` and CREDITED to the recipient's `OPERATING` vault.
4.  **Dispute**: If a dispute is raised, funds are frozen in `PaySafe`. Neural Sentinel AI analyzes evidence and provides a resolution recommendation.
5.  **Refund**: If the transaction is cancelled or a dispute is resolved in favor of the sender, funds are DEBITED from `PaySafe` and CREDITED back to the sender's `OPERATING` vault.

### 3.4 Sub-Wallet Fund Shifting (Goals & Budgets)
When a user initiates a payment from a **GOAL** or **BUDGET** sub-wallet, the engine executes an automatic **Shift-then-Transfer** sequence:
1.  **Internal Shift**: Funds (Amount + Fees) are shifted from the Sub-Wallet to the user's **OPERATING** vault.
2.  **Standard Settlement**: The transfer proceeds from the **OPERATING** vault to the recipient.
This ensures that sub-wallets remain logically separate while maintaining a unified settlement path.

### 3.3 Stuck Transaction Recovery
The system includes an automated **Reconciliation Engine** that monitors for stuck transactions. If a transfer transaction is identified as stuck, the engine first attempts to re-trigger the settlement process before resorting to a reversal, ensuring maximum reliability for user transactions.

---

## 4. Transaction State Machine & Lifecycle
The engine enforces a strict state machine for all transactions to ensure predictability and auditability.

### 4.1 Allowed States
- `created`: Initial state when intent is captured.
- `pending`: Transaction is awaiting external provider confirmation or internal processing.
- `authorized`: Funds have been successfully locked in escrow.
- `processing`: Settlement legs are being committed.
- `completed`: Funds delivered, ledger balanced, and transaction finalized.
- `failed`: Transaction aborted due to technical or business logic failure.
- `cancelled`: User or system aborted the transaction before authorization.
- `held_for_review`: Flagged by Sentinel AI or Compliance for manual intervention.
- `reversed`: Transaction was successfully rolled back after completion.
- `refunded`: Funds returned to sender via a separate refund operation.

### 4.2 Transition Rules
Transitions are strictly validated. For example, a `completed` transaction cannot move back to `pending`. Administrative overrides (e.g., from `held_for_review` to `completed`) require `SUPER_ADMIN` or `FINANCE` privileges.

---

## 5. Reconciliation & Integrity Engine
To maintain "Bank-Level" precision, ORBI runs a continuous multi-layer reconciliation process.

### 5.1 Internal Reconciliation (Ledger vs. Wallets)
The system periodically calculates the sum of all ledger entries for every wallet and compares it against the cached `balance` in the `wallets` table. Any discrepancy > 0.01 triggers a `SECURITY` alert and a `MISMATCH` report.
- **Proactive Verification**: The `TransactionService` calls `verifyWalletBalance` after every transaction to ensure immediate integrity.
- **System-Wide Audits**: `reconcileAllWallets` is used for deep forensic audits across the entire platform.

### 5.2 System Reconciliation (Transactions vs. Ledger)
Every transaction header must have matching double-entry legs in the `financial_ledger`. The engine identifies "Ghost Transactions" (headers without legs) and imbalanced transfers.

### 5.3 External Reconciliation (Ledger vs. Partners)
The engine cross-references internal settlement account balances against external partner balances (e.g., Bank or Mobile Money provider). Discrepancies trigger high-priority alerts via the `SocketRegistry` and `Messaging` service.

### 5.4 Reconciliation Reports
All audits are persisted in the `reconciliation_reports` table, providing a forensic history of system integrity.

---

## 6. Security & Integrity Guards

### 6.1 DataVault Encryption (Zero-Knowledge Storage)
All sensitive financial data (balances, amounts, secrets) are stored using the **DataVault Protocol**. Values are wrapped in an **Encrypted Data Packet** (`enc_v2_`) containing:
- **Ciphertext**: AES-GCM 256-bit encrypted payload.
- **IV/Tag**: Initialization vector and authentication tag for decryption.
- **KMS Version**: The key version used for the operation.
- **AAD**: Additional Authenticated Data (Origin: `ORBI_V3_CORE`).

### 4.2 Vault Auditor & Forensic Reporting
The **Vault Auditor** provides continuous integrity monitoring and forensic data preservation. It generates **Forensic Reports** containing:
- **Integrity Status**: `VALID` or `TAMPERED` based on cryptographic chain verification.
- **Anomaly Count**: Number of detected ledger inconsistencies.
- **Legal Holds**: List of active restrictions (Target, Reason, IssuedAt, IssuedBy).

### 4.3 Balance Hardening (Total Liability Check)
**Commit Phase (Settle)**: Before any ledger legs are generated, the engine performs a **Total Liability Check**:
`Available Balance >= (Transaction Amount + Regulatory Fees)`
If the balance is insufficient, the transaction is rejected immediately with `INSUFFICIENT_FUNDS`.

**Preview Phase**: The engine calculates all fees and taxes regardless of the user's balance, returning the `available_balance` so the client can display the shortfall.

### 4.2 Atomic Commits (`post_transaction_v2` & `append_ledger_entries_v1`)
All transactions are committed via a single database RPC call. This ensures that:
1.  The Transaction Header is created (for `post_transaction_v2`).
2.  All Ledger Legs are inserted.
3.  All affected Wallet/Vault balances are updated.
**If any step fails, the entire operation is rolled back.**
- **`post_transaction_v2`**: Used for standard P2P and settlement flows.
- **`append_ledger_entries_v1`**: Used for manual ledger adjustments and complex multi-leg operations.

### 6.4 Risk Scoring Engine (Neural Assessment)
**File**: `/backend/security/RiskEngine.ts`  
Every request is evaluated by a neural risk engine before reaching the business logic.
- **Risk Score (0-100)**: Calculated based on IP reputation, WAF signals, and behavioral patterns.
- **Block Threshold**: Requests with a score > 80 are automatically rejected.
- **Challenge Threshold**: Scores between 60-80 trigger a `SECURITY_CHALLENGE` (OTP/Biometric).

### 6.5 Transaction Guard (Policy Engine)
**File**: `/backend/ledger/PolicyEngine.ts`  
Enforces financial policies at the ledger level to prevent fraud and ensure regulatory compliance.
- **Daily Cumulative Limits**: Tracks total volume per user per 24h.
- **Velocity Protection**: Monitors transaction frequency to detect automated attacks.
- **Auto-Freeze Logic**: Accounts exhibiting suspicious patterns are automatically placed on a security hold.

### 6.6 Content Sanitization
**File**: `/backend/security/sanitizer.ts`  
Deep recursive sanitization of all incoming JSON payloads to prevent XSS and injection attacks at the entry point.

---

## 7. Administrative & Forensic Endpoints
For successful Admin Portal development, the following endpoints provide deep visibility into the ledger:

### 5.1 Global Transaction Audit
*   **Endpoint**: `GET /v1/admin/transactions`
*   **Access**: `SUPER_ADMIN`, `ADMIN`, `AUDIT`
*   **Description**: Retrieves a global list of all transactions across the platform.

### 5.2 Forensic Ledger View
*   **Endpoint**: `GET /v1/admin/transactions/:id/ledger`
*   **Access**: `SUPER_ADMIN`, `ADMIN`, `AUDIT`
*   **Description**: Retrieves the specific ledger legs for a transaction.
*   **Forensic Value**: Shows the exact flow of money, including the internal escrow movements and fee collection.

---

## 8. Enterprise B2B Multi-Tenancy & Corporate Treasury
The engine has been upgraded to support Global Enterprise B2B operations. This introduces strict multi-tenancy, corporate goals, and hard budget enforcement.

### 6.1 Organizations (Tenants)
Users are now grouped under **Organizations**. The `organizations` table acts as the root entity for corporate clients, defining their legal name, tax ID, and base currency. Users are linked via `organization_id` and assigned an `org_role` (`ADMIN`, `FINANCE`, `EMPLOYEE`).

### 6.2 Corporate Treasury Goals
Goals can now be marked as `is_corporate`. This transforms them from personal savings pots into **Corporate Treasury Reserves** (e.g., "Q3 Tax Reserve", "Payroll Fund").
*   **Auto-Sweeping**: Excess liquidity from the operating vault can be automatically swept into these reserves.
*   **Multi-Sig Withdrawal**: Large withdrawals from enterprise vaults require multiple approvals (e.g., CFO + CEO) before the ledger releases the funds. The `treasury_approvals` table tracks the approval state.
*   **Maker-Checker Approvals**: Withdrawing from a Corporate Goal requires multi-signature approval from the Finance team.

### 6.3 Departmental Cost Centers (Hard Budgets)
Categories have been upgraded to act as **Enterprise Budgets**.
*   **Hard Limits**: If a budget has `hard_limit = TRUE`, the engine will physically block any transaction that exceeds the allocated amount for the given `period` (Monthly, Quarterly, Annual).
*   **Budget Alerts**: The `budget_alerts` table tracks spending thresholds (e.g., 80% warning, 100% exceeded) and triggers real-time notifications to Finance admins.

For the maintained business operating model, see the [ORBI Business Operational Playbook](./ORBI_BUSINESS_OPERATIONAL_PLAYBOOK.md).

---

## 9. Client App Integration Details
For successful Mobile/Web Client development:

1.  **Transaction Status**: Always display the `status` field from the transaction object.
2.  **Autonomous Vault Resolution**: The backend automatically resolves the correct `OPERATING` vault for the sender and recipient using their **Customer IDs**. Clients do not need to provide internal UUIDs if `customer_id` is known.
3.  **Sub-Wallet Transfers**: To pay from a goal or budget, set `walletType` to `GOAL` or `BUDGET` and provide the `sourceWalletId`.
4.  **Privacy**: Ensure that vaults with `vault_role: INTERNAL_TRANSFER` are filtered out of the user's wallet list.

---

**ORBI Financial Technologies Ltd.**  
*Engineering Division - Sovereign Core Team*
