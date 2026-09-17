# ORBI Reconciliation Engine: Financial Integrity & Compliance
**Classification**: CORE / FINANCIAL INTEGRITY  
**Version**: 1.0.0 (Bank-Grade)  
**Status**: ACTIVE  

---

## 1. Overview
The **ORBI Reconciliation Engine** is a mission-critical service designed to ensure that every cent in the system is accounted for. In a high-frequency fintech environment, discrepancies can arise from network failures, race conditions, or external provider delays. This engine provides the "Source of Truth" verification required for regulatory compliance (Bank of Tanzania) and institutional trust.

---

## 2. Reconciliation Layers

### 2.1 Internal Reconciliation (Ledger vs. Wallets)
*   **Target**: `financial_ledger` vs `wallets`.
*   **Logic**: 
    1.  Sum all `CREDIT` entries and subtract all `DEBIT` entries for a specific `wallet_id` in the ledger.
    2.  Compare this sum against the `balance` field in the `wallets` table.
*   **Automated Verification**: The `TransactionService.verifyWalletBalance` method performs this check programmatically after every transaction.
*   **System-Wide Reconciliation**: The `TransactionService.reconcileAllWallets` method iterates through all active wallets to ensure global integrity.
*   **Tolerance**: 0.01 (to account for minor floating point rounding during display).
*   **Action on Mismatch**: 
    *   Generate `INTERNAL` reconciliation report.
    *   Log `SECURITY` audit event.
    *   Dispatch real-time alert to the user and system admins.

### 2.2 System Reconciliation (Transactions vs. Ledger)
*   **Target**: `transactions` vs `financial_ledger`.
*   **Logic**:
    1.  Verify every `completed` or `processing` transaction has at least two ledger legs (Double-Entry).
    2.  For transfers, verify that the sum of all legs for that `transaction_id` equals zero.
*   **Anomalies Detected**:
    *   **Ghost Transactions**: Transactions that exist in the header table but have no corresponding ledger entries.
    *   **Imbalanced Legs**: Transactions where money was debited but not correctly credited (or vice versa).

### 2.3 External Reconciliation (Ledger vs. Partners)
*   **Target**: `platform_vaults` (Settlement/Liquidity) vs Partner API (Bank/Mobile Money).
*   **Logic**:
    1.  Fetch the real-time balance from the external financial partner (e.g., Vodacom M-Pesa, CRDB Bank).
    2.  Compare it against the internal balance of the corresponding `platform_vault`.
*   **Action on Mismatch**:
    *   Generate `EXTERNAL` reconciliation report.
    *   Broadcast `HIGH` severity alert via WebSockets.
    *   Trigger manual investigation workflow.

### 2.4 Multi-Currency Reconciliation (FX Clearing)
*   **Target**: Currency-specific `FX_CLEARING` accounts and the linked `FX_SPREAD_REVENUE` and `FX_RISK_RESERVE` accounts.
*   **Logic**:
    1.  Verify the signed quote snapshot and compare its source amount, customer rate, final amount, spread, and risk buffer with the settlement legs.
    2.  Verify that source and target `FX_CLEARING` accounts balance independently in their own currencies.
    3.  Verify that the spread and risk-buffer credits reached their matching company accounts and that the net currency position remains within Treasury limits.
*   **Anomalies Detected**:
    *   **Unbalanced Conversions**: Transactions where the conversion legs in the `FX_CLEARING` account do not match the expected exchange rate.
    *   **Currency Leakage**: Discrepancies in the `FX_CLEARING` account that indicate potential rounding errors or unauthorized manual adjustments.

---

## 3. Data Model: `reconciliation_reports`
All reconciliation cycles persist their results for forensic auditing.

| Field | Type | Description |
| :--- | :--- | :--- |
| `id` | UUID | Unique report identifier. |
| `type` | TEXT | `INTERNAL`, `SYSTEM`, or `EXTERNAL`. |
| `expected_balance` | NUMERIC | The balance calculated from the source of truth (e.g., Ledger). |
| `actual_balance` | NUMERIC | The balance found in the target (e.g., Wallet). |
| `difference` | NUMERIC | The absolute difference between expected and actual. |
| `status` | TEXT | `MATCHED`, `MISMATCH`, or `INVESTIGATING`. |
| `metadata` | JSONB | Contextual data (Wallet ID, Transaction ID, Partner ID). |
| `created_at` | TIMESTAMPTZ | Timestamp of the reconciliation check. |

---

## 4. Administrative Controls
Administrators can manage the reconciliation process via the following secure endpoints:

### 4.1 Trigger Full Cycle
*   **Endpoint**: `POST /v1/admin/reconciliation/run`
*   **Access**: `ADMIN` only.
*   **Action**: Executes all three reconciliation layers sequentially.

### 4.2 Review Reports
*   **Endpoint**: `GET /v1/admin/reconciliation/reports`
*   **Access**: `ADMIN`, `AUDIT`.
*   **Description**: Retrieves historical reconciliation reports for forensic review.

### 5.4 Security & Policy Audit Integration
The reconciliation process is augmented by logs from the **Risk Engine** and **Policy Engine**:
- **Policy Violations**: Any transaction blocked by the `PolicyEngine` is logged as a `POLICY_VIOLATION` in the audit trail, allowing reconciliation teams to distinguish between technical failures and intentional blocks.
- **Risk Anomalies**: High-risk scores (80-100) from the `RiskEngine` are cross-referenced during system audits to identify potential fraud patterns that may affect ledger consistency.

---

## 6. Compliance & Auditing
The Reconciliation Engine is designed to satisfy the requirements of the **Bank of Tanzania (BoT)** and other regulatory bodies regarding:
*   **Daily Balancing**: Ensuring that the platform's total liability matches its actual assets.
*   **Forensic Traceability**: Every discrepancy is logged with a timestamp and metadata.
*   **Proactive Alerting**: Real-time detection of financial anomalies.

---

**ORBI Financial Technologies Ltd.**  
*Engineering Division - Financial Integrity Team*
