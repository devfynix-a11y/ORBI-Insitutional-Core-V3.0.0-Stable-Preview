
# ORBI Sovereign Backend Node (v31.0 Titanium)

This is the headless financial Core powering the ORBI ecosystem. It has a
strong controlled-production foundation with SQL-authoritative ledger controls.
External merchant, agent, organization, and developer launch remains subject to
the readiness and certification gates below; the repository must not be
described as fully bank-certified until those gates pass.

## 📚 Documentation

*   **[Documentation Index](./DOCUMENTATION_INDEX.md)**: Canonical map for all maintained docs and merged compatibility files.
*   **[Ecosystem Readiness And Remaining Slices](./ECOSYSTEM_READINESS_AND_REMAINING_SLICES.md)**: Evidence-based launch verdict and delivery plan for merchants, agents, organizations, developers, and external services.
*   **[Ecosystem Authorization Inventory](./ECOSYSTEM_AUTHORIZATION_INVENTORY.md)**: Endpoint-level ownership and tenant-isolation audit for the first security slice.
*   **[ORBI Open Digital Banking And BaaS Roadmap](./ORBI_OPEN_BANKING_BAAS_ROADMAP.md)**: Phased TODO checklist for developer portal, consent, sandbox, webhooks, onboarding, SDKs, reconciliation, risk, control room, and production hardening.
*   **[ORBI Infrastructure Platform Blueprint](./ORBI_INFRASTRUCTURE_PLATFORM_BLUEPRINT.md)**: ORBI as financial infrastructure for merchants and third parties, including hosted secure UI, payment profiles, consent scopes, PaySafe lifecycle, webhooks, and authority boundaries.
*   **Pay Gateway Developer Portal Contracts**: `ORBI PAY GATEWAY/docs/DEVELOPER_PORTAL_CONTRACTS.md` defines service onboarding, sandbox/live access, scopes, allowlists, API key rotation, webhook secret rotation, and developer events.
*   **[ORBI Business Operational Playbook](./ORBI_BUSINESS_OPERATIONAL_PLAYBOOK.md)**: Business model, B2C/B2B/B2B2C operating model, staff roles, merchant/agent operations, risk, support, and daily control-room procedures.
*   **[ORBI Business Identity Federation](./ORBI_BUSINESS_IDENTITY_FEDERATION.md)**: Core/Auth, ORBI Shop, and Pay Gateway identity federation contract for shared business accounts.
*   **[ORBI Registration Identity Contract](./ORBI_REGISTRATION_IDENTITY_CONTRACT.md)**: Required signup payload, `public.users` identity fields, registry families, access levels, and transaction-readiness rules.
*   **[ORBI Global Registration Protocol](./registration/ORBI_GLOBAL_REGISTRATION_PROTOCOL.md)**: Global registration blueprint for mobile, auth web, gateway, merchant, agent, organization, and third-party sources.
*   **[ORBI API Request Contracts](./registration/ORBI_API_REQUEST_CONTRACTS.md)**: Canonical headers, payload examples, method rules, idempotency keys, and error shape for registration and gateway identity requests.
*   **[Production Deployment](./PRODUCTION_DEPLOYMENT.md)**: Active production deployment checks, env requirements, TLS, migrations, workers, release automation, and rollback guidance.
*   **[Environment Variables Reference](./ENVIRONMENT_VARIABLES_REFERENCE.md)**: Complete environment variable catalog.
*   **[ORBI Admin Frontend API SDK](./ORBI_ADMIN_FRONTEND_API_SDK.md)**: Admin portal SDK, failover, activity accounting, safe mutations, and API groups.
*   **[ORBI Talk Gateway Templates](./ORBI_TALK_GATEWAY_TEMPLATES.md)**: Official customer/staff communication template model and seed guidance.
*   **[Financial Core Engine](./CORE_BANKING_ARCHITECTURE.md)**: Multi-tenant ledger, security, escrow, treasury, messaging, and FX architecture.
*   **[Reconciliation Engine](./RECONCILIATION_ENGINE.md)**: Financial integrity, forensic auditing, and reconciliation operations.
*   **[Provider Registry Contract](./PROVIDER_REGISTRY_CONTRACT.md)**: Admin/UI and backend contract for registry-driven providers.
*   **[Project Structure](./PROJECT_STRUCTURE.md)**: Repository layout and ownership.

## Core Capability Baseline

The entries below identify implemented capabilities. Their presence does not by
itself mean the related product is certified for unrestricted production use.
- **Orbi TrustBridge (Secure Escrow)**: Conditional payment system with PaySafe locking, multi-party release, and AI-assisted dispute resolution.
- **Enterprise Treasury Automation**: Multi-Sig withdrawal flows, automated treasury auto-sweep, and departmental budget enforcement.
- **Neural Sentinel AI (Security)**: Real-time behavioral risk analysis and fraud prevention for every ingress operation (<50ms latency).
- **Next-Generation Security Architecture (9-Layer)**: True Zero-Trust model featuring Passkeys (FIDO2), Device Fingerprinting, Behavioral Biometrics, AI Fraud Detection, and Hardware Security Module (HSM) integration.
- **Financial Core Engine (Core Banking)**: True Multi-Tenant Architecture (Individuals, Merchants, Marketplaces, Partners) with strict Row Level Security (RLS) isolation.
- **Enterprise B2B Multi-Tenancy**: Corporate Treasury Goals, Departmental Cost Centers, organization-level limits, and Hard Budget Enforcement.
- **Merchant And Agent Operations**: Merchants accept payments and settlement reporting; agents register customers, operate cash desks, manage float, and earn audited commissions.
- **Transaction State Machine**: Strict lifecycle management (Created -> Authorized -> Settled -> Completed) with forensic auditability.
- **Reconciliation Engine**: Continuous multi-layer verification (Internal, System, External) to ensure absolute ledger integrity.
- **Atomic Multi-Leg Ledger**: Ensures fiscal integrity for every asset migration (Principal + Tax + Fee + Yield). Includes `append_ledger_entries_v1` for high-performance, atomic ledger updates.
- **Multi-Currency & FX Engine**: Real-time currency conversion with liquidity-provider rates, spread-based pricing, locked quotes, and USD normalization.
- **Risk & Compliance Engine (AML)**: Advanced transaction monitoring, velocity checks, structuring detection, and high-risk jurisdiction flagging.
- **Continuous Session Monitoring**: Real-time invalidation of compromised sessions based on IP or device fingerprint changes.
- **Transaction Guard (Policy Engine)**: Financial rule enforcement and limit management (`/backend/ledger/PolicyEngine.ts`).
- **Content Sanitization**: Deep XSS protection for all JSON payloads (`/backend/security/sanitizer.ts`).
- **Cyber Sentinel AI**: Neural behavioral risk analysis for every ingress operation (<50ms latency).
- **Zero-Trust Identity**: Dynamic Identity Quarantine (DIQ) for all new nodes.
- **Intelligent Messaging & Monitoring**: Multi-channel router with direct-to-app WebSocket delivery, automated fallbacks (SMS, Push, WhatsApp, Email), and real-time operational alerting for system administrators. Includes unique transactional reference numbers (`refId`) and device identification for enhanced security context.
- **Real-Time Nexus**: High-throughput WebSocket stream for instant balance updates and direct-to-app notifications.
- **Email Notifications**: Integrated SMTP service for transactional emails and alerts.
- **Robust API Error Handling**: Comprehensive `try-catch` boundaries across all v1 and admin routes, ensuring graceful degradation and consistent error payloads.
- **Transaction Service (V2.0)**: Enhanced financial integrity with proactive balance verification, system-wide reconciliation, and forensic reversal capabilities.

## Deployment
This node targets an organization-managed VM with a static IP and private data
services. See [Self-Hosted Core and Data Migration](./SELF_HOSTED_DATA_MIGRATION.md)
for the network boundary, staged database migration, and restore-first backup
requirements.

## 🏢 Enterprise Readiness
The ORBI Sovereign Backend is a professional, enterprise-grade financial infrastructure designed for high-stakes operations. It features:
- **Modular, Service-Oriented Architecture**: Clean separation of concerns across specialized domains (Ledger, Security, Payments, Enterprise, IAM).
- **Security-First Design**: Multi-layered defense including HSM integration, WAF, KMS, and real-time fraud detection.
- **Resilience and Scalability**: Built for distributed environments with Redis-backed event buses, lock management, and failure recovery engines.
- **Financial Integrity and Compliance**: Atomic ledger operations, continuous reconciliation, and immutable audit trails.
- **Enterprise B2B Capabilities**: Support for complex business relationships, treasury management, and hard budget enforcement.
