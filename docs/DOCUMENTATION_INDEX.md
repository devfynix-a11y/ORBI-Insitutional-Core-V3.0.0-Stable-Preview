# ORBI Documentation Index

- `KEYCLOAK_AUTHENTICATION_PLAYBOOK.md`: self-hosted identity, JWT, sessions,
  subject mapping, password recovery, and mobile PKCE migration.

This index defines the canonical ORBI Institutional Core documentation set. Older or narrow documents may remain as compatibility pointers, but new work should update the canonical document for that area first.

## Canonical Documents

| Area | Canonical Document | Purpose |
| :--- | :--- | :--- |
| Engineering architecture | [ORBI Core Engineering Architecture](./ORBI_CORE_ENGINEERING_ARCHITECTURE.md) | Highest-level engineering contract for Core, ledger, registry, PaySafe, gateway, shared finance, realtime, idempotency, RLS, reporting, and safe-change rules. |
| Core readiness audit | [ORBI Core Readiness Audit](./CORE_READINESS_AUDIT.md) | Current evidence-based readiness status, protected services, remaining certification gates, and next execution order before calling Core 100%. |
| Ecosystem readiness and remaining slices | [ORBI Ecosystem Readiness And Remaining Slices](./ECOSYSTEM_READINESS_AND_REMAINING_SLICES.md) | Canonical launch verdict, evidence, blockers, and delivery order for merchants, agents, organizations, developers, and external services. |
| Ecosystem authorization inventory | [Ecosystem Authorization Inventory](./ECOSYSTEM_AUTHORIZATION_INVENTORY.md) | Slice 1 route/resource authorization matrix and the first P0 remediation batch. |
| Open Banking and BaaS roadmap | [ORBI Open Digital Banking And BaaS Roadmap](./ORBI_OPEN_BANKING_BAAS_ROADMAP.md) | Phased TODO checklist for turning ORBI into a mature Open Digital Banking, BaaS, developer, merchant, sandbox, webhook, compliance, and control-room platform. |
| Infrastructure platform blueprint | [ORBI Infrastructure Platform Blueprint](./ORBI_INFRASTRUCTURE_PLATFORM_BLUEPRINT.md) | ORBI as financial infrastructure for merchants and third parties: hosted secure UI, payment profiles, consent scopes, PaySafe lifecycle, webhooks, and authority boundaries. |
| Business and operating model | [ORBI Business Operational Playbook](./ORBI_BUSINESS_OPERATIONAL_PLAYBOOK.md) | Business model, B2C/B2B/B2B2C operations, merchant/agent/customer flows, operational controls, revenue model, and control-room playbook. |
| Business identity federation | [ORBI Business Identity Federation](./ORBI_BUSINESS_IDENTITY_FEDERATION.md) | Canonical contract for sharing Core/Auth business identity with ORBI Shop, Pay Gateway, and future business surfaces without duplicating passwords or financial authority. |
| Registration identity contract | [ORBI Registration Identity Contract](./ORBI_REGISTRATION_IDENTITY_CONTRACT.md) | Required signup payload, `public.users` financial identity fields, registry families, access levels, and transaction-readiness rules. |
| Registration blueprints | [ORBI Global Registration Protocol](./registration/ORBI_GLOBAL_REGISTRATION_PROTOCOL.md) | Global registration families, source channels, external registration protocol, business upgrade rules, and audit requirements. |
| Registration families | [ORBI Registration Families](./registration/ORBI_REGISTRATION_FAMILIES.md) | Identity family rules for consumer, merchant, agent, staff, and organization membership boundaries. |
| External registration gateway | [ORBI External Registration Gateway Contract](./registration/ORBI_EXTERNAL_REGISTRATION_GATEWAY_CONTRACT.md) | Trusted external registration contract through Pay Gateway with worker scopes, idempotency, and prohibited authority fields. |
| Business access approval | [ORBI Business Access Approval Flow](./registration/ORBI_BUSINESS_ACCESS_APPROVAL_FLOW.md) | Merchant and agent upgrade lifecycle from request to approval, provisioning, rejection, and deactivation. |
| Service actor registration | [ORBI Service Actor Registration Rules](./registration/ORBI_SERVICE_ACTOR_REGISTRATION_RULES.md) | Assisted registration rules for agents, merchants, consent, actor/customer relationships, and notifications. |
| API request contracts | [ORBI API Request Contracts](./registration/ORBI_API_REQUEST_CONTRACTS.md) | Canonical headers, payload examples, method rules, idempotency keys, and error shape for registration and gateway identity requests. |
| Production deployment | [Production Deployment](./PRODUCTION_DEPLOYMENT.md) | Active production deployment requirements, environment variables, TLS, migrations, background workers, rollback, and release automation. |
| System separation | [ORBI System Separation](./ORBI_SYSTEM_SEPARATION.md) | Boundary between ORBI Core, ORBI Pay Gateway, and ORBI Talk Gateway. |
| Environment variables | [Environment Variables Reference](./ENVIRONMENT_VARIABLES_REFERENCE.md) | Complete variable catalog for production and staging environments. |
| Admin portal and SDK | [ORBI Admin Frontend API SDK](./ORBI_ADMIN_FRONTEND_API_SDK.md) | Admin frontend API contract, failover behavior, activity accounting, and SDK usage. |
| Configuration studio | [Admin Config Setup UI Contract](./ADMIN_CONFIG_SETUP_UI_CONTRACT.md) | Provider, FX, routing, fee, and bootstrap configuration contracts. |
| Messaging templates | [ORBI Talk Gateway Templates](./ORBI_TALK_GATEWAY_TEMPLATES.md) | Official ORBI Talk template model, template families, variables, channels, and import guidance. |
| Payment gateway integration | [ORBI Pay Gateway Integration](./ORBI_PAYMENT_GATEWAY_INTEGRATION.md) | Core-side trust boundary for the standalone ORBI Pay Gateway service, callback signing, readiness, and production safety rules. |
| Provider routing | [Provider Registry Contract](./PROVIDER_REGISTRY_CONTRACT.md) | Financial partner registry contract and routing metadata. |
| Provider adapters | [Provider Adapter Architecture](./PROVIDER_ADAPTER_ARCHITECTURE.md) | Provider execution, adapter contracts, retry/failover hooks, and compatibility boundaries. |
| Financial core | [Core Banking Architecture](./CORE_BANKING_ARCHITECTURE.md) | Core ledger, tenants, security, escrow, treasury, messaging, and FX model. |
| Banking engine | [Banking Engine V2](./BANKING_ENGINE_V2.md) | Atomic ledger and TrustBridge architecture details. |
| Transaction movement classification | [Transaction Movement Classification](./TRANSACTION_MOVEMENT_CLASSIFICATION.md) | Canonical movement families/codes for history, reports, receipts, and audit read models without mutating ledger truth. |
| Mobile GraphQL read model | [Mobile GraphQL Read Model](./MOBILE_GRAPHQL_READ_MODEL.md) | Read-only GraphQL snapshot contract and indexes for fast mobile boot, dashboard, history, wealth, and PaySafe reads. |
| Reconciliation | [Reconciliation Engine](./RECONCILIATION_ENGINE.md) | Financial integrity, reports, admin controls, and reconciliation layers. |
| FX settlement and revenue | [FX Settlement and Company Revenue Runbook](./FX_SETTLEMENT_ACCOUNTING_RUNBOOK.md) | Locked quote integrity, segregated company accounts, Treasury funding, revenue recognition, and daily FX reconciliation. |
| Disaster recovery | [Disaster Recovery Runbook](./DISASTER_RECOVERY_RUNBOOK.md) | Incident response, severe failure scenarios, recovery objectives, and evidence. |
| Identity and secret backup | [ORBI Identity And Secret Storage Backup](./IDENTITY_AND_SECRET_STORAGE_BACKUP.md) | Official storage and encrypted backup rules for auth password hashes, developer key fingerprints, webhook secret fingerprints, and restore evidence. |
| Backup restore drill | [Backup Restore Drill Procedure](./BACKUP_RESTORE_DRILL_PROCEDURE.md) | Executable backup restore drill procedure and evidence capture. |
| Release checklist | [Release Checklist](./RELEASE_CHECKLIST.md) | Pre-deploy, smoke, post-deploy, rollback triggers, and evidence. |
| Security simulation | [Security Attack Simulation Plan](./SECURITY_ATTACK_SIMULATION_PLAN.md) | Defensive security validation plan and manual checks. |
| Test plan | [Financial Core Test Plan](./FINANCIAL_CORE_TEST_PLAN.md) | Current test stack, DB integration modes, and priority coverage. |
| Project structure | [Project Structure](./PROJECT_STRUCTURE.md) | Repository layout and ownership of core directories. |

## Merged Compatibility Documents

These files are retained so old links continue to work, but their content has been merged into canonical docs:

| Old Document | Merged Into |
| :--- | :--- |
| [ORBI Operation](./ORBI_OPERATION.md) | [ORBI Business Operational Playbook](./ORBI_BUSINESS_OPERATIONAL_PLAYBOOK.md) |
| [Enterprise B2B Architecture](./ENTERPRISE_B2B_ARCHITECTURE.md) | [ORBI Business Operational Playbook](./ORBI_BUSINESS_OPERATIONAL_PLAYBOOK.md) |
| [Merchant Architecture](./MERCHANT_ARCHITECTURE.md) | [ORBI Business Operational Playbook](./ORBI_BUSINESS_OPERATIONAL_PLAYBOOK.md) |
| [Agent, Merchant, and System Fee Flows](./AGENT_MERCHANT_FEE_FLOWS.md) | [ORBI Business Operational Playbook](./ORBI_BUSINESS_OPERATIONAL_PLAYBOOK.md) |
| [First Backup Restore Drill Plan](./FIRST_BACKUP_RESTORE_DRILL_PLAN.md) | [Backup Restore Drill Procedure](./BACKUP_RESTORE_DRILL_PROCEDURE.md) |
| [Self-Hosted Core and Data Migration](./SELF_HOSTED_DATA_MIGRATION.md) | [Production Deployment](./PRODUCTION_DEPLOYMENT.md) |
| [Self-Hosted Infrastructure Playbook](./SELF_HOSTED_INFRASTRUCTURE_PLAYBOOK.md) | [Release Checklist](./RELEASE_CHECKLIST.md) |
| [ORBI Auth Migration Playbook](./ORBI_AUTH_MIGRATION_PLAYBOOK.md) | [Self-Hosted Core and Data Migration](./SELF_HOSTED_DATA_MIGRATION.md) |
| [Self-Hosted Platform Architecture](./SELF_HOSTED_PLATFORM_ARCHITECTURE.md) | [Self-Hosted Infrastructure Playbook](./SELF_HOSTED_INFRASTRUCTURE_PLAYBOOK.md) |
| [Cloudflare R2 Image Storage](./CLOUDFLARE_R2_IMAGE_STORAGE.md) | [Self-Hosted Platform Architecture](./SELF_HOSTED_PLATFORM_ARCHITECTURE.md) |
| [Frontend Integration Guide](./frontend_integration.md) | [ORBI Admin Frontend API SDK](./ORBI_ADMIN_FRONTEND_API_SDK.md) and [Mobile SDK Guide](./MOBILE_SDK_GUIDE.md) |

## Maintenance Rules

- Keep business and operational policy in the Playbook, not scattered across architecture notes.
- Keep production setup in `PRODUCTION_DEPLOYMENT.md` and data migration controls in `SELF_HOSTED_DATA_MIGRATION.md`.
- Keep API/client integration details in the SDK docs, not in business docs.
- Keep SQL changes documented by migration name when they introduce new business capabilities.
- Do not duplicate ORBI Talk templates under multiple filenames; use `orbi_talk_gateway_templates.json` as the active seed file.
