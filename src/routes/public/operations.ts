import { type RequestHandler, type Router } from 'express';
import { z } from 'zod';
import { sessionHasAnyRole } from '../../middleware/auth/authorization.js';
import { operatorAlertService } from '../../../backend/infrastructure/OperatorAlertService.js';
import { RedisManager } from '../../../backend/enterprise/infrastructure/RedisManager.js';
import { Audit } from '../../../backend/security/audit.js';
import { getAdminSupabase, getSupabase } from '../../../backend/supabaseClient.js';
import { requireIdempotencyKey } from '../../middleware/security/idempotency.js';
import {
  CONFIG_COMMISSION_VIEW_ROLES,
  CONFIG_FX_VIEW_ROLES,
  CONFIG_LEDGER_ADMIN_ROLES,
  RECONCILIATION_REPORT_ROLES,
  RECONCILIATION_RUN_ROLES,
  SUPER_ADMIN_AND_ADMIN_ROLES,
} from '../../middleware/auth/roles.js';

const TreasuryApprovalSchema = z.object({
  txId: z.string().min(1),
  reason: z.string().trim().min(5).max(500),
});

const ReconciliationRunSchema = z.object({
  reason: z.string().trim().min(5).max(500),
});

const BrokerNotificationConfigSchema = z.object({
  thresholdUsd: z.coerce.number().positive().max(1_000_000_000),
  email: z.object({
    enabled: z.boolean().default(false),
    recipients: z.array(z.string().trim().email()).max(20).default([]),
  }).default({ enabled: false, recipients: [] }),
  slack: z.object({
    enabled: z.boolean().default(false),
    channel: z.string().trim().min(1).max(120).default('#ops-security-feed'),
  }).default({ enabled: false, channel: '#ops-security-feed' }),
  autoFreeze: z.object({
    enabled: z.boolean().default(false),
    riskScoreThreshold: z.coerce.number().min(50).max(100).default(90),
    action: z.enum(['SUSPEND_USER', 'FREEZE_USER', 'REQUIRE_REVIEW']).default('SUSPEND_USER'),
  }).default({ enabled: false, riskScoreThreshold: 90, action: 'SUSPEND_USER' }),
  enabled: z.boolean().optional(),
});

const ApiGatewayLockReleaseSchema = z.object({
  reason: z.string().trim().min(5).max(500),
});

const TreasuryWithdrawalRequestSchema = z.object({
  goalId: z.string().uuid(),
  amount: z.coerce.number().positive().max(1_000_000_000_000),
  destinationWalletId: z.string().uuid(),
  reason: z.string().trim().min(5).max(500),
});

const TreasuryAutoSweepSchema = z.object({
  goalId: z.string().uuid(),
  enabled: z.boolean(),
  threshold: z.coerce.number().nonnegative().max(1_000_000_000_000),
  frequency: z.enum(['DAILY', 'WEEKLY', 'MONTHLY']),
  timezone: z.string().trim().min(3).max(80),
  nextRunAt: z.string().datetime({ offset: true }),
  windowMinutes: z.coerce.number().int().min(5).max(1440),
  reason: z.string().trim().min(10).max(500),
});
const OrganizationStatementSchema = z.object({
  periodStart: z.string().datetime({ offset: true }),
  periodEnd: z.string().datetime({ offset: true }),
  timezone: z.string().trim().min(1).max(80).default('Africa/Dar_es_Salaam'),
  reason: z.string().trim().min(10).max(500),
});
const TreasuryAutoSweepReviewSchema = z.object({
  decision: z.enum(['APPROVE', 'REJECT']), reason: z.string().trim().min(10).max(500),
});

const TreasuryPolicySchema = z.object({
  organizationId: z.string().uuid(),
  currency: z.string().trim().toUpperCase().regex(/^[A-Z]{3}$/),
  name: z.string().trim().min(3).max(120),
  description: z.string().trim().max(500).nullable().optional(),
  minApprovals: z.coerce.number().int().min(2).max(20),
  maxAmountPerTx: z.coerce.number().positive().max(1_000_000_000_000).nullable().optional(),
  dailyLimit: z.coerce.number().positive().max(1_000_000_000_000).nullable().optional(),
  reason: z.string().trim().min(5).max(500),
});
const TreasuryApproverChangeSchema = z.object({
  organizationId: z.string().uuid(), targetUserId: z.string().uuid(),
  action: z.enum(['ADD', 'REMOVE']), reason: z.string().trim().min(5).max(500),
});
const TreasuryApproverReviewSchema = z.object({
  decision: z.enum(['APPROVE', 'REJECT']), reason: z.string().trim().min(5).max(500),
});
const OrganizationInvitationSchema = z.object({
  email: z.string().trim().email(), organizationId: z.string().uuid(),
  role: z.enum(['MEMBER', 'MANAGER', 'ACCOUNTANT']),
  reason: z.string().trim().min(5).max(500).default('Organization membership invitation requested'),
});
const OrganizationLinkInvitationSchema = z.object({
  userId: z.string().uuid(), organizationId: z.string().uuid(),
  role: z.enum(['MEMBER', 'MANAGER', 'ACCOUNTANT']),
  reason: z.string().trim().min(5).max(500).default('Organization membership invitation requested'),
});
const OrganizationInvitationResponseSchema = z.object({
  decision: z.enum(['ACCEPT', 'DECLINE']),
});
const OrganizationMemberChangeSchema = z.object({
  targetUserId: z.string().uuid(),
  action: z.enum(['CHANGE_ROLE', 'REMOVE_MEMBER']),
  toRole: z.enum(['MEMBER', 'MANAGER', 'ACCOUNTANT']).nullable().optional(),
  reason: z.string().trim().min(5).max(500),
}).refine((value) => value.action !== 'CHANGE_ROLE' || Boolean(value.toRole), {
  message: 'toRole is required for CHANGE_ROLE',
  path: ['toRole'],
});
const OrganizationMemberChangeReviewSchema = z.object({
  decision: z.enum(['APPROVE', 'REJECT']),
  reason: z.string().trim().min(5).max(500),
});
const OrganizationLeadershipChangeSchema = z.object({
  targetUserId: z.string().uuid(),
  action: z.enum(['ADD_ADMIN', 'REMOVE_ADMIN', 'TRANSFER_PRIMARY_ADMIN']),
  toRole: z.enum(['MEMBER', 'MANAGER', 'ACCOUNTANT']).nullable().optional(),
  reason: z.string().trim().min(5).max(500),
});
const OrganizationLeadershipReviewSchema = z.object({
  decision: z.enum(['APPROVE', 'REJECT']),
  reason: z.string().trim().min(5).max(500),
});
const OrganizationRecoverySchema = z.object({
  beneficiaryUserId: z.string().uuid(),
  incidentReference: z.string().trim().min(8).max(120),
  reason: z.string().trim().min(10).max(500),
  evidence: z.record(z.string(), z.unknown()).default({}),
});
const OrganizationRecoveryReviewSchema = z.object({
  decision: z.enum(['APPROVE', 'REJECT']),
  reason: z.string().trim().min(10).max(500),
});
const OrganizationRecoveryContactSchema = z.object({
  contactUserId: z.string().uuid(),
  contactType: z.enum(['EMAIL', 'PHONE', 'LEGAL_REPRESENTATIVE']),
  reason: z.string().trim().min(10).max(500),
});
const OrganizationRecoveryContactReviewSchema = z.object({
  decision: z.enum(['VERIFY', 'REJECT', 'REVOKE']),
  reason: z.string().trim().min(10).max(500),
});
const OrganizationRecoveryContactRevocationSchema = z.object({ reason: z.string().trim().min(10).max(500) });
const OrganizationReactivationSchema = z.object({
  targetUserId: z.string().uuid(),
  reason: z.string().trim().min(10).max(500),
  evidence: z.object({
    identityReverified: z.literal(true),
    credentialResetConfirmed: z.literal(true),
    incidentClosed: z.literal(true),
  }).passthrough(),
});
const OrganizationReactivationReviewSchema = z.object({
  decision: z.enum(['APPROVE', 'REJECT']),
  reason: z.string().trim().min(10).max(500),
});

const CurrencyCodeSchema = z.string().trim().toUpperCase().regex(/^[A-Z]{3}$/);

const FxCorridorConfigSchema = z.object({
  fromCurrency: CurrencyCodeSchema,
  toCurrency: CurrencyCodeSchema,
  rateProviderCode: z.string().trim().toUpperCase().min(2).max(80),
  settlementProviderId: z.string().uuid().nullable().optional(),
  settlementMode: z.enum(['INTERNAL_LEDGER', 'EXTERNAL_LP', 'HYBRID']).default('INTERNAL_LEDGER'),
  priority: z.coerce.number().int().min(1).max(999).default(100),
  minAmount: z.coerce.number().nonnegative().nullable().optional(),
  maxAmount: z.coerce.number().positive().nullable().optional(),
  supportedCountries: z.array(z.string().trim().toUpperCase().min(2).max(3)).max(64).default([]),
  status: z.enum(['ACTIVE', 'PAUSED', 'DISABLED']).default('ACTIVE'),
  metadata: z.record(z.string(), z.unknown()).default({}),
}).refine((value) => value.fromCurrency !== value.toCurrency, {
  message: 'FX corridor currencies must be different.',
  path: ['toCurrency'],
});

const FxMarginPolicySchema = z.object({
  fromCurrency: CurrencyCodeSchema,
  toCurrency: CurrencyCodeSchema,
  spreadMode: z.enum(['BPS', 'PIPS', 'FIXED_UNIT']).default('BPS'),
  fixedPips: z.coerce.number().nonnegative().default(0),
  marginBps: z.coerce.number().int().min(0).max(2500).default(75),
  riskBufferBps: z.coerce.number().int().min(0).max(2500).default(25),
  quoteLockSeconds: z.coerce.number().int().min(15).max(900).default(45),
  minAmount: z.coerce.number().nonnegative().nullable().optional(),
  maxAmount: z.coerce.number().positive().nullable().optional(),
  status: z.enum(['ACTIVE', 'PAUSED', 'DISABLED']).default('ACTIVE'),
  metadata: z.record(z.string(), z.unknown()).default({}),
}).refine((value) => value.fromCurrency !== value.toCurrency, {
  message: 'FX margin policy currencies must be different.',
  path: ['toCurrency'],
});

const FxExposureLimitSchema = z.object({
  currency: CurrencyCodeSchema,
  maxNetExposureUsd: z.coerce.number().nonnegative().default(0),
  maxDailyVolumeUsd: z.coerce.number().nonnegative().default(0),
  status: z.enum(['ACTIVE', 'PAUSED', 'DISABLED']).default('ACTIVE'),
  metadata: z.record(z.string(), z.unknown()).default({}),
});

type Deps = {
  authenticate: RequestHandler;
  adminOnly: RequestHandler;
  requireSessionPermission: (permissions: string[], roles?: string[]) => RequestHandler;
  LogicCore: any;
  ConfigClient: any;
  KMS: any;
  DataProtection: any;
  TransactionSigning: any;
};

const API_GATEWAY_SECURITY_ROLES = ['SUPER_ADMIN', 'ADMIN', 'AUDIT', 'RISK_OFFICER', 'FRAUD', 'IT'];

const PAYSAFE_RETRYABLE_ERRORS = new Set([
  'VAULT_OFFLINE',
  'SERVICE_ROLE_REQUIRED',
  'PAYSAFE_ESCROW_QUERY_TIMEOUT',
  'PAYSAFE_ESCROW_QUERY_FAILED',
  'PAYSAFE_VAULT_LOOKUP_FAILED',
  'PAYSAFE_TRANSITION_FAILED',
]);

const PAYSAFE_ERROR_MESSAGES: Record<string, string> = {
  VAULT_OFFLINE: 'PaySafe vault service is offline. Please try again shortly.',
  SERVICE_ROLE_REQUIRED: 'PaySafe settlement service is not configured correctly.',
  PAYSAFE_ESCROW_QUERY_TIMEOUT: 'PaySafe records took too long to load. Please try again shortly.',
  PAYSAFE_ESCROW_QUERY_FAILED: 'PaySafe records could not be loaded from the ledger.',
  PAYSAFE_VAULT_LOOKUP_FAILED: 'PaySafe wallet lookup failed. Please try again shortly.',
  PAYSAFE_VAULT_NOT_FOUND: 'Your PaySafe wallet is not ready yet.',
  PAYSAFE_VAULT_UNAVAILABLE: 'Your PaySafe wallet is locked or temporarily unavailable.',
  OPERATING_WALLET_REQUIRED: 'Your operating wallet is not ready yet.',
  RECIPIENT_VAULT_NOT_FOUND: 'The recipient wallet is not ready yet.',
  RECIPIENT_NOT_FOUND: 'The recipient could not be found.',
  PAYSAFE_AMOUNT_INVALID: 'Enter a valid PaySafe amount.',
  PAYSAFE_DESCRIPTION_REQUIRED: 'Enter a PaySafe description.',
  PAYSAFE_SELF_ESCROW_NOT_ALLOWED: 'You cannot create a PaySafe with yourself.',
  PAYSAFE_SENDER_ACCOUNT_NOT_ACTIVE: 'Your account is not active for PaySafe.',
  PAYSAFE_RECIPIENT_ACCOUNT_NOT_ACTIVE: 'The recipient account is not active for PaySafe.',
  PAYSAFE_CURRENCY_MISMATCH: 'PaySafe wallets must use the same currency.',
  ESCROW_NOT_FOUND: 'This PaySafe record could not be found.',
  ESCROW_ACCESS_DENIED: 'You do not have access to this PaySafe.',
  UNAUTHORIZED_RELEASE: 'Only the sender can request this PaySafe release.',
};

function paySafeErrorResponse(req: any, error: any) {
  const raw = String(error?.message || error || 'PAYSAFE_SERVICE_ERROR');
  const code = raw.match(/[A-Z][A-Z0-9_]+/)?.[0] || 'PAYSAFE_SERVICE_ERROR';
  const retryable = PAYSAFE_RETRYABLE_ERRORS.has(code);
  const status =
    code === 'ESCROW_NOT_FOUND' ? 404 :
    code === 'ESCROW_ACCESS_DENIED' || code === 'UNAUTHORIZED_RELEASE' ? 403 :
    retryable ? 503 :
    code === 'PAYSAFE_SERVICE_ERROR' ? 500 :
    400;
  return {
    status,
    body: {
      success: false,
      service: 'PAYSAFE',
      code,
      error: code,
      message: PAYSAFE_ERROR_MESSAGES[code] || 'PaySafe request could not be completed.',
      retryable,
      traceId: req.traceId || req.get?.('x-trace-id') || req.get?.('x-request-id') || null,
    },
  };
}

function withPaySafeTimeout<T>(
  operation: Promise<T>,
  code = 'PAYSAFE_ESCROW_QUERY_TIMEOUT',
  timeoutMs = Number(process.env.ORBI_PAYSAFE_ROUTE_TIMEOUT_MS || 8000),
): Promise<T> {
  let timeout: NodeJS.Timeout | undefined;
  const timeoutPromise = new Promise<T>((_resolve, reject) => {
    timeout = setTimeout(() => reject(new Error(code)), timeoutMs);
  });
  return Promise.race([operation, timeoutPromise]).finally(() => {
    if (timeout) clearTimeout(timeout);
  });
}

const isUuidLike = (value: unknown) =>
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(value || ''));

const normalizeFxConfigError = (error: unknown) => {
  if (error instanceof z.ZodError) {
    return {
      status: 400,
      body: {
        success: false,
        error: 'FX_CONFIG_VALIDATION_FAILED',
        details: error.issues.map((issue) => ({
          path: issue.path,
          message: issue.message,
        })),
      },
    };
  }
  return {
    status: 500,
    body: {
      success: false,
      error: 'FX_CONFIG_OPERATION_FAILED',
      message: String((error as any)?.message || error || 'FX configuration failed.'),
    },
  };
};

const requireFxAdminStore = () => {
  const sb = getAdminSupabase() || getSupabase();
  if (!sb) throw new Error('FX_CONFIG_STORE_UNAVAILABLE');
  return sb;
};

const computeFxExposure = (rows: any[]) => {
  const byCurrency = new Map<string, { currency: string; bought: number; sold: number; spread: number; count: number }>();
  for (const row of rows || []) {
    const from = String(row.from_currency || '').toUpperCase();
    const to = String(row.to_currency || '').toUpperCase();
    const sourceAmount = Number(row.source_amount || 0);
    const targetAmount = Number(row.target_amount || 0);
    const spreadAmount = Number(row.spread_amount || 0);
    if (from) {
      const current = byCurrency.get(from) || { currency: from, bought: 0, sold: 0, spread: 0, count: 0 };
      current.sold += sourceAmount;
      current.count += 1;
      byCurrency.set(from, current);
    }
    if (to) {
      const current = byCurrency.get(to) || { currency: to, bought: 0, sold: 0, spread: 0, count: 0 };
      current.bought += targetAmount;
      current.spread += spreadAmount;
      current.count += 1;
      byCurrency.set(to, current);
    }
  }
  return Array.from(byCurrency.values()).map((row) => ({
    ...row,
    netPosition: Number((row.bought - row.sold).toFixed(6)),
    spread: Number(row.spread.toFixed(6)),
  }));
};

const enrichGatewayActors = async (rows: any[]) => {
  const sb = getAdminSupabase() || getSupabase();
  if (!sb || rows.length === 0) return new Map<string, any>();

  const actorIds = Array.from(new Set(
    rows
      .map((row) => row.actor_id || row.actorId || row.actor_ref || row.actorRef)
      .filter((value) => value && isUuidLike(value)),
  ));
  if (actorIds.length === 0) return new Map<string, any>();

  const actorMap = new Map<string, any>();
  const [{ data: users }, { data: staff }] = await Promise.all([
    sb.from('users')
      .select('id, full_name, email, phone, customer_id, account_status, status_reason, status_reason_code')
      .in('id', actorIds),
    sb.from('staff')
      .select('id, full_name, email, role, account_status, status_reason, status_reason_code')
      .in('id', actorIds),
  ]);

  for (const user of users || []) {
    actorMap.set(String(user.id), { registryType: 'USER', ...user });
  }
  for (const staffRow of staff || []) {
    actorMap.set(String(staffRow.id), { registryType: 'STAFF', ...staffRow });
  }
  return actorMap;
};

export const registerOperationsRoutes = (v1: Router, deps: Deps) => {
  const {
    authenticate,
    adminOnly,
    requireSessionPermission,
    LogicCore,
    ConfigClient,
    KMS,
    DataProtection,
    TransactionSigning,
  } = deps;

  v1.get('/enterprise/organizations', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const result = await LogicCore.getOrganizations(session.sub);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/enterprise/organizations', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const result = await LogicCore.createOrganization(req.body, session.sub);
      if (result.error) return res.status(400).json({ success: false, error: result.error });
      res.json(result);
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/enterprise/organizations/:id', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const privileged = sessionHasAnyRole(session, ['ADMIN', 'SUPER_ADMIN', 'AUDIT']);
      const result = await LogicCore.getOrganizationDetails(req.params.id, session.sub, privileged);
      if (result.error) return res.status(404).json({ success: false, error: result.error });
      if (privileged) {
        await Audit.log('SECURITY', session.sub, 'ORGANIZATION_PRIVILEGED_READ', {
          organizationId: req.params.id,
        });
      }
      res.json(result);
    } catch (e: any) {
      const status = e.message === 'ORGANIZATION_ACCESS_DENIED' ? 403 : 500;
      res.status(status).json({ success: false, error: e.message });
    }
  });

  v1.post('/enterprise/organizations/:id/roles', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const result = await LogicCore.createOrganizationRole(req.params.id, req.body, session.sub);
      if (result.error) return res.status(400).json({ success: false, error: result.error });
      res.json(result);
    } catch (e: any) {
      const status = e instanceof z.ZodError ? 400 : 500;
      res.status(status).json({ success: false, error: e.message });
    }
  });

  v1.post('/enterprise/organizations/:id/admin-change-requests', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const input = OrganizationLeadershipChangeSchema.parse(req.body);
      const result = await LogicCore.requestOrganizationAdminChange(req.params.id, input, session.sub);
      if (result.error) return res.status(409).json({ success: false, error: result.error });
      res.json(result);
    } catch (e: any) {
      res.status(e instanceof z.ZodError ? 400 : 500).json({ success: false, error: e.message });
    }
  });

  v1.post('/enterprise/admin-change-requests/:id/respond', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const input = OrganizationLeadershipReviewSchema.parse(req.body);
      const result = await LogicCore.respondOrganizationAdminChange(req.params.id, input, session.sub);
      if (result.error) return res.status(409).json({ success: false, error: result.error });
      res.json(result);
    } catch (e: any) {
      res.status(e instanceof z.ZodError ? 400 : 500).json({ success: false, error: e.message });
    }
  });

  v1.post('/enterprise/organizations/:id/recovery-cases', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const input = OrganizationRecoverySchema.parse(req.body);
      const result = await LogicCore.requestOrganizationRecovery(req.params.id, input, session.sub);
      if (result.error) return res.status(409).json({ success: false, error: result.error });
      res.json(result);
    } catch (e: any) {
      res.status(e instanceof z.ZodError ? 400 : 500).json({ success: false, error: e.message });
    }
  });

  v1.post('/enterprise/organization-recovery-cases/:id/respond', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const input = OrganizationRecoveryReviewSchema.parse(req.body);
      const result = await LogicCore.respondOrganizationRecovery(req.params.id, input, session.sub);
      if (result.error) return res.status(409).json({ success: false, error: result.error });
      res.json(result);
    } catch (e: any) {
      res.status(e instanceof z.ZodError ? 400 : 500).json({ success: false, error: e.message });
    }
  });

  v1.post('/enterprise/organizations/:id/recovery-contacts', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const input = OrganizationRecoveryContactSchema.parse(req.body);
      const result = await LogicCore.requestOrganizationRecoveryContact(req.params.id, input, session.sub);
      if (result.error) return res.status(409).json({ success: false, error: result.error });
      res.json(result);
    } catch (e: any) { res.status(e instanceof z.ZodError ? 400 : 500).json({ success: false, error: e.message }); }
  });

  v1.post('/enterprise/organization-recovery-contacts/:id/revoke', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const input = OrganizationRecoveryContactRevocationSchema.parse(req.body);
      const result = await LogicCore.requestOrganizationRecoveryContactRevocation(req.params.id, input.reason, session.sub);
      if (result.error) return res.status(409).json({ success: false, error: result.error });
      res.json(result);
    } catch (e: any) { res.status(e instanceof z.ZodError ? 400 : 500).json({ success: false, error: e.message }); }
  });

  v1.post('/enterprise/organization-recovery-contacts/:id/respond', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const input = OrganizationRecoveryContactReviewSchema.parse(req.body);
      const result = await LogicCore.respondOrganizationRecoveryContact(req.params.id, input, session.sub);
      if (result.error) return res.status(409).json({ success: false, error: result.error });
      res.json(result);
    } catch (e: any) { res.status(e instanceof z.ZodError ? 400 : 500).json({ success: false, error: e.message }); }
  });

  v1.post('/enterprise/organizations/:id/reactivation-cases', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const input = OrganizationReactivationSchema.parse(req.body);
      const result = await LogicCore.requestOrganizationReactivation(req.params.id, input, session.sub);
      if (result.error) return res.status(409).json({ success: false, error: result.error });
      res.json(result);
    } catch (e: any) { res.status(e instanceof z.ZodError ? 400 : 500).json({ success: false, error: e.message }); }
  });

  v1.post('/enterprise/organization-reactivation-cases/:id/respond', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const input = OrganizationReactivationReviewSchema.parse(req.body);
      const result = await LogicCore.respondOrganizationReactivation(req.params.id, input, session.sub);
      if (result.error) return res.status(409).json({ success: false, error: result.error });
      res.json(result);
    } catch (e: any) { res.status(e instanceof z.ZodError ? 400 : 500).json({ success: false, error: e.message }); }
  });

  v1.post('/enterprise/users/link', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const { userId, organizationId, role, reason } = OrganizationLinkInvitationSchema.parse(req.body);
      const result = await LogicCore.linkUserToOrganization(userId, organizationId, role, session.sub, reason);
      if (result.error) return res.status(400).json({ success: false, error: result.error });
      res.json(result);
    } catch (e: any) {
      res.status(e instanceof z.ZodError ? 400 : 500).json({ success: false, error: e.message });
    }
  });

  v1.post('/enterprise/users/invite', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const { email, organizationId, role, reason } = OrganizationInvitationSchema.parse(req.body);
      const result = await LogicCore.inviteUserByEmail(email, organizationId, role, session.sub, reason);
      if (result.error) return res.status(400).json({ success: false, error: result.error });
      res.json(result);
    } catch (e: any) {
      res.status(e instanceof z.ZodError ? 400 : 500).json({ success: false, error: e.message });
    }
  });

  v1.post('/enterprise/treasury/withdraw/request', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const { goalId, amount, destinationWalletId, reason } = TreasuryWithdrawalRequestSchema.parse(req.body);
      const result = await LogicCore.requestTreasuryWithdrawal(session.sub, goalId, amount, destinationWalletId, reason);
      if (result.error) return res.status(400).json({ success: false, error: result.error });
      res.json(result);
    } catch (e: any) {
      const status = e instanceof z.ZodError ? 400 : 500;
      res.status(status).json({ success: false, error: e.message });
    }
  });

  v1.post('/enterprise/treasury/withdraw/approve', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const { txId, reason } = TreasuryApprovalSchema.parse(req.body);
      const result = await LogicCore.approveTreasuryWithdrawal(session.sub, txId, reason);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.get('/enterprise/treasury/approvals', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    const orgId = req.query.orgId as string;
    if (!orgId) return res.status(400).json({ success: false, error: 'MISSING_ORG_ID' });
    try {
      const privileged = sessionHasAnyRole(session, ['ADMIN', 'SUPER_ADMIN', 'AUDIT', 'ACCOUNTANT']);
      const result = await LogicCore.getPendingApprovals(orgId, session.sub, privileged);
      if (privileged) {
        await Audit.log('SECURITY', session.sub, 'ORGANIZATION_TREASURY_PRIVILEGED_READ', {
          organizationId: orgId,
        });
      }
      res.json(result);
    } catch (e: any) {
      const status = e.message === 'ORGANIZATION_ACCESS_DENIED' ? 403 : 500;
      res.status(status).json({ success: false, error: e.message });
    }
  });

  v1.post('/enterprise/treasury/autosweep', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const input = TreasuryAutoSweepSchema.parse(req.body);
      const privileged = sessionHasAnyRole(session, ['ADMIN', 'SUPER_ADMIN']);
      const result = await LogicCore.configureAutoSweep(input, session.sub, privileged);
      res.json(result);
    } catch (e: any) {
      const status = e instanceof z.ZodError ? 400 :
        e.message === 'ORGANIZATION_ACCESS_DENIED' ? 403 :
        e.message === 'ORGANIZATION_RESOURCE_NOT_FOUND' ? 404 : 500;
      res.status(status).json({ success: false, error: e.message });
    }
  });

  v1.get('/escrow', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const result = await withPaySafeTimeout(LogicCore.getEscrows(session.sub));
      res.json({ success: true, data: result });
    } catch (e: any) {
      const response = paySafeErrorResponse(req, e);
      console.warn('[PAYSAFE_ROUTE] escrow list failed', response.body);
      res.status(response.status).json(response.body);
    }
  });

  v1.post('/enterprise/treasury/autosweep-requests/:requestId/respond', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const input = TreasuryAutoSweepReviewSchema.parse(req.body);
      const result = await LogicCore.respondAutoSweepChange(req.params.requestId, input, session.sub);
      res.json(result);
    } catch (e: any) {
      res.status(e instanceof z.ZodError ? 400 : 403).json({ success: false, error: e.message });
    }
  });

  v1.post('/enterprise/organization-invitations/:id/respond', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const { decision } = OrganizationInvitationResponseSchema.parse(req.body);
      const result = await LogicCore.respondOrganizationInvitation(req.params.id, decision, session.sub);
      if (result.error) return res.status(409).json({ success: false, error: result.error });
      res.json(result);
    } catch (e: any) {
      res.status(e instanceof z.ZodError ? 400 : 500).json({ success: false, error: e.message });
    }
  });

  v1.post('/enterprise/organizations/:id/member-changes', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const input = OrganizationMemberChangeSchema.parse(req.body);
      const result = await LogicCore.requestOrganizationMemberChange(req.params.id, input, session.sub);
      if (result.error) return res.status(409).json({ success: false, error: result.error });
      res.json(result);
    } catch (e: any) {
      res.status(e instanceof z.ZodError ? 400 : 500).json({ success: false, error: e.message });
    }
  });

  v1.post('/enterprise/member-changes/:id/respond', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const input = OrganizationMemberChangeReviewSchema.parse(req.body);
      const result = await LogicCore.respondOrganizationMemberChange(req.params.id, input, session.sub);
      if (result.error) return res.status(409).json({ success: false, error: result.error });
      res.json(result);
    } catch (e: any) {
      res.status(e instanceof z.ZodError ? 400 : 500).json({ success: false, error: e.message });
    }
  });

  v1.get('/enterprise/treasury/policy', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    const organizationId = String(req.query.organizationId || '');
    const currency = String(req.query.currency || 'TZS').trim().toUpperCase();
    try {
      const result = await LogicCore.getTreasuryPolicy(organizationId, currency, session.sub);
      res.json(result);
    } catch (e: any) {
      res.status(e.message === 'ORGANIZATION_ACCESS_DENIED' ? 403 : 500).json({ success: false, error: e.message });
    }
  });

  v1.put('/enterprise/treasury/policy', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const input = TreasuryPolicySchema.parse(req.body);
      const result = await LogicCore.upsertTreasuryPolicy(input, session.sub);
      res.json(result);
    } catch (e: any) {
      const message = String(e.message || '');
      const status = e instanceof z.ZodError ? 400 :
        message.includes('ADMIN_REQUIRED') ? 403 :
        message.includes('QUORUM_UNAVAILABLE') || message.includes('LIMIT_') ? 409 : 500;
      res.status(status).json({ success: false, error: message });
    }
  });
  v1.post('/enterprise/treasury/approver-changes', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try { res.json(await LogicCore.requestTreasuryApproverChange(TreasuryApproverChangeSchema.parse(req.body), session.sub)); }
    catch (e: any) { res.status(e instanceof z.ZodError ? 400 : String(e.message).includes('ADMIN_REQUIRED') ? 403 : 409).json({ success:false,error:e.message }); }
  });
  v1.post('/enterprise/treasury/approver-changes/:id/respond', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try { res.json(await LogicCore.respondTreasuryApproverChange(req.params.id, TreasuryApproverReviewSchema.parse(req.body), session.sub)); }
    catch (e: any) { res.status(e instanceof z.ZodError ? 400 : String(e.message).includes('REVIEWER_REQUIRED') ? 403 : 409).json({ success:false,error:e.message }); }
  });
  v1.post('/enterprise/organizations/:id/statements', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try { res.json(await LogicCore.generateOrganizationStatement(req.params.id, OrganizationStatementSchema.parse(req.body), session.sub)); }
    catch (e: any) { const message=String(e.message||''); res.status(e instanceof z.ZodError?400:message.includes('ACCESS_DENIED')?403:message.includes('PERIOD_INVALID')?400:409).json({success:false,error:message}); }
  });
  v1.get('/enterprise/organizations/:id/statements', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try { res.json(await LogicCore.listOrganizationStatements(req.params.id, session.sub)); }
    catch (e: any) { res.status(String(e.message).includes('ACCESS_DENIED')?403:500).json({success:false,error:e.message}); }
  });
  v1.get('/enterprise/organization-statements/:id', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try { res.json(await LogicCore.getOrganizationStatement(req.params.id, session.sub, Number(req.query.offset||0), Number(req.query.limit||100))); }
    catch (e: any) { res.status(String(e.message).includes('ACCESS_DENIED')?403:String(e.message).includes('NOT_FOUND')?404:400).json({success:false,error:e.message}); }
  });

  v1.get('/escrow/:id', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const result = await withPaySafeTimeout(LogicCore.getEscrow(req.params.id, session.sub));
      if (!result) return res.status(404).json({ success: false, error: 'ESCROW_NOT_FOUND' });
      res.json({ success: true, data: result });
    } catch (e: any) {
      const response = paySafeErrorResponse(req, e);
      console.warn('[PAYSAFE_ROUTE] escrow detail failed', response.body);
      res.status(response.status).json(response.body);
    }
  });

  v1.post('/escrow/create', authenticate as any, requireIdempotencyKey, async (req, res) => {
    const {
      recipientCustomerId,
      recipient_customer_id,
      recipientId,
      recipient_id,
      recipientUserId,
      recipient_user_id,
      identifier,
      amount,
      description,
      conditions,
    } = req.body;
    const userId = (req as any).session.sub;
    try {
      const recipientIdentifier = String(
        recipientCustomerId ||
        recipient_customer_id ||
        recipientUserId ||
        recipient_user_id ||
        recipientId ||
        recipient_id ||
        identifier ||
        '',
      ).trim();
      if (!recipientIdentifier) {
        return res.status(400).json({ success: false, error: 'RECIPIENT_REQUIRED' });
      }
      const referenceId = await withPaySafeTimeout(
        LogicCore.createEscrow(userId, recipientIdentifier, amount, description, conditions),
        'PAYSAFE_ESCROW_CREATE_TIMEOUT',
      );
      res.json({ success: true, referenceId });
    } catch (e: any) {
      const response = paySafeErrorResponse(req, e);
      console.warn('[PAYSAFE_ROUTE] escrow create failed', response.body);
      res.status(response.status).json(response.body);
    }
  });

  v1.post('/escrow/release', authenticate as any, requireIdempotencyKey, async (req, res) => {
    const { referenceId } = req.body;
    const userId = (req as any).session.sub;
    try {
      const result = await withPaySafeTimeout(
        LogicCore.releaseEscrow(referenceId, userId),
        'PAYSAFE_TRANSITION_TIMEOUT',
      );
      res.json({ success: true, data: result });
    } catch (e: any) {
      const response = paySafeErrorResponse(req, e);
      console.warn('[PAYSAFE_ROUTE] escrow release failed', response.body);
      res.status(response.status).json(response.body);
    }
  });

  v1.post('/escrow/accept', authenticate as any, requireIdempotencyKey, async (req, res) => {
    const { referenceId } = req.body;
    const userId = (req as any).session.sub;
    try {
      const result = await withPaySafeTimeout(
        LogicCore.acceptEscrow(referenceId, userId),
        'PAYSAFE_TRANSITION_TIMEOUT',
      );
      res.json({ success: true, data: result });
    } catch (e: any) {
      const response = paySafeErrorResponse(req, e);
      console.warn('[PAYSAFE_ROUTE] escrow accept failed', response.body);
      res.status(response.status).json(response.body);
    }
  });

  v1.post('/escrow/dispute', authenticate as any, requireIdempotencyKey, async (req, res) => {
    const { referenceId, reason } = req.body;
    const userId = (req as any).session.sub;
    try {
      const result = await withPaySafeTimeout(
        LogicCore.disputeEscrow(referenceId, userId, reason),
        'PAYSAFE_TRANSITION_TIMEOUT',
      );
      res.json({ success: true, data: result ?? null });
    } catch (e: any) {
      const response = paySafeErrorResponse(req, e);
      console.warn('[PAYSAFE_ROUTE] escrow dispute failed', response.body);
      res.status(response.status).json(response.body);
    }
  });

  v1.post('/escrow/refund', authenticate as any, requireIdempotencyKey, async (req, res) => {
    const { referenceId, reason } = req.body;
    const userId = (req as any).session.sub;

    try {
      const result = await withPaySafeTimeout(
        LogicCore.refundEscrow(referenceId, userId, reason),
        'PAYSAFE_TRANSITION_TIMEOUT',
      );
      res.json({ success: true, data: result });
    } catch (e: any) {
      const response = paySafeErrorResponse(req, e);
      console.warn('[PAYSAFE_ROUTE] escrow refund failed', response.body);
      res.status(response.status).json(response.body);
    }
  });

  v1.get('/enterprise/budgets/alerts', authenticate as any, async (req, res) => {
    const orgId = req.query.orgId as string;
    if (!orgId) return res.status(400).json({ success: false, error: 'MISSING_ORG_ID' });
    try {
      const result = await LogicCore.getBudgetAlerts(orgId);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/admin/reconciliation/run', authenticate as any, requireSessionPermission(['reconciliation.run'], [...RECONCILIATION_RUN_ROLES]), async (req, res) => {
    try {
      const { reason } = ReconciliationRunSchema.parse(req.body);
      const session = (req as any).session;
      await LogicCore.runFullReconciliation(session.sub, reason);
      res.json({ success: true, message: 'Full reconciliation cycle triggered.' });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/reconciliation/reports', authenticate as any, requireSessionPermission(['reconciliation.read', 'reconciliation.run'], [...RECONCILIATION_REPORT_ROLES]), async (req, res) => {
    const limit = Number(req.query.limit || 50);
    try {
      const result = await LogicCore.getReconciliationReports(limit);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/config/ledger', authenticate as any, requireSessionPermission(['config.ledger.read', 'config.ledger.write'], [...CONFIG_LEDGER_ADMIN_ROLES]), async (_req, res) => {
    try {
      const config = await ConfigClient.getRuleConfig(true);
      res.json({ success: true, data: config.transaction_limits });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/admin/config/ledger', authenticate as any, requireSessionPermission(['config.ledger.write'], [...CONFIG_LEDGER_ADMIN_ROLES]), async (req, res) => {
    try {
      const currentConfig = await ConfigClient.getRuleConfig();
      const newLimits = req.body;
      const updatedConfig = {
        ...currentConfig,
        transaction_limits: {
          ...currentConfig.transaction_limits,
          ...newLimits,
        },
      };

      await ConfigClient.saveConfig(updatedConfig);
      res.json({ success: true, message: 'Ledger configuration updated successfully.' });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/risk/broker-notifications', authenticate as any, requireSessionPermission(['admin.audit.read', 'config.ledger.read'], [...CONFIG_LEDGER_ADMIN_ROLES, 'AUDIT', 'RISK_OFFICER', 'FRAUD']), async (_req, res) => {
    try {
      const currentConfig = await ConfigClient.getRuleConfig(true);
      const brokerNotifications = currentConfig.broker_notifications || currentConfig.rules?.broker_notifications || {};
      const autoFreeze = currentConfig.auto_freeze || currentConfig.rules?.auto_freeze || {};
      res.json({
        success: true,
        data: {
          enabled: brokerNotifications.enabled !== false,
          thresholdUsd: Number(brokerNotifications.thresholdUsd || 10000),
          email: {
            enabled: brokerNotifications.email?.enabled === true,
            recipients: Array.isArray(brokerNotifications.email?.recipients) ? brokerNotifications.email.recipients : [],
          },
          slack: {
            enabled: brokerNotifications.slack?.enabled === true,
            channel: brokerNotifications.slack?.channel || '#ops-security-feed',
            webhookConfigured: Boolean(process.env.ORBI_SLACK_WEBHOOK_URL || process.env.SLACK_WEBHOOK_URL),
          },
          autoFreeze: {
            enabled: autoFreeze.enabled === true,
            riskScoreThreshold: Number(autoFreeze.riskScoreThreshold || 90),
            action: autoFreeze.action || 'SUSPEND_USER',
          },
          eventCode: brokerNotifications.eventCode || 'DYNAMIC_BROKER_LIMIT_EXCEEDED',
          updatedAt: brokerNotifications.updatedAt || null,
        },
      });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/admin/risk/broker-notifications', authenticate as any, requireSessionPermission(['config.ledger.write'], [...CONFIG_LEDGER_ADMIN_ROLES, 'RISK_OFFICER', 'FRAUD']), async (req, res) => {
    const session = (req as any).session;
    try {
      const parsed = BrokerNotificationConfigSchema.parse(req.body || {});
      const enabled = parsed.enabled ?? (parsed.email.enabled || parsed.slack.enabled);
      const brokerNotifications = {
        enabled,
        thresholdUsd: parsed.thresholdUsd,
        email: {
          enabled: parsed.email.enabled,
          recipients: parsed.email.recipients,
        },
        slack: {
          enabled: parsed.slack.enabled,
          channel: parsed.slack.channel,
        },
        eventCode: 'DYNAMIC_BROKER_LIMIT_EXCEEDED',
        updatedAt: new Date().toISOString(),
        updatedBy: session?.sub || 'unknown',
      };
      const autoFreeze = {
        enabled: parsed.autoFreeze.enabled,
        riskScoreThreshold: parsed.autoFreeze.riskScoreThreshold,
        action: parsed.autoFreeze.action,
        targetRoles: ['SUPER_ADMIN', 'ADMIN', 'RISK_OFFICER', 'FRAUD'],
        updatedAt: new Date().toISOString(),
        updatedBy: session?.sub || 'unknown',
      };

      const currentConfig = await ConfigClient.getRuleConfig();
      const updatedRules = {
        ...(currentConfig.rules || {}),
        broker_notifications: brokerNotifications,
        auto_freeze: autoFreeze,
      };
      const updatedConfig = {
        ...currentConfig,
        rules: updatedRules,
        broker_notifications: brokerNotifications,
        auto_freeze: autoFreeze,
      };

      await ConfigClient.saveConfig(updatedConfig);
      res.json({
        success: true,
        message: 'Dynamic broker notification rules updated.',
        data: {
          ...brokerNotifications,
          slack: {
            ...brokerNotifications.slack,
            webhookConfigured: Boolean(process.env.ORBI_SLACK_WEBHOOK_URL || process.env.SLACK_WEBHOOK_URL),
          },
          autoFreeze,
        },
      });
    } catch (e: any) {
      if (e?.name === 'ZodError') {
        return res.status(400).json({ success: false, error: 'VALIDATION_FAILED', issues: e.issues });
      }
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/operator-alerts', authenticate as any, requireSessionPermission(['admin.audit.read', 'transaction.view', 'user.read'], ['SUPER_ADMIN', 'ADMIN', 'AUDIT', 'RISK_OFFICER', 'FRAUD', 'IT', 'CUSTOMER_CARE']), async (req, res) => {
    const session = (req as any).session;
    try {
      const data = await operatorAlertService.list({
        role: session?.role || session?.user?.role,
        status: String(req.query.status || 'ALL'),
        limit: Number(req.query.limit || 50),
      });
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.patch('/admin/operator-alerts/:id/read', authenticate as any, requireSessionPermission(['admin.audit.read', 'transaction.view', 'user.read'], ['SUPER_ADMIN', 'ADMIN', 'AUDIT', 'RISK_OFFICER', 'FRAUD', 'IT', 'CUSTOMER_CARE']), async (req, res) => {
    const session = (req as any).session;
    try {
      const data = await operatorAlertService.markRead(String(req.params.id), session?.sub || 'unknown');
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.patch('/admin/operator-alerts/:id/resolve', authenticate as any, requireSessionPermission(['admin.audit.read', 'transaction.view', 'user.read'], ['SUPER_ADMIN', 'ADMIN', 'AUDIT', 'RISK_OFFICER', 'FRAUD', 'IT', 'CUSTOMER_CARE']), async (req, res) => {
    const session = (req as any).session;
    try {
      const reason = String(req.body?.reason || '').trim();
      const data = await operatorAlertService.resolve(String(req.params.id), session?.sub || 'unknown', reason || undefined);
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/api-gateway/security/locks', authenticate as any, requireSessionPermission(['admin.audit.read', 'user.read'], API_GATEWAY_SECURITY_ROLES), async (req, res) => {
    try {
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });

      const limit = Math.min(200, Math.max(1, Number(req.query.limit || 80)));
      const status = String(req.query.status || 'active').trim().toLowerCase();
      const includeReleased = status === 'all' || status === 'released';

      const { data: quarantineRows, error: quarantineError } = await sb
        .from('api_gateway_quarantines')
        .select('id, actor_id, actor_ref, route_group, scope_key, reason, status, expires_at, released_at, released_by, metadata, created_at')
        .in('status', includeReleased ? ['active', 'released'] : ['active'])
        .order('created_at', { ascending: false })
        .limit(limit);
      if (quarantineError) throw quarantineError;

      const { data: eventRows, error: eventError } = await sb
        .from('api_gateway_security_events')
        .select('id, actor_id, actor_ref, route, method, route_group, operation_class, action, risk_score, ip_hash, device_hash, app_id, trace_id, metadata, created_at')
        .in('action', ['API_GATEWAY_ATTEMPT_LOCKED', 'API_GATEWAY_QUARANTINED', 'API_GATEWAY_THROTTLED'])
        .order('created_at', { ascending: false })
        .limit(limit);
      if (eventError) throw eventError;

      const combined = [
        ...(quarantineRows || []).map((row: any) => ({
          id: row.id,
          recordType: 'quarantine',
          action: row.reason === 'API_GATEWAY_ATTEMPT_LOCK' ? 'API_GATEWAY_ATTEMPT_LOCKED' : 'API_GATEWAY_QUARANTINED',
          actorId: row.actor_id,
          actorRef: row.actor_ref,
          route: row.metadata?.route || null,
          method: row.metadata?.method || null,
          routeGroup: row.route_group,
          operationClass: row.metadata?.operationClass || null,
          riskScore: row.metadata?.score || null,
          ipHash: row.metadata?.ipHash || null,
          deviceHash: row.metadata?.deviceHash || null,
          appId: row.metadata?.appId || null,
          traceId: row.metadata?.traceId || null,
          scopeKey: row.scope_key,
          status: row.status,
          reason: row.reason,
          expiresAt: row.expires_at,
          releasedAt: row.released_at,
          releasedBy: row.released_by,
          metadata: row.metadata || {},
          createdAt: row.created_at,
        })),
        ...(eventRows || []).map((row: any) => ({
          id: row.id,
          recordType: 'event',
          action: row.action,
          actorId: row.actor_id,
          actorRef: row.actor_ref,
          route: row.route,
          method: row.method,
          routeGroup: row.route_group,
          operationClass: row.operation_class,
          riskScore: row.risk_score,
          ipHash: row.ip_hash,
          deviceHash: row.device_hash,
          appId: row.app_id,
          traceId: row.trace_id,
          scopeKey: row.metadata?.scopeKey || null,
          status: row.metadata?.expiresAt && new Date(row.metadata.expiresAt).getTime() < Date.now() ? 'expired' : 'active',
          reason: row.metadata?.reason || row.action,
          expiresAt: row.metadata?.expiresAt || null,
          releasedAt: null,
          releasedBy: null,
          metadata: row.metadata || {},
          createdAt: row.created_at,
        })),
      ]
        .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)))
        .slice(0, limit);

      const actorMap = await enrichGatewayActors(combined);
      const data = combined.map((row) => ({
        ...row,
        actor: actorMap.get(String(row.actorId || row.actorRef)) || {
          registryType: String(row.actorRef || '').startsWith('anonymous:') ? 'ANONYMOUS_SOURCE' : 'UNKNOWN',
          id: row.actorId || null,
          reference: row.actorRef || null,
        },
        canRelease: Boolean(row.scopeKey && row.status === 'active'),
      }));

      res.json({
        success: true,
        data,
        meta: {
          note: 'Use POST /v1/admin/api-gateway/security/locks/:id/release with a reason to clear a Redis lock/quarantine by scope key.',
        },
      });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/admin/api-gateway/security/locks/:id/release', authenticate as any, requireSessionPermission(['admin.audit.read'], API_GATEWAY_SECURITY_ROLES), async (req, res) => {
    const session = (req as any).session;
    try {
      const parsed = ApiGatewayLockReleaseSchema.parse(req.body || {});
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });

      const id = String(req.params.id || '').trim();
      let recordType: 'quarantine' | 'event' = 'quarantine';
      let record: any = null;

      const quarantineResult = await sb
        .from('api_gateway_quarantines')
        .select('id, actor_id, actor_ref, route_group, scope_key, reason, status, metadata, expires_at, created_at')
        .eq('id', id)
        .maybeSingle();

      if (quarantineResult.data) {
        record = quarantineResult.data;
      } else {
        const eventResult = await sb
          .from('api_gateway_security_events')
          .select('id, actor_id, actor_ref, route, method, route_group, operation_class, action, metadata, created_at')
          .eq('id', id)
          .maybeSingle();
        if (eventResult.error) throw eventResult.error;
        record = eventResult.data;
        recordType = 'event';
      }

      if (!record) return res.status(404).json({ success: false, error: 'API_GATEWAY_LOCK_NOT_FOUND' });

      const scopeKey = String(record.scope_key || record.metadata?.scopeKey || '').trim();
      if (!scopeKey) {
        return res.status(400).json({
          success: false,
          error: 'API_GATEWAY_SCOPE_KEY_MISSING',
          message: 'This historical lock record does not include a Redis scope key. It may predate resolvable gateway locks.',
        });
      }

      await RedisManager.delete(scopeKey);

      if (recordType === 'quarantine') {
        await sb
          .from('api_gateway_quarantines')
          .update({
            status: 'released',
            released_at: new Date().toISOString(),
            released_by: session?.sub || 'unknown',
            metadata: {
              ...(record.metadata || {}),
              releaseReason: parsed.reason,
              releasedByRole: session?.role || session?.user?.role || null,
            },
          })
          .eq('id', id);
      }

      await Audit.log('SECURITY', session?.sub || 'unknown', 'API_GATEWAY_LOCK_RELEASED', {
        actor_name: session?.email || session?.user?.email || 'ORBI Admin',
        targetRecordId: id,
        targetRecordType: recordType,
        targetActorRef: record.actor_ref || record.actor_id || null,
        routeGroup: record.route_group,
        scopeKey,
        reason: parsed.reason,
      }).catch(() => {});

      res.json({
        success: true,
        data: {
          released: true,
          id,
          recordType,
          scopeKey,
          reason: parsed.reason,
        },
      });
    } catch (e: any) {
      if (e?.name === 'ZodError') {
        return res.status(400).json({ success: false, error: 'VALIDATION_FAILED', issues: e.issues });
      }
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/config/commissions', authenticate as any, requireSessionPermission(['config.commissions.read', 'config.commissions.write'], [...CONFIG_COMMISSION_VIEW_ROLES]), async (_req, res) => {
    try {
      const config = await ConfigClient.getRuleConfig(true);
      res.json({ success: true, data: config.commission_programs || {} });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/admin/config/commissions', authenticate as any, requireSessionPermission(['config.commissions.write'], [...CONFIG_LEDGER_ADMIN_ROLES]), async (req, res) => {
    try {
      const currentConfig = await ConfigClient.getRuleConfig();
      const updatedConfig = {
        ...currentConfig,
        commission_programs: {
          ...(currentConfig.commission_programs || {}),
          ...(req.body || {}),
        },
      };
      await ConfigClient.saveConfig(updatedConfig);
      res.json({ success: true, message: 'Commission configuration updated successfully.' });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/config/fx-rates', authenticate as any, requireSessionPermission(['config.fx.read', 'config.fx.write'], [...CONFIG_FX_VIEW_ROLES]), async (_req, res) => {
    res.status(410).json({
      success: false,
      error: 'FX_MANUAL_RATES_DEPRECATED',
      message: 'FX market rates are supplied by LiquidityProviderAdapter. Configure spread, risk buffer, and quote lock policies instead.',
    });
  });

  v1.post('/admin/config/fx-rates', authenticate as any, requireSessionPermission(['config.fx.write'], [...CONFIG_LEDGER_ADMIN_ROLES]), async (req, res) => {
    void req;
    res.status(410).json({
      success: false,
      error: 'FX_MANUAL_RATES_DEPRECATED',
      message: 'Manual FX rates are not accepted. Use LiquidityProviderAdapter for market rates and fx_margin_policies for ORBI spread policy.',
    });
  });

  v1.get('/admin/config/fx/corridors', authenticate as any, requireSessionPermission(['config.fx.read', 'config.fx.write'], [...CONFIG_FX_VIEW_ROLES]), async (_req, res) => {
    try {
      const sb = requireFxAdminStore();
      const { data, error } = await sb
        .from('fx_corridors')
        .select('*')
        .order('priority', { ascending: true })
        .order('from_currency', { ascending: true });
      if (error) throw error;
      res.json({ success: true, data: data || [] });
    } catch (error) {
      const payload = normalizeFxConfigError(error);
      res.status(payload.status).json(payload.body);
    }
  });

  v1.put('/admin/config/fx/corridors', authenticate as any, requireSessionPermission(['config.fx.write'], [...CONFIG_LEDGER_ADMIN_ROLES]), requireIdempotencyKey, async (req, res) => {
    try {
      const parsed = FxCorridorConfigSchema.parse(req.body || {});
      const sb = requireFxAdminStore();
      const row = {
        from_currency: parsed.fromCurrency,
        to_currency: parsed.toCurrency,
        rate_provider_code: parsed.rateProviderCode,
        settlement_provider_id: parsed.settlementProviderId || null,
        settlement_mode: parsed.settlementMode,
        priority: parsed.priority,
        min_amount: parsed.minAmount ?? null,
        max_amount: parsed.maxAmount ?? null,
        supported_countries: parsed.supportedCountries,
        status: parsed.status,
        metadata: parsed.metadata,
        updated_at: new Date().toISOString(),
      };
      const { data, error } = await sb
        .from('fx_corridors')
        .upsert(row, { onConflict: 'from_currency,to_currency,rate_provider_code' })
        .select('*')
        .single();
      if (error) throw error;
      res.json({ success: true, data });
    } catch (error) {
      const payload = normalizeFxConfigError(error);
      res.status(payload.status).json(payload.body);
    }
  });

  v1.get('/admin/config/fx/margins', authenticate as any, requireSessionPermission(['config.fx.read', 'config.fx.write'], [...CONFIG_FX_VIEW_ROLES]), async (_req, res) => {
    try {
      const sb = requireFxAdminStore();
      const { data, error } = await sb
        .from('fx_margin_policies')
        .select('*')
        .order('from_currency', { ascending: true })
        .order('to_currency', { ascending: true });
      if (error) throw error;
      res.json({ success: true, data: data || [] });
    } catch (error) {
      const payload = normalizeFxConfigError(error);
      res.status(payload.status).json(payload.body);
    }
  });

  v1.put('/admin/config/fx/margins', authenticate as any, requireSessionPermission(['config.fx.write'], [...CONFIG_LEDGER_ADMIN_ROLES]), requireIdempotencyKey, async (req, res) => {
    try {
      const parsed = FxMarginPolicySchema.parse(req.body || {});
      const sb = requireFxAdminStore();
      const row = {
        from_currency: parsed.fromCurrency,
        to_currency: parsed.toCurrency,
        spread_mode: parsed.spreadMode,
        fixed_pips: parsed.fixedPips,
        margin_bps: parsed.marginBps,
        risk_buffer_bps: parsed.riskBufferBps,
        quote_lock_seconds: parsed.quoteLockSeconds,
        min_amount: parsed.minAmount ?? null,
        max_amount: parsed.maxAmount ?? null,
        status: parsed.status,
        metadata: parsed.metadata,
        updated_at: new Date().toISOString(),
      };
      const { data, error } = await sb
        .from('fx_margin_policies')
        .upsert(row, { onConflict: 'from_currency,to_currency' })
        .select('*')
        .single();
      if (error) throw error;
      res.json({ success: true, data });
    } catch (error) {
      const payload = normalizeFxConfigError(error);
      res.status(payload.status).json(payload.body);
    }
  });

  v1.get('/admin/config/fx/providers/health', authenticate as any, requireSessionPermission(['config.fx.read', 'config.fx.write'], [...CONFIG_FX_VIEW_ROLES]), async (_req, res) => {
    try {
      const sb = requireFxAdminStore();
      const [{ data: health, error: healthError }, { data: corridors, error: corridorError }] = await Promise.all([
        sb.from('fx_provider_health').select('*').order('updated_at', { ascending: false }),
        sb.from('fx_corridors').select('rate_provider_code,status'),
      ]);
      if (healthError) throw healthError;
      if (corridorError) throw corridorError;
      const activeProviders = new Set((corridors || []).map((row: any) => String(row.rate_provider_code || '').toUpperCase()).filter(Boolean));
      res.json({
        success: true,
        data: Array.from(activeProviders).map((providerCode) => ({
          providerCode,
          corridorCount: (corridors || []).filter((row: any) => String(row.rate_provider_code || '').toUpperCase() === providerCode).length,
          health: (health || []).find((row: any) => String(row.provider_code || '').toUpperCase() === providerCode) || null,
        })),
      });
    } catch (error) {
      const payload = normalizeFxConfigError(error);
      res.status(payload.status).json(payload.body);
    }
  });

  v1.get('/admin/config/fx/exposure', authenticate as any, requireSessionPermission(['config.fx.read', 'config.fx.write'], [...CONFIG_FX_VIEW_ROLES]), async (_req, res) => {
    try {
      const sb = requireFxAdminStore();
      const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
      const [{ data: events, error: eventError }, { data: limits, error: limitError }] = await Promise.all([
        sb.from('fx_reconciliation_events').select('*').gte('created_at', since).order('created_at', { ascending: false }).limit(1000),
        sb.from('fx_treasury_exposure_limits').select('*').order('currency', { ascending: true }),
      ]);
      if (eventError) throw eventError;
      if (limitError) throw limitError;
      res.json({
        success: true,
        data: {
          window: '24h',
          exposure: computeFxExposure((events || []).filter((row: any) => String(row.status || '').toUpperCase() === 'MATCHED')),
          pendingQuoteCount: (events || []).filter((row: any) => String(row.status || '').toUpperCase() === 'PENDING').length,
          limits: limits || [],
        },
      });
    } catch (error) {
      const payload = normalizeFxConfigError(error);
      res.status(payload.status).json(payload.body);
    }
  });

  v1.put('/admin/config/fx/exposure-limits', authenticate as any, requireSessionPermission(['config.fx.write'], [...CONFIG_LEDGER_ADMIN_ROLES]), requireIdempotencyKey, async (req, res) => {
    try {
      const parsed = FxExposureLimitSchema.parse(req.body || {});
      const sb = requireFxAdminStore();
      const { data, error } = await sb
        .from('fx_treasury_exposure_limits')
        .upsert({
          currency: parsed.currency,
          max_net_exposure_usd: parsed.maxNetExposureUsd,
          max_daily_volume_usd: parsed.maxDailyVolumeUsd,
          status: parsed.status,
          metadata: parsed.metadata,
          updated_at: new Date().toISOString(),
        }, { onConflict: 'currency' })
        .select('*')
        .single();
      if (error) throw error;
      res.json({ success: true, data });
    } catch (error) {
      const payload = normalizeFxConfigError(error);
      res.status(payload.status).json(payload.body);
    }
  });

  v1.get('/admin/config/fx/reconciliation', authenticate as any, requireSessionPermission(['reconciliation.reports.read', 'config.fx.read'], [...RECONCILIATION_REPORT_ROLES, ...CONFIG_FX_VIEW_ROLES]), async (req, res) => {
    try {
      const sb = requireFxAdminStore();
      const limit = Math.min(Number(req.query.limit || 100), 500);
      const status = String(req.query.status || '').trim().toUpperCase();
      let query = sb.from('fx_reconciliation_events').select('*').order('created_at', { ascending: false }).limit(limit);
      if (status) query = query.eq('status', status);
      const { data, error } = await query;
      if (error) throw error;
      res.json({ success: true, data: data || [] });
    } catch (error) {
      const payload = normalizeFxConfigError(error);
      res.status(payload.status).json(payload.body);
    }
  });

  v1.post('/admin/kms/rewrap', authenticate as any, adminOnly as any, async (req, res) => {
    try {
      const confirm = String(req.body?.confirm || '').trim().toUpperCase();
      if (confirm !== 'REWRAP_KEYS') {
        return res.status(400).json({
          success: false,
          error: 'CONFIRMATION_REQUIRED',
          message: 'Set confirm=REWRAP_KEYS to proceed.',
        });
      }

      const newMasterKey = String(req.body?.newMasterKey || '').trim();
      const resolvedMasterKey = newMasterKey || String(process.env.KMS_MASTER_KEY || '').trim();
      if (!resolvedMasterKey) {
        return res.status(400).json({
          success: false,
          error: 'KMS_MASTER_KEY_MISSING',
          message: 'No master key provided or configured.',
        });
      }

      await KMS.reWrapAllKeys(resolvedMasterKey);
      res.json({ success: true, message: 'KMS keys re-wrapped successfully.' });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/kms/health', authenticate as any, adminOnly as any, async (_req, res) => {
    try {
      const probe = { ping: 'pong', ts: Date.now() };
      const cipher = await DataProtection.encryptValue(probe, { route: 'public_operations_probe' });
      const decoded = await DataProtection.decryptValue(cipher);
      const ok = decoded && typeof decoded === 'object' && (decoded as any).ping === 'pong';
      res.json({
        success: ok,
        data: {
          ok,
          ts: Date.now(),
        },
      });
    } catch (e: any) {
      res.status(500).json({
        success: false,
        error: e.message,
      });
    }
  });

  v1.post('/admin/kms/diagnose', authenticate as any, adminOnly as any, async (req, res) => {
    try {
      const masterKey = String(req.body?.masterKey || process.env.KMS_MASTER_KEY || '').trim();
      if (!masterKey) {
        return res.status(400).json({
          success: false,
          error: 'KMS_MASTER_KEY_MISSING',
        });
      }

      const configuredSalt = process.env.KMS_SALT || '';
      const defaultSalt = 'orbi-kms-wrapping-salt-v1';

      const matchConfigured = await KMS.testUnwrapWithSecret(masterKey, configuredSalt || undefined);
      const matchDefault = await KMS.testUnwrapWithSecret(masterKey, defaultSalt);

      res.json({
        success: true,
        data: {
          matchConfiguredSalt: matchConfigured,
          matchDefaultSalt: matchDefault,
          configuredSalt: configuredSalt ? 'SET' : 'EMPTY',
        },
      });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/sys/bootstrap', authenticate as any, async (req, res) => {
    const token = (req as any).authToken as string | null;
    try {
      const result = await LogicCore.getBootstrapData(token);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/sys/metrics', authenticate as any, async (_req, res) => {
    try {
      const result = await LogicCore.getSystemMetrics();
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/transactions/secure-sign', authenticate as any, async (req, res) => {
    try {
      const { transactionPayload, signature, publicKey } = req.body;

      const hash = TransactionSigning.generateTransactionHash(transactionPayload);
      const isValid = TransactionSigning.verifySecureEnclaveSignature(hash, signature, publicKey);

      if (!isValid) {
        return res.status(403).json({ success: false, error: 'SECURE_ENCLAVE_SIGNATURE_INVALID' });
      }

      const result = await LogicCore.processSecurePayment(transactionPayload, (req as any).session.user);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });
};
