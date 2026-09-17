import { type RequestHandler, type Router } from 'express';
import { Messaging } from '../../../backend/features/MessagingService.js';
import { requireIdempotencyKey, resolveIdempotencyHeader } from '../../middleware/security/idempotency.js';
import { resolveOperatingWealthWalletStrict } from './wealthShared.js';

type Deps = {
  authenticate: RequestHandler;
  LogicCore: any;
  getSupabase: () => any;
  getAdminSupabase: () => any;
  SharedBudgetCreateSchema: any;
  SharedBudgetUpdateSchema: any;
  SharedBudgetMemberAddSchema: any;
  SharedBudgetAllocateSchema: any;
  SharedBudgetInviteResponseSchema: any;
  SharedBudgetApprovalResponseSchema: any;
  SharedBudgetSpendSchema: any;
  wealthNumber: (value: any) => number;
  resolveSharedBudgetMembership: (sb: any, budgetId: string, userId: string) => Promise<any>;
  canManageSharedBudget: (role: string) => boolean;
  canSpendFromSharedBudget: (role: string) => boolean;
  canReviewSharedBudgetSpend: (role: string) => boolean;
  resolveUserBySharedBudgetIdentifier: (sb: any, identifier: string) => Promise<any>;
  expireSharedBudgetInvitationIfNeeded: (sb: any, invite: any) => Promise<any>;
  executeSharedBudgetSpend: (sb: any, input: any) => Promise<any>;
};

const ORBI_USER_SELECT = 'id, full_name, email, phone';

const compactIds = (rows: any[], key: string): string[] => Array.from(new Set(
  (rows || []).map((row: any) => String(row?.[key] || '')).filter(Boolean),
));

const fetchUsersById = async (sb: any, userIds: string[]): Promise<Map<string, any>> => {
  if (!userIds.length) return new Map();
  const { data, error } = await sb
    .from('users')
    .select(ORBI_USER_SELECT)
    .in('id', userIds);
  if (error) throw new Error(error.message);
  return new Map((data || []).map((user: any) => [String(user.id), user]));
};

const fetchSharedBudgetsById = async (sb: any, budgetIds: string[]): Promise<Map<string, any>> => {
  if (!budgetIds.length) return new Map();
  const { data, error } = await sb
    .from('shared_budgets')
    .select('id, name, purpose, currency, budget_limit, funded_amount, spent_amount, period_type, approval_mode, status, auto_allocate_enabled, auto_allocate_mode, auto_allocate_amount, auto_allocate_threshold')
    .in('id', budgetIds);
  if (error) throw new Error(error.message);
  return new Map((data || []).map((budget: any) => [String(budget.id), budget]));
};

type ReportRangeKey = 'week' | 'month' | 'year';

const toMoneyNumber = (value: any): number => {
  const parsed = Number(value || 0);
  return Number.isFinite(parsed) ? parsed : 0;
};

const formatBudgetAmount = (amount: any, currency: any) => {
  const numeric = Number(amount || 0);
  const safeAmount = Number.isFinite(numeric) ? numeric : 0;
  return `${String(currency || 'TZS').toUpperCase()} ${safeAmount.toLocaleString('en-US', {
    minimumFractionDigits: 0,
    maximumFractionDigits: 2,
  })}`;
};

const notifyBudgetMembers = async (
  sb: any,
  budgetId: string,
  subject: string,
  body: string,
  variables: Record<string, any> = {},
  options: { excludeUserIds?: string[] } = {},
) => {
  const excluded = new Set((options.excludeUserIds || []).map((userId) => String(userId)));
  const { data: members } = await sb
    .from('shared_budget_members')
    .select('user_id')
    .eq('budget_id', budgetId)
    .eq('status', 'ACTIVE');
  const userIds: string[] = Array.from(
    new Set<string>((members || []).map((member: any) => String(member.user_id || '')).filter(Boolean)),
  ).filter((userId) => !excluded.has(userId));
  const eventCode = variables.eventCode || 'SHARED_BUDGET_UPDATED';
  const eventId = String(variables.eventId || variables.transactionId || variables.approvalId || variables.inviteId || variables.memberId || '').trim();

  await Promise.all(userIds.map((userId) => Messaging.dispatch(userId, 'info', subject, body, {
    push: true,
    sms: true,
    email: true,
    systemCustomBypass: true,
    mandatory: true,
    eventCode,
    ...(eventId ? { idempotencyKey: `${eventCode}:${eventId}` } : {}),
    variables: {
      ...variables,
      recipient_user_id: userId,
    },
    metadata: {
      ...(variables.metadata || {}),
      budgetId,
      recipientUserId: userId,
      eventCode: variables.eventCode || 'SHARED_BUDGET_UPDATED',
    },
  }).catch((error: any) => {
    console.warn('[Wealth][SharedBudget] Member notification deferred', {
      budgetId,
      userId,
      code: String(error?.code || error?.message || ''),
    });
  })));
};

const notifySharedBudgetSpend = async (
  sb: any,
  budget: any,
  actorUserId: string,
  data: any,
  amount: any,
  spendType: any,
  options: { requiresApproval?: boolean; approvedByUserId?: string | null } = {},
) => {
  const normalizedType = String(spendType || '').trim().toUpperCase();
  const isWithdrawal = ['SHARED_BUDGET_WITHDRAWAL_TO_ACCOUNT', 'SHARED_BUDGET_AGENT_CASHOUT'].includes(normalizedType);
  const amountLabel = formatBudgetAmount(amount, budget.currency);
  const budgetName = String(budget.name || 'Mezani');
  const transactionId = data?.transaction?.internalId || data?.transaction?.id || data?.budget_transaction?.transaction_id || null;
  const eventId = String(transactionId || data?.approval?.id || data?.budget_transaction?.id || '').trim();
  const eventCode = options.requiresApproval
    ? 'SHARED_BUDGET_SPEND_APPROVAL_REQUESTED'
    : isWithdrawal
      ? 'SHARED_BUDGET_WITHDRAWAL_COMPLETED'
      : 'SHARED_BUDGET_SPEND_COMPLETED';
  const actorSubject = options.requiresApproval
    ? 'Mezani request sent'
    : isWithdrawal
      ? 'Mezani withdrawal completed'
      : 'Mezani spend completed';
  const actorBody = options.requiresApproval
    ? `Your request for ${amountLabel} from ${budgetName} has been sent for approval.`
    : isWithdrawal
      ? `${amountLabel} has been withdrawn from ${budgetName}.`
      : `${amountLabel} has been spent from ${budgetName}.`;

  await Messaging.dispatch(actorUserId, 'info', actorSubject, actorBody, {
    push: true,
    sms: true,
    email: true,
    systemCustomBypass: true,
    mandatory: true,
    eventCode,
    ...(eventId ? { idempotencyKey: `${eventCode}:${eventId}` } : {}),
    variables: {
      eventCode,
      budgetId: budget.id,
      budgetName,
      amount: amountLabel,
      currency: String(budget.currency || 'TZS').toUpperCase(),
      transactionId,
      eventId,
      spendType: normalizedType,
      approvedByUserId: options.approvedByUserId || null,
    },
    metadata: {
      budgetId: budget.id,
      transactionId,
      amount: Number(amount || 0),
      currency: String(budget.currency || 'TZS').toUpperCase(),
      spendType: normalizedType,
      eventCode,
      approvedByUserId: options.approvedByUserId || null,
    },
  }).catch((error: any) => {
    console.warn('[Wealth][SharedBudget] Actor spend notification deferred', {
      budgetId: budget.id,
      userId: actorUserId,
      code: String(error?.code || error?.message || ''),
    });
  });

  await notifyBudgetMembers(
    sb,
    budget.id,
    options.requiresApproval
      ? 'Mezani request needs approval'
      : isWithdrawal
        ? 'Mezani withdrawal posted'
        : 'Mezani activity posted',
    options.requiresApproval
      ? `${amountLabel} request from ${budgetName} is waiting for approval.`
      : isWithdrawal
        ? `${amountLabel} has been withdrawn from ${budgetName}.`
        : `${amountLabel} activity has been posted on ${budgetName}.`,
    {
      eventCode,
      budgetId: budget.id,
      budgetName,
      amount: amountLabel,
      currency: String(budget.currency || 'TZS').toUpperCase(),
      transactionId,
      spendType: normalizedType,
      actorUserId,
      approvedByUserId: options.approvedByUserId || null,
    },
    { excludeUserIds: [actorUserId] },
  );
};

const resolveReportRange = (raw: unknown): { key: ReportRangeKey; start: Date; end: Date } => {
  const key = String(Array.isArray(raw) ? raw[0] : raw || 'month').toLowerCase() as ReportRangeKey;
  const safeKey: ReportRangeKey = ['week', 'month', 'year'].includes(key) ? key : 'month';
  const end = new Date();
  const start = new Date(end);

  if (safeKey === 'week') {
    const day = start.getDay();
    const mondayOffset = day === 0 ? -6 : 1 - day;
    start.setDate(start.getDate() + mondayOffset);
    start.setHours(0, 0, 0, 0);
  } else if (safeKey === 'year') {
    start.setMonth(0, 1);
    start.setHours(0, 0, 0, 0);
  } else {
    start.setDate(1);
    start.setHours(0, 0, 0, 0);
  }

  return { key: safeKey, start, end };
};

const buildSharedBudgetReport = (budget: any, members: any[], transactions: any[], usersById: Map<string, any>, range: ReturnType<typeof resolveReportRange>) => {
  const periodByUser = new Map<string, number>();
  const totalSpent = (transactions || []).reduce((sum: number, transaction: any) => {
    const amount = toMoneyNumber(transaction.amount);
    const userId = String(transaction.member_user_id || '');
    if (userId) periodByUser.set(userId, (periodByUser.get(userId) || 0) + amount);
    return sum + amount;
  }, 0);

  return {
    report_type: 'SHARED_BUDGET',
    range: {
      key: range.key,
      start: range.start.toISOString(),
      end: range.end.toISOString(),
    },
    budget: {
      id: budget.id,
      name: budget.name,
      purpose: budget.purpose,
      currency: budget.currency || 'TZS',
      budget_limit: toMoneyNumber(budget.budget_limit),
      spent_amount: toMoneyNumber(budget.spent_amount),
      funded_amount: toMoneyNumber(budget.funded_amount),
      remaining_amount: Math.max(0, toMoneyNumber(budget.funded_amount) - toMoneyNumber(budget.spent_amount)),
      period_type: budget.period_type,
      status: budget.status,
    },
    summary: {
      currency: budget.currency || 'TZS',
      total_spent: totalSpent,
      transaction_count: transactions.length,
      member_count: members.length,
      budget_limit: toMoneyNumber(budget.budget_limit),
      funded_amount: toMoneyNumber(budget.funded_amount),
      remaining_amount: Math.max(0, toMoneyNumber(budget.funded_amount) - toMoneyNumber(budget.spent_amount)),
    },
    members: (members || []).map((member: any) => ({
      ...member,
      users: usersById.get(String(member.user_id)) || null,
      period_spent_amount: periodByUser.get(String(member.user_id)) || 0,
    })),
    transactions: (transactions || []).map((transaction: any) => ({
      ...transaction,
      users: usersById.get(String(transaction.member_user_id)) || null,
    })),
    generatedAt: new Date().toISOString(),
    issuer: 'ORBI FINANCIAL TECHNOLOGIES',
  };
};

export const registerSharedBudgetRoutes = (v1: Router, deps: Deps) => {
  const {
    authenticate,
    LogicCore,
    getSupabase,
    getAdminSupabase,
    SharedBudgetCreateSchema,
    SharedBudgetUpdateSchema,
    SharedBudgetMemberAddSchema,
    SharedBudgetAllocateSchema,
    SharedBudgetInviteResponseSchema,
    SharedBudgetApprovalResponseSchema,
    SharedBudgetSpendSchema,
    wealthNumber,
    resolveSharedBudgetMembership,
    canManageSharedBudget,
    canSpendFromSharedBudget,
    canReviewSharedBudgetSpend,
    resolveUserBySharedBudgetIdentifier,
    expireSharedBudgetInvitationIfNeeded,
    executeSharedBudgetSpend,
  } = deps;

  v1.get('/wealth/shared-budgets', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const { data: memberships, error: memberError } = await sb
        .from('shared_budget_members')
        .select('budget_id, role, member_limit, spent_amount')
        .eq('user_id', session.sub)
        .eq('status', 'ACTIVE');
      if (memberError) return res.status(400).json({ success: false, error: memberError.message });

      const memberBudgetIds = Array.from(new Set((memberships || []).map((item: any) => String(item.budget_id || '')).filter(Boolean)));
      const { data: ownerBudgets, error: ownerError } = await sb
        .from('shared_budgets')
        .select('*')
        .eq('owner_user_id', session.sub)
        .order('created_at', { ascending: false });
      if (ownerError) return res.status(400).json({ success: false, error: ownerError.message });

      let memberBudgets: any[] = [];
      if (memberBudgetIds.length > 0) {
        const { data: memberRows, error: memberBudgetError } = await sb
          .from('shared_budgets')
          .select('*')
          .in('id', memberBudgetIds)
          .order('created_at', { ascending: false });
        if (memberBudgetError) return res.status(400).json({ success: false, error: memberBudgetError.message });
        memberBudgets = memberRows || [];
      }

      const membershipByBudget = new Map<string, any>(
        (memberships || []).map((item: any) => [String(item.budget_id), item]),
      );
      const budgetsById = new Map<string, any>();
      for (const budget of [...(ownerBudgets || []), ...memberBudgets]) {
        budgetsById.set(String(budget.id), budget);
      }
      const items = Array.from(budgetsById.values()).map((budget: any) => {
        const isOwner = budget.owner_user_id === session.sub;
        const membership = membershipByBudget.get(String(budget.id));
        const myRole = isOwner ? 'OWNER' : String(membership?.role || 'SPENDER').toUpperCase();
        const memberLimit = membership?.member_limit == null ? null : wealthNumber(membership.member_limit);
        const mySpent = isOwner ? wealthNumber(budget.spent_amount) : wealthNumber(membership?.spent_amount || 0);
        const myRemaining = memberLimit == null ? null : Math.max(0, memberLimit - mySpent);
        return {
          ...budget,
          my_role: myRole,
          is_owner: isOwner,
          member_limit: memberLimit,
          my_spent_amount: mySpent,
          my_remaining_limit: myRemaining,
          funded_amount: wealthNumber(budget.funded_amount),
          spent_amount: wealthNumber(budget.spent_amount),
          remaining_amount: Math.max(0, wealthNumber(budget.funded_amount) - wealthNumber(budget.spent_amount)),
        };
      }).sort((a: any, b: any) => new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime());
      res.json({ success: true, data: { budgets: items } });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/wealth/shared-budgets', authenticate as any, requireIdempotencyKey, async (req, res) => {
    const session = (req as any).session;
    try {
      const payload = SharedBudgetCreateSchema.parse(req.body);
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const idempotencyKey = String(resolveIdempotencyHeader(req)).trim();
      const { data: creation, error } = await sb.rpc('create_shared_budget_v1', {
        p_actor_id: session.sub, p_name: payload.name, p_purpose: payload.purpose || null,
        p_currency: payload.currency?.toUpperCase() || 'TZS', p_budget_limit: payload.budget_limit,
        p_period_type: payload.period_type || 'MONTHLY', p_approval_mode: payload.approval_mode || 'AUTO',
        p_idempotency_key: idempotencyKey, p_metadata: { created_from: 'mobile_app' },
      });
      if (error) return res.status(400).json({ success: false, error: error.message });
      let data = creation?.budget;
      if (!creation?.idempotent && (payload.auto_allocate_enabled || payload.auto_allocate_mode || payload.auto_allocate_amount || payload.auto_allocate_threshold)) {
        const { data: configured, error: configureError } = await sb.from('shared_budgets').update({
          auto_allocate_enabled: payload.auto_allocate_enabled || false,
          auto_allocate_mode: payload.auto_allocate_mode || (payload.auto_allocate_enabled ? 'FIXED' : 'MANUAL'),
          auto_allocate_amount: payload.auto_allocate_amount || 0,
          auto_allocate_threshold: payload.auto_allocate_threshold || 0,
        }).eq('id', data.id).select('*').single();
        if (configureError) return res.status(400).json({ success: false, error: configureError.message });
        data = configured;
      }
      if (payload.auto_allocate_enabled) {
        const autoMode = payload.auto_allocate_mode || 'FIXED';
        await sb.from('allocation_rules').insert({
          user_id: session.sub,
          name: `Auto allocate to ${data.name}`,
          trigger_type: 'DEPOSIT',
          source_wallet_id: null,
          target_type: 'BUDGET',
          target_id: data.id,
          mode: autoMode,
          fixed_amount: autoMode === 'FIXED' ? payload.auto_allocate_amount || 0 : null,
          percentage: autoMode === 'PERCENT' ? payload.auto_allocate_amount || 0 : null,
          priority: 10,
          is_active: true,
          metadata: {
            created_from: 'shared_budget_auto_allocate',
            shared_budget_id: data.id,
            threshold: payload.auto_allocate_threshold || 0,
          },
        });
      }
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.patch('/wealth/shared-budgets/:id', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const payload = SharedBudgetUpdateSchema.parse(req.body);
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const { membership } = await resolveSharedBudgetMembership(sb, req.params.id, session.sub);
      if (!canManageSharedBudget(String(membership.role || ''))) {
        return res.status(403).json({ success: false, error: 'SHARED_BUDGET_ACCESS_DENIED' });
      }
      const updatePayload: any = { updated_at: new Date().toISOString() };
      if (payload.name !== undefined) updatePayload.name = payload.name;
      if (payload.purpose !== undefined) updatePayload.purpose = payload.purpose;
      if (payload.currency !== undefined) updatePayload.currency = payload.currency.toUpperCase();
      if (payload.budget_limit !== undefined) updatePayload.budget_limit = payload.budget_limit;
      if (payload.auto_allocate_enabled !== undefined) updatePayload.auto_allocate_enabled = payload.auto_allocate_enabled;
      if (payload.auto_allocate_mode !== undefined) updatePayload.auto_allocate_mode = payload.auto_allocate_mode;
      if (payload.auto_allocate_amount !== undefined) updatePayload.auto_allocate_amount = payload.auto_allocate_amount;
      if (payload.auto_allocate_threshold !== undefined) updatePayload.auto_allocate_threshold = payload.auto_allocate_threshold;
      if (payload.period_type !== undefined) updatePayload.period_type = payload.period_type;
      if (payload.approval_mode !== undefined) updatePayload.approval_mode = payload.approval_mode;
      if (payload.status !== undefined) updatePayload.status = payload.status;
      const { data, error } = await sb
        .from('shared_budgets')
        .update(updatePayload)
        .eq('id', req.params.id)
        .select('*')
        .single();
      if (error) return res.status(400).json({ success: false, error: error.message });
      if (
        payload.auto_allocate_enabled !== undefined ||
        payload.auto_allocate_mode !== undefined ||
        payload.auto_allocate_amount !== undefined ||
        payload.auto_allocate_threshold !== undefined
      ) {
        const autoMode = payload.auto_allocate_mode || data.auto_allocate_mode || 'FIXED';
        const { data: existingRule } = await sb
          .from('allocation_rules')
          .select('id')
          .eq('user_id', session.sub)
          .eq('target_type', 'BUDGET')
          .eq('target_id', data.id)
          .eq('metadata->>created_from', 'shared_budget_auto_allocate')
          .maybeSingle();
        const rulePayload = {
          user_id: session.sub,
          name: `Auto allocate to ${data.name}`,
          trigger_type: 'DEPOSIT',
          source_wallet_id: null,
          target_type: 'BUDGET',
          target_id: data.id,
          mode: autoMode,
          fixed_amount: autoMode === 'FIXED' ? data.auto_allocate_amount || 0 : null,
          percentage: autoMode === 'PERCENT' ? data.auto_allocate_amount || 0 : null,
          priority: 10,
          is_active: data.auto_allocate_enabled === true,
          metadata: {
            created_from: 'shared_budget_auto_allocate',
            shared_budget_id: data.id,
            threshold: data.auto_allocate_threshold || 0,
          },
        };
        if (existingRule?.id) {
          await sb.from('allocation_rules').update(rulePayload).eq('id', existingRule.id);
        } else if (data.auto_allocate_enabled === true) {
          await sb.from('allocation_rules').insert(rulePayload);
        }
      }
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(e.message === 'SHARED_BUDGET_ACCESS_DENIED' ? 403 : 400).json({ success: false, error: e.message });
    }
  });

  v1.post('/wealth/shared-budgets/:id/allocate', authenticate as any, requireIdempotencyKey, async (req, res) => {
    const session = (req as any).session;
    try {
      const payload = {
        ...SharedBudgetAllocateSchema.parse(req.body),
        idempotencyKey: String(resolveIdempotencyHeader(req)).trim(),
      };
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const budgetId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
      const { budget, membership } = await resolveSharedBudgetMembership(sb, budgetId, session.sub);
      if (!canManageSharedBudget(String(membership.role || ''))) {
        return res.status(403).json({ success: false, error: 'SHARED_BUDGET_ALLOCATE_DENIED' });
      }

      const { sourceRecord, sourceTable } = await resolveOperatingWealthWalletStrict(
        sb,
        session.sub,
        payload.source_wallet_id || undefined,
      );
      const amount = wealthNumber(payload.amount);
      const currency = String(payload.currency || budget.currency || sourceRecord.currency || 'TZS').toUpperCase();
      const currentFunded = wealthNumber(budget.funded_amount || 0);
      const budgetLimit = wealthNumber(budget.budget_limit || 0);
      if (budgetLimit > 0 && currentFunded + amount > budgetLimit) {
        return res.status(400).json({ success: false, error: 'SHARED_BUDGET_ALLOCATION_LIMIT_EXCEEDED' });
      }

      const reference = `budget_alloc_${payload.idempotencyKey}`;
      const { data, error } = await sb.rpc('shared_budget_allocate_v1', {
        p_user_id: session.sub,
        p_budget_id: budget.id,
        p_source_wallet_id: sourceRecord.id,
        p_amount: amount,
        p_currency: currency,
        p_description: payload.note || `Mezani allocation: ${budget.name}`,
        p_reference_id: reference,
        p_metadata: {
          shared_budget_id: budget.id,
          shared_budget_name: budget.name,
          source_table: sourceTable,
          source_wallet_role: sourceRecord.vault_role || sourceRecord.type || null,
          allocation_origin: 'MEZANI_ALLOCATE_FUNDS',
        },
      });
      if (error) return res.status(400).json({ success: false, error: error.message });

      const txId = data?.transaction_id || null;
      let transaction = null;
      if (txId) {
        const { data: tx } = await sb
          .from('transactions')
          .select('*')
          .eq('id', txId)
          .maybeSingle();
        transaction = tx || null;
      }

      const { data: budgetTx, error: budgetTxError } = await sb
        .from('shared_budget_transactions')
        .insert({
          shared_budget_id: budget.id,
          member_user_id: session.sub,
          source_wallet_id: sourceRecord.id,
          transaction_id: txId,
          merchant_name: 'Mezani',
          provider: 'ORBI_INTERNAL',
          category: 'ALLOCATION',
          amount,
          currency,
          status: 'COMPLETED',
          note: payload.note || 'Funds allocated to Mezani',
          metadata: {
            allocation_source: 'OPERATING_WALLET',
            allocation_destination: 'SHARED_BUDGET_RESERVE',
            reference_id: reference,
          },
        })
        .select('*')
        .single();
      if (budgetTxError) return res.status(400).json({ success: false, error: budgetTxError.message });

      res.json({
        success: true,
        data: {
          transaction,
          budget_transaction: budgetTx,
          shared_budget: {
            ...budget,
            funded_amount: Number(data?.budget_funded_after ?? currentFunded + amount),
            remaining_amount: Math.max(0, Number(data?.budget_available_after ?? currentFunded + amount - wealthNumber(budget.spent_amount))),
          },
          source_balance: Number(data?.source_balance_after ?? sourceRecord.balance),
          idempotent: Boolean(data?.idempotent),
        },
      });
    } catch (e: any) {
      res.status(e.message === 'SHARED_BUDGET_ACCESS_DENIED' ? 403 : 400).json({ success: false, error: e.message });
    }
  });

  v1.get('/wealth/shared-budgets/:id/members', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const { budget, membership } = await resolveSharedBudgetMembership(sb, req.params.id, session.sub);
      if (!canManageSharedBudget(String(membership.role || ''))) {
        return res.status(403).json({ success: false, error: 'SHARED_BUDGET_ACCESS_DENIED' });
      }
      const { data, error } = await sb
        .from('shared_budget_members')
        .select('id,budget_id,user_id,role,status,member_limit,spent_amount,metadata,created_at')
        .eq('budget_id', budget.id)
        .eq('status', 'ACTIVE')
        .order('created_at', { ascending: true });
      if (error) return res.status(400).json({ success: false, error: error.message });
      const usersById = await fetchUsersById(sb, compactIds(data || [], 'user_id'));
      const members = (data || []).map((member: any) => ({
        ...member,
        users: usersById.get(String(member.user_id)) || null,
      }));
      res.json({ success: true, data: { members } });
    } catch (e: any) {
      res.status(e.message === 'SHARED_BUDGET_ACCESS_DENIED' ? 403 : 400).json({ success: false, error: e.message });
    }
  });

  v1.delete('/wealth/shared-budgets/:id/members/:memberId', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const { budget, membership } = await resolveSharedBudgetMembership(sb, req.params.id, session.sub);
      if (!canManageSharedBudget(String(membership.role || ''))) {
        return res.status(403).json({ success: false, error: 'SHARED_BUDGET_MEMBER_REMOVE_DENIED' });
      }
      const { data: member, error: memberError } = await sb
        .from('shared_budget_members')
        .select('*')
        .eq('id', req.params.memberId)
        .eq('budget_id', budget.id)
        .maybeSingle();
      if (memberError) return res.status(400).json({ success: false, error: memberError.message });
      if (!member) return res.status(404).json({ success: false, error: 'SHARED_BUDGET_MEMBER_NOT_FOUND' });
      if (String(member.user_id) === String(budget.owner_user_id)) {
        return res.status(400).json({ success: false, error: 'SHARED_BUDGET_OWNER_CANNOT_BE_REMOVED' });
      }
      if (String(member.user_id) === String(session.sub)) {
        return res.status(400).json({ success: false, error: 'SHARED_BUDGET_SELF_REMOVE_DENIED' });
      }
      const { data, error } = await sb
        .from('shared_budget_members')
        .update({
          status: 'REMOVED',
          metadata: {
            ...(member.metadata || {}),
            removed_by: session.sub,
            removed_at: new Date().toISOString(),
          },
          updated_at: new Date().toISOString(),
        })
        .eq('id', member.id)
        .select('*')
        .single();
      if (error) return res.status(400).json({ success: false, error: error.message });
      try {
        await Messaging.dispatch(
          budget.owner_user_id,
          'info',
          'Mezani member updated',
          `A member was removed from ${budget.name}.`,
          { push: true, eventCode: 'SHARED_BUDGET_MEMBER_REMOVED', metadata: { budgetId: budget.id, memberId: data.id, removedUserId: member.user_id } },
        );
      } catch (notifyError) {
        console.warn('[Wealth][SharedBudget] Member removal notification failed', notifyError);
      }
      res.json({ success: true, data: { member: data } });
    } catch (e: any) {
      res.status(e.message === 'SHARED_BUDGET_ACCESS_DENIED' ? 403 : 400).json({ success: false, error: e.message });
    }
  });

  v1.post('/wealth/shared-budgets/:id/leave', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const { budget, membership } = await resolveSharedBudgetMembership(sb, req.params.id, session.sub);
      if (String(membership.role || '').toUpperCase() === 'OWNER' || String(budget.owner_user_id) === String(session.sub)) {
        return res.status(400).json({ success: false, error: 'SHARED_BUDGET_OWNER_CANNOT_LEAVE' });
      }
      const { data, error } = await sb
        .from('shared_budget_members')
        .update({
          status: 'LEFT',
          metadata: {
            ...(membership.metadata || {}),
            left_by: session.sub,
            left_at: new Date().toISOString(),
          },
          updated_at: new Date().toISOString(),
        })
        .eq('id', membership.id)
        .select('*')
        .single();
      if (error) return res.status(400).json({ success: false, error: error.message });
      try {
        await Messaging.dispatch(
          budget.owner_user_id,
          'info',
          'Mezani member left',
          `A member left ${budget.name}.`,
          { push: true, eventCode: 'SHARED_BUDGET_MEMBER_LEFT', metadata: { budgetId: budget.id, memberId: data.id, userId: session.sub } },
        );
      } catch (notifyError) {
        console.warn('[Wealth][SharedBudget] Member leave notification failed', notifyError);
      }
      res.json({ success: true, data: { member: data } });
    } catch (e: any) {
      res.status(e.message === 'SHARED_BUDGET_ACCESS_DENIED' ? 403 : 400).json({ success: false, error: e.message });
    }
  });

  v1.get('/wealth/shared-budgets/:id/transactions', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const { budget, membership } = await resolveSharedBudgetMembership(sb, req.params.id, session.sub);
      let query = sb
        .from('shared_budget_transactions')
        .select('*')
        .eq('shared_budget_id', budget.id);
      if (!canManageSharedBudget(String(membership.role || ''))) {
        query = query.eq('member_user_id', session.sub);
      }
      const { data, error } = await query.order('created_at', { ascending: false });
      if (error) return res.status(400).json({ success: false, error: error.message });
      const usersById = await fetchUsersById(sb, compactIds(data || [], 'member_user_id'));
      const transactions = (data || []).map((transaction: any) => ({
        ...transaction,
        users: usersById.get(String(transaction.member_user_id)) || null,
      }));
      res.json({ success: true, data: { transactions } });
    } catch (e: any) {
      res.status(e.message === 'SHARED_BUDGET_ACCESS_DENIED' ? 403 : 400).json({ success: false, error: e.message });
    }
  });

  v1.get('/wealth/shared-budgets/:id/report', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    const range = resolveReportRange(req.query.range);
    try {
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const { budget, membership } = await resolveSharedBudgetMembership(sb, req.params.id, session.sub);
      if (!canManageSharedBudget(String(membership.role || ''))) {
        return res.status(403).json({ success: false, error: 'SHARED_BUDGET_ACCESS_DENIED' });
      }

      const { data: memberRows, error: memberError } = await sb
        .from('shared_budget_members')
        .select('id,budget_id,user_id,role,status,member_limit,spent_amount,metadata,created_at')
        .eq('budget_id', budget.id)
        .eq('status', 'ACTIVE')
        .order('created_at', { ascending: true });
      if (memberError) return res.status(400).json({ success: false, error: memberError.message });

      const { data: transactionRows, error: transactionError } = await sb
        .from('shared_budget_transactions')
        .select('*')
        .eq('shared_budget_id', budget.id)
        .gte('created_at', range.start.toISOString())
        .lte('created_at', range.end.toISOString())
        .order('created_at', { ascending: false });
      if (transactionError) return res.status(400).json({ success: false, error: transactionError.message });

      const userIds = Array.from(new Set([
        ...compactIds(memberRows || [], 'user_id'),
        ...compactIds(transactionRows || [], 'member_user_id'),
      ]));
      const usersById = await fetchUsersById(sb, userIds);
      res.json({
        success: true,
        data: buildSharedBudgetReport(budget, memberRows || [], transactionRows || [], usersById, range),
      });
    } catch (e: any) {
      res.status(e.message === 'SHARED_BUDGET_ACCESS_DENIED' ? 403 : 400).json({ success: false, error: e.message });
    }
  });

  v1.get('/wealth/shared-budgets/:id/invitations', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const { budget, membership } = await resolveSharedBudgetMembership(sb, req.params.id, session.sub);
      if (!canManageSharedBudget(String(membership.role || ''))) {
        return res.status(403).json({ success: false, error: 'SHARED_BUDGET_ACCESS_DENIED' });
      }
      const { data, error } = await sb
        .from('shared_budget_invitations')
        .select('id,budget_id,inviter_user_id,invitee_user_id,invitee_identifier,role,member_limit,status,message,responded_at,expires_at,metadata,created_at')
        .eq('budget_id', budget.id)
        .order('created_at', { ascending: false });
      if (error) return res.status(400).json({ success: false, error: error.message });
      const usersById = await fetchUsersById(sb, compactIds(data || [], 'invitee_user_id'));
      const invitations = (data || []).map((invite: any) => ({
        ...invite,
        users: usersById.get(String(invite.invitee_user_id)) || null,
      }));
      res.json({ success: true, data: { invitations } });
    } catch (e: any) {
      res.status(e.message === 'SHARED_BUDGET_ACCESS_DENIED' ? 403 : 400).json({ success: false, error: e.message });
    }
  });

  v1.get('/wealth/shared-budget-invitations', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const { data, error } = await sb
        .from('shared_budget_invitations')
        .select('id,budget_id,inviter_user_id,invitee_user_id,invitee_identifier,role,member_limit,status,message,responded_at,expires_at,metadata,created_at')
        .eq('invitee_user_id', session.sub)
        .order('created_at', { ascending: false });
      if (error) return res.status(400).json({ success: false, error: error.message });
      const budgetsById = await fetchSharedBudgetsById(sb, compactIds(data || [], 'budget_id'));
      const usersById = await fetchUsersById(sb, compactIds(data || [], 'inviter_user_id'));
      const invitations = [];
      for (const invite of data || []) {
        invitations.push(await expireSharedBudgetInvitationIfNeeded(sb, {
          ...invite,
          shared_budgets: budgetsById.get(String(invite.budget_id)) || null,
          users: usersById.get(String(invite.inviter_user_id)) || null,
        }));
      }
      res.json({ success: true, data: { invitations } });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.post('/wealth/shared-budgets/:id/invitations', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const payload = SharedBudgetMemberAddSchema.parse(req.body);
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const { budget, membership } = await resolveSharedBudgetMembership(sb, req.params.id, session.sub);
      if (!canManageSharedBudget(String(membership.role || ''))) {
        return res.status(403).json({ success: false, error: 'SHARED_BUDGET_ACCESS_DENIED' });
      }
      const verifiedInviteeUserId = String(
        payload.invitee_user_id ||
        payload.inviteeUserId ||
        payload.recipient_id ||
        payload.recipientId ||
        '',
      ).trim();
      const memberUser = verifiedInviteeUserId
        ? await resolveUserBySharedBudgetIdentifier(sb, verifiedInviteeUserId)
        : await resolveUserBySharedBudgetIdentifier(sb, payload.identifier);
      if (!memberUser?.id) {
        return res.status(404).json({ success: false, error: 'USER_NOT_FOUND' });
      }
      if (String(memberUser.id) === String(budget.owner_user_id)) {
        return res.status(400).json({ success: false, error: 'OWNER_ALREADY_MEMBER' });
      }
      const { data: existingMember, error: existingMemberError } = await sb
        .from('shared_budget_members')
        .select('id,status')
        .eq('budget_id', budget.id)
        .eq('user_id', memberUser.id)
        .maybeSingle();
      if (existingMemberError) return res.status(400).json({ success: false, error: existingMemberError.message });
      if (String(existingMember?.status || '').toUpperCase() === 'ACTIVE') {
        return res.status(400).json({ success: false, error: 'SHARED_BUDGET_MEMBER_ALREADY_EXISTS' });
      }
      const { data: pendingInvite, error: pendingInviteError } = await sb
        .from('shared_budget_invitations')
        .select('*')
        .eq('budget_id', budget.id)
        .eq('invitee_user_id', memberUser.id)
        .eq('status', 'PENDING')
        .order('created_at', { ascending: false })
        .limit(1)
        .maybeSingle();
      if (pendingInviteError) {
        return res.status(400).json({ success: false, error: pendingInviteError.message });
      }
      if (pendingInvite) {
        return res.status(400).json({ success: false, error: 'SHARED_BUDGET_INVITE_ALREADY_PENDING' });
      }

      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
      const { data, error } = await sb
        .from('shared_budget_invitations')
        .insert({
          budget_id: budget.id,
          inviter_user_id: session.sub,
          invitee_user_id: memberUser.id,
          invitee_identifier: payload.identifier,
          role: payload.role || 'SPENDER',
          member_limit: payload.member_limit || null,
          message: payload.message || null,
          expires_at: expiresAt,
          metadata: {
            invited_by: session.sub,
            invite_source: 'shared_budget_member_sheet',
            identifier: payload.identifier,
          },
        })
        .select('id,budget_id,inviter_user_id,invitee_user_id,invitee_identifier,role,member_limit,status,message,responded_at,expires_at,metadata,created_at')
        .single();
      if (error) return res.status(400).json({ success: false, error: error.message });

      await Messaging.dispatch(
        String(memberUser.id),
        'info',
        'Shared budget invitation',
        `${session.user?.user_metadata?.full_name || 'A member'} invited you to join "${budget.name}" as ${String(payload.role || 'SPENDER').toLowerCase()}.`,
        {
          push: true,
          sms: true,
          email: true,
          mandatory: true,
          systemCustomBypass: true,
          eventCode: 'SHARED_BUDGET_INVITATION',
          idempotencyKey: `SHARED_BUDGET_INVITATION:${data.id}`,
          variables: {
            budget_name: budget.name,
            role: payload.role || 'SPENDER',
            invite_id: data.id,
          },
        },
      );

      res.json({ success: true, data: { invitation: data } });
    } catch (e: any) {
      res.status(e.message === 'SHARED_BUDGET_ACCESS_DENIED' ? 403 : 400).json({ success: false, error: e.message });
    }
  });

  v1.post('/wealth/shared-budget-invitations/:id/respond', authenticate as any, requireIdempotencyKey, async (req, res) => {
    const session = (req as any).session;
    try {
      const payload = SharedBudgetInviteResponseSchema.parse(req.body);
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });

      const { data, error } = await sb.rpc('respond_shared_budget_invitation_v1', {
        p_actor_id: session.sub, p_invitation_id: req.params.id, p_action: payload.action,
        p_idempotency_key: String(resolveIdempotencyHeader(req)).trim(),
      });
      if (error) return res.status(400).json({ success: false, error: error.message });
      res.json({ success: true, data });
    } catch (e: any) {
      const status = e.message === 'SHARED_BUDGET_INVITE_ACCESS_DENIED' ? 403 : 400;
      res.status(status).json({ success: false, error: e.message });
    }
  });

  v1.get('/wealth/shared-budgets/:id/approvals', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const { budget, membership } = await resolveSharedBudgetMembership(sb, req.params.id, session.sub);
      if (!canReviewSharedBudgetSpend(String(membership.role || ''))) {
        return res.status(403).json({ success: false, error: 'SHARED_BUDGET_ACCESS_DENIED' });
      }
      const { data, error } = await sb
        .from('shared_budget_approvals')
        .select('*')
        .eq('shared_budget_id', budget.id)
        .order('created_at', { ascending: false });
      if (error) return res.status(400).json({ success: false, error: error.message });
      const usersById = await fetchUsersById(sb, Array.from(new Set([
        ...compactIds(data || [], 'requester_user_id'),
        ...compactIds(data || [], 'reviewer_user_id'),
      ])));
      const approvals = (data || []).map((approval: any) => ({
        ...approval,
        users: usersById.get(String(approval.requester_user_id)) || null,
        reviewer: usersById.get(String(approval.reviewer_user_id)) || null,
      }));
      res.json({ success: true, data: { approvals } });
    } catch (e: any) {
      const status = e.message === 'SHARED_BUDGET_ACCESS_DENIED' ? 403 : 400;
      res.status(status).json({ success: false, error: e.message });
    }
  });

  v1.post('/wealth/shared-budget-approvals/:id/respond', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const payload = SharedBudgetApprovalResponseSchema.parse(req.body);
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });

      const { data: approval, error: approvalError } = await sb
        .from('shared_budget_approvals')
        .select('*')
        .eq('id', req.params.id)
        .maybeSingle();
      if (approvalError) return res.status(400).json({ success: false, error: approvalError.message });
      if (!approval) return res.status(404).json({ success: false, error: 'SHARED_BUDGET_APPROVAL_NOT_FOUND' });
      const { budget, membership } = await resolveSharedBudgetMembership(sb, approval.shared_budget_id, session.sub);
      if (!canReviewSharedBudgetSpend(String(membership.role || ''))) {
        return res.status(403).json({ success: false, error: 'SHARED_BUDGET_ACCESS_DENIED' });
      }

      const { data: claim, error: claimError } = await sb.rpc('claim_shared_budget_approval_v1', {
        p_reviewer_id: session.sub, p_approval_id: approval.id, p_action: payload.action,
      });
      if (claimError) return res.status(400).json({ success: false, error: claimError.message });
      if (payload.action === 'REJECT') return res.json({ success: true, data: claim });

      const requesterMembershipResult = await resolveSharedBudgetMembership(
        sb,
        approval.shared_budget_id,
        String(approval.requester_user_id),
      );

      const approvalMetadata = approval.metadata && typeof approval.metadata === 'object'
        ? approval.metadata
        : {};

      const spendPayload = {
        idempotencyKey: String(approval.id),
        idempotency_key: String(approval.id),
        source_wallet_id: approvalMetadata.source_wallet_id || null,
        amount: wealthNumber(approval.amount),
        currency: approval.currency || budget.currency || 'TZS',
        provider: approval.provider || null,
        bill_category: approval.bill_category || null,
        reference: approval.reference || null,
        description: approval.note || null,
        type: approvalMetadata.type || 'EXTERNAL_PAYMENT',
        metadata: {
          ...approvalMetadata,
          approval_reviewer_user_id: session.sub,
          approval_reviewer_role: membership.role || 'MANAGER',
          approval_response_note: payload.note || null,
        },
      };

      let spendData: any;
      try {
        spendData = await executeSharedBudgetSpend(sb, {
          budget,
          membership: requesterMembershipResult.membership,
          actorUserId: String(approval.requester_user_id),
          actorUser: { ...(session.user || {}), id: String(approval.requester_user_id) },
          payload: spendPayload,
          approvalId: approval.id,
        });
      } catch (spendError: any) {
        await sb.rpc('finish_shared_budget_approval_v1', {
          p_reviewer_id: session.sub, p_approval_id: approval.id, p_status: 'FAILED',
          p_transaction_id: null, p_error: String(spendError?.message || spendError),
        });
        throw spendError;
      }
      await notifySharedBudgetSpend(
        sb,
        budget,
        String(approval.requester_user_id),
        spendData,
        approval.amount,
        approvalMetadata.type || 'EXTERNAL_PAYMENT',
        { approvedByUserId: session.sub },
      );

      const transactionId = (spendData as any)?.transaction?.internalId || (spendData as any)?.transaction?.id || null;
      const { data: updatedApproval, error: approvalUpdateError } = await sb.rpc('finish_shared_budget_approval_v1', {
        p_reviewer_id: session.sub, p_approval_id: approval.id, p_status: 'APPROVED',
        p_transaction_id: transactionId, p_error: null,
      });
      if (approvalUpdateError) return res.status(400).json({ success: false, error: approvalUpdateError.message });

      res.json({ success: true, data: { approval: updatedApproval, ...spendData } });
    } catch (e: any) {
      const status = e.message === 'SHARED_BUDGET_ACCESS_DENIED' ? 403 : 400;
      res.status(status).json({ success: false, error: e.message });
    }
  });

  v1.post('/wealth/shared-budgets/:id/spend/preview', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const payload = SharedBudgetSpendSchema.parse(req.body);
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const budgetId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
      const { budget, membership } = await resolveSharedBudgetMembership(sb, budgetId, session.sub);
      if (!canSpendFromSharedBudget(String(membership.role || ''))) {
        return res.status(403).json({ success: false, error: 'SHARED_BUDGET_SPEND_DENIED' });
      }
      const currentSpent = wealthNumber(budget.spent_amount);
      const budgetLimit = wealthNumber(budget.budget_limit);
      const fundedAmount = wealthNumber(budget.funded_amount || 0);
      const fundedAvailable = Math.max(0, fundedAmount - currentSpent);
      if (currentSpent + payload.amount > budgetLimit) {
        return res.status(400).json({ success: false, error: 'SHARED_BUDGET_LIMIT_EXCEEDED' });
      }
      if (payload.amount > fundedAvailable) {
        return res.status(400).json({ success: false, error: 'SHARED_BUDGET_FUNDS_REQUIRED' });
      }
      const memberSpent = wealthNumber(membership.spent_amount || 0);
      const memberLimit = payload.amount + memberSpent;
      if (membership.member_limit && memberLimit > wealthNumber(membership.member_limit)) {
        return res.status(400).json({ success: false, error: 'SHARED_BUDGET_MEMBER_LIMIT_EXCEEDED' });
      }

      const { sourceRecord, sourceTable } = await resolveOperatingWealthWalletStrict(
        sb,
        session.sub,
        payload.source_wallet_id || undefined,
      );
      const spendType = String(payload.type || 'EXTERNAL_PAYMENT').trim().toUpperCase();
      const isWithdrawalIntent = [
        'SHARED_BUDGET_WITHDRAWAL_TO_ACCOUNT',
        'SHARED_BUDGET_AGENT_CASHOUT',
      ].includes(spendType);
      const withdrawalDestination = spendType === 'SHARED_BUDGET_AGENT_CASHOUT'
        ? 'ORBI_AGENT'
        : spendType === 'SHARED_BUDGET_WITHDRAWAL_TO_ACCOUNT'
          ? 'OPERATING_WALLET'
          : null;

      if (isWithdrawalIntent) {
        return res.json({
          success: true,
          data: {
            preview: {
              success: true,
              type: spendType,
              amount: payload.amount,
              currency: (payload.currency || budget.currency || 'TZS').toUpperCase(),
              destination: withdrawalDestination,
              advisory: withdrawalDestination === 'ORBI_AGENT'
                ? 'Funds will be marked as withdrawn from this Mezani and prepared for ORBI Agent cash-out audit.'
                : 'Funds will be marked as withdrawn from this Mezani to your ORBI account audit trail.',
            },
            budget: {
              ...budget,
              funded_amount: fundedAmount,
              remaining_amount: Math.max(0, fundedAvailable - payload.amount),
            },
            member: {
              ...membership,
              remaining_member_limit: membership.member_limit
                ? Math.max(0, wealthNumber(membership.member_limit) - memberSpent - payload.amount)
                : null,
            },
          },
        });
      }

      const result = await LogicCore.getTransactionPreview(session.sub, {
        sourceWalletId: sourceRecord.id,
        recipientId: payload.provider,
        amount: payload.amount,
        currency: (payload.currency || budget.currency || 'TZS').toUpperCase(),
        description: payload.description || `${budget.name} spend`,
        type: spendType,
        metadata: {
          ...(payload.metadata || {}),
          shared_budget_id: budget.id,
          shared_budget_name: budget.name,
          shared_budget_role: membership.role || 'SPENDER',
          bill_provider: payload.provider || null,
          bill_category: payload.bill_category || null,
          bill_reference: payload.reference || null,
          shared_budget_preview: true,
          spend_origin: 'SHARED_BUDGET',
          spend_type: spendType,
          source_wallet_id: sourceRecord.id,
          source_wallet_table: sourceTable,
          source_wallet_role: sourceRecord.vault_role || sourceRecord.type || null,
        },
      });
      if (!result.success) return res.status(400).json(result);
      res.json({
        success: true,
        data: {
          preview: result,
          budget: {
            ...budget,
            funded_amount: fundedAmount,
            remaining_amount: Math.max(0, fundedAvailable - payload.amount),
          },
          member: {
            ...membership,
            remaining_member_limit: membership.member_limit
              ? Math.max(0, wealthNumber(membership.member_limit) - memberSpent - payload.amount)
              : null,
          },
        },
      });
    } catch (e: any) {
      const status = e.message === 'SHARED_BUDGET_SPEND_DENIED' ? 403 : 400;
      res.status(status).json({ success: false, error: e.message });
    }
  });

  v1.post('/wealth/shared-budgets/:id/spend/settle', authenticate as any, requireIdempotencyKey, async (req, res) => {
    const session = (req as any).session;
    try {
      const payload = {
        ...SharedBudgetSpendSchema.parse(req.body),
        idempotencyKey: String(resolveIdempotencyHeader(req)).trim(),
      };
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const budgetId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
      const { budget, membership } = await resolveSharedBudgetMembership(sb, budgetId, session.sub);
      if (!canSpendFromSharedBudget(String(membership.role || ''))) {
        return res.status(403).json({ success: false, error: 'SHARED_BUDGET_SPEND_DENIED' });
      }
      const currentSpent = wealthNumber(budget.spent_amount);
      const budgetLimit = wealthNumber(budget.budget_limit);
      const fundedAmount = wealthNumber(budget.funded_amount || 0);
      const fundedAvailable = Math.max(0, fundedAmount - currentSpent);
      if (currentSpent + payload.amount > budgetLimit) {
        return res.status(400).json({ success: false, error: 'SHARED_BUDGET_LIMIT_EXCEEDED' });
      }
      if (payload.amount > fundedAvailable) {
        return res.status(400).json({ success: false, error: 'SHARED_BUDGET_FUNDS_REQUIRED' });
      }
      const memberSpent = wealthNumber(membership.spent_amount || 0);
      if (membership.member_limit && memberSpent + payload.amount > wealthNumber(membership.member_limit)) {
        return res.status(400).json({ success: false, error: 'SHARED_BUDGET_MEMBER_LIMIT_EXCEEDED' });
      }
      const { sourceRecord, sourceTable } = await resolveOperatingWealthWalletStrict(
        sb,
        session.sub,
        payload.source_wallet_id || undefined,
      );
      const normalizedPayload = {
        ...payload,
        source_wallet_id: sourceRecord.id,
        metadata: {
          ...(payload.metadata || {}),
          source_wallet_id: sourceRecord.id,
          source_wallet_table: sourceTable,
          source_wallet_role: sourceRecord.vault_role || sourceRecord.type || null,
        },
      };
      if (String(budget.approval_mode || 'AUTO').toUpperCase() === 'REVIEW') {
        const approvalMetadata = {
              ...(normalizedPayload.metadata || {}),
              source_wallet_id: sourceRecord.id,
              type: payload.type || 'EXTERNAL_PAYMENT',
              shared_budget_name: budget.name,
              requester_role: membership.role || 'SPENDER',
              spend_origin: 'SHARED_BUDGET',
              withdrawal_destination: ['SHARED_BUDGET_WITHDRAWAL_TO_ACCOUNT', 'SHARED_BUDGET_AGENT_CASHOUT']
                .includes(String(payload.type || '').trim().toUpperCase())
                ? String(payload.type).trim().toUpperCase() === 'SHARED_BUDGET_AGENT_CASHOUT'
                  ? 'ORBI_AGENT'
                  : 'OPERATING_WALLET'
                : null,
              bill_provider: payload.provider || null,
              bill_category: payload.bill_category || null,
              bill_reference: payload.reference || null,
              preview_required: true,
        };
        const { data: approvalResult, error } = await sb.rpc('request_shared_budget_approval_v1', {
          p_actor_id: session.sub, p_budget_id: budget.id, p_amount: payload.amount,
          p_currency: (payload.currency || budget.currency || 'TZS').toUpperCase(),
          p_provider: payload.provider || null, p_bill_category: payload.bill_category || null,
          p_reference: payload.reference || null, p_note: payload.description || null,
          p_idempotency_key: payload.idempotencyKey, p_metadata: approvalMetadata,
        });
        if (error) return res.status(400).json({ success: false, error: error.message });
        const data = approvalResult?.approval;
        await notifySharedBudgetSpend(sb, budget, session.sub, { approval: data }, payload.amount, payload.type, {
          requiresApproval: true,
        });
        return res.json({ success: true, data: { approval: data, requires_approval: true } });
      }

      const data = await executeSharedBudgetSpend(sb, {
        budget,
        membership,
        actorUserId: session.sub,
        actorUser: session.user,
        payload: normalizedPayload,
      });
      await notifySharedBudgetSpend(sb, budget, session.sub, data, payload.amount, payload.type || 'EXTERNAL_PAYMENT');
      res.json({ success: true, data });
    } catch (e: any) {
      const status = e.message === 'SHARED_BUDGET_SPEND_DENIED' ? 403 : 400;
      res.status(status).json({ success: false, error: e.message });
    }
  });
};
