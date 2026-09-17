import { createHash, createHmac, randomUUID } from 'crypto';
import { type RequestHandler, type Router } from 'express';
import {
  requireIdempotencyKey,
  resolveIdempotencyHeader,
} from '../../middleware/security/idempotency.js';
import { GlobalTimeResolver } from '../../../backend/utils/GlobalTimeResolver.js';
import { TransactionMovementClassifier } from '../../../backend/transactions/movement/TransactionMovementClassifier.js';
import { DataProtection } from '../../../backend/security/DataProtection.js';
import { signLockedFxSnapshot } from '../../../backend/ledger/FXLockedQuote.js';

type Deps = {
  authenticate: RequestHandler;
  authenticateApiKey: RequestHandler;
  validate: (schema: any) => RequestHandler;
  requireRole: (session: any, roles: string[]) => boolean;
  LogicCore: any;
  getSupabase: () => any;
  getAdminSupabase?: () => any;
  PolicyEngine: any;
  FXEngine: any;
  TransactionService: any;
  WalletCreateSchema: any;
  WalletLockSchema: any;
  WalletUnlockSchema: any;
  PaymentIntentSchema: any;
  TransactionIssueSchema: any;
};

const quoteErrorStatus = (message: string) => {
  if (/DB_OFFLINE|UNAVAILABLE/i.test(message)) return 503;
  if (/PLATFORM_FEE_CONFIG_REQUIRED|PROVIDER_ROUTE_NOT_FOUND|NOT_CONFIGURED/i.test(message)) return 409;
  if (/NOT_FOUND|REQUIRED|ACCESS_DENIED|INSUFFICIENT|BLOCK/i.test(message)) return 400;
  return 500;
};

const quoteErrorPayload = (error: any, context: string) => {
  const message = String(error?.message || error || 'TRANSACTION_PREVIEW_FAILED');
  const code = message.split(':')[0] || 'TRANSACTION_PREVIEW_FAILED';
  return {
    success: false,
    error: code,
    message,
    context,
    retryable: quoteErrorStatus(message) >= 500,
  };
};

const firstHeaderValue = (value: unknown): string | undefined => {
  const raw = Array.isArray(value) ? value[0] : value;
  if (typeof raw !== 'string') return undefined;
  const trimmed = raw.trim();
  return trimmed || undefined;
};

const ipGeoFromRequest = (req: any) => {
  const countryCode = firstHeaderValue(req.headers['cf-ipcountry']) ||
    firstHeaderValue(req.headers['x-vercel-ip-country']) ||
    firstHeaderValue(req.headers['x-orbi-ip-country']);
  const region = firstHeaderValue(req.headers['x-vercel-ip-country-region']) ||
    firstHeaderValue(req.headers['x-orbi-ip-region']);
  const city = firstHeaderValue(req.headers['x-vercel-ip-city']) ||
    firstHeaderValue(req.headers['x-orbi-ip-city']);
  const latitude = firstHeaderValue(req.headers['x-vercel-ip-latitude']) ||
    firstHeaderValue(req.headers['x-orbi-ip-latitude']);
  const longitude = firstHeaderValue(req.headers['x-vercel-ip-longitude']) ||
    firstHeaderValue(req.headers['x-orbi-ip-longitude']);

  if (!countryCode && !region && !city && !latitude && !longitude) return null;
  return {
    countryCode: countryCode?.toUpperCase(),
    region,
    city,
    latitude: latitude ? Number(latitude) : undefined,
    longitude: longitude ? Number(longitude) : undefined,
    source: 'ip_geo',
    capturedAt: new Date().toISOString(),
    ipHashAvailable: Boolean(req.ip || req.headers['x-forwarded-for']),
  };
};

const enrichTransactionGeoMetadata = (req: any) => {
  const payload = req.body && typeof req.body === 'object' ? req.body : {};
  const metadata = payload.metadata && typeof payload.metadata === 'object' ? payload.metadata : {};
  const ipGeo = ipGeoFromRequest(req);
  if (!ipGeo || metadata.ipGeo || metadata.ip_geo) return payload;
  req.body = {
    ...payload,
    metadata: {
      ...metadata,
      ipGeo,
    },
  };
  return req.body;
};

const walletCurrencyCode = (value: unknown): string => String(value || '').trim().toUpperCase();

const isIsoCurrencyCode = (value: string): boolean => /^[A-Z]{3}$/.test(value);

const colorForCurrencyWallet = (currency: string): string => {
  const colors: Record<string, string> = {
    TZS: '#06D6A0',
    USD: '#1D4ED8',
    EUR: '#0F766E',
    GBP: '#7C3AED',
    KES: '#F59E0B',
    UGX: '#DC2626',
    RWF: '#0891B2',
  };
  return colors[currency] || '#118AB2';
};

const isSupportedFxCurrency = async (sb: any, currency: string): Promise<boolean> => {
  const [fromRes, toRes] = await Promise.all([
    sb.from('fx_corridors').select('id').eq('status', 'ACTIVE').eq('from_currency', currency).limit(1),
    sb.from('fx_corridors').select('id').eq('status', 'ACTIVE').eq('to_currency', currency).limit(1),
  ]);
  if (fromRes.error) throw fromRes.error;
  if (toRes.error) throw toRes.error;
  return Boolean((fromRes.data || []).length || (toRes.data || []).length);
};

const normalizeCurrencyCode = (value: unknown) =>
  String(value || '').trim().toUpperCase();

const fxQuoteErrorStatus = (code: string) => {
  if (/UNAVAILABLE|DB_OFFLINE/i.test(code)) return 503;
  if (/NOT_CONFIGURED|CONFIG_REQUIRED/i.test(code)) return 409;
  return 400;
};

const fxQuoteErrorPayload = (error: any) => {
  const message = String(error?.message || error || 'FX_QUOTE_FAILED');
  const code = message.split(':')[0] || 'FX_QUOTE_FAILED';
  return {
    success: false,
    error: code,
    message,
    context: 'fx_quote',
    retryable: fxQuoteErrorStatus(code) >= 500,
  };
};

const hashFxQuotePayload = (payload: Record<string, any>) =>
  createHash('sha256').update(JSON.stringify(payload)).digest('hex');

const sortDeep = (value: any): any => {
  if (Array.isArray(value)) return value.map((item) => sortDeep(item));
  if (!value || typeof value !== 'object') return value;
  return Object.keys(value)
    .sort()
    .reduce((acc: Record<string, any>, key) => {
      acc[key] = sortDeep(value[key]);
      return acc;
    }, {});
};

const normalizeNullable = (value: any) => {
  const text = String(value || '').trim();
  return text || null;
};

const parseFxAmount = (value: any) => {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return 0;
  return Math.round(parsed * 100) / 100;
};

const buildFxCanonicalIntent = (payload: Record<string, any>) => sortDeep({
  amount: parseFxAmount(payload.amount),
  currency: normalizeCurrencyCode(payload.currency),
  type: 'FX_CONVERSION',
  description: String(payload.description || '').trim(),
  category: normalizeNullable(payload.category),
  categoryId: normalizeNullable(payload.categoryId ?? payload.category_id ?? payload.metadata?.categoryId ?? payload.metadata?.category_id),
  sourceWalletId: normalizeNullable(payload.sourceWalletId || payload.source_wallet_id || payload.walletId || payload.wallet_id || payload.metadata?.sourceWalletId || payload.metadata?.source_wallet_id),
  targetWalletId: normalizeNullable(payload.targetWalletId || payload.target_wallet_id || payload.metadata?.targetWalletId || payload.metadata?.target_wallet_id),
  recipientId: null,
  recipientCustomerId: null,
  merchantId: null,
  merchantPayNumber: null,
  channel: normalizeNullable(payload.channel || payload.metadata?.channel),
  providerCode: null,
  feeConfigId: null,
  flowCode: null,
  totalDebit: parseFxAmount(payload.amount),
  totalFee: 0,
});

const signFxQuote = (quoteId: string, quoteHash: string, expiresAt: string, userId: string) => {
  const secret = process.env.ORBI_TRANSACTION_QUOTE_SIGNING_SECRET || process.env.JWT_SECRET || process.env.SESSION_SECRET;
  if (!secret) return '';
  return createHmac('sha256', secret)
    .update([quoteId, userId, quoteHash, expiresAt].join('|'))
    .digest('hex');
};

const enrichTransactionTimeMetadata = (req: any) => {
  req.body = {
    ...req.body,
    metadata: GlobalTimeResolver.attachMetadata(
      req.body?.metadata || {},
      GlobalTimeResolver.buildClientContextFromRequest(req.body || {}, req.headers || {}),
    ),
  };
};

type ReportRangeKey = 'week' | 'month' | 'year';

const toMoneyNumber = (value: any): number => {
  const parsed = Number(value || 0);
  return Number.isFinite(parsed) ? parsed : 0;
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

const transactionTimestamp = (transaction: any): Date | null => {
  const raw = transaction?.created_at || transaction?.createdAt || transaction?.date;
  if (!raw) return null;
  const parsed = new Date(raw);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
};

const transactionLedgerSide = (transaction: any): 'CREDIT' | 'DEBIT' | null => {
  const sideText = [
    transaction?.ledger?.entry_side,
    transaction?.ledger?.entry_type,
    transaction?.entry_side,
    transaction?.entry_type,
    transaction?.direction,
    transaction?.metadata?.ledger?.entry_side,
    transaction?.metadata?.entry_side,
  ].map((value) => String(value || '').toUpperCase()).join(' ');

  if (sideText.includes('CREDIT')) return 'CREDIT';
  if (sideText.includes('DEBIT')) return 'DEBIT';

  const signedAmount = Number(
    transaction?.signed_amount ??
    transaction?.signedAmount ??
    transaction?.net_amount ??
    transaction?.netAmount,
  );
  if (Number.isFinite(signedAmount) && signedAmount !== 0) {
    return signedAmount > 0 ? 'CREDIT' : 'DEBIT';
  }

  return null;
};

const transactionReportAmount = (transaction: any): number => {
  const amount = toMoneyNumber(
    transaction?.amount ??
    transaction?.signed_amount ??
    transaction?.signedAmount ??
    transaction?.net_amount ??
    transaction?.netAmount,
  );
  return Math.abs(amount);
};

const transactionBalanceAfter = (transaction: any): number | null => {
  const raw = firstText([
    transaction?.balance_after,
    transaction?.balanceAfter,
    transaction?.available_balance_after,
    transaction?.availableBalanceAfter,
    transaction?.running_balance,
    transaction?.ledger?.balance_after,
    transaction?.metadata?.balance_after,
  ]);
  if (!raw) return null;
  const parsed = Number(raw);
  return Number.isFinite(parsed) ? parsed : null;
};

const movementFamilyOf = (transaction: any): string => String(
  transaction?.movement_family ||
  transaction?.metadata?.movement_family ||
  transaction?.metadata?.movement_classification?.movement_family ||
  '',
).toUpperCase();

const isInternalMoneyMovement = (transaction: any): boolean => {
  return movementFamilyOf(transaction) === 'INTERNAL_SS';
};

const isIncomeSpendingMovement = (transaction: any): boolean => {
  const family = movementFamilyOf(transaction);
  return family === 'INTERNAL_P2P' || family === 'EXTERNAL';
};

const buildTransactionReport = (transactions: any[], range: ReturnType<typeof resolveReportRange>) => {
  const scoped = (transactions || []).filter((transaction: any) => {
    const timestamp = transactionTimestamp(transaction);
    return timestamp ? timestamp >= range.start && timestamp <= range.end : false;
  }).sort((a: any, b: any) => {
    const at = transactionTimestamp(a)?.getTime() || 0;
    const bt = transactionTimestamp(b)?.getTime() || 0;
    return at - bt;
  });

  const summary = scoped.reduce((acc: any, transaction: any) => {
    const amount = transactionReportAmount(transaction);
    const side = transactionLedgerSide(transaction);
    const balanceAfter = transactionBalanceAfter(transaction);
    const previousBalance = acc._last_operating_balance;
    const balanceDelta = balanceAfter !== null && previousBalance !== null
      ? balanceAfter - previousBalance
      : null;
    const reconciledAmount = balanceDelta !== null && balanceDelta !== 0
      ? Math.abs(balanceDelta)
      : amount;
    const reconciledSide = balanceDelta !== null && balanceDelta !== 0
      ? (balanceDelta > 0 ? 'CREDIT' : 'DEBIT')
      : side;

    if (reconciledSide === 'CREDIT') {
      acc.total_credit += reconciledAmount;
      acc.total_in += reconciledAmount;
      acc.money_in += reconciledAmount;
    } else if (reconciledSide === 'DEBIT') {
      acc.total_debit += reconciledAmount;
      acc.total_out += reconciledAmount;
      acc.money_out += reconciledAmount;
    } else {
      acc.unclassified_movements += amount;
      acc.unclassified_movement_count += 1;
    }

    if (isInternalMoneyMovement(transaction)) {
      acc.internal_movements += amount;
      acc.internal_movement_count += 1;
    } else if (isIncomeSpendingMovement(transaction) && reconciledSide === 'CREDIT') {
      acc.external_in += reconciledAmount;
    } else if (isIncomeSpendingMovement(transaction) && reconciledSide === 'DEBIT') {
      acc.external_out += reconciledAmount;
    }
    acc.net = acc.total_credit - acc.total_debit;
    acc.gross_movement += amount;
    acc.transaction_count += 1;
    if (balanceAfter !== null) {
      acc._last_operating_balance = balanceAfter;
    }
    const currency = String(transaction?.currency || 'TZS').toUpperCase();
    acc.currency = acc.currency || currency;
    acc.currencies[currency] = (acc.currencies[currency] || 0) + amount;
    const status = String(transaction?.status || 'UNKNOWN').toUpperCase();
    acc.statuses[status] = (acc.statuses[status] || 0) + 1;
    return acc;
  }, {
    currency: 'TZS',
    total_in: 0,
    total_out: 0,
    total_credit: 0,
    total_debit: 0,
    credit_total: 0,
    debit_total: 0,
    money_in: 0,
    money_out: 0,
    external_in: 0,
    external_out: 0,
    internal_movements: 0,
    internal_movement_count: 0,
    unclassified_movements: 0,
    unclassified_movement_count: 0,
    gross_movement: 0,
    net: 0,
    transaction_count: 0,
    currencies: {},
    statuses: {},
    _last_operating_balance: null,
  });

  summary.credit_total = summary.total_credit;
  summary.debit_total = summary.total_debit;
  delete summary._last_operating_balance;

  return {
    report_type: 'TRANSACTION_HISTORY',
    range: {
      key: range.key,
      start: range.start.toISOString(),
      end: range.end.toISOString(),
    },
    summary,
    transactions: scoped,
    generatedAt: new Date().toISOString(),
    issuer: 'ORBI FINANCIAL TECHNOLOGIES',
  };
};

const sumRows = (rows: any[], fields: string[], currency?: string): number => rows.reduce((total, row) => {
  if (currency && String(row?.currency || currency).toUpperCase() !== currency.toUpperCase()) return total;
  const value = fields.map((field) => row?.[field]).find((item) => item !== undefined && item !== null);
  return total + toMoneyNumber(value);
}, 0);

const safeRows = async (label: string, query: any): Promise<any[]> => {
  try {
    const { data, error } = await query;
    if (error) {
      console.warn(`[Transactions Report] ${label} snapshot skipped:`, error.message);
      return [];
    }
    return Array.isArray(data) ? data : [];
  } catch (error: any) {
    console.warn(`[Transactions Report] ${label} snapshot failed:`, error?.message || error);
    return [];
  }
};

const activeEscrowStatuses = new Set([
  'PENDING',
  'ACCEPTED',
  'HELD',
  'FUNDS_HELD',
  'IN_PROGRESS',
  'DISPUTED',
]);

const buildBalanceSnapshot = async (sb: any, userId: string, currency = 'TZS') => {
  const safeCurrency = String(currency || 'TZS').toUpperCase();
  const wallets = await safeRows(
    'wallets',
    sb.from('wallets')
      .select('id,name,type,management_tier,balance,currency,user_id')
      .eq('user_id', userId),
  );
  const vaults = await safeRows(
    'platform_vaults',
    sb.from('platform_vaults')
      .select('id,name,vault_role,balance,currency,user_id')
      .eq('user_id', userId),
  );
  const goals = await safeRows(
    'goals',
    sb.from('goals')
      .select('id,name,current,currency,status,user_id')
      .eq('user_id', userId),
  );
  const escrows = await safeRows(
    'escrow_agreements',
    sb.from('escrow_agreements')
      .select('id,amount,currency,status,sender_id,receiver_id')
      .or(`sender_id.eq.${userId},receiver_id.eq.${userId}`),
  );
  const potMembers = await safeRows(
    'shared_pot_members',
    sb.from('shared_pot_members').select('pot_id').eq('user_id', userId),
  );
  const potIds = potMembers.map((row) => String(row?.pot_id || '').trim()).filter(Boolean);
  const potsQuery = potIds.length
    ? sb.from('shared_pots')
      .select('id,name,current_amount,currency,status,owner_user_id')
      .or(`owner_user_id.eq.${userId},id.in.(${potIds.join(',')})`)
    : sb.from('shared_pots')
      .select('id,name,current_amount,currency,status,owner_user_id')
      .eq('owner_user_id', userId);
  const pots = await safeRows('shared_pots', potsQuery);
  const budgetMembers = await safeRows(
    'shared_budget_members',
    sb.from('shared_budget_members').select('budget_id').eq('user_id', userId),
  );
  const budgetIds = budgetMembers.map((row) => String(row?.budget_id || '').trim()).filter(Boolean);
  const budgetsQuery = budgetIds.length
    ? sb.from('shared_budgets')
      .select('id,name,budget_limit,spent_amount,currency,status,owner_user_id')
      .or(`owner_user_id.eq.${userId},id.in.(${budgetIds.join(',')})`)
    : sb.from('shared_budgets')
      .select('id,name,budget_limit,spent_amount,currency,status,owner_user_id')
      .eq('owner_user_id', userId);
  const budgets = await safeRows('shared_budgets', budgetsQuery);

  const allWalletLike = [...wallets, ...vaults];
  const restrictedMarker = /(escrow|paysafe|pay safe|budget|goal|pot|fungu|reserve|bill)/i;
  const availableRows = allWalletLike.filter((row) => !restrictedMarker.test([
    row?.name,
    row?.wallet_name,
    row?.vault_name,
    row?.vault_role,
    row?.type,
    row?.wallet_type,
    row?.bucket_type,
  ].join(' ')));
  const availableBalance = sumRows(availableRows, ['available_balance', 'balance'], safeCurrency);
  const walletRestrictedBalance = sumRows(
    allWalletLike.filter((row) => restrictedMarker.test([
      row?.name,
      row?.wallet_name,
      row?.vault_name,
      row?.vault_role,
      row?.type,
      row?.wallet_type,
      row?.bucket_type,
    ].join(' '))),
    ['available_balance', 'balance'],
    safeCurrency,
  );
  const paysafeBalance = sumRows(
    escrows.filter((row) => activeEscrowStatuses.has(String(row?.status || '').toUpperCase())),
    ['amount'],
    safeCurrency,
  );
  const goalsBalance = sumRows(goals, ['current'], safeCurrency);
  const potsBalance = sumRows(pots, ['current_amount'], safeCurrency);
  const budgetsBalance = budgets.reduce((total, row) => {
    if (String(row?.currency || safeCurrency).toUpperCase() !== safeCurrency) return total;
    const limit = toMoneyNumber(row?.budget_limit);
    const spent = toMoneyNumber(row?.spent_amount);
    return total + Math.max(limit - spent, 0);
  }, 0);
  const insideOrbiTotal = availableBalance + walletRestrictedBalance + paysafeBalance + goalsBalance + potsBalance + budgetsBalance;

  return {
    captured_at: new Date().toISOString(),
    currency: safeCurrency,
    main_balance: insideOrbiTotal,
    available_balance: availableBalance,
    inside_orbi_total: insideOrbiTotal,
    paysafe_balance: paysafeBalance,
    escrow_balance: paysafeBalance,
    goals_balance: goalsBalance,
    shared_pots_balance: potsBalance,
    shared_budgets_balance: budgetsBalance,
    other_internal_balance: walletRestrictedBalance,
    breakdown: [
      { key: 'available_balance', label_en: 'Available balance', label_sw: 'Salio linalotumika', amount: availableBalance, currency: safeCurrency },
      { key: 'paysafe_balance', label_en: 'PaySafe / escrow', label_sw: 'PaySafe / escrow', amount: paysafeBalance, currency: safeCurrency },
      { key: 'shared_pots_balance', label_en: 'Fungu pots', label_sw: 'Vifungu', amount: potsBalance, currency: safeCurrency },
      { key: 'shared_budgets_balance', label_en: 'Mezani budgets', label_sw: 'Mezani', amount: budgetsBalance, currency: safeCurrency },
      { key: 'goals_balance', label_en: 'Goals', label_sw: 'Malengo', amount: goalsBalance, currency: safeCurrency },
      { key: 'other_internal_balance', label_en: 'Other internal holds', label_sw: 'Mizania mingine ya ndani', amount: walletRestrictedBalance, currency: safeCurrency },
    ],
  };
};

const transactionIdentity = (transaction: any): string | null => {
  const raw = transaction?.internalId ||
    transaction?.internal_id ||
    transaction?.transaction_id ||
    transaction?.transactionId ||
    transaction?.id ||
    transaction?.reference ||
    transaction?.referenceId ||
    transaction?.transaction_reference;
  const id = String(raw || '').trim();
  return id || null;
};

const firstText = (values: any[]): string | undefined => {
  for (const value of values) {
    const text = String(value || '').trim();
    if (text && text.toLowerCase() !== 'null') return text;
  }
  return undefined;
};

const normalizeWalletName = (wallet: any, fallback?: string): string | undefined => firstText([
  wallet?.wallet_name,
  wallet?.name,
  wallet?.display_name,
  fallback,
]);

const isOperatingWalletRecord = (wallet: any): boolean => {
  const text = [
    wallet?.display_name,
    wallet?.wallet_name,
    wallet?.name,
    wallet?.type,
    wallet?.wallet_type,
    wallet?.bucket_type,
    wallet?.vault_role,
    wallet?.role,
    wallet?.management_tier,
  ].map((value) => String(value || '').toLowerCase()).join(' ');
  if (/(escrow|paysafe|pay safe|goal|saving|budget|mezani|pot|fungu|reserve|bill)/.test(text)) {
    return false;
  }
  return /(operating|main|internal vault|default|dilpesa|spendable|available)/.test(text);
};

const isOperatingLedgerLeg = (leg: any, walletById: Map<string, any>): boolean => {
  const bucket = String(leg?.bucket_type || '').toUpperCase();
  if (bucket && bucket !== 'OPERATING') return false;
  return isOperatingWalletRecord(walletById.get(String(leg?.wallet_id || '')));
};

const pickGeneralReportBalanceLeg = (
  legs: any[],
  userId: string,
  walletById: Map<string, any>,
  transaction?: any,
): any => {
  const ownedLegs = (legs || []).filter((leg: any) => {
    const wallet = walletById.get(String(leg?.wallet_id || ''));
    if (wallet?.user_id) {
      return String(wallet.user_id) === String(userId);
    }
    return String(leg?.user_id || '') === String(userId);
  });
  const operatingLegs = ownedLegs.filter((leg: any) =>
    isOperatingLedgerLeg(leg, walletById),
  );
  const preferredSide = preferredGeneralReportBalanceSide(transaction);
  if (preferredSide) {
    const preferredOperating = operatingLegs
      .filter((leg: any) => String(leg?.entry_side || leg?.entry_type || '').toUpperCase().includes(preferredSide))
      .sort(sortLedgerLegsNewestFirst)[0];
    if (preferredOperating) return preferredOperating;
  }
  return operatingLegs.sort(sortLedgerLegsNewestFirst)[0] || null;
};

const pickReportSourceLeg = (
  legs: any[],
  transaction: any,
  walletById: Map<string, any>,
  userId: string,
): any => {
  const debitLegs = (legs || []).filter((leg: any) =>
    String(leg?.entry_side || leg?.entry_type || '').toUpperCase().includes('DEBIT'),
  );
  const sourceWalletId = String(transaction?.walletId || transaction?.wallet_id || transaction?.source_wallet_id || '').trim();
  if (sourceWalletId) {
    const exact = debitLegs.find((leg: any) => String(leg?.wallet_id || '') === sourceWalletId);
    if (exact) return exact;
  }
  return debitLegs.find((leg: any) =>
    String(walletById.get(String(leg?.wallet_id || ''))?.user_id || leg?.user_id || '') === String(userId) &&
    isOperatingLedgerLeg(leg, walletById),
  ) || debitLegs[0];
};

const pickReportDestinationLeg = (
  legs: any[],
  transaction: any,
  walletById: Map<string, any>,
  userId: string,
): any => {
  const creditLegs = (legs || []).filter((leg: any) =>
    String(leg?.entry_side || leg?.entry_type || '').toUpperCase().includes('CREDIT'),
  );
  const destinationWalletId = String(transaction?.toWalletId || transaction?.to_wallet_id || transaction?.destination_wallet_id || '').trim();
  if (destinationWalletId) {
    const exact = creditLegs.find((leg: any) => String(leg?.wallet_id || '') === destinationWalletId);
    if (exact) return exact;
  }
  return creditLegs.find((leg: any) => {
    const wallet = walletById.get(String(leg?.wallet_id || ''));
    return String(wallet?.user_id || leg?.user_id || '') !== String(userId) &&
      isOperatingLedgerLeg(leg, walletById);
  }) || creditLegs.find((leg: any) => {
    const wallet = walletById.get(String(leg?.wallet_id || ''));
    return !String(wallet?.vault_role || wallet?.name || '').toLowerCase().includes('paysafe');
  }) || creditLegs[0];
};

const preferredGeneralReportBalanceSide = (transaction?: any): 'CREDIT' | 'DEBIT' | null => {
  const text = [
    transaction?.type,
    transaction?.transaction_type,
    transaction?.status,
    transaction?.description,
    transaction?.note,
    transaction?.metadata?.source_wallet_role,
    transaction?.metadata?.target_wallet_role,
    transaction?.metadata?.escrow_status,
  ].map((value) => String(value || '').toLowerCase()).join(' ');
  if (/(refund|refunded|reverse|reversed|deposit|withdrawal|withdraw|target_wallet_role.*operating)/.test(text)) {
    return 'CREDIT';
  }
  if (/(contribution|hold|escrow|paysafe|source_wallet_role.*operating)/.test(text)) {
    return 'DEBIT';
  }
  return null;
};

const sortLedgerLegsNewestFirst = (a: any, b: any): number => {
  const at = new Date(a?.created_at || 0).getTime();
  const bt = new Date(b?.created_at || 0).getTime();
  return bt - at;
};

const enrichTransactionsForReport = async (
  sb: any,
  userId: string,
  transactions: any[],
): Promise<any[]> => {
  const ids = Array.from(new Set(
    transactions
      .map(transactionIdentity)
      .filter((id): id is string => Boolean(id)),
  ));
  if (!ids.length) return transactions;

  try {
    const { data: ledgerRows, error: ledgerError } = await sb
      .from('financial_ledger')
      .select('id,transaction_id,user_id,wallet_id,entry_side,entry_type,amount,balance_after,description,created_at')
      .in('transaction_id', ids);

    if (ledgerError || !Array.isArray(ledgerRows) || ledgerRows.length === 0) {
      if (ledgerError) console.warn('[Transactions Report] ledger enrichment skipped:', ledgerError.message);
      return transactions;
    }

    const walletIds = Array.from(new Set(
      ledgerRows
        .map((row: any) => String(row?.wallet_id || '').trim())
        .filter(Boolean),
    ));

    const walletById = new Map<string, any>();
    if (walletIds.length) {
      const { data: wallets, error: walletError } = await sb
        .from('wallets')
        .select('id,name,type,management_tier,is_primary,user_id')
        .in('id', walletIds);
      if (!walletError && Array.isArray(wallets)) {
        wallets.forEach((wallet: any) => walletById.set(String(wallet.id), wallet));
      } else if (walletError) {
        console.warn('[Transactions Report] wallet enrichment skipped:', walletError.message);
      }

      const { data: vaults, error: vaultError } = await sb
        .from('platform_vaults')
        .select('id,name,vault_role,user_id')
        .in('id', walletIds);
      if (!vaultError && Array.isArray(vaults)) {
        vaults.forEach((vault: any) => walletById.set(String(vault.id), vault));
      } else if (vaultError) {
        console.warn('[Transactions Report] vault enrichment skipped:', vaultError.message);
      }

      const { data: goals, error: goalError } = await sb
        .from('goals')
        .select('id,name,user_id')
        .in('id', walletIds);
      if (!goalError && Array.isArray(goals)) {
        goals.forEach((goal: any) => walletById.set(String(goal.id), goal));
      } else if (goalError) {
        console.warn('[Transactions Report] goal enrichment skipped:', goalError.message);
      }
    }

    const legsByTransaction = new Map<string, any[]>();
    ledgerRows.forEach((row: any) => {
      const txId = String(row?.transaction_id || '').trim();
      if (!txId) return;
      const existing = legsByTransaction.get(txId) || [];
      existing.push(row);
      legsByTransaction.set(txId, existing);
    });

    const userIds = Array.from(new Set([
      ...ledgerRows.map((row: any) => String(row?.user_id || '').trim()),
      ...Array.from(walletById.values()).map((wallet: any) => String(wallet?.user_id || '').trim()),
    ].filter(Boolean)));
    const sharedPotIds = Array.from(new Set(
      transactions
        .map((transaction: any) => String(transaction?.metadata?.shared_pot_id || '').trim())
        .filter(Boolean),
    ));
    const sharedBudgetIds = Array.from(new Set(
      transactions
        .map((transaction: any) => String(transaction?.shared_budget_id || transaction?.metadata?.shared_budget_id || '').trim())
        .filter(Boolean),
    ));
    const userById = new Map<string, any>();
    if (userIds.length) {
      const { data: users, error: userError } = await sb
        .from('users')
        .select('id,full_name,customer_id')
        .in('id', userIds);
      if (!userError && Array.isArray(users)) {
        users.forEach((user: any) => userById.set(String(user.id), user));
      } else if (userError) {
        console.warn('[Transactions Report] user enrichment skipped:', userError.message);
      }
    }
    const sharedPotById = new Map<string, any>();
    if (sharedPotIds.length) {
      const { data: sharedPots, error: sharedPotError } = await sb
        .from('shared_pots')
        .select('id,name')
        .in('id', sharedPotIds);
      if (!sharedPotError && Array.isArray(sharedPots)) {
        sharedPots.forEach((pot: any) => sharedPotById.set(String(pot.id), pot));
      } else if (sharedPotError) {
        console.warn('[Transactions Report] shared pot enrichment skipped:', sharedPotError.message);
      }
    }
    const sharedBudgetById = new Map<string, any>();
    if (sharedBudgetIds.length) {
      const { data: sharedBudgets, error: sharedBudgetError } = await sb
        .from('shared_budgets')
        .select('id,name')
        .in('id', sharedBudgetIds);
      if (!sharedBudgetError && Array.isArray(sharedBudgets)) {
        sharedBudgets.forEach((budget: any) => sharedBudgetById.set(String(budget.id), budget));
      } else if (sharedBudgetError) {
        console.warn('[Transactions Report] shared budget enrichment skipped:', sharedBudgetError.message);
      }
    }

    return transactions.map((transaction: any) => {
      const txId = transactionIdentity(transaction);
      const legs = txId ? (legsByTransaction.get(txId) || []) : [];
      if (!legs.length) return transaction;

      const userLeg = legs.find((leg: any) => String(leg?.user_id || '') === String(userId)) || legs[0];
      const balanceLeg = pickGeneralReportBalanceLeg(legs, userId, walletById, transaction);
      const debitLeg = pickReportSourceLeg(legs, transaction, walletById, userId);
      const creditLeg = pickReportDestinationLeg(legs, transaction, walletById, userId);
      const movementClassification = TransactionMovementClassifier.classify({
        transaction,
        legs,
        walletMap: walletById,
        userId,
      });
      const sourceWallet = walletById.get(String((debitLeg || userLeg)?.wallet_id || ''));
      const destinationWallet = walletById.get(String((creditLeg || userLeg)?.wallet_id || ''));
      const sourceUser = userById.get(String(debitLeg?.user_id || sourceWallet?.user_id || ''));
      const destinationUser = userById.get(String(creditLeg?.user_id || destinationWallet?.user_id || ''));
      const sourceContext = transaction?.source_wallet_context || transaction?.source_wallet_details || transaction?.source_wallet || {};
      const destinationContext = transaction?.destination_wallet_context || transaction?.destination_wallet_details || transaction?.destination_wallet || {};
      const sourceWalletName = normalizeWalletName(
        sourceWallet,
        firstText([
          transaction?.source_wallet_name,
          transaction?.sourceWalletName,
          transaction?.metadata?.source_wallet_name,
          transaction?.metadata?.source_wallet_context?.wallet_name,
          sourceContext?.wallet_name,
          sourceContext?.name,
        ]),
      );
      const destinationWalletName = normalizeWalletName(
        destinationWallet,
        firstText([
          transaction?.destination_wallet_name,
          transaction?.targetWalletName,
          transaction?.metadata?.destination_wallet_name,
          transaction?.metadata?.destination_wallet_context?.wallet_name,
          destinationContext?.wallet_name,
          destinationContext?.name,
        ]),
      );
      const sourceDisplayName = firstText([
        transaction?.source_display_name,
        transaction?.from_display_name,
        sourceUser?.full_name,
        sourceWalletName,
        'Orbi',
      ]);
      const destinationDisplayName = firstText([
        transaction?.metadata?.recipient_snapshot?.name,
        transaction?.metadata?.recipient_name,
        transaction?.recipient_name,
        transaction?.destination_display_name,
        transaction?.to_display_name,
        destinationUser?.full_name,
        destinationWalletName,
        'External Destination',
      ]);
      const sharedPot = sharedPotById.get(String(transaction?.metadata?.shared_pot_id || ''));
      const sharedPotLabel = sharedPot?.name ? `Fungu: ${sharedPot.name}` : undefined;
      const sharedBudget = sharedBudgetById.get(String(transaction?.shared_budget_id || transaction?.metadata?.shared_budget_id || ''));
      const sharedBudgetLabel = sharedBudget?.name ? `Mezani: ${sharedBudget.name}` : undefined;
      const internalResourceLabel = sharedPotLabel || sharedBudgetLabel;
      const balanceSide = String(balanceLeg?.entry_side || balanceLeg?.entry_type || '').toUpperCase();
      const resolvedSourceDisplayName = internalResourceLabel && balanceSide.includes('CREDIT')
        ? internalResourceLabel
        : sourceDisplayName;
      const resolvedDestinationDisplayName = internalResourceLabel && balanceSide.includes('DEBIT')
        ? internalResourceLabel
        : destinationDisplayName;
      const balanceAfter = firstText([
        balanceLeg?.balance_after,
        transaction?.balance_after,
        transaction?.balanceAfter,
      ]);

      return {
        ...transaction,
        ledger_entry_id: balanceLeg?.id || userLeg?.id || transaction?.ledger_entry_id,
        movement_family: movementClassification.movement_family,
        movement_code: movementClassification.movement_code,
        movement_group: movementClassification.movement_group,
        movement_classification: movementClassification,
        metadata: {
          ...(transaction?.metadata || {}),
          movement_family: movementClassification.movement_family,
          movement_code: movementClassification.movement_code,
          movement_group: movementClassification.movement_group,
          movement_classification: movementClassification,
        },
        balance_after: balanceAfter,
        running_balance: balanceAfter,
        from_display_name: resolvedSourceDisplayName,
        to_display_name: resolvedDestinationDisplayName,
        source_display_name: resolvedSourceDisplayName,
        destination_display_name: resolvedDestinationDisplayName,
        source_wallet_id: (debitLeg || userLeg)?.wallet_id || transaction?.source_wallet_id,
        destination_wallet_id: (creditLeg || userLeg)?.wallet_id || transaction?.destination_wallet_id,
        source_wallet_name: sourceWalletName,
        destination_wallet_name: destinationWalletName,
        ledger: {
          ...(transaction?.ledger || {}),
          id: balanceLeg?.id,
          balance_after: balanceAfter,
          entry_side: balanceLeg?.entry_side,
          entry_type: balanceLeg?.entry_type,
          wallet_id: balanceLeg?.wallet_id,
          balance_scope: 'OPERATING_WALLET',
        },
        balance_scope: 'OPERATING_WALLET',
      };
    });
  } catch (error: any) {
    console.warn('[Transactions Report] enrichment failed:', error?.message || error);
    return transactions;
  }
};

export const registerCoreFinanceRoutes = (v1: Router, deps: Deps) => {
  const {
    authenticate,
    authenticateApiKey,
    validate,
    requireRole,
    LogicCore,
    getSupabase,
    getAdminSupabase,
    PolicyEngine,
    FXEngine,
    TransactionService,
    WalletCreateSchema,
    WalletLockSchema,
    WalletUnlockSchema,
    PaymentIntentSchema,
    TransactionIssueSchema,
  } = deps;

  v1.post('/core/tenants', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const result = await LogicCore.createTenant(session.sub, req.body);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/core/tenants/my', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const result = await LogicCore.getUserTenants(session.sub);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(quoteErrorStatus(e.message)).json({ success: false, error: e.message });
    }
  });

  v1.post('/core/tenants/:id/api-keys', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const result = await LogicCore.generateTenantApiKeys(session.sub, req.params.id, req.body.type);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/core/tenants/:id/api-keys', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const result = await LogicCore.getTenantApiKeys(session.sub, req.params.id);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.delete('/core/tenants/:id/api-keys/:keyId', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const result = await LogicCore.revokeTenantApiKey(session.sub, req.params.id, req.params.keyId);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/core/tenants/:id/wallets', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const result = await LogicCore.getTenantWallets(session.sub, req.params.id);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/external/wallets', authenticateApiKey as any, async (req, res) => {
    const tenantId = (req as any).tenantId;
    try {
      const sb = getSupabase();
      if (!sb) throw new Error('Database not connected');

      const { data, error } = await sb.from('wallets').select('*').eq('tenant_id', tenantId);

      if (error) throw new Error(error.message);
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/core/tenants/:id/settlement/config', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const result = await LogicCore.getTenantSettlementConfig(session.sub, req.params.id);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.patch('/core/tenants/:id/settlement/config', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const result = await LogicCore.updateTenantSettlementConfig(session.sub, req.params.id, req.body);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/core/tenants/:id/settlement/pending', authenticate as any, async (req, res) => {
    try {
      const result = await LogicCore.getTenantPendingSettlement(req.params.id);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/core/tenants/:id/settlement/payout', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const result = await LogicCore.triggerTenantPayout(session.sub, req.params.id);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/core/tenants/:id/settlement/history', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const result = await LogicCore.getTenantPayoutHistory(session.sub, req.params.id);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/wallets/linked', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const allWallets = await LogicCore.getWallets(session.sub);
      const linked = allWallets.filter((w: any) => w.management_tier === 'linked');
      res.json({ success: true, data: linked });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/wallets/sovereign', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const allWallets = await LogicCore.getWallets(session.sub);
      const sovereign = allWallets.filter((w: any) => w.management_tier === 'sovereign');
      res.json({ success: true, data: sovereign });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/user/dashboard', authenticate as any, async (req, res) => {
    const token = (req as any).authToken as string | null;
    try {
      const result = await LogicCore.getBootstrapData(token);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/dashboard', authenticate as any, async (req, res) => {
    const token = (req as any).authToken as string | null;
    try {
      const result = await LogicCore.getBootstrapData(token);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/wallets', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const result = await LogicCore.getWallets(session.sub);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/wallets', authenticate as any, validate(WalletCreateSchema), async (req, res) => {
    const session = (req as any).session;
    try {
      const result = await LogicCore.postWallet({ ...req.body, userId: session.sub });
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/wallets/currency', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    const currency = walletCurrencyCode(req.body?.currency);

    if (!isIsoCurrencyCode(currency)) {
      return res.status(400).json({
        success: false,
        error: 'FX_CURRENCY_INVALID',
        message: 'Currency code must be an ISO 4217 three-letter code.',
      });
    }

    try {
      const sb = getAdminSupabase?.() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });

      const supported = await isSupportedFxCurrency(sb, currency);
      if (!supported) {
        return res.status(400).json({
          success: false,
          error: 'FX_CURRENCY_NOT_SUPPORTED',
          message: 'This currency is not available for ORBI FX wallets yet.',
        });
      }

      const { data: existing, error: existingError } = await sb
        .from('platform_vaults')
        .select('*')
        .eq('user_id', session.sub)
        .eq('vault_role', 'OPERATING')
        .eq('currency', currency)
        .neq('status', 'closed')
        .maybeSingle();
      if (existingError) throw existingError;

      if (existing) {
        return res.json({
          success: true,
          data: {
            wallet: existing,
            created: false,
          },
        });
      }

      const encryptedBalance = await DataProtection.encryptAmount(0, {
        userId: session.sub,
        currency,
        purpose: 'multi_currency_wallet_opening',
      });
      const now = new Date().toISOString();
      const { data: wallet, error: insertError } = await sb
        .from('platform_vaults')
        .insert({
          id: randomUUID(),
          user_id: session.sub,
          vault_role: 'OPERATING',
          name: `Orbi - ${currency}`,
          balance: 0,
          encrypted_balance: encryptedBalance,
          currency,
          color: colorForCurrencyWallet(currency),
          icon: 'currency-exchange',
          status: 'active',
          metadata: {
            multi_currency_wallet: true,
            wallet_family: 'orbi_multi_currency',
            opened_via: 'mobile_fx',
            created_at: now,
          },
        })
        .select('*')
        .single();
      if (insertError) throw insertError;

      res.status(201).json({
        success: true,
        data: {
          wallet,
          created: true,
        },
      });
    } catch (e: any) {
      res.status(500).json({
        success: false,
        error: 'FX_CURRENCY_WALLET_OPEN_FAILED',
        message: e.message,
      });
    }
  });

  v1.delete('/wallets/:id', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const walletId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
      await LogicCore.deleteWallet(session.sub, walletId);
      res.json({ success: true });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.post('/wallets/:id/lock', authenticate as any, validate(WalletLockSchema), async (req, res) => {
    const session = (req as any).session;
    const isAdmin = requireRole(session, ['ADMIN', 'SUPER_ADMIN', 'IT', 'STAFF']);
    try {
      const walletId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
      const result = await LogicCore.lockWallet(session.sub, walletId, {
        reason: req.body.reason,
        pin: req.body.pin,
        force: req.body.force,
        isAdmin,
      });
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.post('/wallets/:id/unlock', authenticate as any, validate(WalletUnlockSchema), async (req, res) => {
    const session = (req as any).session;
    const isAdmin = requireRole(session, ['ADMIN', 'SUPER_ADMIN', 'IT', 'STAFF']);
    if (!isAdmin && !req.body.pin) {
      return res.status(400).json({ success: false, error: 'PIN_REQUIRED' });
    }
    try {
      const walletId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
      const result = await LogicCore.unlockWallet(session.sub, walletId, {
        reason: req.body.reason,
        pin: req.body.pin,
        force: req.body.force,
        isAdmin,
      });
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.get('/fx/currencies', authenticate as any, async (_req, res) => {
    try {
      const sb = getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });

      const { data, error } = await sb
        .from('fx_corridors')
        .select('id, from_currency, to_currency, min_amount, max_amount, settlement_mode, status')
        .eq('status', 'ACTIVE')
        .order('from_currency', { ascending: true })
        .order('to_currency', { ascending: true });
      if (error) throw error;

      const currencies = Array.from(
        new Set(
          (data || [])
            .flatMap((row: any) => [walletCurrencyCode(row.from_currency), walletCurrencyCode(row.to_currency)])
            .filter(isIsoCurrencyCode),
        ),
      ).sort();

      res.json({
        success: true,
        data: {
          currencies,
          corridors: data || [],
        },
      });
    } catch (e: any) {
      res.status(500).json({
        success: false,
        error: 'FX_CURRENCY_CATALOG_FAILED',
        message: e.message,
      });
    }
  });

  v1.post('/transactions/settle', authenticate as any, validate(PaymentIntentSchema), requireIdempotencyKey, async (req, res) => {
    const session = (req as any).session;
    const idempotencyKey = resolveIdempotencyHeader(req);

    try {
      enrichTransactionTimeMetadata(req);
      enrichTransactionGeoMetadata(req);
      const binding = await LogicCore.bindSettlementQuote(
        session.sub,
        req.body,
        String(idempotencyKey).trim(),
      );
      const settlementPayload = {
        ...binding.payload,
        idempotencyKey: String(idempotencyKey).trim(),
      };

      const kycStatus = session.user.user_metadata?.kyc_status || 'unverified';
      const amount = settlementPayload.amount || 0;
      const currency = settlementPayload.currency || 'TZS';

      const policyResult = await PolicyEngine.evaluateTransaction(session.sub, amount, currency, 'settlement');
      if (!policyResult.allowed) {
        return res.status(403).json({
          success: false,
          error: 'POLICY_VIOLATION',
          message: policyResult.reason,
        });
      }

      if (kycStatus !== 'verified' && amount > 1000000) {
        return res.status(403).json({
          success: false,
          error: 'KYC_LIMIT_EXCEEDED',
          message: 'Unverified accounts are limited to 1,000,000 TZS per transaction. Please complete KYC.',
        });
      }

      const serverFxQuote = String(settlementPayload.type || '').toUpperCase() === 'FX_CONVERSION'
        ? binding.quote
        : undefined;
      const result = await LogicCore.processSecurePayment(settlementPayload, session.user, serverFxQuote);
      await LogicCore.markSettlementQuoteResult(session.sub, binding.quoteId, result);

      if (!result.success) {
        if (result.error === 'SECURITY_CHALLENGE') {
          return res.status(403).json(result);
        }

        const isTransient =
          result.error?.includes('LOCK_TIMEOUT') ||
          result.error?.includes('LEDGER_COMMIT_FAILED') ||
          result.error?.includes('LEDGER_FAULT') ||
          result.error?.includes('INFRASTRUCTURE_ERROR');

        const statusCode = isTransient ? 500 : 400;
        return res.status(statusCode).json(result);
      }

      await PolicyEngine.commitMetrics(session.sub, amount, currency);
      res.json({ success: true, data: result });
    } catch (e: any) {
      console.error(`[Transaction] Settle Error: ${e.message}`);
      const statusCode = quoteErrorStatus(String(e.message || ''));
      res.status(statusCode).json(quoteErrorPayload(e, 'transaction_confirmation'));
    }
  });

  v1.post('/transactions/preview', authenticate as any, validate(PaymentIntentSchema), async (req, res) => {
    const session = (req as any).session;
    try {
      enrichTransactionTimeMetadata(req);
      enrichTransactionGeoMetadata(req);
      const result = await LogicCore.getTransactionPreview(session.sub, req.body);
      if (!result.success) {
        return res.status(400).json(result);
      }
      res.json({ success: true, data: result });
    } catch (e: any) {
      const statusCode = quoteErrorStatus(String(e.message || ''));
      res.status(statusCode).json(quoteErrorPayload(e, 'transaction_preview'));
    }
  });

  v1.get('/transactions/settlement-status', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    const quoteId = String(req.query.quoteId || req.query.quote_id || '').trim();
    const idempotencyKey = String(req.query.idempotencyKey || req.query.idempotency_key || '').trim();

    if (!quoteId && !idempotencyKey) {
      return res.status(400).json({
        success: false,
        error: 'SETTLEMENT_LOOKUP_KEY_REQUIRED',
        message: 'quoteId or idempotencyKey is required.',
      });
    }

    try {
      const sb = getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });

      let query = sb
        .from('transaction_quotes')
        .select('id, status, idempotency_key, transaction_id, settlement_result, confirmed_at, settled_at, updated_at, expires_at')
        .eq('user_id', session.sub);

      if (quoteId) query = query.eq('id', quoteId);
      if (idempotencyKey) query = query.eq('idempotency_key', idempotencyKey);

      const { data: quote, error } = await query.maybeSingle();
      if (error) throw error;
      if (!quote) {
        return res.status(404).json({
          success: false,
          error: 'SETTLEMENT_STATUS_NOT_FOUND',
          message: 'No settlement state was found for this transaction preview.',
        });
      }

      let transaction: any = null;
      const transactionId = quote.transaction_id ? String(quote.transaction_id) : '';
      if (transactionId) {
        transaction = await LogicCore.getTransactionForUser(session.sub, transactionId);
      }

      res.json({
        success: true,
        data: {
          quoteId: quote.id,
          idempotencyKey: quote.idempotency_key,
          quoteStatus: quote.status,
          status: transaction?.status || quote.status,
          transactionId,
          transaction,
          settlementResult: quote.settlement_result || null,
          confirmedAt: quote.confirmed_at,
          settledAt: quote.settled_at,
          updatedAt: quote.updated_at,
          expiresAt: quote.expires_at,
        },
      });
    } catch (e: any) {
      res.status(500).json({
        success: false,
        error: 'SETTLEMENT_STATUS_LOOKUP_FAILED',
        message: e.message,
      });
    }
  });

  v1.get('/fx/quote', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    const from = normalizeCurrencyCode(req.query.from);
    const to = normalizeCurrencyCode(req.query.to);
    const amount = Number(req.query.amount);

    if (!from || !to) {
      return res.status(400).json({
        success: false,
        error: 'FX_PAIR_REQUIRED',
        message: 'from and to currency codes are required.',
        context: 'fx_quote',
        retryable: false,
      });
    }

    if (!/^[A-Z]{3}$/.test(from) || !/^[A-Z]{3}$/.test(to)) {
      return res.status(400).json({
        success: false,
        error: 'FX_PAIR_INVALID',
        message: 'Currency codes must be ISO 4217 three-letter codes.',
        context: 'fx_quote',
        retryable: false,
      });
    }

    if (from === to) {
      return res.status(400).json({
        success: false,
        error: 'FX_PAIR_SAME_CURRENCY',
        message: 'from and to currencies must be different.',
        context: 'fx_quote',
        retryable: false,
      });
    }

    if (!Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({
        success: false,
        error: 'FX_AMOUNT_INVALID',
        message: 'amount must be a positive number.',
        context: 'fx_quote',
        retryable: false,
      });
    }

    try {
      const sourceWalletId = normalizeNullable(req.query.sourceWalletId || req.query.source_wallet_id);
      const targetWalletId = normalizeNullable(req.query.targetWalletId || req.query.target_wallet_id);
      const shouldLockQuote = String(req.query.lock || req.query.locked || '').trim().toLowerCase() === 'true';
      const result = await FXEngine.processConversion(amount, from, to);

      if (!shouldLockQuote) {
        return res.json({
          success: true,
          data: {
            ...result,
            quoteId: null,
            quoteContext: {
              type: 'FX_CONVERSION',
              quoteId: null,
              fromCurrency: from,
              toCurrency: to,
              quotedAt: result.quotedAt,
              expiresAt: result.expiresAt,
              expiresInSeconds: result.expiresInSeconds,
              lockedRate: false,
            },
          },
        });
      }

      const sb = getSupabase();
      if (!sb) {
        return res.status(503).json({
          success: false,
          error: 'DB_OFFLINE',
          message: 'FX quote lock storage is unavailable.',
          context: 'fx_quote',
          retryable: true,
        });
      }
      if (!sourceWalletId || !targetWalletId) {
        return res.status(400).json({
          success: false,
          error: 'FX_WALLET_PAIR_REQUIRED',
          message: 'sourceWalletId and targetWalletId are required for a locked FX quote.',
          context: 'fx_quote',
          retryable: false,
        });
      }

      const quoteId = `fx_${randomUUID()}`;
      const description = String(req.query.description || `FX conversion ${from} to ${to}`).trim();
      const requestPayload = {
        type: 'FX_CONVERSION',
        amount,
        currency: from,
        fromCurrency: from,
        toCurrency: to,
        sourceWalletId,
        targetWalletId,
        description,
        metadata: {
          category: 'FX',
          fx_quote: true,
          source_currency: from,
          target_currency: to,
        },
      };
      const quoteHash = hashFxQuotePayload(buildFxCanonicalIntent(requestPayload));
      const quoteSignature = signFxQuote(quoteId, quoteHash, result.expiresAt, session.sub);
      const quoteSnapshot: Record<string, any> = {
        ...result,
        quoteId,
        type: 'FX_CONVERSION',
        amount,
        currency: from,
        sourceWallet: { id: sourceWalletId, currency: from },
        targetWallet: { id: targetWalletId, currency: to },
        debit: { sourceWalletId, total: amount },
        fees: { totalFee: 0, flowCode: null, configId: null },
        status: 'QUOTED',
      };
      quoteSnapshot.fxSnapshotSignature = signLockedFxSnapshot(
        quoteSnapshot,
        quoteId,
        session.sub,
        process.env.ORBI_TRANSACTION_QUOTE_SIGNING_SECRET || process.env.JWT_SECRET || process.env.SESSION_SECRET || '',
      );
      const { error: insertError } = await sb.from('transaction_quotes').insert({
        id: quoteId,
        user_id: session.sub,
        payload_hash: quoteHash,
        quote_signature: quoteSignature,
        request_payload: requestPayload,
        quote_snapshot: quoteSnapshot,
        amount,
        currency: from,
        transaction_type: 'FX_CONVERSION',
        source_wallet_id: sourceWalletId,
        target_wallet_id: targetWalletId,
        total_debit: amount,
        total_fee: Number(result.fee || 0),
        can_submit: true,
        status: 'QUOTED',
        expires_at: result.expiresAt,
      });
      if (insertError) throw insertError;

      const { error: reconciliationError } = await sb.from('fx_reconciliation_events').insert({
        quote_id: quoteId,
        user_id: session.sub,
        from_currency: from,
        to_currency: to,
        source_amount: amount,
        target_amount: Number(result.finalAmount || 0),
        customer_rate: Number(result.customerRate || result.exchangeRate || 0),
        market_rate: Number(result.marketRate || result.baseRate || 0),
        spread_amount: Number(result.spreadAmount || 0),
        spread_currency: result.spreadCurrency || to,
        provider_code: result.liquidityProvider?.providerCode || null,
        settlement_mode: result.liquidityProvider?.settlementMode || null,
        status: 'PENDING',
        metadata: {
          quoteExpiresAt: result.expiresAt,
          liquidityProvider: result.liquidityProvider,
          marginBps: result.marginBps,
          riskBufferBps: result.riskBufferBps,
          protectionBps: result.protectionBps,
          quotedMarginAmount: result.quotedMarginAmount,
          quotedRiskBufferAmount: result.quotedRiskBufferAmount,
          spreadCurrency: result.spreadCurrency,
          revenueStatus: 'QUOTED_ESTIMATE',
        },
      });
      if (reconciliationError) throw reconciliationError;

      res.json({
        success: true,
        data: {
          ...result,
          quoteId,
          quoteContext: {
            type: 'FX_CONVERSION',
            quoteId,
            fromCurrency: from,
            toCurrency: to,
            quotedAt: result.quotedAt,
            expiresAt: result.expiresAt,
            expiresInSeconds: result.expiresInSeconds,
            lockedRate: true,
          },
        },
      });
    } catch (e: any) {
      const payload = fxQuoteErrorPayload(e);
      res.status(fxQuoteErrorStatus(payload.error)).json(payload);
    }
  });

  v1.get('/transactions', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    const limit = Number(req.query.limit || 50);
    const offset = Number(req.query.offset || 0);
    try {
      const result = await LogicCore.getTransactionsPaginated(session.sub, limit, offset);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/transactions/report', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    const range = resolveReportRange(req.query.range);
    const limit = Math.min(Math.max(Number(req.query.limit || 500), 1), 1000);
    try {
      const result = await LogicCore.getTransactionsPaginated(session.sub, limit, 0);
      const transactions = Array.isArray(result) ? result : (result?.items || result?.transactions || result?.data || []);
      const enrichedTransactions = await enrichTransactionsForReport(
        getSupabase(),
        session.sub,
        transactions,
      );
      const report = buildTransactionReport(enrichedTransactions, range);
      const balances = await buildBalanceSnapshot(
        getSupabase(),
        session.sub,
        report.summary?.currency || 'TZS',
      );
      const summary = {
        ...report.summary,
        available_balance: balances.available_balance,
        availableBalance: balances.available_balance,
        inside_orbi_total: balances.inside_orbi_total,
        insideOrbiTotal: balances.inside_orbi_total,
      };
      res.json({
        success: true,
        data: {
          ...report,
          summary,
          balances,
          balance_snapshot: balances,
        },
      });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/transactions/:id', authenticate as any, async (req, res) => {
    const session = (req as any).session;
    try {
      const transactionId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
      const transaction = await LogicCore.getTransactionForUser(session.sub, transactionId);
      if (!transaction) {
        return res.status(404).json({ success: false, error: 'TRANSACTION_NOT_FOUND' });
      }
      res.json({ success: true, data: transaction });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/transactions/:id/lock', authenticate as any, validate(TransactionIssueSchema), async (req, res) => {
    const session = (req as any).session;
    try {
      const transactionId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
      const result = await LogicCore.requestTransactionRecall(session.sub, transactionId, req.body.reason);
      res.json({
        success: true,
        data: {
          ...result,
          advisory: 'Transaction recall requested. Funds remain under review and may take up to 24 hours to reflect back to your operating wallet.',
        },
      });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.get('/transactions/:id/receipt', authenticate as any, async (req, res) => {
    const { id } = req.params;
    const session = (req as any).session;

    try {
      const service = new TransactionService();
      const transactions = await service.getLatestTransactions(session.sub, 100, 0);
      const tx = transactions.find((t: any) => t.internalId === id || t.referenceId === id || t.id === id);

      if (!tx) {
        return res.status(404).json({ success: false, error: 'TRANSACTION_NOT_FOUND' });
      }

      res.json({
        success: true,
        data: {
          ...tx,
          generatedAt: new Date().toISOString(),
          issuer: 'ORBI FINANCIAL TECHNOLOGIES',
        },
      });
    } catch (e: any) {
      console.error(`[Receipt Data] Fetch failed for ${id}:`, e);
      res.status(500).json({ success: false, error: 'RECEIPT_DATA_FAULT', message: e.message });
    }
  });
};
