import crypto from 'crypto';
import { URL } from 'url';
import type { Express, NextFunction, Request, Response, Router } from 'express';
import { z } from 'zod';
import { getAdminSupabase, getSupabase } from '../../../backend/supabaseClient.js';
import { BankingEngineService } from '../../../backend/ledger/transactionEngine.js';
import { Audit } from '../../../backend/security/audit.js';
import { Server as LogicCore } from '../../../backend/server.js';
import { Webhooks } from '../../../backend/payments/webhookHandler.js';
import { platformFeeService } from '../../../backend/payments/PlatformFeeService.js';
import { gatewayPaymentIntentService } from '../../../backend/payments/GatewayPaymentIntentService.js';
import { PaymentProfileService } from '../../../backend/payments/PaymentProfileService.js';
import { Messaging } from '../../../backend/features/MessagingService.js';
import { OTPService } from '../../../backend/security/otpService.js';
import { Identity } from '../../../iam/identityService.js';
import { BusinessIdentity } from '../../../backend/business/BusinessIdentityService.js';
import { firebasePushService } from '../../../backend/infrastructure/firebasePushService.js';
import {
  createInternalWorkerMiddleware,
  getInternalAuditMetadata,
  workerHasRequiredScopes,
} from '../../middleware/auth/authorization.js';

const requireWorkerScope = (requiredScopes: string[]) =>
  (req: Request, res: Response, next: NextFunction) => {
    const worker = (req as any).internalWorker || null;
    if (!workerHasRequiredScopes(worker, requiredScopes)) {
      return res.status(403).json({
        success: false,
        error: 'WORKER_SCOPE_REQUIRED',
        message: `Missing required worker scope: ${requiredScopes.join(', ')}`,
      });
    }
    return next();
  };

const quoteErrorStatus = (message: string) => {
  if (/DB_OFFLINE|UNAVAILABLE/i.test(message)) return 503;
  if (/NOT_CONFIGURED|NOT_FOUND|REQUIRED|ACCESS_DENIED|INSUFFICIENT|BLOCK/i.test(message)) return 400;
  return 500;
};

const normalizeChallengeDecision = (value: unknown) => {
  const decision = String(value || '').trim().toLowerCase();
  if (['approve', 'approved', 'accept', 'accepted', 'confirm', 'confirmed'].includes(decision)) {
    return 'approve' as const;
  }
  if (['reject', 'rejected', 'decline', 'declined', 'deny', 'denied', 'cancel', 'cancelled'].includes(decision)) {
    return 'reject' as const;
  }
  throw new Error('SERVICE_CHALLENGE_DECISION_INVALID');
};

const servicePaymentNotificationTimeoutMs = Math.max(
  250,
  Number(process.env.ORBI_NOTIFICATION_SIDE_EFFECT_TIMEOUT_MS || 2500),
);

const dispatchServicePaymentNotificationSafely = (
  factory: () => Promise<unknown>,
  context: Record<string, unknown>,
) => {
  const task = Promise.resolve()
    .then(factory)
    .catch((error: any) => {
      console.warn('[PayGateway] service authorization notification failed', {
        ...context,
        error: error?.message || String(error || 'UNKNOWN_NOTIFICATION_ERROR'),
      });
    });

  Promise.race([
    task,
    new Promise((resolve) => setTimeout(() => resolve('timeout'), servicePaymentNotificationTimeoutMs)),
  ])
    .then((result) => {
      if (result === 'timeout') {
        console.warn('[PayGateway] service authorization notification still running in background', {
          ...context,
          timeoutMs: servicePaymentNotificationTimeoutMs,
        });
      }
    })
    .catch(() => undefined);
};

async function completeApprovedServiceChallengeWithPaySafeHold(
  actorUserId: string,
  response: Awaited<ReturnType<typeof gatewayPaymentIntentService.respondToChallenge>>,
) {
  const intent = response.intent || {};
  const requestPayload = intent.request_payload || {};
  const requestMetadata = requestPayload.metadata || {};
  const challengeMetadata = response.challenge?.metadata || {};
  const merchantId = String(
    intent.merchant_id ||
      challengeMetadata.merchantId ||
      challengeMetadata.merchant_id ||
      requestMetadata.merchantId ||
      requestMetadata.merchant_id ||
      '',
  ).trim();
  if (!merchantId) throw new Error('MERCHANT_CONTEXT_REQUIRED');

  const sb = getAdminSupabase() || getSupabase();
  if (!sb) throw new Error('DB_OFFLINE');
  const { data: merchant, error: merchantError } = await sb
    .from('merchants')
    .select('id,business_name,owner_user_id,status')
    .eq('id', merchantId)
    .maybeSingle();
  if (merchantError) throw new Error(merchantError.message || 'MERCHANT_LOOKUP_FAILED');
  if (!merchant) throw new Error('MERCHANT_NOT_FOUND');
  if (String(merchant.status || '').toLowerCase() !== 'active') throw new Error('MERCHANT_NOT_ACTIVE');
  const recipientUserId = String(merchant.owner_user_id || '').trim();
  if (!recipientUserId) throw new Error('MERCHANT_OWNER_REQUIRED');

  const currency = String(intent.currency || requestPayload.currency || 'TZS').toUpperCase();
  const amount = Number(intent.amount || requestPayload.amount || 0);
  const reference = String(intent.reference || requestPayload.reference || '').trim();
  const serviceCode = String(intent.service_code || requestPayload.serviceCode || '').trim();
  const description = String(
    requestPayload.description ||
      requestMetadata.description ||
      `Protected checkout ${reference || intent.intent_id}`,
  ).trim();

  const paysafeReferenceId = await LogicCore.createEscrow(
    actorUserId,
    recipientUserId,
    amount,
    description,
    {
      ...(requestMetadata || {}),
      merchantId,
      serviceCode,
      orderId: requestMetadata.orderId || requestMetadata.order_id || reference || null,
      gatewayIntentId: String(intent.intent_id),
      gatewayChallengeId: String(response.challenge?.challenge_id || ''),
      gatewayReference: reference || null,
      source: 'pay_gateway_service_challenge',
      settlementPolicy: 'paysafe_hold_required',
      thirdPartyAuthorization: true,
      merchantName: merchant.business_name || null,
      currency,
    },
  );

  return {
    paysafeReferenceId,
    merchant,
    amount,
    currency,
    reference,
    serviceCode,
  };
}

const TrustedGatewayEventSchema = z.object({
  providerId: z.string().min(1),
  reference: z.string().min(1),
  status: z.enum(['completed', 'failed', 'processing', 'pending']),
  message: z.string().min(1).max(1000),
  providerEventId: z.string().min(1).optional(),
  rawStatus: z.string().min(1).optional(),
  payload: z.record(z.string(), z.unknown()).optional(),
});

const ServicePaymentRequestSchema = z.object({
  environment: z.enum(['sandbox', 'live']).default('live'),
  simulationScenario: z.enum(['success', 'decline', 'timeout', 'requires_action']).optional(),
  intentId: z.string().min(1),
  serviceCode: z.string().min(1),
  operation: z.enum(['collection', 'payout', 'refund', 'paysafe']),
  paymentCategory: z.enum(['orbi', 'mobile_money', 'bank', 'card']).optional(),
  paymentRail: z.enum(['orbi_wallet', 'mno_tz', 'bank_transfer_tz', 'card_gateway']).optional(),
  providerCode: z.string().optional(),
  reference: z.string().min(1),
  amount: z.number().nonnegative(),
  currency: z.string().min(3).max(8),
  description: z.string().max(500).optional(),
  customer: z.object({
    type: z.enum(['user', 'guest', 'external_customer']).optional(),
    name: z.string().optional(),
    email: z.string().email().optional(),
    phone: z.string().optional(),
    userId: z.string().optional(),
  }).optional(),
  walletId: z.string().optional(),
  accountNumber: z.string().optional(),
  metadata: z.record(z.string(), z.unknown()).default({}),
  checkoutUrl: z.string().optional(),
  createdAt: z.string().optional(),
});

const PaySafeBalanceRequestSchema = z.object({
  serviceCode: z.string().min(1),
  merchantId: z.string().optional(),
  userId: z.string().optional(),
  customerId: z.string().optional(),
  email: z.string().email().optional(),
  phone: z.string().optional(),
  includeHistory: z.boolean().optional().default(false),
  metadata: z.record(z.string(), z.unknown()).default({}),
});

const IdentityResolveRequestSchema = z.object({
  serviceCode: z.string().min(1),
  identifier: z.string().trim().min(3).max(120),
  metadata: z.record(z.string(), z.unknown()).default({}),
});

const PayGatewayPushRequestSchema = z.object({
  eventId: z.string().trim().min(1).max(160),
  userId: z.string().uuid(),
  title: z.string().trim().min(1).max(160),
  body: z.string().trim().min(1).max(2000),
  data: z.record(z.string(), z.unknown()).optional().default({}),
  environment: z.enum(['sandbox', 'live']),
});

const BusinessRegistrationRequestSchema = z.object({
  serviceCode: z.string().min(1),
  userId: z.string().optional(),
  email: z.string().email().optional(),
  phone: z.string().trim().min(1).max(40).optional(),
  requestedRole: z.string().optional(),
  requested_role: z.string().optional(),
  businessName: z.string().trim().min(1).max(160).optional(),
  business_name: z.string().trim().min(1).max(160).optional(),
  externalBusinessId: z.string().trim().max(160).optional(),
  note: z.string().trim().max(1000).optional(),
  metadata: z.record(z.string(), z.unknown()).default({}),
}).refine((value) => value.userId || value.email || value.phone, {
  message: 'userId, email, or phone is required',
});

const PaymentProfileRequestSchema = z.object({
  serviceCode: z.string().min(1),
  userId: z.string().optional(),
  customerId: z.string().optional(),
  email: z.string().email().optional(),
  phone: z.string().trim().min(1).max(40).optional(),
  externalCustomerId: z.string().trim().min(1).max(160).optional(),
  scopes: z.array(z.string().trim().min(1).max(80)).min(1).max(20),
  consent: z.record(z.string(), z.unknown()).default({}),
  metadata: z.record(z.string(), z.unknown()).default({}),
  expiresAt: z.string().datetime().optional(),
  idempotencyKey: z.string().trim().min(8).max(160).optional(),
}).refine((value) => value.userId || value.customerId || value.email || value.phone, {
  message: 'userId, customerId, email, or phone is required',
});

const MerchantOrderPaymentStatusRequestSchema = z.object({
  serviceCode: z.string().min(1),
  merchantId: z.string().min(1),
  orderId: z.string().min(1),
  metadata: z.record(z.string(), z.unknown()).default({}),
});

const MerchantSettlementsRequestSchema = z.object({
  serviceCode: z.string().min(1),
  merchantId: z.string().min(1),
  currency: z.string().min(3).max(8).optional(),
  status: z.string().optional(),
  limit: z.number().int().min(1).max(100).optional().default(50),
  offset: z.number().int().min(0).optional().default(0),
  metadata: z.record(z.string(), z.unknown()).default({}),
});

type ServicePaymentCoreEvent = {
  intentId: string;
  serviceCode: string;
  status: 'requires_action' | 'processing' | 'pending' | 'completed' | 'failed';
  message?: string;
  transactionId?: string;
  challenge?: {
    type: 'PIN' | 'OTP' | 'PASSKEY' | 'BIOMETRIC' | '3DS';
    challengeId: string;
    prompt: string;
    expiresAt?: string;
    delivery?: {
      channel?: 'sms' | 'email' | 'push' | 'in_app';
      destinationHint?: string;
    };
    metadata?: Record<string, unknown>;
  };
  raw?: Record<string, unknown>;
};

const stableSerialize = (value: unknown): string => {
  if (value === null || value === undefined) return '';
  if (typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((entry) => stableSerialize(entry)).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, entryValue]) => entryValue !== undefined)
    .sort(([left], [right]) => left.localeCompare(right));
  return `{${entries.map(([key, entryValue]) => `${JSON.stringify(key)}:${stableSerialize(entryValue)}`).join(',')}}`;
};

const hashInternalRequestBody = (body: unknown): string =>
  crypto.createHash('sha256').update(stableSerialize(body)).digest('hex');

const buildSignedCoreToPayGatewayHeaders = (method: string, path: string, body: unknown): Record<string, string> => {
  const signingSecret = process.env.WORKER_SIGNING_SECRET || process.env.WORKER_SECRET || '';
  if (!signingSecret) throw new Error('WORKER_SIGNING_SECRET_NOT_CONFIGURED');
  const workerId = process.env.ORBI_CORE_PAY_GATEWAY_WORKER_ID || 'orbi-core';
  const scopes = 'gateway:service-payments:result';
  const timestamp = new Date().toISOString();
  const nonce = crypto.randomUUID();
  const requestId = crypto.randomUUID();
  const bodySha256 = hashInternalRequestBody(body);
  const environment = String(process.env.ORBI_RUNTIME_ENVIRONMENT || '').toLowerCase();
  if (!['sandbox','live'].includes(environment)) throw new Error('ORBI_RUNTIME_ENVIRONMENT_NOT_CONFIGURED');
  const canonicalPayload = [
    method.toUpperCase(),
    path,
    workerId,
    scopes,
    timestamp,
    nonce,
    requestId,
    environment,
    bodySha256,
  ].join('\n');
  const signature = crypto.createHmac('sha256', signingSecret).update(canonicalPayload).digest('hex');
  return {
    'content-type': 'application/json',
    'x-worker-id': workerId,
    'x-worker-scopes': scopes,
    'x-worker-request-id': requestId,
    'x-worker-timestamp': timestamp,
    'x-worker-nonce': nonce,
    'x-orbi-environment': environment,
    'x-worker-signature': signature,
    'x-worker-key-id': process.env.WORKER_KEY_ID || 'orbi-core-v1',
  };
};

const postServicePaymentEventToPayGateway = async (event: ServicePaymentCoreEvent): Promise<Record<string, unknown>> => {
  const baseUrl = String(
    process.env.ORBI_PAY_GATEWAY_INTERNAL_BASE_URL ||
      process.env.ORBI_PAY_GATEWAY_BASE_URL ||
      '',
  ).trim();
  if (!baseUrl) return { attempted: false, delivered: false, error: 'ORBI_PAY_GATEWAY_BASE_URL_NOT_CONFIGURED' };
  const path = process.env.ORBI_PAY_GATEWAY_SERVICE_PAYMENT_EVENT_PATH || '/v1/internal/core/service-payment-events';
  const endpoint = new URL(path, baseUrl);
  const body = JSON.stringify(event);
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      ...buildSignedCoreToPayGatewayHeaders('POST', endpoint.pathname, event),
      'content-length': Buffer.byteLength(body).toString(),
    },
    body,
  });
  let payload: any = null;
  try {
    payload = await response.json();
  } catch {
    payload = { raw: await response.text().catch(() => '') };
  }
  return {
    attempted: true,
    delivered: response.ok,
    statusCode: response.status,
    payload,
  };
};

const normalizePhoneCandidate = (value?: string) => String(value || '').replace(/[^\d+]/g, '').trim();
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const hashGuestIdentifier = (value?: string) => {
  const clean = String(value || '').trim().toLowerCase();
  return clean ? crypto.createHash('sha256').update(clean).digest('hex') : null;
};

const maskEmail = (value?: string) => {
  const email = String(value || '').trim().toLowerCase();
  const [local, domain] = email.split('@');
  if (!local || !domain) return null;
  return `${local.slice(0, 2)}***@${domain}`;
};

const maskPhone = (value?: string) => {
  const phone = normalizePhoneCandidate(value);
  if (!phone) return null;
  return `${phone.slice(0, 4)}***${phone.slice(-3)}`;
};

const metadataFlag = (metadata: Record<string, unknown>, ...keys: string[]) =>
  keys.some((key) => metadata[key] === true || String(metadata[key] || '').toLowerCase() === 'true');

const categoryForRail = (rail: string) => {
  if (rail === 'orbi_wallet') return 'orbi';
  if (rail === 'mno_tz') return 'mobile_money';
  if (rail === 'bank_transfer_tz') return 'bank';
  if (rail === 'card_gateway') return 'card';
  return '';
};

const resolvePaySafeFundingRoute = (request: z.infer<typeof ServicePaymentRequestSchema>) => {
  const metadata = request.metadata || {};
  const paymentRail = String(request.paymentRail || metadata.paymentRail || metadata.payment_rail || '').trim();
  const paymentCategory = String(
    request.paymentCategory ||
      metadata.paymentCategory ||
      metadata.payment_category ||
      categoryForRail(paymentRail) ||
      '',
  ).trim();

  if (request.operation !== 'paysafe') {
    return null;
  }

  if (!paymentCategory || !paymentRail) {
    throw new Error('PAYSAFE_PAYMENT_ROUTE_REQUIRED');
  }

  if (categoryForRail(paymentRail) !== paymentCategory) {
    throw new Error('PAYSAFE_PAYMENT_ROUTE_MISMATCH');
  }

  if (paymentCategory !== 'orbi' && !String(request.providerCode || metadata.providerCode || metadata.provider_code || '').trim()) {
    throw new Error('PAYSAFE_EXTERNAL_PROVIDER_CODE_REQUIRED');
  }

  return {
    paymentCategory,
    paymentRail,
    providerCode: String(request.providerCode || metadata.providerCode || metadata.provider_code || '').trim() || null,
    settlementPolicy: 'paysafe_hold_required',
  };
};

const isGuestPaySafeCheckout = (request: z.infer<typeof ServicePaymentRequestSchema>) => {
  const metadata = request.metadata || {};
  const buyer = metadata.buyer && typeof metadata.buyer === 'object'
    ? metadata.buyer as Record<string, unknown>
    : {};
  const customerType = String(request.customer?.type || buyer.type || metadata.customerType || '').toLowerCase();
  return request.operation === 'paysafe' && (
    customerType === 'guest' ||
    customerType === 'external_customer' ||
    metadataFlag(metadata, 'guestCheckout', 'guest_checkout')
  );
};

const createGuestEscrowParticipant = async (
  sb: NonNullable<ReturnType<typeof getAdminSupabase> | ReturnType<typeof getSupabase>>,
  request: z.infer<typeof ServicePaymentRequestSchema>,
  merchantContext: Awaited<ReturnType<typeof resolveServiceMerchantContext>>,
) => {
  const metadata = request.metadata || {};
  const buyer = metadata.buyer && typeof metadata.buyer === 'object'
    ? metadata.buyer as Record<string, unknown>
    : {};
  const email = String(request.customer?.email || buyer.email || '').trim().toLowerCase();
  const phone = normalizePhoneCandidate(String(request.customer?.phone || buyer.phone || ''));
  const shopOrderId = stringFromMetadata(metadata, 'shopOrderId', 'orderId', 'order_id') || request.reference;
  const { data, error } = await sb
    .from('guest_escrow_participants')
    .upsert({
      service_code: request.serviceCode,
      reference: request.reference,
      payment_intent_id: request.intentId,
      shop_order_id: shopOrderId,
      merchant_id: merchantContext?.merchant?.id || null,
      merchant_wallet_id: merchantContext?.escrowWallet?.id || null,
      display_name: String(request.customer?.name || buyer.name || 'Guest buyer').trim(),
      email_hash: hashGuestIdentifier(email),
      phone_hash: hashGuestIdentifier(phone),
      email_hint: maskEmail(email),
      phone_hint: maskPhone(phone),
      verification_status: 'unverified',
      refund_policy: 'original_payment_method_only',
      metadata: {
        source: 'paysafe_guest_checkout',
        serviceCode: request.serviceCode,
        reference: request.reference,
        shopOrderId,
        checkoutUrl: request.checkoutUrl || null,
        paymentProduct: metadata.paymentProduct || 'paysafe',
        paySafeAction: metadata.paySafeAction || 'create_escrow',
        guestCheckout: true,
        refundPolicy: 'original_payment_method_only',
      },
      updated_at: new Date().toISOString(),
    }, {
      onConflict: 'service_code,reference',
    })
    .select('id,service_code,reference,shop_order_id,merchant_id,merchant_wallet_id,verification_status,refund_policy')
    .single();
  if (error) throw error;
  return data;
};

const findServicePaymentCustomer = async (customer: z.infer<typeof ServicePaymentRequestSchema>['customer']) => {
  const sb = getAdminSupabase() || getSupabase();
  if (!sb) throw new Error('DB_OFFLINE');
  const userId = String(customer?.userId || '').trim();
  const customerId = String((customer as Record<string, unknown> | undefined)?.customerId || '').trim();
  const email = String(customer?.email || '').trim().toLowerCase();
  const phone = normalizePhoneCandidate(customer?.phone);

  if (userId && uuidPattern.test(userId)) {
    const { data, error } = await sb
      .from('users')
      .select('id, full_name, email, phone, customer_id, account_status')
      .eq('id', userId)
      .maybeSingle();
    if (error) throw error;
    if (data) return data;
  }

  if (customerId) {
    const { data, error } = await sb
      .from('users')
      .select('id, full_name, email, phone, customer_id, account_status')
      .ilike('customer_id', customerId)
      .maybeSingle();
    if (error) throw error;
    if (data) return data;
  }

  if (email) {
    const { data, error } = await sb
      .from('users')
      .select('id, full_name, email, phone, customer_id, account_status')
      .ilike('email', email)
      .maybeSingle();
    if (error) throw error;
    if (data) return data;
  }

  if (phone) {
    const { data, error } = await sb
      .from('users')
      .select('id, full_name, email, phone, customer_id, account_status')
      .or(`phone.eq.${phone},phone.eq.${phone.replace(/^\+/, '')}`)
      .limit(1)
      .maybeSingle();
    if (error) throw error;
    if (data) return data;
  }

  return null;
};

const findPaySafeBalanceUser = async (request: z.infer<typeof PaySafeBalanceRequestSchema>) =>
  request.userId || request.customerId || request.email || request.phone
    ? findServicePaymentCustomer({
        userId: request.userId,
        customerId: request.customerId,
        email: request.email,
        phone: request.phone,
      } as any)
    : null;

const numberFromDb = (value: unknown): number => {
  const parsed = Number(value || 0);
  return Number.isFinite(parsed) ? parsed : 0;
};

const referenceFromEscrow = (row: Record<string, any>): string | undefined => {
  const conditions = row.conditions && typeof row.conditions === 'object' ? row.conditions : {};
  const disputeMetadata = row.dispute_metadata && typeof row.dispute_metadata === 'object' ? row.dispute_metadata : {};
  return String(
    conditions.reference ||
      conditions.orderId ||
      conditions.order_id ||
      conditions.serviceReference ||
      disputeMetadata.reference ||
      row.transaction_id ||
      '',
  ) || undefined;
};

const buildPaySafeBalanceProjection = (user: Record<string, any>, escrows: Record<string, any>[]) => {
  const totals = new Map<string, {
    currency: string;
    incomingHeld: number;
    outgoingHeld: number;
    incomingDisputed: number;
    outgoingDisputed: number;
    releasedIncoming: number;
    refundedOutgoing: number;
    totalIncomingProtected: number;
    totalOutgoingProtected: number;
  }>();

  const ensureTotal = (currency: string) => {
    const key = currency.toUpperCase();
    if (!totals.has(key)) {
      totals.set(key, {
        currency: key,
        incomingHeld: 0,
        outgoingHeld: 0,
        incomingDisputed: 0,
        outgoingDisputed: 0,
        releasedIncoming: 0,
        refundedOutgoing: 0,
        totalIncomingProtected: 0,
        totalOutgoingProtected: 0,
      });
    }
    return totals.get(key)!;
  };

  const userId = String(user.id);
  const items = escrows.map((row) => {
    const amount = numberFromDb(row.amount);
    const currency = String(row.currency || 'TZS').toUpperCase();
    const status = String(row.status || '').toUpperCase();
    const direction = String(row.receiver_id) === userId ? 'incoming' : 'outgoing';
    const total = ensureTotal(currency);

    if (status === 'HELD') {
      if (direction === 'incoming') total.incomingHeld += amount;
      else total.outgoingHeld += amount;
    } else if (status === 'DISPUTED') {
      if (direction === 'incoming') total.incomingDisputed += amount;
      else total.outgoingDisputed += amount;
    } else if (status === 'RELEASED' && direction === 'incoming') {
      total.releasedIncoming += amount;
    } else if (status === 'REFUNDED' && direction === 'outgoing') {
      total.refundedOutgoing += amount;
    }

    total.totalIncomingProtected = total.incomingHeld + total.incomingDisputed;
    total.totalOutgoingProtected = total.outgoingHeld + total.outgoingDisputed;

    return {
      escrowId: row.id,
      transactionId: row.transaction_id || undefined,
      direction,
      amount,
      currency,
      status,
      reference: referenceFromEscrow(row),
      conditions: row.conditions || {},
      disputeMetadata: row.dispute_metadata || {},
      createdAt: row.created_at || undefined,
      updatedAt: row.updated_at || undefined,
      expiresAt: row.expires_at || undefined,
    };
  });

  return {
    user: {
      id: userId,
      displayName: user.full_name || undefined,
      email: user.email || undefined,
      phone: user.phone || undefined,
      accountStatus: user.account_status || undefined,
    },
    totals: Array.from(totals.values()),
    escrows: items,
  };
};

const stringFromMetadata = (metadata: Record<string, unknown>, ...keys: string[]): string => {
  for (const key of keys) {
    const value = metadata[key];
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return '';
};

const resolveServiceMerchantContext = async (
  sb: NonNullable<ReturnType<typeof getAdminSupabase> | ReturnType<typeof getSupabase>>,
  request: z.infer<typeof ServicePaymentRequestSchema>,
) => {
  const metadata = request.metadata || {};
  const merchantId = stringFromMetadata(metadata, 'merchantId', 'merchant_id');
  const paySafeAction = stringFromMetadata(metadata, 'paySafeAction', 'paysafe_action');
  const requireMerchant = request.operation === 'paysafe' || Boolean(metadata.requireActiveMerchant);

  if (!merchantId) {
    if (!requireMerchant) return null;
    throw new Error('MERCHANT_CONTEXT_REQUIRED');
  }

  const { data: merchant, error: merchantError } = await sb
    .from('merchants')
    .select('id,business_name,owner_user_id,status,metadata')
    .eq('id', merchantId)
    .maybeSingle();
  if (merchantError) throw merchantError;
  if (!merchant) throw new Error('MERCHANT_NOT_FOUND');
  if (String(merchant.status || '').toLowerCase() !== 'active') {
    throw new Error('MERCHANT_NOT_ACTIVE');
  }
  if (!String(merchant.owner_user_id || '').trim()) {
    throw new Error('MERCHANT_OWNER_REQUIRED');
  }

  const resolveWalletByType = async (types: string[]) => {
    const { data, error } = await sb
      .from('merchant_wallets')
      .select('id,merchant_id,owner_user_id,name,wallet_type,is_primary,balance,currency,status,metadata')
      .eq('merchant_id', merchant.id)
      .eq('status', 'active')
      .in('wallet_type', types)
      .order('is_primary', { ascending: false })
      .limit(1)
      .maybeSingle();
    if (error) throw error;
    return data;
  };

  const escrowWallet = await resolveWalletByType(['paysafe_escrow', 'escrow', 'holding']);
  const settlementWallet = await resolveWalletByType(['settlement', 'operating']);

  if (request.operation === 'paysafe' && !escrowWallet) {
    throw new Error('PAYSAFE_ESCROW_MERCHANT_WALLET_REQUIRED');
  }

  let feeQuote: Record<string, unknown> | null = null;
  if (request.amount > 0) {
    try {
      const fee = await platformFeeService.resolveFee({
        flowCode: stringFromMetadata(metadata, 'feeFlowCode', 'fee_flow_code') || 'MERCHANT_PAYMENT',
        amount: request.amount,
        currency: request.currency,
        transactionModel: 'MERCHANT_PAYMENT',
        transactionType: request.operation === 'paysafe' ? 'MERCHANT_PAYMENT' : request.operation.toUpperCase(),
        operationType: request.operation === 'paysafe'
          ? `PAYSAFE_${paySafeAction ? paySafeAction.toUpperCase() : 'ESCROW'}`
          : request.operation.toUpperCase(),
        direction: request.operation === 'refund' ? 'OUTBOUND' : 'INBOUND',
        channel: 'PAY_GATEWAY',
        metadata: {
          ...metadata,
          merchantId: merchant.id,
          serviceCode: request.serviceCode,
        },
      });
      feeQuote = {
        flowCode: fee.flowCode,
        configId: fee.configId,
        currency: fee.currency,
        amount: fee.amount,
        serviceFee: fee.serviceFee,
        taxAmount: fee.taxAmount,
        govFeeAmount: fee.govFeeAmount,
        totalFee: fee.totalFee,
        netAmount: fee.netAmount,
      };
    } catch (error: any) {
      feeQuote = {
        unresolved: true,
        error: error.message || 'FEE_QUOTE_UNAVAILABLE',
      };
    }
  }

  return {
    merchant,
    escrowWallet,
    settlementWallet,
    feeQuote,
  };
};

const resolveActiveMerchant = async (
  sb: NonNullable<ReturnType<typeof getAdminSupabase> | ReturnType<typeof getSupabase>>,
  merchantId: string,
) => {
  const { data: merchant, error } = await sb
    .from('merchants')
    .select('id,business_name,owner_user_id,status,metadata')
    .eq('id', merchantId)
    .maybeSingle();
  if (error) throw error;
  if (!merchant) throw new Error('MERCHANT_NOT_FOUND');
  if (String(merchant.status || '').toLowerCase() !== 'active') throw new Error('MERCHANT_NOT_ACTIVE');
  return merchant;
};

const flattenHeaders = (headers: Request['headers']): Record<string, string | undefined> =>
  Object.fromEntries(
    Object.entries(headers).map(([key, value]) => [
      key,
      Array.isArray(value) ? value.join(',') : value === undefined ? undefined : String(value),
    ]),
  );

export const registerInternalRoutes = (internal: Router) => {
  internal.use(createInternalWorkerMiddleware());

  internal.post('/transactions/claim', requireWorkerScope(['transactions:claim']), async (req, res) => {
    const limit = req.body.limit || 100;
    const sb = getAdminSupabase() || getSupabase();
    if (!sb) return res.status(500).json({ success: false, error: 'DB_OFFLINE' });

    try {
      const { data, error } = await sb
        .from('transactions')
        .update({ status: 'processing', updated_at: new Date().toISOString() })
        .eq('status', 'pending')
        .order('created_at', { ascending: true })
        .limit(limit)
        .select();

      if (error) throw error;
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  internal.put('/transactions/:id/resolve', requireWorkerScope(['transactions:resolve']), async (req, res) => {
    const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
    const { status } = req.body;
    const workerId = String((req as any).internalWorker?.id || req.get('x-worker-id') || `internal-route:${id}`);

    try {
      const engine = new BankingEngineService();
      if (status === 'completed') {
        const success = await engine.completeSettlement(id, undefined, workerId);
        res.json({ success });
      } else {
        const sb = getAdminSupabase() || getSupabase();
        const { error } = await sb!.from('transactions').update({ status: 'failed' }).eq('id', id);
        res.json({ success: !error });
      }
    } catch (e: any) {
      const message = String(e?.message || e || '');
      const statusCode = message.includes('CONCURRENCY_CONFLICT')
        ? 409
        : message.includes('INVALID_SETTLEMENT_STATE')
          ? 409
          : 500;
      res.status(statusCode).json({ success: false, error: message });
    }
  });

  internal.get('/transactions/reversible', requireWorkerScope(['transactions:read']), async (_req, res) => {
    const sb = getAdminSupabase() || getSupabase();
    if (!sb) return res.status(500).json({ success: false, error: 'DB_OFFLINE' });

    const fifteenMinsAgo = new Date(Date.now() - 15 * 60 * 1000).toISOString();

    try {
      const { data, error } = await sb
        .from('transactions')
        .select('*')
        .or(`status.eq.failed,and(status.eq.processing,updated_at.lt.${fifteenMinsAgo})`);

      if (error) throw error;
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  internal.post('/transactions/:id/reverse', requireWorkerScope(['transactions:reverse']), async (req, res) => {
    const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
    const { reason } = req.body;

    try {
      const sb = getAdminSupabase() || getSupabase();
      const { data: tx } = await sb!.from('transactions').select('*').eq('id', id).single();
      if (!tx) return res.status(404).json({ success: false, error: 'NOT_FOUND' });

      const { error } = await sb!
        .from('transactions')
        .update({
          status: 'reversed',
          metadata: { ...tx.metadata, reversal_reason: reason, reversed_at: new Date().toISOString() },
        })
        .eq('id', id);

      if (error) throw error;

      await Audit.log('FINANCIAL', tx.user_id, 'TRANSACTION_REVERSED', {
        txId: id,
        reason,
        ...getInternalAuditMetadata(req),
      });
      res.json({ success: true });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  internal.get('/transactions/recent', requireWorkerScope(['transactions:read']), async (req, res) => {
    const minutes = parseInt(req.query.minutes as string) || 5;
    const sb = getAdminSupabase() || getSupabase();
    const startTime = new Date(Date.now() - minutes * 60 * 1000).toISOString();

    try {
      const { data, error } = await sb!.from('transactions').select('*').gte('created_at', startTime);
      if (error) throw error;
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  internal.post('/security/anomalies', requireWorkerScope(['security:anomalies:write']), async (req, res) => {
    const { transactionId, severity, description } = req.body;
    try {
      const sb = getAdminSupabase() || getSupabase();
      const { data: tx } = await sb!.from('transactions').select('*').eq('id', transactionId).single();

      await Audit.log('FRAUD', tx?.user_id || 'SYSTEM', 'WORKER_ANOMALY_REPORTED', {
        transactionId,
        severity,
        description,
        ...getInternalAuditMetadata(req),
      });

      if (sb) {
        await sb.from('provider_anomalies').insert({
          transaction_id: transactionId,
          risk_score: severity === 'high' ? 90 : 50,
          detection_flags: ['WORKER_REPORTED'],
          status: 'OPEN',
          metadata: { description },
        });
      }
      res.json({ success: true });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  internal.get('/tasks/pending', requireWorkerScope(['tasks:read']), async (_req, res) => {
    const sb = getAdminSupabase() || getSupabase();
    try {
      const { data, error } = await sb!.from('tasks').select('*').eq('status', 'pending');
      if (error) throw error;
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  internal.put('/tasks/:id/status', requireWorkerScope(['tasks:write']), async (req, res) => {
    const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
    const { status, result } = req.body;
    try {
      const sb = getAdminSupabase() || getSupabase();
      const { error } = await sb!
        .from('tasks')
        .update({
          status,
          metadata: result ? { result } : undefined,
          updated_at: new Date().toISOString(),
        })
        .eq('id', id);
      if (error) throw error;
      res.json({ success: true });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  internal.get('/messages/queued', requireWorkerScope(['messages:read']), async (_req, res) => {
    const sb = getAdminSupabase() || getSupabase();
    try {
      const { data, error } = await sb!.from('user_messages').select('*').eq('status', 'queued');
      if (error) throw error;
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  internal.post('/offline/requests', requireWorkerScope(['offline:requests:write']), async (req, res) => {
    try {
      const result = await LogicCore.processOfflineGatewayRequest(req.body);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  internal.post('/offline/confirmations', requireWorkerScope(['offline:confirmations:write']), async (req, res) => {
    try {
      const result = await LogicCore.processOfflineGatewayConfirmation(req.body);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  internal.post('/gateway/provider-events', requireWorkerScope(['gateway:events:write']), async (req, res) => {
    const parsed = TrustedGatewayEventSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        error: 'TRUSTED_GATEWAY_EVENT_INVALID',
        issues: parsed.error.issues.map((issue) => ({
          path: issue.path.join('.'),
          message: issue.message,
        })),
      });
    }

    const workerId = String((req as any).internalWorker?.id || req.get('x-worker-id') || 'payment-gateway');

    try {
      const result = await Webhooks.handleTrustedGatewayEvent({
        ...parsed.data,
        sourceIp: req.ip,
        headers: flattenHeaders(req.headers),
      });

      await Audit.log('FINANCIAL', workerId, 'TRUSTED_GATEWAY_EVENT_RECEIVED', {
        providerId: parsed.data.providerId,
        reference: parsed.data.reference,
        status: parsed.data.status,
        providerEventId: parsed.data.providerEventId || null,
        rawStatus: parsed.data.rawStatus || null,
        ...getInternalAuditMetadata(req),
      });

      return res.json({ success: true, data: result });
    } catch (e: any) {
      const message = String(e?.message || e || 'TRUSTED_GATEWAY_EVENT_FAILED');
      const statusCode = message === 'PROVIDER_NOT_FOUND' ? 404 : message === 'DB_OFFLINE' ? 503 : 500;
      await Audit.log('FINANCIAL', workerId, 'TRUSTED_GATEWAY_EVENT_FAILED', {
        providerId: parsed.data.providerId,
        reference: parsed.data.reference,
        status: parsed.data.status,
        error: message,
        ...getInternalAuditMetadata(req),
      });
      return res.status(statusCode).json({ success: false, error: message });
    }
  });

  internal.post('/pay-gateway/service-payment-requests', requireWorkerScope(['gateway:service-payments:write']), async (req, res) => {
    const parsed = ServicePaymentRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        error: 'SERVICE_PAYMENT_REQUEST_INVALID',
        issues: parsed.error.issues.map((issue) => ({
          path: issue.path.join('.'),
          message: issue.message,
        })),
      });
    }

    const workerId = String((req as any).internalWorker?.id || req.get('x-worker-id') || 'payment-gateway');
    const request = parsed.data;
    const signedEnvironment = String((req as any).internalRequestIdentity?.environment || '');
    if (signedEnvironment !== request.environment) return res.status(403).json({ success: false, error: 'REQUEST_ENVIRONMENT_MISMATCH' });
    let event: ServicePaymentCoreEvent | null = null;
    let resolvedCustomer: Record<string, any> | null = null;

    try {
      if (request.environment === 'sandbox') {
        if (process.env.ORBI_ENABLE_SANDBOX_ROUTES !== 'true') throw new Error('SANDBOX_ROUTES_DISABLED');
        if (!request.simulationScenario) throw new Error('SANDBOX_SCENARIO_REQUIRED');
        const simulation = await gatewayPaymentIntentService.simulateSandbox({
          intentId: request.intentId, serviceCode: request.serviceCode, reference: request.reference,
          operation: request.operation, scenario: request.simulationScenario, amount: request.amount,
          currency: request.currency, requestPayload: request as unknown as Record<string, unknown>,
        });
        await Audit.log('FINANCIAL', workerId, 'SANDBOX_PAYMENT_SIMULATED', { serviceCode: request.serviceCode, intentId: request.intentId, scenario: request.simulationScenario, status: simulation.status, replayed: simulation.replayed, ...getInternalAuditMetadata(req) });
        return res.json({ success: true, data: simulation });
      }
      const paySafeFundingRoute = resolvePaySafeFundingRoute(request);
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) throw new Error('DB_OFFLINE');

      let merchantContext: Awaited<ReturnType<typeof resolveServiceMerchantContext>> = null;
      try {
        merchantContext = await resolveServiceMerchantContext(sb, request);
      } catch (merchantError: any) {
        event = {
          intentId: request.intentId,
          serviceCode: request.serviceCode,
          status: 'failed',
          message: 'Merchant account is not ready for this PaySafe/payment request.',
          raw: {
            reason: merchantError.message || 'MERCHANT_CONTEXT_INVALID',
            reference: request.reference,
            operation: request.operation,
            paySafeFundingRoute,
          },
        };
      }

      const guestPaySafeCheckout = !event && isGuestPaySafeCheckout(request);
      const customer = event || guestPaySafeCheckout ? null : await findServicePaymentCustomer(request.customer);
      resolvedCustomer = customer;
      if (!event && guestPaySafeCheckout) {
        const guestParticipant = await createGuestEscrowParticipant(sb, request, merchantContext);
        event = {
          intentId: request.intentId,
          serviceCode: request.serviceCode,
          status: 'processing',
          message: 'Guest PaySafe participant recorded. Funds remain protected in merchant escrow and guest refunds are limited to the original payment method.',
          raw: {
            reason: 'GUEST_PAYSAFE_PARTICIPANT_RECORDED',
            customerType: 'guest',
            guestParticipantId: guestParticipant.id,
            shopOrderId: guestParticipant.shop_order_id || request.reference,
            merchantId: guestParticipant.merchant_id || null,
            merchantWalletId: guestParticipant.merchant_wallet_id || null,
            refundPolicy: guestParticipant.refund_policy || 'original_payment_method_only',
            verificationStatus: guestParticipant.verification_status || 'unverified',
            operation: request.operation,
            reference: request.reference,
            amount: request.amount,
            currency: request.currency,
            paySafeFundingRoute,
            merchant: merchantContext ? {
              id: merchantContext.merchant.id,
              businessName: merchantContext.merchant.business_name,
              hasPaySafeEscrowWallet: Boolean(merchantContext.escrowWallet),
              hasSettlementWallet: Boolean(merchantContext.settlementWallet),
            } : null,
            feeQuote: merchantContext?.feeQuote || null,
          },
        };
      } else if (!event && !customer) {
        event = {
          intentId: request.intentId,
          serviceCode: request.serviceCode,
          status: 'failed',
          message: 'Customer was not found in ORBI Core.',
          raw: {
            reason: 'CUSTOMER_NOT_FOUND',
            reference: request.reference,
          },
        };
      } else if (!event && customer && !['active', 'verified'].includes(String(customer.account_status || '').toLowerCase())) {
        event = {
          intentId: request.intentId,
          serviceCode: request.serviceCode,
          status: 'failed',
          message: 'Customer account is not active for payment authorization.',
          raw: {
            reason: 'CUSTOMER_ACCOUNT_NOT_ACTIVE',
            customerId: customer.id,
            accountStatus: customer.account_status || null,
            reference: request.reference,
          },
        };
      } else if (!event && customer) {
        const challengeId = `pay_ch_${crypto.randomUUID().replace(/-/g, '')}`;
        const expiresAt = new Date(Date.now() + 3 * 60 * 1000).toISOString();
        const paySafeAction = typeof request.metadata?.paySafeAction === 'string'
          ? String(request.metadata.paySafeAction).replace(/_/g, ' ')
          : '';
        const amountLabel = request.amount > 0
          ? `${request.currency.toUpperCase()} ${request.amount}`
          : `${request.operation}${paySafeAction ? ` ${paySafeAction}` : ''}`;
        const otcContact = String(customer.phone || customer.email || '').trim();
        const otc = otcContact
          ? await OTPService.generateAndSend(
              String(customer.id),
              otcContact,
              'SERVICE_PAYMENT_AUTHORIZATION',
              customer.phone ? 'sms' : 'email',
              'ORBI payment challenge',
            )
          : null;
        if (!otc?.requestId || ['THROTTLED', 'ERROR_NO_CONTACT'].includes(String(otc.requestId))) {
          throw new Error('SERVICE_PAYMENT_OTC_DELIVERY_FAILED');
        }
        event = {
          intentId: request.intentId,
          serviceCode: request.serviceCode,
          status: 'requires_action',
          message: 'Customer authorization and OTC verification are required before ORBI Core can continue payment processing.',
          challenge: {
            type: 'OTP',
            challengeId,
            prompt: `Enter the ORBI OTC sent to you to approve ${amountLabel} for ${request.serviceCode}.`,
            expiresAt,
            delivery: {
              channel: String(otc.deliveryType || '').includes('sms')
                ? 'sms'
                : String(otc.deliveryType || '').includes('email')
                  ? 'email'
                  : 'push',
              destinationHint: otc.deliveryContact || 'registered ORBI contact',
            },
            metadata: {
              customerId: customer.id,
              reference: request.reference,
              operation: request.operation,
              otcRequired: true,
              otcRequestId: otc.requestId,
              otcDeliveryType: otc.deliveryType || null,
              otcDeliveryContact: otc.deliveryContact || null,
              paySafeFundingRoute,
              merchantId: merchantContext?.merchant?.id || null,
              merchantName: merchantContext?.merchant?.business_name || null,
              merchantEscrowWalletId: merchantContext?.escrowWallet?.id || null,
              merchantWalletsResolved: Boolean(merchantContext?.escrowWallet),
              feeQuote: merchantContext?.feeQuote || null,
            },
          },
          raw: {
            customerId: customer.id,
            customerEmail: customer.email || null,
            customerPhone: customer.phone || null,
            operation: request.operation,
            reference: request.reference,
            amount: request.amount,
            currency: request.currency,
            paySafeFundingRoute,
            merchant: merchantContext ? {
              id: merchantContext.merchant.id,
              businessName: merchantContext.merchant.business_name,
              hasPaySafeEscrowWallet: Boolean(merchantContext.escrowWallet),
              hasSettlementWallet: Boolean(merchantContext.settlementWallet),
            } : null,
            feeQuote: merchantContext?.feeQuote || null,
          },
        };
      }

      if (!event) {
        throw new Error('SERVICE_PAYMENT_EVENT_NOT_RESOLVED');
      }

      const persistence = await gatewayPaymentIntentService.persist({
        intentId: request.intentId,
        serviceCode: request.serviceCode,
        reference: request.reference,
        operation: request.operation,
        customerUserId: resolvedCustomer?.id || null,
        merchantId: merchantContext?.merchant?.id || null,
        amount: request.amount,
        currency: request.currency,
        requestPayload: request as unknown as Record<string, unknown>,
        responsePayload: event as unknown as Record<string, unknown>,
        status: event.status,
        challenge: event.challenge
          ? {
              challengeId: event.challenge.challengeId,
              type: event.challenge.type,
              expiresAt: event.challenge.expiresAt,
              metadata: event.challenge.metadata,
            }
          : undefined,
      });

      if (persistence.replayed === true && persistence.response) {
        event = persistence.response as ServicePaymentCoreEvent;
      }
      const outboxEventKey = String(persistence.outboxEventKey || '');

      if (event.status === 'requires_action' && event.challenge && resolvedCustomer?.id) {
        const merchantName = String(merchantContext?.merchant?.business_name || request.serviceCode || 'ORBI service');
        const amountText = `${request.currency.toUpperCase()} ${Number(request.amount || 0).toLocaleString('en-US')}`;
        const notificationCustomerId = String(resolvedCustomer.id);
        const notificationEvent = event;
        const notificationChallenge = event.challenge;
        dispatchServicePaymentNotificationSafely(
          () => Messaging.dispatch(
            notificationCustomerId,
            'update',
            'Approve ORBI payment request',
            `Enter your ORBI OTC to approve ${amountText} for ${merchantName}. Reference ${request.reference}.`,
            {
              push: true,
              email: false,
              sms: false,
              template: 'SERVICE_PAYMENT_AUTHORIZATION_REQUIRED',
              eventCode: 'SERVICE_PAYMENT_AUTHORIZATION_REQUIRED',
              variables: {
                amount: request.amount,
                currency: request.currency,
                serviceName: merchantName,
                reference: request.reference,
              },
              localized: {
                en: {
                  subject: 'Approve ORBI payment request',
                  body: `Enter your ORBI OTC to approve ${amountText} for ${merchantName}. Reference ${request.reference}.`,
                },
                sw: {
                  subject: 'Thibitisha ombi la malipo ya ORBI',
                  body: `Weka OTC yako ya ORBI kuthibitisha ${amountText} kwa ${merchantName}. Kumbukumbu ${request.reference}.`,
                },
              },
              metadata: {
                source: 'pay_gateway',
                category: 'service_payment_authorization',
                servicePaymentChallenge: {
                  challengeId: notificationChallenge.challengeId,
                  challengeType: notificationChallenge.type,
                  intentId: notificationEvent.intentId,
                  serviceCode: notificationEvent.serviceCode,
                  reference: request.reference,
                  amount: request.amount,
                  currency: request.currency,
                  operation: request.operation,
                  expiresAt: notificationChallenge.expiresAt,
                  merchantName,
                  otcRequired: notificationChallenge.metadata?.otcRequired === true,
                  otcRequestId: notificationChallenge.metadata?.otcRequestId || null,
                  otcDeliveryType: notificationChallenge.metadata?.otcDeliveryType || null,
                  otcDeliveryContact: notificationChallenge.metadata?.otcDeliveryContact || null,
                },
              },
            },
          ),
          {
            intentId: notificationEvent.intentId,
            serviceCode: notificationEvent.serviceCode,
            customerId: notificationCustomerId,
            reference: request.reference,
          },
        );
      }

      const gatewayDelivery = await postServicePaymentEventToPayGateway(event).catch((error: any) => ({
        attempted: true,
        delivered: false,
        error: error.message || 'PAY_GATEWAY_SERVICE_PAYMENT_EVENT_FAILED',
      }));
      if (outboxEventKey) {
        await gatewayPaymentIntentService.recordDelivery(
          outboxEventKey,
          gatewayDelivery.delivered === true,
          gatewayDelivery.delivered === true
            ? undefined
            : String(
                gatewayDelivery.error ||
                  (gatewayDelivery as Record<string, unknown>).statusCode ||
                  'DELIVERY_FAILED',
              ),
        ).catch(() => undefined);
      }

      await Audit.log('FINANCIAL', event.raw?.customerId ? String(event.raw.customerId) : workerId, 'SERVICE_PAYMENT_REQUEST_RECEIVED', {
        serviceCode: request.serviceCode,
        intentId: request.intentId,
        reference: request.reference,
        operation: request.operation,
        paymentCategory: request.paymentCategory || request.metadata?.paymentCategory || null,
        paymentRail: request.paymentRail || request.metadata?.paymentRail || null,
        providerCode: request.providerCode || request.metadata?.providerCode || null,
        amount: request.amount,
        currency: request.currency,
        coreStatus: event.status,
        durableReplay: persistence.replayed === true,
        outboxEventKey: outboxEventKey || null,
        gatewayDelivery,
        ...getInternalAuditMetadata(req),
      });

      return res.json({
        success: true,
        data: {
          ...event,
          gatewayDelivery,
        },
      });
    } catch (e: any) {
      const message = String(e?.message || e || 'SERVICE_PAYMENT_REQUEST_FAILED');
      await Audit.log('FINANCIAL', workerId, 'SERVICE_PAYMENT_REQUEST_FAILED', {
        serviceCode: request.serviceCode,
        intentId: request.intentId,
        reference: request.reference,
        error: message,
        ...getInternalAuditMetadata(req),
      });
      return res.status(message === 'DB_OFFLINE' ? 503 : 500).json({ success: false, error: message });
    }
  });

  internal.post('/pay-gateway/service-payment-challenges/:challengeId/respond', requireWorkerScope(['gateway:service-payments:write', 'gateway:service-payments:result']), async (req, res) => {
    const workerId = String((req as any).internalWorker?.id || req.get('x-worker-id') || 'payment-gateway');
    const challengeId = String(req.params.challengeId || '').trim();
    let decision: 'approve' | 'reject';
    try {
      decision = normalizeChallengeDecision(req.body?.decision || req.body?.action || req.body?.status);
    } catch (e: any) {
      return res.status(400).json({ success: false, error: e.message });
    }

    try {
      const idempotencyKey = String(
        req.get('idempotency-key') ||
          req.get('x-idempotency-key') ||
          req.body?.idempotencyKey ||
          req.body?.idempotency_key ||
          '',
      ).trim();
      if (idempotencyKey.length < 8) {
        return res.status(400).json({ success: false, error: 'IDEMPOTENCY_KEY_REQUIRED' });
      }

      const challengeRecord = await gatewayPaymentIntentService.getChallengeForGateway(challengeId);
      const userId = String(challengeRecord.challenge.customer_user_id || '').trim();
      if (!userId) throw new Error('GATEWAY_CHALLENGE_CUSTOMER_REQUIRED');
      const challengeMetadata = challengeRecord.challenge?.metadata || {};
      const challengeStatus = String(challengeRecord.challenge.status || '').toUpperCase();
      const isTerminalReplay = ['VERIFIED', 'REJECTED', 'EXPIRED', 'CANCELLED'].includes(challengeStatus);
      if (decision === 'approve' && !isTerminalReplay && challengeMetadata.otcRequired === true) {
        const otcRequestId = String(
          req.body?.otcRequestId ||
            req.body?.otpRequestId ||
            req.body?.requestId ||
            req.body?.otc_request_id ||
            req.body?.otp_request_id ||
            challengeMetadata.otcRequestId ||
            '',
        ).trim();
        const otcCode = String(
          req.body?.otcCode ||
            req.body?.otpCode ||
            req.body?.otc_code ||
            req.body?.otp_code ||
            req.body?.code ||
            req.body?.pin ||
            '',
        ).trim();
        if (!otcRequestId || !otcCode) {
          return res.status(400).json({
            success: false,
            error: 'SERVICE_PAYMENT_OTC_REQUIRED',
            message: 'Enter the OTC sent to the customer registered ORBI contact.',
          });
        }
        const verified = await OTPService.verify(otcRequestId, otcCode, userId);
        if (!verified) {
          return res.status(403).json({
            success: false,
            error: 'SERVICE_PAYMENT_OTC_INVALID',
            message: 'The OTC is invalid or expired.',
          });
        }
      }

      const response = await gatewayPaymentIntentService.respondToChallenge({
        challengeId,
        userId,
        decision,
        idempotencyKey,
        metadata: {
          channel: 'hosted_gateway_challenge',
          otc_verified_at: decision === 'approve' && challengeMetadata.otcRequired === true
            ? new Date().toISOString()
            : null,
          worker_id: workerId,
          app_id: req.get('x-orbi-app-id') || null,
        },
      });

      let event = response.event;
      if (decision === 'approve') {
        const alreadyHeld = response.replayed === true && (
          String(event.status || '').toLowerCase() === 'completed' ||
          String(event.transactionId || '').trim().length > 0 ||
          String((event.raw || {}).status || '').toLowerCase() === 'payment_held'
        );
        try {
          if (alreadyHeld) {
            await Audit.log('FINANCIAL', userId, 'SERVICE_PAYMENT_HOSTED_CHALLENGE_HOLD_REPLAYED', {
              challengeId,
              decision,
              intentId: event.intentId,
              serviceCode: event.serviceCode,
              workerId,
              ...getInternalAuditMetadata(req),
            }).catch(() => undefined);
          } else {
          const hold = await completeApprovedServiceChallengeWithPaySafeHold(
            userId,
            response,
          );
          event = {
            ...event,
            status: 'completed',
            message: 'ORBI PaySafe hold created successfully.',
            transactionId: hold.paysafeReferenceId,
            raw: {
              ...(event.raw || {}),
              status: 'payment_held',
              paysafeReferenceId: hold.paysafeReferenceId,
              merchantId: hold.merchant.id,
              merchantName: hold.merchant.business_name || null,
              reference: hold.reference,
              amount: hold.amount,
              currency: hold.currency,
            },
          };
          await gatewayPaymentIntentService.updateIntentEvent(event.intentId, event, 'COMPLETED');
          }
        } catch (holdError: any) {
          event = {
            ...event,
            status: 'failed',
            message: holdError.message || 'ORBI PaySafe hold failed after authorization.',
            raw: {
              ...(event.raw || {}),
              status: 'payment_hold_failed',
              error: holdError.message || 'PAYSAFE_HOLD_FAILED',
            },
          };
          await gatewayPaymentIntentService.updateIntentEvent(event.intentId, event, 'FAILED').catch(() => undefined);
        }
      }

      const gatewayDelivery = await gatewayPaymentIntentService
        .deliverServicePaymentEvent(event)
        .catch((error: any) => ({
          attempted: true,
          delivered: false,
          error: error.message || 'PAY_GATEWAY_SERVICE_PAYMENT_EVENT_FAILED',
        }));

      await Audit.log('FINANCIAL', userId, 'SERVICE_PAYMENT_HOSTED_CHALLENGE_RESPONDED', {
        challengeId,
        decision,
        intentId: event.intentId,
        serviceCode: event.serviceCode,
        gatewayDelivery,
        replayed: response.replayed === true,
        workerId,
        ...getInternalAuditMetadata(req),
      });

      return res.json({
        success: true,
        data: {
          ...response.event,
          ...event,
          gatewayDelivery,
          replayed: response.replayed === true,
        },
      });
    } catch (e: any) {
      const message = e.message || 'SERVICE_CHALLENGE_RESPONSE_FAILED';
      await Audit.log('FINANCIAL', workerId, 'SERVICE_PAYMENT_HOSTED_CHALLENGE_RESPONSE_FAILED', {
        challengeId,
        decision,
        error: message,
        ...getInternalAuditMetadata(req),
      }).catch(() => undefined);
      return res.status(quoteErrorStatus(message)).json({ success: false, error: message });
    }
  });

  internal.post('/pay-gateway/notifications/push', requireWorkerScope(['gateway:notifications:push']), async (req, res) => {
    const parsed = PayGatewayPushRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: 'PUSH_NOTIFICATION_REQUEST_INVALID' });
    }
    const signedEnvironment = String((req as any).internalRequestIdentity?.environment || '');
    if (signedEnvironment !== parsed.data.environment) {
      return res.status(403).json({ success: false, error: 'PUSH_NOTIFICATION_ENVIRONMENT_MISMATCH' });
    }
    const sb = getAdminSupabase();
    if (!sb) return res.status(503).json({ success: false, error: 'IDENTITY_STORE_UNAVAILABLE' });
    const userResult = await sb.from('users').select('fcm_token, notif_push').eq('id', parsed.data.userId).maybeSingle();
    const staffResult = userResult.data ? null : await sb.from('staff').select('fcm_token, notif_push').eq('id', parsed.data.userId).maybeSingle();
    const profile = userResult.data || staffResult?.data;
    if (!profile) return res.status(404).json({ success: false, error: 'PUSH_RECIPIENT_NOT_FOUND' });
    if (profile.notif_push === false) return res.status(409).json({ success: false, error: 'PUSH_RECIPIENT_OPTED_OUT' });
    if (!profile.fcm_token) return res.status(409).json({ success: false, error: 'PUSH_DEVICE_TOKEN_MISSING' });

    const receipt = await firebasePushService.sendWithReceipt({
      token: profile.fcm_token,
      title: parsed.data.title,
      body: parsed.data.body,
      data: { ...parsed.data.data, eventId: parsed.data.eventId, event_origin: 'ORBI_PAY_GATEWAY' },
      requestId: parsed.data.eventId,
    });
    await Audit.log('SECURITY', parsed.data.userId, 'PAY_GATEWAY_PUSH_DELIVERY_ATTEMPTED', {
      eventId: parsed.data.eventId,
      status: receipt.status,
      providerMessageId: receipt.messageId || null,
      ...getInternalAuditMetadata(req),
    }).catch(() => undefined);
    const statusCode = receipt.status === 'sent' ? 200 : receipt.status === 'invalid_token' ? 410 : 503;
    return res.status(statusCode).json({ success: receipt.status === 'sent', data: receipt });
  });

  internal.post('/pay-gateway/identity-resolve', requireWorkerScope(['gateway:identity:read']), async (req, res) => {
    const parsed = IdentityResolveRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        error: 'IDENTITY_RESOLVE_REQUEST_INVALID',
        issues: parsed.error.issues.map((issue) => ({
          path: issue.path.join('.'),
          message: issue.message,
        })),
      });
    }

    const workerId = String((req as any).internalWorker?.id || req.get('x-worker-id') || 'payment-gateway');
    const identifier = parsed.data.identifier.trim();
    const identifierIsEmail = identifier.includes('@');
    const identifierIsUuid = uuidPattern.test(identifier);
    const resolvedPublicProfile = identifierIsUuid
      ? null
      : await Identity.lookupUser(identifier).catch((error: any) => {
          throw error;
        });
    const customer = resolvedPublicProfile
      ? await findServicePaymentCustomer({ userId: resolvedPublicProfile.id } as any)
      : await findServicePaymentCustomer({ userId: identifierIsUuid ? identifier : undefined } as any);

    if (!customer) {
      await Audit.log('FINANCIAL', workerId, 'PAY_GATEWAY_IDENTITY_RESOLVE_NOT_FOUND', {
        serviceCode: parsed.data.serviceCode,
        identifierType: identifierIsEmail ? 'email' : identifierIsUuid ? 'user_id' : 'public_identifier',
        ...getInternalAuditMetadata(req),
      });
      return res.status(404).json({ success: false, error: 'IDENTITY_NOT_FOUND' });
    }

    const activeForPayments = ['active', 'verified'].includes(String(customer.account_status || '').toLowerCase());
    await Audit.log('FINANCIAL', customer.id, 'PAY_GATEWAY_IDENTITY_RESOLVED', {
      serviceCode: parsed.data.serviceCode,
      activeForPayments,
      ...getInternalAuditMetadata(req),
    });

    return res.json({
      success: true,
      data: {
        id: customer.id,
        customerId: customer.customer_id || null,
        displayName: customer.full_name || null,
        emailHint: maskEmail(customer.email) || null,
        phoneHint: maskPhone(customer.phone) || null,
        activeForPayments,
      },
    });
  });

  internal.post('/pay-gateway/business/registrations', requireWorkerScope(['gateway:business-registration:write']), async (req, res) => {
    const parsed = BusinessRegistrationRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        error: 'BUSINESS_REGISTRATION_REQUEST_INVALID',
        issues: parsed.error.issues.map((issue) => ({
          path: issue.path.join('.'),
          message: issue.message,
        })),
      });
    }

    const workerId = String((req as any).internalWorker?.id || req.get('x-worker-id') || 'payment-gateway');
    const body = parsed.data;

    try {
      const result = await BusinessIdentity.submitGatewayBusinessRegistration({
        serviceCode: body.serviceCode,
        userId: body.userId,
        email: body.email,
        phone: body.phone,
        requestedRole: body.requestedRole || body.requested_role,
        businessName: body.businessName || body.business_name,
        externalBusinessId: body.externalBusinessId,
        note: body.note,
        submittedVia: 'pay_gateway_business_registration',
        metadata: body.metadata || {},
      }, workerId);

      await Audit.log('ADMIN', workerId, 'PAY_GATEWAY_BUSINESS_REGISTRATION_SUBMITTED', {
        serviceCode: body.serviceCode,
        requestId: result.request?.id,
        alreadyPending: result.alreadyPending,
        externalBusinessId: body.externalBusinessId || null,
        ...getInternalAuditMetadata(req),
      });

      return res.status(result.alreadyPending ? 200 : 201).json({
        success: true,
        data: result,
      });
    } catch (e: any) {
      const message = String(e?.message || 'BUSINESS_REGISTRATION_FAILED');
      await Audit.log('ADMIN', workerId, 'PAY_GATEWAY_BUSINESS_REGISTRATION_FAILED', {
        serviceCode: body.serviceCode,
        error: message,
        externalBusinessId: body.externalBusinessId || null,
        ...getInternalAuditMetadata(req),
      }).catch(() => undefined);
      return res.status(quoteErrorStatus(message)).json({ success: false, error: message });
    }
  });

  internal.post('/pay-gateway/payment-profiles', requireWorkerScope(['gateway:payment-profiles:write']), async (req, res) => {
    const parsed = PaymentProfileRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        error: 'PAYMENT_PROFILE_REQUEST_INVALID',
        issues: parsed.error.issues.map((issue) => ({
          path: issue.path.join('.'),
          message: issue.message,
        })),
      });
    }

    const workerId = String((req as any).internalWorker?.id || req.get('x-worker-id') || 'payment-gateway');
    const body = parsed.data;

    try {
      const result = await PaymentProfileService.createOrLink({
        serviceCode: body.serviceCode,
        userId: body.userId,
        customerId: body.customerId,
        email: body.email,
        phone: body.phone,
        externalCustomerId: body.externalCustomerId,
        scopes: body.scopes,
        consent: body.consent,
        metadata: body.metadata,
        expiresAt: body.expiresAt,
        idempotencyKey: body.idempotencyKey,
        createdByWorkerId: workerId,
      });

      await Audit.log('FINANCIAL', result.profile.userId || workerId, 'PAY_GATEWAY_PAYMENT_PROFILE_CREATED', {
        serviceCode: body.serviceCode,
        paymentProfileId: result.profile.paymentProfileId,
        externalCustomerId: body.externalCustomerId || null,
        scopes: body.scopes,
        replayed: result.replayed,
        ...getInternalAuditMetadata(req),
      });

      return res.status(result.replayed ? 200 : 201).json({
        success: true,
        data: result,
      });
    } catch (e: any) {
      const message = String(e?.message || 'PAYMENT_PROFILE_CREATE_FAILED');
      await Audit.log('FINANCIAL', workerId, 'PAY_GATEWAY_PAYMENT_PROFILE_FAILED', {
        serviceCode: body.serviceCode,
        error: message,
        externalCustomerId: body.externalCustomerId || null,
        ...getInternalAuditMetadata(req),
      }).catch(() => undefined);
      return res.status(quoteErrorStatus(message)).json({ success: false, error: message });
    }
  });

  internal.post('/pay-gateway/paysafe-balances', requireWorkerScope(['gateway:paysafe-balances:read']), async (req, res) => {
    const parsed = PaySafeBalanceRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        error: 'PAYSAFE_BALANCE_REQUEST_INVALID',
        issues: parsed.error.issues.map((issue) => ({
          path: issue.path.join('.'),
          message: issue.message,
        })),
      });
    }

    const workerId = String((req as any).internalWorker?.id || req.get('x-worker-id') || 'payment-gateway');
    const request = parsed.data;

    try {
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });

      const user = await findPaySafeBalanceUser(request);
      const userScoped = Boolean(request.userId || request.email || request.phone);
      if (userScoped && !user) {
        await Audit.log('FINANCIAL', workerId, 'PAYSAFE_BALANCE_QUERY_USER_NOT_FOUND', {
          serviceCode: request.serviceCode,
          userId: request.userId || null,
          emailProvided: Boolean(request.email),
          phoneProvided: Boolean(request.phone),
          ...getInternalAuditMetadata(req),
        });
        return res.status(404).json({ success: false, error: 'PAYSAFE_USER_NOT_FOUND' });
      }

      const merchantId = request.merchantId || stringFromMetadata(request.metadata || {}, 'merchantId', 'merchant_id');
      if (!merchantId) {
        return res.status(400).json({ success: false, error: 'PAYSAFE_MERCHANT_CONTEXT_REQUIRED' });
      }

      const merchant = await resolveActiveMerchant(sb, merchantId);

      const activeStatuses = ['HELD', 'DISPUTED'];
      const historicalStatuses = ['HELD', 'DISPUTED', 'RELEASED', 'REFUNDED'];
      const statuses = request.includeHistory ? historicalStatuses : activeStatuses;
      let query = sb
        .from('escrow_agreements')
        .select('id,transaction_id,sender_id,receiver_id,amount,currency,conditions,status,dispute_metadata,expires_at,created_at,updated_at')
        .contains('conditions', { merchantId })
        .in('status', statuses)
        .order('created_at', { ascending: false })
        .limit(request.includeHistory ? 100 : 50);
      if (user) {
        query = query.or(`sender_id.eq.${user.id},receiver_id.eq.${user.id}`);
      }
      const { data, error } = await query;

      if (error) throw error;

      const projection = user
        ? buildPaySafeBalanceProjection(user, data || [])
        : {
            user: null,
            totals: buildPaySafeBalanceProjection({ id: merchant.owner_user_id || '00000000-0000-0000-0000-000000000000' }, data || []).totals,
            escrows: (data || []).map((row: Record<string, any>) => ({
              escrowId: row.id,
              transactionId: row.transaction_id || undefined,
              direction: String(row.receiver_id) === String(merchant.owner_user_id) ? 'incoming' : 'outgoing',
              amount: numberFromDb(row.amount),
              currency: String(row.currency || 'TZS').toUpperCase(),
              status: String(row.status || '').toUpperCase(),
              reference: referenceFromEscrow(row),
              conditions: row.conditions || {},
              disputeMetadata: row.dispute_metadata || {},
              createdAt: row.created_at || undefined,
              updatedAt: row.updated_at || undefined,
              expiresAt: row.expires_at || undefined,
            })),
          };
      await Audit.log('FINANCIAL', user ? String(user.id) : String(merchant.owner_user_id || workerId), 'PAYSAFE_BALANCE_QUERY_READ', {
        serviceCode: request.serviceCode,
        includeHistory: request.includeHistory,
        escrowCount: projection.escrows.length,
        totals: projection.totals.map((total) => ({
          currency: total.currency,
          incomingHeld: total.incomingHeld,
          incomingDisputed: total.incomingDisputed,
          outgoingHeld: total.outgoingHeld,
          outgoingDisputed: total.outgoingDisputed,
        })),
        merchantId,
        ...getInternalAuditMetadata(req),
      });

      return res.json({
        success: true,
        data: {
          serviceCode: request.serviceCode,
          merchant: {
            id: merchant.id,
            businessName: merchant.business_name,
          },
          ...projection,
        },
      });
    } catch (e: any) {
      const message = String(e?.message || e || 'PAYSAFE_BALANCE_QUERY_FAILED');
      await Audit.log('FINANCIAL', workerId, 'PAYSAFE_BALANCE_QUERY_FAILED', {
        serviceCode: request.serviceCode,
        userId: request.userId || null,
        error: message,
        ...getInternalAuditMetadata(req),
      });
      return res.status(message === 'DB_OFFLINE' ? 503 : 500).json({ success: false, error: message });
    }
  });

  internal.post('/pay-gateway/merchant-order-payment-status', requireWorkerScope(['gateway:merchant-payments:read']), async (req, res) => {
    const parsed = MerchantOrderPaymentStatusRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        error: 'MERCHANT_ORDER_PAYMENT_STATUS_REQUEST_INVALID',
        issues: parsed.error.issues.map((issue) => ({ path: issue.path.join('.'), message: issue.message })),
      });
    }

    const workerId = String((req as any).internalWorker?.id || req.get('x-worker-id') || 'payment-gateway');
    const request = parsed.data;
    try {
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const merchant = await resolveActiveMerchant(sb, request.merchantId);
      const orderId = request.orderId;

      const { data: escrows, error: escrowError } = await sb
        .from('escrow_agreements')
        .select('id,transaction_id,sender_id,receiver_id,amount,currency,conditions,status,dispute_metadata,expires_at,created_at,updated_at')
        .contains('conditions', { merchantId: request.merchantId, orderId })
        .order('created_at', { ascending: false })
        .limit(20);
      if (escrowError) throw escrowError;

      const transactionIds = (escrows || [])
        .map((row: any) => row.transaction_id)
        .filter(Boolean);
      const { data: merchantTransactions, error: mtError } = transactionIds.length
        ? await sb
            .from('merchant_transactions')
            .select('id,transaction_id,merchant_id,merchant_wallet_id,customer_user_id,direction,amount,currency,status,service_type,metadata,created_at,updated_at')
            .eq('merchant_id', request.merchantId)
            .in('transaction_id', transactionIds)
        : { data: [], error: null } as any;
      if (mtError) throw mtError;

      const latestEscrow = (escrows || [])[0] || null;
      const paymentStatus = latestEscrow
        ? String(latestEscrow.status || '').toLowerCase()
        : merchantTransactions?.[0]?.status || 'not_found';

      await Audit.log('FINANCIAL', String(merchant.owner_user_id || workerId), 'MERCHANT_ORDER_PAYMENT_STATUS_READ', {
        serviceCode: request.serviceCode,
        merchantId: request.merchantId,
        orderId,
        paymentStatus,
        escrowCount: escrows?.length || 0,
        ...getInternalAuditMetadata(req),
      });

      return res.json({
        success: true,
        data: {
          serviceCode: request.serviceCode,
          merchant: {
            id: merchant.id,
            businessName: merchant.business_name,
          },
          orderId,
          paymentStatus,
          escrows: (escrows || []).map((row: Record<string, any>) => ({
            escrowId: row.id,
            transactionId: row.transaction_id || undefined,
            amount: numberFromDb(row.amount),
            currency: String(row.currency || 'TZS').toUpperCase(),
            status: String(row.status || '').toUpperCase(),
            reference: referenceFromEscrow(row),
            conditions: row.conditions || {},
            disputeMetadata: row.dispute_metadata || {},
            createdAt: row.created_at || undefined,
            updatedAt: row.updated_at || undefined,
            expiresAt: row.expires_at || undefined,
          })),
          merchantTransactions: merchantTransactions || [],
        },
      });
    } catch (e: any) {
      const message = String(e?.message || e || 'MERCHANT_ORDER_PAYMENT_STATUS_FAILED');
      await Audit.log('FINANCIAL', workerId, 'MERCHANT_ORDER_PAYMENT_STATUS_FAILED', {
        serviceCode: request.serviceCode,
        merchantId: request.merchantId,
        orderId: request.orderId,
        error: message,
        ...getInternalAuditMetadata(req),
      });
      const status = message === 'MERCHANT_NOT_FOUND' ? 404 : message === 'MERCHANT_NOT_ACTIVE' ? 403 : 500;
      return res.status(status).json({ success: false, error: message });
    }
  });

  internal.post('/pay-gateway/merchant-settlements', requireWorkerScope(['gateway:merchant-settlements:read']), async (req, res) => {
    const parsed = MerchantSettlementsRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        error: 'MERCHANT_SETTLEMENTS_REQUEST_INVALID',
        issues: parsed.error.issues.map((issue) => ({ path: issue.path.join('.'), message: issue.message })),
      });
    }

    const workerId = String((req as any).internalWorker?.id || req.get('x-worker-id') || 'payment-gateway');
    const request = parsed.data;
    try {
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const merchant = await resolveActiveMerchant(sb, request.merchantId);

      let query = sb
        .from('merchant_settlement_reports')
        .select('id,merchant_id,owner_user_id,period_start,period_end,currency,gross_amount,fee_amount,net_amount,transaction_count,status,metadata,created_at,updated_at')
        .eq('merchant_id', request.merchantId)
        .order('period_end', { ascending: false })
        .range(request.offset, request.offset + request.limit - 1);
      if (request.currency) query = query.eq('currency', request.currency.toUpperCase());
      if (request.status) query = query.eq('status', request.status);
      const { data, error } = await query;
      if (error) throw error;

      await Audit.log('FINANCIAL', String(merchant.owner_user_id || workerId), 'MERCHANT_SETTLEMENTS_READ', {
        serviceCode: request.serviceCode,
        merchantId: request.merchantId,
        count: data?.length || 0,
        ...getInternalAuditMetadata(req),
      });

      return res.json({
        success: true,
        data: {
          serviceCode: request.serviceCode,
          merchant: {
            id: merchant.id,
            businessName: merchant.business_name,
          },
          settlements: data || [],
        },
      });
    } catch (e: any) {
      const message = String(e?.message || e || 'MERCHANT_SETTLEMENTS_FAILED');
      await Audit.log('FINANCIAL', workerId, 'MERCHANT_SETTLEMENTS_FAILED', {
        serviceCode: request.serviceCode,
        merchantId: request.merchantId,
        error: message,
        ...getInternalAuditMetadata(req),
      });
      const status = message === 'MERCHANT_NOT_FOUND' ? 404 : message === 'MERCHANT_NOT_ACTIVE' ? 403 : 500;
      return res.status(status).json({ success: false, error: message });
    }
  });

  internal.put('/messages/:id/status', requireWorkerScope(['messages:write']), async (req, res) => {
    const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
    const { status } = req.body;
    try {
      const sb = getAdminSupabase() || getSupabase();
      const { error } = await sb!
        .from('user_messages')
        .update({
          status,
          sent_at: status === 'sent' ? new Date().toISOString() : undefined,
        })
        .eq('id', id);
      if (error) throw error;
      res.json({ success: true });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  internal.post('/email/test', requireWorkerScope(['email:test']), async (req, res) => {
    const to = String(req.body?.to || '').trim();
    if (!to || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to)) {
      return res.status(400).json({
        success: false,
        error: 'EMAIL_RECIPIENT_INVALID',
      });
    }

    try {
      const result = await LogicCore.testEmail(to);
      return res.status(result.success ? 200 : 502).json(result);
    } catch (e: any) {
      return res.status(500).json({ success: false, error: e.message || 'EMAIL_TEST_FAILED' });
    }
  });

  internal.get('/email/verify', requireWorkerScope(['email:verify']), async (_req, res) => {
    try {
      const result = await LogicCore.verifyEmailConfig();
      return res.status(result.success ? 200 : 503).json(result);
    } catch (e: any) {
      return res.status(500).json({ success: false, error: e.message || 'EMAIL_VERIFY_FAILED' });
    }
  });
};

export const mountInternalRoutes = (app: Express, internal: Router) => {
  app.use('/api/internal', internal);
};
