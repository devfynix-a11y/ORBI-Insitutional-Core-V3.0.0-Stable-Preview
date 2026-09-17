import type { RequestHandler, Router } from 'express';
import {
  listRegistryBackedBillProviders,
} from '../../../backend/payments/billProviderRegistry.js';
import { gatewayPaymentIntentService } from '../../../backend/payments/GatewayPaymentIntentService.js';
import { Audit } from '../../../backend/security/audit.js';
import { OTPService } from '../../../backend/security/otpService.js';
import {
  requireIdempotencyKey,
  resolveIdempotencyHeader,
} from '../../middleware/security/idempotency.js';

function attachIdempotencyKey(req: any) {
  const idempotencyKey = resolveIdempotencyHeader(req);
  if (idempotencyKey && req.body && typeof req.body === 'object') {
    req.body.idempotencyKey = String(idempotencyKey).trim();
  }
}

async function bindSettlementPayload(LogicCore: any, session: any, req: any, payload: Record<string, any>) {
  const idempotencyKey = String(resolveIdempotencyHeader(req)).trim();
  const binding = await LogicCore.bindSettlementQuote(session.sub, payload, idempotencyKey);
  return {
    binding,
    payload: {
      ...binding.payload,
      idempotencyKey,
    },
  };
}

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

async function completeApprovedServiceChallengeWithPaySafeHold(
  deps: Pick<Deps, 'LogicCore' | 'getAdminSupabase' | 'getSupabase'>,
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

  const sb = deps.getAdminSupabase() || deps.getSupabase();
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

  const paysafeReferenceId = await deps.LogicCore.createEscrow(
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

type Deps = {
  authenticate: RequestHandler;
  validate: (schema: any) => RequestHandler;
  requireRole: (session: any, roles: string[]) => boolean;
  LogicCore: any;
  Webhooks: any;
  getAdminSupabase: () => any;
  getSupabase: () => any;
  resolveWealthSourceWallet: (sb: any, userId: string, sourceWalletId?: string) => Promise<any>;
  assertBillPaymentSourceAllowed: (sourceRecord: any) => void;
  billReserveValuesMatch: (left: any, right: any) => boolean;
  resolveBillReserveReference: (reserve: any) => string | null;
  wealthNumber: (value: any) => number;
  ServiceCustomerRegistrationSchema: any;
  PaymentIntentSchema: any;
  BillReservePaymentSchema: any;
};

export const registerCommerceRoutes = (v1: Router, deps: Deps) => {
  const {
    authenticate,
    validate,
    requireRole,
    LogicCore,
    Webhooks,
    getAdminSupabase,
    getSupabase,
    resolveWealthSourceWallet,
    assertBillPaymentSourceAllowed,
    billReserveValuesMatch,
    resolveBillReserveReference,
    wealthNumber,
    ServiceCustomerRegistrationSchema,
    PaymentIntentSchema,
    BillReservePaymentSchema,
  } = deps;

  v1.post('/webhooks/:partnerId', async (req, res) => {
    const { partnerId } = req.params;
    try {
      const signatureHeader = req.get('x-signature') || req.get('x-webhook-signature') || req.get('x-orbi-signature') || undefined;
      const eventId = req.get('x-event-id') || req.get('x-webhook-id') || req.get('x-provider-event-id') || undefined;
      await Webhooks.handleCallback(req.body, partnerId, {
        signature: signatureHeader,
        rawPayload: (req as any).rawBody,
        explicitEventId: eventId,
        headers: Object.fromEntries(
          Object.entries(req.headers).map(([key, value]) => [
            key,
            Array.isArray(value) ? value.join(',') : value ? String(value) : undefined,
          ]),
        ),
        sourceIp: req.ip,
      });
      res.json({ success: true });
    } catch (e: any) {
      console.error(`[Webhook] Error processing webhook for ${partnerId}:`, e);
      const status = ['INVALID_SIGNATURE', 'MISSING_SIGNATURE', 'WEBHOOK_SECRET_NOT_CONFIGURED', 'REPLAY_DETECTED'].includes(e.message) ? 403 : 500;
      res.status(status).json({ success: false, error: e.message });
    }
  });

  v1.get('/merchants/categories', authenticate, async (_req, res) => {
    try {
      const result = await LogicCore.getMerchantCategories();
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(quoteErrorStatus(e.message)).json({ success: false, error: e.message });
    }
  });

  v1.get('/merchants', authenticate, async (req, res) => {
    const category = req.query.category;
    try {
      const result = await LogicCore.getMerchants(category);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(quoteErrorStatus(e.message)).json({ success: false, error: e.message });
    }
  });

  v1.post('/merchants/accounts', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['MERCHANT', 'ADMIN', 'SUPER_ADMIN'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const result = await LogicCore.createMerchantAccount(session.sub, req.body);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(quoteErrorStatus(e.message)).json({ success: false, error: e.message });
    }
  });

  v1.get('/merchants/accounts/my', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['MERCHANT', 'ADMIN', 'SUPER_ADMIN'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const result = await LogicCore.getUserMerchantAccounts(session.sub);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(quoteErrorStatus(e.message)).json({ success: false, error: e.message });
    }
  });

  v1.get('/merchants/accounts/:id', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['MERCHANT', 'ADMIN', 'SUPER_ADMIN', 'AUDIT'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const privileged = requireRole(session, ['ADMIN', 'SUPER_ADMIN', 'AUDIT']);
      const result = await LogicCore.getMerchantAccountById(req.params.id, session.sub, privileged);
      if (privileged) {
        await Audit.log('SECURITY', session.sub, 'MERCHANT_ACCOUNT_PRIVILEGED_READ', {
          merchantId: req.params.id,
        });
      }
      res.json({ success: true, data: result });
    } catch (e: any) {
      const status = e.message === 'ACCESS_DENIED' ? 403 : e.message === 'MERCHANT_NOT_FOUND' ? 404 : 500;
      res.status(status).json({ success: false, error: e.message });
    }
  });

  v1.patch('/merchants/accounts/:id/settlement', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['MERCHANT', 'ADMIN', 'SUPER_ADMIN'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const privileged = requireRole(session, ['ADMIN', 'SUPER_ADMIN']);
      const result = await LogicCore.updateMerchantSettlement(req.params.id, req.body, session.sub, privileged);
      await Audit.log('SECURITY', session.sub, 'MERCHANT_SETTLEMENT_CONFIGURATION_UPDATED', {
        merchantId: req.params.id,
        privileged,
      });
      res.json({ success: true, data: result });
    } catch (e: any) {
      const status = e.message === 'ACCESS_DENIED' ? 403 : e.message === 'MERCHANT_NOT_FOUND' ? 404 : 500;
      res.status(status).json({ success: false, error: e.message });
    }
  });

  v1.get('/merchant/transactions', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['MERCHANT', 'ADMIN', 'SUPER_ADMIN', 'AUDIT'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    const limit = Number(req.query.limit || 50);
    const offset = Number(req.query.offset || 0);
    try {
      const result = await LogicCore.getMerchantTransactions(session.sub, limit, offset);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/merchant/wallets', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['MERCHANT', 'ADMIN', 'SUPER_ADMIN', 'AUDIT'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const result = await LogicCore.getMerchantWallets(session.sub);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/merchant/customers/register', authenticate, validate(ServiceCustomerRegistrationSchema), async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['MERCHANT', 'ADMIN', 'SUPER_ADMIN'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const result = await LogicCore.registerCustomerByServiceActor(session.user, 'MERCHANT', req.body);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.get('/merchant/customers', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['MERCHANT', 'ADMIN', 'SUPER_ADMIN', 'AUDIT'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const result = await LogicCore.getServiceLinkedCustomers(session.sub, 'MERCHANT');
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/payments/service-challenges', authenticate, async (req, res) => {
    const session = (req as any).session;
    try {
      const items = await gatewayPaymentIntentService.listPendingChallengesForUser(session.sub);
      return res.json({ success: true, data: { items } });
    } catch (e: any) {
      const message = e.message || 'SERVICE_CHALLENGE_LIST_FAILED';
      return res.status(quoteErrorStatus(message)).json({ success: false, error: message });
    }
  });

  v1.post('/payments/service-challenges/:challengeId/respond', authenticate, requireIdempotencyKey, async (req, res) => {
    const session = (req as any).session;
    let decision: 'approve' | 'reject';
    try {
      decision = normalizeChallengeDecision(req.body?.decision || req.body?.action || req.body?.status);
    } catch (e: any) {
      return res.status(400).json({ success: false, error: e.message });
    }

    try {
      const idempotencyKey = String(resolveIdempotencyHeader(req)).trim();
      const challengeId = String(req.params.challengeId || '').trim();
      const pending = await gatewayPaymentIntentService.getPendingChallengeForUser(
        challengeId,
        session.sub,
      );
      const challengeMetadata = pending.challenge?.metadata || {};
      if (decision === 'approve' && challengeMetadata.otcRequired === true) {
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
            message: 'Enter the OTC sent to your registered ORBI contact.',
          });
        }
        const verified = await OTPService.verify(otcRequestId, otcCode, session.sub);
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
        userId: session.sub,
        decision,
        idempotencyKey,
        metadata: {
          channel: 'mobile_app',
          otc_verified_at: decision === 'approve' && challengeMetadata.otcRequired === true
            ? new Date().toISOString()
            : null,
          device_id: req.get('x-device-id') || req.get('x-orbi-device-id') || null,
          app_id: req.get('x-orbi-app-id') || null,
        },
      });

      let event = response.event;
      if (decision === 'approve') {
        try {
          const hold = await completeApprovedServiceChallengeWithPaySafeHold(
            { LogicCore, getAdminSupabase, getSupabase },
            session.sub,
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

      await Audit.log('FINANCIAL', session.sub, 'SERVICE_PAYMENT_CHALLENGE_RESPONDED', {
        challengeId: req.params.challengeId,
        decision,
        intentId: event.intentId,
        serviceCode: event.serviceCode,
        gatewayDelivery,
        replayed: response.replayed === true,
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
      await Audit.log('FINANCIAL', session.sub, 'SERVICE_PAYMENT_CHALLENGE_RESPONSE_FAILED', {
        challengeId: req.params.challengeId,
        decision,
        error: message,
      }).catch(() => undefined);
      return res.status(quoteErrorStatus(message)).json({ success: false, error: message });
    }
  });

  v1.post('/merchant/payments/preview', authenticate, validate(PaymentIntentSchema), async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['MERCHANT', 'ADMIN', 'SUPER_ADMIN'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const result = await LogicCore.getTransactionPreview(session.sub, {
        ...req.body,
        metadata: { ...(req.body.metadata || {}), service_context: 'MERCHANT' },
      });
      if (!result.success) return res.status(400).json(result);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/merchant/payments/settle', authenticate, validate(PaymentIntentSchema), requireIdempotencyKey, async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['MERCHANT', 'ADMIN', 'SUPER_ADMIN'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const { binding, payload } = await bindSettlementPayload(LogicCore, session, req, {
        ...req.body,
        metadata: { ...(req.body.metadata || {}), service_context: 'MERCHANT' },
      });
      const result = await LogicCore.processMerchantPayment(payload, session.user);
      await LogicCore.markSettlementQuoteResult(session.sub, binding.quoteId, result);
      if (!result.success) return res.status(400).json(result);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/payments/orbi-pay/preview', authenticate, validate(PaymentIntentSchema), async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['CONSUMER', 'USER', 'MERCHANT', 'ADMIN', 'SUPER_ADMIN'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const result = await LogicCore.previewOrbiPayPayment(session.sub, req.body);
      if (!result.success) return res.status(400).json(result);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/payments/orbi-pay/settle', authenticate, validate(PaymentIntentSchema), requireIdempotencyKey, async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['CONSUMER', 'USER', 'MERCHANT', 'ADMIN', 'SUPER_ADMIN'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const { binding, payload } = await bindSettlementPayload(LogicCore, session, req, {
        ...req.body,
        type: req.body.type || 'MERCHANT_PAYMENT',
        metadata: {
          ...(req.body.metadata || {}),
          service_context: 'MERCHANT',
          payment_channel: req.body.channel || 'ORBI_PAY',
          merchant_pay_number: req.body.merchantPayNumber,
          merchant_reference: req.body.reference,
          merchant_name: req.body.merchantName,
        },
      });
      const result = await LogicCore.processOrbiPayPayment(payload, session.user);
      await LogicCore.markSettlementQuoteResult(session.sub, binding.quoteId, result);
      if (!result.success) return res.status(400).json(result);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/payments/bills/providers', authenticate, async (_req, res) => {
    try {
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const result = await listRegistryBackedBillProviders(sb);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/payments/bills/preview', authenticate, validate(PaymentIntentSchema), async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['CONSUMER', 'USER', 'MERCHANT', 'ADMIN', 'SUPER_ADMIN'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const sourceWalletId = String(req.body?.sourceWalletId || req.body?.source_wallet_id || '').trim();
      const { sourceRecord } = await resolveWealthSourceWallet(sb, session.sub, sourceWalletId || undefined);
      assertBillPaymentSourceAllowed(sourceRecord);
      const result = await LogicCore.previewBillPayment(session.sub, req.body);
      if (!result.success) return res.status(400).json(result);
      res.json({ success: true, data: result });
    } catch (e: any) {
      const status = e.message === 'GOAL_FUNDS_BILL_PAYMENT_NOT_ALLOWED' ? 400 : quoteErrorStatus(e.message);
      res.status(status).json({ success: false, error: e.message });
    }
  });

  v1.post('/payments/bills/settle', authenticate, validate(PaymentIntentSchema), requireIdempotencyKey, async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['CONSUMER', 'USER', 'MERCHANT', 'ADMIN', 'SUPER_ADMIN'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const { binding, payload } = await bindSettlementPayload(LogicCore, session, req, {
        ...req.body,
        type: req.body.type || 'BILL_PAYMENT',
        metadata: {
          ...(req.body.metadata || {}),
          service_context: 'BILL_PAYMENT',
          bill_provider: req.body.provider,
          bill_category: req.body.billCategory,
          bill_reference: req.body.reference,
        },
      });
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const sourceWalletId = String(payload?.sourceWalletId || payload?.source_wallet_id || '').trim();
      const { sourceRecord } = await resolveWealthSourceWallet(sb, session.sub, sourceWalletId || undefined);
      assertBillPaymentSourceAllowed(sourceRecord);
      const result = await LogicCore.processBillPayment(payload, session.user);
      await LogicCore.markSettlementQuoteResult(session.sub, binding.quoteId, result);
      if (!result.success) return res.status(400).json(result);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(e.message === 'GOAL_FUNDS_BILL_PAYMENT_NOT_ALLOWED' ? 400 : quoteErrorStatus(e.message)).json({ success: false, error: e.message });
    }
  });

  v1.post('/payments/bills/preview-from-reserve', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['CONSUMER', 'USER', 'MERCHANT', 'ADMIN', 'SUPER_ADMIN'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const payload = BillReservePaymentSchema.parse(req.body);
      const reserveId = String(payload.bill_reserve_id || payload.reserve_id || '').trim();
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });

      const { data: reserve, error: reserveError } = await sb.from('bill_reserves').select('*').eq('id', reserveId).eq('user_id', session.sub).single();
      if (reserveError || !reserve) return res.status(404).json({ success: false, error: 'BILL_RESERVE_NOT_FOUND' });
      if (String(reserve.status || 'ACTIVE').toUpperCase() !== 'ACTIVE' || reserve.is_active === false) {
        return res.status(400).json({ success: false, error: 'BILL_RESERVE_INACTIVE' });
      }

      const { sourceRecord } = await resolveWealthSourceWallet(sb, session.sub, String(reserve.source_wallet_id || '').trim() || undefined);
      assertBillPaymentSourceAllowed(sourceRecord);
      if (!billReserveValuesMatch(payload.provider, reserve.provider_name || reserve.provider)) {
        return res.status(400).json({ success: false, error: 'BILL_RESERVE_PROVIDER_MISMATCH' });
      }
      if (payload.billCategory && reserve.bill_type && !billReserveValuesMatch(payload.billCategory, reserve.bill_type)) {
        return res.status(400).json({ success: false, error: 'BILL_RESERVE_CATEGORY_MISMATCH' });
      }
      const reserveReference = resolveBillReserveReference(reserve);
      if (payload.reference && reserveReference && !billReserveValuesMatch(payload.reference, reserveReference)) {
        return res.status(400).json({ success: false, error: 'BILL_RESERVE_REFERENCE_MISMATCH' });
      }

      const lockedBalance = wealthNumber(reserve.locked_balance || reserve.reserve_amount || 0);
      if (lockedBalance < payload.amount) {
        return res.status(400).json({ success: false, error: 'BILL_RESERVE_INSUFFICIENT_BALANCE' });
      }

      res.json({
        success: true,
        data: {
          success: true,
          funding_mode: 'RESERVE',
          reserve_id: reserve.id,
          amount: payload.amount,
          totalAmount: payload.amount,
          netAmount: payload.amount,
          currency: String(payload.currency || reserve.currency || sourceRecord.currency || 'TZS').toUpperCase(),
          provider: payload.provider,
          billCategory: payload.billCategory || reserve.bill_type,
          reference: payload.reference || reserveReference,
          description: payload.description || `Bill payment from reserve: ${payload.provider}`,
          reserveBalanceBefore: lockedBalance,
          reserveBalanceAfter: lockedBalance - payload.amount,
          sourceWalletId: sourceRecord.id,
        },
      });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.post('/payments/bills/settle-from-reserve', authenticate, requireIdempotencyKey, async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['CONSUMER', 'USER', 'MERCHANT', 'ADMIN', 'SUPER_ADMIN'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      attachIdempotencyKey(req);
      const payload = BillReservePaymentSchema.parse(req.body);
      const reserveId = String(payload.bill_reserve_id || payload.reserve_id || '').trim();
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const { data, error } = await sb.rpc('settle_bill_payment_from_reserve_v1', {
        p_user_id: session.sub,
        p_reserve_id: reserveId,
        p_amount: payload.amount,
        p_currency: String(payload.currency || 'TZS').toUpperCase(),
        p_provider: payload.provider,
        p_bill_category: payload.billCategory || null,
        p_reference: payload.reference || null,
        p_description: payload.description || null,
      });
      if (error) return res.status(400).json({ success: false, error: error.message });
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.get('/agent/transactions', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['AGENT', 'ADMIN', 'SUPER_ADMIN', 'AUDIT'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    const limit = Number(req.query.limit || 50);
    const offset = Number(req.query.offset || 0);
    try {
      const result = await LogicCore.getAgentTransactions(session.sub, limit, offset);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(quoteErrorStatus(e.message)).json({ success: false, error: e.message });
    }
  });

  v1.get('/agent/wallets', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['AGENT', 'ADMIN', 'SUPER_ADMIN', 'AUDIT'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const result = await LogicCore.getAgentWallets(session.sub);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(quoteErrorStatus(e.message)).json({ success: false, error: e.message });
    }
  });

  v1.get('/agent/lookup', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['USER', 'AGENT', 'ADMIN', 'SUPER_ADMIN', 'AUDIT'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const query = String(req.query.q || '').trim();
      const result = await LogicCore.lookupAgentByCode(query);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.post('/agent/customers/register', authenticate, validate(ServiceCustomerRegistrationSchema), async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['AGENT', 'ADMIN', 'SUPER_ADMIN'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const result = await LogicCore.registerCustomerByServiceActor(session.user, 'AGENT', req.body);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.get('/agent/customers', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['AGENT', 'ADMIN', 'SUPER_ADMIN', 'AUDIT'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const result = await LogicCore.getServiceLinkedCustomers(session.sub, 'AGENT');
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(quoteErrorStatus(e.message)).json({ success: false, error: e.message });
    }
  });

  v1.get('/agent/commissions', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['AGENT', 'ADMIN', 'SUPER_ADMIN', 'AUDIT', 'ACCOUNTANT'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const result = await LogicCore.getServiceCommissions(session.sub, 'AGENT');
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(quoteErrorStatus(e.message)).json({ success: false, error: e.message });
    }
  });

  v1.post('/agent/cash/deposit/preview', authenticate, validate(PaymentIntentSchema), async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['AGENT', 'ADMIN', 'SUPER_ADMIN'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const result = await LogicCore.getTransactionPreview(session.sub, {
        ...req.body,
        type: 'DEPOSIT',
        metadata: { ...(req.body.metadata || {}), service_context: 'AGENT_CASH', cash_direction: 'deposit' },
      });
      if (!result.success) return res.status(400).json(result);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/agent/cash/deposit/settle', authenticate, validate(PaymentIntentSchema), requireIdempotencyKey, async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['AGENT', 'ADMIN', 'SUPER_ADMIN'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const { binding, payload } = await bindSettlementPayload(LogicCore, session, req, {
        ...req.body,
        type: 'DEPOSIT',
        metadata: { ...(req.body.metadata || {}), service_context: 'AGENT_CASH', cash_direction: 'deposit' },
      });
      const result = await LogicCore.processAgentCashOperation(payload, session.user, 'deposit');
      await LogicCore.markSettlementQuoteResult(session.sub, binding.quoteId, result);
      if (!result.success) return res.status(400).json(result);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/agent/cash/withdraw/preview', authenticate, validate(PaymentIntentSchema), async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['AGENT', 'ADMIN', 'SUPER_ADMIN'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const result = await LogicCore.getTransactionPreview(session.sub, {
        ...req.body,
        type: 'WITHDRAWAL',
        metadata: { ...(req.body.metadata || {}), service_context: 'AGENT_CASH', cash_direction: 'withdrawal' },
      });
      if (!result.success) return res.status(400).json(result);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/agent/cash/withdraw/settle', authenticate, validate(PaymentIntentSchema), requireIdempotencyKey, async (req, res) => {
    const session = (req as any).session;
    if (!requireRole(session, ['AGENT', 'ADMIN', 'SUPER_ADMIN'])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }
    try {
      const { binding, payload } = await bindSettlementPayload(LogicCore, session, req, {
        ...req.body,
        type: 'WITHDRAWAL',
        metadata: { ...(req.body.metadata || {}), service_context: 'AGENT_CASH', cash_direction: 'withdrawal' },
      });
      const result = await LogicCore.processAgentCashOperation(payload, session.user, 'withdrawal');
      await LogicCore.markSettlementQuoteResult(session.sub, binding.quoteId, result);
      if (!result.success) return res.status(400).json(result);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });
};
