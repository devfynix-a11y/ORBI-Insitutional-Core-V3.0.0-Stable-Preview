import crypto from 'crypto';
import { URL } from 'url';

import { getAdminSupabase } from '../supabaseClient.js';

type PersistIntentInput = {
  intentId: string;
  serviceCode: string;
  reference: string;
  operation: string;
  customerUserId?: string | null;
  merchantId?: string | null;
  amount: number;
  currency: string;
  requestPayload: Record<string, unknown>;
  responsePayload: Record<string, unknown>;
  status: string;
  challenge?: {
    challengeId: string;
    type: string;
    expiresAt?: string;
    metadata?: Record<string, unknown>;
  };
};

type ServicePaymentCoreEvent = {
  intentId: string;
  serviceCode: string;
  status: 'requires_action' | 'submitted_to_core' | 'processing' | 'pending' | 'completed' | 'failed';
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

type ChallengeDecision = 'approve' | 'reject';
type ChallengeType = NonNullable<ServicePaymentCoreEvent['challenge']>['type'];
type ChallengeResponseResult = {
  event: ServicePaymentCoreEvent;
  intent: any;
  challenge: any;
  replayed: boolean;
};

const stableSerialize = (value: unknown): string => {
  if (value === null || value === undefined) return '';
  if (typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableSerialize).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, entryValue]) => entryValue !== undefined)
    .sort(([left], [right]) => left.localeCompare(right));
  return `{${entries.map(([key, entryValue]) => `${JSON.stringify(key)}:${stableSerialize(entryValue)}`).join(',')}}`;
};

export class GatewayPaymentIntentService {
  hashRequest(payload: Record<string, unknown>): string {
    return crypto.createHash('sha256').update(stableSerialize(payload)).digest('hex');
  }

  async persist(input: PersistIntentInput) {
    const sb = getAdminSupabase();
    if (!sb) throw new Error('SERVICE_ROLE_REQUIRED');

    const { data, error } = await sb.rpc('persist_gateway_payment_intent_v1', {
      p_intent_id: input.intentId,
      p_service_code: input.serviceCode,
      p_reference: input.reference,
      p_operation: input.operation,
      p_request_hash: this.hashRequest(input.requestPayload),
      p_customer_user_id: input.customerUserId || null,
      p_merchant_id: input.merchantId || null,
      p_amount: input.amount,
      p_currency: input.currency,
      p_status: input.status,
      p_request_payload: input.requestPayload,
      p_response_payload: input.responsePayload,
      p_challenge_id: input.challenge?.challengeId || null,
      p_challenge_type: input.challenge?.type || null,
      p_challenge_expires_at: input.challenge?.expiresAt || null,
      p_challenge_metadata: input.challenge?.metadata || {},
    });

    if (error) {
      const domainError = String(error.message || '').match(/GATEWAY_[A-Z0-9_]+/)?.[0];
      throw new Error(domainError || 'GATEWAY_INTENT_PERSIST_FAILED');
    }
    return (data || {}) as Record<string, any>;
  }

  async recordDelivery(eventKey: string, delivered: boolean, errorMessage?: string) {
    const sb = getAdminSupabase();
    if (!sb || !eventKey) return;
    const { error } = await sb.rpc('record_gateway_payment_event_delivery_v1', {
      p_event_key: eventKey,
      p_delivered: delivered,
      p_error: errorMessage || null,
    });
    if (error) throw new Error('GATEWAY_EVENT_DELIVERY_RECORD_FAILED');
  }

  async simulateSandbox(input: { intentId: string; serviceCode: string; reference: string; operation: string; scenario: 'success'|'decline'|'timeout'|'requires_action'; amount: number; currency: string; requestPayload: Record<string, unknown> }) {
    const sb = getAdminSupabase();
    if (!sb) throw new Error('SERVICE_ROLE_REQUIRED');
    const { data, error } = await sb.rpc('simulate_sandbox_payment_v1', {
      p_service_code: input.serviceCode, p_intent_id: input.intentId,
      p_reference: input.reference, p_operation: input.operation, p_scenario: input.scenario,
      p_request_hash: this.hashRequest(input.requestPayload), p_amount: input.amount, p_currency: input.currency,
    });
    if (error) throw new Error(String(error.message || '').match(/SANDBOX_[A-Z0-9_]+/)?.[0] || 'SANDBOX_SIMULATION_FAILED');
    return data as ServicePaymentCoreEvent & { environment: 'sandbox'; scenario: string; simulation: true; replayed: boolean };
  }

  async listPendingChallengesForUser(userId: string) {
    const sb = getAdminSupabase();
    if (!sb) throw new Error('SERVICE_ROLE_REQUIRED');

    const { data: challenges, error } = await sb
      .from('gateway_payment_challenges')
      .select('id,challenge_id,challenge_type,status,expires_at,metadata,created_at,intent_id')
      .eq('customer_user_id', userId)
      .eq('status', 'PENDING')
      .gt('expires_at', new Date().toISOString())
      .order('created_at', { ascending: false });
    if (error) throw new Error(error.message || 'GATEWAY_CHALLENGE_LIST_FAILED');

    const intentIds = Array.from(new Set((challenges || []).map((row: any) => row.intent_id).filter(Boolean)));
    const intentByRowId: Record<string, any> = {};
    if (intentIds.length > 0) {
      const { data: intents, error: intentError } = await sb
        .from('gateway_payment_intents')
        .select('id,intent_id,service_code,reference,operation,amount,currency,status,response_payload,created_at')
        .in('id', intentIds);
      if (intentError) throw new Error(intentError.message || 'GATEWAY_INTENT_LIST_FAILED');
      for (const intent of intents || []) intentByRowId[String(intent.id)] = intent;
    }

    return (challenges || []).map((challenge: any) => ({
      id: challenge.challenge_id,
      type: challenge.challenge_type,
      status: challenge.status,
      expiresAt: challenge.expires_at,
      metadata: challenge.metadata || {},
      intent: intentByRowId[String(challenge.intent_id)] || null,
      createdAt: challenge.created_at,
    }));
  }

  async getPendingChallengeForUser(challengeId: string, userId: string) {
    const sb = getAdminSupabase();
    if (!sb) throw new Error('SERVICE_ROLE_REQUIRED');

    const { data: challenge, error } = await sb
      .from('gateway_payment_challenges')
      .select('id,challenge_id,customer_user_id,challenge_type,status,expires_at,metadata,intent_id')
      .eq('challenge_id', challengeId)
      .maybeSingle();
    if (error) throw new Error(error.message || 'GATEWAY_CHALLENGE_LOOKUP_FAILED');
    if (!challenge) throw new Error('GATEWAY_CHALLENGE_NOT_FOUND');
    if (String(challenge.customer_user_id) !== String(userId)) {
      throw new Error('GATEWAY_CHALLENGE_ACCESS_DENIED');
    }
    if (String(challenge.status) !== 'PENDING') {
      throw new Error(`GATEWAY_CHALLENGE_${String(challenge.status).toUpperCase()}`);
    }
    if (new Date(String(challenge.expires_at)).getTime() <= Date.now()) {
      throw new Error('GATEWAY_CHALLENGE_EXPIRED');
    }

    const { data: intent, error: intentError } = await sb
      .from('gateway_payment_intents')
      .select('*')
      .eq('id', challenge.intent_id)
      .maybeSingle();
    if (intentError) throw new Error(intentError.message || 'GATEWAY_INTENT_LOOKUP_FAILED');
    if (!intent) throw new Error('GATEWAY_INTENT_NOT_FOUND');

    return { challenge, intent };
  }

  async getPendingChallengeForGateway(challengeId: string) {
    const result = await this.getChallengeForGateway(challengeId);
    if (String(result.challenge.status) !== 'PENDING') {
      throw new Error(`GATEWAY_CHALLENGE_${String(result.challenge.status).toUpperCase()}`);
    }
    if (new Date(String(result.challenge.expires_at)).getTime() <= Date.now()) {
      throw new Error('GATEWAY_CHALLENGE_EXPIRED');
    }
    return result;
  }

  async getChallengeForGateway(challengeId: string) {
    const sb = getAdminSupabase();
    if (!sb) throw new Error('SERVICE_ROLE_REQUIRED');

    const { data: challenge, error } = await sb
      .from('gateway_payment_challenges')
      .select('id,challenge_id,customer_user_id,challenge_type,status,expires_at,metadata,intent_id')
      .eq('challenge_id', challengeId)
      .maybeSingle();
    if (error) throw new Error(error.message || 'GATEWAY_CHALLENGE_LOOKUP_FAILED');
    if (!challenge) throw new Error('GATEWAY_CHALLENGE_NOT_FOUND');

    const { data: intent, error: intentError } = await sb
      .from('gateway_payment_intents')
      .select('*')
      .eq('id', challenge.intent_id)
      .maybeSingle();
    if (intentError) throw new Error(intentError.message || 'GATEWAY_INTENT_LOOKUP_FAILED');
    if (!intent) throw new Error('GATEWAY_INTENT_NOT_FOUND');

    return { challenge, intent };
  }

  async respondToChallenge(input: {
    challengeId: string;
    userId: string;
    decision: ChallengeDecision;
    idempotencyKey: string;
    metadata?: Record<string, unknown>;
  }): Promise<ChallengeResponseResult> {
    const sb = getAdminSupabase();
    if (!sb) throw new Error('SERVICE_ROLE_REQUIRED');

    const { data: challenge, error } = await sb
      .from('gateway_payment_challenges')
      .select('id,challenge_id,customer_user_id,challenge_type,status,expires_at,metadata,intent_id')
      .eq('challenge_id', input.challengeId)
      .maybeSingle();
    if (error) throw new Error(error.message || 'GATEWAY_CHALLENGE_LOOKUP_FAILED');
    if (!challenge) throw new Error('GATEWAY_CHALLENGE_NOT_FOUND');
    if (String(challenge.customer_user_id) !== String(input.userId)) {
      throw new Error('GATEWAY_CHALLENGE_ACCESS_DENIED');
    }

    const { data: intent, error: intentError } = await sb
      .from('gateway_payment_intents')
      .select('*')
      .eq('id', challenge.intent_id)
      .maybeSingle();
    if (intentError) throw new Error(intentError.message || 'GATEWAY_INTENT_LOOKUP_FAILED');
    if (!intent) throw new Error('GATEWAY_INTENT_NOT_FOUND');

    const existingMetadata = challenge.metadata && typeof challenge.metadata === 'object'
      ? challenge.metadata as Record<string, unknown>
      : {};
    const existingDecision = String(existingMetadata.response_decision || '').toLowerCase();
    const existingKey = String(existingMetadata.response_idempotency_key || '');
    const terminal = ['VERIFIED', 'REJECTED', 'EXPIRED', 'CANCELLED'].includes(String(challenge.status));
    if (terminal) {
      if (existingKey && existingKey === input.idempotencyKey && existingDecision === input.decision) {
        const storedEvent = intent.response_payload as ServicePaymentCoreEvent | null;
        if (storedEvent && typeof storedEvent === 'object' && typeof storedEvent.status === 'string') {
          return {
            event: storedEvent,
            intent,
            challenge,
            replayed: true,
          };
        }
        return this.buildChallengeResponseEvent(intent, challenge, input.decision, true);
      }
      throw new Error(`GATEWAY_CHALLENGE_${String(challenge.status).toUpperCase()}`);
    }

    const now = new Date();
    if (new Date(String(challenge.expires_at)).getTime() <= now.getTime()) {
      const expiredMetadata = {
        ...existingMetadata,
        expired_at: now.toISOString(),
      };
      await sb
        .from('gateway_payment_challenges')
        .update({ status: 'EXPIRED', metadata: expiredMetadata })
        .eq('id', challenge.id);
      await sb
        .from('gateway_payment_intents')
        .update({
          status: 'EXPIRED',
          response_payload: {
            ...(intent.response_payload || {}),
            status: 'failed',
            message: 'Customer authorization expired before confirmation.',
          },
          updated_at: now.toISOString(),
        })
        .eq('id', intent.id);
      throw new Error('GATEWAY_CHALLENGE_EXPIRED');
    }

    const nextChallengeStatus = input.decision === 'approve' ? 'VERIFIED' : 'REJECTED';
    const nextIntentStatus = input.decision === 'approve' ? 'AUTHORIZED' : 'CANCELLED';
    const responseMetadata = {
      ...existingMetadata,
      ...(input.metadata || {}),
      response_decision: input.decision,
      response_idempotency_key: input.idempotencyKey,
      responded_at: now.toISOString(),
      responded_by: input.userId,
    };
    const responseResult = this.buildChallengeResponseEvent(
      intent,
      { ...challenge, metadata: responseMetadata },
      input.decision,
      false,
    );

    const { error: challengeUpdateError } = await sb
      .from('gateway_payment_challenges')
      .update({
        status: nextChallengeStatus,
        metadata: responseMetadata,
        verified_at: input.decision === 'approve' ? now.toISOString() : null,
        rejected_at: input.decision === 'reject' ? now.toISOString() : null,
      })
      .eq('id', challenge.id);
    if (challengeUpdateError) throw new Error(challengeUpdateError.message || 'GATEWAY_CHALLENGE_UPDATE_FAILED');

    const responsePayload = {
      ...(intent.response_payload || {}),
      ...responseResult.event,
    };
    const { error: intentUpdateError } = await sb
      .from('gateway_payment_intents')
      .update({
        status: nextIntentStatus,
        response_payload: responsePayload,
        updated_at: now.toISOString(),
      })
      .eq('id', intent.id);
    if (intentUpdateError) throw new Error(intentUpdateError.message || 'GATEWAY_INTENT_UPDATE_FAILED');

    return {
      event: responseResult.event,
      intent: { ...intent, status: nextIntentStatus, response_payload: responsePayload },
      challenge: { ...challenge, status: nextChallengeStatus, metadata: responseMetadata },
      replayed: false,
    };
  }

  async deliverServicePaymentEvent(event: ServicePaymentCoreEvent): Promise<Record<string, unknown>> {
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
        ...this.buildSignedCoreToPayGatewayHeaders('POST', endpoint.pathname, event),
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
  }

  async updateIntentEvent(intentId: string, event: ServicePaymentCoreEvent, status?: string) {
    const sb = getAdminSupabase();
    if (!sb) throw new Error('SERVICE_ROLE_REQUIRED');
    const normalizedStatus = String(status || event.status || '').toUpperCase();
    const patch: Record<string, unknown> = {
      status: normalizedStatus === 'COMPLETED'
        ? 'COMPLETED'
        : normalizedStatus === 'FAILED'
          ? 'FAILED'
          : normalizedStatus === 'CANCELLED'
            ? 'CANCELLED'
            : normalizedStatus === 'PROCESSING'
              ? 'PROCESSING'
              : 'AUTHORIZED',
      response_payload: event as unknown as Record<string, unknown>,
      updated_at: new Date().toISOString(),
    };
    if (patch.status === 'COMPLETED') patch.completed_at = new Date().toISOString();
    if (patch.status === 'FAILED') patch.failed_at = new Date().toISOString();

    const { error } = await sb
      .from('gateway_payment_intents')
      .update(patch)
      .eq('intent_id', intentId);
    if (error) throw new Error(error.message || 'GATEWAY_INTENT_EVENT_UPDATE_FAILED');
  }

  private buildChallengeResponseEvent(
    intent: any,
    challenge: any,
    decision: ChallengeDecision,
    replayed: boolean,
  ): ChallengeResponseResult {
    const approved = decision === 'approve';
    return {
      event: {
        intentId: String(intent.intent_id),
        serviceCode: String(intent.service_code),
        status: approved ? 'submitted_to_core' : 'failed',
        message: approved
          ? 'Customer authorization approved. Payment processing may continue.'
          : 'Customer declined the payment authorization request.',
        challenge: {
          type: String(challenge.challenge_type || 'PIN') as ChallengeType,
          challengeId: String(challenge.challenge_id),
          prompt: approved ? 'Authorization approved.' : 'Authorization declined.',
          expiresAt: challenge.expires_at ? String(challenge.expires_at) : undefined,
          delivery: { channel: 'in_app' as const, destinationHint: 'ORBI mobile app' },
          metadata: challenge.metadata || {},
        },
        raw: {
          decision,
          replayed,
          reference: intent.reference,
          operation: intent.operation,
          amount: Number(intent.amount || 0),
          currency: intent.currency,
          customerId: intent.customer_user_id || null,
          merchantId: intent.merchant_id || null,
        },
      } satisfies ServicePaymentCoreEvent,
      intent,
      challenge,
      replayed,
    };
  }

  private buildSignedCoreToPayGatewayHeaders(method: string, path: string, body: unknown): Record<string, string> {
    const signingSecret = process.env.WORKER_SIGNING_SECRET || process.env.WORKER_SECRET || '';
    if (!signingSecret) throw new Error('WORKER_SIGNING_SECRET_NOT_CONFIGURED');
    const workerId = process.env.ORBI_CORE_PAY_GATEWAY_WORKER_ID || 'orbi-core';
    const scopes = 'gateway:service-payments:result';
    const timestamp = new Date().toISOString();
    const nonce = crypto.randomUUID();
    const requestId = crypto.randomUUID();
    const bodySha256 = this.hashRequest(body as Record<string, unknown>);
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
  }
}

export const gatewayPaymentIntentService = new GatewayPaymentIntentService();
