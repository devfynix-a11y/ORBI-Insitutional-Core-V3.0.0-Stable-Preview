import { User, MoneyOperation, RailType } from '../../types.js';
import { UUID } from '../../services/utils.js';
import { getAdminSupabase, getSupabase } from '../supabaseClient.js';
import { SecurityRules } from '../../ledger/rulesEngine.js';
import { TransactionService } from '../../ledger/transactionService.js';
import { platformFeeService } from './PlatformFeeService.js';
import { providerRoutingService } from './ProviderRoutingService.js';
import { FXEngine } from '../ledger/FXEngine.js';
import { verifyLockedFxSnapshot } from '../ledger/FXLockedQuote.js';
import { transactionFeeClassifier } from './TransactionFeeClassifier.js';
import { logger } from '../infrastructure/logger.js';
import { createHash, createHmac } from 'crypto';

type QuoteInput = {
  userId: string;
  payload: any;
};

type PreflightIssueSeverity = 'warning' | 'blocking';

type PreflightIssue = {
  code: string;
  severity: PreflightIssueSeverity;
  subject: string;
  message: string;
  retryable?: boolean;
  metadata?: Record<string, any>;
};

type WalletSnapshot = {
  id: string;
  table: 'wallets' | 'platform_vaults';
  currency: string;
  balance: number;
  name?: string | null;
  userId?: string | null;
  role?: string | null;
  status?: string | null;
  isPrimary?: boolean;
  isLocked?: boolean;
  lockReason?: string | null;
  lockedAt?: string | null;
  metadata?: Record<string, any> | null;
};

type TransactionGeoSignal = {
  countryCode: string | null;
  region: string | null;
  city: string | null;
  latitude: number | null;
  longitude: number | null;
  source: string | null;
  consented: boolean | null;
  capturedAt: string | null;
};

const quoteLogger = logger.child({ component: 'transaction_quote_service' });

type QuoteBindingResult = {
  quoteId: string;
  payload: Record<string, any>;
  quote: Record<string, any>;
};

const DEBIT_TYPES = new Set([
  'INTERNAL_TRANSFER',
  'PEER_TRANSFER',
  'EXTERNAL_PAYMENT',
  'BILL_PAYMENT',
  'WITHDRAWAL',
  'MERCHANT_PAYMENT',
]);

const EXTERNAL_TYPES = new Set([
  'EXTERNAL_PAYMENT',
  'BILL_PAYMENT',
  'WITHDRAWAL',
  'DEPOSIT',
  'MERCHANT_PAYMENT',
]);

export class TransactionQuoteService {
  private rules = SecurityRules;

  async quote({ userId, payload }: QuoteInput) {
    const sb = getAdminSupabase() || getSupabase();
    if (!sb) throw new Error('DB_OFFLINE');

    const amount = this.parseAmount(payload.amount);
    const currency = this.normalizeCurrency(payload.currency);
    const type = this.normalizeType(payload.type || 'INTERNAL_TRANSFER');
    const metadata = payload.metadata && typeof payload.metadata === 'object' ? payload.metadata : {};
    const sourceWalletId = this.extractWalletId(payload, metadata, [
      'sourceWalletId',
      'source_wallet_id',
      'walletId',
      'wallet_id',
      'fromWalletId',
      'from_wallet_id',
    ]);
    const targetWalletId = this.extractWalletId(payload, metadata, [
      'targetWalletId',
      'target_wallet_id',
      'toWalletId',
      'to_wallet_id',
      'recipientWalletId',
      'recipient_wallet_id',
    ]);

    if (amount <= 0) throw new Error('QUOTE_AMOUNT_REQUIRED');
    if (!currency) throw new Error('QUOTE_CURRENCY_REQUIRED');

    const classification = transactionFeeClassifier.classify({
      type,
      category: payload.category,
      categoryId: payload.categoryId,
      metadata,
      channel: payload.channel,
    });
    const user = await this.resolveUser(sb, userId);
    const issues: PreflightIssue[] = [];
    let sourceWallet: WalletSnapshot | null = null;
    let targetWallet: WalletSnapshot | null = null;

    try {
      ({ sourceWallet, targetWallet } = await this.resolveTransactionWallets({
        sb,
        userId,
        type,
        currency,
        payload,
        metadata,
        sourceWalletId,
        targetWalletId,
      }));
    } catch (error) {
      issues.push(this.issueFromError(error, 'wallet_resolution'));
    }

    const sourceCurrency = sourceWallet?.currency || currency;
    const targetCurrency = targetWallet?.currency || currency;
    const provider = await this.resolveProviderForPreview(type, currency, metadata, classification, issues);
    const fee = await this.resolveFeeForPreview({
      amount,
      currency,
      classification,
      metadata,
      provider,
      issues,
    });

    const fx = await this.resolveFxForPreview(amount, sourceCurrency, targetCurrency, issues);

    const totalDebit = this.round(amount + fee.totalFee);
    const balance = await this.resolveBalanceForPreview(userId, sourceWallet, type, issues);
    const history = await this.fetchRuleHistory(sb, userId);
    const geoIssues = this.buildGeoComplianceIssues(metadata, history);
    const risk = await this.evaluateRulesForPreview(user as any, {
      ...payload,
      type,
      classification,
      amount,
      currency,
      sourceWalletId: sourceWallet?.id || sourceWalletId || undefined,
      targetWalletId: targetWallet?.id || targetWalletId || undefined,
      metadata: {
        ...metadata,
        quote_only: true,
      },
    }, history, issues);

    issues.push(...this.buildAccountIssues(user, amount, currency));
    issues.push(...this.buildWalletIssues('source_wallet', sourceWallet, type));
    issues.push(...this.buildWalletIssues('target_wallet', targetWallet, type));
    issues.push(...this.buildSelfTransferIssues(sourceWallet, targetWallet));
    issues.push(...this.buildBalanceIssues(type, balance, totalDebit, sourceWallet));
    issues.push(...geoIssues);
    issues.push(...this.buildRiskIssues(risk));

    const state = this.resolvePreflightState(issues, risk.decision);
    const canSubmit = !issues.some((issue) => issue.severity === 'blocking');

    const quoteId = `qt_${UUID.generate()}`;
    const expiresAt = new Date(Date.now() + this.resolveQuoteTtlMs()).toISOString();

    const quote = {
      success: true,
      quoteId,
      expiresAt,
      status: canSubmit ? (risk.decision === 'CHALLENGE' ? 'challenge_required' : 'ready') : 'blocked',
      state,
      canSubmit,
      issues,
      amount,
      currency,
      type,
      sourceWallet: sourceWallet ? this.formatWallet(sourceWallet) : null,
      targetWallet: targetWallet ? this.formatWallet(targetWallet) : null,
      provider: provider ? {
        providerId: provider.providerId,
        providerCode: provider.providerCode,
        providerName: provider.providerName,
        rail: provider.rail,
        operation: provider.operation,
        routingDecision: provider.routingDecision || null,
      } : null,
      fees: {
        flowCode: fee.flowCode,
        configId: fee.configId,
        serviceFee: fee.serviceFee,
        taxAmount: fee.taxAmount,
        govFeeAmount: fee.govFeeAmount,
        stampDutyFixed: fee.stampDutyFixed,
        totalFee: fee.totalFee,
      },
      fx,
      debit: {
        amount,
        fee: fee.totalFee,
        total: totalDebit,
        currency,
        sourceWalletId: sourceWallet?.id || null,
        sourceWalletName: sourceWallet ? this.resolveWalletDisplayName(sourceWallet) : null,
      },
      balance: {
        available: balance,
        required: this.requiresDebit(type) ? totalDebit : 0,
        sufficient: !this.requiresDebit(type) || balance >= totalDebit,
        sourceOfTruth: 'ledger',
      },
      risk: {
        decision: risk.decision,
        score: risk.score,
        passed: risk.passed,
        challengeRequired: risk.decision === 'CHALLENGE',
        blocked: risk.decision === 'BLOCK',
      },
      geoCompliance: this.buildGeoComplianceSummary(metadata, history, geoIssues),
      checks: this.buildChecks({
        user,
        type,
        amount,
        currency,
        sourceWallet,
        targetWallet,
        provider,
        fee,
        balance,
        totalDebit,
        risk,
        issues,
      }),
      warnings: this.buildWarnings(type, balance, totalDebit, risk.decision, issues),
    };

    quoteLogger.info('transaction.preview_result', {
      actor_id: userId,
      quote_id: quoteId,
      can_submit: canSubmit,
      state,
      status: quote.status,
      risk_decision: risk.decision,
      type,
      amount,
      currency,
      source_wallet_resolved: Boolean(sourceWallet?.id),
      target_wallet_resolved: Boolean(targetWallet?.id),
      issue_summary: issues.map((issue) => ({
        code: issue.code,
        severity: issue.severity,
        subject: issue.subject,
      })),
    });

    const quoteHash = this.hashCanonicalIntent(this.buildCanonicalIntent(payload, quote));
    const quoteSignature = this.signQuote(quoteId, quoteHash, expiresAt, userId);
    await this.persistQuote({
      sb,
      userId,
      payload,
      quote: {
        ...quote,
        quoteHash,
        quoteSignature,
      },
      quoteHash,
      quoteSignature,
    });

    return {
      ...quote,
      quoteHash,
      quoteSignature,
    };
  }

  async bindSettlementQuote(args: {
    userId: string;
    payload: Record<string, any>;
    idempotencyKey: string;
  }): Promise<QuoteBindingResult> {
    const sb = getAdminSupabase() || getSupabase();
    if (!sb) throw new Error('DB_OFFLINE');

    const quoteId = this.extractQuoteId(args.payload);
    if (!quoteId) {
      throw new Error('QUOTE_ID_REQUIRED: Confirming a transaction requires a server-issued preview quote.');
    }

    const { data: quoteRow, error } = await sb
      .from('transaction_quotes')
      .select('*')
      .eq('id', quoteId)
      .eq('user_id', args.userId)
      .maybeSingle();

    if (error) throw new Error(`QUOTE_LOOKUP_FAILED:${error.message}`);
    if (!quoteRow) throw new Error('QUOTE_NOT_FOUND');

    const status = String(quoteRow.status || '').toUpperCase();
    const storedIdempotencyKey = String(quoteRow.idempotency_key || '').trim();
    const incomingIdempotencyKey = String(args.idempotencyKey || '').trim();
    const canRetryConfirmedQuote =
      status === 'CONFIRMED' &&
      storedIdempotencyKey &&
      storedIdempotencyKey === incomingIdempotencyKey;

    if (!['QUOTED', 'READY'].includes(status) && !canRetryConfirmedQuote) {
      throw new Error(`QUOTE_NOT_SETTLEABLE:${status || 'UNKNOWN'}`);
    }

    const expiresAt = quoteRow.expires_at ? new Date(quoteRow.expires_at).getTime() : 0;
    if (!expiresAt || expiresAt < Date.now()) {
      await this.markQuoteStatus(sb, quoteId, 'EXPIRED');
      throw new Error('QUOTE_EXPIRED: Please refresh the transaction preview before confirming.');
    }

    if (quoteRow.can_submit === false) {
      throw new Error('QUOTE_BLOCKED: This preview had blocking validation issues and cannot be settled.');
    }

    const quote = this.objectFromJson(quoteRow.quote_snapshot);
    const expectedHash = String(quoteRow.payload_hash || '');
    const actualHash = this.hashCanonicalIntent(this.buildCanonicalIntent(args.payload, quote));
    if (expectedHash && actualHash !== expectedHash) {
      throw new Error('QUOTE_PAYLOAD_MISMATCH: Transaction details changed after preview. Refresh the preview before confirming.');
    }

    const storedSignature = String(quoteRow.quote_signature || '');
    const canonicalExpiresAt = String(quote.expiresAt || quoteRow.expires_at || '');
    const expectedSignature = this.signQuote(quoteId, expectedHash, canonicalExpiresAt, args.userId);
    if (storedSignature && storedSignature !== expectedSignature) {
      throw new Error('QUOTE_SIGNATURE_INVALID: Transaction preview integrity check failed.');
    }
    if (String(quoteRow.transaction_type || '').toUpperCase() === 'FX_CONVERSION') {
      verifyLockedFxSnapshot(
        quote,
        quoteId,
        args.userId,
        process.env.ORBI_TRANSACTION_QUOTE_SIGNING_SECRET || process.env.JWT_SECRET || process.env.SESSION_SECRET || '',
      );
    }

    if (!canRetryConfirmedQuote) {
      const { data: confirmed, error: updateError } = await sb
        .from('transaction_quotes')
        .update({
          status: 'CONFIRMED',
          idempotency_key: incomingIdempotencyKey,
          confirmed_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        })
        .eq('id', quoteId)
        .eq('user_id', args.userId)
        .in('status', ['QUOTED', 'READY'])
        .select('id')
        .maybeSingle();

      if (updateError) throw new Error(`QUOTE_CONFIRM_FAILED:${updateError.message}`);
      if (!confirmed) {
        const { data: current } = await sb
          .from('transaction_quotes')
          .select('status, idempotency_key')
          .eq('id', quoteId)
          .eq('user_id', args.userId)
          .maybeSingle();
        const currentStatus = String(current?.status || '').toUpperCase();
        const currentIdempotencyKey = String(current?.idempotency_key || '').trim();
        if (currentStatus === 'CONFIRMED' && currentIdempotencyKey === incomingIdempotencyKey) {
          return {
            quoteId,
            payload: {
              ...this.objectFromJson(quoteRow.request_payload),
              quoteId,
              quoteHash: expectedHash,
              idempotencyKey: incomingIdempotencyKey,
              metadata: {
                ...(this.objectFromJson(quoteRow.request_payload).metadata || {}),
                quote_id: quoteId,
                quote_hash: expectedHash,
                quote_bound: true,
              },
            },
            quote,
          };
        }
        throw new Error(`QUOTE_CONFIRM_CONFLICT:${currentStatus || 'UNKNOWN'}`);
      }
    }

    const storedPayload = this.objectFromJson(quoteRow.request_payload);
    return {
      quoteId,
      payload: {
        ...storedPayload,
        quoteId,
        quoteHash: expectedHash,
        idempotencyKey: incomingIdempotencyKey,
        metadata: {
          ...(storedPayload.metadata && typeof storedPayload.metadata === 'object' ? storedPayload.metadata : {}),
          quote_id: quoteId,
          quote_hash: expectedHash,
          quote_bound: true,
        },
      },
      quote,
    };
  }

  async markQuoteSettlementResult(args: {
    quoteId?: string | null;
    userId: string;
    result: any;
  }) {
    const quoteId = args.quoteId ? String(args.quoteId).trim() : '';
    if (!quoteId) return;
    const sb = getAdminSupabase() || getSupabase();
    if (!sb) return;

    const success = args.result?.success === true;
    const transactionId = this.normalizeNullable(
      args.result?.transaction?.internalId ||
      args.result?.transaction?.id ||
      args.result?.transactionId ||
      args.result?.id,
    );
    const transactionStatus = String(args.result?.transaction?.status || args.result?.status || '').toLowerCase();
    const settlementStatus = success
      ? (['processing', 'pending', 'authorized', 'created'].includes(transactionStatus) ? 'SETTLING' : 'SETTLED')
      : null;
    const challenge = args.result?.error === 'SECURITY_CHALLENGE' || args.result?.challengeRequired === true;

    const { error: quoteUpdateError } = await sb
      .from('transaction_quotes')
      .update({
        status: success ? (settlementStatus || (transactionId ? 'SETTLED' : 'SETTLING')) : (challenge ? 'CONFIRMED' : 'FAILED'),
        transaction_id: transactionId,
        settlement_result: args.result || null,
        settled_at: success ? new Date().toISOString() : null,
        updated_at: new Date().toISOString(),
      })
      .eq('id', quoteId)
      .eq('user_id', args.userId);
    if (quoteUpdateError) throw quoteUpdateError;

    const { data: reconciliationRow, error: reconciliationReadError } = await sb
      .from('fx_reconciliation_events')
      .select('metadata')
      .eq('quote_id', quoteId)
      .eq('user_id', args.userId)
      .maybeSingle();
    if (reconciliationReadError) throw reconciliationReadError;

    const { error: reconciliationUpdateError } = await sb
      .from('fx_reconciliation_events')
      .update({
        transaction_id: transactionId,
        status: success ? (settlementStatus === 'SETTLED' ? 'MATCHED' : 'PENDING') : (challenge ? 'PENDING' : 'FAILED'),
        metadata: {
          ...(reconciliationRow?.metadata && typeof reconciliationRow.metadata === 'object' ? reconciliationRow.metadata : {}),
          settlementStatus: settlementStatus || null,
          challengeRequired: challenge,
          settlementResult: args.result || null,
          revenueStatus: success ? 'SETTLED_SPREAD_ESTIMATE' : 'NOT_REALIZED',
        },
        updated_at: new Date().toISOString(),
      })
      .eq('quote_id', quoteId)
      .eq('user_id', args.userId);
    if (reconciliationUpdateError) throw reconciliationUpdateError;
  }

  private async persistQuote(args: {
    sb: any;
    userId: string;
    payload: Record<string, any>;
    quote: Record<string, any>;
    quoteHash: string;
    quoteSignature: string;
  }) {
    const { error } = await args.sb.from('transaction_quotes').insert({
      id: args.quote.quoteId,
      user_id: args.userId,
      payload_hash: args.quoteHash,
      quote_signature: args.quoteSignature,
      request_payload: args.payload,
      quote_snapshot: args.quote,
      amount: Number(args.quote.amount || 0),
      currency: args.quote.currency || null,
      transaction_type: args.quote.type || null,
      source_wallet_id: args.quote.debit?.sourceWalletId || args.quote.sourceWallet?.id || null,
      target_wallet_id: args.quote.targetWallet?.id || null,
      total_debit: Number(args.quote.debit?.total || args.quote.amount || 0),
      total_fee: Number(args.quote.fees?.totalFee || 0),
      provider_code: args.quote.provider?.providerCode || null,
      fee_config_id: args.quote.fees?.configId || null,
      can_submit: args.quote.canSubmit === true,
      status: args.quote.canSubmit === true ? 'QUOTED' : 'BLOCKED',
      expires_at: args.quote.expiresAt,
    });
    if (error) throw new Error(`QUOTE_STORAGE_FAILED:${error.message}`);
  }

  private buildCanonicalIntent(payload: Record<string, any>, quote: Record<string, any>) {
    const metadata = payload.metadata && typeof payload.metadata === 'object' ? payload.metadata : {};
    return this.sortDeep({
      amount: this.parseAmount(payload.amount ?? quote.amount),
      currency: this.normalizeCurrency(payload.currency ?? quote.currency),
      type: this.normalizeType(payload.type || quote.type || 'INTERNAL_TRANSFER'),
      description: String(payload.description || '').trim(),
      category: this.normalizeNullable(payload.category),
      categoryId: this.normalizeNullable(payload.categoryId ?? payload.category_id ?? metadata.categoryId ?? metadata.category_id),
      sourceWalletId: this.normalizeNullable(
        payload.sourceWalletId ||
        payload.source_wallet_id ||
        payload.walletId ||
        payload.wallet_id ||
        metadata.sourceWalletId ||
        metadata.source_wallet_id ||
        quote.debit?.sourceWalletId ||
        quote.sourceWallet?.id,
      ),
      targetWalletId: this.normalizeNullable(
        payload.targetWalletId ||
        payload.target_wallet_id ||
        metadata.targetWalletId ||
        metadata.target_wallet_id ||
        quote.targetWallet?.id,
      ),
      recipientId: this.normalizeNullable(payload.recipientId || payload.recipient_id || metadata.recipientId || metadata.recipient_id),
      recipientCustomerId: this.normalizeNullable(
        payload.recipient_customer_id ||
        payload.recipientCustomerId ||
        metadata.recipient_customer_id ||
        metadata.recipientCustomerId,
      ),
      merchantId: this.normalizeNullable(payload.merchantId || payload.merchant_id || metadata.merchantId || metadata.merchant_id),
      merchantPayNumber: this.normalizeNullable(payload.merchantPayNumber || payload.merchant_pay_number || metadata.merchantPayNumber || metadata.merchant_pay_number),
      channel: this.normalizeNullable(payload.channel || metadata.channel),
      providerCode: this.normalizeNullable(
        metadata.providerCode ||
        metadata.provider_code ||
        metadata.provider ||
        payload.providerInput ||
        quote.provider?.providerCode,
      ),
      feeConfigId: this.normalizeNullable(quote.fees?.configId),
      flowCode: this.normalizeNullable(quote.fees?.flowCode),
      totalDebit: this.round(Number(quote.debit?.total || payload.totalDebit || payload.total_debit || payload.amount || 0)),
      totalFee: this.round(Number(quote.fees?.totalFee || 0)),
    });
  }

  private hashCanonicalIntent(intent: Record<string, any>) {
    return createHash('sha256').update(JSON.stringify(intent)).digest('hex');
  }

  private signQuote(quoteId: string, quoteHash: string, expiresAt: string, userId: string) {
    const secret = process.env.ORBI_TRANSACTION_QUOTE_SIGNING_SECRET || process.env.JWT_SECRET || process.env.SESSION_SECRET;
    if (!secret) return '';
    return createHmac('sha256', secret)
      .update([quoteId, userId, quoteHash, expiresAt].join('|'))
      .digest('hex');
  }

  private extractQuoteId(payload: Record<string, any>) {
    return this.normalizeNullable(
      payload.quoteId ||
      payload.quote_id ||
      payload.preview?.quoteId ||
      payload.preview?.quote_id ||
      payload.preview_snapshot?.quoteId ||
      payload.preview_snapshot?.quote_id ||
      payload.metadata?.quoteId ||
      payload.metadata?.quote_id,
    );
  }

  private objectFromJson(value: any): Record<string, any> {
    if (!value) return {};
    if (typeof value === 'string') {
      try {
        const parsed = JSON.parse(value);
        return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
      } catch {
        return {};
      }
    }
    return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  }

  private sortDeep(value: any): any {
    if (Array.isArray(value)) return value.map((item) => this.sortDeep(item));
    if (!value || typeof value !== 'object') return value;
    return Object.keys(value)
      .sort()
      .reduce((acc: Record<string, any>, key) => {
        acc[key] = this.sortDeep(value[key]);
        return acc;
      }, {});
  }

  private async markQuoteStatus(sb: any, quoteId: string, status: string) {
    await sb
      .from('transaction_quotes')
      .update({ status, updated_at: new Date().toISOString() })
      .eq('id', quoteId);
  }

  private async resolveUser(sb: any, userId: string): Promise<User> {
    const { data: authUser, error } = await sb.auth.admin.getUserById(userId);
    if (error || !authUser?.user) throw new Error('IDENTITY_NOT_FOUND');

    const { data: profile } = await sb
      .from('users')
      .select('account_status, kyc_status, currency, language, full_name, registry_type, role, organization_id, customer_id')
      .eq('id', userId)
      .maybeSingle();

    const user = authUser.user;
    user.user_metadata = {
      ...(user.user_metadata || {}),
      ...(profile || {}),
    };
    return user as any;
  }

  private async resolveWallet(sb: any, walletId: string): Promise<WalletSnapshot> {
    const { data: wallet } = await sb
      .from('wallets')
      .select('id, name, currency, balance, user_id, type, status, is_primary, management_tier, is_locked, lock_reason, locked_at, metadata')
      .eq('id', walletId)
      .maybeSingle();

    if (wallet) {
      return {
        id: wallet.id,
        table: 'wallets',
        name: wallet.name,
        userId: wallet.user_id,
        currency: this.normalizeCurrency(wallet.currency) || 'USD',
        balance: Number(wallet.balance || 0),
        role: wallet.type || wallet.management_tier || null,
        status: wallet.status || null,
        isPrimary: wallet.is_primary === true,
        isLocked: wallet.is_locked === true,
        lockReason: wallet.lock_reason || null,
        lockedAt: wallet.locked_at || null,
        metadata: wallet.metadata || null,
      };
    }

    const { data: vault } = await sb
      .from('platform_vaults')
      .select('id, name, currency, balance, user_id, vault_role, status, is_locked, lock_reason, locked_at, metadata')
      .eq('id', walletId)
      .maybeSingle();

    if (vault) {
      return {
        id: vault.id,
        table: 'platform_vaults',
        name: vault.name,
        userId: vault.user_id,
        currency: this.normalizeCurrency(vault.currency) || 'USD',
        balance: Number(vault.balance || 0),
        role: vault.vault_role || null,
        status: vault.status || null,
        isLocked: vault.is_locked === true,
        lockReason: vault.lock_reason || null,
        lockedAt: vault.locked_at || null,
        metadata: vault.metadata || null,
      };
    }

    throw new Error(`WALLET_NOT_FOUND:${walletId}`);
  }

  private async resolveTransactionWallets(args: {
    sb: any;
    userId: string;
    type: string;
    currency: string;
    payload: any;
    metadata: Record<string, any>;
    sourceWalletId: string | null;
    targetWalletId: string | null;
  }): Promise<{ sourceWallet: WalletSnapshot | null; targetWallet: WalletSnapshot | null }> {
    const {
      sb,
      userId,
      type,
      currency,
      payload,
      metadata,
      sourceWalletId,
      targetWalletId,
    } = args;

    const [explicitSource, explicitTarget] = await Promise.all([
      sourceWalletId ? this.resolveWallet(sb, sourceWalletId) : Promise.resolve(null),
      targetWalletId ? this.resolveWallet(sb, targetWalletId) : Promise.resolve(null),
    ]);

    if (explicitSource?.userId && String(explicitSource.userId) !== String(userId)) {
      throw new Error('SOURCE_WALLET_ACCESS_DENIED');
    }

    let sourceWallet = explicitSource;
    let targetWallet = explicitTarget;

    if (!sourceWallet && this.requiresDebit(type)) {
      sourceWallet = await this.resolveUserOperatingWallet(sb, userId, currency, 'SOURCE');
    }

    if (!targetWallet && (type === 'INTERNAL_TRANSFER' || type === 'PEER_TRANSFER')) {
      const recipientUserId = await this.resolveRecipientUserId(sb, payload, metadata);
      if (!recipientUserId) {
        throw new Error('RECIPIENT_REQUIRED_FOR_QUOTE');
      }
      targetWallet = await this.resolveUserOperatingWallet(sb, recipientUserId, currency, 'TARGET');
    }

    if (!targetWallet && type === 'DEPOSIT') {
      targetWallet = await this.resolveUserOperatingWallet(sb, userId, currency, 'TARGET');
    }

    return { sourceWallet, targetWallet };
  }

  private async resolveUserOperatingWallet(
    sb: any,
    userId: string,
    currency: string,
    purpose: 'SOURCE' | 'TARGET',
  ): Promise<WalletSnapshot> {
    const normalizedCurrency = this.normalizeCurrency(currency);
    const { data: vaults, error: vaultError } = await sb
      .from('platform_vaults')
      .select('id, name, currency, balance, user_id, vault_role, status, is_locked, lock_reason, locked_at, metadata')
      .eq('user_id', userId);

    if (vaultError) throw new Error(vaultError.message);

    const vaultCandidates = (vaults || []).map((vault: any) => ({
      id: vault.id,
      table: 'platform_vaults' as const,
      name: vault.name,
      userId: vault.user_id,
      currency: this.normalizeCurrency(vault.currency) || normalizedCurrency || 'USD',
      balance: Number(vault.balance || 0),
      role: vault.vault_role || null,
      status: vault.status || null,
      isPrimary: false,
      isLocked: vault.is_locked === true,
      lockReason: vault.lock_reason || null,
      lockedAt: vault.locked_at || null,
      metadata: vault.metadata || null,
    }));

    const preferredVault = this.pickBestWallet(vaultCandidates, normalizedCurrency, [
      'OPERATING',
      'PRIMARY',
      'MAIN',
    ]);
    if (preferredVault) return preferredVault;

    const { data: wallets, error: walletError } = await sb
      .from('wallets')
      .select('id, name, currency, balance, user_id, type, status, is_primary, management_tier, is_locked, lock_reason, locked_at, metadata')
      .eq('user_id', userId);

    if (walletError) throw new Error(walletError.message);

    const walletCandidates = (wallets || []).map((wallet: any) => ({
      id: wallet.id,
      table: 'wallets' as const,
      name: wallet.name,
      userId: wallet.user_id,
      currency: this.normalizeCurrency(wallet.currency) || normalizedCurrency || 'USD',
      balance: Number(wallet.balance || 0),
      role: wallet.type || wallet.management_tier || null,
      status: wallet.status || null,
      isPrimary: wallet.is_primary === true,
      isLocked: wallet.is_locked === true,
      lockReason: wallet.lock_reason || null,
      lockedAt: wallet.locked_at || null,
      metadata: wallet.metadata || null,
    }));

    const preferredWallet = this.pickBestWallet(walletCandidates, normalizedCurrency, [
      'OPERATING',
      'PRIMARY',
      'MAIN',
      'LINKED',
    ]);
    if (preferredWallet) return preferredWallet;

    throw new Error(`${purpose}_WALLET_REQUIRED_FOR_QUOTE:${normalizedCurrency || 'ANY'}`);
  }

  private pickBestWallet(
    wallets: WalletSnapshot[],
    currency: string,
    preferredRoles: string[],
  ): WalletSnapshot | null {
    const active = wallets.filter((wallet) => !this.isInactiveWallet(wallet));
    const candidates = active.length > 0 ? active : wallets;
    const sameCurrency = candidates.filter((wallet) => !currency || wallet.currency === currency);
    const pool = sameCurrency.length > 0 ? sameCurrency : candidates;
    if (pool.length === 0) return null;

    const roleRank = (wallet: WalletSnapshot) => {
      const role = String(wallet.role || wallet.name || '').trim().toUpperCase();
      const direct = preferredRoles.findIndex((preferred) => role === preferred);
      if (direct >= 0) return direct;
      const contains = preferredRoles.findIndex((preferred) => role.includes(preferred));
      if (contains >= 0) return contains + 10;
      if (wallet.isPrimary) return 20;
      return 100;
    };

    return [...pool].sort((a, b) => {
      const rankDelta = roleRank(a) - roleRank(b);
      if (rankDelta !== 0) return rankDelta;
      return Number(b.balance || 0) - Number(a.balance || 0);
    })[0] || null;
  }

  private async resolveRecipientUserId(sb: any, payload: any, metadata: Record<string, any>) {
    const explicit = this.normalizeNullable(
      payload.recipientId ||
      payload.recipient_id ||
      metadata.recipientId ||
      metadata.recipient_id,
    );
    if (explicit && this.looksLikeUuid(explicit)) return explicit;

    const lookup = this.normalizeNullable(
      payload.recipient_customer_id ||
      payload.recipientCustomerId ||
      payload.recipient ||
      metadata.recipient_customer_id ||
      metadata.recipientCustomerId ||
      explicit,
    );
    if (!lookup) return null;

    const lookups = [
      { column: 'customer_id', operator: 'ilike' },
      { column: 'phone', operator: 'eq' },
      { column: 'email', operator: 'ilike' },
    ];
    for (const item of lookups) {
      const query = sb.from('users').select('id');
      const { data: user, error } = item.operator === 'ilike'
        ? await query.ilike(item.column, lookup).maybeSingle()
        : await query.eq(item.column, lookup).maybeSingle();

      if (error) throw new Error(error.message);
      if (user?.id) return user.id;
    }

    return null;
  }

  private async resolveBalance(userId: string, wallet: WalletSnapshot | null, type: string) {
    if (!this.requiresDebit(type)) return Number.MAX_SAFE_INTEGER;
    if (!wallet?.id) throw new Error(`SOURCE_WALLET_REQUIRED_FOR_QUOTE:${type}`);

    const txService = new TransactionService();
    return txService.getLatestBalance(userId, wallet.id);
  }

  private async resolveBalanceForPreview(
    userId: string,
    wallet: WalletSnapshot | null,
    type: string,
    issues: PreflightIssue[],
  ) {
    try {
      return await this.resolveBalance(userId, wallet, type);
    } catch (error) {
      issues.push(this.issueFromError(error, 'balance'));
      return 0;
    }
  }

  private async resolveProviderIfRequired(type: string, currency: string, metadata: Record<string, any>, classification: ReturnType<typeof transactionFeeClassifier.classify>) {
    if (!EXTERNAL_TYPES.has(type)) return null;

    return providerRoutingService.resolveProvider({
      rail: classification.rail as any,
      operation: transactionFeeClassifier.resolveProviderOperation(classification),
      currency,
      countryCode: metadata.countryCode || metadata.country_code,
      preferredProviderCode:
        metadata.providerCode ||
        metadata.provider_code ||
        metadata.provider ||
        metadata.bill_provider ||
        metadata.payment_provider,
      preferredProviderId: metadata.providerId || metadata.provider_id,
    });
  }

  private async resolveProviderForPreview(
    type: string,
    currency: string,
    metadata: Record<string, any>,
    classification: ReturnType<typeof transactionFeeClassifier.classify>,
    issues: PreflightIssue[],
  ) {
    try {
      return await this.resolveProviderIfRequired(type, currency, metadata, classification);
    } catch (error) {
      issues.push(this.issueFromError(error, 'provider'));
      return null;
    }
  }

  private async resolveFeeForPreview(args: {
    amount: number;
    currency: string;
    classification: ReturnType<typeof transactionFeeClassifier.classify>;
    metadata: Record<string, any>;
    provider: any;
    issues: PreflightIssue[];
  }) {
    const { amount, currency, classification, metadata, provider, issues } = args;
    try {
      return await platformFeeService.resolveFee({
        flowCode: classification.flowCode,
        amount,
        currency,
        providerId: provider?.providerId,
        countryCode: metadata.countryCode || metadata.country_code,
        rail: provider?.rail || classification.rail,
        channel: classification.channel,
        direction: classification.direction,
        transactionModel: classification.transactionModel,
        categoryCode: classification.categoryCode,
        categoryId: classification.categoryId,
        operationType: classification.operationType,
        transactionType: classification.transactionType,
        metadata,
      });
    } catch (error) {
      issues.push(this.issueFromError(error, 'fee_configuration'));
      return this.zeroFee(classification.flowCode, amount, currency, classification);
    }
  }

  private async resolveFxForPreview(
    amount: number,
    sourceCurrency: string,
    targetCurrency: string,
    issues: PreflightIssue[],
  ) {
    if (sourceCurrency === targetCurrency) return null;
    try {
      return await FXEngine.processConversion(amount, sourceCurrency, targetCurrency);
    } catch (error) {
      issues.push(this.issueFromError(error, 'fx'));
      return null;
    }
  }

  private async evaluateRulesForPreview(
    user: User,
    payload: Record<string, any>,
    history: any[],
    issues: PreflightIssue[],
  ) {
    try {
      return await this.rules.evaluate(user as any, payload, history);
    } catch (error) {
      issues.push(this.issueFromError(error, 'transaction_rules'));
      return {
        passed: false,
        decision: 'BLOCK',
        score: 100,
        results: [],
        requirements: [],
      };
    }
  }

  private async fetchRuleHistory(sb: any, userId: string) {
    const { data, error } = await sb
      .from('transactions')
      .select('id, amount, currency, type, status, date, created_at, metadata')
      .eq('user_id', userId)
      .order('created_at', { ascending: false })
      .limit(100);

    if (error) return [];

    return (data || []).map((tx: any) => ({
      id: tx.id,
      amount: Number(tx.amount || 0),
      currency: this.normalizeCurrency(tx.currency),
      type: tx.type,
      status: tx.status,
      date: tx.date || tx.created_at,
      metadata: tx.metadata || {},
    }));
  }

  private buildWarnings(
    type: string,
    balance: number,
    totalDebit: number,
    decision: string,
    issues: PreflightIssue[],
  ) {
    return [
      this.requiresDebit(type) && balance < totalDebit ? 'INSUFFICIENT_FUNDS_IF_SUBMITTED' : '',
      decision === 'CHALLENGE' ? 'SECURITY_CHALLENGE_REQUIRED_IF_SUBMITTED' : '',
      decision === 'BLOCK' ? 'SECURITY_BLOCK_IF_SUBMITTED' : '',
      ...issues.filter((issue) => issue.severity === 'warning').map((issue) => issue.code),
    ].filter(Boolean);
  }

  private buildAccountIssues(user: User, amount: number, currency: string): PreflightIssue[] {
    const metadata = (user as any).user_metadata || {};
    const accountStatus = String(metadata.account_status || 'active').trim().toLowerCase();
    const kycStatus = String(metadata.kyc_status || 'unknown').trim().toLowerCase();
    const issues: PreflightIssue[] = [];

    if (accountStatus && accountStatus !== 'active') {
      issues.push({
        code: 'ACCOUNT_NOT_ACTIVE',
        severity: 'blocking',
        subject: 'account',
        message: `Account is ${accountStatus}; transaction cannot be submitted until the account is active.`,
        metadata: { accountStatus },
      });
    }

    const highValueLimit = Number(process.env.ORBI_PREVIEW_KYC_LIMIT || 1000000);
    if (amount >= highValueLimit && !['verified', 'approved', 'complete'].includes(kycStatus)) {
      issues.push({
        code: 'KYC_REQUIRED_FOR_AMOUNT',
        severity: 'blocking',
        subject: 'account',
        message: `KYC must be verified before submitting a ${currency} ${amount} transaction.`,
        metadata: { kycStatus, highValueLimit },
      });
    }

    return issues;
  }

  private buildWalletIssues(subject: 'source_wallet' | 'target_wallet', wallet: WalletSnapshot | null, type: string): PreflightIssue[] {
    const issues: PreflightIssue[] = [];
    const required =
      subject === 'source_wallet'
        ? this.requiresDebit(type)
        : ['INTERNAL_TRANSFER', 'PEER_TRANSFER', 'DEPOSIT'].includes(type);

    if (!wallet) {
      if (required) {
        issues.push({
          code: subject === 'source_wallet' ? 'SOURCE_WALLET_REQUIRED' : 'TARGET_WALLET_REQUIRED',
          severity: 'blocking',
          subject,
          message: `${subject === 'source_wallet' ? 'Source' : 'Target'} wallet could not be resolved for ${type}.`,
        });
      }
      return issues;
    }

    if (this.isInactiveWallet(wallet)) {
      issues.push({
        code: subject === 'source_wallet' ? 'SOURCE_WALLET_UNAVAILABLE' : 'TARGET_WALLET_UNAVAILABLE',
        severity: 'blocking',
        subject,
        message: `${subject === 'source_wallet' ? 'Source' : 'Target'} wallet is ${wallet.status}.`,
        metadata: { walletId: wallet.id, status: wallet.status },
      });
    }

    if (wallet.isLocked) {
      issues.push({
        code: subject === 'source_wallet' ? 'SOURCE_WALLET_LOCKED' : 'TARGET_WALLET_LOCKED',
        severity: 'blocking',
        subject,
        message: `${subject === 'source_wallet' ? 'Source' : 'Target'} wallet is locked${wallet.lockReason ? `: ${wallet.lockReason}` : ''}.`,
        metadata: { walletId: wallet.id, lockReason: wallet.lockReason, lockedAt: wallet.lockedAt },
      });
    }

    return issues;
  }

  private buildSelfTransferIssues(
    sourceWallet: WalletSnapshot | null,
    targetWallet: WalletSnapshot | null,
  ): PreflightIssue[] {
    if (!sourceWallet?.id || !targetWallet?.id) return [];
    if (String(sourceWallet.id) !== String(targetWallet.id)) return [];

    const walletName = this.resolveWalletDisplayName(sourceWallet);
    return [{
      code: 'SELF_TRANSFER_WALLET_NOT_ALLOWED',
      severity: 'blocking',
      subject: 'wallet_resolution',
      message: `You cannot send money to the same wallet (${walletName}). Select a different source wallet or target wallet.`,
      metadata: {
        sourceWalletId: sourceWallet.id,
        targetWalletId: targetWallet.id,
        sourceWalletName: walletName,
        targetWalletName: this.resolveWalletDisplayName(targetWallet),
      },
    }];
  }

  private buildBalanceIssues(
    type: string,
    balance: number,
    totalDebit: number,
    sourceWallet: WalletSnapshot | null,
  ): PreflightIssue[] {
    if (!this.requiresDebit(type) || !sourceWallet) return [];
    if (balance >= totalDebit) return [];
    return [{
      code: 'INSUFFICIENT_FUNDS',
      severity: 'blocking',
      subject: 'balance',
      message: `Available balance is ${balance}, required debit is ${totalDebit}.`,
      metadata: {
        walletId: sourceWallet.id,
        available: balance,
        required: totalDebit,
        deficit: this.round(totalDebit - balance),
      },
    }];
  }

  private buildRiskIssues(risk: any): PreflightIssue[] {
    if (risk.decision === 'BLOCK') {
      return [{
        code: 'TRANSACTION_RULE_BLOCKED',
        severity: 'blocking',
        subject: 'transaction_rules',
        message: 'Transaction rules blocked this preview. Review the rule results before submitting.',
        metadata: { score: risk.score, results: risk.results || [] },
      }];
    }
    if (risk.decision === 'CHALLENGE') {
      return [{
        code: 'SECURITY_CHALLENGE_REQUIRED',
        severity: 'warning',
        subject: 'transaction_rules',
        message: 'Transaction may proceed only after the required security challenge is satisfied.',
        metadata: { score: risk.score, requirements: risk.requirements || [] },
      }];
    }
    return [];
  }

  private buildGeoComplianceIssues(
    metadata: Record<string, any>,
    history: any[],
  ): PreflightIssue[] {
    const current = this.extractTransactionGeo(metadata);
    const issues: PreflightIssue[] = [];
    const networkFallback = this.isNetworkGeoFallback(current, metadata);

    if (!this.hasSufficientGeo(current)) {
      issues.push({
        code: 'TRANSACTION_GEO_REQUIRED',
        severity: 'blocking',
        subject: 'geo_compliance',
        message: networkFallback
          ? 'Device GPS location is required. Network/IP location is not enough to complete this transaction.'
          : 'Transaction location is required before this preview can continue.',
        metadata: {
          required: ['metadata.geo.countryCode', 'metadata.geo.region or rounded coordinates'],
          source: current.source,
          consented: current.consented,
          fallback: networkFallback,
        },
      });
      return issues;
    }

    if (current.consented === false && !networkFallback) {
      issues.push({
        code: 'TRANSACTION_GEO_CONSENT_REQUIRED',
        severity: 'blocking',
        subject: 'geo_compliance',
        message: 'Location consent is required for transaction risk checks.',
        metadata: { source: current.source },
      });
      return issues;
    }

    if (!this.hasCoordinates(current)) {
      issues.push({
        code: 'TRANSACTION_GEO_APPROXIMATE',
        severity: 'warning',
        subject: 'geo_compliance',
        message: 'Only approximate transaction location was provided; live travel-risk checks are limited.',
        metadata: {
          countryCode: current.countryCode,
          region: current.region,
          source: current.source,
        },
      });
      return issues;
    }

    const previous = this.findPreviousGeoTransaction(history);
    if (!previous || !this.hasCoordinates(previous)) return issues;

    const currentTime = this.geoTimestampMs(current) || Date.now();
    const previousTime = this.geoTimestampMs(previous);
    if (!previousTime || currentTime <= previousTime) return issues;

    const minutes = (currentTime - previousTime) / 60000;
    const distanceKm = this.distanceKm(
      previous.latitude!,
      previous.longitude!,
      current.latitude!,
      current.longitude!,
    );
    const speedKmh = minutes > 0 ? distanceKm / (minutes / 60) : 0;
    const maxKmh = Number(process.env.ORBI_GEO_MAX_TRAVEL_KMH || 900);
    const minDistanceKm = Number(process.env.ORBI_GEO_MIN_TRAVEL_DISTANCE_KM || 25);

    if (distanceKm >= minDistanceKm && speedKmh > maxKmh) {
      issues.push({
        code: 'IMPOSSIBLE_GEO_TRAVEL',
        severity: 'blocking',
        subject: 'geo_compliance',
        message: 'Transaction location changed too quickly compared with the previous transaction. Please verify the account before continuing.',
        metadata: {
          distanceKm: this.round(distanceKm),
          elapsedMinutes: this.round(minutes),
          estimatedSpeedKmh: this.round(speedKmh),
          maxAllowedKmh: maxKmh,
          previous: {
            countryCode: previous.countryCode,
            region: previous.region,
            city: previous.city,
            capturedAt: previous.capturedAt,
            source: previous.source,
          },
          current: {
            countryCode: current.countryCode,
            region: current.region,
            city: current.city,
            capturedAt: current.capturedAt,
            source: current.source,
          },
        },
      });
    }

    return issues;
  }

  private buildGeoComplianceSummary(
    metadata: Record<string, any>,
    history: any[],
    issues: PreflightIssue[],
  ) {
    const current = this.extractTransactionGeo(metadata);
    const previous = this.findPreviousGeoTransaction(history);
    return {
      required: true,
      passed: !issues.some((issue) => issue.subject === 'geo_compliance' && issue.severity === 'blocking'),
      warning: issues.some((issue) => issue.subject === 'geo_compliance' && issue.severity === 'warning'),
      current: {
        countryCode: current.countryCode,
        region: current.region,
        city: current.city,
        hasCoordinates: this.hasCoordinates(current),
        source: current.source,
        consented: current.consented,
        capturedAt: current.capturedAt,
      },
      previous: previous ? {
        countryCode: previous.countryCode,
        region: previous.region,
        city: previous.city,
        hasCoordinates: this.hasCoordinates(previous),
        source: previous.source,
        capturedAt: previous.capturedAt,
      } : null,
      issueCodes: issues.filter((issue) => issue.subject === 'geo_compliance').map((issue) => issue.code),
    };
  }

  private extractTransactionGeo(metadata: Record<string, any>): TransactionGeoSignal {
    const geo = this.objectValue(metadata.geo);
    const riskContext = this.objectValue(metadata.riskContext);
    const ipGeo = this.objectValue(metadata.ipGeo || metadata.ip_geo);
    const fallback = Object.keys(geo).length > 0 ? geo : ipGeo;

    return {
      countryCode: this.normalizeNullable(
        geo.countryCode ||
        geo.country_code ||
        riskContext.countryCode ||
        riskContext.country_code ||
        metadata.countryCode ||
        metadata.country_code ||
        ipGeo.countryCode ||
        ipGeo.country_code,
      )?.toUpperCase() || null,
      region: this.normalizeNullable(
        geo.region ||
        geo.regionCode ||
        geo.region_code ||
        riskContext.region ||
        metadata.region ||
        metadata.regionCode ||
        metadata.region_code ||
        ipGeo.region ||
        ipGeo.regionCode ||
        ipGeo.region_code,
      ),
      city: this.normalizeNullable(geo.city || riskContext.city || metadata.city || ipGeo.city),
      latitude: this.numberOrNull(
        fallback.latitudeRounded ??
        fallback.latRounded ??
        fallback.latitude ??
        fallback.lat,
      ),
      longitude: this.numberOrNull(
        fallback.longitudeRounded ??
        fallback.lngRounded ??
        fallback.longitude ??
        fallback.lng,
      ),
      source: this.normalizeNullable(geo.source || riskContext.source || metadata.geoSource || ipGeo.source) || null,
      consented: this.booleanOrNull(geo.consented ?? geo.locationConsent ?? riskContext.locationConsent ?? metadata.locationConsent),
      capturedAt: this.normalizeNullable(geo.capturedAt || geo.captured_at || metadata.geoCapturedAt || ipGeo.capturedAt || ipGeo.captured_at),
    };
  }

  private findPreviousGeoTransaction(history: any[]): TransactionGeoSignal | null {
    for (const tx of history) {
      const metadata = tx?.metadata && typeof tx.metadata === 'object' ? tx.metadata : {};
      const geo = this.extractTransactionGeo({
        ...metadata,
        geo: metadata.geo || metadata.ipGeo || metadata.ip_geo,
        geoCapturedAt: metadata.geoCapturedAt || metadata.geo_captured_at || tx.date,
      });
      if (this.hasSufficientGeo(geo)) return geo;
    }
    return null;
  }

  private hasSufficientGeo(geo: TransactionGeoSignal) {
    return Boolean(
      this.hasCoordinates(geo) ||
      (geo.countryCode && (geo.region || geo.city))
    );
  }

  private hasCoordinates(geo: TransactionGeoSignal) {
    return geo.latitude !== null && geo.longitude !== null;
  }

  private isNetworkGeoFallback(geo: TransactionGeoSignal, metadata: Record<string, any>) {
    const riskContext = this.objectValue(metadata.riskContext);
    const source = String(geo.source || '').toLowerCase();
    return (
      riskContext.locationFallback === true ||
      source.includes('network_ip') ||
      source.includes('ip_geo') ||
      source.includes('request_ip')
    );
  }

  private geoTimestampMs(geo: TransactionGeoSignal) {
    if (!geo.capturedAt) return null;
    const time = new Date(geo.capturedAt).getTime();
    return Number.isFinite(time) ? time : null;
  }

  private distanceKm(lat1: number, lon1: number, lat2: number, lon2: number) {
    const radiusKm = 6371;
    const toRad = (value: number) => (value * Math.PI) / 180;
    const dLat = toRad(lat2 - lat1);
    const dLon = toRad(lon2 - lon1);
    const a =
      Math.sin(dLat / 2) * Math.sin(dLat / 2) +
      Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) *
      Math.sin(dLon / 2) * Math.sin(dLon / 2);
    return radiusKm * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  }

  private objectValue(value: any): Record<string, any> {
    return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  }

  private numberOrNull(value: any): number | null {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }

  private booleanOrNull(value: any): boolean | null {
    if (typeof value === 'boolean') return value;
    if (typeof value === 'string') {
      const normalized = value.trim().toLowerCase();
      if (['true', 'yes', '1'].includes(normalized)) return true;
      if (['false', 'no', '0'].includes(normalized)) return false;
    }
    return null;
  }

  private resolvePreflightState(issues: PreflightIssue[], decision: string) {
    if (issues.some((issue) => issue.subject === 'geo_compliance' && issue.severity === 'blocking')) return 'GEO_COMPLIANCE_REQUIRED';
    if (issues.some((issue) => issue.code === 'SELF_TRANSFER_WALLET_NOT_ALLOWED')) return 'SELF_TRANSFER_NOT_ALLOWED';
    if (issues.some((issue) => issue.code === 'INSUFFICIENT_FUNDS')) return 'INSUFFICIENT_FUNDS';
    if (issues.some((issue) => issue.code.includes('WALLET_LOCKED'))) return 'WALLET_LOCKED';
    if (issues.some((issue) => issue.code.includes('WALLET_REQUIRED'))) return 'WALLET_REQUIRED';
    if (issues.some((issue) => issue.code.includes('PROVIDER'))) return 'PROVIDER_UNAVAILABLE';
    if (issues.some((issue) => issue.code.includes('FEE'))) return 'FEE_CONFIGURATION_REQUIRED';
    if (issues.some((issue) => issue.code.includes('ACCOUNT') || issue.code.includes('KYC'))) return 'ACCOUNT_RESTRICTED';
    if (decision === 'BLOCK') return 'RULE_BLOCKED';
    if (decision === 'CHALLENGE') return 'CHALLENGE_REQUIRED';
    if (issues.some((issue) => issue.severity === 'blocking')) return 'BLOCKED';
    return 'READY';
  }

  private buildChecks(args: {
    user: User;
    type: string;
    amount: number;
    currency: string;
    sourceWallet: WalletSnapshot | null;
    targetWallet: WalletSnapshot | null;
    provider: any;
    fee: any;
    balance: number;
    totalDebit: number;
    risk: any;
    issues: PreflightIssue[];
  }) {
    const metadata = (args.user as any).user_metadata || {};
    const hasIssue = (subject: string) => args.issues.some((issue) => issue.subject === subject && issue.severity === 'blocking');
    return {
      account: {
        passed: !hasIssue('account'),
        status: metadata.account_status || 'active',
        kycStatus: metadata.kyc_status || 'unknown',
        registryType: metadata.registry_type || null,
        role: metadata.role || null,
        organizationId: metadata.organization_id || null,
      },
      sourceWallet: {
        passed: !hasIssue('source_wallet'),
        required: this.requiresDebit(args.type),
        wallet: args.sourceWallet ? this.formatWallet(args.sourceWallet) : null,
        displayName: args.sourceWallet ? this.resolveWalletDisplayName(args.sourceWallet) : null,
      },
      targetWallet: {
        passed: !hasIssue('target_wallet'),
        required: ['INTERNAL_TRANSFER', 'PEER_TRANSFER', 'DEPOSIT'].includes(args.type),
        wallet: args.targetWallet ? this.formatWallet(args.targetWallet) : null,
        displayName: args.targetWallet ? this.resolveWalletDisplayName(args.targetWallet) : null,
      },
      balance: {
        passed: !this.requiresDebit(args.type) || args.balance >= args.totalDebit,
        available: args.balance,
        required: this.requiresDebit(args.type) ? args.totalDebit : 0,
        deficit: this.requiresDebit(args.type) ? Math.max(0, this.round(args.totalDebit - args.balance)) : 0,
      },
      provider: {
        passed: !hasIssue('provider'),
        required: EXTERNAL_TYPES.has(args.type),
        providerId: args.provider?.providerId || null,
        providerCode: args.provider?.providerCode || null,
      },
      fees: {
        passed: !hasIssue('fee_configuration'),
        flowCode: args.fee.flowCode,
        configId: args.fee.configId || null,
        totalFee: args.fee.totalFee,
      },
      transactionRules: {
        passed: args.risk.passed === true,
        decision: args.risk.decision,
        score: args.risk.score,
      },
    };
  }

  private issueFromError(error: unknown, subject: string): PreflightIssue {
    const raw = error instanceof Error ? error.message : String(error || 'UNKNOWN_ERROR');
    const [code, detail] = raw.split(':');
    const normalizedCode = String(code || 'UNKNOWN_ERROR').trim().toUpperCase();
    const retryable = ['DB_OFFLINE', 'PROVIDER_ROUTE_NOT_FOUND', 'FX_RATE_UNAVAILABLE'].includes(normalizedCode);
    return {
      code: normalizedCode,
      severity: 'blocking',
      subject,
      message: this.issueMessage(normalizedCode, detail || raw),
      retryable,
      metadata: { detail: detail || null },
    };
  }

  private issueMessage(code: string, detail: string) {
    switch (code) {
      case 'SOURCE_WALLET_REQUIRED_FOR_QUOTE':
        return `No usable source wallet was found for this transaction${detail ? ` (${detail})` : ''}.`;
      case 'TARGET_WALLET_REQUIRED_FOR_QUOTE':
        return `No usable target wallet was found for this transaction${detail ? ` (${detail})` : ''}.`;
      case 'RECIPIENT_REQUIRED_FOR_QUOTE':
        return 'Recipient could not be resolved to an active ORBI account.';
      case 'SOURCE_WALLET_ACCESS_DENIED':
        return 'The selected source wallet does not belong to the authenticated account.';
      case 'PROVIDER_ROUTE_NOT_FOUND':
        return 'No active provider route is configured for this transaction model.';
      case 'PLATFORM_FEE_CONFIG_REQUIRED':
        return 'No active platform fee configuration matches this transaction model and category.';
      case 'DB_OFFLINE':
        return 'Database is not reachable for transaction preview.';
      case 'LEDGER_BALANCE_UNAVAILABLE':
        return 'Ledger balance is temporarily unavailable for the selected source wallet.';
      case 'LEDGER_BALANCE_INVALID':
        return 'Ledger balance could not be verified for the selected source wallet.';
      case 'SOURCE_WALLET_REQUIRED_FOR_BALANCE':
        return 'A verified source wallet is required before this transaction can continue.';
      default:
        return detail || code;
    }
  }

  private zeroFee(flowCode: string, amount: number, currency: string, classification: Record<string, any>) {
    return {
      flowCode,
      configId: null,
      configName: null,
      currency,
      amount,
      percentageRate: 0,
      fixedAmount: 0,
      minimumFee: 0,
      maximumFee: null,
      taxRate: 0,
      govFeeRate: 0,
      stampDutyFixed: 0,
      percentageFee: 0,
      serviceFee: 0,
      taxAmount: 0,
      govFeeAmount: 0,
      totalFee: 0,
      netAmount: amount,
      classification,
      metadata: { fallback: true },
    };
  }

  private formatWallet(wallet: WalletSnapshot) {
    return {
      id: wallet.id,
      type: wallet.table,
      name: wallet.name || null,
      displayName: this.resolveWalletDisplayName(wallet),
      currency: wallet.currency,
      role: wallet.role || null,
      status: wallet.status || null,
      isLocked: wallet.isLocked === true,
    };
  }

  private resolveWalletDisplayName(wallet: WalletSnapshot) {
    const metadata = wallet.metadata || {};
    return (
      wallet.name ||
      metadata.display_name ||
      metadata.account_name ||
      metadata.label ||
      wallet.role ||
      `${wallet.currency} wallet`
    );
  }

  private requiresDebit(type: string) {
    return DEBIT_TYPES.has(type);
  }

  private normalizeType(value: string) {
    const normalized = String(value || '').trim().toUpperCase();
    if (normalized === 'INTERNAL') return 'INTERNAL_TRANSFER';
    if (normalized === 'EXTERNAL') return 'EXTERNAL_PAYMENT';
    return normalized;
  }

  private normalizeCurrency(value: any) {
    return String(value || '').trim().toUpperCase();
  }

  private normalizeNullable(value: any) {
    const text = String(value || '').trim();
    return text || null;
  }

  private extractWalletId(payload: any, metadata: Record<string, any>, keys: string[]) {
    for (const key of keys) {
      const direct = this.normalizeNullable(payload?.[key]);
      if (direct) return direct;
      const nested = this.normalizeNullable(metadata?.[key]);
      if (nested) return nested;
    }
    return null;
  }

  private isInactiveWallet(wallet: WalletSnapshot) {
    const status = String(wallet.status || '').trim().toLowerCase();
    return ['blocked', 'disabled', 'inactive', 'suspended', 'closed'].includes(status);
  }

  private looksLikeUuid(value: string) {
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
  }

  private parseAmount(value: any) {
    const parsed = Number(value);
    if (!Number.isFinite(parsed)) return 0;
    return this.round(parsed);
  }

  private round(value: number) {
    return Math.round(value * 100) / 100;
  }

  private resolveQuoteTtlMs() {
    const configured = Number(process.env.ORBI_TRANSACTION_QUOTE_TTL_SECONDS || 120);
    return Math.max(30, configured) * 1000;
  }
}

export const transactionQuoteService = new TransactionQuoteService();
