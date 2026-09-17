import { logger } from './logger.js';
import parsePhoneNumber from 'libphonenumber-js';
import { MessageType, TemplateChannel, TemplateLanguage, TemplateName, TemplatePayloads } from '../templates/template_types.js';
import {
    NotificationBrand,
    NotificationBrandContext,
    resolveNotificationBrand,
    resolveTemplateNotificationBrand,
} from './NotificationBrandResolver.js';

export const orbiTalkGatewayLogger = logger.child({ component: 'orbi_talk_gateway_service' });

const envFirst = (...keys: string[]) => {
    for (const key of keys) {
        const value = process.env[key]?.trim();
        if (value) return value;
    }
    return undefined;
};

class OrbiTalkGatewayService {
    private apiKey: string | undefined;
    private baseUrl: string | undefined;

    constructor() {
        this.apiKey = envFirst('ORBI_TALK_GATEWAY_API_KEY');
        this.baseUrl = this.normalizeBaseUrl(
            envFirst(
                'ORBI_TALK_GATEWAY_URL',
                'ORBI_TALK_GATEWAY_BASE_URL'
            )
        );
        
        if (!this.apiKey) {
            orbiTalkGatewayLogger.warn('orbi_talk_gateway.api_key_missing');
        }
        if (!this.baseUrl) {
            orbiTalkGatewayLogger.warn('orbi_talk_gateway.url_missing');
        }
    }

    private normalizeBaseUrl(url?: string): string | undefined {
        const raw = url?.trim();
        if (!raw) return undefined;
        return raw.replace(/\/+$/, '').replace(/\/api$/, '');
    }

    private externalDeliveryDisabled(): boolean {
        return process.env.ORBI_DISABLE_EXTERNAL_DELIVERIES === 'true';
    }

    private normalizePhone(phone: string): string {
        try {
            const parsed = parsePhoneNumber(phone, 'TZ');
            if (parsed && parsed.isValid()) {
                return parsed.format('E.164');
            }
            return phone.startsWith('+') ? phone : '+' + phone.replace(/\s/g, '');
        } catch (e) {
            return phone.startsWith('+') ? phone : '+' + phone.replace(/\s/g, '');
        }
    }

    private ownerUid(ownerUid?: string): string | undefined {
        return ownerUid || envFirst('ORBI_TALK_GATEWAY_USER_ID');
    }

    private ownerEmail(ownerEmail?: string): string | undefined {
        return ownerEmail || envFirst('ORBI_TALK_GATEWAY_USER_EMAIL');
    }

    private redactPushPayload<T extends Record<string, any>>(payload: T): T {
        return {
            ...payload,
            ...(payload.token ? { token: '[redacted]' } : {}),
            ...(payload.fcmToken ? { fcmToken: '[redacted]' } : {}),
        };
    }

    private brandPayload(context?: NotificationBrandContext | NotificationBrand) {
        const brand = context && 'source' in context
            ? context as NotificationBrand
            : resolveNotificationBrand(context);
        return {
            brand,
            brandCode: brand.code,
            senderName: brand.displayName,
            fromName: brand.displayName,
            sender: brand.displayName,
            platformName: brand.displayName,
            senderEmail: brand.senderEmail,
            fromEmail: brand.senderEmail,
            replyTo: brand.replyTo,
            logoUrl: brand.logoUrl,
        };
    }

    private normalizeTemplateData<T extends TemplateName>(templateName: T, data: TemplatePayloads[T]): TemplatePayloads[T] {
        const normalized: Record<string, any> = { ...(data as Record<string, any>) };

        for (const [key, value] of Object.entries(normalized)) {
            if (typeof value === 'string') {
                normalized[key] = value.trim();
            }
        }

        const fallbackName =
            normalized.name ||
            normalized.full_name ||
            normalized.customerName ||
            normalized.recipientName ||
            normalized.senderName ||
            'User';
        const fallbackDeviceName =
            normalized.deviceName ||
            normalized.device_name ||
            'ORBI Mobile';
        const fallbackRefId =
            normalized.refId ||
            normalized.reference ||
            normalized.transactionId ||
            normalized.requestId ||
            `ORBI-${Date.now().toString(36).toUpperCase()}`;
        const fallbackTimestamp =
            normalized.timestamp ||
            normalized.createdAt ||
            normalized.created_at ||
            new Date().toISOString();
        const fallbackCurrency = normalized.currency || 'TZS';
        const fallbackAmount = normalized.amount ?? '0';
        const fallbackRecipientName =
            normalized.recipientName ||
            normalized.customerName ||
            normalized.name ||
            fallbackName;
        const fallbackSenderName =
            normalized.senderName ||
            normalized.actorLabel ||
            normalized.name ||
            fallbackName;
        const fallbackActorLabel = normalized.actorLabel || 'ORBI';

        normalized.refId = normalized.refId || fallbackRefId;

        switch (templateName) {
            case 'OTP_Message':
                normalized.name = normalized.name || fallbackName;
                normalized.deviceName = normalized.deviceName || fallbackDeviceName;
                break;
            case 'Welcome_Message':
            case 'LOW_BALANCE':
                normalized.name = normalized.name || fallbackName;
                break;
            case 'New_Device_Alert':
                normalized.deviceName = normalized.deviceName || fallbackDeviceName;
                break;
            case 'Transfer_Sent':
                normalized.senderName = normalized.senderName || fallbackSenderName;
                normalized.recipientName = normalized.recipientName || fallbackRecipientName;
                normalized.currency = normalized.currency || fallbackCurrency;
                normalized.amount = normalized.amount ?? fallbackAmount;
                normalized.timestamp = normalized.timestamp || fallbackTimestamp;
                break;
            case 'Transfer_Received':
                normalized.senderName = normalized.senderName || fallbackSenderName;
                normalized.currency = normalized.currency || fallbackCurrency;
                normalized.amount = normalized.amount ?? fallbackAmount;
                normalized.timestamp = normalized.timestamp || fallbackTimestamp;
                break;
            case 'Escrow_Created':
            case 'Escrow_Request_Received':
            case 'Escrow_Released':
            case 'Escrow_Refunded':
                normalized.senderName = normalized.senderName || fallbackSenderName;
                normalized.recipientName = normalized.recipientName || fallbackRecipientName;
                normalized.currency = normalized.currency || fallbackCurrency;
                normalized.amount = normalized.amount ?? fallbackAmount;
                break;
            case 'Salary_Received':
                normalized.employeeName = normalized.employeeName || fallbackName;
                normalized.name = normalized.name || normalized.employeeName;
                normalized.month = normalized.month || new Intl.DateTimeFormat('en', { month: 'long', year: 'numeric' }).format(new Date());
                normalized.currency = normalized.currency || fallbackCurrency;
                normalized.amount = normalized.amount ?? fallbackAmount;
                normalized.timestamp = normalized.timestamp || fallbackTimestamp;
                break;
            case 'Treasury_Withdrawal_Request':
                normalized.employeeName = normalized.employeeName || fallbackName;
                normalized.currency = normalized.currency || fallbackCurrency;
                normalized.amount = normalized.amount ?? fallbackAmount;
                normalized.reason = normalized.reason || 'Treasury operation review';
                break;
            case 'Merchant_Service_Update':
            case 'Merchant_Customer_Payment_Update':
                normalized.actorLabel = normalized.actorLabel || fallbackActorLabel;
                normalized.currency = normalized.currency || fallbackCurrency;
                normalized.amount = normalized.amount ?? fallbackAmount;
                normalized.status = normalized.status || 'COMPLETED';
                break;
            case 'Agent_Cash_Update':
            case 'Agent_Customer_Cash_Update':
                normalized.actorLabel = normalized.actorLabel || fallbackActorLabel;
                normalized.currency = normalized.currency || fallbackCurrency;
                normalized.amount = normalized.amount ?? fallbackAmount;
                normalized.direction = normalized.direction || 'deposit';
                normalized.status = normalized.status || 'COMPLETED';
                break;
            case 'Agent_Commission_Paid':
                normalized.actorLabel = normalized.actorLabel || fallbackActorLabel;
                normalized.currency = normalized.currency || fallbackCurrency;
                normalized.amount = normalized.amount ?? fallbackAmount;
                break;
            case 'Service_Customer_Registered':
                normalized.actorLabel = normalized.actorLabel || fallbackActorLabel;
                normalized.customerName = normalized.customerName || fallbackRecipientName;
                break;
            case 'Service_Access_Approved':
                normalized.actorLabel = normalized.actorLabel || fallbackActorLabel;
                break;
            case 'Security_Alert_Message':
                normalized.subject = normalized.subject || 'ORBI security alert';
                normalized.body = normalized.body || 'A security event was detected on your ORBI account.';
                break;
            case 'Promo_Message':
            case 'Transactional_Message':
                normalized.body = normalized.body || normalized.subject || 'ORBI account update.';
                break;
            default:
                break;
        }

        return normalized as TemplatePayloads[T];
    }

    async sendSms(recipient: string, body: string, language: string = 'en', ownerUid?: string, ownerEmail?: string, requestId?: string): Promise<boolean> {
        if (this.externalDeliveryDisabled()) {
            orbiTalkGatewayLogger.info('orbi_talk_gateway.external_delivery_disabled', { channel: 'sms' });
            return false;
        }
        if (!this.apiKey || !this.baseUrl) {
            orbiTalkGatewayLogger.error('orbi_talk_gateway.sms_missing_configuration', { channel: 'sms' });
            return false;
        }

        const normalizedRecipient = this.normalizePhone(recipient);

        try {
            const endpoint = `${this.baseUrl}/api/send-sms`;
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-api-key': this.apiKey
                },
                body: JSON.stringify({
                    recipient: normalizedRecipient,
                    body,
                    channel: 'sms',
                    messageType: 'transactional',
                    language,
                    ownerUid: this.ownerUid(ownerUid),
                    ownerEmail: this.ownerEmail(ownerEmail),
                    requestId
                })
            });

            if (!response.ok) {
                const errorText = await response.text();
                orbiTalkGatewayLogger.error('orbi_talk_gateway.sms_failed', { endpoint, status_code: response.status, channel: 'sms', recipient: normalizedRecipient, error_text: errorText });
                return false;
            }

            orbiTalkGatewayLogger.info('orbi_talk_gateway.sms_sent', { channel: 'sms', recipient: normalizedRecipient });
            return true;
        } catch (error) {
            orbiTalkGatewayLogger.error('orbi_talk_gateway.sms_exception', { channel: 'sms', recipient: normalizedRecipient }, error);
            return false;
        }
    }

    async sendEmail(recipient: string, subject: string, body: string, html?: string, language: string = 'en', ownerUid?: string, ownerEmail?: string, requestId?: string, brand?: NotificationBrandContext | NotificationBrand): Promise<boolean> {
        if (this.externalDeliveryDisabled()) {
            orbiTalkGatewayLogger.info('orbi_talk_gateway.external_delivery_disabled', { channel: 'email' });
            return false;
        }
        if (!this.apiKey || !this.baseUrl) {
            orbiTalkGatewayLogger.error('orbi_talk_gateway.email_missing_configuration', { channel: 'email', recipient });
            return false;
        }

        try {
            const endpoint = `${this.baseUrl}/api/send-email`;
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-api-key': this.apiKey
                },
                body: JSON.stringify({
                    recipient,
                    body,
                    subject,
                    html,
                    ...this.brandPayload(brand),
                    messageType: 'transactional',
                    language,
                    ownerUid: this.ownerUid(ownerUid),
                    ownerEmail: this.ownerEmail(ownerEmail),
                    requestId
                })
            });

            if (!response.ok) {
                const errorText = await response.text();
                orbiTalkGatewayLogger.error('orbi_talk_gateway.email_failed', { endpoint, status_code: response.status, channel: 'email', recipient, error_text: errorText });
                return false;
            }

            orbiTalkGatewayLogger.info('orbi_talk_gateway.email_sent', { channel: 'email', recipient });
            return true;
        } catch (error) {
            orbiTalkGatewayLogger.error('orbi_talk_gateway.email_exception', { channel: 'email', recipient }, error);
            return false;
        }
    }

    async getEmailHealth(): Promise<{
        success: boolean;
        status: 'ACTIVE' | 'MISSING_CONFIG' | 'UNREACHABLE';
        provider?: string | null;
        configured?: boolean;
        missing?: string[];
        allowedSenders?: Array<{ email: string; sender: string }>;
        raw?: any;
    }> {
        if (!this.apiKey || !this.baseUrl) {
            orbiTalkGatewayLogger.error('orbi_talk_gateway.email_health_missing_configuration');
            return {
                success: false,
                status: 'MISSING_CONFIG',
                missing: [
                    ...(!this.apiKey ? ['ORBI_TALK_GATEWAY_API_KEY'] : []),
                    ...(!this.baseUrl ? ['ORBI_TALK_GATEWAY_URL'] : []),
                ],
            };
        }

        const endpoint = `${this.baseUrl}/api/email/health`;
        try {
            const response = await fetch(endpoint, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'x-api-key': this.apiKey,
                },
            });
            const payload = await response.json().catch(() => ({}));
            if (!response.ok) {
                orbiTalkGatewayLogger.error('orbi_talk_gateway.email_health_failed', {
                    endpoint,
                    status_code: response.status,
                    missing: payload?.email?.missing || [],
                });
                return {
                    success: false,
                    status: 'MISSING_CONFIG',
                    provider: payload?.email?.provider || null,
                    configured: Boolean(payload?.email?.configured),
                    missing: Array.isArray(payload?.email?.missing) ? payload.email.missing : [],
                    allowedSenders: Array.isArray(payload?.email?.allowedSenders) ? payload.email.allowedSenders : [],
                    raw: payload,
                };
            }

            return {
                success: true,
                status: 'ACTIVE',
                provider: payload?.email?.provider || null,
                configured: Boolean(payload?.email?.configured),
                missing: Array.isArray(payload?.email?.missing) ? payload.email.missing : [],
                allowedSenders: Array.isArray(payload?.email?.allowedSenders) ? payload.email.allowedSenders : [],
                raw: payload,
            };
        } catch (error) {
            orbiTalkGatewayLogger.error('orbi_talk_gateway.email_health_exception', { endpoint }, error);
            return {
                success: false,
                status: 'UNREACHABLE',
                missing: [],
            };
        }
    }

    async sendPush(fcmToken: string, title: string, body: string, data: Record<string, any> = {}, language: string = 'en', ownerUid?: string, ownerEmail?: string, requestId?: string): Promise<boolean> {
        if (this.externalDeliveryDisabled()) {
            orbiTalkGatewayLogger.info('orbi_talk_gateway.external_delivery_disabled', { channel: 'push' });
            return false;
        }
        if (!this.apiKey || !this.baseUrl) {
            orbiTalkGatewayLogger.error('orbi_talk_gateway.push_missing_configuration', { channel: 'push' });
            return false;
        }

        try {
            const payload = {
                token: fcmToken,
                title,
                body,
                data,
                language,
                ownerUid: this.ownerUid(ownerUid),
                ownerEmail: this.ownerEmail(ownerEmail),
                requestId
            };

            orbiTalkGatewayLogger.debug('orbi_talk_gateway.push_payload_prepared', {
                channel: 'push',
                payload: this.redactPushPayload(payload),
            });

            const endpoint = `${this.baseUrl}/api/send-push`;
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-api-key': this.apiKey
                },
                body: JSON.stringify(payload)
            });

            if (!response.ok) {
                const errorText = await response.text();
                orbiTalkGatewayLogger.error('orbi_talk_gateway.push_failed', { endpoint, status_code: response.status, channel: 'push', error_text: errorText });
                return false;
            }

            orbiTalkGatewayLogger.info('orbi_talk_gateway.push_sent', {
                channel: 'push',
                event_origin: data.event_origin || data.eventOrigin || 'ORBI_TALK_GATEWAY',
                delivery_rail: data.delivery_rail || data.deliveryRail || 'TALK_GATEWAY_PUSH',
                request_id: requestId,
            });
            return true;
        } catch (error) {
            orbiTalkGatewayLogger.error('orbi_talk_gateway.push_exception', { channel: 'push' }, error);
            return false;
        }
    }

    async sendTemplate<T extends TemplateName>(
        templateName: T, 
        recipient: string, 
        data: TemplatePayloads[T], 
        options: { channel?: string; language?: string; messageType?: 'transactional' | 'promotional'; fcmToken?: string; ownerUid?: string; ownerEmail?: string; requestId?: string; brand?: NotificationBrandContext | NotificationBrand } = {}
    ): Promise<boolean> {
        const { channel = 'sms', language = 'en', messageType = 'transactional', fcmToken, ownerUid, ownerEmail, requestId, brand } = options;

        if (this.externalDeliveryDisabled()) {
            orbiTalkGatewayLogger.info('orbi_talk_gateway.external_delivery_disabled', { channel, template_name: templateName });
            return false;
        }

        if (!this.apiKey || !this.baseUrl) {
            orbiTalkGatewayLogger.error('orbi_talk_gateway.template_missing_configuration', { channel, recipient, template_name: templateName });
            return false;
        }

        const normalizedRecipient = (channel === 'sms' || channel === 'whatsapp') ? this.normalizePhone(recipient) : recipient;

        try {
            const normalizedData = this.normalizeTemplateData(templateName, data);
            const resolvedBrand = resolveTemplateNotificationBrand(
                templateName,
                normalizedData as Record<string, any>,
                brand,
            );
            const payload = {
                templateName,
                recipient: normalizedRecipient,
                data: normalizedData,
                ...this.brandPayload(resolvedBrand),
                channel,
                language,
                messageType,
                ownerUid: this.ownerUid(ownerUid),
                ownerEmail: this.ownerEmail(ownerEmail),
                requestId,
                ...(fcmToken && channel !== 'push' ? { fcmToken } : {})
            };

            orbiTalkGatewayLogger.debug('orbi_talk_gateway.template_payload_prepared', {
                channel,
                recipient,
                template_name: templateName,
                payload: this.redactPushPayload(payload),
            });

            const endpoint = `${this.baseUrl}/api/send-template`;
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-api-key': this.apiKey
                },
                body: JSON.stringify(payload)
            });

            if (!response.ok) {
                const errorText = await response.text();
                orbiTalkGatewayLogger.error('orbi_talk_gateway.template_failed', { endpoint, status_code: response.status, channel, recipient, template_name: templateName, error_text: errorText });
                return false;
            }

            const responseBody = await response.json().catch(() => ({} as any));
            const status = String(responseBody?.status || '').toLowerCase();
            const dispatchAccepted =
                channel === 'email'
                    ? responseBody?.emailSent === true || responseBody?.success === true
                    : responseBody?.pushed === true || status === 'sent' || status === 'delivered';

            if (!dispatchAccepted) {
                orbiTalkGatewayLogger.warn('orbi_talk_gateway.template_queued_or_not_dispatched', {
                    channel,
                    recipient,
                    template_name: templateName,
                    message_id: responseBody?.messageId,
                    pushed: responseBody?.pushed,
                    email_sent: responseBody?.emailSent,
                    status: responseBody?.status,
                    dispatch_reason: responseBody?.dispatchReason,
                    message: responseBody?.message,
                });
                return false;
            }

            orbiTalkGatewayLogger.info('orbi_talk_gateway.template_sent', {
                channel,
                recipient,
                template_name: templateName,
                message_id: responseBody?.messageId,
                pushed: responseBody?.pushed,
                email_sent: responseBody?.emailSent,
            });
            return true;
        } catch (error) {
            orbiTalkGatewayLogger.error('orbi_talk_gateway.template_exception', { channel, recipient, template_name: templateName }, error);
            return false;
        }
    }

    async getTemplateCatalog(options: {
        search?: string;
        channel?: TemplateChannel;
        language?: TemplateLanguage;
        messageType?: MessageType;
        limit?: number;
    } = {}): Promise<Array<{
        name: string;
        channel: TemplateChannel;
        language: TemplateLanguage | string;
        messageType: MessageType;
        subject?: string;
        body: string;
        variables: string[];
    }>> {
        if (!this.apiKey || !this.baseUrl) {
            orbiTalkGatewayLogger.error('orbi_talk_gateway.template_catalog_missing_configuration');
            return [];
        }

        const params = new URLSearchParams();
        if (options.search) params.set('search', options.search);
        if (options.channel) params.set('channel', options.channel);
        if (options.language) params.set('language', options.language);
        if (options.messageType) params.set('messageType', options.messageType);
        if (options.limit) params.set('limit', String(options.limit));
        const ownerUid = this.ownerUid();
        if (ownerUid) params.set('ownerUid', ownerUid);

        const endpoint = `${this.baseUrl}/api/templates/catalog${params.size ? `?${params.toString()}` : ''}`;

        try {
            const response = await fetch(endpoint, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'x-api-key': this.apiKey
                },
            });

            if (!response.ok) {
                const errorText = await response.text();
                orbiTalkGatewayLogger.error('orbi_talk_gateway.template_catalog_failed', { endpoint, status_code: response.status, error_text: errorText });
                return [];
            }

            const payload = await response.json().catch(() => ({}));
            return Array.isArray(payload?.data) ? payload.data : [];
        } catch (error) {
            orbiTalkGatewayLogger.error('orbi_talk_gateway.template_catalog_exception', { endpoint }, error);
            return [];
        }
    }
}

export const orbiTalkGatewayService = new OrbiTalkGatewayService();
