
import { UserMessage, UserProfile, Wallet } from '../../types.js';
import { getSupabase, getAdminSupabase } from '../../services/supabaseClient.js';
import { UUID } from '../../services/utils.js';
import { Storage, STORAGE_KEYS } from '../storage.js';
import { GoogleGenAI } from "@google/genai";
import { DataVault } from '../security/encryption.js';
import { DataProtection } from '../security/DataProtection.js';
import { orbiTalkGatewayService } from '../infrastructure/orbiTalkGatewayService.js';
import { firebasePushService } from '../infrastructure/firebasePushService.js';
import parsePhoneNumber from 'libphonenumber-js';

import { SocketRegistry } from '../infrastructure/SocketRegistry.js';

import { TemplateName, TemplatePayloads } from '../templates/template_types.js';
import { officialOrbiTalkTemplatePolicy } from './OfficialOrbiTalkTemplatePolicy.js';
import {
    NotificationBrand,
    NotificationBrandContext,
    resolveNotificationBrand,
} from '../infrastructure/NotificationBrandResolver.js';
import { GlobalTimeResolver } from '../utils/GlobalTimeResolver.js';
import { getOrbiDatabase } from '../../services/orbiDatabase.js';

/**
 * NEXUS MESSAGING & NOTIFICATION NODE (V5.1)
 * -----------------------------------------
 * Orchestrates direct-to-user alerts and AI-synthesized system notifications.
 */
class MessagingService {
    private readonly profileCache = new Map<string, { value: any; expiresAt: number }>();
    private readonly profileInflight = new Map<string, Promise<any>>();
    private readonly profileCacheEpoch = new Map<string, number>();
    private readonly PROFILE_CACHE_TTL_MS = 30_000;

    public invalidateUserProfile(userId: string) {
        const key = String(userId || '').trim();
        if (!key) return;
        this.profileCache.delete(key);
        this.profileInflight.delete(key);
        this.profileCacheEpoch.set(key, (this.profileCacheEpoch.get(key) || 0) + 1);
    }

    private async getUserProfile(userId: string): Promise<any> {
        const key = String(userId || '').trim();
        const now = Date.now();
        const cached = this.profileCache.get(key);
        if (cached && cached.expiresAt > now) {
            return cached.value;
        }

        const inflight = this.profileInflight.get(key);
        if (inflight) {
            return inflight;
        }

        const cacheEpoch = this.profileCacheEpoch.get(key) || 0;
        const loadPromise = this.loadUserProfile(key);
        this.profileInflight.set(key, loadPromise);
        try {
            const profile = await loadPromise;
            if ((this.profileCacheEpoch.get(key) || 0) === cacheEpoch) {
                this.profileCache.set(key, {
                    value: profile,
                    expiresAt: now + this.PROFILE_CACHE_TTL_MS,
                });
            }
            return profile;
        } finally {
            if (this.profileInflight.get(key) === loadPromise) {
                this.profileInflight.delete(key);
            }
        }
    }

    private async loadUserProfile(userId: string): Promise<any> {
        const sb = getAdminSupabase();
        if (sb) {
            let { data: profile } = await sb.from('users')
                .select('full_name, name, language, notif_push, notif_email, notif_security, notif_financial, notif_budget, notif_marketing, phone, nationality, email, fcm_token, id_type, metadata')
                .eq('id', userId)
                .maybeSingle();
            let resolvedProfile: any = profile;
                
            if (!resolvedProfile) {
                const { data: staffProfile } = await sb.from('staff')
                    .select('full_name, name, language, notif_push, notif_email, notif_security, notif_financial, notif_budget, notif_marketing, phone, nationality, email, fcm_token, id_type')
                    .eq('id', userId)
                    .maybeSingle();
                resolvedProfile = staffProfile;
            }

            const profileData: any = resolvedProfile || {};
            const { data: recentDevice } = await sb
                .from('user_devices')
                .select('device_name')
                .eq('user_id', userId)
                .order('last_active_at', { ascending: false })
                .limit(1)
                .maybeSingle();
            
            // Fallback to Auth if phone is missing
            let phone = profileData.phone;
            let fullName = String(profileData.full_name || profileData.name || '').trim();
            let email = String(profileData.email || '').trim();
            if (!phone && userId && userId !== 'system') {
                const { data: authData } = await sb.auth.admin.getUserById(userId);
                phone = authData.user?.phone || authData.user?.user_metadata?.phone || '';
                fullName =
                    fullName ||
                    String(
                        authData.user?.user_metadata?.full_name ||
                        authData.user?.user_metadata?.name ||
                        authData.user?.user_metadata?.display_name ||
                        '',
                    ).trim();
                email = email || String(authData.user?.email || authData.user?.user_metadata?.email || '').trim();
            } else if (userId && userId !== 'system') {
                const { data: authData } = await sb.auth.admin.getUserById(userId);
                fullName =
                    fullName ||
                    String(
                        authData.user?.user_metadata?.full_name ||
                        authData.user?.user_metadata?.name ||
                        authData.user?.user_metadata?.display_name ||
                        '',
                    ).trim();
                email = email || String(authData.user?.email || authData.user?.user_metadata?.email || '').trim();
            }

            const resolvedFcmToken =
                profileData.fcm_token || await this.loadDevicePushToken(userId);

            return {
                full_name: fullName || (email ? email.split('@')[0] : '') || 'User',
                name: fullName || (email ? email.split('@')[0] : '') || 'User',
                language: profileData.language || 'en',
                notif_push: profileData.notif_push ?? true,
                notif_email: profileData.notif_email ?? true,
                notif_security: profileData.notif_security ?? true,
                notif_financial: profileData.notif_financial ?? true,
                notif_budget: profileData.notif_budget ?? true,
                notif_marketing: profileData.notif_marketing ?? false,
                phone: phone,
                nationality: profileData.nationality || 'Tanzania',
                email,
                fcm_token: resolvedFcmToken,
                id_type: profileData.id_type,
                metadata: profileData.metadata || {},
                device_name: recentDevice?.device_name || 'ORBI Mobile',
            };
        }
        return {
            full_name: 'User',
            name: 'User',
            language: 'en',
            notif_push: true,
            notif_email: true,
            notif_security: true,
            notif_financial: true,
            notif_budget: true,
            notif_marketing: false,
            nationality: 'Tanzania',
            metadata: {},
            device_name: 'ORBI Mobile',
        };
    }

    private async loadDevicePushToken(userId: string): Promise<string | null> {
        const normalizedUserId = String(userId || '').trim();
        if (!normalizedUserId || normalizedUserId === 'system') return null;

        try {
            const pool = getOrbiDatabase();
            const { rows } = await pool.query(
                `
                SELECT fcm_token
                FROM public.users
                WHERE id = $1::uuid
                  AND fcm_token IS NOT NULL
                  AND length(fcm_token) > 0
                UNION ALL
                SELECT fcm_token
                FROM public.staff
                WHERE id = $1::uuid
                  AND fcm_token IS NOT NULL
                  AND length(fcm_token) > 0
                LIMIT 1
                `,
                [normalizedUserId],
            );
            return rows[0]?.fcm_token || null;
        } catch (error: any) {
            console.warn('[Messaging] Direct FCM token lookup failed', {
                userId: normalizedUserId,
                error: error?.message || String(error),
            });
            return null;
        }
    }

    private resolveTimeZone(profile: any, variables: Record<string, any> = {}): string {
        const metadata = profile?.metadata && typeof profile.metadata === 'object' ? profile.metadata : {};
        const explicit = [
            variables.timezone,
            variables.timeZone,
            variables.display_timezone,
            variables.sender_timezone,
            metadata.timezone,
            metadata.timeZone,
            metadata.preferred_timezone,
            metadata.preferredTimeZone,
        ]
            .map((value) => String(value || '').trim())
            .find(Boolean);

        if (explicit && this.isValidTimeZone(explicit)) return explicit;

        // Financial audit rule: never infer a user's timezone from country/phone.
        // If no explicit timezone was captured, preserve canonical UTC display.
        return 'UTC';
    }

    private isValidTimeZone(timeZone: string): boolean {
        try {
            new Intl.DateTimeFormat('en-US', { timeZone }).format(new Date());
            return true;
        } catch {
            return false;
        }
    }

    private buildTimeContext(profile: any, variables: Record<string, any> = {}, occurredAtUtc = new Date().toISOString()) {
        const resolved = GlobalTimeResolver.resolve({
            occurredAtUtc,
            profile,
            metadata: { clientTimeContext: variables.clientTimeContext || variables.client_time_context },
            language: profile?.language || variables.language,
        });
        return {
            canonical_utc: resolved.canonicalUtc,
            display_timezone: resolved.timeZone,
            display_timezone_label: resolved.timeZoneLabel,
            display_clock: resolved.displayClock,
            display_date_time: resolved.displayDateTime,
            display_timestamp: resolved.displayTimestamp,
            message_time: resolved.displayTimestamp,
            source: resolved.source,
        };
    }

    private timeZoneLabel(date: Date, timeZone: string): string {
        if (timeZone === 'UTC') return 'UTC';
        if (timeZone === 'Africa/Dar_es_Salaam' || timeZone === 'Africa/Nairobi' || timeZone === 'Africa/Kampala') return 'EAT';
        if (timeZone === 'Africa/Johannesburg') return 'SAST';
        try {
            const parts = new Intl.DateTimeFormat('en-US', {
                timeZone,
                timeZoneName: 'short',
            }).formatToParts(date);
            return parts.find((part) => part.type === 'timeZoneName')?.value || timeZone;
        } catch {
            return timeZone;
        }
    }

    private normalizeTemplateVariables(
        profile: any,
        variables: Record<string, any> = {},
        fallback: { refId?: string; subject?: string; body?: string } = {},
    ) {
        const name =
            String(
                variables.name ||
                variables.full_name ||
                profile?.full_name ||
                profile?.name ||
                '',
            ).trim() ||
            String(profile?.email || '').split('@')[0] ||
            'User';

        const deviceName =
            String(
                variables.deviceName ||
                variables.device_name ||
                profile?.device_name ||
                'ORBI Mobile',
            ).trim() || 'ORBI Mobile';

        return {
            refId: fallback.refId,
            subject: fallback.subject,
            body: fallback.body,
            timestamp: new Date().toISOString(),
            name,
            full_name: name,
            customerName: variables.customerName || name,
            recipientName: variables.recipientName || name,
            senderName: variables.senderName || name,
            employeeName: variables.employeeName || name,
            actorLabel: variables.actorLabel || 'ORBI',
            deviceName,
            device_name: deviceName,
            email: profile?.email || '',
            phone: profile?.phone || '',
            language: profile?.language || 'en',
            nationality: profile?.nationality || 'Tanzania',
            currency: variables.currency || 'TZS',
            amount: variables.amount ?? 0,
            status: variables.status || 'COMPLETED',
            direction: variables.direction || 'deposit',
            ...variables,
        };
    }

    public async sendWelcomeMessage(user: any, wallets: Wallet[]) {
        const orbiWallet = wallets.find(w => w.name === 'Orbi') || wallets[0];
        const accountId = orbiWallet?.accountNumber || user.customer_id || 'Pending';
        const profile = await this.getUserProfile(user.id);
        const language = profile.language;
        
        let userFullName = user.user_metadata?.full_name;
        if (!userFullName) {
            const sb = getAdminSupabase();
            if (sb) {
                let { data: profile } = await sb.from('users').select('full_name').eq('id', user.id).maybeSingle();
                if (!profile) {
                    const { data: staffProfile } = await sb.from('staff').select('full_name').eq('id', user.id).maybeSingle();
                    profile = staffProfile;
                }
                userFullName = profile?.full_name;
            }
        }
        userFullName = userFullName || (language === 'sw' ? 'Mteja' : 'Customer');
        
        const translations = {
            en: {
                subject: "Welcome to Orbi",
                body: `Hello ${userFullName},

Welcome to Orbi. We are pleased to inform you that your account is now active and ready for use.

**Account Details:**
- **Account ID:** ${accountId}
- **Registered Email:** ${user.email}

Your Orbi and PaySafe accounts have been successfully configured. You may now begin managing your assets through our secure platform.

Should you require any assistance, our support team is available to help:
- **Phone:** [+255 764 258 114](tel:+255764258114)
- **Email:** [auth.orbi@gmail.com](mailto:auth.orbi@gmail.com)

Thank you for choosing Orbi.

Best regards,

**Daniel Z. Gibai**
CEO, ORBI`
            },
            sw: {
                subject: "Karibu Orbi",
                body: `Habari ${userFullName},

Karibu Orbi. Tunafurahi kukujulisha kuwa akaunti yako sasa imewashwa na iko tayari kukutumia.

**Maelezo ya Akaunti:**
- **ID ya Akaunti:** ${accountId}
- **Barua Pepe:** ${user.email}

Akaunti zako za Orbi na PaySafe zimesanidiwa kwa mafanikio. Sasa unaweza kuanza kusimamia mali zako kupitia jukwaa letu salama.

Ikiwa unahitaji msaada wowote, timu yetu ya msaada iko tayari kukusaidia:
- **Simu:** [+255 764 258 114](tel:+255764258114)
- **Barua Pepe:** [auth.orbi@gmail.com](mailto:auth.orbi@gmail.com)

Asante kwa kuichagua Orbi.

Kila la heri,

**Daniel Z. Gibai**
CEO, ORBI`
            }
        };

        const t = translations[language as 'en' | 'sw'] || translations.en;
        const subject = t.subject;
        const body = t.body;

        // 1. Dispatch In-App Notification (Push via Socket)
        await this.dispatch(user.id, 'info', subject, body, {
            sms: true,
            email: true,
            template: 'Welcome_Message',
            variables: { name: userFullName }
        });
    }

    public async dispatch(
        userId: string, 
        category: 'security' | 'update' | 'promo' | 'info',
        subject: string, 
        body: string,
        options: {
            sms?: boolean,
            email?: boolean,
            push?: boolean,
            whatsapp?: boolean,
            template?: string,
            eventCode?: string,
            /** Stable business-event key. Required by governance callers to suppress duplicate delivery. */
            idempotencyKey?: string,
            /** Mandatory security/governance notices cannot be disabled by marketing preferences. */
            mandatory?: boolean,
            variables?: Record<string, any>,
            brand?: NotificationBrandContext | NotificationBrand,
            systemCustomBypass?: boolean,
            metadata?: Record<string, any>,
            localized?: {
                en?: { subject: string; body: string },
                sw?: { subject: string; body: string },
            },
        } = {}
    ): Promise<UserMessage | null> {
        const sb = getAdminSupabase();
        let id = UUID.generate();
        const idempotencyKey = String(options.idempotencyKey || '').trim();
        if (idempotencyKey) {
            if (!sb) throw new Error('DB_OFFLINE: Cannot safely claim an idempotent notification.');
            const eventCode = String(options.eventCode || '').trim();
            if (!eventCode) throw new Error('NOTIFICATION_EVENT_REQUIRED: eventCode is required with idempotencyKey.');
            const { data: claim, error: claimError } = await sb.rpc('claim_notification_delivery_v1', {
                p_event_key: idempotencyKey,
                p_recipient_user_id: userId,
                p_message_id: id,
                p_event_code: eventCode,
            });
            if (claimError) throw new Error(`NOTIFICATION_CLAIM_FAILED: ${claimError.message}`);
            if (claim?.message_id) id = String(claim.message_id);
            if (claim?.acquired !== true) {
                console.info('[Messaging] Duplicate notification suppressed', { userId, eventCode, idempotencyKey });
                return null;
            }
        }
        
        // Check user profile and preferences before dispatching
        const profile = await this.getUserProfile(userId);
        const language = String(profile.language || 'en').toLowerCase().startsWith('sw') ? 'sw' : 'en';
        const localizedCopy = options.localized?.[language] || options.localized?.en;
        const effectiveSubject = localizedCopy?.subject || subject;
        const effectiveBody = localizedCopy?.body || body;
        
        const isAllowed = (cat: string) => {
            if (cat === 'security') return profile.notif_security;
            if (cat === 'promo') return profile.notif_marketing;
            if (cat === 'update') return profile.notif_financial;
            if (cat === 'info') return profile.notif_financial || profile.notif_budget;
            return true;
        };

        if (!options.mandatory && !isAllowed(category)) {
            console.info(`[Messaging] Skipping notification for ${userId} due to preference settings for category: ${category}`);
            return null;
        }

        const pushAllowed = options.mandatory || profile.notif_push !== false;
        const emailAllowed = options.mandatory || profile.notif_email !== false;
        if (!pushAllowed) options.push = false;
        if (!emailAllowed) options.email = false;

        const refId = id.substring(0, 8).toUpperCase();
        const isTransactional = ['security', 'update', 'info'].includes(category);
        const templatePlan = officialOrbiTalkTemplatePolicy.resolve({
            category,
            subject: effectiveSubject,
            body: effectiveBody,
            refId,
            template: options.template,
            variables: options.variables,
            systemCustomBypass: options.systemCustomBypass,
        });

        let displaySubject = effectiveSubject;
        let displayBody = effectiveBody;
        const createdAtUtc = new Date().toISOString();
        const timeContext = this.buildTimeContext(profile, options.variables, createdAtUtc);

        if (isTransactional && !body.includes('Ref:') && !body.includes('Kumb:')) {
            displayBody = `Ref: ${refId}. ${body}`;
        }
        
        // Encrypt sensitive content before persistence
        const [encSubject, encBody] = await Promise.all([
            DataProtection.encryptMessageContent(displaySubject, { field: 'subject' }),
            DataProtection.encryptMessageContent(displayBody, { field: 'body' })
        ]);

        const msg: UserMessage = {
            id, 
            user_id: userId, 
            subject: encSubject as any, 
            body: encBody as any, 
            category, 
            is_read: false, 
            created_at: createdAtUtc,
            metadata: {
                ...(options.metadata || {}),
                audit_time: timeContext,
            },
        };

        // 0. Real-Time Nexus Push (Decrypted for immediate display)
        console.log(`[Messaging] Attempting to send Socket notification to ${userId}`);
        const socketSent = await SocketRegistry.send(userId, {
            type: 'NOTIFICATION',
            payload: {
                id,
                refId,
                category,
                template_name: options.template,
                event_code: options.eventCode,
                subject: displaySubject, // Send plain text for display
                body: displayBody,       // Send plain text for display
                timestamp: msg.created_at,
                metadata: msg.metadata,
            }
        });
        console.log(`[Messaging] Socket notification sent result: ${socketSent} for user ${userId}`);

        // 1. Cloud Sync
        if (sb) {
            try { 
                await sb.from('user_messages').insert(msg); 
                console.log(`[Messaging] Cloud sync successful for message ${id}`);
            } catch (e) {
                console.error("[Messaging] Cloud push fault.", e);
            }
        }

        // 2. Multi-Channel Escalation
        const isTanzania = profile.nationality?.toLowerCase().includes('tanzania') || 
                           profile.nationality?.toLowerCase().includes('tz') || 
                           profile.phone?.startsWith('+255') ||
                           profile.id_type === 'NIDA';
        const eventCode = String(options.eventCode || '').toUpperCase();
        const templateName = String(templatePlan.templateName || options.template || '').toUpperCase();
        const isSecurityMessage = category === 'security';
        const isCriticalSecurityMessage =
            isSecurityMessage &&
            !templateName.includes('OTP') &&
            (
                templateName.includes('SECURITY_ALERT') ||
                templateName.includes('NEW_DEVICE_ALERT') ||
                eventCode.includes('SECURITY') ||
                eventCode.includes('DEVICE') ||
                eventCode.includes('DISPUTE') ||
                eventCode.includes('REVERS') ||
                eventCode.includes('BLOCK') ||
                eventCode.includes('FRAUD') ||
                eventCode.includes('RISK') ||
                eventCode.includes('AML') ||
                options.email === true
            );
        const isMoneyMovementMessage =
            [
                'TRANSFER_SENT',
                'TRANSFER_RECEIVED',
                'SALARY_RECEIVED',
                'ESCROW_CREATED',
                'ESCROW_RELEASED',
                'MERCHANT_SERVICE_UPDATE',
                'MERCHANT_CUSTOMER_PAYMENT_UPDATE',
                'AGENT_CASH_UPDATE',
                'AGENT_CUSTOMER_CASH_UPDATE',
                'AGENT_COMMISSION_PAID',
                'TREASURY_WITHDRAWAL_REQUEST',
            ].some((key) => templateName.includes(key));
        const shouldSendEmailForAuditTrail =
            emailAllowed &&
            Boolean(profile.email) &&
            (isCriticalSecurityMessage || isMoneyMovementMessage || options.email === true);
        
        // Add refId to variables for templates
        const vars = this.normalizeTemplateVariables(
            profile,
            {
                ...templatePlan.variables,
                ...(options.variables || {}),
            },
            {
                refId,
                subject: displaySubject,
                body: displayBody,
            },
        );
        const brandVariables = vars as Record<string, any>;
        let notificationBrand: NotificationBrand | null = null;
        try {
            notificationBrand = options.brand && 'source' in options.brand
                ? options.brand as NotificationBrand
                : resolveNotificationBrand({
                    ...(options.brand || {}),
                    brandCode: options.brand?.brandCode || brandVariables.brandCode,
                    displayName: options.brand?.displayName,
                    merchantName:
                        options.brand?.merchantName ||
                        brandVariables.merchantName ||
                        brandVariables.businessName ||
                        (String(options.eventCode || '').toUpperCase().includes('MERCHANT')
                            ? brandVariables.actorLabel
                            : undefined),
                    serviceCode: options.brand?.serviceCode || brandVariables.serviceCode,
                    eventCode: options.eventCode,
                    replyTo: options.brand?.replyTo || brandVariables.replyTo,
                    logoUrl: options.brand?.logoUrl || brandVariables.logoUrl,
                    senderEmail: options.brand?.senderEmail || brandVariables.senderEmail,
                });
        } catch (error) {
            console.error('[Messaging] External notification brand resolution failed.', {
                userId,
                eventCode: options.eventCode,
                template: templatePlan.templateName,
                error: error instanceof Error ? error.message : String(error),
            });
        }

        let formattedPhone = profile.phone;
        if (profile.phone) {
            try {
                const parsed = parsePhoneNumber(profile.phone, (profile.country as any) || 'TZ');
                formattedPhone = parsed ? parsed.format('E.164') : (profile.phone.startsWith('+') ? profile.phone : '+' + profile.phone.replace(/\s/g, ''));
            } catch (e) {
                formattedPhone = profile.phone.startsWith('+') ? profile.phone : '+' + profile.phone.replace(/\s/g, '');
            }
        }

        // Channel policy:
        // - Tanzania users still receive SMS for high-deliverability local rails.
        // - Security and transactional/financial events also go to email when available.
        // - Non-Tanzania users prefer email, then WhatsApp for phone-only users.
        // - Promotional messages only use opted-in/requested channels.
        if (isTanzania && profile.phone) {
            options.sms = true;
            options.email = shouldSendEmailForAuditTrail;
            options.whatsapp = false;
        } else if (profile.email) {
            options.email = shouldSendEmailForAuditTrail;
            options.sms = options.sms === true;
            options.whatsapp = options.whatsapp ?? false;
        } else if (profile.phone) {
            // Non-Tanzania with phone but no email -> WhatsApp
            options.whatsapp = true;
            options.sms = false;
            options.email = false;
        }

        const hasFcmToken = Boolean(profile.fcm_token);
        const shouldDefaultPush = pushAllowed && hasFcmToken;
        options.push = options.push ?? shouldDefaultPush;

        // Try Push Notification. Closed apps only receive notifications through
        // device push, so allowed in-app messages must not be socket-only when a
        // valid device token exists and the user has push enabled. Core is the
        // authoritative push sender for Core events; Orbi Talk Gateway is the
        // parallel communications rail using the same requestId for audit.
        if (options.push && pushAllowed && profile.fcm_token) {
            const pushData = {
                title: displaySubject,
                body: displayBody,
                category,
                messageId: id,
                refId,
                event_origin: 'ORBI_CORE',
                eventOrigin: 'ORBI_CORE',
                delivery_rail: 'CORE_FIREBASE',
                deliveryRail: 'CORE_FIREBASE',
                ...(options.template ? { templateName: options.template } : {}),
                ...(options.eventCode ? { eventCode: options.eventCode } : {}),
            };
            const corePushSent = await firebasePushService.send({
                token: profile.fcm_token,
                title: displaySubject,
                body: displayBody,
                data: pushData,
                requestId: id,
            });
            if (!corePushSent) {
                console.info('[Messaging] Push rail result', {
                    userId,
                    messageId: id,
                    category,
                    corePushSent,
                });
            }
        } else {
            console.info('[Messaging] Push notification skipped', {
                userId,
                messageId: id,
                category,
                pushAllowed,
                requestedPush: options.push === true,
                hasFcmToken,
            });
        }

        // Try SMS
        if (notificationBrand && options.sms && profile.phone) {
            if (templatePlan.templateName) {
                const templateSent = await orbiTalkGatewayService.sendTemplate(templatePlan.templateName as TemplateName, formattedPhone, vars as any, {
                    language, 
                    messageType: category === 'promo' ? 'promotional' : 'transactional',
                    channel: 'sms',
                    fcmToken: profile.fcm_token,
                    requestId: id,
                    brand: notificationBrand,
                });
                if (!templateSent && category !== 'promo') {
                    await orbiTalkGatewayService.sendSms(
                        formattedPhone,
                        `${displaySubject}: ${displayBody}`,
                        language,
                        undefined,
                        undefined,
                        id,
                    );
                }
            } else if (templatePlan.systemCustomBypass) {
                await orbiTalkGatewayService.sendSms(formattedPhone, `${displaySubject}: ${displayBody}`, language, undefined, undefined, id);
            }
        }

        // Try Email (with fallback to SMS if requested)
        if (notificationBrand && options.email && emailAllowed && profile.email) {
            let emailSent = false;
            if (templatePlan.templateName) {
                emailSent = await orbiTalkGatewayService.sendTemplate(templatePlan.templateName as TemplateName, profile.email, vars as any, { 
                    language, 
                    messageType: category === 'promo' ? 'promotional' : 'transactional',
                    channel: 'email',
                    fcmToken: profile.fcm_token,
                    requestId: id,
                    brand: notificationBrand,
                });
            }
            if (!emailSent && category !== 'promo') {
                await orbiTalkGatewayService.sendEmail(
                    profile.email,
                    displaySubject,
                    displayBody,
                    undefined,
                    language,
                    undefined,
                    undefined,
                    id,
                    notificationBrand,
                );
            }
        }

        // Try WhatsApp
        if (notificationBrand && options.whatsapp && profile.phone) {
            if (templatePlan.templateName) {
                await orbiTalkGatewayService.sendTemplate(templatePlan.templateName as TemplateName, formattedPhone, vars as any, { 
                    language, 
                    messageType: category === 'promo' ? 'promotional' : 'transactional',
                    channel: 'whatsapp',
                    fcmToken: profile.fcm_token,
                    requestId: id,
                    brand: notificationBrand,
                });
            } else if (templatePlan.systemCustomBypass) {
                // Fallback to SMS if no template, as WhatsApp usually requires templates for business-initiated messages
                await orbiTalkGatewayService.sendSms(formattedPhone, `${subject}: ${body}`, language, undefined, undefined, id);
            }
        }

        // 3. Local Volatile Cache for Instant Retrieval
        const localMsgs = Storage.getFromDB<UserMessage>('orbi_messages') || [];
        localMsgs.unshift(msg);
        Storage.saveToDB('orbi_messages', localMsgs.slice(0, 50));

        if (sb && idempotencyKey) {
            const { error: finishError } = await sb.rpc('finish_notification_delivery_v1', {
                p_event_key: idempotencyKey,
                p_recipient_user_id: userId,
                p_status: 'DISPATCHED',
                p_error: null,
            });
            if (finishError) {
                console.error('[Messaging] Could not finalize notification delivery ledger', {
                    userId, idempotencyKey, error: finishError.message,
                });
            }
        }

        console.info(`[Messaging] Node Signal Dispatched to ${userId}: ${subject}`);
        return msg;
    }

    public async dispatchServiceActivity(
        userId: string,
        event:
            | 'MERCHANT_PAYMENT_PENDING'
            | 'MERCHANT_PAYMENT_COMPLETED'
            | 'MERCHANT_PAYMENT_FAILED'
            | 'MERCHANT_CUSTOMER_PAYMENT_PENDING'
            | 'MERCHANT_CUSTOMER_PAYMENT_COMPLETED'
            | 'MERCHANT_CUSTOMER_PAYMENT_FAILED'
            | 'AGENT_CASH_PENDING'
            | 'AGENT_CASH_COMPLETED'
            | 'AGENT_CASH_FAILED'
            | 'AGENT_CUSTOMER_CASH_PENDING'
            | 'AGENT_CUSTOMER_CASH_COMPLETED'
            | 'AGENT_CUSTOMER_CASH_FAILED'
            | 'AGENT_COMMISSION_PAID'
            | 'SERVICE_CUSTOMER_REGISTERED'
            | 'SERVICE_CUSTOMER_ONBOARDED'
            | 'SERVICE_ACCESS_APPROVED',
        context: Record<string, any> = {},
        category: 'update' | 'info' | 'security' = 'update',
    ) {
        const profile = await this.getUserProfile(userId);
        const language = profile.language === 'sw' ? 'sw' : 'en';
        const currency = context.currency || 'TZS';
        const numericAmount = context.amount != null ? Number(context.amount) : null;
        const amount = numericAmount != null ? `${numericAmount.toLocaleString(language === 'sw' ? 'sw-TZ' : 'en-US')} ${currency}` : null;
        const resolvedActorLabel = String(context.actorLabel || '').trim();
        const actorLabel = resolvedActorLabel || (language === 'sw' ? 'huduma yako ya ORBI' : 'your ORBI service desk');
        const customerLabel = context.customerName || context.customerId || (language === 'sw' ? 'mteja' : 'customer');
        const direction = String(context.direction || '').toLowerCase();

        const translations = {
            en: {
                MERCHANT_PAYMENT_PENDING: {
                    subject: 'Merchant payment received',
                    body: `A merchant payment of ${amount || currency} is being processed in ${actorLabel}.`,
                },
                MERCHANT_PAYMENT_COMPLETED: {
                    subject: 'Merchant payment completed',
                    body: `A merchant payment of ${amount || currency} has settled successfully in ${actorLabel}.`,
                },
                MERCHANT_PAYMENT_FAILED: {
                    subject: 'Merchant payment update',
                    body: `A merchant payment in ${actorLabel} did not complete. Review the latest transaction activity for details.`,
                },
                MERCHANT_CUSTOMER_PAYMENT_PENDING: {
                    subject: 'Merchant payment is processing',
                    body: `Your payment of ${amount || currency} is being processed through ${actorLabel}.`,
                },
                MERCHANT_CUSTOMER_PAYMENT_COMPLETED: {
                    subject: 'Merchant payment completed',
                    body: `Your payment of ${amount || currency} through ${actorLabel} completed successfully.`,
                },
                MERCHANT_CUSTOMER_PAYMENT_FAILED: {
                    subject: 'Merchant payment update',
                    body: `Your payment through ${actorLabel} did not complete. Review your latest activity for details.`,
                },
                AGENT_CASH_PENDING: {
                    subject: 'Agent cash request received',
                    body: `A ${direction || 'cash'} request of ${amount || currency} is being processed in ${actorLabel}.`,
                },
                AGENT_CASH_COMPLETED: {
                    subject: 'Agent cash request completed',
                    body: `A ${direction || 'cash'} request of ${amount || currency} has completed successfully in ${actorLabel}.`,
                },
                AGENT_CASH_FAILED: {
                    subject: 'Agent cash request update',
                    body: `A ${direction || 'cash'} request in ${actorLabel} did not complete. Review the latest activity for details.`,
                },
                AGENT_CUSTOMER_CASH_PENDING: {
                    subject: 'Cash service is processing',
                    body: `Your ${direction || 'cash'} request of ${amount || currency} is being processed through ${actorLabel}.`,
                },
                AGENT_CUSTOMER_CASH_COMPLETED: {
                    subject: 'Cash service completed',
                    body: `Your ${direction || 'cash'} request of ${amount || currency} through ${actorLabel} completed successfully.`,
                },
                AGENT_CUSTOMER_CASH_FAILED: {
                    subject: 'Cash service update',
                    body: `Your ${direction || 'cash'} request through ${actorLabel} did not complete. Review your latest activity for details.`,
                },
                AGENT_COMMISSION_PAID: {
                    subject: 'Agent commission paid',
                    body: `A commission of ${amount || currency} was credited to your ORBI agent account.`,
                },
                SERVICE_CUSTOMER_REGISTERED: {
                    subject: 'Customer added successfully',
                    body: `${customerLabel} was added through ${actorLabel} and is now linked to your service activity.`,
                },
                SERVICE_CUSTOMER_ONBOARDED: {
                    subject: 'Your ORBI account is ready',
                    body: `Your ORBI account was created successfully and linked to ${actorLabel}.`,
                },
                SERVICE_ACCESS_APPROVED: {
                    subject: 'Service access approved',
                    body: `Your ORBI access has been updated. ${actorLabel} is now available on your account.`,
                },
            },
            sw: {
                MERCHANT_PAYMENT_PENDING: {
                    subject: 'Malipo ya merchant yamepokelewa',
                    body: `Malipo ya merchant ya ${amount || currency} yanachakatwa kwenye ${actorLabel}.`,
                },
                MERCHANT_PAYMENT_COMPLETED: {
                    subject: 'Malipo ya merchant yamekamilika',
                    body: `Malipo ya merchant ya ${amount || currency} yamekamilika kwa mafanikio kwenye ${actorLabel}.`,
                },
                MERCHANT_PAYMENT_FAILED: {
                    subject: 'Taarifa ya malipo ya merchant',
                    body: `Malipo ya merchant kwenye ${actorLabel} hayajakamilika. Angalia shughuli zako za karibuni kwa maelezo.`,
                },
                MERCHANT_CUSTOMER_PAYMENT_PENDING: {
                    subject: 'Malipo ya merchant yanachakatwa',
                    body: `Malipo yako ya ${amount || currency} kupitia ${actorLabel} yanachakatwa.`,
                },
                MERCHANT_CUSTOMER_PAYMENT_COMPLETED: {
                    subject: 'Malipo ya merchant yamekamilika',
                    body: `Malipo yako ya ${amount || currency} kupitia ${actorLabel} yamekamilika kwa mafanikio.`,
                },
                MERCHANT_CUSTOMER_PAYMENT_FAILED: {
                    subject: 'Taarifa ya malipo ya merchant',
                    body: `Malipo yako kupitia ${actorLabel} hayajakamilika. Angalia shughuli zako za karibuni kwa maelezo.`,
                },
                AGENT_CASH_PENDING: {
                    subject: 'Ombi la fedha la agent limepokelewa',
                    body: `Ombi la ${direction == 'withdrawal' ? 'utoaji' : 'uwekaji'} la ${amount || currency} linachakatwa kwenye ${actorLabel}.`,
                },
                AGENT_CASH_COMPLETED: {
                    subject: 'Ombi la fedha la agent limekamilika',
                    body: `Ombi la ${direction == 'withdrawal' ? 'utoaji' : 'uwekaji'} la ${amount || currency} limekamilika kwa mafanikio kwenye ${actorLabel}.`,
                },
                AGENT_CASH_FAILED: {
                    subject: 'Taarifa ya fedha ya agent',
                    body: `Ombi la ${direction == 'withdrawal' ? 'utoaji' : 'uwekaji'} kwenye ${actorLabel} halijakamilika. Angalia shughuli zako za karibuni kwa maelezo.`,
                },
                AGENT_CUSTOMER_CASH_PENDING: {
                    subject: 'Huduma ya fedha inachakatwa',
                    body: `Ombi lako la ${direction == 'withdrawal' ? 'utoaji' : 'uwekaji'} la ${amount || currency} kupitia ${actorLabel} linachakatwa.`,
                },
                AGENT_CUSTOMER_CASH_COMPLETED: {
                    subject: 'Huduma ya fedha imekamilika',
                    body: `Ombi lako la ${direction == 'withdrawal' ? 'utoaji' : 'uwekaji'} la ${amount || currency} kupitia ${actorLabel} limekamilika kwa mafanikio.`,
                },
                AGENT_CUSTOMER_CASH_FAILED: {
                    subject: 'Taarifa ya huduma ya fedha',
                    body: `Ombi lako la ${direction == 'withdrawal' ? 'utoaji' : 'uwekaji'} kupitia ${actorLabel} halijakamilika. Angalia shughuli zako za karibuni kwa maelezo.`,
                },
                AGENT_COMMISSION_PAID: {
                    subject: 'Kamisheni ya agent imelipwa',
                    body: `Kamisheni ya ${amount || currency} imeingizwa kwenye akaunti yako ya agent ya ORBI.`,
                },
                SERVICE_CUSTOMER_REGISTERED: {
                    subject: 'Mteja ameongezwa kwa mafanikio',
                    body: `${customerLabel} ameongezwa kupitia ${actorLabel} na sasa ameunganishwa na huduma zako.`,
                },
                SERVICE_CUSTOMER_ONBOARDED: {
                    subject: 'Akaunti yako ya ORBI iko tayari',
                    body: `Akaunti yako ya ORBI imefunguliwa kwa mafanikio na imeunganishwa na ${actorLabel}.`,
                },
                SERVICE_ACCESS_APPROVED: {
                    subject: 'Huduma imeidhinishwa',
                    body: `Ufikiaji wako wa ORBI umesasishwa. ${actorLabel} sasa inapatikana kwenye akaunti yako.`,
                },
            },
        } as const;

        const copy = translations[language][event] || translations.en[event];
        const templateMap = {
            MERCHANT_PAYMENT_PENDING: 'Merchant_Service_Update',
            MERCHANT_PAYMENT_COMPLETED: 'Merchant_Service_Update',
            MERCHANT_PAYMENT_FAILED: 'Merchant_Service_Update',
            MERCHANT_CUSTOMER_PAYMENT_PENDING: 'Merchant_Customer_Payment_Update',
            MERCHANT_CUSTOMER_PAYMENT_COMPLETED: 'Merchant_Customer_Payment_Update',
            MERCHANT_CUSTOMER_PAYMENT_FAILED: 'Merchant_Customer_Payment_Update',
            AGENT_CASH_PENDING: 'Agent_Cash_Update',
            AGENT_CASH_COMPLETED: 'Agent_Cash_Update',
            AGENT_CASH_FAILED: 'Agent_Cash_Update',
            AGENT_CUSTOMER_CASH_PENDING: 'Agent_Customer_Cash_Update',
            AGENT_CUSTOMER_CASH_COMPLETED: 'Agent_Customer_Cash_Update',
            AGENT_CUSTOMER_CASH_FAILED: 'Agent_Customer_Cash_Update',
            AGENT_COMMISSION_PAID: 'Agent_Commission_Paid',
            SERVICE_CUSTOMER_REGISTERED: 'Service_Customer_Registered',
            SERVICE_CUSTOMER_ONBOARDED: 'Service_Customer_Registered',
            SERVICE_ACCESS_APPROVED: 'Service_Access_Approved',
        } as const;

        const templateVariables: Record<string, any> = {
            refId: context.refId,
            actorLabel,
            amount: numericAmount ?? context.amount ?? 0,
            currency,
            status: String(context.status || '').toUpperCase() || (
                event.includes('FAILED')
                    ? 'FAILED'
                    : event.includes('PENDING')
                      ? 'PENDING'
                      : 'COMPLETED'
            ),
            direction: direction || 'deposit',
            customerName: customerLabel,
            senderEmail: context.senderEmail,
        };

        // Intentionally delegate channel choice to dispatch().
        // This keeps service-actor notifications aligned with the global
        // ORBI policy:
        // - language from the user's stored profile
        // - Tanzania/users with +255 or NIDA preference -> SMS first
        // - otherwise email when available
        // - otherwise WhatsApp for phone-only non-Tanzania users
        // - realtime socket push and gateway push continue to follow the same node
        return this.dispatch(userId, category, copy.subject, copy.body, {
            template: templateMap[event],
            eventCode: event,
            variables: templateVariables,
            brand: {
                merchantName: event.includes('MERCHANT') ? resolvedActorLabel : undefined,
                displayName: event.includes('AGENT') ? resolvedActorLabel : undefined,
                senderEmail: String(context.senderEmail || '').trim() || undefined,
                eventCode: event,
            },
        });
    }

    /**
     * GENERATE CONTEXTUAL ALERT
     * Employs Gemini to wrap cold transaction data into professional human-readable alerts.
     */
    public async generateContextualAlert(type: 'payment' | 'security' | 'goal', context: any, userId?: string): Promise<{ subject: string, body: string }> {
        try {
            const apiKey = process.env.GEMINI_API_KEY;
            if (!apiKey) throw new Error("GEMINI_API_KEY_MISSING");
            
            let language = 'en';
            if (userId) {
                const profile = await this.getUserProfile(userId);
                language = profile.language;
            }

            const ai = new GoogleGenAI({ apiKey });
            const systemPrompt = `You are the Orbi Customer Assistant. Convert technical transaction events into friendly, simple, and clear notifications for a mobile app. 
            Avoid technical jargon like 'ledger', 'settlement', 'vault', 'node', or 'finalized'. Use words like 'payment', 'account', 'secure', or 'ready'.
            CRITICAL: Do NOT use the word 'Fynix' or 'fynix'. Always use 'Orbi'.
            LANGUAGE: Respond strictly in ${language === 'sw' ? 'Swahili (Kiswahili)' : 'English'}.
            Respond strictly in valid JSON: { "subject": "Short Title", "body": "1-sentence message" }`;
            
            const userPrompt = `Event: ${type.toUpperCase()}, Data: ${JSON.stringify(context)}. 
            If status is 'held_for_review', sound helpful but cautious about security. 
            If status is 'completed', sound cheerful and helpful.`;

            const response = await ai.models.generateContent({
                model: 'gemini-2.5-flash',
                contents: userPrompt,
                config: { 
                  systemInstruction: systemPrompt, 
                  responseMimeType: "application/json"
                }
            });
            
            const parsed = JSON.parse(response.text || '{}');
            if (parsed.subject && parsed.body) return parsed;
        } catch (e) {
            console.warn("[Messaging] Intelligence node fault, utilizing heuristic fallback.");
        }

        let language = 'en';
        if (userId) {
            const profile = await this.getUserProfile(userId);
            language = profile.language;
        }

        const fallbacks = {
            en: {
                payment: { subject: "Payment Received", body: "A credit transaction has been successfully processed and added to your account balance." },
                security: { subject: "Security Notification", body: "A security verification was performed on your account to ensure continued protection." },
                goal: { subject: "Savings Goal Update", body: "Congratulations on your progress. You are moving closer to achieving your financial goal." }
            },
            sw: {
                payment: { subject: "Malipo Yamepokelewa", body: "Muamala wa mkopo umekamilika kwa mafanikio na kuongezwa kwenye salio la akaunti yako." },
                security: { subject: "Taarifa ya Usalama", body: "Uhakiki wa usalama umefanyika kwenye akaunti yako ili kuhakikisha ulinzi unaendelea." },
                goal: { subject: "Maendeleo ya Akiba", body: "Hongera kwa hatua uliyopiga. Unakaribia kufikia lengo lako la kifedha." }
            }
        };
        const t = (fallbacks as any)[language] || fallbacks.en;
        return t[type] || { 
            subject: language === 'sw' ? "Taarifa ya Akaunti" : "Account Notification", 
            body: language === 'sw' ? "Ombi lako la hivi karibuni limeshughulikiwa kwa mafanikio." : "Your recent request has been processed successfully." 
        };
    }

    public async getMessages(userId: string, limit: number = 50, offset: number = 0): Promise<UserMessage[]> {
        const sb = getAdminSupabase();
        if (sb) {
            const { data } = await sb.from('user_messages')
                .select('id,user_id,subject,body,category,is_read,created_at,metadata')
                .eq('user_id', userId)
                .order('created_at', { ascending: false })
                .range(offset, offset + limit - 1);
            
            // Decrypt messages before returning
            if (data) {
                return Promise.all(data.map(async (msg) => {
                    try {
                        return {
                            ...msg,
                            subject: await DataProtection.decryptMessageContent(msg.subject, msg.subject),
                            body: await DataProtection.decryptMessageContent(msg.body, msg.body)
                        };
                    } catch (error) {
                        console.warn('[Messaging] Message decrypt failed, returning safe fallback.', {
                            userId,
                            messageId: msg.id,
                            category: msg.category,
                            error: error instanceof Error ? error.message : String(error),
                        });
                        return {
                            ...msg,
                            subject: 'Secure ORBI message',
                            body: 'This message could not be decrypted on this device yet.',
                        };
                    }
                }));
            }
        }
        return [];
    }

    public async markAsRead(userId: string, messageId: string) {
        const sb = getAdminSupabase();
        if (sb) {
            await sb.from('user_messages')
                .update({ is_read: true })
                .eq('id', messageId)
                .eq('user_id', userId);
        }
    }

    public async markAllAsRead(userId: string) {
        const sb = getAdminSupabase();
        if (sb) {
            await sb.from('user_messages')
                .update({ is_read: true })
                .eq('user_id', userId);
        }
    }

    public async deleteMessage(userId: string, messageId: string) {
        const sb = getAdminSupabase();
        if (sb) {
            await sb.from('user_messages')
                .delete()
                .eq('id', messageId)
                .eq('user_id', userId);
        }
    }

    public async sendNewDeviceAlert(userId: string, deviceName: string) {
        const subject = "Security Alert: New Device";
        const body = `A new device '${deviceName}' has been used to access your account. If this was not you, please contact support immediately.`;
        
        await this.dispatch(userId, 'security', subject, body, {
            template: 'New_Device_Alert',
            variables: { deviceName }
        });
    }
}

export const Messaging = new MessagingService();

