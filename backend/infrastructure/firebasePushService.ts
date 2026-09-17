import {
  cert,
  getApps,
  initializeApp,
  type App,
  type ServiceAccount,
} from 'firebase-admin/app';
import { getMessaging, type Message } from 'firebase-admin/messaging';

import { logger } from './logger.js';
import { getAdminSupabase } from '../../services/supabaseClient.js';

const pushLogger = logger.child({ component: 'firebase_push_service' });

type PushPayload = {
  token: string;
  title: string;
  body: string;
  data?: Record<string, any>;
  requestId?: string;
};

export type PushDeliveryReceipt = {
  status: 'sent' | 'unavailable' | 'invalid_token' | 'failed';
  messageId?: string;
  errorCode?: string;
};

class FirebasePushService {
  private app: App | null = null;
  private attemptedInit = false;

  private async clearRejectedToken(token: string, requestId?: string) {
    const sb = getAdminSupabase();
    if (!sb) return;

    try {
      await Promise.all([
        sb.from('users').update({ fcm_token: null }).eq('fcm_token', token),
        sb.from('staff').update({ fcm_token: null }).eq('fcm_token', token),
      ]);
      pushLogger.warn('firebase_push.rejected_token_cleared', {
        request_id: requestId,
      });
    } catch (error) {
      pushLogger.error(
        'firebase_push.rejected_token_clear_failed',
        { request_id: requestId },
        error,
      );
    }
  }

  private loadServiceAccount(): ServiceAccount | null {
    const rawJson =
      process.env.FIREBASE_SERVICE_ACCOUNT_JSON?.trim() ||
      process.env.FIREBASE_ADMIN_SDK_JSON?.trim() ||
      '';
    const base64Json =
      process.env.FIREBASE_SERVICE_ACCOUNT_JSON_BASE64?.trim() || '';

    const candidate = rawJson || (base64Json
      ? Buffer.from(base64Json, 'base64').toString('utf8')
      : '');

    if (!candidate) return null;

    try {
      const parsed = JSON.parse(candidate);
      if (parsed.private_key && typeof parsed.private_key === 'string') {
        parsed.private_key = parsed.private_key.replace(/\\n/g, '\n');
      }
      return parsed as ServiceAccount;
    } catch (error) {
      pushLogger.error('firebase_push.invalid_service_account_json', {}, error);
      return null;
    }
  }

  private ensureInitialized(): App | null {
    if (this.app) return this.app;
    if (this.attemptedInit) return null;
    this.attemptedInit = true;

    try {
      const serviceAccount = this.loadServiceAccount();
      if (!serviceAccount) {
        pushLogger.warn('firebase_push.service_account_missing');
        return null;
      }

      const appName = 'orbi-sovereign-backend-push';
      this.app = getApps().find(
        (candidate): candidate is App => candidate.name === appName,
      ) ??
        initializeApp(
          { credential: cert(serviceAccount) },
          appName,
        );

      pushLogger.info('firebase_push.initialized');
      return this.app!;
    } catch (error) {
      pushLogger.error('firebase_push.init_failed', {}, error);
      return null;
    }
  }

  async sendWithReceipt({ token, title, body, data = {}, requestId }: PushPayload): Promise<PushDeliveryReceipt> {
    const firebaseApp = this.ensureInitialized();
    if (!firebaseApp) {
      pushLogger.warn('firebase_push.send_skipped_unavailable', {
        request_id: requestId,
      });
      return { status: 'unavailable', errorCode: 'FIREBASE_NOT_CONFIGURED' };
    }

    try {
      const normalizedData: Record<string, string> = {};
      for (const [key, value] of Object.entries(data)) {
        if (value === undefined || value === null) continue;
        normalizedData[key] = typeof value === 'string' ? value : JSON.stringify(value);
      }

      const message: Message = {
        token,
        notification: { title, body },
        data: normalizedData,
        android: {
          priority: 'high',
          notification: {
            channelId: 'orbi_alert_notifications_v2',
            sound: 'default',
          },
        },
        apns: {
          headers: {
            'apns-priority': '10',
          },
          payload: {
            aps: {
              sound: 'default',
              contentAvailable: true,
            },
          },
        },
      };

      const response = await getMessaging(firebaseApp).send(message);
      pushLogger.info('firebase_push.sent', {
        request_id: requestId,
        message_id: response,
      });
      return { status: 'sent', messageId: response };
    } catch (error: any) {
      const code = String(error?.code || '');
      pushLogger.error(
        'firebase_push.send_failed',
        {
          request_id: requestId,
          error_code: code,
        },
        error,
      );
      if (
        code === 'messaging/registration-token-not-registered' ||
        code === 'messaging/invalid-registration-token'
      ) {
        await this.clearRejectedToken(token, requestId);
        return { status: 'invalid_token', errorCode: code };
      }
      return { status: 'failed', errorCode: code || 'FIREBASE_SEND_FAILED' };
    }
  }

  async send(payload: PushPayload): Promise<boolean> {
    return (await this.sendWithReceipt(payload)).status === 'sent';
  }
}

export const firebasePushService = new FirebasePushService();
