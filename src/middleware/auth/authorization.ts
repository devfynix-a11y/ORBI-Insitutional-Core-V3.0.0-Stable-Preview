import crypto from 'crypto';
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import type { DetailedPeerCertificate, TLSSocket } from 'tls';
import { RedisClusterFactory } from '../../../backend/infrastructure/RedisClusterFactory.js';
import { Audit } from '../../../backend/security/audit.js';
import { isInstitutionalStaffContext, normalizeRole } from './roles.js';

export type AuthorizationScope = 'USER' | 'ADMIN' | 'SYSTEM' | 'INTERNAL';
export type InternalRequestAuthMode = 'legacy-shared-secret' | 'signed-hmac-sha256';

export type WorkerIdentity = {
  id: string;
  scopes: string[];
};

export type MutualTlsIdentity = {
  verified: boolean;
  subject: string | null;
  issuer: string | null;
  serialNumber: string | null;
  forwardedCert: string | null;
  verificationHeader: string | null;
  source: 'direct' | 'proxy' | 'none';
  authorizationError: string | null;
  attestedByProxy: boolean;
};

export type InternalRequestIdentity = WorkerIdentity & {
  environment: 'sandbox' | 'live';
  authMode: InternalRequestAuthMode;
  requestId: string;
  remoteIp: string;
  userAgent: string;
  path: string;
  method: string;
  keyId: string | null;
  nonce: string | null;
  timestamp: string | null;
  bodySha256: string;
  signatureVerified: boolean;
  replayProtected: boolean;
  mtlsVerified: boolean;
  mtlsSubject: string | null;
  mtlsIssuer: string | null;
  mtlsSerialNumber: string | null;
};

export type SessionAuthorizationOptions = {
  allowedScopes?: AuthorizationScope[];
  allowedRoles?: string[];
  allowedOrgRoles?: string[];
  permissions?: string[];
};

export type InternalWorkerOptions = {
  requiredScopes?: string[];
  allowLegacySecret?: boolean;
};

const normalizeUpper = (value: unknown, fallback = ''): string =>
  String(value ?? fallback).trim().toUpperCase();

const stableSerialize = (value: unknown): string => {
  if (value === null || value === undefined) return '';
  if (typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((entry) => stableSerialize(entry)).join(',')}]`;

  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, entryValue]) => entryValue !== undefined)
    .sort(([left], [right]) => left.localeCompare(right));

  return `{${entries.map(([key, entryValue]) => `${JSON.stringify(key)}:${stableSerialize(entryValue)}`).join(',')}}`;
};

const hashRequestBody = (body: unknown): string =>
  crypto.createHash('sha256').update(stableSerialize(body)).digest('hex');

const timingSafeMatch = (left: string, right: string): boolean => {
  const leftBuffer = Buffer.from(left, 'utf8');
  const rightBuffer = Buffer.from(right, 'utf8');
  if (leftBuffer.length !== rightBuffer.length) return false;
  return crypto.timingSafeEqual(leftBuffer, rightBuffer);
};

const parseScopeValues = (value: unknown): string[] => {
  if (Array.isArray(value)) {
    return value.flatMap((entry) => parseScopeValues(entry));
  }

  if (typeof value !== 'string') {
    return [];
  }

  return value
    .split(',')
    .map((scope) => scope.trim())
    .filter(Boolean);
};

const localReplayStore = new Map<string, number>();
const signedInternalRequestMaxAgeSeconds = Number(process.env.ORBI_INTERNAL_REQUEST_MAX_AGE_SECONDS || 300);
const signedInternalReplayWindowSeconds = Number(process.env.ORBI_INTERNAL_REPLAY_WINDOW_SECONDS || 600);
const allowLocalReplayStore =
  process.env.NODE_ENV !== 'production' || process.env.ORBI_ALLOW_PROCESS_LOCAL_INTERNAL_REPLAY_STORE === 'true';
const trustedMtlsProxyHeader = String(process.env.ORBI_INTERNAL_MTLS_PROXY_HEADER || 'x-orbi-mtls-attested').trim();
const trustedMtlsProxySecret = String(process.env.ORBI_INTERNAL_MTLS_PROXY_SHARED_SECRET || '').trim();
const getInternalMtlsMode = () => {
  const configured = String(process.env.ORBI_INTERNAL_MTLS_MODE || '').trim().toLowerCase();
  if (configured === 'required' || configured === 'optional') return configured;
  if (configured === 'off') return 'off';
  return process.env.NODE_ENV === 'production' ? 'required' : 'off';
};

const getInternalMtlsSource = (): 'proxy' | 'direct' => {
  const configured = String(process.env.ORBI_INTERNAL_MTLS_SOURCE || '').trim().toLowerCase();
  if (configured === 'direct') return 'direct';
  return 'proxy';
};

export const extractBearerToken = (req: Pick<Request, 'headers'>): string | null => {
  const authorization = typeof req.headers.authorization === 'string'
    ? req.headers.authorization
    : null;

  if (!authorization?.startsWith('Bearer ')) {
    return null;
  }

  const token = authorization.substring(7).trim();
  return token || null;
};

export const resolveSessionRole = (session: any): string =>
  normalizeRole(
    session?.role ||
      session?.user?.role ||
      session?.user?.user_metadata?.role ||
      'USER',
  );

export const resolveSessionOrgRole = (session: any): string =>
  normalizeUpper(session?.user?.user_metadata?.org_role || '');

export const resolveSessionRegistryType = (session: any): string =>
  normalizeUpper(
    session?.user?.registry_type ||
      session?.user?.user_metadata?.registry_type ||
      'CONSUMER',
  );

export const resolveAuthorizationScope = (session: any): AuthorizationScope => {
  const role = resolveSessionRole(session);
  const registryType = resolveSessionRegistryType(session);

  if (role === 'SYSTEM' || registryType === 'SYSTEM') {
    return 'SYSTEM';
  }

  if (isInstitutionalStaffContext(role, registryType)) {
    return 'ADMIN';
  }

  return 'USER';
};

export const sessionHasAnyRole = (
  session: any,
  roles: string[],
  options?: { allowedOrgRoles?: string[] },
): boolean => {
  const normalizedRoles = roles.map((role) => normalizeUpper(role));
  if (normalizedRoles.includes(resolveSessionRole(session))) {
    return true;
  }

  const normalizedOrgRoles = (options?.allowedOrgRoles || []).map((role) => normalizeUpper(role));
  if (!normalizedOrgRoles.length) {
    return false;
  }

  return normalizedOrgRoles.includes(resolveSessionOrgRole(session));
};

export const sessionHasPermission = (session: any, permission: string): boolean => {
  const permissions = Array.isArray(session?.permissions) ? session.permissions : [];
  return permissions.includes(permission);
};

export const sessionHasAnyPermission = (session: any, permissions: string[]): boolean =>
  permissions.some((permission) => sessionHasPermission(session, permission));

export const isSessionAuthorized = (session: any, options: SessionAuthorizationOptions = {}): boolean => {
  if (!session) {
    return false;
  }

  const {
    allowedScopes = [],
    allowedRoles = [],
    allowedOrgRoles = [],
    permissions = [],
  } = options;

  if (allowedScopes.length && allowedScopes.includes(resolveAuthorizationScope(session))) {
    return true;
  }

  if (allowedRoles.length && sessionHasAnyRole(session, allowedRoles, { allowedOrgRoles })) {
    return true;
  }

  if (permissions.length && sessionHasAnyPermission(session, permissions)) {
    return true;
  }

  return !allowedScopes.length && !allowedRoles.length && !allowedOrgRoles.length && !permissions.length;
};

export const createAuthorizationMiddleware = (
  options: SessionAuthorizationOptions,
  error: { code?: string; message?: string } = {},
): RequestHandler => {
  const errorCode = error.code || 'ACCESS_DENIED';
  const errorMessage = error.message || 'Missing required authorization.';

  return (req: Request, res: Response, next: NextFunction) => {
    const session = (req as any).session;
    if (!session) {
      return res.status(401).json({ success: false, error: 'AUTH_REQUIRED' });
    }

    if (!isSessionAuthorized(session, options)) {
      return res.status(403).json({ success: false, error: errorCode, message: errorMessage });
    }

    return next();
  };
};

const carriesForwardedMtlsHeaders = (req: Request): boolean => Boolean(
  req.get('x-ssl-client-verify') ||
  req.get('x-client-cert-verified') ||
  req.get('x-forwarded-client-cert-verified') ||
  req.get('x-ssl-client-subject-dn') ||
  req.get('x-client-cert-subject') ||
  req.get('x-forwarded-client-cert-subject') ||
  req.get('x-forwarded-client-cert') ||
  req.get('x-ssl-client-cert'),
);

const hasTrustedProxyMtlsAttestation = (req: Request): boolean => {
  if (!trustedMtlsProxyHeader || !trustedMtlsProxySecret) {
    return false;
  }

  const attestation = String(req.get(trustedMtlsProxyHeader) || '').trim();
  return Boolean(attestation) && timingSafeMatch(attestation, trustedMtlsProxySecret);
};

const resolveDirectMutualTlsIdentity = (req: Request): MutualTlsIdentity => {
  const socket = req.socket as TLSSocket | undefined;
  const hasPeerCertificate = typeof socket?.getPeerCertificate === 'function';
  const peerCertificate = hasPeerCertificate
    ? socket!.getPeerCertificate(true) as DetailedPeerCertificate | Record<string, unknown>
    : null;
  const hasPresentedCert = Boolean(peerCertificate && Object.keys(peerCertificate).length);
  const certificateRecord = hasPresentedCert && peerCertificate ? peerCertificate : null;
  const certificateSubject = certificateRecord && typeof certificateRecord === 'object' && 'subject' in certificateRecord
    ? JSON.stringify((peerCertificate as DetailedPeerCertificate).subject || {})
    : null;
  const certificateIssuer = certificateRecord && typeof certificateRecord === 'object' && 'issuer' in certificateRecord
    ? JSON.stringify((peerCertificate as DetailedPeerCertificate).issuer || {})
    : null;
  const serialNumber = certificateRecord && typeof certificateRecord === 'object' && 'serialNumber' in certificateRecord
    ? String((peerCertificate as DetailedPeerCertificate).serialNumber || '').trim() || null
    : null;

  const verified = Boolean(socket?.authorized && hasPresentedCert);

  return {
    verified,
    subject: certificateSubject,
    issuer: certificateIssuer,
    serialNumber,
    forwardedCert: null,
    verificationHeader: null,
    source: verified || hasPresentedCert ? 'direct' : 'none',
    authorizationError: typeof socket?.authorizationError === 'string' ? socket.authorizationError : null,
    attestedByProxy: false,
  };
};

const resolveProxyMutualTlsIdentity = (req: Request): MutualTlsIdentity => {
  const verificationHeader = String(
    req.get('x-ssl-client-verify') ||
    req.get('x-client-cert-verified') ||
    req.get('x-forwarded-client-cert-verified') ||
    '',
  ).trim();
  const subject = String(
    req.get('x-ssl-client-subject-dn') ||
    req.get('x-client-cert-subject') ||
    req.get('x-forwarded-client-cert-subject') ||
    '',
  ).trim() || null;
  const issuer = String(
    req.get('x-ssl-client-issuer-dn') ||
    req.get('x-client-cert-issuer') ||
    req.get('x-forwarded-client-cert-issuer') ||
    '',
  ).trim() || null;
  const serialNumber = String(
    req.get('x-ssl-client-serial') ||
    req.get('x-client-cert-serial') ||
    req.get('x-forwarded-client-cert-serial') ||
    '',
  ).trim() || null;
  const forwardedCert = String(
    req.get('x-forwarded-client-cert') ||
    req.get('x-ssl-client-cert') ||
    '',
  ).trim() || null;
  const verified = ['success', 'ok', 'true', 'verified', '1'].includes(String(verificationHeader || '').toLowerCase());

  return {
    verified,
    subject,
    issuer,
    serialNumber,
    forwardedCert,
    verificationHeader: verificationHeader || null,
    source: verified || verificationHeader || subject || issuer || serialNumber || forwardedCert ? 'proxy' : 'none',
    authorizationError: null,
    attestedByProxy: true,
  };
};

export const resolveMutualTlsIdentity = (req: Request): MutualTlsIdentity => {
  const source = getInternalMtlsSource();

  if (source === 'direct') {
    return resolveDirectMutualTlsIdentity(req);
  }

  if (!hasTrustedProxyMtlsAttestation(req)) {
    return {
      verified: false,
      subject: null,
      issuer: null,
      serialNumber: null,
      forwardedCert: null,
      verificationHeader: null,
      source: carriesForwardedMtlsHeaders(req) ? 'proxy' : 'none',
      authorizationError: carriesForwardedMtlsHeaders(req) ? 'UNTRUSTED_PROXY_MTLS_HEADERS' : null,
      attestedByProxy: false,
    };
  }

  return resolveProxyMutualTlsIdentity(req);
};

export const resolveWorkerIdentity = (req: Request): WorkerIdentity | null => {
  const workerId = String(req.get('x-worker-id') || '').trim();
  if (!workerId) {
    return null;
  }

  const scopes = [
    ...parseScopeValues(req.get('x-worker-scopes')),
    ...parseScopeValues(req.get('x-worker-scope')),
    ...parseScopeValues(process.env.WORKER_DEFAULT_SCOPES),
  ];

  const dedupedScopes = [...new Set(scopes)];
  return {
    id: workerId,
    scopes: dedupedScopes,
  };
};

const workerHasScope = (grantedScopes: string[], requiredScope: string): boolean => {
  if (grantedScopes.includes('*') || grantedScopes.includes('internal:*')) {
    return true;
  }

  if (grantedScopes.includes(requiredScope)) {
    return true;
  }

  const requiredParts = requiredScope.split(':');
  for (let i = requiredParts.length - 1; i > 0; i -= 1) {
    const wildcard = `${requiredParts.slice(0, i).join(':')}:*`;
    if (grantedScopes.includes(wildcard)) {
      return true;
    }
  }

  return false;
};

export const workerHasRequiredScopes = (worker: WorkerIdentity | null, requiredScopes: string[] = []): boolean => {
  if (!worker) {
    return false;
  }

  if (!requiredScopes.length) {
    return true;
  }

  return requiredScopes.every((scope) => workerHasScope(worker.scopes, scope));
};

const parseTimestamp = (value: string | null): number | null => {
  if (!value) return null;
  if (/^\d+$/.test(value)) {
    const asNumber = Number(value);
    if (!Number.isNaN(asNumber)) {
      return String(asNumber).length > 10 ? asNumber : asNumber * 1000;
    }
  }

  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : parsed;
};

const createInternalCanonicalPayload = (req: Request, worker: WorkerIdentity, bodySha256: string): string => {
  const timestamp = String(req.get('x-worker-timestamp') || '').trim();
  const nonce = String(req.get('x-worker-nonce') || '').trim();
  const requestId = String(req.get('x-worker-request-id') || '').trim();
  const environment = String(req.get('x-orbi-environment') || '').trim().toLowerCase();
  return [
    req.method.toUpperCase(),
    req.originalUrl || req.path,
    worker.id,
    worker.scopes.join(','),
    timestamp,
    nonce,
    requestId,
    environment,
    bodySha256,
  ].join('\n');
};

const registerReplayKey = async (key: string): Promise<boolean> => {
  const redis = RedisClusterFactory.getClient('monitor');
  if (redis) {
    const result = await redis.set(key, '1', 'EX', signedInternalReplayWindowSeconds, 'NX');
    return result === 'OK';
  }

  if (!allowLocalReplayStore) {
    return true;
  }

  const now = Date.now();
  for (const [storedKey, expiry] of localReplayStore.entries()) {
    if (expiry <= now) {
      localReplayStore.delete(storedKey);
    }
  }

  if (localReplayStore.has(key)) {
    return false;
  }

  localReplayStore.set(key, now + signedInternalReplayWindowSeconds * 1000);
  return true;
};

const logInternalAuthFailure = async (req: Request, workerId: string, code: string, details: Record<string, unknown>) => {
  try {
    await Audit.log('SECURITY', workerId || 'SYSTEM', 'INTERNAL_REQUEST_AUTH_FAILED', {
      worker_id: workerId || null,
      path: req.originalUrl || req.path,
      method: req.method,
      remote_ip: req.ip,
      user_agent: req.get('user-agent') || null,
      failure_code: code,
      ...details,
    });
  } catch {
    // Best effort only.
  }
};

const verifySignedInternalRequest = async (
  req: Request,
  worker: WorkerIdentity,
  bodySha256: string,
  mtlsIdentity: MutualTlsIdentity,
): Promise<{ ok: true; identity: InternalRequestIdentity } | { ok: false; code: string; status: number; message?: string }> => {
  const timestampHeader = String(req.get('x-worker-timestamp') || '').trim();
  const nonce = String(req.get('x-worker-nonce') || '').trim();
  const requestId = String(req.get('x-worker-request-id') || '').trim();
  const signatureHeader = String(req.get('x-worker-signature') || '').trim();
  const keyId = String(req.get('x-worker-key-id') || '').trim() || null;
  const environment = String(req.get('x-orbi-environment') || '').trim().toLowerCase();
  const expectedEnvironment = String(process.env.ORBI_RUNTIME_ENVIRONMENT || '').trim().toLowerCase();
  const signingSecret = process.env.WORKER_SIGNING_SECRET || process.env.WORKER_SECRET || '';

  if (!signingSecret) {
    return { ok: false, code: 'WORKER_SIGNING_SECRET_NOT_CONFIGURED', status: 500 };
  }

  if (!timestampHeader || !nonce || !requestId || !signatureHeader || !['sandbox','live'].includes(environment)) {
    return {
      ok: false,
      code: 'SIGNED_WORKER_HEADERS_REQUIRED',
      status: 401,
      message: 'Signed internal requests require timestamp, nonce, request id, environment, and signature headers.',
    };
  }
  if (!['sandbox','live'].includes(expectedEnvironment)) return { ok: false, code: 'RUNTIME_ENVIRONMENT_NOT_CONFIGURED', status: 500 };
  if (environment !== expectedEnvironment) return { ok: false, code: 'INTERNAL_ENVIRONMENT_MISMATCH', status: 403 };

  const timestampMs = parseTimestamp(timestampHeader);
  if (!timestampMs) {
    return { ok: false, code: 'INVALID_WORKER_TIMESTAMP', status: 401 };
  }

  if (Math.abs(Date.now() - timestampMs) > signedInternalRequestMaxAgeSeconds * 1000) {
    return { ok: false, code: 'STALE_WORKER_TIMESTAMP', status: 401 };
  }

  const canonicalPayload = createInternalCanonicalPayload(req, worker, bodySha256);
  const expectedSignature = crypto
    .createHmac('sha256', signingSecret)
    .update(canonicalPayload)
    .digest('hex');

  if (!timingSafeMatch(expectedSignature, signatureHeader)) {
    return { ok: false, code: 'INVALID_WORKER_SIGNATURE', status: 401 };
  }

  const replayKey = `internal-request:${worker.id}:${requestId}:${nonce}`;
  const accepted = await registerReplayKey(replayKey);
  if (!accepted) {
    return { ok: false, code: 'REPLAY_DETECTED', status: 409 };
  }

  return {
    ok: true,
    identity: {
      ...worker,
      environment: environment as 'sandbox' | 'live',
      authMode: 'signed-hmac-sha256',
      requestId,
      remoteIp: String(req.ip || ''),
      userAgent: String(req.get('user-agent') || ''),
      path: req.originalUrl || req.path,
      method: req.method.toUpperCase(),
      keyId,
      nonce,
      timestamp: new Date(timestampMs).toISOString(),
      bodySha256,
      signatureVerified: true,
      replayProtected: true,
      mtlsVerified: mtlsIdentity.verified,
      mtlsSubject: mtlsIdentity.subject,
      mtlsIssuer: mtlsIdentity.issuer,
      mtlsSerialNumber: mtlsIdentity.serialNumber,
    },
  };
};

const verifyLegacyInternalRequest = (
  req: Request,
  worker: WorkerIdentity,
  bodySha256: string,
  mtlsIdentity: MutualTlsIdentity,
): { ok: true; identity: InternalRequestIdentity } | { ok: false; code: string; status: number; message?: string } => {
  const providedSecret = req.get('x-worker-secret') || req.get('x-orbi-worker-secret');
  const expectedSecret = process.env.WORKER_SECRET;

  if (!providedSecret || !expectedSecret || providedSecret !== expectedSecret) {
    return { ok: false, code: 'UNAUTHORIZED_WORKER', status: 401 };
  }

  return {
    ok: true,
    identity: {
      ...worker,
      environment: String(process.env.ORBI_RUNTIME_ENVIRONMENT || 'live').toLowerCase() === 'sandbox' ? 'sandbox' : 'live',
      authMode: 'legacy-shared-secret',
      requestId: String(req.get('x-worker-request-id') || `${worker.id}:${Date.now()}`),
      remoteIp: String(req.ip || ''),
      userAgent: String(req.get('user-agent') || ''),
      path: req.originalUrl || req.path,
      method: req.method.toUpperCase(),
      keyId: null,
      nonce: null,
      timestamp: null,
      bodySha256,
      signatureVerified: false,
      replayProtected: false,
      mtlsVerified: mtlsIdentity.verified,
      mtlsSubject: mtlsIdentity.subject,
      mtlsIssuer: mtlsIdentity.issuer,
      mtlsSerialNumber: mtlsIdentity.serialNumber,
    },
  };
};

export const getInternalAuditMetadata = (req: Request): Record<string, unknown> => {
  const identity = (req as any).internalRequestIdentity as InternalRequestIdentity | undefined;
  if (!identity) {
    return {};
  }

  return {
    worker_id: identity.id,
    worker_environment: identity.environment,
    worker_scopes: identity.scopes,
    worker_auth_mode: identity.authMode,
    worker_request_id: identity.requestId,
    worker_nonce: identity.nonce,
    worker_timestamp: identity.timestamp,
    worker_key_id: identity.keyId,
    worker_body_sha256: identity.bodySha256,
    worker_remote_ip: identity.remoteIp,
    worker_user_agent: identity.userAgent || null,
    worker_signature_verified: identity.signatureVerified,
    worker_replay_protected: identity.replayProtected,
    worker_mtls_verified: identity.mtlsVerified,
    worker_mtls_subject: identity.mtlsSubject,
    worker_mtls_issuer: identity.mtlsIssuer,
    worker_mtls_serial_number: identity.mtlsSerialNumber,
  };
};

export const createInternalWorkerMiddleware = (
  options: InternalWorkerOptions = {},
): RequestHandler => {
  const requiredScopes = options.requiredScopes || [];
  const requireSignedRequests = process.env.ORBI_REQUIRE_SIGNED_INTERNAL_REQUESTS !== 'false';
  const allowLegacySecret = options.allowLegacySecret ?? (
    process.env.ORBI_ALLOW_LEGACY_INTERNAL_WORKER_AUTH === 'true' ||
    process.env.ORBI_REQUIRE_SIGNED_INTERNAL_REQUESTS === 'false'
  );

  return async (req: Request, res: Response, next: NextFunction) => {
    const internalMtlsMode = getInternalMtlsMode();
    const worker = resolveWorkerIdentity(req);
    const workerId = worker?.id || String(req.get('x-worker-id') || '').trim() || 'UNKNOWN_WORKER';

    if (!worker) {
      await logInternalAuthFailure(req, workerId, 'WORKER_ID_REQUIRED', {});
      return res.status(401).json({ success: false, error: 'WORKER_ID_REQUIRED' });
    }

    const bodySha256 = hashRequestBody(req.body);
    const mtlsIdentity = resolveMutualTlsIdentity(req);

    if (getInternalMtlsSource() === 'proxy' && carriesForwardedMtlsHeaders(req) && !mtlsIdentity.attestedByProxy) {
      await logInternalAuthFailure(req, worker.id, 'UNTRUSTED_MTLS_PROXY_HEADERS', {
        required_scopes: requiredScopes,
        requested_scopes: worker.scopes,
        body_sha256: bodySha256,
        mtls_mode: internalMtlsMode,
      });
      return res.status(401).json({
        success: false,
        error: 'UNTRUSTED_MTLS_PROXY_HEADERS',
        message: 'mTLS verification headers were provided without trusted proxy attestation.',
      });
    }

    if (internalMtlsMode === 'required' && !mtlsIdentity.verified) {
      await logInternalAuthFailure(req, worker.id, 'MTLS_REQUIRED', {
        required_scopes: requiredScopes,
        requested_scopes: worker.scopes,
        body_sha256: bodySha256,
        mtls_mode: internalMtlsMode,
        mtls_source: mtlsIdentity.source,
        mtls_authorization_error: mtlsIdentity.authorizationError,
      });
      return res.status(401).json({
        success: false,
        error: 'MTLS_REQUIRED',
        message: 'Mutual TLS verification is required for internal requests.',
      });
    }

    if (internalMtlsMode === 'optional' && mtlsIdentity.verificationHeader && !mtlsIdentity.verified) {
      await logInternalAuthFailure(req, worker.id, 'INVALID_MTLS_IDENTITY', {
        required_scopes: requiredScopes,
        requested_scopes: worker.scopes,
        body_sha256: bodySha256,
        mtls_mode: internalMtlsMode,
        mtls_verification_header: mtlsIdentity.verificationHeader,
        mtls_source: mtlsIdentity.source,
        mtls_authorization_error: mtlsIdentity.authorizationError,
      });
      return res.status(401).json({ success: false, error: 'INVALID_MTLS_IDENTITY' });
    }

    const wantsSignedMode = Boolean(req.get('x-worker-signature')) || requireSignedRequests;
    const authResult = wantsSignedMode
      ? await verifySignedInternalRequest(req, worker, bodySha256, mtlsIdentity)
      : allowLegacySecret
        ? verifyLegacyInternalRequest(req, worker, bodySha256, mtlsIdentity)
        : {
            ok: false as const,
            code: 'SIGNED_INTERNAL_REQUEST_REQUIRED',
            status: 401,
            message: 'Signed internal request authentication is required for this route.',
          };

    if (!authResult.ok) {
      await logInternalAuthFailure(req, worker.id, authResult.code, {
        required_scopes: requiredScopes,
        requested_scopes: worker.scopes,
        body_sha256: bodySha256,
        mtls_mode: internalMtlsMode,
        mtls_verified: mtlsIdentity.verified,
        mtls_subject: mtlsIdentity.subject,
      });
      return res.status(authResult.status).json({
        success: false,
        error: authResult.code,
        ...(authResult.message ? { message: authResult.message } : {}),
      });
    }

    if (!workerHasRequiredScopes(worker, requiredScopes)) {
      await logInternalAuthFailure(req, worker.id, 'WORKER_SCOPE_REQUIRED', {
        required_scopes: requiredScopes,
        requested_scopes: worker.scopes,
        ...getInternalAuditMetadata({ ...(req as any), internalRequestIdentity: authResult.identity } as Request),
      });
      return res.status(403).json({
        success: false,
        error: 'WORKER_SCOPE_REQUIRED',
        message: `Missing required worker scope: ${requiredScopes.join(', ')}`,
      });
    }

    (req as any).internalWorker = worker;
    (req as any).internalRequestIdentity = authResult.identity;
    (req as any).authorizationScope = 'INTERNAL' satisfies AuthorizationScope;
    return next();
  };
};
