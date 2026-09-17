import assert from 'node:assert/strict';
import test from 'node:test';
import crypto from 'crypto';
import {
  createAuthorizationMiddleware,
  createInternalWorkerMiddleware,
  extractBearerToken,
  getInternalAuditMetadata,
  isSessionAuthorized,
  resolveAuthorizationScope,
  resolveSessionOrgRole,
  resolveSessionRegistryType,
  resolveSessionRole,
  sessionHasAnyPermission,
  sessionHasAnyRole,
} from '../src/middleware/auth/authorization.ts';
import { RedisClusterFactory } from '../backend/infrastructure/RedisClusterFactory.js';

const stableSerialize = (value: unknown): string => {
  if (value === null || value === undefined) return '';
  if (typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((entry) => stableSerialize(entry)).join(',')}]`;

  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, entryValue]) => entryValue !== undefined)
    .sort(([left], [right]) => left.localeCompare(right));

  return `{${entries.map(([key, entryValue]) => `${JSON.stringify(key)}:${stableSerialize(entryValue)}`).join(',')}}`;
};

const hashBody = (body: unknown) =>
  crypto.createHash('sha256').update(stableSerialize(body)).digest('hex');

const createResponse = () => {
  const response: any = {
    statusCode: 200,
    body: null,
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(payload: any) {
      this.body = payload;
      return this;
    },
  };
  return response;
};

test('authorization helpers resolve role, org role, registry type, and scope consistently', () => {
  const session = {
    role: 'admin',
    permissions: ['provider.write'],
    user: {
      role: 'ignored',
      registry_type: 'staff',
      user_metadata: {
        role: 'ignored-too',
        org_role: 'ADMIN',
      },
    },
  };

  assert.equal(resolveSessionRole(session), 'ADMIN');
  assert.equal(resolveSessionOrgRole(session), 'ADMIN');
  assert.equal(resolveSessionRegistryType(session), 'STAFF');
  assert.equal(resolveAuthorizationScope(session), 'ADMIN');
  assert.equal(sessionHasAnyRole(session, ['ADMIN']), true);
  assert.equal(sessionHasAnyPermission(session, ['provider.read', 'provider.write']), true);
});

test('session authorization supports separated scopes and org-role aware checks', () => {
  const session = {
    user: {
      registry_type: 'consumer',
      user_metadata: {
        role: 'user',
        org_role: 'ADMIN',
      },
    },
  };

  assert.equal(
    isSessionAuthorized(session, { allowedRoles: ['ADMIN'], allowedOrgRoles: ['ADMIN'] }),
    true,
  );
  assert.equal(
    isSessionAuthorized(session, { allowedScopes: ['ADMIN'] }),
    false,
  );
});

test('extractBearerToken returns null for non-bearer headers', () => {
  assert.equal(extractBearerToken({ headers: {} } as any), null);
  assert.equal(extractBearerToken({ headers: { authorization: 'Basic abc' } } as any), null);
  assert.equal(extractBearerToken({ headers: { authorization: 'Bearer token-123' } } as any), 'token-123');
});

test('createAuthorizationMiddleware enforces session role access', async () => {
  const middleware = createAuthorizationMiddleware({ allowedRoles: ['ADMIN'] });
  const nextCalls: string[] = [];

  const allowedReq: any = {
    session: {
      user: {
        user_metadata: { role: 'ADMIN' },
      },
    },
  };
  const allowedRes = createResponse();
  await middleware(allowedReq, allowedRes as any, () => {
    nextCalls.push('allowed');
  });

  assert.deepEqual(nextCalls, ['allowed']);
  assert.equal(allowedRes.statusCode, 200);

  const deniedReq: any = {
    session: {
      user: {
        user_metadata: { role: 'USER' },
      },
    },
  };
  const deniedRes = createResponse();
  await middleware(deniedReq, deniedRes as any, () => {
    nextCalls.push('denied');
  });

  assert.equal(deniedRes.statusCode, 403);
  assert.equal(deniedRes.body.error, 'ACCESS_DENIED');
  assert.deepEqual(nextCalls, ['allowed']);
});

test('createInternalWorkerMiddleware requires secret, worker id, and scopes', async () => {
  process.env.WORKER_SECRET = 'top-secret';
  process.env.WORKER_DEFAULT_SCOPES = '';
  process.env.ORBI_REQUIRE_SIGNED_INTERNAL_REQUESTS = 'false';

  const middleware = createInternalWorkerMiddleware({ requiredScopes: ['transactions:resolve'] });
  const nextCalls: string[] = [];

  const allowedReq: any = {
    method: 'POST',
    path: '/transactions/resolve',
    originalUrl: '/api/internal/transactions/resolve',
    ip: '127.0.0.1',
    body: {},
    headers: {},
    get(name: string) {
      const lookup: Record<string, string> = {
        'x-worker-secret': 'top-secret',
        'x-worker-id': 'worker-1',
        'x-worker-scopes': 'transactions:*,messages:read',
      };
      return lookup[name.toLowerCase()] || undefined;
    },
  };
  const allowedRes = createResponse();
  await middleware(allowedReq, allowedRes as any, () => {
    nextCalls.push('allowed');
  });

  assert.deepEqual(nextCalls, ['allowed']);
  assert.equal(allowedReq.internalWorker.id, 'worker-1');
  assert.deepEqual(allowedReq.internalWorker.scopes, ['transactions:*', 'messages:read']);
  assert.equal(allowedReq.authorizationScope, 'INTERNAL');

  const deniedReq: any = {
    method: 'POST',
    path: '/transactions/resolve',
    originalUrl: '/api/internal/transactions/resolve',
    ip: '127.0.0.1',
    body: {},
    headers: {},
    get(name: string) {
      const lookup: Record<string, string> = {
        'x-worker-secret': 'top-secret',
        'x-worker-id': 'worker-2',
        'x-worker-scopes': 'messages:read',
      };
      return lookup[name.toLowerCase()] || undefined;
    },
  };
  const deniedRes = createResponse();
  await middleware(deniedReq, deniedRes as any, () => {
    nextCalls.push('denied');
  });

  assert.equal(deniedRes.statusCode, 403);
  assert.equal(deniedRes.body.error, 'WORKER_SCOPE_REQUIRED');
  assert.deepEqual(nextCalls, ['allowed']);

  delete process.env.ORBI_REQUIRE_SIGNED_INTERNAL_REQUESTS;
});


test('createInternalWorkerMiddleware accepts signed requests and exposes audit metadata', async () => {
  process.env.WORKER_SECRET = 'top-secret';
  process.env.WORKER_SIGNING_SECRET = 'signing-secret';
  process.env.ORBI_REQUIRE_SIGNED_INTERNAL_REQUESTS = 'true';
  process.env.ORBI_RUNTIME_ENVIRONMENT = 'live';
  process.env.ORBI_ALLOW_PROCESS_LOCAL_INTERNAL_REPLAY_STORE = 'true';

  const previousRedisGetClient = RedisClusterFactory.getClient;
  (RedisClusterFactory as any).getClient = () => null;

  const body = { amount: 1500, currency: 'TZS' };
  const bodySha256 = hashBody(body);
  const timestamp = new Date().toISOString();
  const nonce = `nonce-${crypto.randomUUID()}`;
  const requestId = `req-${crypto.randomUUID()}`;
  const canonical = [
    'POST',
    '/api/internal/transactions/claim',
    'signed-worker',
    'transactions:*',
    timestamp,
    nonce,
    requestId,
    'live',
    bodySha256,
  ].join('\n');
  const signature = crypto.createHmac('sha256', 'signing-secret').update(canonical).digest('hex');

  const middleware = createInternalWorkerMiddleware({ requiredScopes: ['transactions:claim'] });
  let nextCalled = false;
  const req: any = {
    method: 'POST',
    path: '/transactions/claim',
    originalUrl: '/api/internal/transactions/claim',
    ip: '127.0.0.1',
    body,
    headers: {},
    get(name: string) {
      const lookup: Record<string, string> = {
        'x-worker-id': 'signed-worker',
        'x-worker-scopes': 'transactions:*',
        'x-worker-timestamp': timestamp,
        'x-worker-nonce': nonce,
        'x-worker-request-id': requestId,
        'x-orbi-environment': 'live',
        'x-worker-signature': signature,
        'user-agent': 'worker-test',
      };
      return lookup[name.toLowerCase()] || undefined;
    },
  };
  const res = createResponse();

  await middleware(req, res as any, () => {
    nextCalled = true;
  });

  assert.equal(nextCalled, true);
  assert.equal(req.internalRequestIdentity.authMode, 'signed-hmac-sha256');
  assert.equal(req.internalRequestIdentity.signatureVerified, true);
  assert.equal(req.internalRequestIdentity.replayProtected, true);
  assert.equal(getInternalAuditMetadata(req).worker_request_id, requestId);

  (RedisClusterFactory as any).getClient = previousRedisGetClient;
  delete process.env.ORBI_ALLOW_PROCESS_LOCAL_INTERNAL_REPLAY_STORE;
});

test('createInternalWorkerMiddleware blocks replayed signed requests', async () => {
  process.env.WORKER_SECRET = 'top-secret';
  process.env.WORKER_SIGNING_SECRET = 'signing-secret';
  process.env.ORBI_REQUIRE_SIGNED_INTERNAL_REQUESTS = 'true';
  process.env.ORBI_RUNTIME_ENVIRONMENT = 'live';
  process.env.ORBI_ALLOW_PROCESS_LOCAL_INTERNAL_REPLAY_STORE = 'true';

  const previousRedisGetClient = RedisClusterFactory.getClient;
  (RedisClusterFactory as any).getClient = () => null;

  const body = { amount: 1500, currency: 'TZS' };
  const bodySha256 = hashBody(body);
  const timestamp = new Date().toISOString();
  const nonce = `nonce-${crypto.randomUUID()}`;
  const requestId = `req-${crypto.randomUUID()}`;
  const canonical = [
    'POST',
    '/api/internal/transactions/claim',
    'signed-worker',
    'transactions:*',
    timestamp,
    nonce,
    requestId,
    'live',
    bodySha256,
  ].join('\n');
  const signature = crypto.createHmac('sha256', 'signing-secret').update(canonical).digest('hex');

  const middleware = createInternalWorkerMiddleware({ requiredScopes: ['transactions:claim'] });

  const buildReq = () => ({
    method: 'POST',
    path: '/transactions/claim',
    originalUrl: '/api/internal/transactions/claim',
    ip: '127.0.0.1',
    body,
    headers: {},
    get(name: string) {
      const lookup: Record<string, string> = {
        'x-worker-id': 'signed-worker',
        'x-worker-scopes': 'transactions:*',
        'x-worker-timestamp': timestamp,
        'x-worker-nonce': nonce,
        'x-worker-request-id': requestId,
        'x-orbi-environment': 'live',
        'x-worker-signature': signature,
        'user-agent': 'worker-test',
      };
      return lookup[name.toLowerCase()] || undefined;
    },
  });

  const firstRes = createResponse();
  await middleware(buildReq() as any, firstRes as any, () => {});
  assert.equal(firstRes.statusCode, 200);

  const secondRes = createResponse();
  await middleware(buildReq() as any, secondRes as any, () => {});
  assert.equal(secondRes.statusCode, 409);
  assert.equal(secondRes.body.error, 'REPLAY_DETECTED');

  (RedisClusterFactory as any).getClient = previousRedisGetClient;
  delete process.env.ORBI_ALLOW_PROCESS_LOCAL_INTERNAL_REPLAY_STORE;
  delete process.env.ORBI_REQUIRE_SIGNED_INTERNAL_REQUESTS;
});


test('createInternalWorkerMiddleware enforces mTLS when configured as required', async () => {
  process.env.WORKER_SECRET = 'top-secret';
  process.env.WORKER_SIGNING_SECRET = 'signing-secret';
  process.env.ORBI_REQUIRE_SIGNED_INTERNAL_REQUESTS = 'true';
  process.env.ORBI_RUNTIME_ENVIRONMENT = 'live';
  process.env.ORBI_INTERNAL_MTLS_MODE = 'required';

  const body = { amount: 10 };
  const bodySha256 = crypto.createHash('sha256').update('{"amount":10}').digest('hex');
  const timestamp = new Date().toISOString();
  const nonce = 'nonce-mtls';
  const requestId = 'req-mtls';
  const canonical = [
    'POST',
    '/api/internal/transactions/claim',
    'signed-worker',
    'transactions:*',
    timestamp,
    nonce,
    requestId,
    'live',
    bodySha256,
  ].join('\n');
  const signature = crypto.createHmac('sha256', 'signing-secret').update(canonical).digest('hex');

  const middleware = createInternalWorkerMiddleware({ requiredScopes: ['transactions:claim'] });
  const req: any = {
    method: 'POST',
    path: '/transactions/claim',
    originalUrl: '/api/internal/transactions/claim',
    ip: '127.0.0.1',
    body,
    headers: {},
    get(name: string) {
      const lookup: Record<string, string> = {
        'x-worker-id': 'signed-worker',
        'x-worker-scopes': 'transactions:*',
        'x-worker-timestamp': timestamp,
        'x-worker-nonce': nonce,
        'x-worker-request-id': requestId,
        'x-orbi-environment': 'live',
        'x-worker-signature': signature,
      };
      return lookup[name.toLowerCase()] || undefined;
    },
  };
  const res = createResponse();

  await middleware(req, res as any, () => {});

  assert.equal(res.statusCode, 401);
  assert.equal(res.body.error, 'MTLS_REQUIRED');

  delete process.env.ORBI_INTERNAL_MTLS_MODE;
  delete process.env.ORBI_REQUIRE_SIGNED_INTERNAL_REQUESTS;
});


test('production default mTLS mode resolves to required when unset', async () => {
  const previousNodeEnv = process.env.NODE_ENV;
  const previousMtlsMode = process.env.ORBI_INTERNAL_MTLS_MODE;
  const previousRequireSigned = process.env.ORBI_REQUIRE_SIGNED_INTERNAL_REQUESTS;
  const previousSigningSecret = process.env.WORKER_SIGNING_SECRET;

  process.env.NODE_ENV = 'production';
  delete process.env.ORBI_INTERNAL_MTLS_MODE;
  process.env.ORBI_REQUIRE_SIGNED_INTERNAL_REQUESTS = 'true';
  process.env.ORBI_RUNTIME_ENVIRONMENT = 'live';
  process.env.WORKER_SIGNING_SECRET = 'signing-secret';

  const body = { amount: 15 };
  const bodySha256 = crypto.createHash('sha256').update('{"amount":15}').digest('hex');
  const timestamp = new Date().toISOString();
  const nonce = 'nonce-prod-default';
  const requestId = 'req-prod-default';
  const canonical = [
    'POST',
    '/api/internal/transactions/claim',
    'signed-worker',
    'transactions:*',
    timestamp,
    nonce,
    requestId,
    bodySha256,
  ].join('\n');
  const signature = crypto.createHmac('sha256', 'signing-secret').update(canonical).digest('hex');

  const middleware = createInternalWorkerMiddleware({ requiredScopes: ['transactions:claim'] });
  const req: any = {
    method: 'POST',
    path: '/transactions/claim',
    originalUrl: '/api/internal/transactions/claim',
    ip: '127.0.0.1',
    body,
    headers: {},
    get(name: string) {
      const lookup: Record<string, string> = {
        'x-worker-id': 'signed-worker',
        'x-worker-scopes': 'transactions:*',
        'x-worker-timestamp': timestamp,
        'x-worker-nonce': nonce,
        'x-worker-request-id': requestId,
        'x-orbi-environment': 'live',
        'x-worker-signature': signature,
      };
      return lookup[name.toLowerCase()] || undefined;
    },
  };
  const res = createResponse();

  await middleware(req, res as any, () => {});

  assert.equal(res.statusCode, 401);
  assert.equal(res.body.error, 'MTLS_REQUIRED');

  process.env.NODE_ENV = previousNodeEnv;
  if (previousMtlsMode === undefined) delete process.env.ORBI_INTERNAL_MTLS_MODE;
  else process.env.ORBI_INTERNAL_MTLS_MODE = previousMtlsMode;
  if (previousRequireSigned === undefined) delete process.env.ORBI_REQUIRE_SIGNED_INTERNAL_REQUESTS;
  else process.env.ORBI_REQUIRE_SIGNED_INTERNAL_REQUESTS = previousRequireSigned;
  if (previousSigningSecret === undefined) delete process.env.WORKER_SIGNING_SECRET;
  else process.env.WORKER_SIGNING_SECRET = previousSigningSecret;
});
