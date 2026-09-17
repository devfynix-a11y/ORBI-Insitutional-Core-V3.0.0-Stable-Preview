import { logger } from '../../backend/infrastructure/logger.js';
import { getAdminSupabase, getSupabase } from '../../services/supabaseClient.js';
import fs from 'fs';
import { getOrbiDatabase } from '../../services/orbiDatabase.js';

const REQUIRED_ENV_PROD = [
  'JWT_SECRET',
  'RP_ID',
  'ORBI_WEB_ORIGIN',
  'ORBI_ANDROID_APP_HASH',
  'ORBI_MOBILE_ORIGIN',
  'KMS_MASTER_KEY',
  'WORKER_SECRET',
  'WORKER_SIGNING_SECRET',
  'ORBI_INTERNAL_MTLS_MODE',
  'ORBI_RUNTIME_ENVIRONMENT',
  'SUPABASE_URL',
  'SUPABASE_SERVICE_ROLE_KEY',
  'SUPABASE_ANON_KEY',
  'FIREBASE_SERVICE_ACCOUNT_JSON_BASE64',
];

const OPTIONAL_ENV = [
  'ORBI_MONITOR_API_KEY',
  'ORBI_WEBHOOK_MAX_AGE_SECONDS',
  'ORBI_WEBHOOK_REPLAY_WINDOW_SECONDS',
  'ORBI_PROVIDER_TIMEOUT_MS',
  'ORBI_PROVIDER_MAX_ATTEMPTS',
  'ORBI_PROVIDER_RETRY_DELAY_MS',
  'ORBI_MAX_QUERY_LENGTH',
  'ORBI_MAX_QUERY_PARAMS',
  'ORBI_REQUIRE_API_CONTENT_TYPE',
  'ORBI_REQUIRE_ADMIN_TRACE',
  'ORBI_REQUIRE_ADMIN_DEVICE_ID',
  'ORBI_API_GATEWAY_ENABLED',
  'ORBI_API_GATEWAY_FAIL_CLOSED',
  'ORBI_API_GATEWAY_REDIS_REQUIRED',
  'ORBI_API_GATEWAY_AI_MODE',
  'ORBI_AI_SECURITY_SCORER_URL',
  'ORBI_AI_SECURITY_SCORER_TIMEOUT_MS',
  'ORBI_TALK_GATEWAY_URL',
  'ORBI_TALK_GATEWAY_BASE_URL',
  'ORBI_TALK_GATEWAY_API_KEY',
  'ORBI_TALK_GATEWAY_USER_ID',
  'ORBI_TALK_GATEWAY_USER_EMAIL',
  'ORBI_PAY_GATEWAY_BASE_URL',
  'ORBI_PAY_GATEWAY_REGION',
  'ORBI_PAY_GATEWAY_JURISDICTION',
  'ORBI_PAY_GATEWAY_LAT',
  'ORBI_PAY_GATEWAY_LNG',
  'ORBI_PAY_GATEWAY_BASE_RISK',
  'VALKEY_CLUSTER_NODES',
  'VALKEY_URL',
  'VALKEY_HOST',
];

const REQUIRED_RPC_DEPENDENCIES = [
  'post_transaction_v2',
  'append_ledger_entries_v1',
  'claim_internal_transfer_settlement',
  'complete_internal_transfer_settlement',
  'repair_wallet_balance_emergency',
];

const DEFAULT_REQUIRED_PLATFORM_FEE_FLOWS = [
  'CORE_TRANSACTION',
  'EXTERNAL_PAYMENT',
  'WITHDRAWAL',
  'EXTERNAL_TO_INTERNAL',
  'INTERNAL_TO_EXTERNAL',
  'EXTERNAL_TO_EXTERNAL',
  'CARD_SETTLEMENT',
  'GATEWAY_SETTLEMENT',
  'FX_CONVERSION',
  'TENANT_SETTLEMENT_PAYOUT',
  'MERCHANT_PAYMENT',
  'AGENT_CASH_DEPOSIT',
  'AGENT_CASH_WITHDRAWAL',
  'AGENT_REFERRAL_COMMISSION',
  'AGENT_CASH_COMMISSION',
  'SYSTEM_OPERATION',
];

const fatalIfMissing = (key: string) => {
  logger.fatal('startup.missing_required_env', { env_key: key });
  process.exit(1);
};

const warnOptional = (key: string) => {
  logger.warn('startup.missing_optional_env', { env_key: key });
};

const parseCsvEnv = (value: string | undefined, fallback: string[] = []) =>
  String(value || '')
    .split(',')
    .map((item) => item.trim().toUpperCase())
    .filter(Boolean)
    .concat(value ? [] : fallback);

const warnGovernanceConfig = (event: string, payload: Record<string, unknown>) => {
  logger.warn(event, payload);
};

export const validateStartupEnvironment = () => {
  const isProd = process.env.NODE_ENV === 'production';
  const runtimeEnvironment = String(process.env.ORBI_RUNTIME_ENVIRONMENT || '').trim().toLowerCase();
  if (isProd && !['sandbox','live'].includes(runtimeEnvironment)) fatalIfMissing('ORBI_RUNTIME_ENVIRONMENT');
  if (isProd && runtimeEnvironment === 'live' && process.env.ORBI_ENABLE_SANDBOX_ROUTES === 'true') {
    logger.fatal('startup.live_runtime_cannot_enable_sandbox_routes'); process.exit(1);
  }
  if (isProd && runtimeEnvironment === 'sandbox' && process.env.ORBI_ENABLE_SANDBOX_ROUTES !== 'true') {
    logger.fatal('startup.sandbox_runtime_requires_sandbox_routes'); process.exit(1);
  }
  const authProvider = String(process.env.ORBI_AUTH_PROVIDER || 'supabase').trim().toLowerCase();
  const usesLocalAuth = authProvider === 'local';
  const usesKeycloak = authProvider === 'keycloak';
  const usesLocalData = String(process.env.ORBI_DATA_PROVIDER || 'supabase').trim().toLowerCase() === 'local';
  const usesR2Images =
    String(process.env.ORBI_IMAGE_STORAGE_PROVIDER || '').trim().toLowerCase() === 'r2';

  for (const key of REQUIRED_ENV_PROD) {
    if (runtimeEnvironment === 'sandbox' && key === 'FIREBASE_SERVICE_ACCOUNT_JSON_BASE64') {
      continue;
    }
    if (usesLocalData && ['SUPABASE_URL', 'SUPABASE_SERVICE_ROLE_KEY', 'SUPABASE_ANON_KEY'].includes(key)) {
      continue;
    }
    if (isProd && !process.env[key]) {
      fatalIfMissing(key);
    }
  }

  if (isProd && runtimeEnvironment === 'sandbox' && !process.env.FIREBASE_SERVICE_ACCOUNT_JSON_BASE64) {
    logger.warn('startup.sandbox_push_provider_not_configured');
  }

  if (usesLocalAuth && !process.env.DATABASE_URL) {
    fatalIfMissing('DATABASE_URL');
  }

  if (usesKeycloak) {
    for (const key of [
      'DATABASE_URL',
      'ORBI_KEYCLOAK_INTERNAL_URL',
      'ORBI_KEYCLOAK_ISSUER',
      'ORBI_KEYCLOAK_AUDIENCE',
      'ORBI_KEYCLOAK_ADMIN_USERNAME',
      'ORBI_KEYCLOAK_ADMIN_PASSWORD',
    ]) {
      if (!process.env[key]) fatalIfMissing(key);
    }
    if (isProd && !String(process.env.ORBI_KEYCLOAK_ISSUER).startsWith('https://')) {
      logger.fatal('startup.invalid_keycloak_issuer_transport', {
        issuer: process.env.ORBI_KEYCLOAK_ISSUER,
      });
      process.exit(1);
    }
  }

  if (usesR2Images) {
    const requiredAliases = [
      {
        label: 'CLOUDFLARE_ACCOUNT_ID_OR_R2_ENDPOINT',
        values: [process.env.CLOUDFLARE_ACCOUNT_ID, process.env.CLOUDFLARE_R2_ENDPOINT],
      },
      {
        label: 'CLOUDFLARE_ACCESS_KEY_ID',
        values: [process.env.CLOUDFLARE_ACCESS_KEY_ID, process.env.CLOUDFLARE_R2_ACCESS_KEY_ID],
      },
      {
        label: 'CLOUDFLARE_SECRET_ACCESS_KEY',
        values: [process.env.CLOUDFLARE_SECRET_ACCESS_KEY, process.env.CLOUDFLARE_R2_SECRET_ACCESS_KEY],
      },
      {
        label: 'CLOUDFLARE_BUCKET_NAME',
        values: [process.env.CLOUDFLARE_BUCKET_NAME, process.env.CLOUDFLARE_R2_IMAGE_BUCKET],
      },
      {
        label: 'CLOUDFLARE_PUBLIC_URL_PREFIX',
        values: [process.env.CLOUDFLARE_PUBLIC_URL_PREFIX, process.env.ORBI_IMAGE_PUBLIC_BASE_URL],
      },
    ];
    for (const requirement of requiredAliases) {
      if (!requirement.values.some((value) => String(value || '').trim())) {
        fatalIfMissing(requirement.label);
      }
    }
  }

  if (isProd && usesLocalData && process.env.ORBI_LOCAL_DATA_PRODUCTION_READY !== 'true') {
    logger.fatal('startup.local_data_provider_not_production_ready', {
      data_provider: 'local',
    });
    process.exit(1);
  }

  for (const key of OPTIONAL_ENV) {
    if (!process.env[key]) {
      logger.info('startup.optional_env_unset', { env_key: key });
    }
  }

  if (isProd) {
    if (!usesLocalData) {
      const supabaseUrl = String(process.env.SUPABASE_URL || '').trim();
      if (!supabaseUrl.startsWith('https://')) {
        logger.fatal('startup.invalid_supabase_transport', {
          supabase_url: supabaseUrl,
        });
        process.exit(1);
      }
    }

    if (
      (process.env.VALKEY_TLS_ENABLED || process.env.REDIS_TLS_ENABLED) === 'true' &&
      (process.env.VALKEY_ALLOW_INSECURE_TLS || process.env.REDIS_ALLOW_INSECURE_TLS) === 'true'
    ) {
      logger.fatal('startup.invalid_prod_redis_tls', {
        valkey_tls_enabled: process.env.VALKEY_TLS_ENABLED || process.env.REDIS_TLS_ENABLED,
        valkey_allow_insecure_tls:
          process.env.VALKEY_ALLOW_INSECURE_TLS || process.env.REDIS_ALLOW_INSECURE_TLS,
      });
      process.exit(1);
    }

    if (process.env.ORBI_ANDROID_APP_HASH && !process.env.ORBI_ANDROID_PACKAGE_NAME) {
      logger.fatal('startup.invalid_android_origin_config', {
        has_android_app_hash: !!process.env.ORBI_ANDROID_APP_HASH,
        has_android_package_name: !!process.env.ORBI_ANDROID_PACKAGE_NAME,
      });
      process.exit(1);
    }

    if (process.env.ORBI_REQUIRE_SIGNED_INTERNAL_REQUESTS === 'false') {
      logger.fatal('startup.invalid_internal_auth_config', {
        require_signed_internal_requests: process.env.ORBI_REQUIRE_SIGNED_INTERNAL_REQUESTS,
      });
      process.exit(1);
    }

    if (process.env.ORBI_ALLOW_LEGACY_INTERNAL_WORKER_AUTH === 'true') {
      logger.fatal('startup.legacy_internal_auth_forbidden', {
        allow_legacy_internal_worker_auth: process.env.ORBI_ALLOW_LEGACY_INTERNAL_WORKER_AUTH,
      });
      process.exit(1);
    }

    const internalMtlsMode = String(process.env.ORBI_INTERNAL_MTLS_MODE || '').trim().toLowerCase();
    const allowHmacOnlyInternalRequests = String(
      process.env.ORBI_ALLOW_HMAC_ONLY_INTERNAL_REQUESTS || '',
    ).trim().toLowerCase() === 'true';

    if (internalMtlsMode !== 'required' && !allowHmacOnlyInternalRequests) {
      logger.fatal('startup.invalid_internal_mtls_mode', {
        internal_mtls_mode: process.env.ORBI_INTERNAL_MTLS_MODE,
        allow_hmac_only_internal_requests: process.env.ORBI_ALLOW_HMAC_ONLY_INTERNAL_REQUESTS,
      });
      process.exit(1);
    }

    if (allowHmacOnlyInternalRequests && internalMtlsMode !== 'required') {
      logger.warn('startup.hmac_only_internal_requests_enabled', {
        internal_mtls_mode: internalMtlsMode,
        requirement: 'temporary_self_hosted_migration_only',
      });
    }

    const internalMtlsSource = String(process.env.ORBI_INTERNAL_MTLS_SOURCE || 'proxy').trim().toLowerCase();
    if (!['proxy', 'direct'].includes(internalMtlsSource)) {
      logger.fatal('startup.invalid_internal_mtls_source', {
        internal_mtls_source: process.env.ORBI_INTERNAL_MTLS_SOURCE,
      });
      process.exit(1);
    }

    if (internalMtlsSource === 'proxy' && !String(process.env.ORBI_INTERNAL_MTLS_PROXY_SHARED_SECRET || '').trim()) {
      logger.fatal('startup.missing_internal_mtls_proxy_secret', {
        internal_mtls_source: internalMtlsSource,
      });
      process.exit(1);
    }

    if (internalMtlsSource === 'direct' && String(process.env.ORBI_TLS_ENABLED || '').trim().toLowerCase() !== 'true') {
      logger.fatal('startup.invalid_direct_mtls_transport', {
        internal_mtls_source: internalMtlsSource,
        tls_enabled: process.env.ORBI_TLS_ENABLED,
      });
      process.exit(1);
    }

    if (String(process.env.ORBI_ENFORCE_HTTPS || 'true').trim().toLowerCase() === 'false') {
      logger.fatal('startup.https_enforcement_disabled', {
        enforce_https: process.env.ORBI_ENFORCE_HTTPS,
      });
      process.exit(1);
    }
  }

  if (String(process.env.ORBI_TLS_ENABLED || '').trim().toLowerCase() === 'true') {
    const requiredTlsPaths = ['ORBI_TLS_KEY_PATH', 'ORBI_TLS_CERT_PATH'];

    for (const key of requiredTlsPaths) {
      const candidate = String(process.env[key] || '').trim();
      if (!candidate) {
        logger.fatal('startup.missing_tls_file_path', { env_key: key });
        process.exit(1);
      }

      if (!fs.existsSync(candidate)) {
        logger.fatal('startup.tls_file_missing', { env_key: key, path: candidate });
        process.exit(1);
      }
    }

    const caPath = String(process.env.ORBI_TLS_CA_PATH || '').trim();
    if (caPath && !fs.existsSync(caPath)) {
      logger.fatal('startup.tls_file_missing', { env_key: 'ORBI_TLS_CA_PATH', path: caPath });
      process.exit(1);
    }

    if (String(process.env.ORBI_INTERNAL_MTLS_SOURCE || 'proxy').trim().toLowerCase() === 'direct') {
      const internalMtlsCaPath = String(process.env.ORBI_INTERNAL_MTLS_CA_PATH || process.env.ORBI_TLS_CA_PATH || '').trim();
      if (!internalMtlsCaPath) {
        logger.fatal('startup.missing_internal_mtls_ca', {
          env_key: 'ORBI_INTERNAL_MTLS_CA_PATH',
        });
        process.exit(1);
      }
      if (!fs.existsSync(internalMtlsCaPath)) {
        logger.fatal('startup.tls_file_missing', { env_key: 'ORBI_INTERNAL_MTLS_CA_PATH', path: internalMtlsCaPath });
        process.exit(1);
      }
    }
  }
};

const validateProviderSecretDependencies = (isProd: boolean) => {
  const hasOrbiTalkGatewayKey = Boolean(process.env.ORBI_TALK_GATEWAY_API_KEY);
  const hasOrbiTalkGatewayUrl = Boolean(
    process.env.ORBI_TALK_GATEWAY_URL ||
    process.env.ORBI_TALK_GATEWAY_BASE_URL
  );

  if (hasOrbiTalkGatewayKey !== hasOrbiTalkGatewayUrl) {
    const payload = {
      has_orbi_talk_gateway_key: hasOrbiTalkGatewayKey,
      has_orbi_talk_gateway_url: hasOrbiTalkGatewayUrl,
    };
    if (isProd) {
      logger.fatal('startup.invalid_orbi_talk_gateway_config', payload);
      process.exit(1);
    } else {
      logger.warn('startup.invalid_orbi_talk_gateway_config', payload);
    }
  }

  if (process.env.ORBI_REQUIRE_WEBHOOK_SIGNATURES !== 'false' && process.env.NODE_ENV === 'production') {
    if (process.env.ORBI_ALLOW_PROCESS_LOCAL_WEBHOOK_REPLAY_STORE === 'true') {
      logger.fatal('startup.invalid_webhook_replay_store', {
        allow_local_replay_store: process.env.ORBI_ALLOW_PROCESS_LOCAL_WEBHOOK_REPLAY_STORE,
      });
      process.exit(1);
    }
  }
};

const validateDbDependencies = async (isProd: boolean) => {
  const adminClient = getAdminSupabase();
  const publicClient = getSupabase();

  if (!adminClient || !publicClient) {
    const payload = {
      has_admin_client: !!adminClient,
      has_public_client: !!publicClient,
    };
    if (isProd) {
      logger.fatal('startup.missing_supabase_clients', payload);
      process.exit(1);
    } else {
      logger.warn('startup.missing_supabase_clients', payload);
      return;
    }
  }

  const shouldValidateDb = isProd || process.env.ORBI_VALIDATE_DB_ON_STARTUP === 'true';
  if (!shouldValidateDb || !adminClient) return;

  const timeoutMs = Number(process.env.ORBI_STARTUP_DB_TIMEOUT_MS || 5000);
  const withTimeout = async <T>(promise: PromiseLike<T>, label: string) => {
    const timer = new Promise<T>((_, reject) =>
      setTimeout(() => reject(new Error(`${label}_TIMEOUT`)), timeoutMs),
    );
    return Promise.race([Promise.resolve(promise), timer]);
  };

  try {
    const connectivityPromise = adminClient
      .from('transactions')
      .select('id')
      .limit(1)
      .maybeSingle()
      .then((result) => result);
    await withTimeout(connectivityPromise, 'DB_CONNECTIVITY');
  } catch (error: any) {
    logger.fatal('startup.db_unreachable', { message: error?.message || String(error) });
    process.exit(1);
  }

  await validatePlatformFeeConfigs(adminClient);
  await validateProviderRegistryReadiness(adminClient);

  const shouldValidateRpc = isProd || process.env.ORBI_VALIDATE_RPC_ON_STARTUP === 'true';
  if (!shouldValidateRpc) return;

  if (String(process.env.ORBI_DATA_PROVIDER || '').trim().toLowerCase() === 'local') {
    try {
      const db = getOrbiDatabase();
      const result = await db.query(
        `
          SELECT p.proname
          FROM pg_proc p
          JOIN pg_namespace n ON n.oid = p.pronamespace
          WHERE n.nspname = 'public'
            AND p.proname = ANY($1::text[])
        `,
        [REQUIRED_RPC_DEPENDENCIES],
      );
      const found = new Set(result.rows.map((row: any) => String(row.proname || '')));
      const missing = REQUIRED_RPC_DEPENDENCIES.filter((name) => !found.has(name));
      if (missing.length > 0) {
        logger.fatal('startup.rpc_missing', { missing_rpc: missing });
        process.exit(1);
      }
      logger.info('startup.rpc_catalog_validated', { rpc_count: found.size });
      return;
    } catch (error: any) {
      logger.fatal('startup.rpc_catalog_validation_failed', { message: error?.message || String(error) });
      process.exit(1);
    }
  }
  const isParameterizedRpcProbeMiss = (message: string) =>
    /without parameters in the schema cache/i.test(message) ||
    /function .* requires/i.test(message) ||
    /invalid input syntax/i.test(message) ||
    /missing required/i.test(message);

  for (const rpcName of REQUIRED_RPC_DEPENDENCIES) {
    try {
      const result = await adminClient.rpc(rpcName as any, {} as any);
      if (result.error && /does not exist|missing function/i.test(String(result.error.message || ''))) {
        logger.fatal('startup.rpc_missing', { rpc: rpcName, message: result.error.message });
        process.exit(1);
      }
      if (result.error) {
        const message = String(result.error.message || '');
        if (isParameterizedRpcProbeMiss(message)) {
          logger.info('startup.rpc_parameterized_probe_skipped', { rpc: rpcName, message });
        } else {
          logger.warn('startup.rpc_probe_error', { rpc: rpcName, message });
        }
      }
    } catch (error: any) {
      const message = String(error?.message || error || '');
      if (/does not exist|missing function/i.test(message)) {
        logger.fatal('startup.rpc_missing', { rpc: rpcName, message });
        process.exit(1);
      }
      if (isParameterizedRpcProbeMiss(message)) {
        logger.info('startup.rpc_parameterized_probe_skipped', { rpc: rpcName, message });
      } else {
        logger.warn('startup.rpc_probe_error', { rpc: rpcName, message });
      }
    }
  }
};

const validatePlatformFeeConfigs = async (adminClient: any) => {
  const requiredFlows = parseCsvEnv(
    process.env.ORBI_REQUIRED_PLATFORM_FEE_FLOWS,
    DEFAULT_REQUIRED_PLATFORM_FEE_FLOWS,
  );
  if (requiredFlows.length === 0) return;

  const { data, error } = await adminClient
    .from('platform_fee_configs')
    .select('flow_code, status')
    .eq('status', 'ACTIVE')
    .in('flow_code', requiredFlows);

  if (error) {
    warnGovernanceConfig('startup.platform_fee_config_check_failed', {
      message: error.message,
      enforcement: 'runtime',
    });
    return;
  }

  const configuredFlows = new Set((data || []).map((row: any) => String(row.flow_code || '').trim().toUpperCase()));
  const missingFlows = requiredFlows.filter((flow) => !configuredFlows.has(flow));
  if (missingFlows.length > 0) {
    warnGovernanceConfig('startup.platform_fee_configs_missing', {
      missing_flows: missingFlows,
      enforcement: 'runtime',
    });
  }
};

const validateProviderRegistryReadiness = async (adminClient: any) => {
  const { data: partners, error } = await adminClient
    .from('financial_partners')
    .select('id, name, status, api_base_url, webhook_secret, provider_metadata, mapping_config')
    .eq('status', 'ACTIVE');

  if (error) {
    warnGovernanceConfig('startup.provider_registry_check_failed', {
      message: error.message,
      enforcement: 'runtime',
    });
    return;
  }

  const activePartners = partners || [];
  if (activePartners.length === 0) {
    warnGovernanceConfig('startup.no_active_financial_partners', {
      enforcement: 'runtime',
    });
    return;
  }

  const { data: routingRules, error: routingError } = await adminClient
    .from('provider_routing_rules')
    .select('provider_id, status')
    .eq('status', 'ACTIVE');

  const routedProviderIds = new Set(
    routingError ? [] : (routingRules || []).map((row: any) => String(row.provider_id || '').trim()).filter(Boolean),
  );

  const readinessFailures = activePartners
    .map((partner: any) => {
      const metadata = partner.provider_metadata && typeof partner.provider_metadata === 'object'
        ? partner.provider_metadata
        : {};
      const registry = partner.mapping_config && typeof partner.mapping_config === 'object'
        ? partner.mapping_config
        : {};
      const operations = registry.operations && typeof registry.operations === 'object'
        ? Object.keys(registry.operations)
        : [];
      const callback = registry.callback && typeof registry.callback === 'object'
        ? registry.callback
        : null;
      const registryKind = String(metadata.registry_kind || 'EXTERNAL_PROVIDER').trim().toUpperCase();
      const isUniversalSwitch = registryKind === 'UNIVERSAL_SWITCH' || registryKind === 'CLEARING_NETWORK';
      const hasBaseUrl =
        Boolean(String(partner.api_base_url || '').trim()) ||
        Boolean(String(registry.service_root || '').trim()) ||
        Boolean(registry.service_roots && Object.keys(registry.service_roots).length > 0);
      const hasWebhookSecret =
        Boolean(String(partner.webhook_secret || '').trim()) ||
        Boolean(String(metadata?.secrets?.webhook_secret || '').trim());
      const providerCode = String(metadata.provider_code || metadata.switch_profile_code || metadata.pay_gateway_provider_code || '').trim();

      const missing = [
        !providerCode ? 'provider_metadata.provider_code_or_switch_profile_code' : '',
        operations.length === 0 ? 'mapping_config.operations' : '',
        !isUniversalSwitch && !callback ? 'mapping_config.callback' : '',
        !isUniversalSwitch && callback && !String(callback.reference_field || '').trim() ? 'mapping_config.callback.reference_field' : '',
        !isUniversalSwitch && callback && !String(callback.status_field || '').trim() ? 'mapping_config.callback.status_field' : '',
        !isUniversalSwitch && !hasWebhookSecret ? 'webhook_secret' : '',
        !hasBaseUrl ? 'api_base_url_or_service_root' : '',
        !routedProviderIds.has(String(partner.id)) ? 'provider_routing_rules' : '',
        isUniversalSwitch && !String(metadata.message_standard || '').trim() ? 'provider_metadata.message_standard' : '',
        isUniversalSwitch && String(metadata.message_standard || '').trim().toUpperCase() === 'ISO20022' && !String(metadata.clearing_network || '').trim() ? 'provider_metadata.clearing_network' : '',
        isUniversalSwitch && String(metadata.message_standard || '').trim().toUpperCase() === 'ISO20022' && !String(metadata.iso20022_profile || '').trim() ? 'provider_metadata.iso20022_profile' : '',
      ].filter(Boolean);

      return missing.length > 0
        ? {
            id: partner.id,
            name: partner.name,
            missing,
          }
        : null;
    })
    .filter(Boolean);

  if (routingError) {
    warnGovernanceConfig('startup.provider_routing_rules_check_failed', {
      message: routingError.message,
      enforcement: 'runtime',
    });
    return;
  }

  if (readinessFailures.length > 0) {
    warnGovernanceConfig('startup.provider_registry_not_ready', {
      providers: readinessFailures,
      enforcement: 'runtime',
    });
  }
};

export const validateStartupDependencies = async () => {
  const isProd = process.env.NODE_ENV === 'production';

  validateProviderSecretDependencies(isProd);
  await validateDbDependencies(isProd);
};
