const provider = String(
  process.env.ORBI_DB_INTEGRATION_PROVIDER
    || process.env.ORBI_DATA_PROVIDER
    || 'supabase',
).trim().toLowerCase();

const READ_ENV = provider === 'local'
  ? [
      'ORBI_RUN_DB_INTEGRATION',
      process.env.ORBI_DB_INTEGRATION_DATABASE_URL
        ? 'ORBI_DB_INTEGRATION_DATABASE_URL'
        : 'DATABASE_URL',
    ]
  : [
      'ORBI_RUN_DB_INTEGRATION',
      'SUPABASE_URL',
      'SUPABASE_SERVICE_ROLE_KEY',
    ];

const WRITE_ENV = [
  ...READ_ENV,
  'ORBI_DB_INTEGRATION_ALLOW_WRITES',
  'ORBI_DB_TEST_DISPOSABLE',
  'ORBI_DB_TEST_USER_ID',
  'ORBI_DB_TEST_SOURCE_WALLET_ID',
  'ORBI_DB_TEST_TARGET_WALLET_ID',
  'ORBI_DB_TEST_INTERNAL_TRANSFER_VAULT_ID',
  'ORBI_DB_TEST_LOW_BALANCE_WALLET_ID',
  'ORBI_DB_TEST_LOCKED_WALLET_ID',
  'ORBI_DB_TEST_REVIEW_ACTOR_ID',
  'ORBI_DB_TEST_DRIFT_WALLET_ID',
  'ORBI_DB_TEST_WEBHOOK_PARTNER_ID',
  'ORBI_DB_TEST_OPERATING_VAULT_ID',
  'ORBI_DB_TEST_ESCROW_VAULT_ID',
  'ORBI_DB_TEST_BUDGET_CATEGORY_ID',
  'ORBI_DB_TEST_BUDGET_TRIGGER_AMOUNT',
  'ORBI_DB_TEST_WITHDRAWAL_PROVIDER_ID',
  'ORBI_DB_TEST_TREASURY_MAKER_ID',
  'ORBI_DB_TEST_TREASURY_ADMIN_1_ID',
  'ORBI_DB_TEST_TREASURY_ADMIN_2_ID',
  'ORBI_DB_TEST_TREASURY_CROSS_ORG_ADMIN_ID',
  'ORBI_DB_TEST_TREASURY_ORG_ID',
  'ORBI_DB_TEST_TREASURY_GOAL_ID',
  'ORBI_DB_TEST_TREASURY_DESTINATION_WALLET_ID',
];

const mode = (process.argv[2] || 'read').toLowerCase();
const required = mode === 'write' ? WRITE_ENV : READ_ENV;

const missing = required.filter((key) => {
  const value = process.env[key];
  if (!value) return true;
  if (key === 'ORBI_RUN_DB_INTEGRATION') return value !== 'true';
  if (key === 'ORBI_DB_INTEGRATION_ALLOW_WRITES') return value !== 'true';
  if (key === 'ORBI_DB_TEST_DISPOSABLE') return value !== 'true';
  return false;
});

if (missing.length > 0) {
  console.error(`[db-integration-env] Missing or invalid required env for ${mode} mode:`);
  for (const key of missing) {
    if (key === 'ORBI_RUN_DB_INTEGRATION' || key === 'ORBI_DB_INTEGRATION_ALLOW_WRITES' || key === 'ORBI_DB_TEST_DISPOSABLE') {
      console.error(`- ${key}=true`);
    } else {
      console.error(`- ${key}`);
    }
  }
  process.exit(1);
}

console.info(`[db-integration-env] ${mode} mode env validation passed.`);
