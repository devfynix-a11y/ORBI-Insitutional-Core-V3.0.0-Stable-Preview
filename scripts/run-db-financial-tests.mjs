import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { parse } from 'dotenv';

const args = process.argv.slice(2);

function readArg(name, fallback = '') {
  const index = args.indexOf(name);
  if (index === -1) return fallback;
  return args[index + 1] || fallback;
}

function hasFlag(name) {
  return args.includes(name);
}

function usage() {
  console.log(`
ORBI financial DB test runner

Usage:
  node scripts/run-db-financial-tests.mjs --mode read --env .env.test.local
  node scripts/run-db-financial-tests.mjs --mode write --env .env.test.local --allow-write-fixture --confirm-disposable-database

Rules:
  - read mode verifies DB reachability and financial exception counters.
  - write mode must use disposable fixtures only and requires --allow-write-fixture.
  - secrets are loaded into the child process only and are never printed.
`);
}

if (hasFlag('--help') || hasFlag('-h')) {
  usage();
  process.exit(0);
}

const mode = readArg('--mode', 'read').toLowerCase();
if (!['read', 'write'].includes(mode)) {
  console.error(`[db-financial-runner] Invalid mode "${mode}". Use "read" or "write".`);
  process.exit(1);
}

const envPathArg = readArg('--env');
const testNamePattern = readArg('--test-name-pattern');
if (!envPathArg) {
  console.error('[db-financial-runner] Missing --env path. Use a dedicated DB test env file, not production secrets.');
  usage();
  process.exit(1);
}

if (mode === 'write' && !hasFlag('--allow-write-fixture')) {
  console.error('[db-financial-runner] Write mode refused. Add --allow-write-fixture only for isolated disposable fixtures.');
  process.exit(1);
}
if (mode === 'write' && !hasFlag('--confirm-disposable-database')) {
  console.error('[db-financial-runner] Write mode refused. Confirm the target is disposable with --confirm-disposable-database.');
  process.exit(1);
}

const envPath = resolve(process.cwd(), envPathArg);
if (!existsSync(envPath)) {
  console.error(`[db-financial-runner] Env file not found: ${envPath}`);
  process.exit(1);
}

const baseEnvPath = resolve(process.cwd(), '.env');
const baseEnv = existsSync(baseEnvPath) ? parse(readFileSync(baseEnvPath)) : {};
const loadedEnv = parse(readFileSync(envPath));
const childEnv = {
  ...process.env,
  ...baseEnv,
  ...loadedEnv,
  ORBI_RUN_DB_INTEGRATION: 'true',
  // Database certification must never dispatch through a real notification provider.
  ORBI_DISABLE_EXTERNAL_DELIVERIES: 'true',
};

const provider = String(
  childEnv.ORBI_DB_INTEGRATION_PROVIDER || childEnv.ORBI_DATA_PROVIDER || 'supabase',
).trim().toLowerCase();

if (provider === 'local' && childEnv.ORBI_DB_INTEGRATION_DATABASE_URL) {
  childEnv.DATABASE_URL = childEnv.ORBI_DB_INTEGRATION_DATABASE_URL;
}

for (const key of ['VALKEY_URL', 'REDIS_URL']) {
  if (provider === 'local' && typeof childEnv[key] === 'string') {
    childEnv[key] = childEnv[key].replace('@valkey:', '@127.0.0.1:');
  }
}

if (mode === 'write') {
  childEnv.ORBI_DB_INTEGRATION_ALLOW_WRITES = 'true';
  if (loadedEnv.ORBI_DB_TEST_DISPOSABLE !== 'true') {
    console.error('[db-financial-runner] Write mode refused. The dedicated env file must set ORBI_DB_TEST_DISPOSABLE=true.');
    process.exit(1);
  }
}

const validationMode = mode === 'write' ? 'write' : 'read';
const testFile = mode === 'write'
  ? 'tests/financialCoreDbMutation.test.ts'
  : 'tests/financialCoreDbIntegration.test.ts';

console.info(`[db-financial-runner] Starting ${mode} financial DB tests.`);
console.info(`[db-financial-runner] Env file: ${envPath}`);
console.info(`[db-financial-runner] Base runtime env loaded: ${existsSync(baseEnvPath) ? 'yes' : 'no'}`);
console.info('[db-financial-runner] Secrets are masked and not printed.');

const commands = [
  ['npx', ['tsx', 'tests/helpers/validateDbIntegrationEnv.ts', validationMode]],
  ['npx', [
    'tsx', '--test', '--test-force-exit',
    ...(testNamePattern ? ['--test-name-pattern', testNamePattern] : []),
    testFile,
  ]],
];

const windowsNpxCli = process.platform === 'win32'
  ? join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npx-cli.js')
  : null;

for (const [file, commandArgs] of commands) {
  const useWindowsNpxCli = process.platform === 'win32' && file === 'npx';
  const executable = useWindowsNpxCli ? process.execPath : file;
  const executableArgs = useWindowsNpxCli ? [windowsNpxCli, ...commandArgs] : commandArgs;
  if (!executable) throw new Error(`Executable not found: ${file}`);
  const result = spawnSync(executable, executableArgs, {
    cwd: process.cwd(),
    env: childEnv,
    stdio: 'inherit',
    shell: false,
  });

  if (result.status !== 0) {
    process.exit(result.status || 1);
  }
}

console.info(`[db-financial-runner] ${mode} financial DB tests completed.`);
