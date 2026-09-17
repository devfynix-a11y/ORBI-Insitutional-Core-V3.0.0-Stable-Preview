import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

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
ORBI Core certification runner

Usage:
  node scripts/core-certification.mjs
  node scripts/core-certification.mjs --db-env .env.test.local
  node scripts/core-certification.mjs --db-env .env.test.local --include-db-write
  node scripts/core-certification.mjs --smoke-url https://api.orbifinancial.com

Notes:
  - Always runs build and normal tests.
  - DB read tests run only when --db-env is provided.
  - DB write tests require --include-db-write and must use disposable fixtures.
  - Smoke test requires ORBI_MONITOR_API_KEY in the shell environment.
`);
}

if (hasFlag('--help') || hasFlag('-h')) {
  usage();
  process.exit(0);
}

const startedAt = new Date();
const dbEnv = readArg('--db-env');
const includeDbWrite = hasFlag('--include-db-write');
const smokeUrl = readArg('--smoke-url');
const commitSha = spawnSync('git', ['rev-parse', 'HEAD'], {
  encoding: 'utf8',
  shell: process.platform === 'win32',
}).stdout.trim();

const results = [];

function runStep(name, command, commandArgs, options = {}) {
  console.info(`\n[core-certification] ${name}`);
  const started = Date.now();
  const result = spawnSync(command, commandArgs, {
    cwd: process.cwd(),
    env: { ...process.env, ...(options.env || {}) },
    stdio: 'inherit',
    shell: process.platform === 'win32',
  });

  const passed = result.status === 0;
  const record = {
    name,
    command: [command, ...commandArgs].join(' '),
    passed,
    exitCode: result.status,
    durationMs: Date.now() - started,
    required: options.required !== false,
  };
  results.push(record);

  if (!passed && record.required) {
    writeReport();
    process.exit(result.status || 1);
  }
}

function writeReport() {
  const finishedAt = new Date();
  const passed = results.every((item) => item.passed || item.required === false);
  const outputDir = join(process.cwd(), 'artifacts', 'certification');
  mkdirSync(outputDir, { recursive: true });
  const stamp = finishedAt.toISOString().replace(/[:]/g, '-');
  const jsonPath = join(outputDir, `${stamp}-core-certification.json`);
  const mdPath = join(outputDir, `${stamp}-core-certification.md`);

  const report = {
    generatedAt: finishedAt.toISOString(),
    startedAt: startedAt.toISOString(),
    durationMs: finishedAt.getTime() - startedAt.getTime(),
    commitSha,
    status: passed ? 'PASSED' : 'FAILED',
    dbReadIncluded: Boolean(dbEnv),
    dbWriteIncluded: Boolean(dbEnv && includeDbWrite),
    smokeIncluded: Boolean(smokeUrl),
    results,
  };

  writeFileSync(jsonPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');

  const lines = [
    '# ORBI Core Certification Evidence',
    '',
    `Generated at: ${report.generatedAt}`,
    `Commit SHA: ${report.commitSha || 'unknown'}`,
    `Status: ${report.status}`,
    '',
    '## Checks',
    '',
    '| Check | Required | Result | Duration |',
    '| --- | --- | --- | ---: |',
    ...results.map((item) => (
      `| ${item.name} | ${item.required ? 'yes' : 'no'} | ${item.passed ? 'PASS' : 'FAIL'} | ${item.durationMs}ms |`
    )),
    '',
    '## Notes',
    '',
    `- DB read tests included: ${report.dbReadIncluded ? 'yes' : 'no'}`,
    `- DB write tests included: ${report.dbWriteIncluded ? 'yes' : 'no'}`,
    `- Release smoke included: ${report.smokeIncluded ? 'yes' : 'no'}`,
    '- No secrets are written into this evidence artifact.',
    '',
  ];
  writeFileSync(mdPath, `${lines.join('\n')}\n`, 'utf8');
  console.info(`\n[core-certification] Evidence written:\n- ${jsonPath}\n- ${mdPath}`);
}

runStep('TypeScript build', 'npm', ['run', 'build']);
runStep('Automated test suite', 'npm', ['test']);

if (dbEnv) {
  if (!existsSync(dbEnv)) {
    console.error(`[core-certification] DB env file not found: ${dbEnv}`);
    writeReport();
    process.exit(1);
  }
  runStep('Financial DB read integration', 'node', [
    'scripts/run-db-financial-tests.mjs',
    '--mode',
    'read',
    '--env',
    dbEnv,
  ]);

  if (includeDbWrite) {
    runStep('Financial DB write mutation', 'node', [
      'scripts/run-db-financial-tests.mjs',
      '--mode',
      'write',
      '--env',
      dbEnv,
      '--allow-write-fixture',
      '--confirm-disposable-database',
    ]);
  }
}

if (smokeUrl) {
  runStep('Release smoke test', 'node', ['scripts/release-smoke.mjs'], {
    env: { ORBI_BASE_URL: smokeUrl },
  });
}

writeReport();

const failed = results.filter((item) => !item.passed && item.required !== false);
process.exit(failed.length > 0 ? 1 : 0);
