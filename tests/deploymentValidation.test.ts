import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const validator = readFileSync(
  new URL('../ops/self-hosted/scripts/validate-deployment.sh', import.meta.url),
  'utf8',
);
const compose = readFileSync(
  new URL('../ops/self-hosted/docker-compose.prod.yml', import.meta.url),
  'utf8',
);

test('deployment validation treats environment files as data and supports configured host backup paths', () => {
  assert.match(validator, /env_value\(\)/);
  assert.doesNotMatch(validator, /source "\$\{env_file\}"/);
  assert.match(validator, /ORBI_BACKUP_HOST_DIRECTORY/);
  assert.match(validator, /host_path\(\)/);
  assert.match(compose, /\$\{ORBI_BACKUP_HOST_DIRECTORY:-\/srv\/orbi\/backups\/database\}/);
});
test('Core deployment never pulls or recreates unrelated services', () => {
  const deploy = readFileSync(
    new URL('../ops/self-hosted/scripts/deploy.sh', import.meta.url),
    'utf8',
  );
  assert.match(deploy, /ORBI_CORE_REFRESH_BASE_IMAGE/);
  assert.match(deploy, /existing_project.*self-hosted/);
  assert.match(deploy, /docker-compose\.dev\.yml/);
  assert.match(deploy, /build core/);
  assert.match(deploy, /up -d --no-deps core/);
  assert.doesNotMatch(deploy, /pull --ignore-buildable/);
  assert.doesNotMatch(deploy, /up -d --remove-orphans/);
});