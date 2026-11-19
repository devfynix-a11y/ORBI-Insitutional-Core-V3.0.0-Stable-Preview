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
