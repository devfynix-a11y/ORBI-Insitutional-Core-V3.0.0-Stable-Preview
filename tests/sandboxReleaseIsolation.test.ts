import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const startCore = readFileSync(
  new URL('../ops/self-hosted/scripts/start-core-sandbox.ps1', import.meta.url),
  'utf8',
);
const startGateway = readFileSync(
  new URL('../ops/self-hosted/scripts/start-pay-gateway-sandbox.ps1', import.meta.url),
  'utf8',
);
const seedFixtures = readFileSync(
  new URL('../ops/self-hosted/scripts/seed-sandbox-fixtures.ps1', import.meta.url),
  'utf8',
);
const compose = readFileSync(
  new URL('../ops/self-hosted/docker-compose.prod.yml', import.meta.url),
  'utf8',
);
const gatewayCompose = readFileSync(
  new URL('../ops/self-hosted/Pay_Gateway/docker-compose.yml', import.meta.url),
  'utf8',
);
const deploy = readFileSync(
  new URL('../ops/self-hosted/scripts/deploy.sh', import.meta.url),
  'utf8',
);

test('release sandbox bootstraps only from isolated sandbox containers', () => {
  assert.match(startCore, /Get-ContainerEnvMap "orbi-core-sandbox-1"/);
  assert.match(startCore, /--network orbi_sandbox_private/);
  assert.match(startCore, /docker network connect orbi_sandbox_test_bridge/);
  assert.match(startCore, /Host -notmatch 'sandbox'/);
  assert.doesNotMatch(startCore, /Get-ContainerEnvMap "orbi-core"/);

  assert.match(startGateway, /Get-ComposeSandboxGatewayContainerName/);
  assert.match(startGateway, /--network orbi_sandbox_private/);
  assert.match(startGateway, /docker network connect orbi_sandbox_test_bridge/);
  assert.doesNotMatch(startGateway, /Get-ContainerEnvValue "orbi-pay-gateway" "DATABASE_URL"/);
  assert.match(startGateway, /PAYMENT_GATEWAY_PROMOTION_SIGNING_PRIVATE_KEY/);

  assert.match(seedFixtures, /"orbi-postgres-sandbox-1"/);
  assert.match(seedFixtures, /"orbi-pay-gateway-postgres-sandbox"/);
  assert.doesNotMatch(seedFixtures, /docker exec -i orbi-postgres psql/);
  assert.match(seedFixtures, /database update above grants the deterministic fixture scopes/);
  assert.match(seedFixtures, /\$service = \(Invoke-Gateway "GET" "\/v1\/developer\/services\/\$serviceCode"\)\.data/);
  assert.match(seedFixtures, /Core simulator uses its own sandbox database/);
  assert.match(seedFixtures, /secrets remain exclusively in the isolated Pay Gateway database/);
  const smokeGate = readFileSync(
    new URL('../ops/self-hosted/scripts/test-sandbox-pay-gateway.ps1', import.meta.url),
    'utf8',
  );
  assert.match(smokeGate, /Sandbox simulator completed the success scenario directly/);
  assert.match(smokeGate, /Checkout requires an OTC challenge but none was returned/);

  assert.match(compose, /PAYMENT_GATEWAY_PROMOTION_SIGNING_PRIVATE_KEY/);
  assert.match(compose, /PAYMENT_GATEWAY_PROMOTION_VERIFICATION_PUBLIC_KEY/);
  assert.match(compose, /private key never\s+      # enters the live gateway container/);
  assert.match(compose, /\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/ORBI GATEWAY\/Pay Gateway Backend/);
  assert.doesNotMatch(compose, /\.\.\/\.\.\/\.\.\/ORBI PAY GATEWAY/);
  assert.match(startGateway, /PAYMENT_GATEWAY_PROMOTION_SIGNING_PRIVATE_KEY/);
  assert.match(gatewayCompose, /pay-gateway-postgres-sandbox[\s\S]*?networks: \[orbi_sandbox_private\]/);
  assert.match(gatewayCompose, /pay-gateway-postgres-live[\s\S]*?networks: \[orbi_private\]/);
  assert.doesNotMatch(gatewayCompose, /pay-gateway-sandbox[\s\S]*?networks:\s*\n\s*- orbi_private/);
  assert.match(gatewayCompose, /orbi_sandbox_test_bridge/);
  assert.match(deploy, /up -d --no-deps core/);
  assert.doesNotMatch(deploy, /up -d --remove-orphans/);
});
