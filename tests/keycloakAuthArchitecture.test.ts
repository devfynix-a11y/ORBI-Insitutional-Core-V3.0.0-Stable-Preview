import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';

const root = process.cwd();
const read = (relativePath: string) => fs.readFileSync(path.join(root, relativePath), 'utf8');

test('Keycloak realm requires PKCE and issues the ORBI Core audience', () => {
  const realm = JSON.parse(read('ops/self-hosted/Auth_Security/keycloak/orbi-realm.json'));
  const mobile = realm.clients.find((client: any) => client.clientId === 'orbi-mobile');

  assert.equal(realm.defaultSignatureAlgorithm, 'RS256');
  assert.equal(realm.verifyEmail, true);
  assert.equal(realm.revokeRefreshToken, true);
  assert.equal(realm.refreshTokenMaxReuse, 0);
  assert.equal(mobile.publicClient, true);
  assert.deepEqual(mobile.webOrigins, []);
  assert.equal(mobile.attributes['pkce.code.challenge.method'], 'S256');
  assert.ok(
    mobile.protocolMappers.some(
      (mapper: any) => mapper.config['included.custom.audience'] === 'orbi-core',
    ),
  );
});

test('Core maps Keycloak subjects to immutable ORBI user ids', () => {
  const service = read('iam/keycloakAuthService.ts');
  const migration = read('database/local/002_keycloak_identity_links.sql');

  assert.match(service, /orbi_auth\.identity_links/);
  assert.match(service, /audience:/);
  assert.match(service, /algorithms: \['RS256'\]/);
  assert.match(migration, /provider_subject TEXT NOT NULL/);
  assert.match(migration, /UNIQUE \(provider, user_id\)/);
});

test('production topology keeps Keycloak private behind the edge', () => {
  const compose = read('ops/self-hosted/docker-compose.prod.yml');
  const gateway = read('ops/self-hosted/Gateway/nginx.conf');

  assert.match(compose, /keycloak:/);
  assert.doesNotMatch(compose, /8081:8080/);
  assert.match(gateway, /server_name auth\.orbifinancial\.com/);
  assert.match(gateway, /server keycloak:8080/);
  assert.match(gateway, /location \^~ \/admin\//);
  assert.match(gateway, /location \^~ \/realms\/master\//);
  assert.match(gateway, /server core:3000 resolve/);
});
