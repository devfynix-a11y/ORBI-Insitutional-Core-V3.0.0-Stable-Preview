import assert from 'node:assert/strict';
import test from 'node:test';
import type { AuditLogEntry } from '../types.js';
import { verifyAuditChainLinks } from '../backend/security/audit.js';

const entry = (id: string, prevHash: string, hash: string): AuditLogEntry => ({
  id,
  prevHash,
  hash,
  timestamp: '2026-08-31T00:00:00.000Z',
  type: 'SECURITY',
  actor_id: 'system',
  actor_name: 'ORBI Core',
  action: 'TEST',
  metadata: {},
  signature: 'test-signature',
  verificationStatus: 'UNCHECKED',
});

test('audit verifier accepts a valid partial window anchored before its first row', () => {
  const logs = [entry('a', 'older-head', 'hash-a'), entry('b', 'hash-a', 'hash-b')];
  assert.deepEqual(verifyAuditChainLinks(logs, 'older-head'), {
    valid: true,
    report: { failures: [] },
  });
});

test('audit verifier rejects a fork inside the loaded window', () => {
  const logs = [
    entry('a', 'older-head', 'hash-a'),
    entry('b', 'hash-a', 'hash-b'),
    entry('fork', 'hash-a', 'hash-fork'),
  ];
  assert.deepEqual(verifyAuditChainLinks(logs, 'older-head'), {
    valid: false,
    report: { failures: ['fork'] },
  });
});

test('audit writer declares both process serialization and a database transaction lock', async () => {
  const source = await import('node:fs/promises').then((fs) =>
    fs.readFile(new URL('../backend/security/audit.ts', import.meta.url), 'utf8'),
  );
  assert.match(source, /private logQueue: Promise<void>/);
  assert.match(source, /pg_advisory_xact_lock/);
  assert.match(source, /withOrbiTransaction/);
  assert.match(source, /ORDER BY timestamp DESC, id DESC LIMIT 1/);
  assert.match(source, /Math\.max\(Date\.now\(\), previousTimestamp \+ 1\)/);
});
