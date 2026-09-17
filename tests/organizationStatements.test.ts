import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const migration=readFileSync(new URL('../database/main.sql',import.meta.url),'utf8');
const server=readFileSync(new URL('../backend/server.ts',import.meta.url),'utf8');
const routes=readFileSync(new URL('../src/routes/public/operations.ts',import.meta.url),'utf8');

test('organization statements snapshot authoritative ledger rows under SQL authorization',()=>{
  const fn=migration.split('CREATE OR REPLACE FUNCTION public.generate_organization_statement_v1')[1];
  assert.ok(fn); assert.match(fn,/ORGANIZATION_STATEMENT_ACCESS_DENIED/);
  assert.match(fn,/JOIN public\.users u ON u\.id=fl\.user_id/);
  assert.match(fn,/u\.organization_id=p_organization_id/);
  assert.match(fn,/ORGANIZATION_STATEMENT_LEDGER_INVALID/);
  assert.match(fn,/pg_advisory_xact_lock/);
});

test('statement snapshots are immutable, hashed, replay safe, and service-role only',()=>{
  assert.match(migration,/UNIQUE\(organization_id,period_start,period_end\)/);
  assert.match(migration,/guard_organization_statement_immutability/);
  assert.match(migration,/digest\(convert_to/);
  assert.match(migration,/REVOKE ALL ON TABLE public\.organization_statements,public\.organization_statement_lines FROM anon,authenticated/);
  assert.match(migration,/GRANT EXECUTE ON FUNCTION public\.generate_organization_statement_v1[\s\S]*TO service_role/);
});

test('statement APIs enforce organization finance roles and bounded pagination',()=>{
  assert.match(server,/allowedOrgRoles:\['ADMIN','FINANCE','ACCOUNTANT','SIGNATORY'\]/);
  assert.match(server,/Math\.min\(500,Math\.max\(1,Math\.trunc\(limit\)\)\)/);
  assert.match(routes,/enterprise\/organizations\/:id\/statements/);
  assert.match(routes,/enterprise\/organization-statements\/:id/);
});

test('statement readiness notification uses push, SMS, email, and stable identity',()=>{
  assert.match(server,/eventCode:'ORGANIZATION_STATEMENT_READY'/);
  assert.match(server,/push:true,sms:true,email:true,mandatory:true/);
  assert.match(server,/organization-statement:\$\{data\.statement_id\}:ready:\$\{actorId\}/);
});
