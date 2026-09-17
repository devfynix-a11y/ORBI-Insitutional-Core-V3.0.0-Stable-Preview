import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const sql = readFileSync(new URL('../database/main.sql', import.meta.url), 'utf8');
const routes = readFileSync(new URL('../src/routes/public/adminOps.ts', import.meta.url), 'utf8');

test('audit exports require bounded scope and independent approval', () => {
  const request = sql.split('CREATE OR REPLACE FUNCTION public.request_audit_export_v1')[1];
  const review = sql.split('CREATE OR REPLACE FUNCTION public.respond_audit_export_v1')[1];
  assert.match(request, /INTERVAL '90 days'/);
  assert.match(request, /AUDIT_EXPORT_ACCESS_DENIED/);
  assert.match(review, /p_reviewer_id=v_r\.requested_by/);
  assert.match(review, /AUDIT_EXPORT_SCOPE_TOO_LARGE/);
  assert.match(review, /25000/);
});

test('approved packages snapshot ordered signed evidence with an integrity hash', () => {
  assert.match(sql, /CREATE TABLE IF NOT EXISTS public\.audit_export_entries/);
  assert.match(sql, /ROW_NUMBER\(\) OVER\(ORDER BY a\.timestamp,a\.id\)/);
  assert.match(sql, /digest\(convert_to/);
  assert.match(sql, /a\.hash,a\.signature/);
  assert.match(sql, /REFERENCES public\.audit_trail\(id\) ON DELETE RESTRICT/);
});

test('download claims enforce expiry, limit, parties, and idempotent accounting', () => {
  const claim = sql.split('CREATE OR REPLACE FUNCTION public.claim_audit_export_download_v1')[1];
  assert.match(claim, /FOR UPDATE/);
  assert.match(claim, /p_actor_id<>v_r\.requested_by AND p_actor_id<>v_r\.reviewed_by/);
  assert.match(claim, /AUDIT_EXPORT_EXPIRED/);
  assert.match(claim, /AUDIT_EXPORT_DOWNLOAD_LIMIT/);
  assert.match(sql, /PRIMARY KEY\(package_id,actor_id,idempotency_key\)/);
  assert.match(claim, /'replayed',TRUE/);
});

test('routes require authorization, idempotency, safe CSV, audit, and multichannel notices', () => {
  assert.match(routes, /audit-exports', authenticate, requireIdempotencyKey/);
  assert.match(routes, /audit-export-packages\/:id\/download',authenticate,requireIdempotencyKey/);
  assert.match(routes, /if\(\/\^\[=\+\\-@\]\//);
  assert.match(routes, /push:true,sms:true,email:true,mandatory:true/);
  assert.match(routes, /if\(!claim\.replayed\)await Audit\.log/);
});
