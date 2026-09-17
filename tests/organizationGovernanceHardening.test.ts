import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const schema = readFileSync(new URL('../database/main.sql', import.meta.url), 'utf8');
const server = readFileSync(new URL('../backend/server.ts', import.meta.url), 'utf8');
const routes = readFileSync(new URL('../src/routes/public/operations.ts', import.meta.url), 'utf8');

test('organization invitations are expiring service-role-only records', () => {
  assert.match(schema, /CREATE TABLE IF NOT EXISTS public\.organization_invitations/);
  assert.match(schema, /expires_at TIMESTAMPTZ NOT NULL DEFAULT \(NOW\(\) \+ INTERVAL '72 hours'\)/);
  assert.match(schema, /GRANT EXECUTE ON FUNCTION public\.respond_organization_invitation_v1[\s\S]*TO service_role/);
});

test('invitation acceptance is target-bound, locked, and applies membership atomically', () => {
  const respond = schema.split('CREATE OR REPLACE FUNCTION public.respond_organization_invitation_v1')[1];
  assert.ok(respond);
  assert.match(respond, /FROM public\.organization_invitations[\s\S]*FOR UPDATE/);
  assert.match(respond, /ORGANIZATION_INVITATION_TARGET_REQUIRED/);
  assert.match(respond, /SET organization_id=v_invite\.organization_id,org_role=v_invite\.role/);
  assert.match(respond, /status='EXPIRED'/);
});

test('direct membership linking now creates invitations and privileged roles are denied', () => {
  assert.match(server, /\.rpc\('request_organization_invitation_v1'/);
  assert.doesNotMatch(server, /async linkUserToOrganization[\s\S]*?\.update\(\{\s*organization_id: orgId/);
  assert.match(schema, /ORGANIZATION_INVITATION_PRIVILEGED_ROLE_DENIED/);
  assert.match(routes, /organization-invitations\/:id\/respond/);
});

test('regular member role changes and removal require an independent locked review', () => {
  assert.match(schema, /CREATE TABLE IF NOT EXISTS public\.organization_member_change_requests/);
  const request = schema.split('CREATE OR REPLACE FUNCTION public.request_organization_member_change_v1')[1];
  const respond = schema.split('CREATE OR REPLACE FUNCTION public.respond_organization_member_change_v1')[1];
  assert.match(request, /ORGANIZATION_MEMBER_CHANGE_PRIVILEGED_TARGET/);
  assert.match(request, /ORGANIZATION_MEMBER_CHANGE_TREASURY_TARGET/);
  assert.match(respond, /FROM public\.organization_member_change_requests[\s\S]*FOR UPDATE/);
  assert.match(respond, /p_reviewer_id IN \(v_request\.requested_by,v_request\.target_user_id\)/);
  assert.match(respond, /SET organization_id=NULL,org_role=NULL/);
  assert.match(routes, /organizations\/:id\/member-changes/);
  assert.match(routes, /member-changes\/:id\/respond/);
});

test('privileged leadership changes use feasible SQL-authoritative quorum', () => {
  const request = schema.split('CREATE OR REPLACE FUNCTION public.request_organization_leadership_change_v1')[1];
  const respond = schema.split('CREATE OR REPLACE FUNCTION public.respond_organization_leadership_change_v1')[1];
  assert.match(request, /LEAST\(2,v_reviewers\)/);
  assert.match(request, /ORGANIZATION_LEADERSHIP_REVIEWER_UNAVAILABLE/);
  assert.match(request, /ORGANIZATION_LEADERSHIP_PRIMARY_TRANSFER_REQUIRED/);
  assert.match(request, /ORGANIZATION_LEADERSHIP_TREASURY_REMOVAL_REQUIRED/);
  assert.match(respond, /FROM public\.organization_role_change_requests[\s\S]*FOR UPDATE/);
  assert.match(respond, /ORGANIZATION_LEADERSHIP_LOCKOUT_DENIED/);
  assert.match(server, /\.rpc\('request_organization_leadership_change_v1'/);
  assert.match(server, /\.rpc\('respond_organization_leadership_change_v1'/);
});

test('organization recovery requires verified evidence, cooling, external review, and session revocation', () => {
  assert.match(schema, /CREATE TABLE IF NOT EXISTS public\.organization_recovery_contacts/);
  assert.match(schema, /CREATE TABLE IF NOT EXISTS public\.organization_recovery_cases/);
  const request = schema.split('CREATE OR REPLACE FUNCTION public.request_organization_recovery_v1')[1];
  const respond = schema.split('CREATE OR REPLACE FUNCTION public.respond_organization_recovery_v1')[1];
  assert.match(request, /ORGANIZATION_RECOVERY_CONTACTS_UNVERIFIED/);
  assert.match(request, /p_actor_id IN \(v_org\.primary_admin_user_id,p_beneficiary_id\)/);
  assert.match(respond, /ORGANIZATION_RECOVERY_EXTERNAL_REVIEWER_REQUIRED/);
  assert.match(respond, /ORGANIZATION_RECOVERY_COOLING_ACTIVE/);
  assert.match(respond, /ORGANIZATION_RECOVERY_TREASURY_QUORUM_REQUIRED/);
  assert.match(respond, /UPDATE public\.user_sessions SET is_revoked=TRUE/);
  assert.match(server, /\.rpc\('request_organization_recovery_v1'/);
  assert.match(server, /\.rpc\('respond_organization_recovery_v1'/);
});

test('governance notification delivery is durable and idempotent across channels', () => {
  assert.match(schema, /CREATE TABLE IF NOT EXISTS public\.notification_delivery_events/);
  assert.match(schema, /UNIQUE \(event_key, recipient_user_id\)/);
  assert.match(schema, /claim_notification_delivery_v1/);
  assert.match(schema, /v_row\.status='FAILED'.*INTERVAL '15 minutes'/s);
  assert.match(schema, /finish_notification_delivery_v1/);

  const messaging = readFileSync(new URL('../backend/features/MessagingService.ts', import.meta.url), 'utf8');
  assert.match(messaging, /idempotencyKey\?: string/);
  assert.match(messaging, /Duplicate notification suppressed/);
  assert.match(server, /push: true,[\s\S]*sms: true,[\s\S]*email: true/);
  assert.match(server, /systemCustomBypass: true/);
  assert.match(server, /ORGANIZATION_RECOVERY_REQUESTED/);
});

test('recovery contacts require external identity and independent verification', () => {
  const request = schema.split('CREATE OR REPLACE FUNCTION public.request_organization_recovery_contact_v1')[1];
  const respond = schema.split('CREATE OR REPLACE FUNCTION public.respond_organization_recovery_contact_v1')[1];
  assert.match(request, /RECOVERY_CONTACT_PRIMARY_ADMIN_REQUIRED/);
  assert.match(request, /RECOVERY_CONTACT_EXTERNAL_ACTIVE_USER_REQUIRED/);
  assert.match(request, /digest\(v_value,'sha256'\)/);
  assert.match(respond, /RECOVERY_CONTACT_EXTERNAL_REVIEWER_REQUIRED/);
  assert.match(respond, /RECOVERY_CONTACT_REVOCATION_REQUEST_REQUIRED/);
  assert.match(schema, /COUNT\(DISTINCT contact_user_id\).*status='VERIFIED'.*contact_user_id IS NOT NULL/s);
  assert.match(routes, /organizations\/:id\/recovery-contacts/);
  assert.match(routes, /organization-recovery-contacts\/:id\/respond/);
});

test('reactivation requires remediation, cooling, external review, and least privilege', () => {
  assert.match(schema, /CREATE TABLE IF NOT EXISTS public\.organization_reactivation_cases/);
  const request = schema.split('CREATE OR REPLACE FUNCTION public.request_organization_reactivation_v1')[1];
  const respond = schema.split('CREATE OR REPLACE FUNCTION public.respond_organization_reactivation_v1')[1];
  assert.match(request, /identityReverified/);
  assert.match(request, /credentialResetConfirmed/);
  assert.match(request, /incidentClosed/);
  assert.match(respond, /ORGANIZATION_REACTIVATION_EXTERNAL_REVIEWER_REQUIRED/);
  assert.match(respond, /ORGANIZATION_REACTIVATION_COOLING_ACTIVE/);
  assert.match(respond, /account_status='ACTIVE',org_role='MEMBER'/);
  assert.match(respond, /UPDATE public\.user_sessions SET is_revoked=TRUE/);
  assert.match(routes, /organizations\/:id\/reactivation-cases/);
  assert.match(routes, /organization-reactivation-cases\/:id\/respond/);
});
