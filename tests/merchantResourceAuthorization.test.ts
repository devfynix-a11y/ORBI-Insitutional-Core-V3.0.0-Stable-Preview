import assert from 'node:assert/strict';
import test from 'node:test';

import {
  canAccessMerchantResource,
  canAccessOrganizationResource,
} from '../backend/security/ecosystemAuthorization.js';

test('merchant resource access is limited to its owner', () => {
  const merchant = { owner_user_id: 'merchant-owner' };

  assert.equal(
    canAccessMerchantResource(merchant, { actorUserId: 'merchant-owner' }),
    true,
  );
  assert.equal(
    canAccessMerchantResource(merchant, { actorUserId: 'different-merchant' }),
    false,
  );
});

test('explicit privileged merchant access is distinct from same-role access', () => {
  const merchant = { owner_user_id: 'merchant-owner' };

  assert.equal(
    canAccessMerchantResource(merchant, {
      actorUserId: 'authorized-staff',
      privileged: true,
    }),
    true,
  );
  assert.equal(
    canAccessMerchantResource(merchant, {
      actorUserId: 'other-merchant',
      privileged: false,
    }),
    false,
  );
});

test('merchant resource access fails closed for absent identity or resource', () => {
  assert.equal(canAccessMerchantResource(null, { actorUserId: 'merchant-owner' }), false);
  assert.equal(
    canAccessMerchantResource({ owner_user_id: 'merchant-owner' }, { actorUserId: '' }),
    false,
  );
  assert.equal(
    canAccessMerchantResource(
      { owner_user_id: 'merchant-owner' },
      { actorUserId: '', privileged: true },
    ),
    false,
  );
});

test('organization resource access requires active membership in the requested organization', () => {
  const member = {
    organization_id: 'org-1',
    org_role: 'MEMBER',
    account_status: 'active',
  };

  assert.equal(canAccessOrganizationResource(member, 'org-1'), true);
  assert.equal(canAccessOrganizationResource(member, 'org-2'), false);
  assert.equal(
    canAccessOrganizationResource({ ...member, account_status: 'suspended' }, 'org-1'),
    false,
  );
});

test('organization operation roles are enforced independently of membership', () => {
  const member = {
    organization_id: 'org-1',
    org_role: 'MEMBER',
    account_status: 'active',
  };
  const admin = { ...member, org_role: 'ADMIN' };

  assert.equal(
    canAccessOrganizationResource(member, 'org-1', { allowedOrgRoles: ['ADMIN'] }),
    false,
  );
  assert.equal(
    canAccessOrganizationResource(admin, 'org-1', { allowedOrgRoles: ['ADMIN'] }),
    true,
  );
  assert.equal(
    canAccessOrganizationResource(
      { organization_id: null, org_role: null, account_status: 'active' },
      'org-1',
      { privileged: true },
    ),
    true,
  );
  assert.equal(canAccessOrganizationResource(null, 'org-1', { privileged: true }), false);
});
