export type MerchantResourceAccess = {
  actorUserId: string;
  privileged?: boolean;
};

export type OrganizationActor = {
  organization_id?: unknown;
  org_role?: unknown;
  account_status?: unknown;
};

const normalize = (value: unknown) => String(value ?? '').trim();
const normalizeUpper = (value: unknown) => normalize(value).toUpperCase();

export const canAccessMerchantResource = (
  merchant: { owner_user_id?: unknown } | null | undefined,
  access: MerchantResourceAccess,
): boolean => {
  if (!merchant) return false;
  const ownerUserId = normalize(merchant.owner_user_id);
  const actorUserId = normalize(access.actorUserId);
  if (!actorUserId) return false;
  if (access.privileged === true) return true;
  return ownerUserId.length > 0 && actorUserId.length > 0 && ownerUserId === actorUserId;
};

export const canAccessOrganizationResource = (
  actor: OrganizationActor | null | undefined,
  organizationId: string,
  options: { privileged?: boolean; allowedOrgRoles?: string[] } = {},
): boolean => {
  if (!actor || normalizeUpper(actor.account_status) !== 'ACTIVE') return false;
  if (options.privileged === true) return true;
  const requestedOrganizationId = normalize(organizationId);
  if (!requestedOrganizationId || normalize(actor.organization_id) !== requestedOrganizationId) return false;
  const allowedRoles = (options.allowedOrgRoles || []).map(normalizeUpper);
  return allowedRoles.length === 0 || allowedRoles.includes(normalizeUpper(actor.org_role));
};
