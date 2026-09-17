import type { RequestHandler, Router } from 'express';
import { z } from 'zod';
import { Audit } from '../../../backend/security/audit.js';
import { getAdminSupabase, getSupabase } from '../../../backend/supabaseClient.js';
import { ServiceActorOps } from '../../../backend/features/ServiceActorOps.js';
import {
  agentFloatControlService,
  b2bRiskDashboardService,
  commissionDisputeService,
  merchantSettlementReportsService,
  organizationLimitsService,
} from '../../../backend/features/b2b/index.js';
import { Messaging } from '../../../backend/features/MessagingService.js';
import { staffMessagingAdminService } from '../../../backend/features/StaffMessagingAdminService.js';
import { SocketRegistry } from '../../../backend/infrastructure/SocketRegistry.js';
import { AuthService } from '../../../iam/authService.js';
import { sessionHasAnyRole } from '../../middleware/auth/authorization.js';
import { requireIdempotencyKey, resolveIdempotencyHeader } from '../../middleware/security/idempotency.js';
import {
  AUDIT_DECISION_ROLES,
  DOCUMENT_VERIFICATION_ROLES,
  MARKETING_MESSAGE_ROLES,
  RISK_REVIEW_ROLES,
  SERVICE_ACCESS_READ_ROLES,
  SERVICE_ACCESS_REVIEW_ROLES,
  STAFF_ADMIN_ROLES,
  STAFF_AUDIT_ROLES,
  STAFF_MESSAGE_FLAG_ROLES,
  STAFF_MESSAGE_READ_ROLES,
  STAFF_MESSAGE_SEND_ROLES,
  SUPPORT_TICKET_MANAGE_ROLES,
  SUPPORT_TICKET_VIEW_ROLES,
  SUPER_ADMIN_AND_ADMIN_ROLES,
  SYSTEM_SMS_ROLES,
  TRANSACTION_OVERVIEW_ROLES,
  TRANSACTION_REVIEW_ROLES,
  USER_ADMIN_ROLES,
  USER_SEARCH_ROLES,
} from '../../middleware/auth/roles.js';

const MessageAudienceFiltersSchema = z.object({
  search: z.string().trim().optional(),
  country: z.string().trim().optional(),
  registryType: z.string().trim().optional(),
  kycStatus: z.string().trim().optional(),
  accountStatus: z.string().trim().optional(),
  appOrigin: z.string().trim().optional(),
  hasPhone: z.boolean().optional(),
  hasEmail: z.boolean().optional(),
  createdAfter: z.string().trim().optional(),
  createdBefore: z.string().trim().optional(),
  newCustomersWithinDays: z.coerce.number().int().positive().optional(),
  minTransactionCount: z.coerce.number().int().min(0).optional(),
  minTransactionAmount: z.coerce.number().min(0).optional(),
  maxTransactionAmount: z.coerce.number().min(0).optional(),
  minTotalTransactionAmount: z.coerce.number().min(0).optional(),
  currency: z.string().trim().optional(),
  limit: z.coerce.number().int().min(1).max(5000).optional(),
});

const TemplateCatalogQuerySchema = z.object({
  search: z.string().trim().optional(),
  channel: z.enum(['sms', 'email', 'push', 'whatsapp']).optional(),
  language: z.enum(['en', 'sw']).optional(),
  messageType: z.enum(['transactional', 'promotional']).optional(),
  limit: z.coerce.number().int().min(1).max(200).optional(),
});

const IncompleteRegistrationQuerySchema = z.object({
  registryType: z.string().trim().optional(),
  status: z.string().trim().optional(),
  includeExpired: z.coerce.boolean().optional(),
  limit: z.coerce.number().int().min(1).max(200).optional(),
});

const TemplatePreviewSchema = z.object({
  templateName: z.string().min(1),
  variables: z.record(z.string(), z.unknown()).optional(),
  channel: z.enum(['sms', 'email', 'push', 'whatsapp']).optional(),
  language: z.enum(['en', 'sw']).optional(),
  messageType: z.enum(['transactional', 'promotional']).optional(),
});

const StaffTemplatedSendSchema = z.object({
  templateName: z.string().min(1),
  variables: z.record(z.string(), z.unknown()).optional(),
  userIds: z.array(z.string().uuid()).optional(),
  filters: MessageAudienceFiltersSchema.optional(),
  channel: z.enum(['sms', 'email', 'push', 'whatsapp']).optional(),
  language: z.enum(['en', 'sw']).optional(),
  messageType: z.enum(['transactional', 'promotional']).optional(),
  category: z.enum(['security', 'update', 'promo', 'info']).optional(),
  maxRecipients: z.coerce.number().int().min(1).max(500).optional(),
});

const StaffSystemSmsSchema = z.object({
  body: z.string().min(1).max(2000),
  userIds: z.array(z.string().uuid()).optional(),
  filters: MessageAudienceFiltersSchema.optional(),
  category: z.enum(['security', 'update', 'promo', 'info']).optional(),
  maxRecipients: z.coerce.number().int().min(1).max(500).optional(),
});

const B2B_READ_ROLES = [
  'ADMIN',
  'SUPER_ADMIN',
  'AUDIT',
  'ACCOUNTANT',
  'CUSTOMER_CARE',
  'RISK_OFFICER',
  'FRAUD',
] as const;

const B2B_OPERATE_ROLES = [
  'ADMIN',
  'SUPER_ADMIN',
  'ACCOUNTANT',
  'RISK_OFFICER',
] as const;

const MerchantSettlementReportGenerateSchema = z.object({
  merchantId: z.string().uuid(),
  periodStart: z.string().min(1),
  periodEnd: z.string().min(1),
  currency: z.string().trim().length(3).optional(),
});

const AgentFloatControlSchema = z.object({
  agentId: z.string().uuid(),
  currency: z.string().trim().length(3).optional(),
  minFloat: z.coerce.number().min(0).optional(),
  maxFloat: z.coerce.number().min(0).optional(),
  dailyCashInLimit: z.coerce.number().min(0).optional(),
  dailyCashOutLimit: z.coerce.number().min(0).optional(),
  status: z.enum(['active', 'paused', 'locked']).optional(),
  reason: z.string().trim().min(5).max(500),
});

const CommissionDisputeOpenSchema = z.object({
  commissionId: z.string().uuid(),
  reason: z.string().trim().min(5).max(500),
});

const CommissionDisputeResolveSchema = z.object({
  decision: z.enum(['resolved', 'rejected']),
  resolutionNote: z.string().trim().min(5).max(1000),
});

const OrganizationLimitSchema = z.object({
  organizationId: z.string().uuid(),
  currency: z.string().trim().length(3).optional(),
  maxAmountPerTx: z.coerce.number().min(0).optional(),
  dailyLimit: z.coerce.number().min(0).optional(),
  monthlyLimit: z.coerce.number().min(0).optional(),
  makerCheckerThreshold: z.coerce.number().min(0).optional(),
  autoFreezeThreshold: z.coerce.number().min(0).optional(),
  status: z.enum(['active', 'paused', 'locked']).optional(),
  reason: z.string().trim().min(5).max(500),
});

const AdminUserSearchSchema = z.object({
  query: z.string().trim().optional(),
  role: z.string().trim().optional(),
  registryType: z.string().trim().optional(),
  accountStatus: z.string().trim().optional(),
  kycStatus: z.string().trim().optional(),
  limit: z.coerce.number().int().min(1).max(100).optional(),
});

const AccountStatusUpdateWithReasonSchema = z.object({
  status: z.enum(['active', 'blocked', 'frozen', 'pending']),
  reason: z.string().trim().min(5).max(500),
});

const AdminAuditTrailQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(200).optional(),
  eventType: z.string().trim().optional(),
  actorId: z.string().trim().optional(),
  transactionId: z.string().trim().optional(),
  action: z.string().trim().optional(),
});
const AuditExportRequestSchema=z.object({periodStart:z.string().datetime({offset:true}),periodEnd:z.string().datetime({offset:true}),eventTypes:z.array(z.string().trim().min(1).max(80)).max(20).default([]),actionPrefix:z.string().trim().min(1).max(120).nullable().optional(),format:z.enum(['JSON','CSV']),purpose:z.string().trim().min(10).max(500)});
const AuditExportReviewSchema=z.object({decision:z.enum(['APPROVE','REJECT']),reason:z.string().trim().min(10).max(500)});
const FinancialExceptionAssignSchema=z.object({assigneeId:z.string().uuid()});
const FinancialExceptionResolutionSchema=z.object({disposition:z.enum(['FALSE_POSITIVE','RECONCILED','REVERSED','REPAIRED','ACCEPTED_RISK','REFERRED']),summary:z.string().trim().min(10).max(1000),evidence:z.record(z.string(),z.unknown()).refine(v=>Object.keys(v).length>0,'Evidence is required')});
const FinancialExceptionReviewSchema=z.object({decision:z.enum(['APPROVE','REJECT']),reason:z.string().trim().min(10).max(500)});

const AdminRiskAlertsQuerySchema = z.object({
  status: z.string().trim().optional(),
  days: z.coerce.number().int().min(1).max(90).optional(),
});

const AdminRiskGeoHeatmapQuerySchema = z.object({
  days: z.coerce.number().int().min(1).max(90).optional(),
  countryCode: z.string().trim().min(2).max(3).optional(),
  currency: z.string().trim().length(3).optional(),
  minRiskScore: z.coerce.number().min(0).max(100).optional(),
  limit: z.coerce.number().int().min(1).max(5000).optional(),
});

const AdminRiskLiveGeoQuerySchema = z.object({
  minutes: z.coerce.number().int().min(1).max(1440).optional(),
  countryCode: z.string().trim().min(2).max(3).optional(),
  currency: z.string().trim().length(3).optional(),
  status: z.string().trim().optional(),
  minRiskScore: z.coerce.number().min(0).max(100).optional(),
  precision: z.enum(['region', 'city', 'approximate']).optional(),
  limit: z.coerce.number().int().min(1).max(1000).optional(),
});

const AdminComplianceNodeRiskQuerySchema = z.object({
  windowHours: z.coerce.number().int().min(2).max(168).optional(),
  bucketHours: z.coerce.number().int().min(1).max(12).optional(),
  includeInactive: z.coerce.boolean().optional(),
});

const StaffDirectMessageSchema = z.object({
  recipientId: z.string().uuid().optional(),
  targetRole: z.string().trim().optional(),
  content: z.string().min(1).max(4000),
});

const SupportTicketCreateSchema = z.object({
  title: z.string().min(1).max(200),
  body: z.string().min(1).max(4000),
  category: z.string().trim().min(1).max(80).default('support'),
  priority: z.enum(['low', 'normal', 'high', 'critical']).optional(),
  customerId: z.string().uuid().optional(),
  customerQuery: z.string().trim().optional(),
  assignedTo: z.string().uuid().optional(),
  tags: z.array(z.string().trim().min(1).max(50)).optional(),
});

const SupportTicketUpdateSchema = z.object({
  status: z.enum(['open', 'in_progress', 'resolved', 'closed']).optional(),
  assignedTo: z.string().uuid().nullable().optional(),
  resolution: z.string().trim().max(4000).optional(),
  internalNote: z.string().trim().max(4000).optional(),
});

type GeoSignal = {
  countryCode: string;
  region: string;
  regionCode?: string | null;
  city?: string | null;
  source: string;
  latitude?: number | null;
  longitude?: number | null;
  consented?: boolean;
  capturedAt?: string | null;
};

type RiskGeoBucket = {
  key: string;
  countryCode: string;
  region: string;
  regionCode: string | null;
  city: string | null;
  transactionCount: number;
  riskSignalCount: number;
  alertCount: number;
  totalAmount: number;
  currencies: Set<string>;
  sources: Set<string>;
  riskScoreTotal: number;
  riskScoreSamples: number;
  maxRiskScore: number;
};

type ComplianceNodeZone = {
  id: string;
  name: string;
  provider: 'self_hosted' | 'orbi_pay' | 'database' | 'admin' | 'external';
  role: 'core_api_primary' | 'pay_gateway_edge' | 'ledger_authority' | 'admin_ops' | 'provider_rails';
  baseUrl?: string;
  healthEndpoint?: string;
  regionCode: string;
  jurisdiction: string;
  coordinates: { lat: number; lng: number };
  competencies: string[];
  baseRisk: number;
  active: boolean;
};

type ComplianceNodeBucket = {
  zoneId: string;
  bucketIndex: number;
  bucketStart: string;
  bucketEnd: string;
  riskDensity: number;
  status: 'HEALTHY' | 'WATCH' | 'DEGRADED' | 'CRITICAL_OVERLOAD';
  drivers: Array<{ code: string; count: number; weight: number; score: number }>;
  counts: {
    transactions: number;
    failedTransactions: number;
    heldTransactions: number;
    impossibleTravel: number;
    geoComplianceBlocks: number;
    highRiskSignals: number;
    criticalRiskSignals: number;
    auditSensitiveActions: number;
    providerAnomalies: number;
    amlAlerts: number;
  };
};

const objectValue = (value: unknown): Record<string, any> => (
  value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, any> : {}
);

const firstString = (...values: unknown[]): string | undefined => {
  for (const value of values) {
    if (typeof value !== 'string') continue;
    const trimmed = value.trim();
    if (trimmed) return trimmed;
  }
  return undefined;
};

const numberValue = (value: unknown): number | undefined => {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.trim()) {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return undefined;
};

const normalizeCountryCode = (value: unknown): string | undefined => {
  const normalized = firstString(value)?.toUpperCase();
  return normalized && /^[A-Z]{2,3}$/.test(normalized) ? normalized : undefined;
};

const booleanValue = (value: unknown): boolean | undefined => {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    if (['true', 'yes', '1'].includes(normalized)) return true;
    if (['false', 'no', '0'].includes(normalized)) return false;
  }
  return undefined;
};

const roundCoordinate = (value: number | null | undefined, precision: 'region' | 'city' | 'approximate'): number | null => {
  if (value === null || value === undefined || !Number.isFinite(value)) return null;
  const digits = precision === 'approximate' ? 3 : precision === 'city' ? 2 : 1;
  return Number(value.toFixed(digits));
};

const geoSeverity = (score: number): 'low' | 'medium' | 'high' | 'critical' => {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 35) return 'medium';
  return 'low';
};

const extractGeoSignal = (record: Record<string, any>, fallbackSource: string): GeoSignal => {
  const metadata = objectValue(record.metadata);
  const payload = objectValue(record.payload);
  const payloadMetadata = objectValue(payload.metadata);
  const geo = objectValue(metadata.geo);
  const payloadGeo = objectValue(payload.geo);
  const payloadMetadataGeo = objectValue(payloadMetadata.geo);
  const riskContextGeo = objectValue(objectValue(metadata.riskContext).geo);
  const riskContext = objectValue(metadata.riskContext);

  const countryCode = normalizeCountryCode(
    firstString(
      geo.countryCode,
      geo.country_code,
      payloadGeo.countryCode,
      payloadGeo.country_code,
      payloadMetadataGeo.countryCode,
      payloadMetadataGeo.country_code,
      riskContextGeo.countryCode,
      riskContextGeo.country_code,
      metadata.countryCode,
      metadata.country_code,
      payload.countryCode,
      payload.country_code,
      payloadMetadata.countryCode,
      payloadMetadata.country_code,
      record.countryCode,
      record.country_code,
    ),
  ) || 'UNKNOWN';

  const regionCode = firstString(
    geo.regionCode,
    geo.region_code,
    payloadGeo.regionCode,
    payloadGeo.region_code,
    payloadMetadataGeo.regionCode,
    payloadMetadataGeo.region_code,
    riskContextGeo.regionCode,
    riskContextGeo.region_code,
    metadata.regionCode,
    metadata.region_code,
    payload.regionCode,
    payload.region_code,
    payloadMetadata.regionCode,
    payloadMetadata.region_code,
  ) || null;

  const region = firstString(
    geo.region,
    payloadGeo.region,
    payloadMetadataGeo.region,
    riskContextGeo.region,
    metadata.region,
    payload.region,
    payloadMetadata.region,
    regionCode,
    geo.city,
    payloadGeo.city,
    payloadMetadataGeo.city,
  ) || 'Unknown';

  const city = firstString(
    geo.city,
    payloadGeo.city,
    payloadMetadataGeo.city,
    riskContextGeo.city,
    metadata.city,
    payload.city,
    payloadMetadata.city,
  ) || null;

  const source = firstString(
    geo.source,
    payloadGeo.source,
    payloadMetadataGeo.source,
    riskContextGeo.source,
    metadata.geoSource,
    payload.geoSource,
  ) || fallbackSource;

  const latitude = numberValue(
    geo.latitudeRounded ?? geo.latRounded ?? geo.latitude ?? geo.lat ??
    payloadGeo.latitudeRounded ?? payloadGeo.latRounded ?? payloadGeo.latitude ?? payloadGeo.lat ??
    payloadMetadataGeo.latitudeRounded ?? payloadMetadataGeo.latRounded ?? payloadMetadataGeo.latitude ?? payloadMetadataGeo.lat,
  ) ?? null;
  const longitude = numberValue(
    geo.longitudeRounded ?? geo.lngRounded ?? geo.longitude ?? geo.lng ??
    payloadGeo.longitudeRounded ?? payloadGeo.lngRounded ?? payloadGeo.longitude ?? payloadGeo.lng ??
    payloadMetadataGeo.longitudeRounded ?? payloadMetadataGeo.lngRounded ?? payloadMetadataGeo.longitude ?? payloadMetadataGeo.lng,
  ) ?? null;
  const consented = booleanValue(
    geo.consented ??
    geo.locationConsent ??
    payloadGeo.consented ??
    payloadGeo.locationConsent ??
    payloadMetadataGeo.consented ??
    payloadMetadataGeo.locationConsent ??
    riskContext.locationConsent ??
    metadata.locationConsent,
  );
  const capturedAt = firstString(
    geo.capturedAt,
    geo.captured_at,
    payloadGeo.capturedAt,
    payloadGeo.captured_at,
    payloadMetadataGeo.capturedAt,
    payloadMetadataGeo.captured_at,
    metadata.geoCapturedAt,
  ) || null;

  return { countryCode, region, regionCode, city, source, latitude, longitude, consented, capturedAt };
};

const getRiskGeoBucket = (buckets: Map<string, RiskGeoBucket>, geo: GeoSignal): RiskGeoBucket => {
  const key = `${geo.countryCode}|${geo.regionCode || geo.region}`;
  const existing = buckets.get(key);
  if (existing) return existing;

  const created: RiskGeoBucket = {
    key,
    countryCode: geo.countryCode,
    region: geo.region,
    regionCode: geo.regionCode || null,
    city: geo.city || null,
    transactionCount: 0,
    riskSignalCount: 0,
    alertCount: 0,
    totalAmount: 0,
    currencies: new Set<string>(),
    sources: new Set<string>(),
    riskScoreTotal: 0,
    riskScoreSamples: 0,
    maxRiskScore: 0,
  };
  buckets.set(key, created);
  return created;
};

const envString = (key: string, fallback: string): string => {
  const value = process.env[key]?.trim();
  return value || fallback;
};

const envNumber = (key: string, fallback: number): number => {
  const value = process.env[key]?.trim();
  if (!value) return fallback;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
};

const complianceNodeZones = (): ComplianceNodeZone[] => {
  const primaryUrl = envString('ORBI_PRIMARY_CORE_BASE_URL', 'https://api.orbifinancial.com');
  const payGatewayUrl = envString('ORBI_PAY_GATEWAY_BASE_URL', 'https://pay.orbifinancial.com');

  return [
    {
      id: 'ORBI-PRIMARY-CORE',
      name: 'ORBI Self-Hosted Core',
      provider: 'self_hosted',
      role: 'core_api_primary',
      baseUrl: primaryUrl,
      healthEndpoint: `${primaryUrl}/health`,
      regionCode: envString('ORBI_PRIMARY_CORE_REGION', 'private-datacenter'),
      jurisdiction: envString('ORBI_PRIMARY_CORE_JURISDICTION', 'TZ'),
      coordinates: {
        lat: envNumber('ORBI_PRIMARY_CORE_LAT', -6.7924),
        lng: envNumber('ORBI_PRIMARY_CORE_LNG', 39.2083),
      },
      competencies: ['transaction_preview', 'transaction_settlement', 'wallet_governance', 'admin_api', 'risk_enforcement', 'data_residency'],
      baseRisk: envNumber('ORBI_PRIMARY_CORE_BASE_RISK', 25),
      active: true,
    },
    {
      id: 'ORBI-PAY-GATEWAY-EDGE',
      name: 'ORBI Pay Gateway Edge',
      provider: 'orbi_pay',
      role: 'pay_gateway_edge',
      baseUrl: payGatewayUrl,
      healthEndpoint: `${payGatewayUrl}/health`,
      regionCode: envString('ORBI_PAY_GATEWAY_REGION', 'edge-global'),
      jurisdiction: envString('ORBI_PAY_GATEWAY_JURISDICTION', 'GLOBAL'),
      coordinates: {
        lat: envNumber('ORBI_PAY_GATEWAY_LAT', 40.7128),
        lng: envNumber('ORBI_PAY_GATEWAY_LNG', -74.0060),
      },
      competencies: ['pay_gateway', 'provider_webhooks', 'external_settlement', 'provider_callback_monitoring'],
      baseRisk: envNumber('ORBI_PAY_GATEWAY_BASE_RISK', 35),
      active: Boolean(payGatewayUrl),
    },
    {
      id: 'ORBI-LEDGER-AUTHORITY',
      name: 'Private Ledger Authority',
      provider: 'database',
      role: 'ledger_authority',
      regionCode: envString('ORBI_LEDGER_REGION', 'private-postgres'),
      jurisdiction: envString('ORBI_LEDGER_JURISDICTION', 'TZ'),
      coordinates: {
        lat: envNumber('ORBI_LEDGER_LAT', 51.5072),
        lng: envNumber('ORBI_LEDGER_LNG', -0.1276),
      },
      competencies: ['ledger_truth', 'audit_trail', 'wallet_balances', 'reconciliation', 'forensics'],
      baseRisk: envNumber('ORBI_LEDGER_BASE_RISK', 30),
      active: true,
    },
    {
      id: 'ORBI-ADMIN-OPS',
      name: 'Admin Operations',
      provider: 'admin',
      role: 'admin_ops',
      regionCode: envString('ORBI_ADMIN_OPS_REGION', 'operator-control'),
      jurisdiction: envString('ORBI_ADMIN_OPS_JURISDICTION', 'CONTROL_PLANE'),
      coordinates: {
        lat: envNumber('ORBI_ADMIN_OPS_LAT', -6.7924),
        lng: envNumber('ORBI_ADMIN_OPS_LNG', 39.2083),
      },
      competencies: ['staff_activity', 'kyc_review', 'support_controls', 'configuration_changes', 'audit_review'],
      baseRisk: envNumber('ORBI_ADMIN_OPS_BASE_RISK', 20),
      active: true,
    },
    {
      id: 'ORBI-PROVIDER-RAILS',
      name: 'Provider Rails',
      provider: 'external',
      role: 'provider_rails',
      regionCode: envString('ORBI_PROVIDER_RAILS_REGION', 'provider-network'),
      jurisdiction: envString('ORBI_PROVIDER_RAILS_JURISDICTION', 'EXTERNAL'),
      coordinates: {
        lat: envNumber('ORBI_PROVIDER_RAILS_LAT', -6.3690),
        lng: envNumber('ORBI_PROVIDER_RAILS_LNG', 34.8888),
      },
      competencies: ['mobile_money', 'bank_rails', 'card_rails', 'provider_routing', 'provider_anomalies'],
      baseRisk: envNumber('ORBI_PROVIDER_RAILS_BASE_RISK', 32),
      active: true,
    },
  ];
};

const complianceNodeStatus = (score: number): ComplianceNodeBucket['status'] => {
  if (score >= 75) return 'CRITICAL_OVERLOAD';
  if (score >= 60) return 'DEGRADED';
  if (score >= 35) return 'WATCH';
  return 'HEALTHY';
};

const createComplianceBucket = (
  zoneId: string,
  bucketIndex: number,
  bucketStart: Date,
  bucketEnd: Date,
): ComplianceNodeBucket => ({
  zoneId,
  bucketIndex,
  bucketStart: bucketStart.toISOString(),
  bucketEnd: bucketEnd.toISOString(),
  riskDensity: 0,
  status: 'HEALTHY',
  drivers: [],
  counts: {
    transactions: 0,
    failedTransactions: 0,
    heldTransactions: 0,
    impossibleTravel: 0,
    geoComplianceBlocks: 0,
    highRiskSignals: 0,
    criticalRiskSignals: 0,
    auditSensitiveActions: 0,
    providerAnomalies: 0,
    amlAlerts: 0,
  },
});

const createComplianceTimeline = (
  zones: ComplianceNodeZone[],
  windowHours: number,
  bucketHours: number,
): Map<string, ComplianceNodeBucket[]> => {
  const bucketCount = Math.ceil(windowHours / bucketHours);
  const now = Date.now();
  const windowMs = windowHours * 60 * 60 * 1000;
  const bucketMs = bucketHours * 60 * 60 * 1000;
  const windowStart = now - windowMs;
  const timelines = new Map<string, ComplianceNodeBucket[]>();

  for (const zone of zones) {
    const buckets: ComplianceNodeBucket[] = [];
    for (let index = 0; index < bucketCount; index += 1) {
      const start = new Date(windowStart + index * bucketMs);
      const end = new Date(Math.min(windowStart + (index + 1) * bucketMs, now));
      buckets.push(createComplianceBucket(zone.id, index, start, end));
    }
    timelines.set(zone.id, buckets);
  }

  return timelines;
};

const bucketForTime = (
  buckets: ComplianceNodeBucket[] | undefined,
  createdAt: unknown,
): ComplianceNodeBucket | undefined => {
  if (!buckets?.length) return undefined;
  const time = Date.parse(firstString(createdAt) || '');
  if (!Number.isFinite(time)) return undefined;
  return buckets.find((bucket) => {
    const start = Date.parse(bucket.bucketStart);
    const end = Date.parse(bucket.bucketEnd);
    return time >= start && time < end;
  }) || buckets[buckets.length - 1];
};

const addComplianceDriver = (
  bucket: ComplianceNodeBucket | undefined,
  code: string,
  weight: number,
  countKey?: keyof ComplianceNodeBucket['counts'],
) => {
  if (!bucket) return;
  const existing = bucket.drivers.find((driver) => driver.code === code && driver.weight === weight);
  if (existing) {
    existing.count += 1;
    existing.score += weight;
  } else {
    bucket.drivers.push({ code, count: 1, weight, score: weight });
  }
  if (countKey) bucket.counts[countKey] += 1;
};

const jsonIncludes = (value: unknown, needle: string): boolean => {
  try {
    return JSON.stringify(value || {}).toUpperCase().includes(needle.toUpperCase());
  } catch {
    return false;
  }
};

const finalizeComplianceTimeline = (
  zones: ComplianceNodeZone[],
  timelines: Map<string, ComplianceNodeBucket[]>,
) => {
  for (const zone of zones) {
    const buckets = timelines.get(zone.id) || [];
    for (const bucket of buckets) {
      const driverScore = bucket.drivers.reduce((sum, driver) => sum + driver.score, 0);
      const volumePressure = Math.min(18, Math.log10(bucket.counts.transactions + 1) * 8);
      const rawScore = zone.baseRisk + driverScore + volumePressure;
      bucket.riskDensity = Math.round(Math.min(100, rawScore));
      bucket.status = complianceNodeStatus(bucket.riskDensity);
      bucket.drivers.sort((a, b) => b.score - a.score || b.count - a.count);
    }
  }
};

type Deps = {
  authenticate: RequestHandler;
  adminOnly: RequestHandler;
  validate: (schema: any) => RequestHandler;
  requireSessionPermission: (permissions: string[], roles?: string[]) => RequestHandler;
  LogicCore: any;
  queryStringValue: (value: unknown) => string | undefined;
  syncUserIdentityClassification: (userId: string, updates: { role: string; registryType: string; metadata?: Record<string, any> }) => Promise<void>;
  mapServiceRoleToRegistryType: (role: string) => string;
  TransactionIssueSchema: any;
  TransactionAuditDecisionSchema: any;
  DocumentVerifySchema: any;
  StaffCreateSchema: any;
  StaffAdminUpdateSchema: any;
  StaffPasswordResetSchema: any;
  ManagedIdentityCreateSchema: any;
  ServiceAccessRequestReviewSchema: any;
  AccountStatusUpdateSchema: any;
  UserProfileUpdateSchema: any;
  messagingTestRoutesEnabled: boolean;
};

export const registerAdminOpsRoutes = (v1: Router, deps: Deps) => {
  const {
    authenticate,
    adminOnly,
    validate,
    requireSessionPermission,
    LogicCore,
    queryStringValue,
    syncUserIdentityClassification,
    mapServiceRoleToRegistryType,
    TransactionIssueSchema,
    TransactionAuditDecisionSchema,
    DocumentVerifySchema,
    StaffCreateSchema,
    StaffAdminUpdateSchema,
    StaffPasswordResetSchema,
    ManagedIdentityCreateSchema,
    ServiceAccessRequestReviewSchema,
    AccountStatusUpdateSchema,
    UserProfileUpdateSchema,
    messagingTestRoutesEnabled,
  } = deps;

  v1.get('/admin/transactions', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...TRANSACTION_OVERVIEW_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const result = await LogicCore.getAllTransactions({
        limit: Number(queryStringValue(req.query.limit) || 100),
        offset: Number(queryStringValue(req.query.offset) || 0),
        status: queryStringValue(req.query.status),
        type: queryStringValue(req.query.type),
        currency: queryStringValue(req.query.currency),
        query: queryStringValue(req.query.query),
        dateFrom: queryStringValue(req.query.dateFrom),
        dateTo: queryStringValue(req.query.dateTo),
      });
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/transactions/summary', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...TRANSACTION_OVERVIEW_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const result = await LogicCore.getTransactionVolumeSummary({
        status: queryStringValue(req.query.status),
        type: queryStringValue(req.query.type),
        currency: queryStringValue(req.query.currency),
        query: queryStringValue(req.query.query),
        dateFrom: queryStringValue(req.query.dateFrom),
        dateTo: queryStringValue(req.query.dateTo),
      });
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/transactions/:id/ledger', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...TRANSACTION_REVIEW_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const result = await LogicCore.getLedgerEntries(req.params.id);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/admin/transactions/:id/lock', authenticate, validate(TransactionIssueSchema), async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...TRANSACTION_REVIEW_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const transactionId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
      const result = await LogicCore.lockTransactionForAdmin(session.sub, transactionId, req.body.reason);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.post('/admin/transactions/:id/audit', authenticate, validate(TransactionAuditDecisionSchema), async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...AUDIT_DECISION_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const transactionId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
      const result = await LogicCore.recordTransactionAuditDecision(session.sub, transactionId, req.body.passed, req.body.notes);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.post('/admin/transactions/:id/approve', authenticate, validate(TransactionIssueSchema), async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...SUPER_ADMIN_AND_ADMIN_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const transactionId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
      const result = await LogicCore.approveReviewedTransaction(session.sub, transactionId, req.body.reason);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.post('/admin/transactions/approve-audited', authenticate, validate(TransactionIssueSchema), async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...SUPER_ADMIN_AND_ADMIN_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const result = await LogicCore.approveAllAuditPassedTransactions(session.sub, req.body.reason);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.post('/admin/transactions/:id/reverse', authenticate, validate(TransactionIssueSchema), async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...SUPER_ADMIN_AND_ADMIN_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const transactionId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
      await LogicCore.reverseTransactionForAdmin(session.sub, transactionId, req.body.reason);
      res.json({ success: true });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.patch('/admin/documents/:id/verify', authenticate, validate(DocumentVerifySchema), async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...DOCUMENT_VERIFICATION_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const result = await LogicCore.verifyDocument(req.params.id as string, session.sub, req.body);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/admin/staff', authenticate, requireSessionPermission(['staff.write'], [...STAFF_ADMIN_ROLES]), validate(StaffCreateSchema), async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...SUPER_ADMIN_AND_ADMIN_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const result = await LogicCore.createStaff(req.body, session.sub);
      if (result.error) return res.status(400).json({ success: false, error: result.error });
      res.json({ success: true, data: result.data });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/staff', authenticate, requireSessionPermission(['staff.read', 'staff.write'], [...STAFF_AUDIT_ROLES]), async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...STAFF_AUDIT_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const data = await LogicCore.getAllStaff();
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.patch('/admin/staff/:id', authenticate, requireSessionPermission(['staff.write'], [...STAFF_ADMIN_ROLES]), validate(StaffAdminUpdateSchema), async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...STAFF_ADMIN_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const result = await LogicCore.adminUpdateStaffProfile(req.params.id as string, req.body, session.sub);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/staff/:id/activity', authenticate, requireSessionPermission(['staff.read', 'admin.audit.read'], [...STAFF_AUDIT_ROLES]), async (req, res) => {
    try {
      const staffId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
      const data = await LogicCore.getDetailedUserActivity(staffId);
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/admin/staff/:id/reset-password', authenticate, requireSessionPermission(['staff.write'], [...STAFF_ADMIN_ROLES]), validate(StaffPasswordResetSchema), async (req, res) => {
    const session = (req as any).session;

    try {
      const result = await LogicCore.adminResetStaffPassword(req.params.id as string, req.body.password, session.sub);
      if (result?.error) return res.status(400).json({ success: false, error: result.error });
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/permissions/preview', authenticate, requireSessionPermission(['staff.read', 'staff.write'], [...STAFF_AUDIT_ROLES]), async (req, res) => {
    try {
      const role = String(queryStringValue(req.query.role) || 'USER').trim().toUpperCase();
      const status = String(queryStringValue(req.query.status) || 'active').trim().toLowerCase();
      const permissions = new AuthService().describePermissionsForRole(role as any, status);
      res.json({ success: true, data: { role, status, permissions } });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/admin/users/register', authenticate, validate(ManagedIdentityCreateSchema), async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...SUPER_ADMIN_AND_ADMIN_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const result = await LogicCore.createManagedIdentity(req.body, session.sub);
      if (result.error) return res.status(400).json({ success: false, error: result.error });
      res.json({ success: true, data: result.data });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/service-access/requests', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...SERVICE_ACCESS_READ_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) {
        return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      }

      let query = sb.from('service_access_requests').select('*').order('created_at', { ascending: false });
      const status = String(req.query.status || '').trim();
      const requestedRole = String(req.query.requestedRole || req.query.requested_role || '').trim().toUpperCase();
      if (status) query = query.eq('status', status);
      if (requestedRole) query = query.eq('requested_role', requestedRole);

      const { data, error } = await query;
      if (error) return res.status(500).json({ success: false, error: error.message });
      res.json({ success: true, data: data || [] });
    } catch (e: any) {
      console.error('[Admin] Service Access Requests Error:', e);
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/admin/service-access/requests/:id/review', authenticate, validate(ServiceAccessRequestReviewSchema), async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...SERVICE_ACCESS_REVIEW_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) {
        return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      }

      const { data: existing, error: fetchError } = await sb.from('service_access_requests').select('*').eq('id', req.params.id).maybeSingle();
      if (fetchError) return res.status(500).json({ success: false, error: fetchError.message });
      if (!existing) return res.status(404).json({ success: false, error: 'REQUEST_NOT_FOUND' });

      const currentStatus = String(existing.status || '').toLowerCase();
      if (currentStatus !== 'pending' && currentStatus !== 'under_review') {
        return res.status(409).json({ success: false, error: 'REQUEST_ALREADY_RESOLVED' });
      }

      const decision = String(req.body.decision || '').trim().toUpperCase();
      const reviewNote = req.body.review_note;
      const now = new Date().toISOString();
      const updatePayload: any = {
        status: decision === 'APPROVED' ? 'approved' : 'rejected',
        review_note: reviewNote || null,
        reviewed_by: session.sub,
        reviewed_at: now,
        updated_at: now,
      };

      let provisioning: any = null;
      if (decision === 'APPROVED') {
        updatePayload.approved_at = now;
        await syncUserIdentityClassification(existing.user_id, {
          role: existing.requested_role,
          registryType: existing.requested_registry_type || mapServiceRoleToRegistryType(existing.requested_role),
          metadata: {
            service_access_approved_at: now,
            service_access_approved_role: existing.requested_role,
          },
        });
        provisioning = await ServiceActorOps.provisionApprovedActorAccess(existing.user_id, existing.requested_role, {
          business_name: existing.business_name,
          phone: existing.phone,
          metadata: existing.metadata || {},
        });

        await Messaging.dispatchServiceActivity(existing.user_id, 'SERVICE_ACCESS_APPROVED', {
          actorLabel: existing.requested_role === 'AGENT' ? 'Agent desk' : 'Merchant desk',
        }, 'info');
      }

      const { data, error } = await sb.from('service_access_requests').update(updatePayload).eq('id', req.params.id).select('*').single();
      if (error) return res.status(500).json({ success: false, error: error.message });

      await Audit.log('ADMIN', session.sub, 'SERVICE_ACCESS_REQUEST_REVIEWED', {
        requestId: req.params.id,
        decision,
        targetUserId: existing.user_id,
        requestedRole: existing.requested_role,
      });

      res.json({ success: true, data: { ...data, provisioning } });
    } catch (e: any) {
      console.error('[Admin] Service Access Review Error:', e);
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/service-links', authenticate, adminOnly, async (req, res) => {
    try {
      const actorRole = typeof req.query.actorRole === 'string' ? req.query.actorRole.toUpperCase() : undefined;
      const actorUserId = typeof req.query.actorUserId === 'string' ? req.query.actorUserId : undefined;
      const result = await LogicCore.getServiceLinkedCustomers(actorUserId, actorRole);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/service-commissions', authenticate, adminOnly, async (req, res) => {
    try {
      const actorRole = typeof req.query.actorRole === 'string' ? req.query.actorRole.toUpperCase() : undefined;
      const actorUserId = typeof req.query.actorUserId === 'string' ? req.query.actorUserId : undefined;
      const result = await LogicCore.getServiceCommissions(actorUserId, actorRole);
      res.json({ success: true, data: result });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/b2b/risk-dashboard', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...B2B_READ_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const data = await b2bRiskDashboardService.summary(req.query as Record<string, unknown>);
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(e.message === 'DB_OFFLINE' ? 503 : 500).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/b2b/merchant-settlement-reports', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...B2B_READ_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const data = await merchantSettlementReportsService.list(req.query as Record<string, unknown>);
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(e.message === 'DB_OFFLINE' ? 503 : 500).json({ success: false, error: e.message });
    }
  });

  v1.post('/admin/b2b/merchant-settlement-reports/generate', authenticate, validate(MerchantSettlementReportGenerateSchema), async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...B2B_OPERATE_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const data = await merchantSettlementReportsService.generate({ ...req.body, actorId: session.sub });
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(e.message === 'DB_OFFLINE' ? 503 : 400).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/b2b/agent-float-controls', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...B2B_READ_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const data = await agentFloatControlService.list(req.query as Record<string, unknown>);
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(e.message === 'DB_OFFLINE' ? 503 : 500).json({ success: false, error: e.message });
    }
  });

  v1.post('/admin/b2b/agent-float-controls', authenticate, validate(AgentFloatControlSchema), async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...B2B_OPERATE_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const data = await agentFloatControlService.upsert({ ...req.body, actorId: session.sub });
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(e.message === 'DB_OFFLINE' ? 503 : 400).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/b2b/agent-float-dashboard', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...B2B_READ_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const data = await agentFloatControlService.dashboard(req.query as Record<string, unknown>);
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(e.message === 'DB_OFFLINE' ? 503 : 500).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/b2b/commission-disputes', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...B2B_READ_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const data = await commissionDisputeService.list(req.query as Record<string, unknown>);
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(e.message === 'DB_OFFLINE' ? 503 : 500).json({ success: false, error: e.message });
    }
  });

  v1.post('/admin/b2b/commission-disputes', authenticate, validate(CommissionDisputeOpenSchema), async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...B2B_OPERATE_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const data = await commissionDisputeService.open({ ...req.body, actorId: session.sub });
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(e.message === 'DB_OFFLINE' ? 503 : 400).json({ success: false, error: e.message });
    }
  });

  v1.patch('/admin/b2b/commission-disputes/:id', authenticate, validate(CommissionDisputeResolveSchema), async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...B2B_OPERATE_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const disputeId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
      const data = await commissionDisputeService.resolve(disputeId, { ...req.body, actorId: session.sub });
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(e.message === 'DB_OFFLINE' ? 503 : 400).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/b2b/organization-limits', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...B2B_READ_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const data = await organizationLimitsService.list(req.query as Record<string, unknown>);
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(e.message === 'DB_OFFLINE' ? 503 : 500).json({ success: false, error: e.message });
    }
  });

  v1.post('/admin/b2b/organization-limits', authenticate, validate(OrganizationLimitSchema), async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...B2B_OPERATE_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const data = await organizationLimitsService.upsert(req.body, session.sub);
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(e.message === 'DB_OFFLINE' ? 503 : 400).json({ success: false, error: e.message });
    }
  });

  v1.patch('/admin/users/:id/status', authenticate, validate(AccountStatusUpdateWithReasonSchema), async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...USER_ADMIN_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      await LogicCore.updateAccountStatus(req.params.id as string, req.body.status, session.sub, req.body.reason);
      res.json({ success: true });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.patch('/admin/users/:id/profile', authenticate, validate(UserProfileUpdateSchema), async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...USER_ADMIN_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const result = await LogicCore.adminUpdateUserProfile(req.params.id as string, req.body, session.sub);
      if (result.error) return res.status(400).json({ success: false, error: result.error });
      res.json({ success: true });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/users/incomplete-registrations', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...USER_SEARCH_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const query = IncompleteRegistrationQuerySchema.parse(req.query);
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });

      const statuses = query.status
        ? [query.status.trim().toLowerCase()]
        : ['pending_confirmation', 'unconfirmed', 'inactive'];
      const limit = query.limit || 100;
      const nowMs = Date.now();
      const selectColumns = [
        'id',
        'full_name',
        'customer_id',
        'email',
        'phone',
        'registry_type',
        'role',
        'account_status',
        'created_at',
        'activation_expires_at',
        'activation_method',
        'auth_confirmed_at',
      ].join(', ');

      const fetchTable = async (table: 'users' | 'staff') => {
        let dbQuery = sb
          .from(table)
          .select(selectColumns)
          .in('account_status', statuses)
          .is('auth_confirmed_at', null)
          .order('activation_expires_at', { ascending: true, nullsFirst: false })
          .limit(limit);

        if (!query.includeExpired) {
          dbQuery = dbQuery.or(`activation_expires_at.is.null,activation_expires_at.gte.${new Date(nowMs).toISOString()}`);
        }

        const { data, error } = await dbQuery;
        if (error) throw error;
        return (data || []).map((row: any) => {
          const expiresAtMs = row.activation_expires_at ? new Date(row.activation_expires_at).getTime() : null;
          const hoursRemaining = expiresAtMs ? Math.max(0, Math.ceil((expiresAtMs - nowMs) / (60 * 60 * 1000))) : null;
          return {
            id: row.id,
            sourceTable: table,
            registryType: row.registry_type || (table === 'staff' ? 'STAFF' : 'CONSUMER'),
            role: row.role || (table === 'staff' ? 'STAFF' : 'USER'),
            status: row.account_status,
            fullName: row.full_name,
            customerId: row.customer_id,
            email: row.email,
            phone: row.phone,
            activationMethod: row.activation_method,
            createdAt: row.created_at,
            activationExpiresAt: row.activation_expires_at,
            hoursRemaining,
            expired: expiresAtMs ? expiresAtMs < nowMs : false,
          };
        });
      };

      const rows = [
        ...(await fetchTable('users')),
        ...(await fetchTable('staff')),
      ]
        .filter((row) => !query.registryType || row.registryType.toUpperCase() === query.registryType!.toUpperCase())
        .sort((a, b) => {
          const aTime = a.activationExpiresAt ? new Date(a.activationExpiresAt).getTime() : Number.MAX_SAFE_INTEGER;
          const bTime = b.activationExpiresAt ? new Date(b.activationExpiresAt).getTime() : Number.MAX_SAFE_INTEGER;
          return aTime - bTime;
        })
        .slice(0, limit);

      await Audit.log('ADMIN', session.sub, 'INCOMPLETE_REGISTRATIONS_VIEWED', {
        count: rows.length,
        registryType: query.registryType || 'ALL',
        includeExpired: query.includeExpired === true,
      });

      res.json({
        success: true,
        data: {
          windowHours: 24,
          count: rows.length,
          rows,
        },
      });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/users/search', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...USER_SEARCH_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const query = AdminUserSearchSchema.parse(req.query);
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });

      let dbQuery = sb
        .from('users')
        .select('id, full_name, avatar_url, customer_id, phone, email, registry_type, role, account_status, status_reason, status_reason_code, status_changed_at, status_changed_by, kyc_status, created_at')
        .order('created_at', { ascending: false })
        .limit(query.limit || 25);

      if (query.query) {
        const term = query.query.trim();
        dbQuery = dbQuery.or(
          [
            `full_name.ilike.%${term}%`,
            `customer_id.ilike.%${term}%`,
            `phone.ilike.%${term}%`,
            `email.ilike.%${term}%`,
          ].join(','),
        );
      }
      if (query.role) dbQuery = dbQuery.eq('role', query.role.toUpperCase());
      if (query.registryType) dbQuery = dbQuery.eq('registry_type', query.registryType.toUpperCase());
      if (query.accountStatus) dbQuery = dbQuery.eq('account_status', query.accountStatus.toLowerCase());
      if (query.kycStatus) dbQuery = dbQuery.eq('kyc_status', query.kycStatus.toLowerCase());

      const { data, error } = await dbQuery;
      if (error) return res.status(500).json({ success: false, error: error.message });
      const normalized = (data || []).map((row: any) => {
        const metadata = row.metadata && typeof row.metadata === 'object' ? row.metadata : {};
        const eventType = String(row.event_type || metadata.eventType || 'infrastructure').toLowerCase();
        const status = String(metadata.status || metadata.outcome || 'SUCCESS').toUpperCase();
        const riskSensitivity = String(metadata.riskSensitivity || metadata.risk_sensitivity || metadata.severity || 'LOW').toUpperCase();
        return {
          id: row.id,
          timestamp: row.timestamp,
          eventType,
          action: row.action,
          actorId: row.actor_id || metadata.actorId || metadata.actor_id || 'SYSTEM',
          actorRole: metadata.actorRole || metadata.actor_role || metadata.role || 'SYSTEM',
          targetId: row.transaction_id || metadata.targetId || metadata.target_id || metadata.resourceId || null,
          status: ['SUCCESS', 'FAILED', 'BLOCKED'].includes(status) ? status : status === 'ERROR' ? 'FAILED' : 'SUCCESS',
          riskSensitivity: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(riskSensitivity) ? riskSensitivity : 'LOW',
          traceId: metadata.traceId || metadata.trace_id || null,
          hash: row.hash,
          signature: row.signature,
          metadata,
        };
      });
      res.json({ success: true, data: normalized });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/audit-trail', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...RISK_REVIEW_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const query = AdminAuditTrailQuerySchema.parse(req.query);
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });

      let dbQuery = sb
        .from('audit_trail')
        .select('id, timestamp, event_type, actor_id, transaction_id, action, metadata, hash, signature')
        .order('timestamp', { ascending: false })
        .limit(query.limit || 100);

      if (query.eventType) dbQuery = dbQuery.eq('event_type', query.eventType.toUpperCase());
      if (query.actorId) dbQuery = dbQuery.eq('actor_id', query.actorId);
      if (query.transactionId) dbQuery = dbQuery.eq('transaction_id', query.transactionId);
      if (query.action) dbQuery = dbQuery.ilike('action', `%${query.action}%`);

      const { data, error } = await dbQuery;
      if (error) return res.status(500).json({ success: false, error: error.message });
      res.json({ success: true, data: data || [] });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.post('/admin/audit-exports', authenticate, requireIdempotencyKey, async (req,res)=>{
    const session=(req as any).session;
    if(!sessionHasAnyRole(session,[...RISK_REVIEW_ROLES])) return res.status(403).json({success:false,error:'ACCESS_DENIED'});
    try{
      const session=(req as any).session;const input=AuditExportRequestSchema.parse(req.body);const sb=getAdminSupabase();if(!sb)return res.status(503).json({success:false,error:'DB_OFFLINE'});
      const {data,error}=await sb.rpc('request_audit_export_v1',{p_actor_id:session.sub,p_period_start:input.periodStart,p_period_end:input.periodEnd,p_event_types:input.eventTypes,p_action_prefix:input.actionPrefix||null,p_format:input.format,p_purpose:input.purpose,p_idempotency_key:String(resolveIdempotencyHeader(req))});if(error)throw new Error(error.message);
      const requestId=data?.request_id;if(!data?.replayed)await Audit.log('SECURITY',session.sub,'AUDIT_EXPORT_REQUESTED',{requestId,periodStart:input.periodStart,periodEnd:input.periodEnd,format:input.format,purpose:input.purpose},requestId);
      const {data:reviewers}=await sb.from('staff').select('id,language').eq('account_status','ACTIVE').in('role',['SUPER_ADMIN','ADMIN','AUDIT','RISK_OFFICER']).neq('id',session.sub);
      for(const reviewer of reviewers||[]){const sw=reviewer.language==='sw';try{await Messaging.dispatch(reviewer.id,'security',sw?'Ombi la Hamisho la Ukaguzi':'Audit export approval required',sw?'Ombi la kutoa kumbukumbu za ukaguzi linasubiri idhini yako huru.':'An audit evidence export is awaiting your independent approval.',{push:true,sms:true,email:true,mandatory:true,systemCustomBypass:true,eventCode:'AUDIT_EXPORT_REQUESTED',idempotencyKey:`audit-export:${requestId}:requested:${reviewer.id}`});}catch(e:any){console.warn(`[AuditExport] ${requestId} committed; reviewer notification deferred: ${e.message}`);}}
      res.json({success:true,data:{requestId,status:'PENDING',replayed:Boolean(data?.replayed)}});
    }catch(e:any){res.status(e instanceof z.ZodError?400:String(e.message).includes('ACCESS_DENIED')?403:409).json({success:false,error:e.message});}
  });

  v1.post('/admin/audit-exports/:id/respond',authenticate,async(req,res)=>{
    const session=(req as any).session;if(!sessionHasAnyRole(session,[...RISK_REVIEW_ROLES]))return res.status(403).json({success:false,error:'ACCESS_DENIED'});
     try{const input=AuditExportReviewSchema.parse(req.body);const sb=getAdminSupabase();if(!sb)return res.status(503).json({success:false,error:'DB_OFFLINE'});const {data:request}=await sb.from('audit_export_requests').select('requested_by').eq('id',req.params.id).single();const {data,error}=await sb.rpc('respond_audit_export_v1',{p_reviewer_id:session.sub,p_request_id:req.params.id,p_decision:input.decision,p_reason:input.reason});if(error)throw new Error(error.message);await Audit.log('SECURITY',session.sub,'AUDIT_EXPORT_REVIEWED',{requestId:req.params.id,decision:input.decision,packageId:data?.package_id,contentHash:data?.content_hash},String(req.params.id));
      if(request?.requested_by){try{await Messaging.dispatch(request.requested_by,'security','Audit export review completed',`Your audit export request is ${String(data?.status||input.decision).toLowerCase()}.`,{push:true,sms:true,email:true,mandatory:true,systemCustomBypass:true,eventCode:'AUDIT_EXPORT_REVIEWED',idempotencyKey:`audit-export:${req.params.id}:reviewed:${request.requested_by}`});}catch(e:any){console.warn(`[AuditExport] ${req.params.id} reviewed; notification deferred: ${e.message}`);}}
      res.json({success:true,data});}catch(e:any){res.status(e instanceof z.ZodError?400:String(e.message).includes('MAKER_CHECKER')||String(e.message).includes('ACCESS_DENIED')?403:409).json({success:false,error:e.message});}
  });

  v1.post('/admin/audit-export-packages/:id/download',authenticate,requireIdempotencyKey,async(req,res)=>{
    const session=(req as any).session;if(!sessionHasAnyRole(session,[...RISK_REVIEW_ROLES]))return res.status(403).json({success:false,error:'ACCESS_DENIED'});
    try{const sb=getAdminSupabase();if(!sb)return res.status(503).json({success:false,error:'DB_OFFLINE'});const {data:claim,error}=await sb.rpc('claim_audit_export_download_v1',{p_actor_id:session.sub,p_package_id:req.params.id,p_idempotency_key:String(resolveIdempotencyHeader(req))});if(error)throw new Error(error.message);const {data:entries,error:entryError}=await sb.from('audit_export_entries').select('*').eq('package_id',req.params.id).order('sequence_number',{ascending:true});if(entryError)throw new Error(entryError.message);
      if(!claim.replayed)await Audit.log('SECURITY',session.sub,'AUDIT_EXPORT_DOWNLOADED',{packageId:req.params.id,contentHash:claim.content_hash,downloadNumber:claim.download_number},String(req.params.id));
      if(claim.format==='CSV'){
        const csvCell=(value:any)=>{let text=typeof value==='object'&&value!==null?JSON.stringify(value):String(value??'');if(/^[=+\-@]/.test(text))text=`'${text}`;return `"${text.replace(/"/g,'""')}"`;};
        const columns=['sequence_number','audit_id','timestamp','event_type','actor_id','transaction_id','action','metadata','hash','signature'];
        const csv=[columns.join(','),...(entries||[]).map((row:any)=>columns.map(column=>csvCell(row[column])).join(','))].join('\r\n');
        res.setHeader('Content-Type','text/csv; charset=utf-8');res.setHeader('Content-Disposition',`attachment; filename="orbi-audit-${req.params.id}.csv"`);res.setHeader('X-ORBI-Content-Hash',claim.content_hash);return res.send(csv);
      }
      res.json({success:true,data:{package:claim,entries:entries||[]}});}catch(e:any){const m=String(e.message);res.status(m.includes('DENIED')?403:m.includes('NOT_FOUND')?404:m.includes('EXPIRED')||m.includes('LIMIT')?410:409).json({success:false,error:m});}
  });

  v1.get('/admin/financial-exceptions',authenticate,async(req,res)=>{const session=(req as any).session;if(!sessionHasAnyRole(session,[...RISK_REVIEW_ROLES]))return res.status(403).json({success:false,error:'ACCESS_DENIED'});const sb=getAdminSupabase();if(!sb)return res.status(503).json({success:false,error:'DB_OFFLINE'});const status=String(req.query.status||'').toUpperCase();let query=sb.from('financial_exception_cases').select('*').order('sla_due_at',{ascending:true}).limit(200);if(status)query=query.eq('status',status);const{data,error}=await query;if(error)return res.status(500).json({success:false,error:error.message});res.json({success:true,data:data||[]});});
  v1.post('/admin/financial-exceptions/:id/assign',authenticate,async(req,res)=>{const session=(req as any).session;if(!sessionHasAnyRole(session,[...RISK_REVIEW_ROLES]))return res.status(403).json({success:false,error:'ACCESS_DENIED'});try{const input=FinancialExceptionAssignSchema.parse(req.body),sb=getAdminSupabase();if(!sb)return res.status(503).json({success:false,error:'DB_OFFLINE'});const{data,error}=await sb.rpc('assign_financial_exception_v1',{p_actor_id:session.sub,p_case_id:req.params.id,p_assignee_id:input.assigneeId});if(error)throw new Error(error.message);await Audit.log('SECURITY',session.sub,'FINANCIAL_EXCEPTION_ASSIGNED',{caseId:req.params.id,assigneeId:input.assigneeId},String(req.params.id));try{await Messaging.dispatch(input.assigneeId,'security','Financial exception assigned',`Financial exception ${req.params.id} requires your investigation.`,{push:true,sms:true,email:true,mandatory:true,systemCustomBypass:true,eventCode:'FINANCIAL_EXCEPTION_ASSIGNED',idempotencyKey:`financial-exception:${req.params.id}:assigned:${input.assigneeId}`});}catch(e:any){console.warn(`[FinancialException] assignment notification deferred: ${e.message}`);}res.json({success:true,data});}catch(e:any){res.status(e instanceof z.ZodError?400:String(e.message).includes('DENIED')?403:409).json({success:false,error:e.message});}});
  v1.post('/admin/financial-exceptions/:id/resolution-requests',authenticate,async(req,res)=>{const session=(req as any).session;if(!sessionHasAnyRole(session,[...RISK_REVIEW_ROLES]))return res.status(403).json({success:false,error:'ACCESS_DENIED'});try{const input=FinancialExceptionResolutionSchema.parse(req.body),sb=getAdminSupabase();if(!sb)return res.status(503).json({success:false,error:'DB_OFFLINE'});const{data,error}=await sb.rpc('request_financial_exception_resolution_v1',{p_actor_id:session.sub,p_case_id:req.params.id,p_disposition:input.disposition,p_summary:input.summary,p_evidence:input.evidence});if(error)throw new Error(error.message);await Audit.log('SECURITY',session.sub,'FINANCIAL_EXCEPTION_RESOLUTION_REQUESTED',{caseId:req.params.id,requestId:data,disposition:input.disposition},String(req.params.id));const{data:reviewers}=await sb.from('staff').select('id').eq('account_status','ACTIVE').in('role',['SUPER_ADMIN','ADMIN','AUDIT','RISK_OFFICER']).neq('id',session.sub);for(const reviewer of reviewers||[])try{await Messaging.dispatch(reviewer.id,'security','Exception resolution approval required',`Resolution request ${data} requires independent review.`,{push:true,sms:true,email:true,mandatory:true,systemCustomBypass:true,eventCode:'FINANCIAL_EXCEPTION_RESOLUTION_REQUESTED',idempotencyKey:`financial-exception-resolution:${data}:requested:${reviewer.id}`});}catch(e:any){console.warn(`[FinancialException] review notification deferred: ${e.message}`);}res.json({success:true,data:{requestId:data,status:'PENDING'}});}catch(e:any){res.status(e instanceof z.ZodError?400:String(e.message).includes('DENIED')?403:409).json({success:false,error:e.message});}});
  v1.post('/admin/financial-exception-resolutions/:id/respond',authenticate,async(req,res)=>{const session=(req as any).session;if(!sessionHasAnyRole(session,[...RISK_REVIEW_ROLES]))return res.status(403).json({success:false,error:'ACCESS_DENIED'});try{const input=FinancialExceptionReviewSchema.parse(req.body),sb=getAdminSupabase();if(!sb)return res.status(503).json({success:false,error:'DB_OFFLINE'});const{data:request}=await sb.from('financial_exception_resolution_requests').select('requested_by').eq('id',req.params.id).single();const{data,error}=await sb.rpc('respond_financial_exception_resolution_v1',{p_reviewer_id:session.sub,p_request_id:req.params.id,p_decision:input.decision,p_reason:input.reason});if(error)throw new Error(error.message);await Audit.log('SECURITY',session.sub,'FINANCIAL_EXCEPTION_RESOLUTION_REVIEWED',{requestId:req.params.id,caseId:data?.case_id,status:data?.status},String(data?.case_id||req.params.id));if(request?.requested_by)try{await Messaging.dispatch(request.requested_by,'security','Exception resolution reviewed',`Your resolution request is ${String(data?.status||input.decision).toLowerCase()}.`,{push:true,sms:true,email:true,mandatory:true,systemCustomBypass:true,eventCode:'FINANCIAL_EXCEPTION_RESOLUTION_REVIEWED',idempotencyKey:`financial-exception-resolution:${req.params.id}:reviewed:${request.requested_by}`});}catch(e:any){console.warn(`[FinancialException] resolution notification deferred: ${e.message}`);}res.json({success:true,data});}catch(e:any){res.status(e instanceof z.ZodError?400:String(e.message).includes('MAKER_CHECKER')?403:409).json({success:false,error:e.message});}});

  v1.get('/admin/risk/alerts', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...RISK_REVIEW_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const query = AdminRiskAlertsQuerySchema.parse(req.query);
      const [amlAlerts, anomalyReport] = await Promise.all([
        LogicCore.getPendingAMLAlerts(),
        LogicCore.getAnomalyReport(query.days || 7),
      ]);

      const anomalyDetails = Array.isArray(anomalyReport?.details) ? anomalyReport.details : [];
      const records = [
        ...(Array.isArray(amlAlerts) ? amlAlerts : []).map((alert: any) => ({
          id: alert.id,
          source: 'AML',
          signal: 'AML_TRANSACTION_MONITORING',
          severity: Number(alert.risk_score || 0) >= 80 ? 'critical' : 'high',
          subject: alert.transaction_id || alert.user_id,
          state: alert.status,
          risk_score: alert.risk_score,
          reason: alert.reason,
          created_at: alert.created_at,
        })),
        ...anomalyDetails.map((alert: any) => ({
          id: alert.id,
          source: 'PROVIDER_ANOMALY',
          signal: Array.isArray(alert.detection_flags) ? alert.detection_flags.join(', ') : 'PROVIDER_ANOMALY_DETECTED',
          severity: Number(alert.risk_score || 0) >= 80 ? 'critical' : 'high',
          subject: alert.transaction_id || alert.wallet_id || alert.user_id,
          state: alert.status,
          risk_score: alert.risk_score,
          reason: Array.isArray(alert.detection_flags) ? alert.detection_flags.join(' | ') : '',
          created_at: alert.created_at,
        })),
      ];

      const filtered = query.status
        ? records.filter((record) => String(record.state || '').toUpperCase() === query.status!.toUpperCase())
        : records;

      res.json({ success: true, data: filtered });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/compliance/node-zones/risk-density', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...RISK_REVIEW_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const query = AdminComplianceNodeRiskQuerySchema.parse(req.query);
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });

      const windowHours = query.windowHours || 24;
      const bucketHours = query.bucketHours || 2;
      const zones = complianceNodeZones().filter((zone) => query.includeInactive || zone.active);
      const timelines = createComplianceTimeline(zones, windowHours, bucketHours);
      const since = new Date(Date.now() - windowHours * 60 * 60 * 1000).toISOString();
      const primaryBuckets = timelines.get('ORBI-PRIMARY-CORE');
      const gatewayBuckets = timelines.get('ORBI-GATEWAY-EDGE');
      const ledgerBuckets = timelines.get('ORBI-LEDGER-AUTHORITY');
      const adminBuckets = timelines.get('ORBI-ADMIN-OPS');
      const providerBuckets = timelines.get('ORBI-PROVIDER-RAILS');

      const [transactionsResult, fraudChecksResult, auditResult, amlAlerts, anomalyReport] = await Promise.all([
        sb
          .from('transactions')
          .select('id, amount, currency, status, type, created_at, metadata')
          .gte('created_at', since)
          .order('created_at', { ascending: false })
          .limit(5000),
        sb
          .from('fraud_checks')
          .select('id, user_id, risk_score, decision, flags, payload, created_at')
          .gte('created_at', since)
          .order('created_at', { ascending: false })
          .limit(5000),
        sb
          .from('audit_trail')
          .select('id, timestamp, event_type, action, metadata')
          .gte('timestamp', since)
          .order('timestamp', { ascending: false })
          .limit(5000),
        LogicCore.getPendingAMLAlerts().catch(() => []),
        LogicCore.getAnomalyReport(Math.max(1, Math.ceil(windowHours / 24))).catch(() => ({ details: [] })),
      ]);

      if (transactionsResult.error) return res.status(500).json({ success: false, error: transactionsResult.error.message });
      if (fraudChecksResult.error) return res.status(500).json({ success: false, error: fraudChecksResult.error.message });
      if (auditResult.error) return res.status(500).json({ success: false, error: auditResult.error.message });

      for (const tx of Array.isArray(transactionsResult.data) ? transactionsResult.data : []) {
        const row = objectValue(tx);
        const metadata = objectValue(row.metadata);
        const status = firstString(row.status)?.toUpperCase() || '';
        const type = firstString(row.type)?.toUpperCase() || '';
        const coreBucket = bucketForTime(primaryBuckets, row.created_at);

        if (coreBucket) coreBucket.counts.transactions += 1;
        if (['FAILED', 'ERROR', 'REJECTED', 'DECLINED', 'CANCELLED'].includes(status)) {
          addComplianceDriver(coreBucket, 'FAILED_TRANSACTION', 3, 'failedTransactions');
        }
        if (['HELD', 'HOLD', 'REVIEW', 'PENDING_REVIEW', 'HELD_FOR_REVIEW', 'LOCKED'].includes(status)) {
          addComplianceDriver(coreBucket, 'HELD_FOR_REVIEW', 8, 'heldTransactions');
        }
        if (jsonIncludes(metadata, 'IMPOSSIBLE_GEO_TRAVEL')) {
          addComplianceDriver(coreBucket, 'IMPOSSIBLE_GEO_TRAVEL', 20, 'impossibleTravel');
          addComplianceDriver(bucketForTime(adminBuckets, row.created_at), 'IMPOSSIBLE_GEO_TRAVEL_REVIEW', 12, 'impossibleTravel');
        }
        if (jsonIncludes(metadata, 'TRANSACTION_GEO_REQUIRED') || jsonIncludes(metadata, 'GEO_COMPLIANCE_REQUIRED')) {
          addComplianceDriver(coreBucket, 'GEO_COMPLIANCE_BLOCK', 10, 'geoComplianceBlocks');
          addComplianceDriver(bucketForTime(adminBuckets, row.created_at), 'GEO_COMPLIANCE_REVIEW', 8, 'geoComplianceBlocks');
        }
        if (['EXTERNAL_FUNDS', 'PROVIDER', 'GATEWAY', 'COLLECTION', 'DISBURSEMENT', 'PAYOUT'].some((marker) => type.includes(marker) || jsonIncludes(metadata, marker))) {
          addComplianceDriver(bucketForTime(gatewayBuckets, row.created_at), 'EXTERNAL_RAIL_TRAFFIC', 2);
          addComplianceDriver(bucketForTime(providerBuckets, row.created_at), 'PROVIDER_RAIL_TRAFFIC', 2);
        }
      }

      for (const check of Array.isArray(fraudChecksResult.data) ? fraudChecksResult.data : []) {
        const row = objectValue(check);
        const riskScore = numberValue(row.risk_score) || 0;
        const bucket = bucketForTime(primaryBuckets, row.created_at);
        if (riskScore >= 80) {
          addComplianceDriver(bucket, 'CRITICAL_RISK_SIGNAL', 25, 'criticalRiskSignals');
          addComplianceDriver(bucketForTime(adminBuckets, row.created_at), 'CRITICAL_RISK_REVIEW', 14, 'criticalRiskSignals');
        } else if (riskScore >= 60) {
          addComplianceDriver(bucket, 'HIGH_RISK_SIGNAL', 12, 'highRiskSignals');
        }
        if (jsonIncludes(row.flags, 'PROVIDER') || jsonIncludes(row.payload, 'PROVIDER')) {
          addComplianceDriver(bucketForTime(providerBuckets, row.created_at), 'PROVIDER_RISK_SIGNAL', 12, 'providerAnomalies');
        }
      }

      for (const event of Array.isArray(auditResult.data) ? auditResult.data : []) {
        const row = objectValue(event);
        const action = firstString(row.action, row.event_type)?.toUpperCase() || '';
        const eventBucket = bucketForTime(adminBuckets, row.timestamp);
        const ledgerBucket = bucketForTime(ledgerBuckets, row.timestamp);

        if (
          action.includes('CONFIG') ||
          action.includes('KYC') ||
          action.includes('DOCUMENT') ||
          action.includes('STAFF') ||
          action.includes('SUPPORT') ||
          action.includes('DEVICE') ||
          action.includes('REVERSE') ||
          action.includes('APPROVE') ||
          action.includes('AUDIT')
        ) {
          addComplianceDriver(eventBucket, 'SENSITIVE_ADMIN_ACTIVITY', 4, 'auditSensitiveActions');
        }
        if (action.includes('LEDGER') || action.includes('RECONCILIATION') || action.includes('WALLET')) {
          addComplianceDriver(ledgerBucket, 'LEDGER_GOVERNANCE_ACTIVITY', 6);
        }
        if (action.includes('WEBHOOK') || action.includes('PROVIDER') || action.includes('GATEWAY')) {
          addComplianceDriver(bucketForTime(gatewayBuckets, row.timestamp), 'GATEWAY_OR_PROVIDER_ACTIVITY', 6);
          addComplianceDriver(bucketForTime(providerBuckets, row.timestamp), 'PROVIDER_ACTIVITY', 6);
        }
        if (action.includes('WAF') || action.includes('ATTACK') || action.includes('BRUTE') || action.includes('RATE_LIMIT')) {
          addComplianceDriver(eventBucket, 'SECURITY_CONTROL_EVENT', 18);
        }
      }

      const nowBucketTime = new Date().toISOString();
      for (const alert of Array.isArray(amlAlerts) ? amlAlerts : []) {
        const row = objectValue(alert);
        const bucket = bucketForTime(adminBuckets, row.created_at || nowBucketTime);
        const riskScore = numberValue(row.risk_score) || 0;
        addComplianceDriver(bucket, riskScore >= 80 ? 'CRITICAL_AML_ALERT' : 'HIGH_AML_ALERT', riskScore >= 80 ? 25 : 12, 'amlAlerts');
      }

      const anomalyDetails = Array.isArray(anomalyReport?.details) ? anomalyReport.details : [];
      for (const alert of anomalyDetails) {
        const row = objectValue(alert);
        const bucket = bucketForTime(providerBuckets, row.created_at || nowBucketTime);
        const riskScore = numberValue(row.risk_score) || 0;
        addComplianceDriver(bucket, riskScore >= 80 ? 'CRITICAL_PROVIDER_ANOMALY' : 'PROVIDER_ANOMALY', riskScore >= 80 ? 24 : 15, 'providerAnomalies');
        addComplianceDriver(bucketForTime(gatewayBuckets, row.created_at || nowBucketTime), 'GATEWAY_PROVIDER_ANOMALY', riskScore >= 80 ? 20 : 10);
      }

      finalizeComplianceTimeline(zones, timelines);

      const zoneSummaries = zones.map((zone) => {
        const buckets = timelines.get(zone.id) || [];
        const current = buckets[buckets.length - 1] || null;
        const maxRiskDensity = buckets.reduce((max, bucket) => Math.max(max, bucket.riskDensity), 0);
        const criticalBucketCount = buckets.filter((bucket) => bucket.status === 'CRITICAL_OVERLOAD').length;
        const topDrivers = buckets
          .flatMap((bucket) => bucket.drivers)
          .reduce((map, driver) => {
            const existing = map.get(driver.code) || { code: driver.code, count: 0, score: 0 };
            existing.count += driver.count;
            existing.score += driver.score;
            map.set(driver.code, existing);
            return map;
          }, new Map<string, { code: string; count: number; score: number }>());

        return {
          ...zone,
          currentRiskDensity: current?.riskDensity || zone.baseRisk,
          currentStatus: current?.status || complianceNodeStatus(zone.baseRisk),
          maxRiskDensity,
          criticalBucketCount,
          topDrivers: Array.from(topDrivers.values()).sort((a, b) => b.score - a.score).slice(0, 6),
        };
      });

      await Audit.log('ADMIN', session.sub, 'COMPLIANCE_NODE_RISK_DENSITY_VIEWED', {
        windowHours,
        bucketHours,
        zoneCount: zones.length,
      });

      res.json({
        success: true,
        data: {
          generatedAt: new Date().toISOString(),
          windowHours,
          bucketHours,
          bucketCount: Math.ceil(windowHours / bucketHours),
          model: {
            description: 'Compliance Node Zones are logical ORBI infrastructure and control-plane boundaries mapped to real deployment domains and operational responsibilities.',
            thresholds: {
              healthy: '0-34',
              watch: '35-59',
              degraded: '60-74',
              criticalOverload: '75-100',
            },
            privacy: 'This endpoint returns infrastructure/control-plane risk density only. It does not expose raw user GPS coordinates.',
          },
          zones: zoneSummaries,
          timeline: Object.fromEntries(Array.from(timelines.entries())),
        },
      });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/risk/geo-heatmap', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...RISK_REVIEW_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const query = AdminRiskGeoHeatmapQuerySchema.parse(req.query);
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });

      const days = query.days || 7;
      const limit = query.limit || 2000;
      const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
      const countryFilter = query.countryCode?.trim().toUpperCase();
      const currencyFilter = query.currency?.trim().toUpperCase();
      const minRiskScore = query.minRiskScore ?? 0;

      let txQuery = sb
        .from('transactions')
        .select('id, user_id, amount, currency, status, type, created_at, metadata')
        .gte('created_at', since)
        .order('created_at', { ascending: false })
        .limit(limit);

      if (currencyFilter) txQuery = txQuery.eq('currency', currencyFilter);

      const [transactionsResult, fraudChecksResult] = await Promise.all([
        txQuery,
        sb
          .from('fraud_checks')
          .select('id, user_id, risk_score, decision, flags, payload, created_at')
          .gte('created_at', since)
          .order('created_at', { ascending: false })
          .limit(limit),
      ]);

      const transactionsError = transactionsResult.error;
      const fraudChecksError = fraudChecksResult.error;
      if (transactionsError) return res.status(500).json({ success: false, error: transactionsError.message });
      if (fraudChecksError) return res.status(500).json({ success: false, error: fraudChecksError.message });

      const buckets = new Map<string, RiskGeoBucket>();
      const transactions = Array.isArray(transactionsResult.data) ? transactionsResult.data : [];
      const fraudChecks = Array.isArray(fraudChecksResult.data) ? fraudChecksResult.data : [];

      for (const tx of transactions) {
        const row = objectValue(tx);
        const geo = extractGeoSignal(row, 'transaction_metadata');
        if (countryFilter && geo.countryCode !== countryFilter) continue;

        const bucket = getRiskGeoBucket(buckets, geo);
        bucket.transactionCount += 1;
        bucket.totalAmount += numberValue(row.amount) || 0;
        bucket.sources.add(geo.source);

        const currency = firstString(row.currency)?.toUpperCase();
        if (currency) bucket.currencies.add(currency);

        const metadata = objectValue(row.metadata);
        const riskScore = numberValue(metadata.riskScore ?? metadata.risk_score ?? objectValue(metadata.riskContext).riskScore);
        if (riskScore !== undefined && riskScore >= minRiskScore) {
          bucket.riskSignalCount += 1;
          bucket.riskScoreTotal += riskScore;
          bucket.riskScoreSamples += 1;
          bucket.maxRiskScore = Math.max(bucket.maxRiskScore, riskScore);
        }
      }

      for (const check of fraudChecks) {
        const row = objectValue(check);
        const riskScore = numberValue(row.risk_score) || 0;
        if (riskScore < minRiskScore) continue;

        const geo = extractGeoSignal(row, 'fraud_check_payload');
        if (countryFilter && geo.countryCode !== countryFilter) continue;

        const bucket = getRiskGeoBucket(buckets, geo);
        bucket.riskSignalCount += 1;
        bucket.riskScoreTotal += riskScore;
        bucket.riskScoreSamples += 1;
        bucket.maxRiskScore = Math.max(bucket.maxRiskScore, riskScore);
        bucket.sources.add(geo.source);

        const decision = firstString(row.decision)?.toUpperCase();
        if (decision && decision !== 'ALLOW' && decision !== 'APPROVED' && decision !== 'PASS') {
          bucket.alertCount += 1;
        }
      }

      const regions = Array.from(buckets.values()).map((bucket) => {
        const avgRiskScore = bucket.riskScoreSamples > 0 ? bucket.riskScoreTotal / bucket.riskScoreSamples : 0;
        const volumePressure = Math.min(100, bucket.transactionCount * 2);
        const signalPressure = Math.min(100, bucket.riskSignalCount * 15 + bucket.alertCount * 20);
        const intensity = Math.round(Math.min(100, (bucket.maxRiskScore * 0.5) + (avgRiskScore * 0.25) + (signalPressure * 0.2) + (volumePressure * 0.05)));

        return {
          key: bucket.key,
          countryCode: bucket.countryCode,
          region: bucket.region,
          regionCode: bucket.regionCode,
          city: bucket.city,
          transactionCount: bucket.transactionCount,
          riskSignalCount: bucket.riskSignalCount,
          alertCount: bucket.alertCount,
          avgRiskScore: Math.round(avgRiskScore * 100) / 100,
          maxRiskScore: bucket.maxRiskScore,
          totalAmount: Math.round(bucket.totalAmount * 100) / 100,
          currencies: Array.from(bucket.currencies).sort(),
          sources: Array.from(bucket.sources).sort(),
          intensity,
          severity: geoSeverity(intensity),
        };
      }).sort((a, b) => b.intensity - a.intensity || b.riskSignalCount - a.riskSignalCount || b.transactionCount - a.transactionCount);

      res.json({
        success: true,
        data: {
          windowDays: days,
          generatedAt: new Date().toISOString(),
          sourceTables: ['transactions.metadata', 'fraud_checks.payload'],
          privacy: {
            granularity: 'country_region',
            rawCoordinatesReturned: false,
            note: 'Heatmap data is aggregated for admin risk operations; raw client location should never be exposed in this response.',
          },
          summary: {
            totalTransactions: transactions.length,
            totalRiskSignals: fraudChecks.length,
            returnedRegions: regions.length,
            filters: {
              countryCode: countryFilter || null,
              currency: currencyFilter || null,
              minRiskScore,
              limit,
            },
          },
          regions,
        },
      });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/risk/live-geo', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...RISK_REVIEW_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const query = AdminRiskLiveGeoQuerySchema.parse(req.query);
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });

      const minutes = query.minutes || 60;
      const limit = query.limit || 250;
      const precision = query.precision || 'city';
      const since = new Date(Date.now() - minutes * 60 * 1000).toISOString();
      const countryFilter = query.countryCode?.trim().toUpperCase();
      const currencyFilter = query.currency?.trim().toUpperCase();
      const statusFilter = query.status?.trim().toUpperCase();
      const minRiskScore = query.minRiskScore ?? 0;

      let txQuery = sb
        .from('transactions')
        .select('id, user_id, amount, currency, status, type, created_at, metadata')
        .gte('created_at', since)
        .order('created_at', { ascending: false })
        .limit(limit);

      if (currencyFilter) txQuery = txQuery.eq('currency', currencyFilter);
      if (statusFilter) txQuery = txQuery.eq('status', statusFilter);

      const { data, error } = await txQuery;
      if (error) return res.status(500).json({ success: false, error: error.message });

      const points = (Array.isArray(data) ? data : []).flatMap((tx: any) => {
        const row = objectValue(tx);
        const geo = extractGeoSignal(row, 'transaction_metadata');
        const metadata = objectValue(row.metadata);
        const riskContext = objectValue(metadata.riskContext);
        const riskScore = numberValue(metadata.riskScore ?? metadata.risk_score ?? riskContext.riskScore) || 0;
        const hasCoordinates = geo.latitude !== null && geo.latitude !== undefined && geo.longitude !== null && geo.longitude !== undefined;

        if (!hasCoordinates) return [];
        if (geo.consented === false) return [];
        if (countryFilter && geo.countryCode !== countryFilter) return [];
        if (riskScore < minRiskScore) return [];

        return [{
          id: row.id,
          transactionId: row.id,
          userId: row.user_id || null,
          status: row.status || null,
          type: row.type || null,
          amount: numberValue(row.amount) || 0,
          currency: firstString(row.currency)?.toUpperCase() || null,
          countryCode: geo.countryCode,
          region: geo.region,
          regionCode: geo.regionCode || null,
          city: geo.city || null,
          latitude: roundCoordinate(geo.latitude, precision),
          longitude: roundCoordinate(geo.longitude, precision),
          precision,
          source: geo.source,
          consented: true,
          capturedAt: geo.capturedAt,
          createdAt: row.created_at || null,
          riskScore,
          severity: geoSeverity(riskScore),
        }];
      });

      await Audit.log('ADMIN', session.sub, 'RISK_LIVE_GEO_VIEWED', {
        minutes,
        limit,
        precision,
        returnedPoints: points.length,
        filters: {
          countryCode: countryFilter || null,
          currency: currencyFilter || null,
          status: statusFilter || null,
          minRiskScore,
        },
      });

      res.json({
        success: true,
        data: {
          windowMinutes: minutes,
          generatedAt: new Date().toISOString(),
          privacy: {
            granularity: precision,
            consentRequired: true,
            note: 'Live geo points are for restricted risk operations. Coordinates are rounded and every access is audited.',
          },
          summary: {
            returnedPoints: points.length,
            filters: {
              countryCode: countryFilter || null,
              currency: currencyFilter || null,
              status: statusFilter || null,
              minRiskScore,
              limit,
              precision,
            },
          },
          points,
        },
      });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/staff-messages', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...STAFF_MESSAGE_READ_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const { data, error } = await sb.from('staff_messages').select('*').order('created_at', { ascending: false }).limit(100);
      if (error) return res.status(500).json({ success: false, error: error.message });
      res.json({ success: true, data: data || [] });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/admin/staff-messages', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...STAFF_MESSAGE_SEND_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const payload = StaffDirectMessageSchema.parse(req.body);
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });

      const insertPayload = {
        sender_id: session.sub,
        sender_name: session.user?.full_name || session.user?.email || 'Institutional staff',
        recipient_id: payload.recipientId || null,
        target_role: payload.targetRole || null,
        content: payload.content,
        type: 'staff',
        created_at: new Date().toISOString(),
      };

      const { data, error } = await sb.from('staff_messages').insert(insertPayload).select('*').single();
      if (error) return res.status(500).json({ success: false, error: error.message });
      await Audit.log('ADMIN', session.sub, 'STAFF_DIRECT_MESSAGE_SENT', {
        messageId: data?.id,
        recipientId: payload.recipientId || null,
        targetRole: payload.targetRole || null,
        contentLength: payload.content.length,
      });
      SocketRegistry.broadcast({
        type: 'STAFF_MESSAGE_CREATED',
        payload: {
          message: data,
          messageId: data?.id,
          recipientId: payload.recipientId || null,
          targetRole: payload.targetRole || null,
          senderId: session.sub,
          timestamp: new Date().toISOString(),
        },
      });
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.patch('/admin/staff-messages/:id/flag', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...STAFF_MESSAGE_FLAG_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const { data, error } = await sb
        .from('staff_messages')
        .update({ is_flagged: true })
        .eq('id', req.params.id)
        .select('*')
        .single();
      if (error) return res.status(500).json({ success: false, error: error.message });
      await Audit.log('ADMIN', session.sub, 'STAFF_MESSAGE_FLAGGED', {
        messageId: req.params.id,
        originalSenderId: data?.sender_id,
        recipientId: data?.recipient_id || null,
      });
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/support-tickets', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...SUPPORT_TICKET_VIEW_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });
      const { data, error } = await sb.from('support_tickets').select('*').order('created_at', { ascending: false }).limit(100);
      if (error) return res.status(500).json({ success: false, error: error.message });
      const normalized = (data || []).map((ticket: any) => ({
        id: ticket.id,
        created_at: ticket.created_at,
        ...(ticket.data || {}),
      }));
      res.json({ success: true, data: normalized });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  v1.post('/admin/support-tickets', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...SUPPORT_TICKET_MANAGE_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const payload = SupportTicketCreateSchema.parse(req.body);
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });

      let resolvedCustomerId = payload.customerId || null;
      if (!resolvedCustomerId && payload.customerQuery) {
        const profile = await LogicCore.lookupUser(payload.customerQuery);
        resolvedCustomerId = profile?.id || null;
      }

      const record = {
        title: payload.title,
        body: payload.body,
        category: payload.category,
        priority: payload.priority || 'normal',
        status: 'open',
        customer_id: resolvedCustomerId,
        customer_query: payload.customerQuery || null,
        assigned_to: payload.assignedTo || null,
        tags: payload.tags || [],
        created_by: session.sub,
        created_by_name: session.user?.full_name || session.user?.email || 'Institutional staff',
      };

      const { data, error } = await sb
        .from('support_tickets')
        .insert({ data: record, created_at: new Date().toISOString() })
        .select('*')
        .single();
      if (error) return res.status(500).json({ success: false, error: error.message });
      await Audit.log('ADMIN', session.sub, 'SUPPORT_TICKET_CREATED', {
        ticketId: data?.id,
        customerId: resolvedCustomerId,
        category: payload.category,
        priority: payload.priority || 'normal',
        assignedTo: payload.assignedTo || null,
        hasCustomerQuery: Boolean(payload.customerQuery),
      });
      SocketRegistry.broadcast({
        type: 'SUPPORT_TICKET_CREATED',
        payload: {
          ticket: { id: data.id, created_at: data.created_at, ...(data.data || {}) },
          ticketId: data?.id,
          category: payload.category,
          priority: payload.priority || 'normal',
          assignedTo: payload.assignedTo || null,
          createdBy: session.sub,
          timestamp: new Date().toISOString(),
        },
      });
      res.json({ success: true, data: { id: data.id, created_at: data.created_at, ...(data.data || {}) } });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.patch('/admin/support-tickets/:id', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...SUPPORT_TICKET_MANAGE_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const payload = SupportTicketUpdateSchema.parse(req.body);
      const sb = getAdminSupabase() || getSupabase();
      if (!sb) return res.status(503).json({ success: false, error: 'DB_OFFLINE' });

      const { data: existing, error: fetchError } = await sb.from('support_tickets').select('*').eq('id', req.params.id).maybeSingle();
      if (fetchError) return res.status(500).json({ success: false, error: fetchError.message });
      if (!existing) return res.status(404).json({ success: false, error: 'TICKET_NOT_FOUND' });

      const current = existing.data || {};
      const next = {
        ...current,
        ...(payload.status ? { status: payload.status } : {}),
        ...(payload.assignedTo !== undefined ? { assigned_to: payload.assignedTo } : {}),
        ...(payload.resolution ? { resolution: payload.resolution, resolved_at: new Date().toISOString() } : {}),
        ...(payload.internalNote ? { internal_note: payload.internalNote } : {}),
        updated_by: session.sub,
        updated_at: new Date().toISOString(),
      };

      const { data, error } = await sb
        .from('support_tickets')
        .update({ data: next })
        .eq('id', req.params.id)
        .select('*')
        .single();
      if (error) return res.status(500).json({ success: false, error: error.message });
      await Audit.log('ADMIN', session.sub, payload.status === 'resolved' || payload.status === 'closed' ? 'SUPPORT_TICKET_RESOLVED' : 'SUPPORT_TICKET_UPDATED', {
        ticketId: req.params.id,
        customerId: next.customer_id || null,
        status: next.status,
        assignedTo: next.assigned_to || null,
        hasInternalNote: Boolean(payload.internalNote),
        hasResolution: Boolean(payload.resolution),
      });
      SocketRegistry.broadcast({
        type: 'SUPPORT_TICKET_UPDATED',
        payload: {
          ticket: { id: data.id, created_at: data.created_at, ...(data.data || {}) },
          ticketId: req.params.id,
          status: next.status,
          assignedTo: next.assigned_to || null,
          updatedBy: session.sub,
          timestamp: new Date().toISOString(),
        },
      });
      res.json({ success: true, data: { id: data.id, created_at: data.created_at, ...(data.data || {}) } });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.get('/admin/messaging/templates', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...MARKETING_MESSAGE_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const query = TemplateCatalogQuerySchema.parse(req.query);
      const data = await staffMessagingAdminService.searchTemplates(query);
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.post('/admin/messaging/templates/preview', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...MARKETING_MESSAGE_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const payload = TemplatePreviewSchema.parse(req.body);
      const data = await staffMessagingAdminService.previewTemplate(payload);
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.post('/admin/messaging/audience/preview', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...MARKETING_MESSAGE_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const filters = MessageAudienceFiltersSchema.parse(req.body || {});
      const data = await staffMessagingAdminService.previewAudience(filters);
      res.json({ success: true, data });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.post('/admin/messaging/send-template', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...MARKETING_MESSAGE_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const payload = StaffTemplatedSendSchema.parse(req.body);
      const data = await staffMessagingAdminService.sendTemplated({
        actorId: session.sub,
        ...payload,
      });

      await Audit.log('ADMIN', session.sub, 'STAFF_TEMPLATE_MESSAGE_SENT', {
        templateName: payload.templateName,
        userIdCount: payload.userIds?.length || 0,
        hasFilters: !!payload.filters,
        category: payload.category || null,
      });

      res.json({ success: true, data });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  v1.post('/admin/messaging/send-system-sms', authenticate, async (req, res) => {
    const session = (req as any).session;
    if (!sessionHasAnyRole(session, [...SYSTEM_SMS_ROLES])) {
      return res.status(403).json({ success: false, error: 'ACCESS_DENIED' });
    }

    try {
      const payload = StaffSystemSmsSchema.parse(req.body);
      const data = await staffMessagingAdminService.sendSystemCustomSms({
        actorId: session.sub,
        ...payload,
      });

      await Audit.log('ADMIN', session.sub, 'STAFF_SYSTEM_SMS_SENT', {
        userIdCount: payload.userIds?.length || 0,
        hasFilters: !!payload.filters,
        category: payload.category || null,
      });

      res.json({ success: true, data });
    } catch (e: any) {
      res.status(400).json({ success: false, error: e.message });
    }
  });

  if (messagingTestRoutesEnabled) {
    v1.post('/messaging/email', authenticate, async (_req, res) => {
      res.status(403).json({ success: false, error: 'EMAIL_SERVICE_DISABLED' });
    });
  }
};
