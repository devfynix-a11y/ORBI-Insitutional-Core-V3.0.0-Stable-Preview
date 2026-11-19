param(
  [string]$CoreDatabase = "orbi_core_sandbox",
  [string]$GatewayDatabase = "orbi_pay_gateway_sandbox",
  [string]$GatewayBaseUrl = "http://127.0.0.1:3101",
  [string]$OutputPath = ".sandbox\orbi-sandbox-fixtures.json",
  [switch]$RotateSecrets
)

$ErrorActionPreference = "Stop"

function Get-ContainerEnvMap([string]$ContainerName) {
  $rows = docker inspect $ContainerName --format '{{json .Config.Env}}' | ConvertFrom-Json
  $map = [ordered]@{}
  foreach ($row in $rows) {
    $parts = $row -split '=', 2
    if ($parts.Length -eq 2) {
      $map[$parts[0]] = $parts[1]
    }
  }
  $map
}

function Invoke-PostgresFile([string]$ContainerName, [string]$Database, [string]$User, [string]$Sql) {
  $temp = [System.IO.Path]::GetTempFileName()
  try {
    Set-Content -LiteralPath $temp -Value $Sql -Encoding UTF8
    Get-Content -LiteralPath $temp -Raw | docker exec -i $ContainerName psql -U $User -d $Database -v ON_ERROR_STOP=1
    if ($LASTEXITCODE -ne 0) {
      throw "PostgreSQL fixture load failed for database '$Database'."
    }
  } finally {
    Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
  }
}

function Invoke-Gateway([string]$Method, [string]$Path, [object]$Body = $null) {
  $headers = @{ "x-orbi-pay-operator-key" = $operatorKey }
  $uri = "$GatewayBaseUrl$Path"
  if ($null -eq $Body) {
    return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers
  }
  return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers -ContentType "application/json" -Body ($Body | ConvertTo-Json -Depth 20)
}

$gatewayEnv = Get-ContainerEnvMap "orbi-pay-gateway-sandbox"
if (-not $gatewayEnv.Contains("PAYMENT_GATEWAY_OPERATOR_DISCOVERY_API_KEY")) {
  throw "PAYMENT_GATEWAY_OPERATOR_DISCOVERY_API_KEY not found on orbi-pay-gateway-sandbox."
}
$operatorKey = $gatewayEnv["PAYMENT_GATEWAY_OPERATOR_DISCOVERY_API_KEY"]
$corePostgresEnv = Get-ContainerEnvMap "orbi-postgres-sandbox-1"
$gatewayPostgresEnv = Get-ContainerEnvMap "orbi-pay-gateway-postgres-sandbox"

if (
  -not $corePostgresEnv.Contains("POSTGRES_USER") -or
  -not $gatewayPostgresEnv.Contains("POSTGRES_USER")
) {
  throw "Sandbox PostgreSQL credentials are not available from the sandbox containers."
}

$corePostgresUser = $corePostgresEnv["POSTGRES_USER"]
$gatewayPostgresUser = $gatewayPostgresEnv["POSTGRES_USER"]

$coreSql = @'
create extension if not exists pgcrypto;

do $$
declare
  daniel_id uuid := '11111111-1111-4111-8111-111111111111';
  catherine_id uuid := '22222222-2222-4222-8222-222222222222';
  merchant_owner_id uuid := '33333333-3333-4333-8333-333333333333';
  merchant_id uuid := '44444444-4444-4444-8444-444444444444';
  sandbox_provider_id uuid := '55555555-5555-4555-8555-555555555555';
  now_utc timestamptz := now();
  fee_flow text;
begin
  -- The Core simulator uses its own sandbox database. Mirror only the
  -- non-secret service authorization record here; API keys and webhook
  -- secrets remain exclusively in the isolated Pay Gateway database.
  insert into public.pay_gateway_developer_services (
    service_code, display_name, legal_name, business_type, country_code,
    contact_email, contact_phone, status, environments, scopes_granted,
    external_developer_id, metadata, created_at, updated_at
  ) values (
    'orbi-shop-sandbox', 'ORBI Shop Sandbox', 'ORBI Shop Sandbox Limited',
    'marketplace', 'TZ', 'sandbox-shop@orbifinancial.test', '+255700000303',
    'active', array['sandbox'],
    array['identity:resolve','payment_profile:create','payment_profile:read','payments:create','escrow:create','escrow:read','escrow:release:request','escrow:refund:request','escrow:dispute:create','webhooks:receive'],
    'sandbox-orbi-shop',
    jsonb_build_object('sandbox', true, 'coreMerchantId', merchant_id::text, 'fixture', 'release-gate'),
    now_utc, now_utc
  ) on conflict (service_code) do update set
    status = excluded.status,
    environments = excluded.environments,
    scopes_granted = excluded.scopes_granted,
    metadata = excluded.metadata,
    updated_at = now_utc;

  insert into auth.users (
    id, aud, role, email, phone, encrypted_password, email_confirmed_at,
    phone_confirmed_at, raw_app_meta_data, raw_user_meta_data, created_at, updated_at
  ) values
    (
      daniel_id, 'authenticated', 'authenticated', 'sandbox.daniel@orbifinancial.test',
      '+255700000101', 'sandbox-login-disabled', now_utc, now_utc,
      '{"provider":"sandbox","providers":["sandbox"]}'::jsonb,
      jsonb_build_object(
        'full_name', 'Daniel Zakaria Sandbox',
        'customer_id', 'OB26-SANDBOX-0101',
        'phone', '+255700000101',
        'currency', 'TZS',
        'preferred_currency', 'TZS',
        'country_code', 'TZ',
        'country_name', 'Tanzania',
        'dial_code', '+255',
        'language', 'sw',
        'registry_type', 'CONSUMER',
        'role', 'USER',
        'app_origin', 'ORBI_SANDBOX'
      ),
      now_utc, now_utc
    ),
    (
      catherine_id, 'authenticated', 'authenticated', 'sandbox.catherine@orbifinancial.test',
      '+255700000202', 'sandbox-login-disabled', now_utc, now_utc,
      '{"provider":"sandbox","providers":["sandbox"]}'::jsonb,
      jsonb_build_object(
        'full_name', 'Catherine Daniel Sandbox',
        'customer_id', 'OB26-SANDBOX-0202',
        'phone', '+255700000202',
        'currency', 'TZS',
        'preferred_currency', 'TZS',
        'country_code', 'TZ',
        'country_name', 'Tanzania',
        'dial_code', '+255',
        'language', 'en',
        'registry_type', 'CONSUMER',
        'role', 'USER',
        'app_origin', 'ORBI_SANDBOX'
      ),
      now_utc, now_utc
    ),
    (
      merchant_owner_id, 'authenticated', 'authenticated', 'sandbox.shop@orbifinancial.test',
      '+255700000303', 'sandbox-login-disabled', now_utc, now_utc,
      '{"provider":"sandbox","providers":["sandbox"]}'::jsonb,
      jsonb_build_object(
        'full_name', 'ORBI Shop Sandbox Seller',
        'customer_id', 'OB26-SANDBOX-0303',
        'phone', '+255700000303',
        'currency', 'TZS',
        'preferred_currency', 'TZS',
        'country_code', 'TZ',
        'country_name', 'Tanzania',
        'dial_code', '+255',
        'language', 'en',
        'registry_type', 'MERCHANT',
        'role', 'USER',
        'app_origin', 'ORBI_SANDBOX'
      ),
      now_utc, now_utc
    )
  on conflict (id) do update set
    email = excluded.email,
    phone = excluded.phone,
    raw_user_meta_data = excluded.raw_user_meta_data,
    updated_at = now_utc;

  update public.users set
    account_status = 'active',
    kyc_status = 'verified',
    kyc_level = 2,
    auth_confirmed_at = now_utc,
    activation_method = 'sandbox_seed',
    metadata = coalesce(metadata, '{}'::jsonb) || jsonb_build_object('sandbox', true, 'seeded_at', now_utc)
  where id in (daniel_id, catherine_id, merchant_owner_id);

  update public.platform_vaults set balance = 100000000, updated_at = now_utc
  where user_id = daniel_id and vault_role = 'OPERATING';

  update public.platform_vaults set balance = 25000000, updated_at = now_utc
  where user_id = catherine_id and vault_role = 'OPERATING';

  update public.platform_vaults set balance = 0, updated_at = now_utc
  where user_id = merchant_owner_id and vault_role = 'OPERATING';

  insert into public.merchants (id, business_name, owner_user_id, status, metadata, created_at, updated_at)
  values (
    merchant_id,
    'ORBI Shop Sandbox',
    merchant_owner_id,
    'active',
    jsonb_build_object(
      'sandbox', true,
      'service_code', 'orbi-shop-sandbox',
      'merchant_account_ref', 'merchant_orbi_shop_sandbox',
      'settlement_model', 'paysafe_escrow'
    ),
    now_utc,
    now_utc
  )
  on conflict (id) do update set
    business_name = excluded.business_name,
    owner_user_id = excluded.owner_user_id,
    status = excluded.status,
    metadata = excluded.metadata,
    updated_at = now_utc;

  insert into public.merchant_wallets (
    id, merchant_id, owner_user_id, name, wallet_type, is_primary,
    balance, currency, status, metadata, created_at, updated_at
  ) values (
    '66666666-6666-4666-8666-666666666666',
    merchant_id,
    merchant_owner_id,
    'ORBI Shop Sandbox Escrow',
    'escrow',
    true,
    0,
    'TZS',
    'active',
    jsonb_build_object('sandbox', true, 'service_code', 'orbi-shop-sandbox'),
    now_utc,
    now_utc
  )
  on conflict (id) do update set
    merchant_id = excluded.merchant_id,
    owner_user_id = excluded.owner_user_id,
    name = excluded.name,
    wallet_type = excluded.wallet_type,
    is_primary = excluded.is_primary,
    status = excluded.status,
    metadata = excluded.metadata,
    updated_at = now_utc;

  insert into public.financial_partners (
    id, name, type, supported_currencies, api_base_url, provider_metadata,
    mapping_config, logic_type, status, created_at, updated_at
  ) values (
    sandbox_provider_id,
    'ORBI Sandbox Simulator',
    'mobile_money',
    array['TZS'],
    'http://pay-gateway-sandbox:3101',
    jsonb_build_object(
      'sandbox', true,
      'provider_code', 'orbi-sandbox-simulator',
      'rail', 'MOBILE_MONEY',
      'mode', 'simulator',
      'supports_webhooks', true,
      'operations', jsonb_build_array(
        'COLLECTION_REQUEST',
        'DISBURSEMENT_REQUEST',
        'REFUND_REQUEST',
        'WEBHOOK_VERIFY'
      )
    ),
    jsonb_build_object(
      'sandbox', true,
      'service_root', 'http://pay-gateway-sandbox:3101/v1/simulator',
      'operations', jsonb_build_object(
        'COLLECTION_REQUEST', jsonb_build_object('path', '/collections', 'method', 'POST'),
        'DISBURSEMENT_REQUEST', jsonb_build_object('path', '/payouts', 'method', 'POST'),
        'REFUND_REQUEST', jsonb_build_object('path', '/refunds', 'method', 'POST')
      ),
      'callback', jsonb_build_object(
        'reference_field', 'reference',
        'status_field', 'status',
        'amount_field', 'amount',
        'currency_field', 'currency'
      )
    ),
    'REGISTRY',
    'ACTIVE',
    now_utc,
    now_utc
  )
  on conflict (id) do update set
    name = excluded.name,
    type = excluded.type,
    supported_currencies = excluded.supported_currencies,
    api_base_url = excluded.api_base_url,
    provider_metadata = excluded.provider_metadata,
    mapping_config = excluded.mapping_config,
    logic_type = excluded.logic_type,
    status = excluded.status,
    updated_at = now_utc;

  insert into public.provider_routing_rules (
    rail, country_code, currency, operation_code, provider_id, priority, conditions, status, created_at, updated_at
  ) values
    ('MOBILE_MONEY', 'TZ', 'TZS', 'COLLECTION_REQUEST', sandbox_provider_id, 10, '{"sandbox":true}'::jsonb, 'ACTIVE', now_utc, now_utc),
    ('MOBILE_MONEY', 'TZ', 'TZS', 'DISBURSEMENT_REQUEST', sandbox_provider_id, 10, '{"sandbox":true}'::jsonb, 'ACTIVE', now_utc, now_utc),
    ('WALLET', 'TZ', 'TZS', 'INTERNAL_TRANSFER', sandbox_provider_id, 10, '{"sandbox":true}'::jsonb, 'ACTIVE', now_utc, now_utc)
  on conflict do nothing;

  insert into public.payment_rail_capabilities (
    switch_partner_id, capability_code, display_name, rail, country_code, currency,
    operation_codes, status, priority, min_amount, max_amount, fee_profile_code,
    pay_gateway_provider_code, pay_gateway_capability_code, icon, color, requires, metadata, created_at, updated_at
  ) values (
    sandbox_provider_id,
    'orbi-sandbox-mobile-money-tz',
    'ORBI Sandbox Mobile Money',
    'MOBILE_MONEY',
    'TZ',
    'TZS',
    array['COLLECTION_REQUEST','DISBURSEMENT_REQUEST'],
    'ACTIVE',
    10,
    100,
    100000000,
    'sandbox-zero-fee',
    'orbi-sandbox-simulator',
    'sandbox-mobile-money',
    'smartphone',
    '#0EA5E9',
    '{"idempotency":true,"challenge":true}'::jsonb,
    '{"sandbox":true}'::jsonb,
    now_utc,
    now_utc
  )
  on conflict (switch_partner_id, capability_code) do update set
    display_name = excluded.display_name,
    status = excluded.status,
    metadata = excluded.metadata,
    updated_at = now_utc;

  foreach fee_flow in array array[
    'CORE_TRANSACTION',
    'EXTERNAL_PAYMENT',
    'WITHDRAWAL',
    'EXTERNAL_TO_INTERNAL',
    'INTERNAL_TO_EXTERNAL',
    'EXTERNAL_TO_EXTERNAL',
    'CARD_SETTLEMENT',
    'GATEWAY_SETTLEMENT',
    'FX_CONVERSION',
    'TENANT_SETTLEMENT_PAYOUT',
    'MERCHANT_PAYMENT',
    'AGENT_CASH_DEPOSIT',
    'AGENT_CASH_WITHDRAWAL',
    'AGENT_REFERRAL_COMMISSION',
    'AGENT_CASH_COMMISSION',
    'SYSTEM_OPERATION'
  ] loop
    insert into public.platform_fee_configs (
      name, flow_code, currency, country_code, percentage_rate, fixed_amount,
      minimum_fee, maximum_fee, tax_rate, gov_fee_rate, stamp_duty_fixed,
      priority, status, metadata, created_at, updated_at
    ) values (
      'Sandbox zero fee - ' || fee_flow,
      fee_flow,
      'TZS',
      'TZ',
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      1,
      'ACTIVE',
      jsonb_build_object('sandbox', true, 'seeded_by', 'seed-sandbox-fixtures'),
      now_utc,
      now_utc
    )
    on conflict do nothing;

    insert into public.platform_fee_configs (
      name, flow_code, currency, country_code, percentage_rate, fixed_amount,
      minimum_fee, maximum_fee, tax_rate, gov_fee_rate, stamp_duty_fixed,
      priority, status, metadata, created_at, updated_at
    ) values (
      'Sandbox zero fee - ' || fee_flow || ' - global',
      fee_flow,
      'TZS',
      null,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      1,
      'ACTIVE',
      jsonb_build_object('sandbox', true, 'seeded_by', 'seed-sandbox-fixtures'),
      now_utc,
      now_utc
    )
    on conflict do nothing;
  end loop;
end $$;
'@

Invoke-PostgresFile "orbi-postgres-sandbox-1" $CoreDatabase $corePostgresUser $coreSql

$serviceCode = "orbi-shop-sandbox"
$applicationBody = @{
  externalDeveloperId = "sandbox-orbi-shop"
  legalName = "ORBI Shop Sandbox Limited"
  displayName = "ORBI Shop Sandbox"
  contactEmail = "sandbox-shop@orbifinancial.test"
  contactPhone = "+255700000303"
  businessType = "marketplace"
  countryCode = "TZ"
  requestedEnvironments = @("sandbox")
  requestedScopes = @(
    "identity:resolve",
    "payment_profile:create",
    "payment_profile:read",
    "payments:create",
    "escrow:create",
    "escrow:read",
    "escrow:release:request",
    "escrow:refund:request",
    "escrow:dispute:create",
    "webhooks:receive"
  )
  redirectUrls = @(
    "https://shop.orbifinancial.com/checkout/orbi/return",
    "https://shop.orbifinancial.com/api/orbi-pay/link/callback"
  )
  webhookUrls = @("https://shop.orbifinancial.com/api/orbi-pay/sandbox/webhooks")
  useCases = @("Sandbox checkout and PaySafe escrow lifecycle testing.")
  supportEmail = "support@orbifinancial.com"
  metadata = @{
    sandbox = $true
    coreMerchantId = "44444444-4444-4444-8444-444444444444"
    merchantAccountRef = "merchant_orbi_shop_sandbox"
    allowedOperations = @("collection", "paysafe", "refund")
    allowedCurrencies = @("TZS")
    allowedCountries = @("TZ")
    merchant = @{
      merchantIdEnv = "ORBI_SHOP_SANDBOX_MERCHANT_ID"
      feeProfileCode = "sandbox-zero-fee"
      feeFlowCode = "MERCHANT_PAYMENT"
      requireActiveMerchant = $true
    }
  }
  termsAccepted = $true
}

$services = Invoke-Gateway "GET" "/v1/developer/services"
$service = $services.data | Where-Object { $_.serviceCode -eq $serviceCode } | Select-Object -First 1

if (-not $service) {
  $application = Invoke-Gateway "POST" "/v1/developer/service-applications" $applicationBody
  $approval = Invoke-Gateway "POST" "/v1/developer/service-applications/$($application.data.applicationId)/approve" @{
    serviceCode = $serviceCode
    initialStatus = "active"
  }
  $service = $approval.data
}

$serviceMetadata = @'
{
  "sandbox": true,
  "coreMerchantId": "44444444-4444-4444-8444-444444444444",
  "merchantAccountRef": "merchant_orbi_shop_sandbox",
  "allowedOperations": ["collection", "paysafe", "refund"],
  "allowedCurrencies": ["TZS"],
  "allowedCountries": ["TZ"],
  "merchant": {
    "merchantIdEnv": "ORBI_SHOP_SANDBOX_MERCHANT_ID",
    "feeProfileCode": "sandbox-zero-fee",
    "feeFlowCode": "MERCHANT_PAYMENT",
    "requireActiveMerchant": true
  }
}
'@
$serviceMetadata = ($serviceMetadata -replace "\s+", "").Replace("'", "''")
$serviceScopes = ($applicationBody.requestedScopes | ConvertTo-Json -Compress).Replace("'", "''")
Invoke-PostgresFile "orbi-pay-gateway-postgres-sandbox" $GatewayDatabase $gatewayPostgresUser @"
update public.pay_gateway_developer_services
set metadata = coalesce(metadata, '{}'::jsonb) || '$serviceMetadata'::jsonb,
    scopes_granted = (
      select array_agg(distinct scope_value)
      from (
        select unnest(coalesce(scopes_granted, array[]::text[])) as scope_value
        union
        select jsonb_array_elements_text('$serviceScopes'::jsonb) as scope_value
      ) merged_scopes
    ),
    updated_at = now()
where service_code = '$serviceCode';
"@

# The database update above grants the deterministic fixture scopes. Reload the
# service before deciding whether a request is needed, otherwise a repeated
# release gate sees stale scope data and creates an unnecessary pending request.
$service = (Invoke-Gateway "GET" "/v1/developer/services/$serviceCode").data
foreach ($scope in $applicationBody.requestedScopes) {
  if ($service.scopesGranted -notcontains $scope) {
    $scopeRequest = Invoke-Gateway "POST" "/v1/developer/services/$serviceCode/scope-requests" @{
      requestedScopes = @($scope)
      reason = "Sandbox fixture grants this scope for deterministic developer testing."
      environment = "sandbox"
      metadata = @{ sandbox = $true }
    }
    Invoke-Gateway "POST" "/v1/developer/scope-requests/$($scopeRequest.data.requestId)/decision" @{
      decision = "approve"
      reason = "Approved for sandbox fixture testing only."
      decidedBy = "sandbox-seed"
      metadata = @{ sandbox = $true }
    } | Out-Null
  }
}

Invoke-Gateway "POST" "/v1/developer/services/$serviceCode/allowlists" @{
  redirectUrls = $applicationBody.redirectUrls
  webhookUrls = $applicationBody.webhookUrls
  reason = "Sandbox fixture allowlists ORBI Shop sandbox callbacks."
  environment = "sandbox"
} | Out-Null

$service = (Invoke-Gateway "GET" "/v1/developer/services/$serviceCode").data
$activeKey = $service.keys | Where-Object { $_.environment -eq "sandbox" -and $_.status -eq "active" } | Select-Object -First 1
$activeWebhookSecret = $service.webhookSecrets | Where-Object { $_.environment -eq "sandbox" -and $_.status -eq "active" } | Select-Object -First 1

$apiKeySecret = $null
$webhookSecret = $null
if ($RotateSecrets -or -not $activeKey) {
  $keyResult = Invoke-Gateway "POST" "/v1/developer/services/$serviceCode/api-keys/issue" @{
    environment = "sandbox"
    requestedBy = "sandbox-seed"
    reason = "Issue or rotate sandbox API key for deterministic integration testing."
  }
  $apiKeySecret = $keyResult.data.oneTimeSecret
  $activeKey = $keyResult.data.key
}
if ($RotateSecrets -or -not $activeWebhookSecret) {
  $secretResult = Invoke-Gateway "POST" "/v1/developer/services/$serviceCode/webhook-secrets/issue" @{
    environment = "sandbox"
    requestedBy = "sandbox-seed"
    reason = "Issue or rotate sandbox webhook secret for deterministic integration testing."
  }
  $webhookSecret = $secretResult.data.oneTimeSecret
  $activeWebhookSecret = $secretResult.data.webhookSecret
}

Invoke-PostgresFile "orbi-pay-gateway-postgres-sandbox" $GatewayDatabase $gatewayPostgresUser @"
update public.pay_gateway_developer_services
set metadata = coalesce(metadata, '{}'::jsonb) || '$serviceMetadata'::jsonb,
    scopes_granted = (
      select array_agg(distinct scope_value)
      from (
        select unnest(coalesce(scopes_granted, array[]::text[])) as scope_value
        union
        select jsonb_array_elements_text('$serviceScopes'::jsonb) as scope_value
      ) merged_scopes
    ),
    updated_at = now()
where service_code = '$serviceCode';
"@

$output = @{
  generatedAt = (Get-Date).ToUniversalTime().ToString("o")
  environment = "sandbox"
  gatewayBaseUrl = "https://sandbox-pay.orbifinancial.com"
  coreBaseUrl = "http://core-sandbox:3000"
  serviceCode = $serviceCode
  merchantId = "44444444-4444-4444-8444-444444444444"
  demoUsers = @(
    @{
      name = "Daniel Zakaria Sandbox"
      customerId = "OB26-SANDBOX-0101"
      phone = "+255700000101"
      openingOperatingBalance = "100000000"
    },
    @{
      name = "Catherine Daniel Sandbox"
      customerId = "OB26-SANDBOX-0202"
      phone = "+255700000202"
      openingOperatingBalance = "25000000"
    }
  )
  apiKey = if ($apiKeySecret) { $apiKeySecret } else { $null }
  apiKeyNote = if ($apiKeySecret) { "New one-time sandbox API key generated. Store securely." } else { "Active sandbox API key already existed; no raw key can be displayed." }
  apiKeyId = $activeKey.keyId
  webhookSecret = if ($webhookSecret) { $webhookSecret } else { $null }
  webhookSecretNote = if ($webhookSecret) { "New one-time sandbox webhook secret generated. Store securely." } else { "Active sandbox webhook secret already existed; no raw secret can be displayed." }
  webhookSecretId = $activeWebhookSecret.secretId
}

$outputDirectory = Split-Path -Parent $OutputPath
if ($outputDirectory) {
  New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}
$output | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $OutputPath -Encoding UTF8

Write-Output "Sandbox fixtures seeded."
Write-Output "Fixture metadata written to $OutputPath."
Write-Output "If apiKey/webhookSecret are null, rotate via Developer Portal/operator endpoint to reveal new one-time values."
