param(
  [string]$GatewayImage = "orbi-pay-gateway:local",
  [string]$GatewayRepoPath = "D:\FYNIX\ORBI\Orbi Infrastructures\ORBI GATEWAY\Pay Gateway Backend",
  [string]$SandboxDatabase = "orbi_pay_gateway_sandbox",
  [string]$SandboxCoreUrl = "http://core-sandbox:3000",
  [string]$SandboxWorkerSecretPath = ".sandbox\pay-gateway-sandbox-worker-signing-secret.txt",
  [string]$SandboxEncryptionSecretPath = ".sandbox\pay-gateway-sandbox-secret-encryption-key.txt",
  [string]$SandboxPortalAuthSecretPath = ".sandbox\pay-gateway-sandbox-portal-auth-secret.txt",
  [string]$SandboxServiceAccessTokenSecretPath = ".sandbox\pay-gateway-sandbox-service-access-token-secret.txt",
  [string]$SandboxMtlsDirectory = "D:\FYNIX\ORBI\SECREATES\ORBI_MTLS_SANDBOX",
  [switch]$EnableDirectMtls
)

$ErrorActionPreference = "Stop"

function New-OrbiSecret([int]$Length) {
  $chars = 48..57 + 65..90 + 97..122
  -join ($chars | Get-Random -Count $Length | ForEach-Object { [char]$_ })
}

function Get-OrCreateSecretFile([string]$Path, [int]$Length) {
  $fullPath = [System.IO.Path]::GetFullPath((Join-Path (Get-Location) $Path))
  $parent = Split-Path -Parent $fullPath
  if (-not (Test-Path $parent)) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
  }
  if (Test-Path $fullPath) {
    $existing = (Get-Content -LiteralPath $fullPath -Raw).Trim()
    if ($existing) { return $existing }
  }
  $secret = New-OrbiSecret $Length
  Set-Content -LiteralPath $fullPath -Value $secret -NoNewline -Encoding ASCII
  return $secret
}

function Get-ContainerEnvValue([string]$ContainerName, [string]$Key) {
  $envRows = docker inspect $ContainerName --format '{{json .Config.Env}}' | ConvertFrom-Json
  $row = $envRows | Where-Object { $_ -like "$Key=*" } | Select-Object -First 1
  if (-not $row) {
    throw "$Key not found on $ContainerName"
  }
  $row -replace "^$Key=", ""
}

function Invoke-Postgres([string]$Database, [string]$Sql) {
  docker exec orbi-postgres psql -U orbi -d $Database -v ON_ERROR_STOP=1 -c $Sql | Out-Null
}

$providersPath = Join-Path $GatewayRepoPath "config\providers.example.json"
$servicesPath = Join-Path $GatewayRepoPath "config\services.json"
$workerSigningSecret = Get-OrCreateSecretFile $SandboxWorkerSecretPath 96
$gatewayEncryptionSecret = Get-OrCreateSecretFile $SandboxEncryptionSecretPath 96
$portalAuthSecret = Get-OrCreateSecretFile $SandboxPortalAuthSecretPath 96
$serviceAccessTokenSecret = Get-OrCreateSecretFile $SandboxServiceAccessTokenSecretPath 96

if (-not (Test-Path $providersPath)) {
  throw "Provider manifest not found: $providersPath"
}
if (-not (Test-Path $servicesPath)) {
  throw "Service registry not found: $servicesPath"
}

$liveDatabaseUrl = Get-ContainerEnvValue "orbi-pay-gateway" "DATABASE_URL"
$sandboxDatabaseUrl = $liveDatabaseUrl -replace "/orbi(\?.*)?$", "/$SandboxDatabase`$1"
if ($sandboxDatabaseUrl -eq $liveDatabaseUrl) {
  throw "Could not derive sandbox database URL safely."
}

$databaseExists = docker exec orbi-postgres psql -U orbi -d orbi -tAc "select 1 from pg_database where datname = '$SandboxDatabase';"
if (-not $databaseExists) {
  Invoke-Postgres "orbi" "create database $SandboxDatabase owner orbi;"
}

$hasDeveloperTables = docker exec orbi-postgres psql -U orbi -d $SandboxDatabase -tAc "select count(*) from information_schema.tables where table_schema = 'public' and table_name like 'pay_gateway_developer_%';"
if ([int]$hasDeveloperTables -eq 0) {
  docker exec orbi-postgres pg_dump -U orbi -d orbi --schema-only `
    -t public.pay_gateway_developer_services `
    -t public.pay_gateway_developer_api_keys `
    -t public.pay_gateway_developer_webhook_secrets `
    -t public.pay_gateway_developer_secret_events |
    docker exec -i orbi-postgres psql -U orbi -d $SandboxDatabase -v ON_ERROR_STOP=1 | Out-Null
}

$existing = docker ps -a --filter "name=^orbi-pay-gateway-sandbox$" --format "{{.Names}}"
if ($existing) {
  docker rm -f orbi-pay-gateway-sandbox | Out-Null
}

if ($EnableDirectMtls) {
  if (-not (Test-Path -LiteralPath $SandboxMtlsDirectory)) {
    throw "Sandbox mTLS directory not found: $SandboxMtlsDirectory. Run generate-mtls-certificates.ps1 -Environment sandbox first."
  }
  $SandboxCoreUrl = "https://core-sandbox:3000"
}

$mtlsEnvArgs = New-Object System.Collections.Generic.List[string]
if ($EnableDirectMtls) {
  $mtlsEnvArgs.Add("-e")
  $mtlsEnvArgs.Add("PAYMENT_GATEWAY_INTERNAL_MTLS_ENABLED=true")
  $mtlsEnvArgs.Add("-e")
  $mtlsEnvArgs.Add("PAYMENT_GATEWAY_INTERNAL_MTLS_CERT_PATH=/opt/orbi/mtls/pay-gateway-client.crt")
  $mtlsEnvArgs.Add("-e")
  $mtlsEnvArgs.Add("PAYMENT_GATEWAY_INTERNAL_MTLS_KEY_PATH=/opt/orbi/mtls/pay-gateway-client.key")
  $mtlsEnvArgs.Add("-e")
  $mtlsEnvArgs.Add("PAYMENT_GATEWAY_INTERNAL_MTLS_CA_PATH=/opt/orbi/mtls/orbi-internal-ca.crt")
  $mtlsEnvArgs.Add("-e")
  $mtlsEnvArgs.Add("PAYMENT_GATEWAY_INTERNAL_MTLS_REJECT_UNAUTHORIZED=true")
}

$mtlsVolumeArgs = New-Object System.Collections.Generic.List[string]
if ($EnableDirectMtls) {
  $mtlsVolumeArgs.Add("-v")
  $mtlsVolumeArgs.Add("${SandboxMtlsDirectory}:/opt/orbi/mtls:ro")
}

$allowPrivateHttpCore = if ($EnableDirectMtls) { "false" } else { "true" }
$gatewayMtlsEnabled = if ($EnableDirectMtls) { "true" } else { "false" }

docker create `
  --name orbi-pay-gateway-sandbox `
  --restart unless-stopped `
  --network orbi-private `
  --network-alias pay-gateway-sandbox `
  -e NODE_ENV=production `
  -e PAYMENT_GATEWAY_PORT=3101 `
  -e PAYMENT_GATEWAY_PUBLIC_BASE_URL=https://sandbox-pay.orbifinancial.com `
  -e PAYMENT_GATEWAY_PROVIDER_MODE=sandbox `
  -e PAYMENT_GATEWAY_CREDENTIAL_MODE=tokenized `
  -e PAYMENT_GATEWAY_REQUIRE_STRONG_CUSTOMER_AUTH=true `
  -e DATABASE_URL=$sandboxDatabaseUrl `
  -e ORBI_SECRET_ENCRYPTION_KEY=$gatewayEncryptionSecret `
  -e PAYMENT_GATEWAY_PROVIDER_MANIFEST_PATH=/app/config/providers.json `
  -e PAYMENT_GATEWAY_SERVICE_REGISTRY_PATH=/app/config/services.json `
  -e PAYMENT_GATEWAY_OPERATOR_DISCOVERY_API_KEY=$(New-OrbiSecret 64) `
  -e PAYMENT_GATEWAY_PORTAL_AUTH_SECRET=$portalAuthSecret `
  -e PAYMENT_GATEWAY_SERVICE_ACCESS_TOKEN_SECRET=$serviceAccessTokenSecret `
  -e PAYMENT_GATEWAY_OIDC_IDENTITY_ISSUER=https://auth.orbifinancial.com/realms/orbi-sandbox `
  -e PAYMENT_GATEWAY_OIDC_IDENTITY_BACKCHANNEL_URL=http://orbi-keycloak:8080/realms/orbi-sandbox `
  -e PAYMENT_GATEWAY_OIDC_IDENTITY_AUDIENCE=orbi-pay-sandbox-identity `
  -e PAYMENT_GATEWAY_OIDC_AUTHORIZATION_CLIENT_ID=orbi-pay-sandbox-developers `
  -e PAYMENT_GATEWAY_FINANCIAL_TOKEN_AUDIENCE=orbi-pay-sandbox-api `
  -e PAYMENT_GATEWAY_ALLOWED_BROWSER_ORIGINS=https://sandbox-pay.orbifinancial.com,https://shop.orbifinancial.com,https://developers.orbifinancial.com `
  -e PAYMENT_GATEWAY_REQUIRE_SIGNED_INTERNAL_INGRESS=true `
  -e PAYMENT_GATEWAY_REQUEST_AUDIT_ENABLED=true `
  -e PAYMENT_GATEWAY_OBP_SANDBOX_TOOLS_ENABLED=true `
  -e ORBI_CORE_INTERNAL_BASE_URL=$SandboxCoreUrl `
  -e PAYMENT_GATEWAY_ALLOW_PRIVATE_HTTP_CORE=$allowPrivateHttpCore `
  -e ORBI_CORE_TRUSTED_GATEWAY_EVENT_PATH=/api/internal/gateway/provider-events `
  -e ORBI_CORE_TRUSTED_SERVICE_PAYMENT_REQUEST_PATH=/api/internal/pay-gateway/service-payment-requests `
  -e ORBI_CORE_TRUSTED_SERVICE_PAYMENT_CHALLENGE_RESPOND_PATH=/api/internal/pay-gateway/service-payment-challenges `
  -e ORBI_CORE_TRUSTED_PAYSAFE_BALANCE_PATH=/api/internal/pay-gateway/paysafe-balances `
  -e ORBI_CORE_TRUSTED_BUSINESS_REGISTRATION_PATH=/api/internal/pay-gateway/business/registrations `
  -e ORBI_CORE_TRUSTED_PAYMENT_PROFILE_PATH=/api/internal/pay-gateway/payment-profiles `
  -e ORBI_CORE_TRUSTED_MERCHANT_ORDER_PAYMENT_STATUS_PATH=/api/internal/pay-gateway/merchant-order-payment-status `
  -e ORBI_CORE_TRUSTED_MERCHANT_SETTLEMENTS_PATH=/api/internal/pay-gateway/merchant-settlements `
  -e ORBI_CORE_CALLBACK_TIMEOUT_MS=30000 `
  -e PAYMENT_GATEWAY_WORKER_ID=orbi-payment-gateway-sandbox `
  -e PAYMENT_GATEWAY_WORKER_SCOPES=gateway:events:write,gateway:service-payments:write,gateway:service-payments:result,gateway:identity:read,gateway:notifications:push,gateway:paysafe-balances:read,gateway:business-registration:write,gateway:payment-profiles:write,gateway:merchant-payments:read,gateway:merchant-settlements:read `
  -e WORKER_SIGNING_SECRET=$workerSigningSecret `
  -e WORKER_KEY_ID=payment-gateway-sandbox-v1 `
  -e PAYMENT_GATEWAY_INTERNAL_MTLS_ENABLED=$gatewayMtlsEnabled `
  @mtlsEnvArgs `
  -e ORBI_SHOP_PAY_API_KEY_TOKEN_REF=env://ORBI_SHOP_SANDBOX_PAY_API_KEY `
  -e ORBI_SHOP_PAY_API_KEY=$(New-OrbiSecret 64) `
  -e ORBI_SHOP_PAY_WEBHOOK_SECRET_TOKEN_REF=env://ORBI_SHOP_SANDBOX_PAY_WEBHOOK_SECRET `
  -e ORBI_SHOP_PAY_WEBHOOK_SECRET=$(New-OrbiSecret 64) `
  -e ORBI_SHOP_PAY_WEBHOOK_URL=https://shop.orbifinancial.com/api/orbi-pay/sandbox/webhooks `
  -e ORBI_SHOP_MERCHANT_ID=44444444-4444-4444-8444-444444444444 `
  -e ORBI_SHOP_SANDBOX_MERCHANT_ID=44444444-4444-4444-8444-444444444444 `
  -v "${providersPath}:/app/config/providers.json:ro" `
  -v "${servicesPath}:/app/config/services.json:ro" `
  @mtlsVolumeArgs `
  -p 127.0.0.1:3101:3101 `
  $GatewayImage | Out-Null

docker network connect --alias pay-gateway-sandbox orbi-edge orbi-pay-gateway-sandbox
docker start orbi-pay-gateway-sandbox | Out-Null

$mode = if ($EnableDirectMtls) { "direct mTLS" } else { "HMAC over private HTTP" }
Write-Output "Sandbox Pay Gateway started on 127.0.0.1:3101 with isolated database '$SandboxDatabase' using $mode."
