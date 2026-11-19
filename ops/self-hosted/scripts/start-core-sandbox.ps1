param(
  [string]$CoreImage = "self-hosted-core",
  [string]$SandboxDatabase = "orbi_core_sandbox",
  [string]$SandboxWorkerSecretPath = ".sandbox\pay-gateway-sandbox-worker-signing-secret.txt",
  [string]$SandboxSecretPrefix = ".sandbox\core-sandbox",
  [string]$SandboxTlsDirectory = "D:\FYNIX\ORBI\SECREATES\ORBI_CORE_TLS_SANDBOX",
  [switch]$EnableDirectMtls,
  [switch]$PrintDockerArgs,
  [switch]$RebuildSchema
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

function Invoke-Postgres([string]$Database, [string]$Sql) {
  docker exec orbi-postgres psql -U orbi -d $Database -v ON_ERROR_STOP=1 -c $Sql | Out-Null
}

# The compose-managed sandbox Core is the source of sandbox-only endpoints,
# credentials, database and cache URLs. Do not rewrite a live Core URL: that
# would silently weaken the isolation the release gate is meant to verify.
$sandboxCoreEnv = Get-ContainerEnvMap "orbi-core-sandbox-1"
$workerSigningSecret = Get-OrCreateSecretFile $SandboxWorkerSecretPath 96
$workerSecret = Get-OrCreateSecretFile "$SandboxSecretPrefix-worker-secret.txt" 96
$jwtSecret = Get-OrCreateSecretFile "$SandboxSecretPrefix-jwt-secret.txt" 96
$sessionSecret = Get-OrCreateSecretFile "$SandboxSecretPrefix-session-secret.txt" 96
$kmsMasterKey = Get-OrCreateSecretFile "$SandboxSecretPrefix-kms-master-key.txt" 96
$kmsMasterSalt = Get-OrCreateSecretFile "$SandboxSecretPrefix-kms-master-salt.txt" 64
$bootstrapAdminSecret = Get-OrCreateSecretFile "$SandboxSecretPrefix-bootstrap-admin-secret.txt" 64
$monitorApiKey = Get-OrCreateSecretFile "$SandboxSecretPrefix-monitor-api-key.txt" 64

if (-not $sandboxCoreEnv.Contains("DATABASE_URL")) {
  throw "DATABASE_URL not found on the compose-managed sandbox Core."
}

$sandboxDatabaseUrl = $sandboxCoreEnv["DATABASE_URL"]
try {
  $sandboxDatabaseUri = [Uri]$sandboxDatabaseUrl
} catch {
  throw "Sandbox Core DATABASE_URL is invalid."
}
if (
  $sandboxDatabaseUri.Host -notmatch 'sandbox' -or
  $sandboxDatabaseUri.AbsolutePath.Trim('/') -ne $SandboxDatabase
) {
  throw "Sandbox Core DATABASE_URL does not target the isolated sandbox database."
}

$existing = docker ps -a --filter "name=^orbi-core-sandbox$" --format "{{.Names}}"
if ($existing) {
  docker rm -f orbi-core-sandbox | Out-Null
}

$envArgs = New-Object System.Collections.Generic.List[string]
foreach ($key in $sandboxCoreEnv.Keys) {
  if ($key -in @("PATH", "NODE_VERSION", "YARN_VERSION")) {
    continue
  }
  $value = $sandboxCoreEnv[$key]
  switch ($key) {
    "NODE_ENV" { $value = "sandbox" }
    "PORT" { $value = "3000" }
    "DATABASE_URL" { $value = $sandboxDatabaseUrl }
    "BACKEND_URL" { $value = "https://sandbox-api.orbifinancial.com" }
    "ORBI_PRIMARY_CORE_BASE_URL" { $value = "https://sandbox-api.orbifinancial.com" }
    "ORBI_WEB_ORIGIN" { $value = "https://sandbox-api.orbifinancial.com" }
    "ORBI_ALLOWED_ORIGINS" { $value = "https://sandbox-api.orbifinancial.com,https://sandbox-pay.orbifinancial.com" }
    "ORBI_ENFORCE_HTTPS" { $value = "false" }
    "ORBI_TLS_ENABLED" { $value = "false" }
    "ORBI_PAY_GATEWAY_BASE_URL" { $value = "https://sandbox-pay.orbifinancial.com" }
    "ORBI_PAY_GATEWAY_INTERNAL_BASE_URL" { $value = "http://pay-gateway-sandbox:3101" }
    "PAYMENT_GATEWAY_PUBLIC_BASE_URL" { $value = "https://sandbox-pay.orbifinancial.com" }
    "PAYMENT_GATEWAY_PROVIDER_MODE" { $value = "sandbox" }
    "PAYMENT_GATEWAY_WORKER_ID" { $value = "orbi-payment-gateway-sandbox" }
    "WORKER_SIGNING_SECRET" { $value = $workerSigningSecret }
    "WORKER_SECRET" { $value = $workerSecret }
    "JWT_SECRET" { $value = $jwtSecret }
    "SESSION_SECRET" { $value = $sessionSecret }
    "KMS_MASTER_KEY" { $value = $kmsMasterKey }
    "KMS_MASTER_SALT" { $value = $kmsMasterSalt }
    "ORBI_BOOTSTRAP_ADMIN_SECRET" { $value = $bootstrapAdminSecret }
    "ORBI_MONITOR_API_KEY" { $value = $monitorApiKey }
    "ORBI_ENABLE_SANDBOX_ROUTES" { $value = "true" }
    "ORBI_ENABLE_GATEWAY_BACKGROUND_JOBS" { $value = "false" }
    "ORBI_ENABLE_INTERNAL_BACKGROUND_JOBS" { $value = "false" }
    "ORBI_API_GATEWAY_ENABLED" { $value = "true" }
    "ORBI_API_GATEWAY_FAIL_CLOSED" { $value = "true" }
  }
  $envArgs.Add("-e")
  $envArgs.Add("$key=$value")
}

if ($EnableDirectMtls) {
  if (-not (Test-Path -LiteralPath $SandboxTlsDirectory)) {
    throw "Sandbox TLS directory not found: $SandboxTlsDirectory. Run generate-mtls-certificates.ps1 -Environment sandbox first."
  }

  $directMtlsEnv = [ordered]@{
    "ORBI_TLS_ENABLED" = "true"
    "ORBI_TLS_CERT_PATH" = "/etc/orbi/tls/fullchain.pem"
    "ORBI_TLS_KEY_PATH" = "/etc/orbi/tls/privkey.pem"
    "ORBI_TLS_CA_PATH" = "/etc/orbi/tls/orbi-internal-ca.crt"
    "ORBI_TLS_REJECT_UNAUTHORIZED" = "true"
    "ORBI_INTERNAL_MTLS_SOURCE" = "direct"
    "ORBI_INTERNAL_MTLS_MODE" = "required"
    "ORBI_INTERNAL_MTLS_CA_PATH" = "/etc/orbi/tls/orbi-internal-ca.crt"
    "ORBI_ALLOW_HMAC_ONLY_INTERNAL_REQUESTS" = "false"
    "ORBI_ALLOW_PRIVATE_HTTP_INTERNAL_REQUESTS" = "false"
    "ORBI_ENFORCE_HTTPS" = "false"
  }

  foreach ($entry in $directMtlsEnv.GetEnumerator()) {
    $envArgs.Add("-e")
    $envArgs.Add("$($entry.Key)=$($entry.Value)")
  }
}

$volumeArgs = New-Object System.Collections.Generic.List[string]
if ($EnableDirectMtls) {
  $dockerTlsDirectory = $SandboxTlsDirectory -replace '\\', '/'
  $volumeArgs.Add("-v")
  $volumeArgs.Add("${dockerTlsDirectory}:/etc/orbi/tls:ro")
}

if ($PrintDockerArgs) {
  @(
    "create",
    "--name", "orbi-core-sandbox",
    "--restart", "unless-stopped",
    "--network", "orbi-private",
    "--network-alias", "core-sandbox",
    "--no-healthcheck"
  ) + @($envArgs.ToArray()) + @($volumeArgs.ToArray()) + @("-p", "127.0.0.1:3001:3000", $CoreImage) | ForEach-Object {
    $arg = [string]$_
    if ($arg -match '=(.+)$' -and $arg -match '(SECRET|PASSWORD|TOKEN|KEY|DATABASE_URL|VALKEY_URL)') {
      $arg = ($arg -replace '=(.+)$', '=<redacted>')
    }
    Write-Output $arg
  }
  exit 0
}

docker create `
  --name orbi-core-sandbox `
  --restart unless-stopped `
  --network orbi_sandbox_private `
  --network-alias core-sandbox `
  --no-healthcheck `
  @envArgs `
  @volumeArgs `
  -p 127.0.0.1:3001:3000 `
  $CoreImage | Out-Null
if ($LASTEXITCODE -ne 0) {
  throw "docker create failed for orbi-core-sandbox."
}

docker network connect orbi_sandbox_test_bridge orbi-core-sandbox
docker start orbi-core-sandbox | Out-Null

$scheme = if ($EnableDirectMtls) { "https" } else { "http" }
Write-Output "Sandbox Core started on ${scheme}://127.0.0.1:3001 with isolated database '$SandboxDatabase'."
