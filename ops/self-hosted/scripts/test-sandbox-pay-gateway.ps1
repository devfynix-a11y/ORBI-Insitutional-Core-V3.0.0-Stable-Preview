param(
  [string]$GatewayRepoPath = "D:\FYNIX\ORBI\Orbi Infrastructures\ORBI GATEWAY\Pay Gateway Backend",
  [string]$GatewayBaseUrl = "http://127.0.0.1:3101",
  [string]$CoreHealthUrl = "http://127.0.0.1:3001/health",
  [string]$FixturePath = ".sandbox\orbi-sandbox-fixtures.json",
  [decimal]$Amount = 1500,
  [switch]$EnsureContainers,
  [switch]$SeedFixtures,
  [switch]$RotateSecrets,
  [switch]$SkipWebhookAssertion,
  [switch]$SkipNegativeTests,
  [switch]$SkipLogScan
)

$ErrorActionPreference = "Stop"

function Resolve-RepoPath([string]$Path) {
  if ([System.IO.Path]::IsPathRooted($Path)) {
    return $Path
  }
  return (Join-Path $PWD $Path)
}

function Assert-Command([string]$Name) {
  if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
    throw "Required command '$Name' was not found in PATH."
  }
}

function Invoke-JsonHealth([string]$Name, [string]$Url) {
  try {
    Invoke-RestMethod -Method GET -Uri $Url -TimeoutSec 12 | Out-Null
    Write-Output "$Name health OK"
  } catch {
    throw "$Name health check failed at $Url. $($_.Exception.Message)"
  }
}

function Get-ValkeyPassword {
  $cmd = docker inspect orbi-valkey --format '{{json .Config.Cmd}}' | ConvertFrom-Json
  for ($index = 0; $index -lt $cmd.Count; $index++) {
    if ($cmd[$index] -eq "--requirepass" -and ($index + 1) -lt $cmd.Count) {
      return $cmd[$index + 1]
    }
  }
  throw "Could not read Valkey password from orbi-valkey container command."
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

function Get-GatewayOperatorKey {
  $envMap = Get-ContainerEnvMap "orbi-pay-gateway-sandbox"
  if (-not $envMap.Contains("PAYMENT_GATEWAY_OPERATOR_DISCOVERY_API_KEY")) {
    throw "Sandbox gateway operator key is not present on orbi-pay-gateway-sandbox."
  }
  return $envMap["PAYMENT_GATEWAY_OPERATOR_DISCOVERY_API_KEY"]
}

function Invoke-GatewayOperator([string]$Path) {
  $operatorKey = Get-GatewayOperatorKey
  try {
    return Invoke-RestMethod `
      -Method GET `
      -Uri "$GatewayBaseUrl$Path" `
      -Headers @{ "x-orbi-pay-operator-key" = $operatorKey } `
      -TimeoutSec 20
  } finally {
    Remove-Variable operatorKey -ErrorAction SilentlyContinue
  }
}

function Invoke-GatewayOperatorPost([string]$Path) {
  $operatorKey = Get-GatewayOperatorKey
  $bodyFile = [System.IO.Path]::GetTempFileName()
  try {
    $statusCodeText = & curl.exe `
      -sS `
      -o $bodyFile `
      -w "%{http_code}" `
      -X POST `
      "$GatewayBaseUrl$Path" `
      -H "Content-Type: application/json" `
      -H "x-orbi-pay-operator-key: $operatorKey" `
      --data "{}"
    if ($LASTEXITCODE -ne 0) {
      throw "curl operator POST failed for $Path."
    }
    $body = Get-Content -LiteralPath $bodyFile -Raw -ErrorAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($body)) {
      throw "Operator POST $Path returned HTTP $statusCodeText with an empty body."
    }
    return $body | ConvertFrom-Json
  } finally {
    Remove-Variable operatorKey -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $bodyFile -Force -ErrorAction SilentlyContinue
  }
}

function Get-OtcFromValkey([string]$RequestId) {
  $redisPassword = Get-ValkeyPassword
  try {
    $raw = docker exec -e REDISCLI_AUTH=$redisPassword orbi-valkey redis-cli GET "otp:$RequestId"
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($raw)) {
      throw "OTC request '$RequestId' was not found in Valkey."
    }
    $payload = $raw | ConvertFrom-Json
    if (-not $payload.code) {
      throw "OTC payload for '$RequestId' did not include a code."
    }
    return [string]$payload.code
  } finally {
    Remove-Variable redisPassword -ErrorAction SilentlyContinue
  }
}

function Invoke-NoRedirectForm([string]$Uri, [hashtable]$Body) {
  $headersFile = [System.IO.Path]::GetTempFileName()
  $bodyFile = [System.IO.Path]::GetTempFileName()
  try {
    $curlArgs = @(
      "-sS",
      "-D", $headersFile,
      "-o", $bodyFile,
      "-w", "%{http_code}",
      "-X", "POST",
      $Uri,
      "-H", "Content-Type: application/x-www-form-urlencoded",
      "--max-redirs", "0"
    )
    foreach ($key in $Body.Keys) {
      $curlArgs += "--data-urlencode"
      $curlArgs += "$key=$($Body[$key])"
    }
    $statusCodeText = & curl.exe @curlArgs
    if ($LASTEXITCODE -ne 0) {
      throw "curl challenge request failed."
    }
    $headers = @{}
    foreach ($line in Get-Content -LiteralPath $headersFile) {
      if ($line -match "^([^:]+):\s*(.*)$") {
        $headers[$Matches[1]] = $Matches[2].Trim()
      }
    }
    [pscustomobject]@{
      StatusCode = [int]$statusCodeText
      Headers = $headers
      Body = Get-Content -LiteralPath $bodyFile -Raw -ErrorAction SilentlyContinue
    }
  } finally {
    Remove-Item -LiteralPath $headersFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $bodyFile -Force -ErrorAction SilentlyContinue
  }
}

function Get-HeaderValue($Headers, [string]$Name) {
  if ($Headers.ContainsKey($Name)) {
    $value = $Headers[$Name]
    if ($value -is [array]) {
      return [string]$value[0]
    }
    return [string]$value
  }
  return $null
}

function Invoke-NodeJson([string]$Script, [string]$WorkingDirectory) {
  Push-Location $WorkingDirectory
  try {
    $output = $Script | node --input-type=module
    if ($LASTEXITCODE -ne 0) {
      throw "Node smoke step failed."
    }
    $jsonLine = ($output | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Last 1)
    if (-not $jsonLine) {
      throw "Node smoke step returned no JSON output."
    }
    return $jsonLine | ConvertFrom-Json
  } finally {
    Pop-Location
  }
}

function Assert-NoBadLogs([datetime]$StartedAtUtc) {
  $sinceSeconds = [Math]::Max(30, [int]([datetime]::UtcNow - $StartedAtUtc).TotalSeconds + 15)
  $badPatterns = @(
    "core_service_payment_event_failed",
    "PAY_SERVICE_NOT_REGISTERED",
    "INVALID_WORKER_SIGNATURE",
    "MERCHANT_CONTEXT_REQUIRED",
    "PLATFORM_FEE_CONFIG_REQUIRED",
    "ORBI_CORE_CALLBACK_TIMEOUT"
  )
  $containers = @("orbi-pay-gateway-sandbox", "orbi-core-sandbox")
  foreach ($container in $containers) {
    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
      $logs = & docker logs --since "${sinceSeconds}s" $container 2>&1 | Out-String
    } finally {
      $ErrorActionPreference = $previousErrorActionPreference
    }
    foreach ($pattern in $badPatterns) {
      if ($logs -match [regex]::Escape($pattern)) {
        throw "Sandbox log scan found '$pattern' in $container logs."
      }
    }
  }
  Write-Output "Sandbox log scan OK"
}

function Assert-WebhookDelivery([string]$IntentId) {
  $deliveryResponse = Invoke-GatewayOperator "/v1/developer/webhook-deliveries?intentId=$IntentId"
  if (-not $deliveryResponse.success) {
    throw "Webhook delivery query failed for intent $IntentId."
  }
  $deliveries = @($deliveryResponse.data)
  $completedDelivery = $deliveries | Where-Object {
    $_.eventType -eq "payment_intent.updated" -and
    $_.payload.paymentIntent.status -eq "completed"
  } | Select-Object -First 1
  if (-not $completedDelivery) {
    throw "No completed payment_intent.updated webhook delivery record found for intent $IntentId."
  }
  if (-not $completedDelivery.deliveryId -or -not $completedDelivery.callbackUrl -or -not $completedDelivery.status) {
    throw "Webhook delivery record for intent $IntentId is missing replay evidence."
  }
  $script:LastCompletedWebhookDeliveryId = $completedDelivery.deliveryId
  Write-Output "Webhook delivery recorded: status=$($completedDelivery.status) deliveryId=$($completedDelivery.deliveryId)"
}

function Assert-WebhookReplay([string]$DeliveryId) {
  if ([string]::IsNullOrWhiteSpace($DeliveryId)) {
    throw "Webhook replay assertion requires a delivery id."
  }
  $replayResponse = Invoke-GatewayOperatorPost "/v1/developer/webhook-deliveries/$DeliveryId/replay"
  if (-not $replayResponse.data -or -not $replayResponse.data.deliveryId) {
    throw "Webhook replay did not return replay delivery evidence for $DeliveryId."
  }
  if ($replayResponse.data.replayOf -ne $DeliveryId) {
    throw "Webhook replay record did not preserve replayOf lineage for $DeliveryId."
  }
  Write-Output "Webhook replay recorded: status=$($replayResponse.data.status) deliveryId=$($replayResponse.data.deliveryId)"
}

Assert-Command "docker"
Assert-Command "node"
Assert-Command "curl.exe"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$gatewayRepoFull = Resolve-RepoPath $GatewayRepoPath
$fixtureFull = Resolve-RepoPath $FixturePath
$sandboxDirectory = Join-Path $repoRoot ".sandbox"
$intentOutputPath = Join-Path $sandboxDirectory "last-sandbox-smoke-intent.json"
$finalOutputPath = Join-Path $sandboxDirectory "last-sandbox-smoke-final.json"

$startedAtUtc = [datetime]::UtcNow

if ($EnsureContainers) {
  & (Join-Path $PSScriptRoot "start-core-sandbox.ps1")
  & (Join-Path $PSScriptRoot "start-pay-gateway-sandbox.ps1")
  Start-Sleep -Seconds 5
}

if ($SeedFixtures) {
  $seedArgs = @{}
  if ($RotateSecrets) {
    $seedArgs["RotateSecrets"] = $true
  }
  & (Join-Path $PSScriptRoot "seed-sandbox-fixtures.ps1") @seedArgs | Out-Host
}

Invoke-JsonHealth "Core sandbox" $CoreHealthUrl
Invoke-JsonHealth "Pay Gateway sandbox" "$GatewayBaseUrl/health"

if (-not (Test-Path -LiteralPath $fixtureFull)) {
  throw "Fixture file not found at $fixtureFull. Run this script with -SeedFixtures -RotateSecrets."
}

$sdkEntry = Join-Path $gatewayRepoFull "sdk\node\dist\index.js"
if (-not (Test-Path -LiteralPath $sdkEntry)) {
  throw "Node SDK build was not found at $sdkEntry. Build the Pay Gateway Node SDK before running the smoke test."
}

New-Item -ItemType Directory -Path $sandboxDirectory -Force | Out-Null

$env:ORBI_SMOKE_FIXTURE_PATH = [string](Resolve-Path $fixtureFull)
$env:ORBI_SMOKE_INTENT_PATH = $intentOutputPath
$env:ORBI_SMOKE_GATEWAY_BASE_URL = $GatewayBaseUrl
$env:ORBI_SMOKE_AMOUNT = [string]$Amount

$createScript = @'
import { createOrbi } from './sdk/node/dist/index.js';
import { readFileSync, writeFileSync } from 'node:fs';

const fixture = JSON.parse(readFileSync(process.env.ORBI_SMOKE_FIXTURE_PATH, 'utf8').replace(/^\uFEFF/, ''));
if (!fixture.apiKey) {
  throw new Error('SANDBOX_API_KEY_MISSING: run seed-sandbox-fixtures.ps1 with -RotateSecrets');
}

const orbi = createOrbi({
  baseUrl: process.env.ORBI_SMOKE_GATEWAY_BASE_URL,
  serviceKey: fixture.apiKey,
  environment: 'Demo',
});

const identity = await orbi.identity.resolve({
  identifier: fixture.demoUsers?.[0]?.phone || '+255700000101',
  metadata: {
    sandbox: true,
    smokeTest: true,
  },
}, {
  environment: 'Demo',
  idempotencyKey: `sandbox-identity:${Date.now()}`,
});
if (!identity.success) {
  throw new Error(`SANDBOX_IDENTITY_LOOKUP_FAILED:${identity.error || identity.message || 'unknown'}`);
}

const reference = `SANDBOX-SMOKE-${Date.now()}`;
const amount = Number(process.env.ORBI_SMOKE_AMOUNT || 1500);
const response = await orbi.payments.checkout({
  operation: 'collection',
  paymentCategory: 'orbi',
  paymentRail: 'orbi_wallet',
  reference,
  amount,
  currency: 'TZS',
  description: 'Sandbox PaySafe smoke checkout',
  returnUrl: 'https://shop.orbifinancial.com/checkout/orbi/return',
  customer: {
    type: 'user',
    name: fixture.demoUsers?.[0]?.name || 'Daniel Zakaria Sandbox',
    phone: fixture.demoUsers?.[0]?.phone || '+255700000101',
  },
  metadata: {
    sandbox: true,
    smokeTest: true,
    merchantId: fixture.merchantId,
    serviceCode: fixture.serviceCode,
  },
}, {
  environment: 'Demo',
  idempotencyKey: `sandbox-smoke:${reference}`,
  requestId: `sandbox-smoke-${reference}`,
});

writeFileSync(process.env.ORBI_SMOKE_INTENT_PATH, JSON.stringify({ reference, response }, null, 2));

const data = response.data || {};
const challenge = data.coreResult?.challenge || {};
console.log(JSON.stringify({
  success: response.success,
  reference,
  intentId: data.id,
  status: data.status,
  challengeMode: data.challengeMode,
  otcRequestId: challenge.metadata?.otcRequestId || null,
  challengeId: challenge.challengeId || null,
  coreStatus: data.coreStatus || null,
  identityResolved: identity.success,
  error: response.error || null,
  message: response.message || null,
}));
'@

$created = Invoke-NodeJson $createScript $gatewayRepoFull
if (-not $created.success) {
  throw "Checkout create failed. $($created.error) $($created.message)"
}
if (-not $created.intentId) {
  throw "Checkout did not return an intent id. Status=$($created.status)"
}
Write-Output "Checkout intent created: $($created.intentId) status=$($created.status)"

# The deterministic sandbox simulator may complete a success scenario directly.
# When a policy requests strong customer authentication, it returns the hosted
# OTC challenge instead. Both paths must reach the same completed, auditable
# intent state; only execute the browser-style approval for the latter.
if ($created.status -ne 'completed') {
  if (-not $created.otcRequestId -or -not $created.challengeId) {
    throw "Checkout requires an OTC challenge but none was returned. Intent=$($created.intentId) Status=$($created.status)"
  }

  $otc = Get-OtcFromValkey $created.otcRequestId
  $challengeUri = "$GatewayBaseUrl/v1/challenges/$($created.intentId)/respond"
  $challengeResponse = Invoke-NoRedirectForm $challengeUri @{
    challengeId = $created.challengeId
    decision = "approve"
    otcCode = $otc
  }

  $statusCode = [int]$challengeResponse.StatusCode
  $location = Get-HeaderValue $challengeResponse.Headers "Location"
  if ($statusCode -lt 300 -or $statusCode -ge 400) {
    throw "Hosted challenge did not redirect after approval. HTTP $statusCode"
  }
  if (-not $location -or ($location -notmatch "orbi_payment_status=approved")) {
    throw "Hosted challenge redirect did not report approved status."
  }
  Write-Output "Hosted challenge approved and redirected"
} else {
  Write-Output "Sandbox simulator completed the success scenario directly"
}

$env:ORBI_SMOKE_INTENT_ID = [string]$created.intentId
$env:ORBI_SMOKE_FINAL_PATH = $finalOutputPath

$finalScript = @'
import { createOrbi } from './sdk/node/dist/index.js';
import { readFileSync, writeFileSync } from 'node:fs';

const fixture = JSON.parse(readFileSync(process.env.ORBI_SMOKE_FIXTURE_PATH, 'utf8').replace(/^\uFEFF/, ''));
const orbi = createOrbi({
  baseUrl: process.env.ORBI_SMOKE_GATEWAY_BASE_URL,
  serviceKey: fixture.apiKey,
  environment: 'Demo',
});

let finalResponse = null;
for (let attempt = 0; attempt < 12; attempt += 1) {
  finalResponse = await orbi.payments.getIntent(process.env.ORBI_SMOKE_INTENT_ID);
  if (finalResponse.success && ['completed', 'failed', 'cancelled'].includes(finalResponse.data.status)) {
    break;
  }
  await new Promise((resolve) => setTimeout(resolve, 1000));
}

writeFileSync(process.env.ORBI_SMOKE_FINAL_PATH, JSON.stringify(finalResponse, null, 2));
const data = finalResponse?.data || {};
console.log(JSON.stringify({
  success: Boolean(finalResponse?.success),
  status: data.status || null,
  coreStatus: data.coreStatus || null,
  coreMessage: data.coreMessage || null,
  escrowId: data.coreResult?.escrow?.id || data.coreResult?.escrowId || null,
  error: finalResponse?.error || null,
  message: finalResponse?.message || null,
}));
'@

$final = Invoke-NodeJson $finalScript $gatewayRepoFull
if (-not $final.success -or $final.status -ne "completed") {
  throw "Payment intent did not complete. status=$($final.status) coreStatus=$($final.coreStatus) error=$($final.error) message=$($final.message)"
}

if (-not $SkipWebhookAssertion) {
  Assert-WebhookDelivery $created.intentId
  Assert-WebhookReplay $script:LastCompletedWebhookDeliveryId
}

if (-not $SkipNegativeTests) {
  $env:ORBI_SMOKE_NEGATIVE_PATH = (Join-Path $sandboxDirectory "last-sandbox-smoke-negative.json")
  $negativeScript = @'
import { createOrbi } from './sdk/node/dist/index.js';
import { readFileSync, writeFileSync } from 'node:fs';

const fixture = JSON.parse(readFileSync(process.env.ORBI_SMOKE_FIXTURE_PATH, 'utf8').replace(/^\uFEFF/, ''));
const baseUrl = process.env.ORBI_SMOKE_GATEWAY_BASE_URL;
const amount = Number(process.env.ORBI_SMOKE_AMOUNT || 1500);
const goodReturnUrl = 'https://shop.orbifinancial.com/checkout/orbi/return';
const badReturnUrl = 'https://evil.example.invalid/checkout/return';
const valid = createOrbi({ baseUrl, serviceKey: fixture.apiKey, environment: 'Demo' });
const invalid = createOrbi({ baseUrl, serviceKey: 'orbi_sk_demo_invalid_negative_test', environment: 'Demo' });

const basePayload = (reference, extra = {}) => ({
  operation: 'collection',
  paymentCategory: 'orbi',
  paymentRail: 'orbi_wallet',
  reference,
  amount,
  currency: 'TZS',
  description: 'Sandbox negative checkout',
  returnUrl: goodReturnUrl,
  customer: {
    type: 'user',
    name: fixture.demoUsers?.[0]?.name || 'Daniel Zakaria Sandbox',
    phone: fixture.demoUsers?.[0]?.phone || '+255700000101',
  },
  metadata: {
    sandbox: true,
    smokeNegativeTest: true,
    merchantId: fixture.merchantId,
    serviceCode: fixture.serviceCode,
  },
  ...extra,
});

const timestamp = Date.now();
const invalidKey = await invalid.payments.createIntent(basePayload(`SANDBOX-NEG-INVALID-KEY-${timestamp}`, { confirm: false }), {
  environment: 'Demo',
  idempotencyKey: `sandbox-neg-invalid-key:${timestamp}`,
});

const badRedirect = await valid.payments.createIntent(basePayload(`SANDBOX-NEG-BAD-REDIRECT-${timestamp}`, {
  confirm: false,
  returnUrl: badReturnUrl,
}), {
  environment: 'Demo',
  idempotencyKey: `sandbox-neg-bad-redirect:${timestamp}`,
});

const replayKey = `sandbox-neg-idempotent:${timestamp}`;
const replayReference = `SANDBOX-NEG-IDEMPOTENT-${timestamp}`;
const replayPayload = basePayload(replayReference, { confirm: false });
const replayFirst = await valid.payments.createIntent(replayPayload, {
  environment: 'Demo',
  idempotencyKey: replayKey,
});
const replaySecond = await valid.payments.createIntent(replayPayload, {
  environment: 'Demo',
  idempotencyKey: replayKey,
});
const replayMismatch = await valid.payments.createIntent(basePayload(`${replayReference}-MISMATCH`, {
  confirm: false,
  amount: amount + 1,
}), {
  environment: 'Demo',
  idempotencyKey: replayKey,
});

// The sandbox simulator chooses the requested outcome deterministically. A
// simulated decline terminates in Core without creating a real customer OTC;
// customer challenges are exercised only through the live-grade Core path.
const declineReference = `SANDBOX-NEG-DECLINE-${timestamp}`;
const decline = await valid.payments.checkout(basePayload(declineReference, {
  metadata: {
    sandbox: true,
    smokeNegativeTest: true,
    merchantId: fixture.merchantId,
    serviceCode: fixture.serviceCode,
    simulationScenario: 'decline',
  },
}), {
  environment: 'Demo',
  idempotencyKey: `sandbox-neg-decline:${timestamp}`,
  requestId: `sandbox-neg-decline-${timestamp}`,
});
const results = {
  invalidKey: { success: invalidKey.success, error: invalidKey.error || null },
  badRedirect: { success: badRedirect.success, error: badRedirect.error || null },
  replay: {
    firstSuccess: replayFirst.success,
    secondSuccess: replaySecond.success,
    sameIntent: Boolean(replayFirst.success && replaySecond.success && replayFirst.data.id === replaySecond.data.id),
    mismatchSuccess: replayMismatch.success,
    mismatchError: replayMismatch.error || null,
  },
  decline: {
    success: Boolean(decline?.success),
    intentId: decline?.data?.id || null,
    status: decline?.data?.status || null,
    coreStatus: decline?.data?.coreStatus || null,
    error: decline?.error || null,
  },
};

writeFileSync(process.env.ORBI_SMOKE_NEGATIVE_PATH, JSON.stringify(results, null, 2));
console.log(JSON.stringify(results));
'@

  $negative = Invoke-NodeJson $negativeScript $gatewayRepoFull
  if ($negative.invalidKey.success -or $negative.invalidKey.error -ne "PAY_SERVICE_AUTH_FAILED") {
    throw "Invalid key negative test failed. error=$($negative.invalidKey.error)"
  }
  if ($negative.badRedirect.success -or $negative.badRedirect.error -ne "DEVELOPER_REDIRECT_URL_NOT_ALLOWED") {
    throw "Bad redirect negative test failed. error=$($negative.badRedirect.error)"
  }
  if (-not $negative.replay.firstSuccess -or -not $negative.replay.secondSuccess -or -not $negative.replay.sameIntent) {
    throw "Idempotency replay test failed."
  }
  if ($negative.replay.mismatchSuccess -or $negative.replay.mismatchError -ne "PAYMENT_INTENT_IDEMPOTENCY_MISMATCH") {
    throw "Idempotency mismatch negative test failed. error=$($negative.replay.mismatchError)"
  }
  if (-not $negative.decline.success -or -not $negative.decline.intentId -or $negative.decline.status -ne 'failed') {
    throw "Sandbox decline simulation did not produce the required failed terminal state. status=$($negative.decline.status) coreStatus=$($negative.decline.coreStatus) error=$($negative.decline.error)"
  }
  Write-Output "Negative tests OK"
}

if (-not $SkipLogScan) {
  Assert-NoBadLogs $startedAtUtc
}

Write-Output "SANDBOX_SMOKE_PASS"
Write-Output "reference=$($created.reference)"
Write-Output "intentId=$($created.intentId)"
Write-Output "status=$($final.status)"
Write-Output "coreStatus=$($final.coreStatus)"
Write-Output "coreMessage=$($final.coreMessage)"
