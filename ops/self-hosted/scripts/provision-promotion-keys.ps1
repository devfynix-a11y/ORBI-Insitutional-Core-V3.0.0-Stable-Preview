param(
  [string]$EnvFile = "ops\self-hosted\.env.production",
  [string]$SandboxGatewayEnvFile = "D:\FYNIX\ORBI\SECREATES\ORBI PAY GATEWAY SANDBOX ENV.txt",
  [string]$LiveGatewayEnvFile = "D:\FYNIX\ORBI\SECREATES\ORBI PAY GATEWAY LIVE ENV.txt"
)

$ErrorActionPreference = 'Stop'

function Set-EnvValue([string]$Path, [string]$Key, [string]$Value) {
  $content = Get-Content -LiteralPath $Path -Raw
  $pattern = "(?m)^" + [regex]::Escape($Key) + "=.*(?:\r?\n|$)"
  $line = "$Key=$Value`r`n"
  if ($content -match $pattern) {
    $content = [regex]::Replace($content, $pattern, $line)
  } else {
    $content = $content.TrimEnd() + "`r`n$line"
  }
  Set-Content -LiteralPath $Path -Value $content -NoNewline -Encoding ASCII
}

function Remove-EnvValue([string]$Path, [string]$Key) {
  $content = Get-Content -LiteralPath $Path -Raw
  $pattern = "(?m)^" + [regex]::Escape($Key) + "=.*(?:\r?\n|$)"
  Set-Content -LiteralPath $Path -Value ([regex]::Replace($content, $pattern, '')) -NoNewline -Encoding ASCII
}

function Get-EnvValue([string]$Path, [string]$Key) {
  $match = [regex]::Match((Get-Content -LiteralPath $Path -Raw), "(?m)^" + [regex]::Escape($Key) + "=(.+)$")
  if ($match.Success) { return $match.Groups[1].Value.Trim() }
  return $null
}

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
  throw 'Node.js is required to provision the Ed25519 promotion key pair.'
}

$envPath = [System.IO.Path]::GetFullPath((Join-Path (Get-Location) $EnvFile))
$sandboxEnvPath = [System.IO.Path]::GetFullPath($SandboxGatewayEnvFile)
$liveEnvPath = [System.IO.Path]::GetFullPath($LiveGatewayEnvFile)
foreach ($path in @($envPath, $sandboxEnvPath, $liveEnvPath)) {
  if (-not (Test-Path -LiteralPath $path)) { throw "Required environment file was not found at $path." }
}

if (-not (Get-EnvValue $envPath 'ORBI_SECRET_ENCRYPTION_KEY')) {
  $gatewayEnv = docker inspect orbi-pay-gateway --format '{{json .Config.Env}}' | ConvertFrom-Json
  $gatewaySecret = $gatewayEnv | Where-Object { $_ -like 'ORBI_SECRET_ENCRYPTION_KEY=*' } | Select-Object -First 1
  if (-not $gatewaySecret) { throw 'ORBI_SECRET_ENCRYPTION_KEY is absent from both the production env file and the running live gateway.' }
  Set-EnvValue $envPath 'ORBI_SECRET_ENCRYPTION_KEY' ($gatewaySecret -replace '^ORBI_SECRET_ENCRYPTION_KEY=', '')
}

$privateValue = Get-EnvValue $sandboxEnvPath 'PAYMENT_GATEWAY_PROMOTION_SIGNING_PRIVATE_KEY'
if (-not $privateValue) {
  $generated = @'
const { generateKeyPairSync } = require('node:crypto');
const { privateKey } = generateKeyPairSync('ed25519', {
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  publicKeyEncoding: { type: 'spki', format: 'pem' },
});
process.stdout.write(privateKey.trim().replace(/\n/g, '\\n'));
'@ | node -
  if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($generated)) { throw 'Node.js could not generate the promotion signing key.' }
  $privateValue = $generated.Trim()
  Set-EnvValue $sandboxEnvPath 'PAYMENT_GATEWAY_PROMOTION_SIGNING_PRIVATE_KEY' $privateValue
}

$publicValue = @'
const { createPrivateKey, createPublicKey } = require('node:crypto');
const privateKey = process.argv[2].replace(/\\n/g, '\n');
process.stdout.write(createPublicKey(createPrivateKey(privateKey)).export({ type: 'spki', format: 'pem' }).trim().replace(/\n/g, '\\n'));
'@ | node - $privateValue
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($publicValue)) { throw 'Node.js could not derive the promotion verification key.' }
$publicValue = $publicValue.Trim()

# A signing key is valid only in the sandbox environment. The two live
# configurations receive the matching public key, and any accidental private
# key in the Core deployment file is removed.
Set-EnvValue $liveEnvPath 'PAYMENT_GATEWAY_PROMOTION_VERIFICATION_PUBLIC_KEY' $publicValue
Set-EnvValue $envPath 'PAYMENT_GATEWAY_PROMOTION_VERIFICATION_PUBLIC_KEY' $publicValue
Remove-EnvValue $envPath 'PAYMENT_GATEWAY_PROMOTION_SIGNING_PRIVATE_KEY'

Write-Output 'Promotion keys verified: sandbox retains the private key and live configurations receive only the matching public key.'
