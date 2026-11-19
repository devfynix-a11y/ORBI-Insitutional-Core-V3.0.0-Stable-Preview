param(
    [switch]$AllowWrites
)

$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
Set-Location $root

# Financial integration tests must never infer the live `orbi` database from
# .env. The committed test env is bound to the dedicated disposable database
# and the Node runner revalidates that guard before it starts a write test.
$testEnv = Join-Path $root '.env.test.local'
if (-not (Test-Path $testEnv)) {
    throw 'Missing .env.test.local. Refusing to run financial tests without the dedicated disposable database environment.'
}

node scripts/run-db-financial-tests.mjs --mode read --env $testEnv
if ($LASTEXITCODE -ne 0 -or -not $AllowWrites) {
    exit $LASTEXITCODE
}

node scripts/run-db-financial-tests.mjs --mode write --env $testEnv --allow-write-fixture --confirm-disposable-database
exit $LASTEXITCODE
