# ORBI Environment Separation Runbook

This runbook keeps ORBI Core, ORBI Pay Gateway, sandbox, and Developer Portal configuration separated. Secrets must not be committed.

## Service Ownership

| Service | Runtime env owner | Notes |
| --- | --- | --- |
| ORBI Core | `D:\FYNIX\ORBI\SECREATES\ORBI CORE ENV.txt` | Core banking, wallets, ledger, auth, realtime, notifications. |
| Pay Gateway Live | `D:\FYNIX\ORBI\SECREATES\ORBI PAY GATEWAY LIVE ENV.txt` | Production BaaS/Open Banking gateway runtime. |
| Pay Gateway Sandbox | `D:\FYNIX\ORBI\SECREATES\ORBI PAY GATEWAY SANDBOX ENV.txt` | Isolated sandbox simulator and demo gateway runtime. |
| Developer Portal | `D:\FYNIX\ORBI\SECREATES\ORBI PAY DEVELOPER PORTAL VARIABLES.txt` | Vercel/BFF variables only. No database URL and no gateway bootstrap secrets. |

## Rules

- Core and Pay Gateway must not share one catch-all `.env` for runtime operations.
- Portal must never connect directly to PostgreSQL or internal databases.
- Portal must call `/api/portal/*`, and the BFF must proxy to Pay Gateway `/v1/portal/*`.
- Pay Gateway live and sandbox must run as separate services with separate env files.
- Sandbox must use sandbox database, sandbox operator key, sandbox worker key, and sandbox merchant credentials.
- Live must use production database, production operator key, production worker key, and production merchant credentials.

## Deploy Pay Gateway Live

```powershell
$compose = "D:\FYNIX\ORBI\ORBI CORE\ORBI-Insitutional-Core-V2.0.4-Preview Stable\ops\self-hosted\Pay_Gateway\docker-compose.yml"
docker compose --profile live -f $compose config --quiet
docker compose --profile live -f $compose up -d --build pay-gateway
```

## Deploy Pay Gateway Sandbox

```powershell
$compose = "D:\FYNIX\ORBI\ORBI CORE\ORBI-Insitutional-Core-V2.0.4-Preview Stable\ops\self-hosted\Pay_Gateway\docker-compose.yml"
docker compose --profile sandbox -f $compose config --quiet
docker compose --profile sandbox -f $compose up -d --build pay-gateway-sandbox
```

## Health Checks

```powershell
Invoke-WebRequest http://127.0.0.1:3100/health -UseBasicParsing
Invoke-WebRequest http://127.0.0.1:3101/health -UseBasicParsing
Invoke-WebRequest https://pay.orbifinancial.com/health -UseBasicParsing
Invoke-WebRequest https://sandbox-pay.orbifinancial.com/health -UseBasicParsing
```

## Portal Connectivity

The portal uses these server-side Vercel variables:

```text
ORBI_PAY_GATEWAY_SANDBOX_BASE_URL=https://sandbox-pay.orbifinancial.com
ORBI_PAY_GATEWAY_LIVE_BASE_URL=https://pay.orbifinancial.com
ORBI_PORTAL_SANDBOX_OPERATOR_KEY=<same value as sandbox PAYMENT_GATEWAY_OPERATOR_DISCOVERY_API_KEY>
ORBI_PORTAL_LIVE_OPERATOR_KEY=<same value as live PAYMENT_GATEWAY_OPERATOR_DISCOVERY_API_KEY>
```

The portal uses these browser-safe variables:

```text
VITE_ORBI_PAY_GATEWAY_BASE_URL=https://sandbox-pay.orbifinancial.com
VITE_ORBI_PORTAL_BFF_BASE_URL=/api/portal
VITE_ORBI_PORTAL_ENVIRONMENT=sandbox
```

Do not add `DATABASE_URL`, `PAYMENT_GATEWAY_PORTAL_*`, `JWT_SECRET`, worker signing secrets, or merchant API keys to the portal frontend environment.

## Audit Checklist

- `docker ps` should show `orbi-pay-gateway` and `orbi-pay-gateway-sandbox` under project `pay_gateway`.
- Gateway containers should have compose service labels.
- `/v1/portal/snapshot` should return JSON with `success=true` when called through the BFF/operator key.
- Vercel 502 usually means Gateway route is not deployed or returned non-JSON.
- Vercel 403 usually means portal operator key does not match the target Gateway environment.
## Enforced Runtime Boundary

| Environment | Public Core URL | Public Pay Gateway URL | Signed header |
| --- | --- | --- | --- |
| Live | `https://api.orbifinancial.com` | `https://pay.orbifinancial.com` | `x-orbi-environment: live` |
| Sandbox | `https://sandbox-api.orbifinancial.com` | `https://sandbox-pay.orbifinancial.com` | `x-orbi-environment: sandbox` |

The edge overwrites the environment header from the hostname. Internal Core/Gateway requests include the environment inside the HMAC canonical payload. Each receiver compares it with its configured runtime and rejects missing, changed, or cross-environment requests. Core sandbox runs as `core-sandbox` on an isolated Docker network and requires independent database, Valkey, object-storage, worker-signing, and mTLS credentials. Never point `ORBI_CORE_SANDBOX_DATABASE_URL`, `ORBI_CORE_SANDBOX_VALKEY_URL`, or sandbox storage variables at live infrastructure.
