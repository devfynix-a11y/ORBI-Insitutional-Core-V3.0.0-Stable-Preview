#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
compose="${root}/ops/self-hosted/docker-compose.prod.yml"
env_file="${ORBI_CORE_ENV_FILE:-${root}/ops/self-hosted/.env.production}"

export ORBI_CORE_ENV_FILE="${env_file}"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

command -v docker >/dev/null 2>&1 || fail "Docker is not installed."
docker compose version >/dev/null 2>&1 || fail "Docker Compose plugin is unavailable."
[[ -f "${env_file}" ]] || fail "Missing ${env_file}. Run generate-secrets.sh."

# Never source an environment file: values may legally contain spaces and must
# remain data, never shell input. Docker Compose receives the same file through
# --env-file below; this helper is only for structural validation.
env_value() {
  local key="$1"
  awk -v key="$key" 'index($0, key "=") == 1 { value = substr($0, length(key) + 2) } END { print value }' "${env_file}"
}

required=(
  JWT_SECRET KMS_MASTER_KEY WORKER_SECRET WORKER_SIGNING_SECRET
  ORBI_MONITOR_API_KEY ORBI_POSTGRES_PASSWORD ORBI_VALKEY_PASSWORD
  ORBI_STORAGE_ROOT_PASSWORD ORBI_GRAFANA_ADMIN_PASSWORD
  ORBI_TLS_CERT_DIRECTORY ORBI_MONITOR_KEY_FILE
  ORBI_BACKUP_ENCRYPTION_KEY
  ORBI_KEYCLOAK_PUBLIC_URL ORBI_KEYCLOAK_ADMIN_USERNAME
  ORBI_KEYCLOAK_ADMIN_PASSWORD
)
for key in "${required[@]}"; do
  [[ -n "$(env_value "${key}")" ]] || fail "Required value ${key} is empty."
done

edge_tls_mode="$(env_value ORBI_EDGE_TLS_MODE)"
edge_tls_mode="${edge_tls_mode:-cloudflare_tunnel}"
tls_cert_directory="$(env_value ORBI_TLS_CERT_DIRECTORY)"
monitor_key_file="$(env_value ORBI_MONITOR_KEY_FILE)"
if [[ "${edge_tls_mode}" != "cloudflare_tunnel" ]]; then
  [[ -f "${tls_cert_directory}/fullchain.pem" ]] || fail "TLS fullchain.pem is missing."
  [[ -f "${tls_cert_directory}/privkey.pem" ]] || fail "TLS privkey.pem is missing."
fi
host_path() {
  local path="$1"
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -u "${path}"
  else
    printf '%s\n' "${path}"
  fi
}

monitor_key_host_path="$(host_path "${monitor_key_file}")"
[[ -f "${monitor_key_host_path}" ]] || fail "Prometheus monitor-key file is missing."
backup_host_directory="$(env_value ORBI_BACKUP_HOST_DIRECTORY)"
backup_host_directory="${backup_host_directory:-/srv/orbi/backups/database}"
backup_host_path="$(host_path "${backup_host_directory}")"
[[ -d "${backup_host_path}" ]] || fail "Backup host directory is missing."
[[ -d "$(dirname "${monitor_key_host_path}")" ]] || fail "Monitor-key parent directory is missing."

docker compose --env-file "${env_file}" -f "${compose}" config --quiet

published="$(
  docker compose --env-file "${env_file}" -f "${compose}" config \
    | awk '/published:/{print $2}'
)"
for port in ${published}; do
  port="${port#\"}"
  port="${port%\"}"
  case "${port}" in
    80|443|9090|3000|3001|3100|3101|5433) ;;
    *) fail "Unexpected published port: ${port}" ;;
  esac
done

if grep -Eq '^(SUPABASE_URL|SUPABASE_SERVICE_ROLE_KEY|SUPABASE_ANON_KEY)=$' "${env_file}" \
  && grep -q '^ORBI_DATA_PROVIDER=supabase$' "${env_file}"; then
  fail "ORBI_DATA_PROVIDER=supabase but Supabase compatibility credentials are empty."
fi

if grep -q '^ORBI_DATA_PROVIDER=local$' "${env_file}" \
  && ! grep -q '^ORBI_LOCAL_DATA_PRODUCTION_READY=true$' "${env_file}"; then
  fail "Local financial-data mode is blocked until ORBI_LOCAL_DATA_PRODUCTION_READY=true."
fi

if grep -q '^ORBI_AUTH_PROVIDER=keycloak$' "${env_file}"; then
  grep -q '^ORBI_KEYCLOAK_PUBLIC_URL=https://' "${env_file}" \
    || fail "Production Keycloak must use an HTTPS public URL."
fi

echo "Deployment configuration is structurally valid."
