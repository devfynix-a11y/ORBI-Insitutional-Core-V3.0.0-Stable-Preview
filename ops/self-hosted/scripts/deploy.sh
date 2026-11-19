#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
compose="${root}/ops/self-hosted/docker-compose.prod.yml"
env_file="${ORBI_CORE_ENV_FILE:-${root}/ops/self-hosted/.env.production}"

export ORBI_CORE_ENV_FILE="${env_file}"

bash "${root}/ops/self-hosted/scripts/validate-deployment.sh"

if [[ "${ORBI_SKIP_RELEASE_GATE:-false}" != "true" ]]; then
  evidence_file="${ORBI_RELEASE_GATE_EVIDENCE:-${root}/ops/self-hosted/.release-gate/core-release-gate.json}"
  current_sha="$(git -C "${root}" rev-parse HEAD)"

  if [[ ! -f "${evidence_file}" ]]; then
    echo "Release gate evidence not found: ${evidence_file}" >&2
    echo "Run ops/self-hosted/scripts/release-gate.ps1 before deployment, or set ORBI_SKIP_RELEASE_GATE=true only for a documented incident diagnostic." >&2
    exit 1
  fi

  node -e "
    const fs = require('fs');
    const evidencePath = process.argv[1];
    const expectedSha = process.argv[2];
    const evidence = JSON.parse(fs.readFileSync(evidencePath, 'utf8'));
    if (evidence.service !== 'orbi-core') {
      throw new Error('Release gate evidence service mismatch.');
    }
    if (evidence.commitSha !== expectedSha) {
      throw new Error('Release gate evidence is for ' + evidence.commitSha + ', expected ' + expectedSha + '.');
    }
    if (evidence.sandboxGateSkipped) {
      throw new Error('Release gate evidence was created with sandbox gate skipped.');
    }
    console.log('Release gate evidence OK for ' + expectedSha);
  " "${evidence_file}" "${current_sha}"
else
  echo "WARNING: ORBI_SKIP_RELEASE_GATE=true. Deployment is bypassing sandbox release evidence." >&2
fi

# Some hosts still run the established self-hosted stack. Its Core container is
# attached to named live networks; release into that project instead of creating
# a parallel Compose project with empty DNS/service discovery.
compose_args=(--profile direct-edge --env-file "${env_file}" -f "${compose}")
existing_project="$(docker inspect orbi-core --format '{{ index .Config.Labels "com.docker.compose.project" }}' 2>/dev/null || true)"
if [[ "${existing_project}" == "self-hosted" ]]; then
  legacy_env_file="${root}/.env"
  [[ -f "${legacy_env_file}" ]] || { echo "Existing self-hosted Core is missing ${legacy_env_file}." >&2; exit 1; }
  compose_args=(
    -p self-hosted
    --env-file "${legacy_env_file}"
    -f "${root}/ops/self-hosted/docker-compose.dev.yml"
    -f "${root}/ops/self-hosted/Auth_Security/docker-compose.yml"
    -f "${root}/ops/self-hosted/Storage/docker-compose.yml"
  )
  echo "Deploying Core into the established self-hosted live stack."
fi

if [[ "${ORBI_CORE_REFRESH_BASE_IMAGE:-false}" == "true" ]]; then
  docker compose "${compose_args[@]}" build --pull core
else
  docker compose "${compose_args[@]}" build core
fi
# Core is released independently. Gateway has its own deployment lifecycle and must not be recreated by a Core release.
docker compose "${compose_args[@]}" up -d --no-deps core
echo "Waiting for Core health..."
for _ in $(seq 1 60); do
  if docker compose "${compose_args[@]}" exec -T core \
    node -e "fetch('http://127.0.0.1:3000/ready').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"; then
    docker compose "${compose_args[@]}" ps
    echo "ORBI deployment is healthy."
    exit 0
  fi
  sleep 5
done

docker compose "${compose_args[@]}" ps
docker compose "${compose_args[@]}" logs --tail=200 core postgres valkey
echo "Deployment did not become ready." >&2
exit 1
