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

docker compose --profile direct-edge --env-file "${env_file}" -f "${compose}" pull --ignore-buildable
docker compose --profile direct-edge --env-file "${env_file}" -f "${compose}" build --pull core
# Core is released independently. Gateway has its own deployment lifecycle and must not be recreated by a Core release.
docker compose --profile direct-edge --env-file "${env_file}" -f "${compose}" up -d --no-deps core

echo "Waiting for Core health..."
for _ in $(seq 1 60); do
  if docker compose --profile direct-edge --env-file "${env_file}" -f "${compose}" exec -T core \
    node -e "fetch('http://127.0.0.1:3000/ready').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"; then
    docker compose --profile direct-edge --env-file "${env_file}" -f "${compose}" ps
    echo "ORBI deployment is healthy."
    exit 0
  fi
  sleep 5
done

docker compose --profile direct-edge --env-file "${env_file}" -f "${compose}" ps
docker compose --profile direct-edge --env-file "${env_file}" -f "${compose}" logs --tail=200 core postgres valkey
echo "Deployment did not become ready." >&2
exit 1
