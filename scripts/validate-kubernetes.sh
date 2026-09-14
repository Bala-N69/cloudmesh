#!/usr/bin/env bash

# Render the development overlay and check the security defaults that the lab
# is expected to demonstrate. This does not apply anything to a cluster.
set -euo pipefail

if ! command -v kubectl >/dev/null 2>&1; then
  echo "Kubernetes validation requires kubectl on PATH. Install kubectl or use the GitHub Actions Kubernetes validation job." >&2
  exit 1
fi

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

rendered_manifest="$(mktemp)"
trap 'rm -f "$rendered_manifest"' EXIT

# Ignore indentation and trailing whitespace, but retain complete values and
# comment markers. pipefail preserves renderer errors through normalization.
if ! kubectl kustomize "$repo_root/kubernetes/overlays/dev" |
  sed 's/^[[:space:]]*//; s/[[:space:]]*$//' > "$rendered_manifest"; then
  echo "Kubernetes validation failed: could not render the development overlay. See the renderer error above." >&2
  exit 1
fi

if ! grep -q '[^[:space:]]' "$rendered_manifest"; then
  echo "Kubernetes validation failed: the development overlay rendered no content." >&2
  exit 1
fi

require_manifest_text() {
  local expected="$1"

  # Kustomize may place this field first in a YAML list item ("- image:").
  # Accept that marker while still requiring the entire field/value to match.
  if ! grep -Fxq -e "$expected" -e "- $expected" -- "$rendered_manifest"; then
    echo "Kubernetes validation failed: missing $expected" >&2
    exit 1
  fi
}

forbid_manifest_text() {
  local unexpected="$1"

  if grep -Fq -- "$unexpected" "$rendered_manifest"; then
    echo "Kubernetes validation failed: unexpected $unexpected" >&2
    exit 1
  fi
}

require_manifest_text "kind: NetworkPolicy"
require_manifest_text "kind: Service"
require_manifest_text "type: ClusterIP"
require_manifest_text "replicas: 1"
require_manifest_text "- Egress"
forbid_manifest_text "egress:"
require_manifest_text "pod-security.kubernetes.io/enforce: restricted"
require_manifest_text "serviceAccountName: cloudmesh-demo"
require_manifest_text "automountServiceAccountToken: false"
require_manifest_text "runAsNonRoot: true"
require_manifest_text "seccompProfile:"
require_manifest_text "type: RuntimeDefault"
require_manifest_text "allowPrivilegeEscalation: false"
require_manifest_text "- ALL"
require_manifest_text "readOnlyRootFilesystem: true"
require_manifest_text "image: nginxinc/nginx-unprivileged:1.27-alpine"
require_manifest_text 'add_header X-Content-Type-Options "nosniff" always;'
require_manifest_text 'add_header X-Frame-Options "DENY" always;'
require_manifest_text 'add_header Referrer-Policy "no-referrer" always;'
require_manifest_text "minReadySeconds: 10"
require_manifest_text "maxUnavailable: 0"
require_manifest_text "maxSurge: 1"
require_manifest_text "progressDeadlineSeconds: 120"
require_manifest_text "startupProbe:"
require_manifest_text "path: /healthz"
require_manifest_text "containerPort: 8080"
require_manifest_text "name: http"
require_manifest_text "port: http"
require_manifest_text "timeoutSeconds: 2"
require_manifest_text "failureThreshold: 12"
require_manifest_text "failureThreshold: 3"
require_manifest_text "terminationGracePeriodSeconds: 30"
require_manifest_text "kind: PodDisruptionBudget"
require_manifest_text "kind: LimitRange"
require_manifest_text "kind: ResourceQuota"
require_manifest_text "cpu: 50m"
require_manifest_text "memory: 64Mi"
require_manifest_text "cpu: 200m"
require_manifest_text "memory: 128Mi"
require_manifest_text "ephemeral-storage: 128Mi"
require_manifest_text "sizeLimit: 64Mi"
require_manifest_text "sizeLimit: 16Mi"
require_manifest_text "sizeLimit: 32Mi"

echo "Kubernetes manifest security checks passed."
