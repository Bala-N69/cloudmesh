#!/usr/bin/env bash

# Render the development overlay and check the security defaults that the lab
# is expected to demonstrate. This does not apply anything to a cluster.
set -euo pipefail

usage() {
  echo "Usage: bash scripts/validate-kubernetes.sh [--help|-h]"
  echo "Render the development overlay with kubectl and check lab guardrails."
  echo "Requires kubectl on PATH. Does not connect to or deploy to a cluster."
}

if [[ "$#" -eq 1 && ( "$1" == "--help" || "$1" == "-h" ) ]]; then
  usage
  exit 0
fi
if [[ "$#" -ne 0 ]]; then
  echo "Kubernetes validation: unexpected arguments." >&2
  usage >&2
  exit 2
fi

if ! command -v kubectl >/dev/null 2>&1; then
  echo "Kubernetes validation requires kubectl on PATH. Install kubectl or use the GitHub Actions Kubernetes validation job." >&2
  exit 1
fi

# CDPATH can make cd print a directory, corrupting the captured root path.
for required_tool in dirname mktemp rm sed grep; do
  if ! command -v "$required_tool" >/dev/null 2>&1; then
    echo "Kubernetes validation requires $required_tool on PATH. Restore the system utilities before retrying." >&2
    exit 1
  fi
done

# Resolve only after verifying the tools needed for rendering and cleanup.
repo_root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

if ! rendered_manifest="$(mktemp)"; then
  echo "Kubernetes validation failed: could not create a temporary manifest. Check temporary-directory permissions and available disk space." >&2
  exit 1
fi
trap 'rm -f "$rendered_manifest"' EXIT

# Ignore indentation and trailing whitespace, but retain complete values and
# comment markers. pipefail preserves renderer errors through normalization.
if ! kubectl kustomize "$repo_root/kubernetes/overlays/dev" |
  sed 's/^[[:space:]]*//; s/[[:space:]]*$//' > "$rendered_manifest"; then
  echo "Kubernetes validation failed: could not render the development overlay. See the renderer error above." >&2
  exit 1
fi

# Comments and document boundaries alone do not contain a workload to check.
if ! grep -Eqv '^($|#|---([[:space:]]|$)|[.][.][.]([[:space:]]|$))' "$rendered_manifest"; then
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
  else
    local search_status=$?
    # Only exit 1 means the forbidden setting was successfully checked and absent.
    if [[ "$search_status" -ne 1 ]]; then
      echo "Kubernetes validation failed: could not check forbidden setting $unexpected (grep exit $search_status)." >&2
      exit 1
    fi
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
