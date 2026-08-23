#!/usr/bin/env bash

# Render the development overlay and check the security defaults that the lab
# is expected to demonstrate. This does not apply anything to a cluster.
set -euo pipefail

rendered_manifest="$(mktemp)"
trap 'rm -f "$rendered_manifest"' EXIT

kubectl kustomize kubernetes/overlays/dev > "$rendered_manifest"

require_manifest_text() {
  local expected="$1"

  if ! grep -Fq -- "$expected" "$rendered_manifest"; then
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
require_manifest_text "- Egress"
forbid_manifest_text "egress:"
require_manifest_text "serviceAccountName: cloudmesh-demo"
require_manifest_text "automountServiceAccountToken: false"
require_manifest_text "runAsNonRoot: true"
require_manifest_text "readOnlyRootFilesystem: true"
require_manifest_text "minReadySeconds: 10"
require_manifest_text "kind: PodDisruptionBudget"
require_manifest_text "kind: LimitRange"
require_manifest_text "kind: ResourceQuota"
require_manifest_text "ephemeral-storage: 128Mi"
require_manifest_text "sizeLimit: 64Mi"

echo "Kubernetes manifest security checks passed."
