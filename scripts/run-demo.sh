#!/usr/bin/env bash
set -eu

# Run the bundled synthetic GCP/Kubernetes review without external services.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
report="$(mktemp "${TMPDIR:-/tmp}/cloudmesh-demo.XXXXXX.md")"

status=0
if (cd "$repo_root" && python3 -m cloudmesh_sentinel.batch \
    examples/batch-demo.json --format markdown --fail-on high) > "$report"; then
  status=0
else
  status=$?
fi

if [ "$status" -ne 1 ]; then
  printf 'Demo scan failed (exit %s); incomplete report: %s\n' "$status" "$report" >&2
  exit "$status"
fi

printf 'Demo report: %s\n' "$report"
printf 'CI gate: FAIL as expected (synthetic HIGH findings).\n'
printf 'Preview: sed -n "1,80p" "%s"\n' "$report"
