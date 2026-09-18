# Kubernetes lab

This directory contains a secure, local-first Kubernetes deployment for
CloudMesh. It is a learning and validation environment: applying it requires a
cluster you control, but creating or reading these files does not use a cloud
account.

## Layout

- `base/` contains the reusable application manifests.
- `overlays/dev/` creates a small development variant with one replica; CI
  validates that this lightweight setting is retained.

The base applies a few deliberate security defaults:

- The container runs as an unprivileged user.
- The workload uses a deliberately versioned `nginx-unprivileged` image rather
  than a floating `latest` tag, and validation prevents accidental image drift.
- Pods use the `RuntimeDefault` seccomp profile, which applies the container
  runtime's default system-call filtering.
- The namespace requests the `restricted` Pod Security Standard, so clusters
  with Pod Security Admission enabled reject non-compliant Pods.
- Pods use a dedicated service account, with token mounting disabled because
  this static demo does not need Kubernetes API access.
- Privilege escalation is disabled and Linux capabilities are dropped.
- The root filesystem is read-only; only the NGINX runtime directories are
  mounted as temporary writable volumes.
- The NGINX configuration adds `nosniff`, `DENY` framing, and no-referrer
  response headers for the static demo endpoint.
- A default-deny NetworkPolicy restricts ingress to explicitly selected
  CloudMesh pods and blocks all egress from this static demo application.
- The Service uses `ClusterIP`, keeping the demo reachable only from within the
  cluster unless an explicit exposure method is added later.
- CPU and memory requests/limits are set.
- Ephemeral-storage requests and limits are set, and each writable NGINX
  runtime volume has a size cap to prevent temporary files from exhausting a
  node's local disk.
- A `LimitRange` supplies conservative CPU and memory defaults for any future
  containers in the namespace, while a `ResourceQuota` bounds the small lab to
  five Pods, 500m requested CPU, 512Mi requested memory, and 1 CPU/1Gi memory
  in total limits.
- A startup probe gives the container up to one minute to become available
  before readiness and liveness checks begin, with a two-second timeout for
  each probe attempt.
- Health probes call a dedicated `/healthz` endpoint that returns `ok`, rather
  than treating any successful page response as a health signal. All probes
  time out after two seconds; readiness and liveness mark the container
  unhealthy after three failed checks.
- Rolling updates keep existing Pods available while one replacement Pod starts;
  a replacement must remain healthy for 10 seconds before it is considered
  available, and Kubernetes reports a stalled rollout after two minutes.
- Replicas are spread across nodes when capacity permits, avoiding a single-node
  concentration without preventing a small development cluster from scheduling
  the workload.
- Pods have a 30-second termination grace period so NGINX can finish active
  requests when a rollout or voluntary disruption removes a replica.
- A PodDisruptionBudget requires at least one healthy Pod during voluntary
  disruptions such as a planned node drain.

## Validate without a cluster

If `kubectl` is installed, render the development configuration locally:

```bash
kubectl kustomize kubernetes/overlays/dev
```

This command only renders YAML; it does not create a cluster or deploy
anything.

To render the overlay and verify the key security defaults used in this lab:

```bash
bash scripts/validate-kubernetes.sh
```

For usage information, run `bash scripts/validate-kubernetes.sh --help`
(or `-h`). Help exits 0 without requiring `kubectl` or creating temporary
files. Unsupported arguments exit 2 before rendering, so a typo or an
unsupported overlay name cannot silently run development checks.

The command above uses a path relative to the repository root. From another
folder, pass the script's absolute path to `bash`; the script locates the
development overlay relative to its own location. For example, from this
`kubernetes/` folder, run `bash ../scripts/validate-kubernetes.sh`.

The script ignores shell `CDPATH` settings while resolving its repository
root. This prevents directory-search output from corrupting the overlay path
when the script is invoked using a relative path. A regression test exercises
this case with controlled renderer output and checks the exact overlay argument.

It requires `kubectl` on your
`PATH`; if it is missing, the script exits with a clear prerequisite message
before creating temporary files. You can also use the GitHub Actions
Kubernetes validation job, which sets up `kubectl` for the runner.

The script checks that the rendered manifests retain the NetworkPolicy,
restricted Pod Security enforcement, dedicated service account with token
mounting disabled, non-root and read-only filesystem settings, default-deny
egress behavior, the one-replica development overlay, privilege-escalation and capability restrictions, rollout
stability and availability settings, internal-only service exposure,
`RuntimeDefault` seccomp, health-probe timeouts and failure thresholds, CPU and
memory resource bounds, all writable-volume size caps, the approved container
image, response-security headers, a 30-second termination grace period, and
PodDisruptionBudget. It does not connect to or change a cluster.

Required settings are matched as complete lines after trimming surrounding
whitespace, with an optional YAML list-item marker (`- `). This accepts fields
that Kustomize places first in a list item, such as `- image: ...`, while
still checking the exact value. This prevents values such as `replicas: 10` from satisfying
`replicas: 1`, and prevents a commented NGINX header from passing. The egress
prohibition remains a substring check so inline forms such as `egress: []`
are still rejected.

These are text guardrails, not a YAML schema or per-resource policy engine.
They also require the `/healthz` probe path, container port `8080`, and the
`http` port name and reference to remain present. This catches accidental
removal or replacement of those endpoint settings. It does not verify every
individual probe or resolve port references between resources.
A matching setting elsewhere in the rendered output can still satisfy a
requirement. Semantic validation will be needed as the lab gains workloads.

The standard Python test suite includes validator regression tests using
controlled renderer output, so it runs without `kubectl` or a cluster:

```bash
python3 -m unittest discover -s tests -p test_kubernetes_validator.py -v
```

Those tests cover matching and failure behavior; the Kubernetes Actions job
separately checks the real Kustomize output.

The validator's exit trap removes its temporary rendered manifest on normal
success and error exits. Regression tests use a dedicated temporary directory
and verify cleanup before the test harness removes that directory, including
renderer errors, empty output, and rejected settings. They also check that an
unrelated fixture file survives. This does not cover forced termination such
as `SIGKILL`, which cannot run an exit trap.

If temporary-file creation fails, validation exits 1 before invoking Kustomize.
The original system error is preserved alongside a message to check temporary
directory permissions and available disk space. Fix the local storage issue
and rerun validation; this is not a manifest policy failure.

If rendering fails, the validator preserves the renderer's error and reports
that the development overlay could not be rendered. A failed renderer cannot
pass even if it emitted valid-looking content first. Empty or whitespace-only
output receives a separate `rendered no content` error before policy checks.
These failures exit 1, making CI failures easier to distinguish from a missing
security setting.

## Apply to a local cluster later

When a local Kubernetes cluster is available, apply the development overlay:

```bash
kubectl apply -k kubernetes/overlays/dev
kubectl get all -n cloudmesh-dev
```

To remove the local lab again:

```bash
kubectl delete -k kubernetes/overlays/dev
```
