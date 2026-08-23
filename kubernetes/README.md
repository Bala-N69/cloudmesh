# Kubernetes lab

This directory contains a secure, local-first Kubernetes deployment for
CloudMesh. It is a learning and validation environment: applying it requires a
cluster you control, but creating or reading these files does not use a cloud
account.

## Layout

- `base/` contains the reusable application manifests.
- `overlays/dev/` creates a small development variant with one replica.

The base applies a few deliberate security defaults:

- The container runs as an unprivileged user.
- Pods use a dedicated service account, with token mounting disabled because
  this static demo does not need Kubernetes API access.
- Privilege escalation is disabled and Linux capabilities are dropped.
- The root filesystem is read-only; only the NGINX runtime directories are
  mounted as temporary writable volumes.
- A default-deny NetworkPolicy restricts ingress to explicitly selected
  CloudMesh pods and blocks all egress from this static demo application.
- CPU and memory requests/limits are set.
- Ephemeral-storage requests and limits are set, and each writable NGINX
  runtime volume has a size cap to prevent temporary files from exhausting a
  node's local disk.
- A `LimitRange` supplies conservative CPU and memory defaults for any future
  containers in the namespace, while a `ResourceQuota` bounds the small lab to
  five Pods, 500m requested CPU, 512Mi requested memory, and 1 CPU/1Gi memory
  in total limits.
- A startup probe gives the container up to one minute to become available
  before readiness and liveness checks begin.
- Health probes call a dedicated `/healthz` endpoint that returns `ok`, rather
  than treating any successful page response as a health signal.
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

The script checks that the rendered manifests retain the NetworkPolicy,
dedicated service account with token mounting disabled, non-root and read-only
filesystem settings, rollout stability delay, and PodDisruptionBudget. It does
not connect to or change a cluster.

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
