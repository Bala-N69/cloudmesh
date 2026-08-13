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
- Privilege escalation is disabled and Linux capabilities are dropped.
- The root filesystem is read-only; only the NGINX runtime directories are
  mounted as temporary writable volumes.
- A default-deny NetworkPolicy restricts ingress to explicitly selected
  CloudMesh pods.
- CPU and memory requests/limits are set.
- A startup probe gives the container up to one minute to become available
  before readiness and liveness checks begin.
- Health probes call a dedicated `/healthz` endpoint that returns `ok`, rather
  than treating any successful page response as a health signal.
- Rolling updates keep existing Pods available while one replacement Pod starts;
  Kubernetes reports a stalled rollout after two minutes.
- A PodDisruptionBudget requires at least one healthy Pod during voluntary
  disruptions such as a planned node drain.

## Validate without a cluster

If `kubectl` is installed, render the development configuration locally:

```bash
kubectl kustomize kubernetes/overlays/dev
```

This command only renders YAML; it does not create a cluster or deploy
anything.

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
