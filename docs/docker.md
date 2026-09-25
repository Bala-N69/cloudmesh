# Run Sentinel in Docker

This packages the existing CLI, not a web service. It opens no ports and needs
no cloud credentials or project. Install and start a Docker-compatible engine
separately before following this guide. Run commands from the repository root.

## Build and run

```bash
docker build --pull -t cloudmesh-sentinel:local .
docker run --rm --network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges cloudmesh-sentinel:local
docker run --rm --network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges cloudmesh-sentinel:local examples/safe-plan.json --format json --fail-on medium
docker run --rm --network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges cloudmesh-sentinel:local examples/demo-plan.json --fail-on high
```

The default command prints help. The safe plan exits 0; the demo intentionally
exits 1 because it contains HIGH findings. Invalid input exits 2. These are the
same CLI exit codes as running Python directly. A Docker engine/startup error
is not a scanner finding.

Building needs network access to retrieve the Python base image. Running the
scanner does not. The `python:3.12-slim` tag is mutable: this setup is not yet
digest-pinned or vulnerability-scanned. No image is published by these commands.

## Scan a separate file

Place a synthetic plan at `/tmp/cloudmesh-plan.json`, then mount only that file:

```bash
docker run --rm --network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --mount type=bind,source=/tmp/cloudmesh-plan.json,target=/input/plan.json,readonly \
  cloudmesh-sentinel:local /input/plan.json --format json --fail-on high
```

The source file must exist and be readable by container UID/GID `10001:10001`.
Do not loosen permissions on sensitive files just to run this example. Do not
mount credentials, the Docker socket, or the whole home directory. Real plans
may contain secrets; keep them out of the repository and build context.

## Security boundaries and tests

The image runs as numeric non-root UID/GID `10001:10001`. It copies only scanner
source and three named synthetic examples. `.dockerignore` excludes everything
else by default, including Git history, local configuration, and future files.
The runtime flags above disable networking, writable root storage, Linux
capabilities, and privilege escalation. They are runtime options, not guarantees
provided by the Dockerfile alone.

After building the image, run the opt-in integration tests:

```bash
CLOUDMESH_DOCKER_TEST_IMAGE=cloudmesh-sentinel:local python3 -m unittest discover -s tests -p test_container.py -v
```

They verify help, safe/risky exit codes and JSON output, and non-root identity
under the hardened runtime options. They never build or pull images. Without
the environment variable, the normal Python suite skips these four tests;
a passing default suite does not prove the container builds or runs.

## GitHub Actions

The `Build and test Sentinel container` job builds `cloudmesh-sentinel:ci` on
an Ubuntu runner and sets `CLOUDMESH_DOCKER_TEST_IMAGE` to enable all four tests.
Build or test failures fail the job. The image remains on the temporary runner:
there is no registry login, image push, deployment, or cloud credential usage.
The job has a ten-minute timeout and read-only repository permissions.

It uses the existing workflow triggers: pull requests targeting `main`, pushes
to `main`, the daily schedule, and manual runs. A feature-branch push alone
does not trigger this workflow unless it updates an open pull request. Wait
for this container job to succeed before treating the image as verified;
the separate Python job still skips the opt-in container tests.
