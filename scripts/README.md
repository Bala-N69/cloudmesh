# One-command local demo

Run `bash scripts/run-demo.sh` from any directory to scan the bundled synthetic
GCP and Kubernetes examples. It writes a new Markdown report under your temporary
directory and prints its location. A simulated HIGH-severity CI gate is expected
to fail; the script exits successfully only after verifying that result. It does
not upload the report or create cloud resources.
