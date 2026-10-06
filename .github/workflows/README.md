# CloudMesh Sentinel checks

The workflow runs scanner tests, container integration tests, Kubernetes manifest
validation, and Python security analysis. It runs on main-branch pushes, pull
requests targeting main, manual dispatch, and the daily schedule.

## Overlapping runs

Concurrency is grouped by workflow, event type, and Git ref:

- A newer pull-request run cancels an older run for the same PR. A cancellation
  in this case is intentional; check the newest run for the result.
- Scheduled, manual, and push runs do not interrupt an already running run in
  their group. GitHub keeps at most one pending run per group; a newer pending
  run replaces an older pending run.
- Different event types and different PRs remain independent.

This avoids redundant overlapping work within a group. It does not change the
four check names, permissions, or test coverage, and does not guarantee hosted
runner availability. Jobs within a run still execute in parallel.

## Hosted runner acquisition failures

If a job has no executed steps and reports
`The job was not acquired by Runner of type hosted even after multiple attempts`,
GitHub could not assign a hosted runner. This is different from a test failure;
changing application code or adding retries inside job steps cannot fix a job
that never starts.

Check GitHub Status for Actions incidents, then use **Re-run failed jobs** on the
affected run once service is healthy. If that option is unavailable for a
cancelled job, use **Re-run all jobs**. If steps did execute, inspect their logs
instead of assuming the same infrastructure issue. Repeated acquisition failures
should be investigated with GitHub support using the run URL and annotations.

No automatic reruns or additional write permissions are configured.
