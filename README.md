<p align="center">
  <img src="./rebound_logo.png" alt="Rebound Logo" width="300"/>
</p>

[![DOI](https://zenodo.org/badge/1180968297.svg)](https://doi.org/10.5281/zenodo.19009015)



Rebound is a framework that provides secure version controls for data stored in the cloud. It can be integrated into applications or used as a standalone service to provide a trust anchor (i.e., a hardware-rooted, cryptographic source of truth over data integrity and freshness) for arbitrary cloud applications. It is built on Tessera transparency logs. It is targeted specifically for cloud applications running inside trusted execution environments that require high assurance over data integrity and freshness; Rebound itself is also designed to run in such an environment. For a quick start with our GitLab CI benchmarks, skip to `Quickstart` below. Reference:

```
@inproceedings{bvs+26,
    title={{It's a Feature, Not a Bug: Secure and Auditable State Rollback for Confidential Cloud Applications}},
    booktitle={{2026 IEEE Symposium on Security and Privacy (S\&P)}},
    author={Burke, Quinn and Vahldiek-Oberwagner, Anjo and Swift, Michael and McDaniel, Patrick},
    month={may},
    year={2026}
}
```

## Layout

```
rebound/
├── librebound/   # Core library APIs
├── cmd/          # HTTP servers (prod-server, simple-server)
└── tests/        # Unit + end-to-end tests
```

## Pre-requisites
- Docker (for micro-benchmarks) and Docker Compose (for macro-benchmarks)
<!-- - Ubuntu 24.04 LTS (not tested on other OSes but should work with minor tweaks)
- Go 1.24
- Docker (for macro-benchmarking)
- Python3 + matplotlib for plotting benchmark results: `sudo apt update && sudo apt -y install python3 python3-matplotlib python3-pandas python3-seaborn` -->
- After cloning this repo, run:
    - `git submodule update --init --recursive` to initialize submodules
    - `go mod tidy` in all subdirs to clean up Go module dependencies

<!-- - After cloning this repo, set `REBOUND_HOME` env var to the absolute path of the `rebound/` directory (either export it in your shell or shell profile). -->

<!-- ## How it works (high level)

- Direct/per-key leaves model: each change appends per-key state leaves (OVM entries like `ovm|{obj}|{j}`), an audit leaf, and a compact "current-view" leaf for gating; not a single packed JSON state leaf.
- Snapshots are tag→set mappings (`snap|{id} → {obj: counter}`) recorded in the state.
- Rollback composes a heads-only overlay to a prior snapshot; selective rollback targets a subset of objects. Pruning retires a snapshot and blocks future rollbacks to it.

## Core library APIs (librebound)

- `StateUpdate(...)` / `StateUpdateBatch(...)`: record deployment state
- `TakeSnapshot(ctx, snapshotID)`: create a rollback point
- `RollbackToSnapshot(ctx, snapshotID, justification)`: rollback to a snapshot
- `RollbackSelective(ctx, snapshotID, objects, justification)`: rollback selected objects
- `PruneSnapshot(ctx, snapshotID, justification)`: retire a snapshot with audit/deauth tombstone -->

<!-- Basic usage lives in `librebound/README.md` with a tiny code sample. -->

<!-- ## Servers

- `prod-server`: wraps the library with a JSON HTTP API
- `simple-server`: mock for local testing

Start one quickly:

```bash
cd cmd/prod-server && go build . && ./prod-server
# or
cd cmd/simple-server && go build . && ./simple-server
```

Then try `tests/test_end_to_end_workflow.sh`. -->

## Tests

Two types:
- `librebound` unit tests: single-leaf updates, verification, heads-only/selective rollback with presence proofs, pruning/deauth gating, and recovery (double-increment reseal)
	<!-- - Now uses direct/per-key leaves (OVM entries) and verifies inclusion of per-key leaves plus the "current-view" leaf for gating; includes heads-only/selective rollback, pruning/deauth gating, and recovery (double-increment reseal) -->
- `tests/` end-to-end: server API workflow and snapshot lifecycle

Run all tests:
```bash
docker run -it -v .:/rebound mcr.microsoft.com/devcontainers/go:1-1.24-bookworm
(enter container shell)
REBOUND_HOME=/rebound
cd $REBOUND_HOME && ./setup.sh
mkdir -p o

cd tests && ./test_all.sh
```

Note: This is a research prototype focused on clarity and verifiability; production deployments should add full TPM integration.

## Micro-benchmark: Measuring local Rebound library/API performance
Run microbenchmarks by varying parameters such as the number of objects to version, how many updates to do, how many snapshots to take, etc.
```bash
docker run -it -v .:/rebound mcr.microsoft.com/devcontainers/go:1-1.24-bookworm
(enter container shell)
REBOUND_HOME=/rebound
cd $REBOUND_HOME && ./setup.sh
mkdir -p o

cd bench/microbench
# Run `go run microbench.go --help` for details on the flags; example:
go run microbench.go --sizes=25 --updates=1 --trials=1 --measure-storage=true --obj-bytes=1 --query-sample=25 --prune-keep=25 --skip-prune-bench=true --work=../../o/tessera --out=../../o/micro
python3 plot_bench.py ../../o/micro --prefix=test --obj-bytes=1 --prune-keep=25
```

## Macro-benchmark: Local GitLab CI (Compose + GitLab Runner + Rebound)

This section describes a local macrobenchmark that measures CI/CD overhead using a GitLab CE instance, a Docker executor runner, and a local Rebound service. Everything is orchestrated via Docker Compose in `rebound/bench/macrobench`.

### Stack overview

- GitLab CE (HTTP at `http://${GITLAB_EXTERNAL_HOST}:8089` on the host, `http://gitlab:8089` on the compose network), where GITLAB_EXTERNAL_HOST=<IP_ADDR or localhost>
- GitLab Runner (Docker executor) attached to the compose network
- Rebound prod-server (`rebound` service) reachable from CI jobs as `http://rebound:8080`
- A sample project with a GitLab CI pipeline that performs state updates and maintenance actions against Rebound

### Quickstart

1) Start the stack

```bash
cd rebound/bench/macrobench
GITLAB_EXTERNAL_HOST=<IP_ADDR or localhost> docker compose up -d
# Then visit http://${GITLAB_EXTERNAL_HOST}:8089 in a web browser

# Optional: wait for GitLab to be ready
curl -sf http://${GITLAB_EXTERNAL_HOST}:8089/users/sign_in >/dev/null && echo ready

```

2) Create and register a runner (new GitLab Runner workflow)

- Open http://${GITLAB_EXTERNAL_HOST}:8089 and sign in as root.
	- Credentials: username `root`, password `xY-7ab_!zPq-R9` (or whatever value you set for `initial_root_password` in the Compose file)
- Admin Area → CI/CD → Runners → New runner
	- Create an instance (or project) runner
    - Assign the tag `local` to the runner in the UI (Admin → Runners → your runner → Edit).
	- Copy the Runner authentication token (glrt-…)

Register and configure the runner via bootstrap (required):

```bash
cd rebound/bench/macrobench
./bootstrap.sh --runner-token glrt-PASTE_TOKEN_HERE
```

Make sure all docker containers are running:
```bash
docker compose ps
```

Notes on bootstrap:
- The bootstrap script registers the runner inside the existing `gitlab-runner` container, sets `runners.docker.network_mode = "macrobench_ci_net"`, restarts the container, mints a PAT, creates/pushes the sample project, and writes `.macrobench.env`.
- With Runner v18+, tags and other properties are managed on the server side. Make sure to assign the tag `local` to the runner in the UI (Admin → Runners → your runner → Edit).
- It always mints a fresh Personal Access Token for the root user programmatically (via gitlab-rails), validates it against the API, and saves it in `./.macrobench.env` as `export GITLAB_PAT=...`.
- It creates or reuses a `sample-app` project and performs the initial Git push using the PAT (required for Git over HTTP).
- Make sure there isn't a mismatch with 'protected' branch scoping - if the pipeline is running on a protected branch, runners (instance-wide or project-wide) must be configured to be allowed to run on protected branches, otherwise they might not pick up the jobs.

3) Run the macrobenchmark

```bash
DEBUG={0,1} USE_REBOUND={0,1} TRIALS=n ./run.sh    # finds the project, pushes commits, triggers maintenance jobs, writes results.csv
# You can monitor the active Gitlab pipelines for the repo (e.g., http://${GITLAB_EXTERNAL_HOST}:8089/root/sample-app/-/pipelines) to see the run.sh script in action.
```

Plot macrobenchmark results (writes PDFs next to the CSVs, typically under $REBOUND_HOME/o):
```bash
cd bench/macrobench
# Outputs go to $REBOUND_HOME/o by default
python3 plot_results.py <macro results dir>
```

Notes on run.sh:
- If a job fails (i.e., the script reports a failure, or you observe a failure in the GitLab web interface), check that all containers are running (`docker compose ps`), check the runner logs (`docker logs gitlab-runner`), and check the job logs in the GitLab web interface for further details to debug.
- It always sources `./.macrobench.env` if present so values in that file (e.g., `GITLAB_PAT`) override any existing environment variables.
- CI jobs are tagged `[local]`; ensure your runner has tag `local`.

### Clean-up

```bash
cd rebound/bench/macrobench
docker compose down -v
```

<!-- ### Pipeline jobs

The sample pipeline (in `rebound-sample-workloads/.gitlab-ci.yml`) communicates with the Rebound service at `http://rebound:8080` (service name and port on the Compose network).

- Per-workload state update jobs (`sample_state_update`, `llama2_state_update`, `sqlite_state_update`)
	- Stage: `deploy`
	- Triggers: automatically on push when workload files change
	- Does: POST `/api/v1/deployment/update` with repository, commit_sha, image_digest (placeholder), actor, workflow_id

- create_snapshot
	- Stage: `maintenance`
	- Triggers: manual (Play in UI or via API)
	- Variables required: `SNAPSHOT_ID`, `JUSTIFICATION`
	- Does: POST `/api/v1/deployment/snapshot`, prints response and exposes a `ROLLBACK_TOKEN`

- rollback
	- Stage: `maintenance`
	- Triggers: manual
	- Variables required: `SNAPSHOT_ID`, `JUSTIFICATION`
	- Variables optional: `ROLLBACK_TOKEN`
	- Does: POST `/api/v1/rollback/initiate`

- prune_snapshot
	- Stage: `maintenance`
	- Triggers: manual
	- Variables required: `SNAPSHOT_ID`, `JUSTIFICATION`
	- Does: POST `/api/v1/snapshot/prune`

- audit_lineage
	- Stage: `audit`
	- Triggers: manual
	- Variables optional: `OBJECT` (defaults to `$REPOSITORY`)
	- Does: GET `/api/v1/lineage/{object}` on the Rebound server and prints a JSON report and a concise table to the job log

Outputs and data locations:
- Service data: stored in the Docker named volume mounted at `/data` inside the `rebound` container (not bind-mounted to the host).
- Host-visible outputs: written under `$REBOUND_HOME/o` on the host. The macrobenchmark compose binds the repo's `o/` folder into the container at `/rebound-home/o`. -->

### Pipeline variables

- `DEPLOYMENT_SERVER_URL` (default: `http://rebound:8080`)
- `REPOSITORY` (default: `$CI_PROJECT_PATH`)
- `ACTOR` (default: `$GITLAB_USER_LOGIN`)
- Job-specific variables as noted above

### Troubleshooting

- Auth errors on git push (HTTP Basic: Access denied): ensure the push URL uses `root:<PAT>@...` and that the PAT is valid and not expired. Bootstrap handles this automatically.
- Runner cannot reach services: ensure `runners.docker.network_mode = "macrobench_ci_net"` and the runner container was restarted after config changes.
- GitLab URL mismatch: host access uses `http://${GITLAB_EXTERNAL_HOST}:8089`; services on the compose network use `http://gitlab:8089`.
- PAT verification: `curl -sS -o /dev/null -w "%{http_code}\n" --header "PRIVATE-TOKEN: $GITLAB_PAT" http://${GITLAB_EXTERNAL_HOST}:8089/api/v4/user` should return `200`.

## Notes
- This benchmark assumes you are running the local Docker Compose stack that includes the `rebound` service on the same Docker network as GitLab Runner, so `http://rebound:8080` is reachable from CI jobs.
- Our examples do not use Sigstore/cosign for image signing, as Rebound already authenticates pipeline outputs (in addition to other things).
- We have a Tessera submodule because we needed to modify the `minCheckpointInterval` in `tessera/storage/posix/files.go` to be lower than the default 1 second.
- In `rebound_api.go`, we also make sure to set the `interval` when calling `WithCheckpointInterval` (which sets the timer tick for kicking off checkpointing events) and set the `maxAge` when calling `WithBatching` (which sets the time limit for leaf sequencing, which is related to I/O operations, separate from checkpointing).
<!-- - We set all three of these (`minCheckpointInterval`, `interval`, and `maxAge`) to `time.Nanosecond` (1 ns) in our experiments to make sure the Tessera timer is not a bottleneck. -->