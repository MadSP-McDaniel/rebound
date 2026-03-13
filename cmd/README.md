# Servers

Two HTTP servers wrap the `librebound` library:

- `prod-server`: full Tessera-backed integration
- `simple-server`: mock for local testing

Start one:

```bash
cd cmd/prod-server && go build . && ./prod-server
# or
cd cmd/simple-server && go build . && ./simple-server
```

Common HTTP surface (mirrors library operations; each write appends a single authoritative state leaf):

- `GET /health`
- `POST /api/v1/deployment/update`
- `POST /api/v1/deployment/snapshot`
- `GET /api/v1/snapshots`
- `POST /api/v1/rollback/initiate`
- `POST /api/v1/snapshot/prune` (retire a snapshot; prevents future rollbacks)
- `GET /api/v1/verify/{snapshot_id}/{key}`

Run the end-to-end workflow script once a server is running:

```bash
cd tests && ./test_end_to_end_workflow.sh
```

Use `prod-server` for verifiable runs; use `simple-server` for quick local checks.*** End Patch
