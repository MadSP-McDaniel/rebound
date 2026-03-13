# Rollback Test Suite

Tests cover the core library and the server workflow at a high level.

## What to run

```bash
# Unit tests for the library
cd ../librebound && go test ./...

# End-to-end workflow against a running server
cd ../tests && ./test_end_to_end_workflow.sh

# Everything (unit + e2e helper)
cd tests && ./test_all.sh
```

## What’s validated

- Single-leaf updates and verification helpers
- Snapshots (tag→set) and listing
- Rollback to a snapshot and selective rollback (with presence proofs)
- Pruning lifecycle and deauth gating
- Freshness/recovery policy (double-increment reseal)
