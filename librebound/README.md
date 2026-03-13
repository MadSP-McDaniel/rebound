# librebound

Core Go library for verifiable deployment state and rollback. Each transaction appends per-key direct leaves for data changes and then appends an authoritative current-view leaf last. The API covers updates, snapshots, rollback (full/selective), pruning, and audit verification.

## Model

Each change appends multiple leaves to the log:
- Direct per-key leaves: one leaf per key written (e.g., `ovm|{obj}|{j}`, `snap|{id}`, `deauth|…`, `log|{txid}`).
- Current-view leaf (authoritative S−1): encodes only the heads needed for decisions: `ovm-head|{obj} → {j}`, `deauth-obj-head|{obj}|{j} → 0/1`, and `deauth-snap-head|{id} → 0/1`. This leaf is appended last in the transaction and is the sole source used for gating and listing (no scanning).

Snapshots are stored as `snap|{id} → {obj: j}` in a per-key leaf. Rollback-to-snapshot re-materializes heads from that tag→set after checking the current-view gates. Selective rollback proves historical presence of each requested version by resolving `ovm|obj|j` via index and inclusion proof, then re-materializes heads if allowed. Pruning writes deauth tombstones and flips the corresponding current-view heads to deny future rollbacks.

## Namespaces (state map keys)

Direct leaves:
- `ovm|{obj}|{j}` → hex(SHA256(content)) stored in the content store
- `snap|{id}` → JSON map `{obj: j}` (tag→set of object heads at snapshot time)
- `deauth|snap|{id}|{c}` → snapshot de-authorization at counter `c` (with justification)
- `deauth|object|{obj}|{j}` → object-version de-authorization tombstone (with justification)
- `log|{txid}` → sha256 of audit lines persisted to audit.log for the same transaction

Current-view heads (authoritative, appended last each transaction):
- `ovm-head|{obj}` → `{j}`
- `deauth-obj-head|{obj}|{j}` → "0" or "1" (explicit; absence is never authorization)
- `deauth-snap-head|{id}` → "0" or "1"

Note: Removed legacy namespaces/behaviors: `head|{obj}` and any packed state leaf model. No legacy fallbacks or scans are used anywhere for gating or listing.

## Main APIs

```go
// New API instance
api, err := librebound.NewReboundAPI(storagePath, /* antispam */ false, signer, verifier, /* testing */ false)

// 1) State updates (single or batch)
_, _ = api.StateUpdate(ctx, key, value)
_, _ = api.StateUpdateBatch(ctx, map[string][]byte{"obj": bytes})

// 2) Snapshots (tag→set)
_, _ = api.TakeSnapshot(ctx, "snap-123")
tags, _ := api.ListSnapshots(ctx) // ["snap-123", ...]

// 3) Rollback (full or selective)
_, _ = api.RollbackToSnapshot(ctx, "snap-123", "incident justification")
_, _ = api.RollbackSelective(ctx, map[string]uint64{"obj": 1}, "targeted fix")

// 4) Prune
_, _ = api.PruneSnapshot(ctx, "snap-123", "retired")

// 5) Audit verification
ok, _ := api.VerifyAudit(ctx, "txid-42")
```

## Verification and guarantees

- Inclusion and freshness: all operations verify sealed, signed checkpoints; inclusion proofs bind fetched per-key leaves to the checkpoint root.
- Current-view is authoritative: listing and gating decisions consult only the latest current-view leaf appended last in the transaction; no scanning.
- Snapshot entry verification: `VerifyEntryInSnapshot(id, key, data)` resolves heads from `snap|id`, then fetches `ovm|key|j` via per-key leaf and compares hashes.
- Selective rollback presence proof: each `(obj,j)` is resolved via index and proved by inclusion before re-materialization.
- Audit binding: `VerifyAudit(txid)` resolves `log|{txid}` via per-key leaf and compares to recomputed digest from audit.log under the sealed checkpoint.
- Deauth gating: `deauth-snap-head|…` and `deauth-obj-head|…` in the current-view explicitly gate rollback; values are `0` (allowed) or `1` (denied). Absence is never authorization.
- Sealing & recovery: strict freshness policy with descendant-only advance, strict S−1 rewind, and counter-only mismatch hard-fail. Recovery reseals and double-increments.

## Quick test

```bash
go test ./...
```

<!-- What’s covered: direct per-key updates + authoritative current-view, tag→set snapshots, selective/full rollback with per-key presence proofs, pruning/deauth gating via current-view heads, lineage, audit verification (per-key), and recovery (double-increment reseal on freshness mismatch). -->

<!-- ## Migration notes

Breaking changes from any prior packed-state or legacy models:
- Per-key leaves are the only write model; the packed state leaf is removed.
- `head|{obj}` is replaced by `ovm-head|{obj}`; all gating/listing flows read from the current-view only.
- All `meta|*` keys are removed from enforcement; per-object provenance fields are not required for verifiability.
- Deauthorization is explicit via `deauth-obj-head|{obj}|{j}` and `deauth-snap-head|{id}`; values are `0/1`; absence is never authorization.
- Auditors resolve `log|{txid}` via per-key leaf; no previous-leaf reads are required. -->
