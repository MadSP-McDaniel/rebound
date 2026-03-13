package librebound

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/transparency-dev/tessera"
	"golang.org/x/mod/sumdb/note"
)

// TestSingleLeafBehavior validates that mutations append exactly one state leaf
// and that IndexDB maps ovm keys to that leaf index; snapshots are tag→set with one leaf.
func TestSingleLeafBehavior(t *testing.T) {
	ctx := context.Background()

	dir, err := os.MkdirTemp("", "rebound-directleaves-")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	signerKey, verifierKey, err := note.GenerateKey(rand.Reader, "test")
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	signer, _ := note.NewSigner(signerKey)
	verifier, _ := note.NewVerifier(verifierKey)

	api, err := NewReboundAPI(dir, false, signer, verifier, true)
	if err != nil {
		t.Fatalf("NewReboundAPI failed: %v", err)
	}
	t.Cleanup(func() { _ = api.Close(ctx) })

	// Baseline checkpoint size
	sizeBefore, err := api.GetCheckpointSize(ctx)
	if err != nil {
		t.Fatalf("GetCheckpointSize baseline failed: %v", err)
	}

	// Single-object update → expect 4 new leaves (ovm + audit + current-view chunk + current-view head)
	_, err = api.StateUpdateBatch(ctx, map[string][]byte{"svc": []byte("A1")})
	if err != nil {
		t.Fatalf("StateUpdateBatch failed: %v", err)
	}

	sizeAfter, err := api.GetCheckpointSize(ctx)
	if err != nil {
		t.Fatalf("GetCheckpointSize after update failed: %v", err)
	}
	if got, want := int(sizeAfter-sizeBefore), 4; got != want {
		t.Fatalf("unexpected leaf count for update (ovm+audit+cv): got %d want %d (before=%d after=%d)", got, want, sizeBefore, sizeAfter)
	}

	// IndexDB should map ovm key to its per-key ovm leaf index, which is (sizeAfter - 4)
	stateIdx := sizeAfter - 4
	ctr := api.GetCurrentCounter()
	ovmKey := fmt.Sprintf("ovm|%s|%d", "svc", ctr)
	if idx, err := api.indexDB.GetIndex(ovmKey); err != nil || idx != stateIdx {
		t.Fatalf("Index for %s = %d err=%v, want %d", ovmKey, idx, err, stateIdx)
	}

	// Take a snapshot; expect four new leaves (snap|id + audit + current-view chunk + current-view head) and index for snap|id
	sizeBefore2 := sizeAfter
	if _, err := api.TakeSnapshot(ctx, "snap-1"); err != nil {
		t.Fatalf("TakeSnapshot failed: %v", err)
	}
	sizeAfter2, err := api.GetCheckpointSize(ctx)
	if err != nil {
		t.Fatalf("GetCheckpointSize after snapshot failed: %v", err)
	}
	if got, want := int(sizeAfter2-sizeBefore2), 4; got != want {
		t.Fatalf("unexpected leaf count for snapshot (snap+audit+cv): got %d want %d", got, want)
	}
	if idx, err := api.indexDB.GetIndex("snap|snap-1"); err != nil || idx != sizeAfter2-4 {
		t.Fatalf("index for snap|snap-1 = %d err=%v, want %d", idx, err, sizeAfter2-4)
	}
}

// TestAuditAndSnapshotVerification checks audit verification and snapshot membership under the single-leaf model.
func TestAuditAndSnapshotVerification(t *testing.T) {
	ctx := context.Background()

	dir, err := os.MkdirTemp("", "rebound-directleaves-verify-")
	if err != nil {
		t.Fatalf("mktemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	signerKey, verifierKey, err := note.GenerateKey(rand.Reader, "test")
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	signer, _ := note.NewSigner(signerKey)
	verifier, _ := note.NewVerifier(verifierKey)

	api, err := NewReboundAPI(dir, false, signer, verifier, true)
	if err != nil {
		t.Fatalf("NewReboundAPI: %v", err)
	}
	t.Cleanup(func() { _ = api.Close(ctx) })

	// Write two versions for object 'svc' so j>0
	if _, err := api.StateUpdate(ctx, "svc", []byte("V1")); err != nil {
		t.Fatalf("svc v1: %v", err)
	}
	if _, err := api.StateUpdate(ctx, "svc", []byte("V2")); err != nil {
		t.Fatalf("svc v2: %v", err)
	}
	// Determine head exists
	api.stateManager.mu.RLock()
	headJStr := string(api.stateManager.state["ovm-head|svc"])
	api.stateManager.mu.RUnlock()
	if headJStr == "" {
		t.Fatalf("missing ovm-head|svc")
	}

	// Take a snapshot and verify membership via tag→set and content hash
	snapID := "snap-verify"
	if _, err := api.TakeSnapshot(ctx, snapID); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	// VerifyEntryInSnapshot resolves via tag→set and content hash
	ok, err := api.VerifyEntryInSnapshot(ctx, snapID, "svc", []byte("V2"))
	if err != nil || !ok {
		t.Fatalf("VerifyEntryInSnapshot failed: ok=%v err=%v", ok, err)
	}

	// Find an audit txid recorded in state and verify its digest against audit.log
	api.stateManager.mu.RLock()
	var txid string
	for k := range api.stateManager.state {
		if strings.HasPrefix(k, "log|") {
			txid = strings.TrimPrefix(k, "log|")
			break
		}
	}
	api.stateManager.mu.RUnlock()
	if txid == "" {
		t.Fatalf("no audit txid found in state")
	}
	ok, err = api.VerifyAudit(ctx, txid)
	if err != nil || !ok {
		t.Fatalf("VerifyAudit(%s) failed: ok=%v err=%v", txid, ok, err)
	}
}

// TestBatchSingleLeafAndIndexing validates leaf counts and index mapping for a
// multi-object batch update under the single-leaf model.
func TestBatchSingleLeafAndIndexing(t *testing.T) {
	ctx := context.Background()

	dir, err := os.MkdirTemp("", "rebound-directleaves-batch-")
	if err != nil {
		t.Fatalf("mktemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	signerKey, verifierKey, err := note.GenerateKey(rand.Reader, "test")
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	signer, _ := note.NewSigner(signerKey)
	verifier, _ := note.NewVerifier(verifierKey)

	api, err := NewReboundAPI(dir, false, signer, verifier, true)
	if err != nil {
		t.Fatalf("NewReboundAPI: %v", err)
	}
	t.Cleanup(func() { _ = api.Close(ctx) })

	// Baseline size then a batch update of two objects: expect len(objects)+1 (audit) +2 (cv chunk+head) leaves
	sizeBefore, err := api.GetCheckpointSize(ctx)
	if err != nil {
		t.Fatalf("GetCheckpointSize: %v", err)
	}

	payload := map[string][]byte{"x": []byte("X1"), "y": []byte("Y1")}
	if _, err := api.StateUpdateBatch(ctx, payload); err != nil {
		t.Fatalf("StateUpdateBatch: %v", err)
	}

	sizeAfter, err := api.GetCheckpointSize(ctx)
	if err != nil {
		t.Fatalf("GetCheckpointSize(after): %v", err)
	}
	if got, want := int(sizeAfter-sizeBefore), len(payload)+3; got != want {
		t.Fatalf("unexpected leaf count for batch (ovm*k + audit + cv): got %d want %d (before=%d after=%d)", got, want, sizeBefore, sizeAfter)
	}

	// Verify index mapping for ovm keys to their own per-key ovm leaves
	ctr := api.GetCurrentCounter()
	idxX, err := api.indexDB.GetIndex(fmt.Sprintf("ovm|%s|%d", "x", ctr))
	if err != nil {
		t.Fatalf("index for ovm|x missing: %v", err)
	}
	idxY, err := api.indexDB.GetIndex(fmt.Sprintf("ovm|%s|%d", "y", ctr))
	if err != nil {
		t.Fatalf("index for ovm|y missing: %v", err)
	}
	if idxX == idxY {
		t.Fatalf("expected distinct per-key leaves for x and y; got same index %d", idxX)
	}
}

// TestSelectiveRollback_SingleLeafAndIndexing validates that selective rollback
// emits exactly one state leaf and correct index mappings under the single-leaf model.
func TestSelectiveRollback_SingleLeafAndIndexing(t *testing.T) {
	ctx := context.Background()

	dir, err := os.MkdirTemp("", "rebound-directleaves-rbsel-")
	if err != nil {
		t.Fatalf("mktemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	signerKey, verifierKey, err := note.GenerateKey(rand.Reader, "test")
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	signer, _ := note.NewSigner(signerKey)
	verifier, _ := note.NewVerifier(verifierKey)

	api, err := NewReboundAPI(dir, false, signer, verifier, true)
	if err != nil {
		t.Fatalf("NewReboundAPI: %v", err)
	}
	t.Cleanup(func() { _ = api.Close(ctx) })

	// Create two versions for 'a' so we can roll back to the first
	if _, err := api.StateUpdate(ctx, "a", []byte("A1")); err != nil {
		t.Fatalf("a A1: %v", err)
	}
	if _, err := api.StateUpdate(ctx, "a", []byte("A2")); err != nil {
		t.Fatalf("a A2: %v", err)
	}

	// Determine the first counter for 'a'
	api.stateManager.mu.RLock()
	var aFirst uint64
	for k := range api.stateManager.state {
		if strings.HasPrefix(k, "ovm|a|") {
			parts := strings.Split(k, "|")
			if len(parts) == 3 {
				if c, err := strconv.ParseUint(parts[2], 10, 64); err == nil {
					if aFirst == 0 || c < aFirst {
						aFirst = c
					}
				}
			}
		}
	}
	headBefore := string(api.stateManager.state["ovm-head|a"])
	api.stateManager.mu.RUnlock()
	if aFirst == 0 || headBefore == "" {
		t.Fatalf("failed to determine counters: aFirst=%d headBefore=%s", aFirst, headBefore)
	}

	sizeBefore, err := api.GetCheckpointSize(ctx)
	if err != nil {
		t.Fatalf("GetCheckpointSize: %v", err)
	}

	// Selective rollback only affects 'a': expect 4 new leaves (ovm + audit + current-view chunk + current-view head)
	ok, err := api.RollbackSelective(ctx, map[string]uint64{"a": aFirst}, "rewind a to A1 (dl)")
	if err != nil || !ok {
		t.Fatalf("RollbackSelective: %v", err)
	}

	sizeAfter, err := api.GetCheckpointSize(ctx)
	if err != nil {
		t.Fatalf("GetCheckpointSize(after): %v", err)
	}
	if got, want := int(sizeAfter-sizeBefore), 4; got != want {
		t.Fatalf("unexpected leaf count for selective rollback (ovm+audit+cv): got %d want %d (before=%d after=%d)", got, want, sizeBefore, sizeAfter)
	}

	// Index mapping for new 'a' head should point to its ovm per-key leaf (sizeAfter-4)
	stateIdx := sizeAfter - 4
	api.stateManager.mu.RLock()
	headAfter := string(api.stateManager.state["ovm-head|a"])
	api.stateManager.mu.RUnlock()
	if headAfter == headBefore {
		t.Fatalf("expected head|a to change on selective rollback; stayed %s", headAfter)
	}
	ovmKey := fmt.Sprintf("ovm|%s|%s", "a", headAfter)
	if idx, err := api.indexDB.GetIndex(ovmKey); err != nil || idx != stateIdx {
		t.Fatalf("Index for %s = %d err=%v, want %d", ovmKey, idx, err, stateIdx)
	}
}

func TestReboundAPI(t *testing.T) {
	// Create a temporary directory for Tessera storage.
	// High-level smoke test for state updates, snapshots, rollback, pruning, and recovery
	// under the single-leaf model.
	dir, err := os.MkdirTemp("", "rollback-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	// Create a new signer and verifier for the test.
	signerKey, verifierKey, err := note.GenerateKey(rand.Reader, "test")
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	signer, err := note.NewSigner(signerKey)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}
	verifier, err := note.NewVerifier(verifierKey)
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	// Initialize the ReboundAPI with testing mode enabled for synchronous writes.
	api, err := NewReboundAPI(dir, false, signer, verifier, true)
	if err != nil {
		t.Fatalf("Failed to create ReboundAPI: %v", err)
	}
	defer api.Close(context.Background())

	ctx := context.Background()

	// 1. Perform a series of state updates.
	t.Log("Step 1: Performing 5 initial state updates...")
	for i := 0; i < 5; i++ {
		key := fmt.Sprintf("key-%d", i)
		value := []byte(fmt.Sprintf("value-%d", i))
		_, err := api.StateUpdate(ctx, key, value)
		if err != nil {
			t.Fatalf("StateUpdate failed for key %s: %v", key, err)
		}
	}
	t.Log("Step 1: Completed.")

	// 2. Take a snapshot of the current state.
	snapshotName := "my-first-snapshot"
	t.Logf("Step 2: Taking snapshot '%s'...", snapshotName)
	snapshotHash, err := api.TakeSnapshot(ctx, snapshotName)
	if err != nil {
		t.Fatalf("TakeSnapshot failed: %v", err)
	}
	if len(snapshotHash) == 0 {
		t.Fatal("TakeSnapshot returned an empty hash")
	}
	t.Logf("Step 2: Snapshot created with hash %x.", snapshotHash)

	// 3. Perform more state updates after the snapshot.
	t.Log("Step 3: Performing state update after snapshot...")
	_, err = api.StateUpdate(ctx, "key-after-snapshot", []byte("new-value"))
	if err != nil {
		t.Fatalf("StateUpdate after snapshot failed: %v", err)
	}
	t.Log("Step 3: Completed.")

	// 4. List snapshots and verify the one we just took is present.
	t.Log("Step 4: Listing snapshots to verify creation...")
	snapshots, err := api.ListSnapshots(ctx)
	if err != nil {
		t.Fatalf("ListSnapshots failed: %v", err)
	}
	if len(snapshots) != 1 || snapshots[0] != snapshotName {
		t.Fatalf("Snapshot verification failed: got %v, want %v", snapshots, []string{snapshotName})
	}
	t.Logf("Step 4: Successfully verified snapshot list: %v.", snapshots)

	// 5. Rollback to the snapshot.
	t.Logf("Step 5: Rolling back to snapshot '%s'...", snapshotName)
	just := "policy-violation-hotfix"
	_, err = api.RollbackToSnapshot(ctx, snapshotName, just)
	if err != nil {
		t.Fatalf("RollbackToSnapshot failed: %v", err)
	}
	t.Log("Step 5: Rollback completed.")

	// 6. Verify that the state is rolled back correctly (heads-only).
	t.Log("Step 6: Verifying state after rollback...")
	// Heads-only rollback should NOT delete keys created after the snapshot; they remain.
	valAfterSnap, exists := getLatestObjectKey(api.stateManager, "key-after-snapshot")
	if !exists {
		t.Fatal(`"key-after-snapshot" should exist after heads-only rollback, but was not found`)
	}
	expNew := sha256.Sum256([]byte("new-value"))
	if !bytes.Equal(valAfterSnap, []byte(hex.EncodeToString(expNew[:]))) {
		t.Fatalf("key-after-snapshot value hash mismatch after rollback: got %s", string(valAfterSnap))
	}
	t.Log(` - PASSED: "key-after-snapshot" correctly preserved.`)

	val, exists := getLatestObjectKey(api.stateManager, "key-4")
	if !exists {
		t.Fatal(`"key-4" should exist after rollback, but was not found`)
	}
	t.Log(` - PASSED: "key-4" correctly present.`)

	expectedValue := []byte("value-4")
	expectedHash := sha256.Sum256(expectedValue)
	expectedHashStr := hex.EncodeToString(expectedHash[:])

	if !bytes.Equal(val, []byte(expectedHashStr)) {
		t.Fatalf(`"key-4" has wrong value: got %s, want hash of "value-4"`, val)
	}
	t.Log(` - PASSED: "key-4" has correct value.`)
	t.Log("Step 6: State verification successful.")

	// 6.b Metadata assertions for rollback-created entries (spot-check one object)
	api.stateManager.mu.RLock()
	// find the counter used in rollback (look up ovm-head|key-4)
	ctrStr := string(api.stateManager.state["ovm-head|key-4"])
	if ctrStr == "" {
		t.Fatalf("missing head counter for key-4")
	}
	// origin should be previous head counter (which exists at update time)
	originKey := fmt.Sprintf("meta|object|%s|%s|origin", "key-4", ctrStr)
	txidKey := fmt.Sprintf("meta|object|%s|%s|txid", "key-4", ctrStr)
	justKey := fmt.Sprintf("meta|object|%s|%s|just", "key-4", ctrStr)
	tsKey := fmt.Sprintf("meta|object|%s|%s|ts", "key-4", ctrStr)

	if _, ok := api.stateManager.state[originKey]; !ok {
		t.Fatalf("missing origin meta for rollback version: %s", originKey)
	}
	txid := string(api.stateManager.state[txidKey])
	if !strings.HasPrefix(txid, "txid-") || len(txid) < 6 {
		t.Fatalf("invalid txid meta, got %q", txid)
	}
	gotJust := string(api.stateManager.state[justKey])
	if gotJust != just {
		t.Fatalf("justification mismatch: got %q want %q", gotJust, just)
	}
	if _, ok := api.stateManager.state[tsKey]; !ok {
		t.Fatalf("missing ts meta for rollback version")
	}

	// 6.c Read actual content from the content store for the rolled-back head
	objHeadCtr := ctrStr
	objKey := fmt.Sprintf("ovm|%s|%s", "key-4", objHeadCtr)
	hashBytes, ok := api.stateManager.state[objKey]
	if !ok {
		t.Fatalf("missing object entry %s after rollback", objKey)
	}
	blob, err := api.contentStore.Fetch(string(hashBytes))
	if err != nil {
		t.Fatalf("failed to fetch content for %s: %v", objKey, err)
	}
	if !bytes.Equal(blob, []byte("value-4")) {
		t.Fatalf("content mismatch for %s: got %q want %q", objKey, string(blob), "value-4")
	}
	// Release the read lock now; subsequent steps will perform writes.
	api.stateManager.mu.RUnlock()

	// 7. Verify an entry within the rolled-back snapshot.
	t.Log("Step 7: Verifying a valid entry ('key-2') within the snapshot...")
	verified, err := api.VerifyEntryInSnapshot(ctx, snapshotName, "key-2", []byte("value-2"))
	if err != nil {
		t.Fatalf("VerifyEntryInSnapshot failed for a valid entry: %v", err)
	}
	if !verified {
		t.Fatal("Failed to verify a valid entry in the snapshot")
	}
	t.Log("Step 7: Successfully verified valid entry.")

	// No sleep needed: state mutations already wait for checkpoint inclusion.

	// 7.b Reconstruct lineage for key-4 and pretty-print it
	lineage, err := api.ReconstructObjectLineage(ctx, "key-4")
	if err != nil {
		t.Fatalf("ReconstructObjectLineage failed: %v", err)
	}
	if len(lineage) == 0 {
		t.Fatalf("expected lineage events for key-4, got 0")
	}
	// Human readable dump first (useful if assertions fail)
	t.Log("Lineage for key-4:\n" + api.FormatLineage(lineage))
	// Ensure the last event corresponds to the rollback recompose counter and hash for value-4
	last := lineage[len(lineage)-1]
	// Hash of value-4 as hex
	expected := sha256.Sum256([]byte("value-4"))
	expectedHex := hex.EncodeToString(expected[:])
	if string(last.ContentHash) != expectedHex || last.TxID == "-" {
		// Fallback: search for the most recent event matching expected hash and with a TxID
		var foundIdx = -1
		for i := len(lineage) - 1; i >= 0; i-- {
			if lineage[i].ContentHash == expectedHex && lineage[i].TxID != "-" {
				foundIdx = i
				break
			}
		}
		if foundIdx == -1 {
			t.Fatalf("expected a rollback lineage event with content hash %s and non-empty TxID, but none found", expectedHex)
		}
		if foundIdx != len(lineage)-1 {
			t.Fatalf("expected the rollback lineage event to be last, but it was at index %d of %d; lineage: %v", foundIdx, len(lineage), lineage)
		}
	}

	// 8. Verify a non-existent entry in the snapshot.
	t.Log("Step 8: Verifying a non-existent entry ('key-not-exist') within the snapshot...")
	verified, err = api.VerifyEntryInSnapshot(ctx, snapshotName, "key-not-exist", nil)
	if err != nil {
		t.Fatalf("VerifyEntryInSnapshot for non-existent key failed: %v", err)
	}
	if !verified {
		t.Fatal("Failed to verify a non-existent entry in the snapshot")
	}
	t.Log("Step 8: Successfully verified absence of non-existent entry.")

	// 8.b Create a richer 5-event lineage for a single object 'svc'
	// Pattern: A -> B -> [take snapshot svc-snap] -> C -> rollback to svc-snap (B*) -> D
	t.Log("Step 8.b: Building 5-event lineage for 'svc' (A->B->C->B*->D)...")
	// Helper to log the current svc head and metadata
	logSvcHead := func(tag string) {
		api.stateManager.mu.RLock()
		defer api.stateManager.mu.RUnlock()
		head := string(api.stateManager.state["ovm-head|svc"])
		txid := ""
		just := ""
		if head != "" {
			txid = string(api.stateManager.state[fmt.Sprintf("meta|object|%s|%s|txid", "svc", head)])
			just = string(api.stateManager.state[fmt.Sprintf("meta|object|%s|%s|just", "svc", head)])
		}
		t.Logf("svc[%s]: head=%s txid=%q just=%q", tag, head, txid, just)
	}
	// Keep per-append checkpoint waits enabled so each state change blocks until
	// a checkpoint includes it (strongest consistency for tests).
	if _, err := api.StateUpdate(ctx, "svc", []byte("A")); err != nil {
		t.Fatalf("svc A update failed: %v", err)
	}
	logSvcHead("A")
	if _, err := api.StateUpdate(ctx, "svc", []byte("B")); err != nil {
		t.Fatalf("svc B update failed: %v", err)
	}
	logSvcHead("B")
	if _, err := api.TakeSnapshot(ctx, "svc-snap"); err != nil {
		t.Fatalf("svc snapshot failed: %v", err)
	}
	t.Log("svc: snapshot 'svc-snap' taken")
	if _, err := api.StateUpdate(ctx, "svc", []byte("C")); err != nil {
		t.Fatalf("svc C update failed: %v", err)
	}
	logSvcHead("C")
	if _, err := api.RollbackToSnapshot(ctx, "svc-snap", "rollback svc to B"); err != nil {
		t.Fatalf("svc rollback failed: %v", err)
	}
	logSvcHead("B*")
	if _, err := api.StateUpdate(ctx, "svc", []byte("D")); err != nil {
		t.Fatalf("svc D update failed: %v", err)
	}
	logSvcHead("D")
	// No manual toggling; per-append waits already ensured checkpoint inclusion.

	// Gather and validate lineage for 'svc'
	svcLineage, err := api.ReconstructObjectLineage(ctx, "svc")
	if err != nil {
		t.Fatalf("ReconstructObjectLineage(svc) failed: %v", err)
	}
	if len(svcLineage) < 5 {
		t.Fatalf("expected at least 5 events for svc lineage, got %d", len(svcLineage))
	}
	// Map content hashes back to labels A/B/C/D for a pretty diagram
	labelFor := func(hash string, txid string) string {
		toHex := func(s string) string { return s }
		sA := sha256.Sum256([]byte("A"))
		hA := hex.EncodeToString(sA[:])
		sB := sha256.Sum256([]byte("B"))
		hB := hex.EncodeToString(sB[:])
		sC := sha256.Sum256([]byte("C"))
		hC := hex.EncodeToString(sC[:])
		sD := sha256.Sum256([]byte("D"))
		hD := hex.EncodeToString(sD[:])
		switch hash {
		case hA:
			if txid != "-" {
				return "A*"
			}
			return "A"
		case hB:
			if txid != "-" {
				return "B*"
			}
			return "B"
		case hC:
			if txid != "-" {
				return "C*"
			}
			return "C"
		case hD:
			if txid != "-" {
				return "D*"
			}
			return "D"
		default:
			// shorten unknown hash for readability
			if len(hash) > 6 {
				return toHex(hash[:6]) + "…"
			}
			return hash
		}
	}
	var labels []string
	for _, e := range svcLineage {
		labels = append(labels, labelFor(e.ContentHash, e.TxID))
	}
	// Expect suffix of the sequence to be: A, B, C, B*, D
	want := []string{"A", "B", "C", "B*", "D"}
	if len(labels) >= len(want) {
		off := len(labels) - len(want)
		gotTail := labels[off:]
		match := true
		for i := range want {
			if gotTail[i] != want[i] {
				match = false
				break
			}
		}
		if !match {
			t.Fatalf("svc lineage tail mismatch: got %v want %v (all=%v)", gotTail, want, labels)
		}
	} else {
		t.Fatalf("svc lineage too short to validate tail: %v", labels)
	}

	// Pretty diagram with a box and arrows
	diagram := func() string {
		// Build arrow line
		arrow := ""
		for i, lbl := range labels {
			if i > 0 {
				arrow += " -> "
			}
			arrow += "[" + lbl + "]"
		}
		// Build detail lines for the last 5 events
		start := 0
		if len(svcLineage) > 5 {
			start = len(svcLineage) - 5
		}
		details := ""
		for _, e := range svcLineage[start:] {
			typ := "update"
			if e.TxID != "-" {
				typ = "rollback"
			}
			details += fmt.Sprintf("  - %-3s c=%-3d leaf=%-3d type=%-9s txid=%-8s just=%q\n",
				labelFor(e.ContentHash, e.TxID), e.Counter, e.LeafIndex, typ, e.TxID, e.Justification)
		}
		content := fmt.Sprintf("svc lineage (last %d of %d events)\n\n%s\n\nDetails:\n%s", len(svcLineage[start:]), len(svcLineage), arrow, details)
		border := strings.Repeat("-", 6+len("svc lineage (last 5 of 5 events)"))
		return "+" + border + "+\n| " + strings.ReplaceAll(content, "\n", "\n| ") + "\n+" + border + "+"
	}()

	t.Log("\n" + diagram)

	// 9. Verify a key that exists but with the wrong data.
	// Use svc-snap to avoid index overwrite from later lineage rebuilds.
	t.Log("Step 9: Verifying an entry ('svc') with incorrect data against 'svc-snap'...")
	verified, err = api.VerifyEntryInSnapshot(ctx, "svc-snap", "svc", []byte("wrong-data"))
	if err == nil && verified {
		t.Fatal("Verified an entry with incorrect data, but expected an error")
	}
	if err != nil && !strings.Contains(err.Error(), "content hash mismatch") {
		t.Fatalf("Expected content hash mismatch error, but got: %v", err)
	}
	t.Log("Step 9: Correctly failed to verify entry with incorrect data.")
}

// TestRollbackSelective verifies heads-only selective rollback re-materializes only targeted objects.
func TestRollbackSelective(t *testing.T) {
	dir, err := os.MkdirTemp("", "rollback-sel-test")
	if err != nil {
		t.Fatalf("mktemp: %v", err)
	}
	defer os.RemoveAll(dir)

	signerKey, verifierKey, err := note.GenerateKey(rand.Reader, "test")
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	signer, _ := note.NewSigner(signerKey)
	verifier, _ := note.NewVerifier(verifierKey)
	api, err := NewReboundAPI(dir, false, signer, verifier, true)
	if err != nil {
		t.Fatalf("NewReboundAPI: %v", err)
	}
	defer api.Close(context.Background())

	ctx := context.Background()
	// Build versions: a@1 -> A1, b@1 -> B1, a@2 -> A2, c@1 -> C1
	if _, err := api.StateUpdate(ctx, "a", []byte("A1")); err != nil {
		t.Fatalf("a A1: %v", err)
	}
	if _, err := api.StateUpdate(ctx, "b", []byte("B1")); err != nil {
		t.Fatalf("b B1: %v", err)
	}
	if _, err := api.StateUpdate(ctx, "a", []byte("A2")); err != nil {
		t.Fatalf("a A2: %v", err)
	}
	if _, err := api.StateUpdate(ctx, "c", []byte("C1")); err != nil {
		t.Fatalf("c C1: %v", err)
	}

	// Resolve counters: first version counter for a is the smaller of ovm|a|* keys.
	api.stateManager.mu.RLock()
	var aFirst uint64
	var aHeadBefore string = string(api.stateManager.state["ovm-head|a"])
	for k := range api.stateManager.state {
		if strings.HasPrefix(k, "ovm|a|") {
			parts := strings.Split(k, "|")
			if len(parts) == 3 {
				if c, err := strconv.ParseUint(parts[2], 10, 64); err == nil {
					if aFirst == 0 || c < aFirst {
						aFirst = c
					}
				}
			}
		}
	}
	bHeadBefore := string(api.stateManager.state["ovm-head|b"])
	cHeadBefore := string(api.stateManager.state["ovm-head|c"])
	api.stateManager.mu.RUnlock()
	if aFirst == 0 || aHeadBefore == "" || bHeadBefore == "" || cHeadBefore == "" {
		t.Fatalf("failed to determine baseline counters: aFirst=%d aHead=%s bHead=%s cHead=%s", aFirst, aHeadBefore, bHeadBefore, cHeadBefore)
	}

	// Selective rollback: rewind only 'a' to its first version
	ok, err := api.RollbackSelective(ctx, map[string]uint64{"a": aFirst}, "rewind a to A1")
	if err != nil || !ok {
		t.Fatalf("RollbackSelective failed: %v", err)
	}

	// Validate: ovm-head|a moved to a new counter and points to A1; b and c unchanged
	api.stateManager.mu.RLock()
	aHeadAfter := string(api.stateManager.state["ovm-head|a"])
	bHeadAfter := string(api.stateManager.state["ovm-head|b"])
	cHeadAfter := string(api.stateManager.state["ovm-head|c"])
	// derive new object key and fetch blob
	aObjKey := fmt.Sprintf("ovm|%s|%s", "a", aHeadAfter)
	aHash := string(api.stateManager.state[aObjKey])
	txid := string(api.stateManager.state[fmt.Sprintf("meta|object|%s|%s|txid", "a", aHeadAfter)])
	just := string(api.stateManager.state[fmt.Sprintf("meta|object|%s|%s|just", "a", aHeadAfter)])
	origin := string(api.stateManager.state[fmt.Sprintf("meta|object|%s|%s|origin", "a", aHeadAfter)])
	// OVM presence
	_, ovmOK := api.stateManager.state[fmt.Sprintf("ovm|%s|%s", "a", aHeadAfter)]
	api.stateManager.mu.RUnlock()

	if aHeadAfter == aHeadBefore {
		t.Fatalf("expected ovm-head|a to change; stayed %s", aHeadAfter)
	}
	if bHeadAfter != bHeadBefore || cHeadAfter != cHeadBefore {
		t.Fatalf("non-target heads changed: b %s->%s c %s->%s", bHeadBefore, bHeadAfter, cHeadBefore, cHeadAfter)
	}
	if !strings.HasPrefix(txid, "txid-") || just != "rewind a to A1" || origin != aHeadBefore {
		t.Fatalf("meta mismatch: txid=%q just=%q origin=%q", txid, just, origin)
	}
	if !ovmOK {
		t.Fatalf("OVM missing for head %s", aHeadAfter)
	}

	// Confirm content is A1
	blob, err := api.contentStore.Fetch(aHash)
	if err != nil {
		t.Fatalf("fetch a blob: %v", err)
	}
	if !bytes.Equal(blob, []byte("A1")) {
		t.Fatalf("a content mismatch: got %q want %q", string(blob), "A1")
	}
}

// TestGetLatestObjectKey tests the helper function in isolation.
func TestGetLatestObjectKey(t *testing.T) {
	sm := NewStateManager()
	sm.state = map[string][]byte{
		"ovm|key-1|1": []byte("hash1"),
		"ovm|key-1|3": []byte("hash3"), // latest version of key-1
		"ovm|key-1|2": []byte("hash2"),
		"ovm|key-2|4": []byte("hash4"), // only version of key-2
		"log|txid-5":  []byte("audithash"),
	}

	// Test case 1: Find the latest version of a key with multiple entries.
	val, exists := getLatestObjectKey(sm, "key-1")
	if !exists || !bytes.Equal(val, []byte("hash3")) {
		t.Errorf("Expected to get 'hash3' for 'key-1', but got '%s'", val)
	}

	// Test case 2: Find a key with a single entry.
	val, exists = getLatestObjectKey(sm, "key-2")
	if !exists || !bytes.Equal(val, []byte("hash4")) {
		t.Errorf("Expected to get 'hash4' for 'key-2', but got '%s'", val)
	}

	// Test case 3: Search for a key that does not exist.
	_, exists = getLatestObjectKey(sm, "key-nonexistent")
	if exists {
		t.Error("Expected not to find 'key-nonexistent', but it was found")
	}
}

// TestSelectiveRollback_RejectsUnknownVersion ensures presence proof enforcement
// by rejecting selective rollback to a version that never existed historically.
func TestSelectiveRollback_RejectsUnknownVersion(t *testing.T) {
	ctx := context.Background()
	dir, err := os.MkdirTemp("", "rollback-sel-unknown")
	if err != nil {
		t.Fatalf("mktemp: %v", err)
	}
	defer os.RemoveAll(dir)

	signerKey, verifierKey, _ := note.GenerateKey(rand.Reader, "test")
	signer, _ := note.NewSigner(signerKey)
	verifier, _ := note.NewVerifier(verifierKey)
	api, err := NewReboundAPI(dir, false, signer, verifier, true)
	if err != nil {
		t.Fatalf("NewReboundAPI: %v", err)
	}
	defer api.Close(ctx)

	// Create a baseline version for x@1
	if _, err := api.StateUpdate(ctx, "x", []byte("X1")); err != nil {
		t.Fatalf("x X1: %v", err)
	}
	// Attempt to roll back to a non-existent version j=9999
	ok, err := api.RollbackSelective(ctx, map[string]uint64{"x": 9999}, "bad-version")
	if err == nil || ok {
		t.Fatalf("expected failure for unknown historical version; ok=%v err=%v", ok, err)
	}
}

// TestStateManager_DeepCopy verifies that GetStateCopy creates a true deep copy.
func TestStateManager_DeepCopy(t *testing.T) {
	sm := NewStateManager()
	originalValue := []byte("original")
	sm.Update("key", originalValue)

	// Get a deep copy of the state.
	stateCopy := sm.GetStateCopy()

	// Mutate the value in the copied map.
	copyValue := stateCopy["key"]
	copyValue[0] = 'M' // "Mutated"

	// Check if the original state in the manager was affected.
	originalValueFromManager, _ := sm.Get("key")
	if bytes.Equal(originalValueFromManager, copyValue) {
		t.Fatal("Mutation of copied state affected the original state in the manager. GetStateCopy is not a deep copy.")
	}
	if !bytes.Equal(originalValueFromManager, originalValue) {
		t.Fatalf("Original value was unexpectedly changed. Got %s, want %s", originalValueFromManager, originalValue)
	}
}

// TestReboundAPI_RollbackToNonExistentSnapshot tests the error path for a missing snapshot.
func TestReboundAPI_RollbackToNonExistentSnapshot(t *testing.T) {
	dir, err := os.MkdirTemp("", "rollback-test-nonexistent")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)
	signerKey, verifierKey, _ := note.GenerateKey(rand.Reader, "test")
	signer, _ := note.NewSigner(signerKey)
	verifier, _ := note.NewVerifier(verifierKey)
	api, err := NewReboundAPI(dir, false, signer, verifier, true)
	if err != nil {
		t.Fatalf("Failed to create ReboundAPI: %v", err)
	}
	defer api.Close(context.Background())

	// Attempt to roll back to a snapshot that was never created.
	_, err = api.RollbackToSnapshot(context.Background(), "snapshot-that-does-not-exist", "test-justification")
	if err == nil {
		t.Fatal("Expected an error when rolling back to a non-existent snapshot, but got nil")
	}
	if !strings.Contains(err.Error(), "not found in index") {
		t.Errorf("Expected 'not found in index' error, but got: %v", err)
	}
}

// TestPruneDisallowsRollback ensures that once a snapshot is pruned,
// attempts to rollback to it are rejected with a clear error.
func TestPruneDisallowsRollback(t *testing.T) {
	dir, err := os.MkdirTemp("", "rollback-test-prune")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	signerKey, verifierKey, _ := note.GenerateKey(rand.Reader, "test")
	signer, _ := note.NewSigner(signerKey)
	verifier, _ := note.NewVerifier(verifierKey)
	api, err := NewReboundAPI(dir, false, signer, verifier, true)
	if err != nil {
		t.Fatalf("Failed to create ReboundAPI: %v", err)
	}
	defer api.Close(context.Background())

	ctx := context.Background()

	// Write some state and take a snapshot
	if _, err := api.StateUpdate(ctx, "svc", []byte("v1")); err != nil {
		t.Fatalf("StateUpdate failed: %v", err)
	}
	snapID := "release-1.0.0"
	if _, err := api.TakeSnapshot(ctx, snapID); err != nil {
		t.Fatalf("TakeSnapshot failed: %v", err)
	}

	// Prune the snapshot; under the per-key model prune appends deauth + audit + current-view chunk + current-view head (4 leaves)
	sizeBefore, err := api.GetCheckpointSize(ctx)
	if err != nil {
		t.Fatalf("GetCheckpointSize before prune failed: %v", err)
	}
	if _, err := api.PruneSnapshot(ctx, snapID, "retire old release"); err != nil {
		t.Fatalf("PruneSnapshot failed: %v", err)
	}
	sizeAfter, err := api.GetCheckpointSize(ctx)
	if err != nil {
		t.Fatalf("GetCheckpointSize after prune failed: %v", err)
	}
	if got, want := int(sizeAfter-sizeBefore), 4; got != want {
		t.Fatalf("unexpected leaf count for prune (deauth+audit+cv): got %d want %d (before=%d after=%d)", got, want, sizeBefore, sizeAfter)
	}

	// Attempt rollback to the pruned snapshot should be denied
	ok, err := api.RollbackToSnapshot(ctx, snapID, "attempt after prune")
	if err == nil || ok {
		t.Fatalf("expected rollback to pruned snapshot to fail; got ok=%v err=%v", ok, err)
	}
	if !strings.Contains(err.Error(), "pruned") {
		t.Fatalf("expected error mentioning 'pruned', got: %v", err)
	}
}

// TestAutoRecovery_Policies exercises the recovery behaviors:
//   - Advance (descendant) reseal under c+2
//   - Counter-only mismatch must hard-fail even with auto-recovery enabled
func TestAutoRecovery_Policies(t *testing.T) {
	dir, err := os.MkdirTemp("", "rollback-test-recover")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	signerKey, verifierKey, _ := note.GenerateKey(rand.Reader, "test")
	signer, _ := note.NewSigner(signerKey)
	verifier, _ := note.NewVerifier(verifierKey)
	api, err := NewReboundAPI(dir, false, signer, verifier, true)
	if err != nil {
		t.Fatalf("Failed to create ReboundAPI: %v", err)
	}
	defer api.Close(context.Background())

	ctx := context.Background()

	// Enable auto-recovery and log the initial counter.
	api.SetAutoRecoverOnFreshnessMismatch(true)
	t.Logf("auto-recovery enabled; counter=%d", api.GetCurrentCounter())

	// 1) Build a baseline state and seal (normal path).
	if _, err := api.StateUpdate(ctx, "svc", []byte("v1")); err != nil {
		t.Fatalf("initial update failed: %v", err)
	}

	// Simulate a process with stale sealed file by advancing the log one entry
	// without updating the seal/counter: we append using appender directly.
	// Then verifySealedFreshness should detect descendant advance and recover.
	// Note: This uses internal fields intentionally for a white-box test.
	newState := api.stateManager.GetStateCopy()
	newState["test|recovery|poke"] = []byte("1")
	b, _ := json.Marshal(newState)
	fut := api.appender.Add(ctx, tessera.NewEntry(b))
	idx, err := fut()
	if err != nil {
		t.Fatalf("failed to append extra entry: %v", err)
	}
	// Wait for checkpoint to include this new entry.
	if err := api.syncWithExpectedSize(ctx, idx.Index+1); err != nil {
		t.Fatalf("sync failed: %v", err)
	}

	// Now verify freshness; it should auto-recover via descendant consistency and succeed.
	t.Log("triggering verifySealedFreshness to exercise advance recovery path…")
	if _, _, err := api.verifySealedFreshness(ctx); err != nil {
		t.Fatalf("auto-recovery (advance) failed: %v", err)
	}
	t.Logf("advance recovery succeeded; counter now=%d", api.GetCurrentCounter())

	// 2) Counter-only mismatch must hard-fail: tamper the in-memory counter.
	api.mu.Lock()
	api.counter += 1 // diverge local counter from sealed
	diverged := api.counter
	api.mu.Unlock()
	t.Logf("intentionally diverged in-memory counter to %d; expecting hard-fail on verify", diverged)
	if _, _, err := api.verifySealedFreshness(ctx); err == nil {
		t.Fatalf("expected counter-only mismatch to hard-fail under auto-recovery, but it succeeded")
	}
}

// TestStateUpdateBatch verifies atomic multi-object updates share the same
// counter and are committed in a single leaf, with proper metadata and content.
func TestStateUpdateBatch(t *testing.T) {
	dir, err := os.MkdirTemp("", "rollback-test-batch")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	signerKey, verifierKey, _ := note.GenerateKey(rand.Reader, "test")
	signer, _ := note.NewSigner(signerKey)
	verifier, _ := note.NewVerifier(verifierKey)
	api, err := NewReboundAPI(dir, false, signer, verifier, true)
	if err != nil {
		t.Fatalf("Failed to create ReboundAPI: %v", err)
	}
	defer api.Close(context.Background())

	ctx := context.Background()

	// Empty batch should error
	if _, err := api.StateUpdateBatch(ctx, map[string][]byte{}); err == nil {
		t.Fatalf("expected error on empty batch update")
	}

	// First batch: svcA and svcB
	payload1 := map[string][]byte{
		"svcA": []byte("A1"),
		"svcB": []byte("B1"),
	}
	if _, err := api.StateUpdateBatch(ctx, payload1); err != nil {
		t.Fatalf("StateUpdateBatch #1 failed: %v", err)
	}

	api.stateManager.mu.RLock()
	headA := string(api.stateManager.state["ovm-head|svcA"])
	headB := string(api.stateManager.state["ovm-head|svcB"])
	api.stateManager.mu.RUnlock()
	if headA == "" || headB == "" {
		t.Fatalf("missing head counters: svcA=%q svcB=%q", headA, headB)
	}
	if headA != headB {
		t.Fatalf("expected same counter for batch update, got svcA=%s svcB=%s", headA, headB)
	}

	// Verify both ovm entries exist with distinct per-key ovm leaf indices
	keyA := fmt.Sprintf("ovm|%s|%s", "svcA", headA)
	keyB := fmt.Sprintf("ovm|%s|%s", "svcB", headB)
	idxA, err := api.indexDB.GetIndex(keyA)
	if err != nil {
		t.Fatalf("index for %s missing: %v", keyA, err)
	}
	idxB, err := api.indexDB.GetIndex(keyB)
	if err != nil {
		t.Fatalf("index for %s missing: %v", keyB, err)
	}
	if idxA == idxB {
		t.Fatalf("expected distinct per-key leaf indices for batch objects, got same index %d", idxA)
	}

	// Verify metadata and content
	api.stateManager.mu.RLock()
	txidA := string(api.stateManager.state[fmt.Sprintf("meta|object|%s|%s|txid", "svcA", headA)])
	justA := string(api.stateManager.state[fmt.Sprintf("meta|object|%s|%s|just", "svcA", headA)])
	hashA := string(api.stateManager.state[keyA])
	api.stateManager.mu.RUnlock()
	if txidA != "-" || justA != "update" {
		t.Fatalf("unexpected meta for svcA: txid=%q just=%q", txidA, justA)
	}
	blobA, err := api.contentStore.Fetch(hashA)
	if err != nil {
		t.Fatalf("fetch content svcA failed: %v", err)
	}
	if !bytes.Equal(blobA, []byte("A1")) {
		t.Fatalf("svcA blob mismatch: got %q want %q", string(blobA), "A1")
	}

	// Second batch: svcA and svcC
	payload2 := map[string][]byte{
		"svcA": []byte("A2"),
		"svcC": []byte("C1"),
	}
	if _, err := api.StateUpdateBatch(ctx, payload2); err != nil {
		t.Fatalf("StateUpdateBatch #2 failed: %v", err)
	}

	api.stateManager.mu.RLock()
	headA2 := string(api.stateManager.state["ovm-head|svcA"])
	headB2 := string(api.stateManager.state["ovm-head|svcB"])
	headC2 := string(api.stateManager.state["ovm-head|svcC"])
	api.stateManager.mu.RUnlock()
	if headA2 == "" || headC2 == "" {
		t.Fatalf("missing heads after batch2: A=%q C=%q", headA2, headC2)
	}
	if headA2 == headA {
		t.Fatalf("expected svcA counter to advance, stayed at %s", headA2)
	}
	if headB2 != headB {
		t.Fatalf("svcB head should remain unchanged, got %s want %s", headB2, headB)
	}
	if headA2 != headC2 {
		t.Fatalf("expected same counter for A and C in batch2, got A=%s C=%s", headA2, headC2)
	}

	// Lineage for svcA should have at least 2 events and end with A2
	linA, err := api.ReconstructObjectLineage(ctx, "svcA")
	if err != nil {
		t.Fatalf("lineage svcA failed: %v", err)
	}
	if len(linA) < 2 {
		t.Fatalf("expected >=2 lineage events for svcA, got %d", len(linA))
	}
	last := linA[len(linA)-1]
	if fmt.Sprint(last.Counter) != headA2 || last.TxID != "-" {
		t.Fatalf("unexpected last lineage: %+v", last)
	}
}

// getLatestObjectKey is a test helper to find the latest version of an object key
// in the state manager's internal map.
func getLatestObjectKey(sm *StateManager, logicalKey string) (val []byte, exists bool) {
	var maxCounter uint64
	var found bool
	// Access the internal state map directly for white-box testing.
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	for k, v := range sm.state {
		parts := strings.Split(k, "|")
		if len(parts) == 3 && parts[0] == "ovm" && parts[1] == logicalKey {
			counter, err := strconv.ParseUint(parts[2], 10, 64)
			if err != nil {
				continue
			}
			if !found || counter > maxCounter {
				maxCounter = counter
				val = v
				found = true
			}
		}
	}
	return val, found
}

// TestAutoRecovery_RewindStrict validates that when the checkpoint is behind the sealed
// size by exactly 1 (S-1), auto-recovery succeeds by resealing and double-incrementing;
// and that rewinds larger than 1 are rejected.
func TestAutoRecovery_RewindStrict(t *testing.T) {
	dir, err := os.MkdirTemp("", "rollback-test-rewind")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	signerKey, verifierKey, _ := note.GenerateKey(rand.Reader, "test")
	signer, _ := note.NewSigner(signerKey)
	verifier, _ := note.NewVerifier(verifierKey)
	api, err := NewReboundAPI(dir, false, signer, verifier, true)
	if err != nil {
		t.Fatalf("Failed to create ReboundAPI: %v", err)
	}
	defer api.Close(context.Background())

	ctx := context.Background()
	api.SetAutoRecoverOnFreshnessMismatch(true)

	// Create a single entry to establish cp size S=1 and counter=2.
	if _, err := api.StateUpdate(ctx, "k", []byte("v")); err != nil {
		t.Fatalf("initial update failed: %v", err)
	}
	// Sanity: capture current checkpoint size/hash and counter.
	cpSize, cpHash, err := api.fetchVerifiedCheckpoint(ctx)
	if err != nil {
		t.Fatalf("fetch checkpoint failed: %v", err)
	}
	if cpSize == 0 {
		t.Fatalf("expected non-zero checkpoint size")
	}
	beforeCtr := api.GetCurrentCounter() // should be 2

	// Forge a sealed blob that claims size S+1 (strict rewind scenario).
	sealed1 := struct {
		V       string `json:"v"`
		Size    uint64 `json:"size"`
		HashHex string `json:"hash"`
		Counter uint64 `json:"counter"`
		SigHex  string `json:"sig"`
	}{V: "v1", Size: cpSize + 1, HashHex: hex.EncodeToString(cpHash), Counter: beforeCtr}
	payload1 := []byte(fmt.Sprintf("v1|size=%d|hash=%s|counter=%d", sealed1.Size, sealed1.HashHex, sealed1.Counter))
	sig1 := ed25519.Sign(api.sealPriv, payload1)
	sealed1.SigHex = hex.EncodeToString(sig1)
	blob1, _ := json.Marshal(sealed1)
	if err := os.WriteFile(api.sealedBlobPath, blob1, 0644); err != nil {
		t.Fatalf("write forged sealed blob failed: %v", err)
	}

	// Trigger verify; recovery should succeed (S-1 allowed) and double-increment counter.
	if _, _, err := api.verifySealedFreshness(ctx); err != nil {
		t.Fatalf("auto-recovery (rewind S-1) failed: %v", err)
	}
	afterCtr := api.GetCurrentCounter()
	if afterCtr != beforeCtr+2 {
		t.Fatalf("expected counter to advance by 2 after S-1 recovery, got before=%d after=%d", beforeCtr, afterCtr)
	}

	// Now craft a sealed blob that claims size S+2 (rewind too far) and expect failure.
	sealed2 := struct {
		V       string `json:"v"`
		Size    uint64 `json:"size"`
		HashHex string `json:"hash"`
		Counter uint64 `json:"counter"`
		SigHex  string `json:"sig"`
	}{V: "v1", Size: cpSize + 2, HashHex: hex.EncodeToString(cpHash), Counter: afterCtr}
	payload2 := []byte(fmt.Sprintf("v1|size=%d|hash=%s|counter=%d", sealed2.Size, sealed2.HashHex, sealed2.Counter))
	sig2 := ed25519.Sign(api.sealPriv, payload2)
	sealed2.SigHex = hex.EncodeToString(sig2)
	blob2, _ := json.Marshal(sealed2)
	if err := os.WriteFile(api.sealedBlobPath, blob2, 0644); err != nil {
		t.Fatalf("write forged sealed blob2 failed: %v", err)
	}
	if _, _, err := api.verifySealedFreshness(ctx); err == nil {
		t.Fatalf("expected auto-recovery to hard-fail on rewind >1, but it succeeded")
	}
}

// TestCounterIncrement_NormalVsRecovery ensures that normal mutations increment
// the monotonic counter once, while auto-recovery performs a double increment.
func TestCounterIncrement_NormalVsRecovery(t *testing.T) {
	dir, err := os.MkdirTemp("", "ctr-inc-test")
	if err != nil {
		t.Fatalf("mktemp: %v", err)
	}
	defer os.RemoveAll(dir)

	signerKey, verifierKey, err := note.GenerateKey(rand.Reader, "test")
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	signer, _ := note.NewSigner(signerKey)
	verifier, _ := note.NewVerifier(verifierKey)
	api, err := NewReboundAPI(dir, false, signer, verifier, true)
	if err != nil {
		t.Fatalf("NewReboundAPI: %v", err)
	}
	defer api.Close(context.Background())

	ctx := context.Background()
	api.SetAutoRecoverOnFreshnessMismatch(true)

	c0 := api.GetCurrentCounter()
	if _, err := api.StateUpdate(ctx, "x", []byte("v1")); err != nil {
		t.Fatalf("StateUpdate v1 failed: %v", err)
	}
	c1 := api.GetCurrentCounter()
	if c1 != c0+1 {
		t.Fatalf("normal inc mismatch: got %d want %d", c1, c0+1)
	}

	// Simulate a stale sealed blob by advancing the log without updating the seal/counter.
	// Append a dummy entry directly to the log and wait for the checkpoint.
	dummy := []byte(`{"noop":true}`)
	fut := api.appender.Add(ctx, tessera.NewEntry(dummy))
	idx, err := fut()
	if err != nil {
		t.Fatalf("append dummy: %v", err)
	}
	if err := api.syncWithExpectedSize(ctx, idx.Index+1); err != nil {
		t.Fatalf("sync after dummy: %v", err)
	}

	// Trigger freshness verification; with auto-recovery it should succeed and double-increment.
	if _, _, err := api.verifySealedFreshness(ctx); err != nil {
		t.Fatalf("verifySealedFreshness after advance: %v", err)
	}
	c2 := api.GetCurrentCounter()
	if c2 != c1+2 {
		t.Fatalf("recovery double-inc mismatch: got %d want %d", c2, c1+2)
	}

	// Normal mutation should again increment once.
	if _, err := api.StateUpdate(ctx, "x", []byte("v2")); err != nil {
		t.Fatalf("StateUpdate v2 failed: %v", err)
	}
	c3 := api.GetCurrentCounter()
	if c3 != c2+1 {
		t.Fatalf("post-recovery normal inc mismatch: got %d want %d", c3, c2+1)
	}
}

// TestAutoRecovery_ColdStartAdvanceReseal simulates a cold-start scenario where
// the process restarts with a sealed blob from a prior checkpoint but the log
// has advanced. With auto-recovery enabled, verifySealedFreshness should detect
// the descendant advance, reseal the latest checkpoint, and double-increment the
// counter (binding to c+2).
func TestAutoRecovery_ColdStartAdvanceReseal(t *testing.T) {
	dir, err := os.MkdirTemp("", "rollback-test-coldstart")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	signerKey, verifierKey, _ := note.GenerateKey(rand.Reader, "test")
	signer, _ := note.NewSigner(signerKey)
	verifier, _ := note.NewVerifier(verifierKey)

	// First instance: create baseline state and seal at c=2
	api1, err := NewReboundAPI(dir, false, signer, verifier, true)
	if err != nil {
		t.Fatalf("Failed to create API instance 1: %v", err)
	}
	ctx := context.Background()
	if _, err := api1.StateUpdate(ctx, "svc", []byte("v1")); err != nil {
		t.Fatalf("initial update failed: %v", err)
	}

	// Advance the log without resealing (simulate external progress while offline).
	newState := api1.stateManager.GetStateCopy()
	newState["test|coldstart|poke"] = []byte("1")
	b, _ := json.Marshal(newState)
	fut := api1.appender.Add(ctx, tessera.NewEntry(b))
	idx, err := fut()
	if err != nil {
		t.Fatalf("failed to append extra entry: %v", err)
	}
	if err := api1.syncWithExpectedSize(ctx, idx.Index+1); err != nil {
		t.Fatalf("sync after extra append failed: %v", err)
	}
	// Close instance 1 to simulate process exit.
	_ = api1.Close(ctx)

	// Second instance: cold start with sealed blob from previous run and advanced log.
	api2, err := NewReboundAPI(dir, false, signer, verifier, true)
	if err != nil {
		t.Fatalf("Failed to create API instance 2: %v", err)
	}
	defer api2.Close(ctx)
	api2.SetAutoRecoverOnFreshnessMismatch(true)

	// Trigger freshness verification; it should auto-recover via descendant proof
	// and reseal, then double-increment the counter from the sealed value.
	if _, _, err := api2.verifySealedFreshness(ctx); err != nil {
		t.Fatalf("cold-start auto-recovery failed: %v", err)
	}
	// The initial commit sealed at counter=2; after reseal we expect counter=4.
	if got := api2.GetCurrentCounter(); got != 4 {
		t.Fatalf("unexpected counter after cold-start reseal: got=%d want=4", got)
	}

	// A normal mutation should again increment once.
	if _, err := api2.StateUpdate(ctx, "svc2", []byte("v2")); err != nil {
		t.Fatalf("post-reseal update failed: %v", err)
	}
	if got := api2.GetCurrentCounter(); got != 5 {
		t.Fatalf("unexpected counter after normal update: got=%d want=5", got)
	}
}

// TestFetchPerKeyValue verifies that direct keys are resolved via the index and inclusion-proofed
// under the latest sealed checkpoint.
func TestFetchPerKeyValue(t *testing.T) {
	ctx := context.Background()
	dir, err := os.MkdirTemp("", "rebound-fetchkey-")
	if err != nil {
		t.Fatalf("mktemp: %v", err)
	}
	defer os.RemoveAll(dir)

	signerKey, verifierKey, _ := note.GenerateKey(rand.Reader, "test")
	signer, _ := note.NewSigner(signerKey)
	verifier, _ := note.NewVerifier(verifierKey)
	api, err := NewReboundAPI(dir, false, signer, verifier, true)
	if err != nil {
		t.Fatalf("NewReboundAPI: %v", err)
	}
	defer api.Close(ctx)

	// Write a single object and wait for checkpoint
	if _, err := api.StateUpdate(ctx, "k", []byte("v1")); err != nil {
		t.Fatalf("StateUpdate: %v", err)
	}

	// Verify sealed freshness to obtain cp size/root
	size, root, err := api.verifySealedFreshness(ctx)
	if err != nil {
		t.Fatalf("verifySealedFreshness: %v", err)
	}

	// Resolve the exact ovm key for current head
	api.stateManager.mu.RLock()
	headJ := string(api.stateManager.state["ovm-head|k"])
	api.stateManager.mu.RUnlock()
	if headJ == "" {
		t.Fatalf("missing ovm-head|k")
	}
	key := fmt.Sprintf("ovm|%s|%s", "k", headJ)

	// fetchPerKeyValue should return the stored hash and validate inclusion
	v, _, err := api.fetchPerKeyValue(ctx, size, root, key)
	if err != nil {
		t.Fatalf("fetchPerKeyValue(%s) failed: %v", key, err)
	}
	// v should equal hex(SHA256("v1"))
	want := sha256.Sum256([]byte("v1"))
	if string(v) != hex.EncodeToString(want[:]) {
		t.Fatalf("unexpected value: got %s want %s", string(v), hex.EncodeToString(want[:]))
	}

	// Unknown key should return a not-found error from the index
	if _, _, err := api.fetchPerKeyValue(ctx, size, root, "ovm|nope|1"); err == nil {
		t.Fatalf("expected error for unknown key")
	}
}
