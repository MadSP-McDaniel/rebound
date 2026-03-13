package librebound

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/client"
	"github.com/transparency-dev/tessera/storage/posix"
	badger_as "github.com/transparency-dev/tessera/storage/posix/antispam"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

const defaultBundleSize = 256

// Research-prototype constants (DO NOT use in production)
const (
	// Hardcoded Ed25519 seed for sealing signatures; 32 bytes hex.
	sealSeedHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
)

// ReboundAPI represents the main handle to the rebound system.
// It orchestrates the state manager, content store, index database, and the
// underlying transparency log (Tessera) to provide a verifiable state machine.
type ReboundAPI struct {
	appender     *tessera.Appender
	reader       tessera.LogReader
	stateManager *StateManager
	contentStore *ContentStore
	indexDB      *IndexDB
	shutdown     func(context.Context) error
	verifier     note.Verifier
	auditLogPath string
	mu           sync.Mutex

	// Controls whether StateUpdate / TakeSnapshot block until a new checkpoint
	// including the appended entry is observable. When false, those methods
	// still block until the entry is durably appended (future() returns) but
	// they do NOT wait for a signed checkpoint to appear, greatly reducing
	// latency. SealCurrentRoot still performs its own sync.
	waitForCheckpoint bool

	// TPM/sealing related fields
	sealedRoot     []byte
	treeSize       uint64
	tpmEnabled     bool
	sealedBlobPath string
	// Hardcoded seal keypair for research prototype (Ed25519 derived from seed)
	sealPriv ed25519.PrivateKey
	sealPub  ed25519.PublicKey

	// Trusted monotonic counter source (simulated). In production this would
	// query hardware (e.g., TPM/TEE monotonic counter). We keep it inside the
	// API to avoid trusting external, mutable components.
	counter uint64

	// If enabled, verifySealedFreshness will attempt an automatic crash
	// recovery when it detects a mismatch between the latest checkpoint and
	// the locally sealed tuple {size,hash,counter}. The recovery policy is:
	//  - Advance (checkpoint ahead of sealed): allowed only if the current
	//    checkpoint is a descendant of the sealed checkpoint (consistency
	//    proof verifies). We reseal the latest checkpoint and bind it to c+2
	//    (double-increment) to preserve anti-rollback, then increment twice.
	//  - Rewind (checkpoint behind sealed): STRICT policy — only permit the
	//    immediate predecessor (S-1). Any earlier regression aborts. When
	//    allowed, reseal S-1 bound to c+2 and increment twice.
	//  - Counter-only mismatch (same root/size; counter differs): no recovery
	//    is attempted — this is a hard failure. Real systems must use a
	//    hardware monotonic counter that persists across crashes.
	//
	// This mirrors Ariadne’s double-inc strategy; the rewind rule is the
	// stricter tweak requested here.
	autoRecoverOnFreshnessMismatch bool

	// Mutation paths append a single state leaf per transaction.
}

// Namespace keys (authoritative names used in state and leaves).
//
// Design notes:
//   - ovm-head|{obj} records the latest version counter j for an object. This is a
//     per-object head pointer. Historically this was stored under "head|{obj}"; we
//     rename it to make the scope explicit (object-version map head).
//   - deauth-obj-head|{obj}|{j} will record the current authorization bit (0/1)
//     for a specific object-version j. Absence must not be used to imply
//     authorization; values are explicit (0 allow, 1 pruned).
//   - deauth-snap-head|{id} will record the current authorization bit (0/1) for a
//     snapshot ID. As above, absence never means authorized.
//
// These constants are defined now to standardize names; deauth-* heads will be
// wired in subsequent steps of the refactor.
const (
	NsOVMHead        = "ovm-head"         // ovm-head|{obj} -> j (string)
	NsDeauthObjHead  = "deauth-obj-head"  // deauth-obj-head|{obj}|{j} -> "0"/"1"
	NsDeauthSnapHead = "deauth-snap-head" // deauth-snap-head|{id} -> "0"/"1"
)

// LineageEvent captures a single version event for an object as reconstructed
// from the transparency log. Each event corresponds to a change in the head
// pointer for the object, i.e., a new version becoming current.
type LineageEvent struct {
	Object        string
	Counter       uint64
	LeafIndex     uint64
	TimestampUnix int64
	TxID          string // non-"-" implies rollback lineage group id
	Justification string // "update" for normal updates, custom reason for rollback
	Origin        string // previous head counter at the time of change (may be "-")
	ContentHash   string // hex(SHA256(content)) as stored in state
}

// NewReboundAPI initializes the ReboundAPI with Tessera storage.
// storagePath is the directory for log files.
// signer and verifier are used for signing and verifying log checkpoints.
// batchingDelay controls how long the appender waits before flushing entries.
// A delay of 0 disables batching, making writes synchronous (useful for tests).
func NewReboundAPI(storagePath string, enableAntispam bool, signer note.Signer, verifier note.Verifier, testing bool) (*ReboundAPI, error) {
	// If REBOUND_HOME is provided, proactively ensure it (and its o/ subdir) exist
	// before any storage initialization. This gives a single, predictable root
	// for auxiliary outputs and sealed artifacts.
	if home := os.Getenv("REBOUND_HOME"); home != "" {
		if err := os.MkdirAll(home, 0755); err != nil {
			return nil, fmt.Errorf("failed to create REBOUND_HOME (%s): %w", home, err)
		}
		if err := os.MkdirAll(filepath.Join(home, "o"), 0755); err != nil {
			return nil, fmt.Errorf("failed to create REBOUND_HOME/o: %w", err)
		}
	}

	storage, err := posix.New(context.Background(), posix.Config{Path: storagePath})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Tessera storage: %w", err)
	}

	opts := tessera.NewAppendOptions().WithCheckpointSigner(signer)
	opts.WithCheckpointInterval(time.Millisecond) // Default to >5ms (tpm seal latency) checkpoint interval (min allowed, see files.go)

	opts = opts.WithBatching(defaultBundleSize, time.Millisecond)

	if enableAntispam {
		antispamPath := filepath.Join(storagePath, ".state", "antispam")
		if err := os.MkdirAll(antispamPath, 0755); err != nil {
			return nil, fmt.Errorf("failed to create antispam directory: %w", err)
		}
		as, err := badger_as.NewAntispam(context.Background(), antispamPath, badger_as.AntispamOpts{})
		if err != nil {
			return nil, fmt.Errorf("failed to create new Badger antispam storage: %w", err)
		}
		opts = opts.WithAntispam(256, as)
	}

	appender, shutdown, reader, err := tessera.NewAppender(context.Background(), storage, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Tessera appender: %w", err)
	}

	auditLogPath := filepath.Join(storagePath, "audit.log")
	if _, err := os.Stat(auditLogPath); os.IsNotExist(err) {
		if err := os.WriteFile(auditLogPath, []byte{}, 0644); err != nil {
			return nil, fmt.Errorf("failed to create audit log file: %w", err)
		}
	}

	// In test mode, we don't start the HTTP server to avoid handler conflicts.
	if !testing {
		// Start HTTP server for log interaction.
		http.HandleFunc("/add", func(w http.ResponseWriter, r *http.Request) {
			b, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			idx, err := appender.Add(r.Context(), tessera.NewEntry(b))()
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(err.Error()))
				return
			}
			if _, err := fmt.Fprintf(w, "%d", idx.Index); err != nil {
				klog.Errorf("/add: %v", err)
				return
			}
		})

		fs := http.FileServer(http.Dir(storagePath))
		http.Handle("/checkpoint", addCacheHeaders("no-cache", fs))
		http.Handle("/tile/", addCacheHeaders("max-age=31536000, immutable", fs))
		http.Handle("/entries/", fs)
	}

	// Ensure state directory exists (used for antispam and as a fallback seal location)
	stateDir := filepath.Join(storagePath, ".state")
	if err := os.MkdirAll(stateDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create state dir: %w", err)
	}

	// Initialize hardcoded seal key (research prototype only)
	// Seed: 32 bytes hex; DO NOT use in production.
	seed, err := hex.DecodeString(sealSeedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid hardcoded seal seed")
	}
	sealPriv := ed25519.NewKeyFromSeed(seed)
	sealPub := ed25519.PublicKey(sealPriv.Public().(ed25519.PublicKey))

	// Determine sealed blob path.
	// In testing mode, always keep seals local to the storagePath to avoid
	// cross-run interference when REBOUND_HOME is set (e.g., by other tools).
	// In non-testing mode, prefer REBOUND_HOME/o so seals are host-visible.
	sealedHome := os.Getenv("REBOUND_HOME")
	var sealedBlobPath string
	if testing {
		sealedBlobPath = filepath.Join(stateDir, "sealed_root.blob")
	} else if sealedHome != "" {
		sealedOutDir := filepath.Join(sealedHome, "o")
		if err := os.MkdirAll(sealedOutDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create sealed output dir: %w", err)
		}
		sealedBlobPath = filepath.Join(sealedOutDir, "sealed_root.blob")
	} else {
		// Fallback to prior location to keep dev flows working
		sealedBlobPath = filepath.Join(stateDir, "sealed_root.blob")
	}

	return &ReboundAPI{
		appender:          appender,
		reader:            reader,
		stateManager:      NewStateManager(),
		contentStore:      NewContentStore(),
		indexDB:           NewIndexDB(),
		shutdown:          shutdown,
		verifier:          verifier,
		tpmEnabled:        false,
		sealedBlobPath:    sealedBlobPath,
		auditLogPath:      auditLogPath,
		waitForCheckpoint: true, // default preserves previous behavior
		counter:           1,    // start at 1 for first commit
		sealPriv:          sealPriv,
		sealPub:           sealPub,
	}, nil
}

// GetCurrentCounter returns the current trusted global counter value. In
// production this would query hardware; here we just expose the in-memory one.
func (api *ReboundAPI) GetCurrentCounter() uint64 {
	api.mu.Lock()
	defer api.mu.Unlock()
	return api.counter
}

// GetCounter returns the current counter without taking the API mutex.
// Callers must ensure appropriate synchronization (e.g., hold api.mu)
// when using this inside mutation paths. This indirection allows swapping
// in a hardware monotonic counter implementation later.
func (api *ReboundAPI) GetCounter() uint64 {
	return api.counter
}

// IncCounter increments the trusted counter by 1 and returns the new value.
// Callers in mutation paths should hold api.mu to ensure atomicity with
// state updates and sealing. In production this would delegate to hardware.
func (api *ReboundAPI) IncCounter() uint64 {
	api.counter++
	return api.counter
}

// fetchVerifiedCheckpoint reads the latest checkpoint and verifies its
// signature using the configured verifier. Returns the size and hash.
func (api *ReboundAPI) fetchVerifiedCheckpoint(ctx context.Context) (uint64, []byte, error) {
	cpBytes, err := api.readCheckpointBlocking(ctx)
	if err != nil {
		return 0, nil, fmt.Errorf("could not read latest checkpoint: %w", err)
	}
	cp, _, _, err := client.FetchCheckpoint(ctx, func(ctx context.Context) ([]byte, error) { return cpBytes, nil }, api.verifier, api.verifier.Name())
	if err != nil {
		return 0, nil, fmt.Errorf("could not parse/verify checkpoint: %w", err)
	}
	return cp.Size, cp.Hash, nil
}

// verifySealedFreshness verifies that the latest signed checkpoint matches the
// locally sealed tuple {hash,size,counter} and that the sealed counter equals
// the current trusted counter. Returns the checkpoint size and hash on success.
func (api *ReboundAPI) verifySealedFreshness(ctx context.Context) (uint64, []byte, error) {
	// Fetch and verify Tessera checkpoint
	size, root, err := api.fetchVerifiedCheckpoint(ctx)
	if err != nil {
		return 0, nil, err
	}

	// Load and verify the sealed blob.
	type sealInfo struct {
		V       string `json:"v"`
		Size    uint64 `json:"size"`
		HashHex string `json:"hash"`
		Counter uint64 `json:"counter"`
		SigHex  string `json:"sig"`
	}
	readAndVerifySeal := func() (*sealInfo, error) {
		// Simulate TPM unseal latency
		time.Sleep(5 * time.Millisecond)
		data, err := os.ReadFile(api.sealedBlobPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read sealed blob: %w", err)
		}
		var s sealInfo
		if err := json.Unmarshal(data, &s); err != nil {
			return nil, fmt.Errorf("failed to parse sealed blob: %w", err)
		}
		if s.V != "v1" {
			return nil, fmt.Errorf("unsupported seal version: %s", s.V)
		}
		payload := []byte(fmt.Sprintf("v1|size=%d|hash=%s|counter=%d", s.Size, s.HashHex, s.Counter))
		sig, err := hex.DecodeString(s.SigHex)
		if err != nil {
			return nil, fmt.Errorf("invalid seal signature encoding: %w", err)
		}
		if !ed25519.Verify(api.sealPub, payload, sig) {
			return nil, fmt.Errorf("seal signature verification failed")
		}
		return &s, nil
	}

	checkOnce := func() (uint64, []byte, error) {
		seal, err := readAndVerifySeal()
		if err != nil {
			return 0, nil, err
		}
		// Root/size must match the latest checkpoint.
		if seal.Size != size {
			return 0, nil, fmt.Errorf("sealed size mismatch: got %d want %d", seal.Size, size)
		}
		if !strings.EqualFold(seal.HashHex, hex.EncodeToString(root)) {
			return 0, nil, fmt.Errorf("sealed hash mismatch")
		}
		// Freshness: sealed counter must equal current trusted counter.
		if seal.Counter != api.GetCurrentCounter() {
			return 0, nil, fmt.Errorf("stale seal: counter=%d current=%d", seal.Counter, api.GetCurrentCounter())
		}
		return size, root, nil
	}

	// First attempt: strict verification.
	if s, r, e := checkOnce(); e == nil {
		return s, r, nil
	} else if !api.autoRecoverOnFreshnessMismatch {
		klog.Warningf("verifySealedFreshness: strict check failed and auto-recovery disabled: %v", e)
		return 0, nil, e
	}

	// Auto-recovery path: classify mismatch and try to recover according to policy.
	// We re-read both the checkpoint and the seal inside recovery while holding
	// api.mu for counter/seal updates to keep state changes atomic.
	klog.Warningf("verifySealedFreshness: strict check failed; attempting auto-recovery")
	if err := api.recoverFromFreshnessMismatch(ctx); err != nil {
		klog.Errorf("verifySealedFreshness: auto-recovery failed: %v", err)
		return 0, nil, err
	}
	klog.Infof("verifySealedFreshness: auto-recovery succeeded; re-verifying")
	// Re-verify once after recovery.
	size2, root2, err2 := api.fetchVerifiedCheckpoint(ctx)
	if err2 != nil {
		return 0, nil, err2
	}
	// Re-run strict verification against the new checkpoint.
	// Note: the re-run will also validate the counter equals the freshly sealed value.
	{
		// Reuse local helper by shadowing size/root for the re-check
		size = size2
		root = root2
		if s, r, e := checkOnce(); e == nil {
			klog.Infof("verifySealedFreshness: post-recovery strict check passed (size=%d)", s)
			return s, r, nil
		} else {
			klog.Errorf("verifySealedFreshness: post-recovery strict check still failing: %v", e)
			return 0, nil, e
		}
	}
}

// verifyLatestObjectHeads ensures that the latest signed head leaf sets the
// head pointer for each object to the expected counter, and that the object
// entry for that counter exists in the same state map. This binds the update
// to the freshest signed checkpoint without redundant proofs.
// This function checks that the latest signed head leaf reflects the expected
// state for each object and verifies the existence of the corresponding entries.
// It returns an error if any discrepancies are found.

// verifyLatestKeyValues checks that the latest signed head leaf contains the
// provided key/value pairs (exact value match).

// verifyLatestPresence checks that the latest signed head leaf contains all
// the provided keys (value is not validated).

// appendAuditLines writes multiple audit lines for a single transaction and
// binds them into the same state leaf under log|{txid}.
// The digest is sha256 of the exact bytes appended to audit.log for this tx.
func (api *ReboundAPI) appendAuditLines(txState map[string][]byte, txid string, lines []string, counter uint64) error {
	var buf bytes.Buffer
	now := time.Now().UnixNano()
	for _, m := range lines {
		if _, err := fmt.Fprintf(&buf, "%d|%s\n", now, m); err != nil {
			return fmt.Errorf("failed to format audit line: %w", err)
		}
	}
	f, err := os.OpenFile(api.auditLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open audit log for appending: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("failed to write to audit log: %w", err)
	}
	auditHash := sha256.Sum256(buf.Bytes())
	auditKey := fmt.Sprintf("log|%s", txid)
	txState[auditKey] = auditHash[:]
	return nil
}

// readCheckpointBlocking reads the latest checkpoint, blocking until a valid one is available.
func (api *ReboundAPI) readCheckpointBlocking(ctx context.Context) ([]byte, error) {
	for {
		cpBytes, err := api.reader.ReadCheckpoint(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			klog.Warningf("Failed to read checkpoint, will retry: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		return cpBytes, nil
	}
}

// syncWithExpectedSize waits until the log checkpoint includes a given size.
func (api *ReboundAPI) syncWithExpectedSize(ctx context.Context, expectedSize uint64) error {
	klog.Infof("Waiting for checkpoint to include size %d", expectedSize)
	for {
		cpBytes, err := api.readCheckpointBlocking(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			klog.Warningf("Failed to read checkpoint while syncing, will retry: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		parsedCP, _, _, err := client.FetchCheckpoint(ctx, func(ctx context.Context) ([]byte, error) { return cpBytes, nil }, api.verifier, api.verifier.Name())
		if err != nil {
			klog.Warningf("Failed to parse checkpoint while syncing, will retry: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if parsedCP.Size >= expectedSize {
			klog.Infof("Checkpoint with size %d is now visible", parsedCP.Size)
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// StateUpdate performs an atomic state update. It stores the new data, updates
// the state map, and commits the new state map to the transparency log.
// It returns the hash of the newly committed state.
func (api *ReboundAPI) StateUpdate(ctx context.Context, objectName string, data []byte) ([]byte, error) {
	// Delegate to batch API for single-object updates.
	return api.StateUpdateBatch(ctx, map[string][]byte{objectName: data})
}

// StateUpdateBatch performs an atomic state update for multiple objects.
// Protocol (namespaces and invariants):
//   - For each object in the batch, writes a per-key leaf: { "ovm|{name}|{c}": hex(SHA256(content)) }
//   - Updates in-memory heads: ovm-head|{name} → {c} and deauth-obj-head|{name}|{c} = "0"
//   - Records audit lines and appends a per-key leaf for { "log|{txid}": sha256(lines) }
//   - Appends a current-view leaf last (authoritative for gating/listing)
//   - Seals root bound to c+1, increments counter once (store-then-inc discipline)
func (api *ReboundAPI) StateUpdateBatch(ctx context.Context, objects map[string][]byte) ([]byte, error) {
	api.mu.Lock()
	defer api.mu.Unlock()

	if len(objects) == 0 {
		return nil, fmt.Errorf("no objects provided for batch update")
	}

	// Store-then-inc: compute next counter but publish it only after sealing.
	counter := api.GetCounter() + 1
	// Generate a transaction id (txid) for this batch mutation.
	txid := fmt.Sprintf("txid-%d", counter)
	// Log the incoming batch for traceability (object names only).
	if klog.V(1).Enabled() {
		var names []string
		for n := range objects {
			names = append(names, n)
		}
		sort.Strings(names)
		klog.V(1).Infof("StateUpdateBatch: c=%d txid=%s objects=%v", counter, txid, names)
	}

	newState := api.stateManager.GetStateCopy()
	// Apply each object mutation in deterministic (sorted) order and append per-key ovm leaf
	var objectNames []string
	for name := range objects {
		objectNames = append(objectNames, name)
	}
	sort.Strings(objectNames)
	for _, objectName := range objectNames {
		data := objects[objectName]
		contentHash, err := api.contentStore.Store(data)
		if err != nil {
			return nil, fmt.Errorf("failed to store content for %s: %w", objectName, err)
		}
		prevHead := "-"
		if b, ok := newState[fmt.Sprintf("%s|%s", NsOVMHead, objectName)]; ok {
			prevHead = string(b)
		}
		// Materialize version tuple under ovm namespace (single source of truth)
		ovmKey := fmt.Sprintf("ovm|%s|%d", objectName, counter)
		newState[ovmKey] = []byte(contentHash)
		headKey := fmt.Sprintf("%s|%s", NsOVMHead, objectName)
		newState[headKey] = []byte(strconv.FormatUint(counter, 10))
		// Explicit per-object-version authorization head defaults to "0" (authorized).
		newState[fmt.Sprintf("%s|%s|%d", NsDeauthObjHead, objectName, counter)] = []byte("0")
		ts := strconv.FormatInt(time.Now().UnixNano(), 10)
		newState[fmt.Sprintf("meta|object|%s|%d|origin", objectName, counter)] = []byte(prevHead)
		// For normal updates, keep meta txid as "-"; txid is recorded in audit lines for correlation.
		newState[fmt.Sprintf("meta|object|%s|%d|txid", objectName, counter)] = []byte("-")
		newState[fmt.Sprintf("meta|object|%s|%d|just", objectName, counter)] = []byte("update")
		newState[fmt.Sprintf("meta|object|%s|%d|ts", objectName, counter)] = []byte(ts)

		// Append per-key ovm leaf for this object, including minimal metadata for lineage
		leaf := map[string][]byte{
			ovmKey: []byte(contentHash),
			// meta keys to allow lineage reconstruction without scanning other leaves
			fmt.Sprintf("meta|object|%s|%d|origin", objectName, counter): []byte(prevHead),
			fmt.Sprintf("meta|object|%s|%d|txid", objectName, counter):   []byte("-"),
			fmt.Sprintf("meta|object|%s|%d|just", objectName, counter):   []byte("update"),
			fmt.Sprintf("meta|object|%s|%d|ts", objectName, counter):     []byte(ts),
		}
		b, err := json.Marshal(leaf)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ovm leaf for %s: %w", objectName, err)
		}
		idx, err := api.appender.Add(ctx, tessera.NewEntry(b))()
		if err != nil {
			return nil, fmt.Errorf("append ovm leaf for %s: %w", objectName, err)
		}
		// Index mapping for quick lookup of this version
		_ = api.indexDB.Store(ovmKey, idx.Index)
	}

	// Sealed audit provenance for this batch update lists all objects.
	var objNames []string
	for name := range objects {
		objNames = append(objNames, name)
	}
	sort.Strings(objNames)
	auditLines := []string{
		fmt.Sprintf("UPDATE_INTENT c=%d txid=%s objects=%v", counter, txid, objNames),
		fmt.Sprintf("UPDATE_APPLY c=%d txid=%s objects=%v head=%d", counter, txid, objNames, counter),
		fmt.Sprintf("TX_COMPLETE c=%d type=update txid=%s batch_size=%d", counter, txid, len(objects)),
	}
	// Append per-key audit leaf and also keep it in newState for internal lookups
	auditState := map[string][]byte{}
	if err := api.appendAuditLines(auditState, txid, auditLines, counter); err != nil {
		return nil, err
	}
	for k, v := range auditState { // only log|txid
		newState[k] = v
		b, err := json.Marshal(map[string][]byte{k: v})
		if err != nil {
			return nil, fmt.Errorf("failed to marshal audit leaf: %w", err)
		}
		res, err := api.appender.Add(ctx, tessera.NewEntry(b))()
		if err != nil {
			return nil, fmt.Errorf("append audit leaf: %w", err)
		}
		_ = api.indexDB.Store(k, res.Index)
	}

	// Compute a return hash deterministically from the in-memory state (not logged as a packed leaf)
	stateBytes, _ := json.Marshal(newState)
	stateHash := sha256.Sum256(stateBytes)

	api.stateManager.LoadStateFromBytes(newState)

	// Append current-view leaf last to provide authoritative S-1 view for gating and listings.
	cvIdx, err := api.appendCurrentViewLeaf(ctx, newState)
	if err != nil {
		return nil, err
	}
	if api.waitForCheckpoint {
		if err := api.syncWithExpectedSize(ctx, cvIdx+1); err != nil {
			return nil, fmt.Errorf("failed to sync after batch state update: %w", err)
		}
	}

	// Seal and bind to the soon-to-be-published counter (c+1)
	if err := api.SealCurrentRoot(ctx, counter); err != nil {
		klog.Warningf("Failed to seal current root after batch update: %v", err)
	}

	// Publish the counter as the final step to keep
	// (current counter == last sealed) invariant.
	_ = api.IncCounter()
	klog.V(1).Infof("StateUpdateBatch: completed publish c=%d", api.counter)

	return stateHash[:], nil
}

// TakeSnapshot commits the current state to the log with a snapshot tag.
// Protocol (namespaces and invariants):
//   - Writes a per-key leaf for snap|{id} as a tag→set (mapping obj→head counter)
//   - Does NOT write any status or metadata fields; eligibility is controlled by current-view heads
//   - Appends a per-key audit leaf and a current-view leaf last
//
// Returns the hash of the committed state.
func (api *ReboundAPI) TakeSnapshot(ctx context.Context, snapshotID string) ([]byte, error) {
	api.mu.Lock()
	defer api.mu.Unlock()

	// Store-then-inc: compute next counter but publish it only after sealing.
	counter := api.GetCounter() + 1
	txid := fmt.Sprintf("txid-%d", counter)
	klog.V(1).Infof("TakeSnapshot: id=%s c=%d txid=%s", snapshotID, counter, txid)

	newState := api.stateManager.GetStateCopy()
	snapshotKey := fmt.Sprintf("snap|%s", snapshotID)
	// Build tag→set mapping of object heads at the time of snapshot.
	snapSet := make(map[string]string)
	for k, v := range newState {
		if strings.HasPrefix(k, NsOVMHead+"|") {
			// k format: head|<obj>
			parts := strings.Split(k, "|")
			if len(parts) == 2 {
				obj := parts[1]
				snapSet[obj] = string(v)
			}
		}
	}
	snapSetBytes, err := json.Marshal(snapSet)
	if err != nil {
		return nil, fmt.Errorf("failed to encode snapshot set: %w", err)
	}
	// Snapshot marker binds the snapshot ID to this set under the authoritative state.
	newState[snapshotKey] = snapSetBytes
	// Explicit snapshot authorization head defaults to "0" (authorized) at creation time.
	newState[fmt.Sprintf("%s|%s", NsDeauthSnapHead, snapshotID)] = []byte("0")
	// No separate snapshot metadata is written; audit lines below provide provenance.

	// Sealed audit provenance for this snapshot.
	auditLines := []string{
		fmt.Sprintf("SNAPSHOT_INTENT c=%d txid=%s id=%s", counter, txid, snapshotID),
		fmt.Sprintf("SNAPSHOT_APPLY c=%d txid=%s id=%s", counter, txid, snapshotID),
		fmt.Sprintf("TX_COMPLETE c=%d type=snapshot txid=%s id=%s", counter, txid, snapshotID),
	}
	// Append per-key snap|id leaf
	{
		b, err := json.Marshal(map[string][]byte{snapshotKey: snapSetBytes})
		if err != nil {
			return nil, fmt.Errorf("failed to marshal snapshot leaf: %w", err)
		}
		idx, err := api.appender.Add(ctx, tessera.NewEntry(b))()
		if err != nil {
			return nil, fmt.Errorf("append snapshot leaf: %w", err)
		}
		_ = api.indexDB.Store(snapshotKey, idx.Index)
	}
	// Append per-key audit leaf and also keep it in newState
	auditState := map[string][]byte{}
	if err := api.appendAuditLines(auditState, txid, auditLines, counter); err != nil {
		return nil, err
	}
	for k, v := range auditState {
		newState[k] = v
		b, err := json.Marshal(map[string][]byte{k: v})
		if err != nil {
			return nil, fmt.Errorf("failed to marshal audit leaf: %w", err)
		}
		res, err := api.appender.Add(ctx, tessera.NewEntry(b))()
		if err != nil {
			return nil, fmt.Errorf("append audit leaf: %w", err)
		}
		_ = api.indexDB.Store(k, res.Index)
	}

	// Return value: hash of current state snapshot (not logged as packed leaf)
	stateBytes, _ := json.Marshal(newState)
	stateHash := sha256.Sum256(stateBytes)

	api.stateManager.LoadStateFromBytes(newState)

	// Append current-view leaf last
	cvIdx, err := api.appendCurrentViewLeaf(ctx, newState)
	if err != nil {
		return nil, err
	}
	if api.waitForCheckpoint {
		if err := api.syncWithExpectedSize(ctx, cvIdx+1); err != nil {
			return nil, fmt.Errorf("failed to sync after taking snapshot: %w", err)
		}
	}

	// Seal and bind to c+1
	if err := api.SealCurrentRoot(ctx, counter); err != nil {
		klog.Warningf("Failed to seal current root after snapshot: %v", err)
	}

	// Publish the counter as the final step.
	_ = api.IncCounter()
	klog.V(1).Infof("TakeSnapshot: completed publish c=%d id=%s", api.counter, snapshotID)

	return stateHash[:], nil
}

// ListSnapshots lists all snapshots that have been taken.
// Reads latest checkpoint and extracts IDs from the preceding state leaf by scanning
// for keys with prefix snap|{id}. This is a read-only, authenticated view.
func (api *ReboundAPI) ListSnapshots(ctx context.Context) ([]string, error) {
	// Authenticate against sealed, counter-bound checkpoint
	size, root, err := api.verifySealedFreshness(ctx)
	if err != nil {
		return nil, err
	}
	if size == 0 {
		return []string{}, nil
	}
	// Reconstruct current-view (head + chunks)
	state, err := api.fetchCurrentView(ctx, size, root)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch current-view: %w", err)
	}
	idsSet := make(map[string]struct{})
	for k := range state {
		if strings.HasPrefix(k, NsDeauthSnapHead+"|") {
			parts := strings.Split(k, "|")
			if len(parts) == 2 {
				idsSet[parts[1]] = struct{}{}
			}
		}
	}
	// Materialize and return in deterministic order
	var ids []string
	for id := range idsSet {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}

// VerifyAudit recomputes the audit digest for the given txid by scanning the
// on-disk audit.log for the most recent block of lines containing "txid=..."
// and comparing sha256(lines) to the digest stored under log|{txid} in the
// latest state leaf included by the sealed, freshness-verified checkpoint.
func (api *ReboundAPI) VerifyAudit(ctx context.Context, txid string) (bool, error) {
	if txid == "" {
		return false, fmt.Errorf("txid must not be empty")
	}
	// 1) Verify freshness.
	size, root, err := api.verifySealedFreshness(ctx)
	if err != nil {
		return false, err
	}
	if size == 0 {
		return false, fmt.Errorf("empty log")
	}
	// Resolve the audit digest from the per-key log|txid leaf and verify inclusion under the same checkpoint.
	key := fmt.Sprintf("log|%s", txid)
	want, _, err := api.fetchPerKeyValue(ctx, size, root, key)
	if err != nil {
		return false, err
	}
	// 2) Recompute digest from audit.log: collect contiguous lines for this tx.
	data, err := os.ReadFile(api.auditLogPath)
	if err != nil {
		return false, fmt.Errorf("failed to read audit log: %w", err)
	}
	// We recorded lines with a timestamp prefix and the provided message; select the
	// most recent block of lines containing "txid=<id>". We consider a block as the
	// contiguous lines from the last occurrence of UPDATE/SNAPSHOT/PRUNE/ROLLBACK markers
	// including TX_COMPLETE with this txid.
	lines := bytes.Split(data, []byte("\n"))
	var block [][]byte
	// Scan from end for TX_COMPLETE with this txid; then walk backwards to prior *_INTENT with same txid.
	txToken := []byte("txid=" + txid)
	start, end := -1, -1
	for i := len(lines) - 1; i >= 0; i-- {
		if bytes.Contains(lines[i], []byte("TX_COMPLETE")) && bytes.Contains(lines[i], txToken) {
			end = i
			break
		}
	}
	if end == -1 {
		return false, fmt.Errorf("no TX_COMPLETE for txid=%s in audit log", txid)
	}
	for i := end; i >= 0; i-- {
		if (bytes.Contains(lines[i], []byte("_INTENT")) || bytes.Contains(lines[i], []byte("INTENT"))) && bytes.Contains(lines[i], txToken) {
			start = i
			break
		}
	}
	if start == -1 {
		return false, fmt.Errorf("no *_INTENT for txid=%s before TX_COMPLETE in audit log", txid)
	}
	block = lines[start : end+1]
	// Recompose exact bytes with trailing newlines (they already include the timestamp prefix and \n)
	buf := bytes.Join(block, []byte("\n"))
	// If the file had a trailing newline, Join added extras; normalize by splitting again
	if len(buf) > 0 && buf[len(buf)-1] != '\n' {
		buf = append(buf, '\n')
	}
	got := sha256.Sum256(buf)
	if !bytes.Equal(got[:], want) {
		return false, fmt.Errorf("audit digest mismatch for %s", txid)
	}
	return true, nil
}

// fetchPerKeyValue locates the per-key leaf for the provided key using the index,
// verifies inclusion of that leaf under the current checkpoint, and returns the value.
func (api *ReboundAPI) fetchPerKeyValue(ctx context.Context, cpSize uint64, cpRoot []byte, key string) ([]byte, uint64, error) {
	idx, err := api.indexDB.GetIndex(key)
	if err != nil {
		return nil, 0, fmt.Errorf("%s not found in index: %w", key, err)
	}
	bundle, err := client.GetEntryBundle(ctx, api.reader.ReadEntryBundle, idx/defaultBundleSize, cpSize)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to fetch bundle for %s at %d: %w", key, idx, err)
	}
	leaf := bundle.Entries[idx%defaultBundleSize]
	// Verify inclusion under checkpoint
	pb, err := client.NewProofBuilder(ctx, cpSize, api.reader.ReadTile)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create proof builder: %w", err)
	}
	incl, err := pb.InclusionProof(ctx, idx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get inclusion proof for %s at %d: %w", key, idx, err)
	}
	if err := proof.VerifyInclusion(rfc6962.DefaultHasher, idx, cpSize, rfc6962.DefaultHasher.HashLeaf(leaf), incl, cpRoot); err != nil {
		return nil, 0, fmt.Errorf("inclusion proof failed for %s at %d: %w", key, idx, err)
	}
	// Parse and extract value
	var m map[string][]byte
	if err := json.Unmarshal(leaf, &m); err != nil {
		return nil, 0, fmt.Errorf("failed to parse per-key leaf for %s: %w", key, err)
	}
	v, ok := m[key]
	if !ok {
		return nil, 0, fmt.Errorf("key %s not present in its per-key leaf (corrupt index?)", key)
	}
	return v, idx, nil
}

// PruneSnapshot records a de-authorization tombstone for a snapshot and commits
// this change to the log with sealed audit provenance.
// Protocol (namespaces and invariants):
//   - Writes a per-key leaf deauth|snap|{id}|{c} with a reason (e.g., justification or "pruned")
//   - Appends a per-key audit leaf and a current-view leaf last
func (api *ReboundAPI) PruneSnapshot(ctx context.Context, snapshotID string, justification string) ([]byte, error) {
	api.mu.Lock()
	defer api.mu.Unlock()

	// Store-then-inc: compute next counter but publish it only after sealing.
	counter := api.GetCounter() + 1
	txid := fmt.Sprintf("txid-%d", counter)
	klog.V(1).Infof("PruneSnapshot: id=%s c=%d txid=%s just=%q", snapshotID, counter, txid, justification)

	newState := api.stateManager.GetStateCopy()
	// De-authorization tombstone for the snapshot at this counter. Presence of any
	// deauth|snap|{id}|* entry gates future rollbacks to this snapshot.
	deauthKey := fmt.Sprintf("deauth|snap|%s|%d", snapshotID, counter)
	// Value can encode the reason; we use the justification string directly for human readability.
	if justification == "" {
		newState[deauthKey] = []byte("pruned")
	} else {
		newState[deauthKey] = []byte(justification)
	}
	// Update explicit snapshot authorization head to "1" (deauthorized).
	newState[fmt.Sprintf("%s|%s", NsDeauthSnapHead, snapshotID)] = []byte("1")
	// Note: meta|deauth|... keys were previously recorded for human-readable provenance,
	// but enforcement and lineage do not rely on them, so they are omitted.

	// Sealed audit provenance.
	auditLines := []string{
		fmt.Sprintf("PRUNE_INTENT c=%d txid=%s snapshot=%s just=%q", counter, txid, snapshotID, justification),
		fmt.Sprintf("PRUNE_APPLY c=%d txid=%s snapshot=%s deauth=1", counter, txid, snapshotID),
		fmt.Sprintf("TX_COMPLETE c=%d type=prune txid=%s snapshot=%s", counter, txid, snapshotID),
	}
	// Append per-key deauth leaf
	{
		b, err := json.Marshal(map[string][]byte{deauthKey: newState[deauthKey]})
		if err != nil {
			return nil, fmt.Errorf("failed to marshal deauth leaf: %w", err)
		}
		idx, err := api.appender.Add(ctx, tessera.NewEntry(b))()
		if err != nil {
			return nil, fmt.Errorf("append deauth leaf: %w", err)
		}
		// Index deauth record for quick checks.
		_ = api.indexDB.Store(fmt.Sprintf("deauth|snap|%s", snapshotID), idx.Index)
	}

	// Append per-key audit leaf and also keep it in newState
	auditState := map[string][]byte{}
	if err := api.appendAuditLines(auditState, txid, auditLines, counter); err != nil {
		return nil, err
	}
	for k, v := range auditState {
		newState[k] = v
		b, err := json.Marshal(map[string][]byte{k: v})
		if err != nil {
			return nil, fmt.Errorf("failed to marshal audit leaf: %w", err)
		}
		res, err := api.appender.Add(ctx, tessera.NewEntry(b))()
		if err != nil {
			return nil, fmt.Errorf("append audit leaf: %w", err)
		}
		_ = api.indexDB.Store(k, res.Index)
	}

	// Compute return hash from newState
	stateBytes, _ := json.Marshal(newState)
	stateHash := sha256.Sum256(stateBytes)

	api.stateManager.LoadStateFromBytes(newState)

	// Append current-view leaf last
	cvIdx, err := api.appendCurrentViewLeaf(ctx, newState)
	if err != nil {
		return nil, err
	}
	if api.waitForCheckpoint {
		if err := api.syncWithExpectedSize(ctx, cvIdx+1); err != nil {
			return nil, fmt.Errorf("failed to sync after prune: %w", err)
		}
	}

	// Seal and bind to c+1
	if err := api.SealCurrentRoot(ctx, counter); err != nil {
		klog.Warningf("Failed to seal current root after prune: %v", err)
	}

	// Publish the counter as the final step.
	_ = api.IncCounter()
	klog.V(1).Infof("PruneSnapshot: completed publish c=%d id=%s", api.counter, snapshotID)

	return stateHash[:], nil
}

// RollbackToSnapshot rolls back the in-memory state to a specific snapshot.
// Protocol:
//   - Verifies snapshot leaf inclusion under latest sealed checkpoint
//   - Gating: denies rollback if any deauth|snap|{id}|* exists in latest state
//   - Recomposition: creates new heads for objects listed in the snapshot using current counter
//   - Appends per-key ovm leaves for each object, a per-key audit leaf, and a current-view leaf last
func (api *ReboundAPI) RollbackToSnapshot(ctx context.Context, snapshotID string, justification string) (bool, error) {
	snapshotKey := fmt.Sprintf("snap|%s", snapshotID)
	if _, err := api.indexDB.GetIndex(snapshotKey); err != nil {
		return false, fmt.Errorf("snapshot %s not found in index: %w", snapshotID, err)
	}
	klog.V(1).Infof("RollbackToSnapshot: id=%s just=%q", snapshotID, justification)

	// Authenticate against sealed, counter-bound checkpoint for freshness
	size, root, err := api.verifySealedFreshness(ctx)
	if err != nil {
		return false, err
	}

	// Gating: deny rollback if any de-authorization tombstone exists for this snapshot id.
	if size == 0 {
		return false, fmt.Errorf("empty log; cannot rollback")
	}
	headState, err := api.fetchCurrentView(ctx, size, root)
	if err != nil {
		return false, fmt.Errorf("failed to fetch current-view for status check: %w", err)
	}
	// Gating via current-view: explicit deauth-snap-head|id must be present and not "1".
	dkey := fmt.Sprintf("%s|%s", NsDeauthSnapHead, snapshotID)
	dv, ok := headState[dkey]
	if !ok {
		return false, fmt.Errorf("current-view incomplete: missing %s; cannot decide authorization for rollback", dkey)
	}
	if string(dv) == "1" {
		return false, fmt.Errorf("snapshot '%s' is pruned; rollback is not permitted", snapshotID)
	}

	// Resolve snapshot tag→set from its per-key leaf with inclusion verification.
	snapTagKey := fmt.Sprintf("snap|%s", snapshotID)
	raw, _, err := api.fetchPerKeyValue(ctx, size, root, snapTagKey)
	if err != nil {
		return false, fmt.Errorf("failed to resolve snapshot set for '%s': %w", snapshotID, err)
	}
	var snapSet map[string]string
	if err := json.Unmarshal(raw, &snapSet); err != nil {
		return false, fmt.Errorf("failed to parse snapshot set for '%s': %w", snapshotID, err)
	}
	klog.Infof("RollbackToSnapshot: Successfully resolved snapshot set for '%s' with %d entries", snapshotID, len(snapSet))

	// --- Begin mutation phase: lock api.mu for all state/index/counter changes ---
	api.mu.Lock()
	defer api.mu.Unlock()

	// Forward recomposition (heads-only): for each object head at the snapshot, materialize a new
	// version at counter c with origin set to current head and txid bound to this rollback.
	// Uses store-then-inc discipline and appends a single state leaf for the recomposition.
	counter := api.GetCounter() + 1
	txid := fmt.Sprintf("txid-%d", counter)
	klog.V(1).Infof("RollbackToSnapshot: composing heads-only overlay c=%d txid=%s", counter, txid)
	curState := api.stateManager.GetStateCopy() // snapshot of current state for origin heads and as base
	// Heads-only rollback: overlay new head/materialized entries onto the current state copy.
	newState := curState
	for objName, snapCtrStr := range snapSet {
		objAtSnapKey := fmt.Sprintf("ovm|%s|%s", objName, snapCtrStr)
		contentHash, _, err := api.fetchPerKeyValue(ctx, size, root, objAtSnapKey)
		if err != nil {
			return false, fmt.Errorf("failed to resolve content hash for %s: %w", objAtSnapKey, err)
		}
		prevHeadCtr := "-"
		if b, ok := curState[fmt.Sprintf("%s|%s", NsOVMHead, objName)]; ok {
			prevHeadCtr = string(b)
		}
		newObjKey := fmt.Sprintf("ovm|%s|%d", objName, counter)
		newState[newObjKey] = contentHash
		newState[fmt.Sprintf("%s|%s", NsOVMHead, objName)] = []byte(strconv.FormatUint(counter, 10))
		// OVM mirror already written via newObjKey
		ts := strconv.FormatInt(time.Now().UnixNano(), 10)
		newState[fmt.Sprintf("meta|object|%s|%d|origin", objName, counter)] = []byte(prevHeadCtr)
		newState[fmt.Sprintf("meta|object|%s|%d|txid", objName, counter)] = []byte(txid)
		newState[fmt.Sprintf("meta|object|%s|%d|just", objName, counter)] = []byte(justification)
		newState[fmt.Sprintf("meta|object|%s|%d|ts", objName, counter)] = []byte(ts)
	}

	// Sealed audit provenance describing this rollback.
	auditLines := []string{
		fmt.Sprintf("ROLLBACK_INTENT c=%d snapshot=%s txid=%s just=%q", counter, snapshotID, txid, justification),
		fmt.Sprintf("ROLLBACK_APPLY c=%d snapshot=%s txid=%s just=%q", counter, snapshotID, txid, justification),
		fmt.Sprintf("TX_COMPLETE c=%d type=rollback snapshot=%s txid=%s just=%q", counter, snapshotID, txid, justification),
	}
	// Append per-key ovm leaves for each object in the snapshot set
	for objName := range snapSet {
		ovmKey := fmt.Sprintf("ovm|%s|%d", objName, counter)
		// Include metadata keys so lineage shows rollback with txid/justification
		leaf := map[string][]byte{
			ovmKey: newState[ovmKey],
			fmt.Sprintf("meta|object|%s|%d|origin", objName, counter): []byte(newState[fmt.Sprintf("meta|object|%s|%d|origin", objName, counter)]),
			fmt.Sprintf("meta|object|%s|%d|txid", objName, counter):   []byte(newState[fmt.Sprintf("meta|object|%s|%d|txid", objName, counter)]),
			fmt.Sprintf("meta|object|%s|%d|just", objName, counter):   []byte(newState[fmt.Sprintf("meta|object|%s|%d|just", objName, counter)]),
			fmt.Sprintf("meta|object|%s|%d|ts", objName, counter):     []byte(newState[fmt.Sprintf("meta|object|%s|%d|ts", objName, counter)]),
		}
		b, err := json.Marshal(leaf)
		if err != nil {
			return false, fmt.Errorf("failed to marshal rollback ovm leaf: %w", err)
		}
		idx, err := api.appender.Add(ctx, tessera.NewEntry(b))()
		if err != nil {
			return false, fmt.Errorf("append rollback ovm leaf: %w", err)
		}
		_ = api.indexDB.Store(ovmKey, idx.Index)
	}
	// Append per-key audit leaf and keep in state
	auditState := map[string][]byte{}
	if err := api.appendAuditLines(auditState, txid, auditLines, counter); err != nil {
		return false, err
	}
	for k, v := range auditState {
		newState[k] = v
		b, err := json.Marshal(map[string][]byte{k: v})
		if err != nil {
			return false, fmt.Errorf("failed to marshal audit leaf: %w", err)
		}
		res, err := api.appender.Add(ctx, tessera.NewEntry(b))()
		if err != nil {
			return false, fmt.Errorf("append audit leaf: %w", err)
		}
		_ = api.indexDB.Store(k, res.Index)
	}

	// Append current-view leaf last
	cvIdx, err := api.appendCurrentViewLeaf(ctx, newState)
	if err != nil {
		return false, err
	}
	if api.waitForCheckpoint {
		if err := api.syncWithExpectedSize(ctx, cvIdx+1); err != nil {
			return false, fmt.Errorf("failed waiting for checkpoint after rollback append: %w", err)
		}
	}

	api.stateManager.LoadStateFromBytes(newState)

	// Seal after rollback to bind the new checkpoint to the counter (c+1)
	if err := api.SealCurrentRoot(ctx, counter); err != nil {
		klog.Warningf("Failed to seal current root after rollback: %v", err)
	}

	// Publish the counter as the final step.
	_ = api.IncCounter()
	klog.V(1).Infof("RollbackToSnapshot: completed publish c=%d id=%s", api.counter, snapshotID)

	return true, nil
}

// VerifyEntryInSnapshot verifies that a key-value pair is correctly included
// within a specific snapshot in the transparency log.
//
// Cryptographic model (current):
//  1. Treat the entire statemap as a single log leaf; verify inclusion of the exact
//     leaf bytes under the latest checkpoint using Tessera's proof APIs.
//  2. Parse those committed bytes and check the key/value inside them. This avoids
//     any inner Merkle logic; membership is implied by being present in the
//     committed blob whose bytes are proven by the log inclusion.
//
// NOTE: Today the statemap is a simple JSON map and we assume it can be parsed in
// memory for verification. If the snapshot blob becomes too large (or you need
// per-key/non-membership proofs without fetching the whole blob), then introduce
// an inner commitment (e.g., a Merkle/Sparse-Merkle root or a manifest of shard
// hashes) inside the logged leaf and perform a second, local membership proof
// against that inner root, still anchored by a single Tessera checkpoint.
func (api *ReboundAPI) VerifyEntryInSnapshot(ctx context.Context, snapshotID string, key string, expectedData []byte) (bool, error) {
	klog.V(2).Infof("VerifyEntryInSnapshot: id=%s key=%s", snapshotID, key)
	// Authenticate against sealed, counter-bound checkpoint
	size, root, err := api.verifySealedFreshness(ctx)
	if err != nil {
		return false, err
	}

	// 1) Fetch the snapshot tag→set from its per-key leaf and verify inclusion.
	snapTagKey := fmt.Sprintf("snap|%s", snapshotID)
	rawSnapSet, _, err := api.fetchPerKeyValue(ctx, size, root, snapTagKey)
	if err != nil {
		return false, fmt.Errorf("snapshot %s not found or not provable: %w", snapshotID, err)
	}
	var snapSet map[string]string
	if err := json.Unmarshal(rawSnapSet, &snapSet); err != nil {
		return false, fmt.Errorf("failed to parse snapshot set for '%s': %w", snapshotID, err)
	}

	// 2) If key is not in the tag→set, membership is false. If expectedData == nil, success.
	cStr, ok := snapSet[key]
	if !ok {
		return expectedData == nil, nil
	}
	if expectedData == nil {
		return false, fmt.Errorf("key '%s' was found in snapshot '%s' but was not expected", key, snapshotID)
	}

	// 3) Resolve the per-key ovm|key|c leaf to get committed content hash and verify inclusion.
	objKey := fmt.Sprintf("ovm|%s|%s", key, cStr)
	actualHash, _, err := api.fetchPerKeyValue(ctx, size, root, objKey)
	if err != nil {
		return false, fmt.Errorf("failed to resolve historical object leaf %s: %w", objKey, err)
	}

	// 4) Compare hashes: expected is hex(SHA256(expectedData)).
	expectedSHA := sha256.Sum256(expectedData)
	expectedHash := hex.EncodeToString(expectedSHA[:])
	if !bytes.Equal(actualHash, []byte(expectedHash)) {
		return false, fmt.Errorf("content hash mismatch for key '%s' in snapshot '%s'", key, snapshotID)
	}

	return true, nil
}

// SealCurrentRoot seals the current tree root. This is a stub for TPM integration.
func (api *ReboundAPI) SealCurrentRoot(ctx context.Context, bindCounter uint64) error {
	// Note: we bind the seal to the provided counter (typically c+1 under
	// store-then-inc). This keeps (sealed.counter == current counter) invariant
	// when verifySealedFreshness reads back the sealed blob.
	// Fetch the latest verified checkpoint (size, hash) without redundant sync or parsing.
	size, hash, err := api.fetchVerifiedCheckpoint(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch verified checkpoint: %w", err)
	}

	// TODO: Integrate TPM-backed sealing for cp.Hash and cp.Size.
	//  - Create a sealed blob bound to desired PCRs and persist it at api.sealedBlobPath.
	//  - Store any required public parameters to enable VerifyLogIntegrity to unseal/verify.
	//  - Replace the in-memory assignment below with TPM seal/unseal flows.
	if api.tpmEnabled {
		return fmt.Errorf("TPM sealing not yet implemented")
	}

	// Simulate TPM seal latency
	time.Sleep(5 * time.Millisecond)

	api.sealedRoot = hash
	api.treeSize = size

	// Research-prototype seal to disk using hardcoded Ed25519 key
	hashHex := hex.EncodeToString(hash)
	// Note: bind the seal to the provided counter value (typically c+1 under store-then-inc).
	payload := []byte(fmt.Sprintf("v1|size=%d|hash=%s|counter=%d", size, hashHex, bindCounter))
	sig := ed25519.Sign(api.sealPriv, payload)
	sealObj := struct {
		V       string `json:"v"`
		Size    uint64 `json:"size"`
		HashHex string `json:"hash"`
		Counter uint64 `json:"counter"`
		SigHex  string `json:"sig"`
	}{V: "v1", Size: size, HashHex: hashHex, Counter: bindCounter, SigHex: hex.EncodeToString(sig)}
	blob, err := json.Marshal(sealObj)
	if err != nil {
		return fmt.Errorf("failed to marshal seal: %w", err)
	}
	if err := os.WriteFile(api.sealedBlobPath, blob, 0644); err != nil {
		return fmt.Errorf("failed to write seal blob: %w", err)
	}
	klog.V(1).Infof("SealCurrentRoot: sealed size=%d hash=%s counter=%d", size, hex.EncodeToString(hash), bindCounter)
	return nil
}

// LoadSealedRoot loads and unseals the root from a trusted source. Stub for TPM.

// SetWaitForCheckpoint toggles whether state mutations wait for a new
// checkpoint to become visible after appending. Disabling this reduces
// latency but means immediate callers may not yet obtain inclusion /
// consistency proofs until the next checkpoint is produced.
func (api *ReboundAPI) SetWaitForCheckpoint(wait bool) {
	api.mu.Lock()
	defer api.mu.Unlock()
	api.waitForCheckpoint = wait
}

// VerifyLogIntegrity checks the current log state against the sealed root.
func (api *ReboundAPI) VerifyLogIntegrity(ctx context.Context) (bool, error) {
	api.mu.Lock()
	sealedRootCopy := make([]byte, len(api.sealedRoot))
	copy(sealedRootCopy, api.sealedRoot)
	treeSizeCopy := api.treeSize
	api.mu.Unlock()
	if len(sealedRootCopy) == 0 {
		return true, nil
	}
	size, hash, err := api.fetchVerifiedCheckpoint(ctx)
	if err != nil {
		return false, err
	}

	if size < treeSizeCopy {
		return false, fmt.Errorf("tree size regression detected: current=%d, sealed=%d", size, treeSizeCopy)
	}

	if size == treeSizeCopy {
		return bytes.Equal(hash, sealedRootCopy), nil
	}

	pb, err := client.NewProofBuilder(ctx, size, api.reader.ReadTile)
	if err != nil {
		return false, fmt.Errorf("failed to create proof builder: %w", err)
	}

	consistencyProof, err := pb.ConsistencyProof(ctx, treeSizeCopy, size)
	if err != nil {
		return false, fmt.Errorf("failed to get consistency proof: %w", err)
	}

	if err := proof.VerifyConsistency(rfc6962.DefaultHasher, treeSizeCopy, size, consistencyProof, sealedRootCopy, hash); err != nil {
		return false, fmt.Errorf("consistency proof verification failed: %w", err)
	}

	return true, nil
}

// GetCheckpointSize returns the size of the latest verified checkpoint.
// This is provided to aid tests and diagnostics.
func (api *ReboundAPI) GetCheckpointSize(ctx context.Context) (uint64, error) {
	size, _, err := api.fetchVerifiedCheckpoint(ctx)
	if err != nil {
		return 0, err
	}
	return size, nil
}

// (legacy verification removed)

// Close shuts down the ReboundAPI and releases resources.
func (api *ReboundAPI) Close(ctx context.Context) error {
	if api.shutdown != nil {
		return api.shutdown(ctx)
	}
	return nil
}

// addCacheHeaders is an HTTP middleware to add cache control headers.
func addCacheHeaders(value string, fs http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Cache-Control", value)
		fs.ServeHTTP(w, r)
	}
}

// FormatLineage returns a compact, human-readable rendering of lineage events.
func (api *ReboundAPI) FormatLineage(events []LineageEvent) string {
	if len(events) == 0 {
		return "(no lineage events)"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "lineage for %q (%d events)\n", events[0].Object, len(events))
	for _, e := range events {
		ts := time.Unix(0, e.TimestampUnix).UTC().Format(time.RFC3339Nano)
		typ := "update"
		if e.TxID != "-" {
			typ = "rollback"
		}
		fmt.Fprintf(&b, "- leaf=%d c=%d ts=%s type=%s txid=%s just=%q origin=%s hash=%s\n",
			e.LeafIndex, e.Counter, ts, typ, e.TxID, e.Justification, e.Origin, e.ContentHash)
	}
	return b.String()
}

// ---------------------------
// Current-view helpers (Value-style)
// ---------------------------
// These helpers assemble a compact, authenticated "current view" of the world
// consisting of three total maps:
//   - ovm-head|{obj} -> j (latest version per object)
//   - deauth-obj-head|{obj}|{j} -> "0"/"1" (authorization per object-version)
//   - deauth-snap-head|{id} -> "0"/"1" (authorization per snapshot id)
//
// They are appended as one leaf at the end of each transaction (intended to be
// leaf S-1 under the next checkpoint), giving verifiers a single inclusion
// proof to establish completeness and freshness for gating without scanning.

// buildCurrentView constructs a transient key/value map containing just the
// head namespaces. It reads from the in-memory StateManager snapshot provided.
//
//lint:ignore U1000 used in subsequent refactor steps; added now for staged integration
func (api *ReboundAPI) buildCurrentView(state map[string][]byte) map[string][]byte {
	view := make(map[string][]byte)
	// Minimal marker to identify current-view leaves and allow versioning the format.
	view["cv|v"] = []byte("1")

	// ovm-head: derive latest j per object from explicit ovm-head entries if present;
	// fall back to scanning state for "ovm|obj|j" if needed. We prefer explicit
	// ovm-head entries as they are stable and O(1).
	for k, v := range state {
		if strings.HasPrefix(k, NsOVMHead+"|") {
			// Copy as-is
			view[k] = append([]byte(nil), v...)
		}
	}
	// In case some objects lack ovm-head (legacy state), derive from ovm keys.
	// This keeps the helper robust during incremental refactors.
	for k := range state {
		if strings.HasPrefix(k, "ovm|") {
			parts := strings.Split(k, "|")
			if len(parts) != 3 {
				continue
			}
			obj := parts[1]
			// Determine max j by comparing with existing head value.
			cur := string(view[NsOVMHead+"|"+obj])
			// If view has no entry or j is larger, set it.
			if j, err := strconv.ParseUint(parts[2], 10, 64); err == nil {
				if cur == "" {
					view[NsOVMHead+"|"+obj] = []byte(strconv.FormatUint(j, 10))
				} else if cj, err2 := strconv.ParseUint(cur, 10, 64); err2 == nil && j > cj {
					view[NsOVMHead+"|"+obj] = []byte(strconv.FormatUint(j, 10))
				}
			}
		}
	}

	// deauth-obj-head: copy any existing explicit entries. Population of these
	// is introduced in later steps of the refactor.
	for k, v := range state {
		if strings.HasPrefix(k, NsDeauthObjHead+"|") {
			view[k] = append([]byte(nil), v...)
		}
	}

	// deauth-snap-head: copy any existing explicit entries.
	for k, v := range state {
		if strings.HasPrefix(k, NsDeauthSnapHead+"|") {
			view[k] = append([]byte(nil), v...)
		}
	}

	return view
}

// appendCurrentViewLeaf marshals and appends the current-view map as a single leaf.
// Callers should invoke this as the last write in a transaction.
//
//lint:ignore U1000 used in subsequent refactor steps; added now for staged integration
func (api *ReboundAPI) appendCurrentViewLeaf(ctx context.Context, state map[string][]byte) (uint64, error) {
	// tlog-tiles entries are uint16 length-prefixed; hard limit is 65535 bytes per entry.
	const entryMax = 65535

	cv := api.buildCurrentView(state)

	// Partition keys into: headKeys (cv|v + deauth-snap-head|*) and otherKeys (the rest).
	head := make(map[string][]byte)
	var otherKeys []string
	// Always include version marker in the head
	if v, ok := cv["cv|v"]; ok {
		head["cv|v"] = append([]byte(nil), v...)
	} else {
		head["cv|v"] = []byte("1")
	}

	for k, v := range cv {
		if k == "cv|v" {
			continue
		}
		if strings.HasPrefix(k, NsDeauthSnapHead+"|") {
			head[k] = append([]byte(nil), v...)
			continue
		}
		otherKeys = append(otherKeys, k)
	}

	sort.Strings(otherKeys)

	// Helper to marshal and ensure size within limit.
	marshalWithin := func(m map[string][]byte) ([]byte, error) {
		b, err := json.Marshal(m)
		if err != nil {
			return nil, err
		}
		if len(b) > entryMax {
			return nil, fmt.Errorf("current-view chunk exceeds %d bytes (got %d)", entryMax, len(b))
		}
		return b, nil
	}

	// Build chunks for otherKeys so that each JSON object <= entryMax bytes.
	// Important: account for the overhead of the "cv|chunk":"1" marker that we
	//            add to every flushed/final chunk by measuring size with the marker.
	var chunks [][]byte
	if len(otherKeys) > 0 {
		cur := make(map[string][]byte)
		for _, k := range otherKeys {
			v := cv[k]
			// Tentatively add k to the current chunk and check size INCLUDING the marker.
			cur[k] = v
			withMarker := make(map[string][]byte, len(cur)+1)
			for ck, cvb := range cur {
				withMarker[ck] = cvb
			}
			withMarker["cv|chunk"] = []byte("1")
			b, err := json.Marshal(withMarker)
			if err != nil {
				return 0, fmt.Errorf("marshal current-view chunk (with marker): %w", err)
			}
			if len(b) > entryMax {
				// Adding k caused overflow after accounting for marker. Remove k and flush cur.
				delete(cur, k)
				if len(cur) > 0 {
					// Flush existing chunk with marker; ensure it fits.
					cur["cv|chunk"] = []byte("1")
					fb, err := marshalWithin(cur)
					if err != nil {
						return 0, fmt.Errorf("marshal current-view flushed chunk: %w", err)
					}
					chunks = append(chunks, fb)
				}
				// Start new chunk with just k and verify it fits with marker as well.
				cur = map[string][]byte{k: v}
				test := map[string][]byte{"cv|chunk": []byte("1"), k: v}
				tb, err := json.Marshal(test)
				if err != nil {
					return 0, fmt.Errorf("marshal current-view single-key chunk: %w", err)
				}
				if len(tb) > entryMax {
					return 0, fmt.Errorf("single current-view entry too large to fit in a chunk: key=%s size=%d (limit %d)", k, len(tb), entryMax)
				}
			}
		}
		if len(cur) > 0 {
			// Flush the final chunk with marker.
			cur["cv|chunk"] = []byte("1")
			fb, err := marshalWithin(cur)
			if err != nil {
				return 0, fmt.Errorf("marshal current-view final chunk: %w", err)
			}
			chunks = append(chunks, fb)
		}
	}

	// Marshal the head leaf; it must fit the limit. If it does not, we fail fast with a clear error.
	headBytes, err := marshalWithin(head)
	if err != nil {
		return 0, fmt.Errorf("marshal head current-view: %w", err)
	}

	// Append non-head chunks first (if any), then append the compact head last and return its index.
	var lastIdx uint64
	for i, cb := range chunks {
		fut := api.appender.Add(ctx, tessera.NewEntry(cb))
		idx, err := fut()
		if err != nil {
			return 0, fmt.Errorf("append current-view chunk %d: %w", i, err)
		}
		lastIdx = idx.Index
	}
	fut := api.appender.Add(ctx, tessera.NewEntry(headBytes))
	idx, err := fut()
	if err != nil {
		return 0, fmt.Errorf("append current-view head: %w", err)
	}
	_ = lastIdx // reserved for potential future use
	return idx.Index, nil
}

// fetchCurrentView reconstructs the current-view by reading the head leaf and
// any immediately-preceding chunk leaves marked with "cv|chunk". It verifies
// inclusion of all scanned leaves under the provided checkpoint.
func (api *ReboundAPI) fetchCurrentView(ctx context.Context, cpSize uint64, cpRoot []byte) (map[string][]byte, error) {
	if cpSize == 0 {
		return map[string][]byte{}, nil
	}
	latestIdx := cpSize - 1
	// Fetch head
	headBundle, err := client.GetEntryBundle(ctx, api.reader.ReadEntryBundle, latestIdx/defaultBundleSize, cpSize)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch head bundle: %w", err)
	}
	headLeaf := headBundle.Entries[latestIdx%defaultBundleSize]
	// Verify inclusion of head
	pb, err := client.NewProofBuilder(ctx, cpSize, api.reader.ReadTile)
	if err != nil {
		return nil, fmt.Errorf("failed to create proof builder: %w", err)
	}
	incl, err := pb.InclusionProof(ctx, latestIdx)
	if err != nil {
		return nil, fmt.Errorf("failed to get inclusion proof for head: %w", err)
	}
	if err := proof.VerifyInclusion(rfc6962.DefaultHasher, latestIdx, cpSize, rfc6962.DefaultHasher.HashLeaf(headLeaf), incl, cpRoot); err != nil {
		return nil, fmt.Errorf("failed to verify head inclusion: %w", err)
	}
	// Parse head; require cv|v to ensure we are at a state leaf
	state := map[string][]byte{}
	if err := json.Unmarshal(headLeaf, &state); err != nil {
		return nil, fmt.Errorf("failed to parse head state: %w", err)
	}
	if _, ok := state["cv|v"]; !ok {
		return nil, fmt.Errorf("head leaf is not a current-view state (missing cv|v)")
	}

	// Walk backward to merge contiguous CV chunks marked with cv|chunk
	for i := latestIdx; i > 0; i-- { // start from head, then previous
		prev := i - 1
		bundle, err := client.GetEntryBundle(ctx, api.reader.ReadEntryBundle, prev/defaultBundleSize, cpSize)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch bundle for prev idx %d: %w", prev, err)
		}
		leaf := bundle.Entries[prev%defaultBundleSize]
		// Verify inclusion
		incl, err := pb.InclusionProof(ctx, prev)
		if err != nil {
			return nil, fmt.Errorf("failed to get inclusion proof for prev idx %d: %w", prev, err)
		}
		if err := proof.VerifyInclusion(rfc6962.DefaultHasher, prev, cpSize, rfc6962.DefaultHasher.HashLeaf(leaf), incl, cpRoot); err != nil {
			return nil, fmt.Errorf("failed to verify inclusion for prev idx %d: %w", prev, err)
		}
		var m map[string][]byte
		if err := json.Unmarshal(leaf, &m); err != nil {
			// Non-JSON leaf or unrelated content; stop scanning.
			break
		}
		if _, ok := m["cv|chunk"]; !ok {
			// Not a CV chunk; stop.
			break
		}
		// Merge chunk keys into state (chunk markers are ignored).
		for k, v := range m {
			if k == "cv|chunk" {
				continue
			}
			state[k] = append([]byte(nil), v...)
		}
		// Continue to previous to see if more chunks exist
	}
	return state, nil
}

// ReconstructObjectLineage scans the transparency log and reconstructs the
// lineage of an object's head over time. Each returned event corresponds to a
// leaf where the object's head pointer changed to a new version counter.
func (api *ReboundAPI) ReconstructObjectLineage(ctx context.Context, objectName string) ([]LineageEvent, error) {
	// Optional debug tracing controlled by env to avoid noisy logs by default.
	debugTrace := os.Getenv("REBOUND_TRACE_LINEAGE") != "" || os.Getenv("REBOUND_DEBUG") == "1"
	dprintf := func(format string, args ...any) {
		if debugTrace {
			fmt.Printf("[ROL] "+format+"\n", args...)
		}
	}

	// Stream-scan the log and reconstruct head changes for the given object.
	// We only emit at most one event per leaf. Many leaves
	// are not state leaves; we decode what we can and ignore the rest.
	startTs := time.Now()
	dprintf("start object=%s", objectName)
	// Helper: scan [start, total) and append events.
	scanRange := func(start, total uint64, events *[]LineageEvent, lastCounter *uint64) error {
		if start >= total {
			return nil
		}
		startBundle := start / defaultBundleSize
		endBundle := (total + defaultBundleSize - 1) / defaultBundleSize
		dprintf("scanRange start=%d total=%d startBundle=%d endBundle=%d", start, total, startBundle, endBundle)
		var processedLeaves uint64
		lastProgressLog := time.Now()
		for bundleIdx := startBundle; bundleIdx < endBundle; bundleIdx++ {
			t0 := time.Now()
			bundle, err := client.GetEntryBundle(ctx, api.reader.ReadEntryBundle, bundleIdx, total)
			if err != nil {
				dprintf("bundle idx=%d fetch error after %s: %v", bundleIdx, time.Since(t0), err)
				return fmt.Errorf("failed to fetch bundle %d: %w", bundleIdx, err)
			}
			dur := time.Since(t0)
			// Log slow bundle fetches to pinpoint stalls.
			if dur > 200*time.Millisecond {
				dprintf("bundle idx=%d fetched in %s entries=%d", bundleIdx, dur, len(bundle.Entries))
			}
			base := bundleIdx * defaultBundleSize
			for off, leaf := range bundle.Entries {
				leafIndex := base + uint64(off)
				if leafIndex < start {
					continue
				}
				if leafIndex >= total {
					break
				}
				processedLeaves++
				// Many leaves are not state snapshots; skip non-JSON or empty entries.
				// Try to parse as a generic JSON object; if that fails or isn't an object, skip the leaf.
				var generic map[string]any
				if err := json.Unmarshal(leaf, &generic); err != nil {
					// Non-JSON (or non-object) leaf; skip.
					continue
				}
				if len(generic) == 0 {
					continue
				}
				// Convert only string values to []byte to form a state-like view for this leaf.
				// Non-state leaves will simply lack the keys we look for and be ignored.
				state := make(map[string][]byte, len(generic))
				for k, v := range generic {
					if s, ok := v.(string); ok {
						if dec, err := base64.StdEncoding.DecodeString(s); err == nil {
							state[k] = dec
						} else {
							state[k] = []byte(s)
						}
					}
				}
				// Gather candidate counters for this leaf: prefer head pointer; fall back to meta.
				var candidates []uint64
				if headBytes, ok := state[fmt.Sprintf("%s|%s", NsOVMHead, objectName)]; ok {
					if headCtr, err := strconv.ParseUint(string(headBytes), 10, 64); err == nil {
						candidates = append(candidates, headCtr)
					}
				}
				if len(candidates) == 0 {
					prefix := fmt.Sprintf("meta|object|%s|", objectName)
					for k := range state {
						if !strings.HasPrefix(k, prefix) {
							continue
						}
						// k: meta|object|<obj>|<ctr>|...
						parts := strings.Split(k, "|")
						if len(parts) < 5 {
							continue
						}
						ctr, err := strconv.ParseUint(parts[3], 10, 64)
						if err != nil {
							continue
						}
						// Avoid duplicates if multiple meta keys for same ctr
						seen := false
						for _, c := range candidates {
							if c == ctr {
								seen = true
								break
							}
						}
						if !seen {
							candidates = append(candidates, ctr)
						}
					}
				}

				// Emit at most one event per leaf, picking the smallest candidate > lastCounter if possible,
				// otherwise the first candidate not equal to lastCounter.
				var chosen uint64
				for _, c := range candidates {
					if *lastCounter == 0 || c != *lastCounter {
						if chosen == 0 || c < chosen {
							chosen = c
						}
					}
				}
				if chosen == 0 {
					continue
				}

				// Populate fields for the chosen counter.
				txid := string(state[fmt.Sprintf("meta|object|%s|%d|txid", objectName, chosen)])
				if txid == "" {
					txid = "-"
				}
				just := string(state[fmt.Sprintf("meta|object|%s|%d|just", objectName, chosen)])
				if just == "" {
					just = "(unknown)"
				}
				origin := string(state[fmt.Sprintf("meta|object|%s|%d|origin", objectName, chosen)])
				if origin == "" {
					origin = "-"
				}
				tsStr := string(state[fmt.Sprintf("meta|object|%s|%d|ts", objectName, chosen)])
				var ts int64
				if tsStr != "" {
					if p, err := strconv.ParseInt(tsStr, 10, 64); err == nil {
						ts = p
					}
				}
				hash := string(state[fmt.Sprintf("ovm|%s|%d", objectName, chosen)])

				*events = append(*events, LineageEvent{
					Object:        objectName,
					Counter:       chosen,
					LeafIndex:     leafIndex,
					TimestampUnix: ts,
					TxID:          txid,
					Justification: just,
					Origin:        origin,
					ContentHash:   hash,
				})
				*lastCounter = chosen
				klog.V(3).Infof("ReconstructObjectLineage: append event object=%s c=%d leaf=%d", objectName, chosen, leafIndex)
			}
			// Emit periodic progress (at most ~1/sec) to show forward movement.
			if debugTrace && time.Since(lastProgressLog) > time.Second {
				dprintf("progress: scanned up to bundle=%d (~leaves=%d)", bundleIdx, processedLeaves)
				lastProgressLog = time.Now()
			}
		}
		return nil
	}

	// Bind lineage to the sealed, counter-checked checkpoint for freshness.
	var events []LineageEvent
	var lastCounter uint64
	dprintf("verifySealedFreshness")
	size, _, err := api.verifySealedFreshness(ctx)
	if err != nil {
		return nil, err
	}
	if size == 0 {
		dprintf("empty log (size=0)")
		return nil, nil
	}
	dprintf("fresh size=%d", size)
	if err := scanRange(0, size, &events, &lastCounter); err != nil {
		return nil, err
	}
	took := time.Since(startTs)
	klog.V(1).Infof("ReconstructObjectLineage: object=%s events=%d scannedSize=%d took=%s", objectName, len(events), size, took)
	dprintf("done object=%s events=%d scannedSize=%d took=%s", objectName, len(events), size, took)
	return events, nil
}

// recoverFromFreshnessMismatch attempts to reconcile a mismatch between the
// latest verified checkpoint and the locally sealed tuple. It implements the
// following policy while holding api.mu to serialize counter/seal mutations:
//
//   - Advance (checkpoint size S' > sealed size S): if and only if the sealed
//     checkpoint is an ancestor of S' (consistency proof verifies), reseal S'
//     bound to c+2 and increment the counter twice.
//   - Rewind (checkpoint size S' < sealed size S): STRICT — only allow S' == S-1
//     (the immediate predecessor). Reseal S-1 bound to c+2 and increment twice.
//   - Same root/size but counter mismatch: resync the in-memory counter to the
//     sealed counter. This is prototype-only; production must persist a monotonic
//     counter in trusted hardware.
//
// On success, the sealed blob will match the current checkpoint and the in-memory
// counter will equal the sealed counter. On failure, no changes are made.
func (api *ReboundAPI) recoverFromFreshnessMismatch(ctx context.Context) error {
	// Re-fetch current checkpoint to classify the situation.
	size, root, err := api.fetchVerifiedCheckpoint(ctx)
	if err != nil {
		return fmt.Errorf("recovery: failed to fetch checkpoint: %w", err)
	}
	// Load the existing seal (if any) and verify its signature.
	type sealInfo struct {
		V       string `json:"v"`
		Size    uint64 `json:"size"`
		HashHex string `json:"hash"`
		Counter uint64 `json:"counter"`
		SigHex  string `json:"sig"`
	}
	// Simulate TPM unseal latency
	time.Sleep(5 * time.Millisecond)
	data, err := os.ReadFile(api.sealedBlobPath)
	if err != nil {
		return fmt.Errorf("recovery: failed to read sealed blob: %w", err)
	}
	var s sealInfo
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("recovery: failed to parse sealed blob: %w", err)
	}
	if s.V != "v1" {
		return fmt.Errorf("recovery: unsupported seal version: %s", s.V)
	}
	payload := []byte(fmt.Sprintf("v1|size=%d|hash=%s|counter=%d", s.Size, s.HashHex, s.Counter))
	sig, err := hex.DecodeString(s.SigHex)
	if err != nil {
		return fmt.Errorf("recovery: invalid seal signature encoding: %w", err)
	}
	if !ed25519.Verify(api.sealPub, payload, sig) {
		return fmt.Errorf("recovery: seal signature verification failed")
	}

	api.mu.Lock()
	defer api.mu.Unlock()

	// Case 1: Same root/size but counter diverged: hard fail by policy.
	if s.Size == size && strings.EqualFold(s.HashHex, hex.EncodeToString(root)) {
		klog.Errorf("recovery: counter-only mismatch (sealed=%d, current=%d); hard-fail by policy", s.Counter, api.counter)
		return fmt.Errorf("recovery: counter mismatch with identical checkpoint: sealed=%d current=%d", s.Counter, api.counter)
	}

	// Helper to double-increment reseal at the current checkpoint.
	resealWithDoubleInc := func(baseCounter uint64) error {
		bind := baseCounter + 2
		klog.Infof("recovery: resealing current checkpoint bound to c+2 (bind=%d); performing double-increment", bind)
		if err := api.SealCurrentRoot(ctx, bind); err != nil {
			return fmt.Errorf("recovery: failed to reseal at c+2: %w", err)
		}
		// Spend two increments to publish c+2 as the new monotonic counter value.
		// In production this would be two authenticated hardware counter bumps.
		api.counter = baseCounter
		_ = api.IncCounter()
		_ = api.IncCounter()
		klog.Infof("recovery: double-increment completed; counter=%d", api.counter)
		return nil
	}

	// Case 2: Checkpoint advanced beyond sealed: allow only if descendant (consistency proof).
	if size > s.Size {
		klog.Warningf("recovery: checkpoint advanced beyond sealed (sealedSize=%d -> cpSize=%d); checking descendant proof", s.Size, size)
		pb, err := client.NewProofBuilder(ctx, size, api.reader.ReadTile)
		if err != nil {
			return fmt.Errorf("recovery: failed to create proof builder: %w", err)
		}
		cons, err := pb.ConsistencyProof(ctx, s.Size, size)
		if err != nil {
			return fmt.Errorf("recovery: failed to obtain consistency proof: %w", err)
		}
		sealedHash, err := hex.DecodeString(s.HashHex)
		if err != nil {
			return fmt.Errorf("recovery: invalid sealed hash hex: %w", err)
		}
		if err := proof.VerifyConsistency(rfc6962.DefaultHasher, s.Size, size, cons, sealedHash, root); err != nil {
			klog.Errorf("recovery: descendant proof failed; refusing to advance: %v", err)
			return fmt.Errorf("recovery: checkpoint is not descendant of sealed: %w", err)
		}
		klog.Infof("recovery: descendant proof verified; proceeding to reseal and double-inc")
		return resealWithDoubleInc(s.Counter)
	}

	// Case 3: Checkpoint behind sealed: STRICT — only allow immediate predecessor (S-1).
	if size < s.Size {
		if s.Size != size+1 {
			klog.Errorf("recovery: rewind too far (sealedSize=%d cpSize=%d); only S-1 allowed", s.Size, size)
			return fmt.Errorf("recovery: rewind too far: sealed=%d checkpoint=%d (only S-1 allowed)", s.Size, size)
		}
		klog.Warningf("recovery: checkpoint behind sealed by 1 (sealedSize=%d -> cpSize=%d); proceeding with strict S-1 reseal", s.Size, size)
		return resealWithDoubleInc(s.Counter)
	}

	// Should not reach here; all cases handled.
	return fmt.Errorf("recovery: unclassified mismatch")
}

// SetAutoRecoverOnFreshnessMismatch toggles automatic crash recovery during
// sealed freshness verification. When enabled, verifySealedFreshness will try
// to reseal the latest checkpoint using the policy documented above and update
// the monotonic counter accordingly via a double-increment.
func (api *ReboundAPI) SetAutoRecoverOnFreshnessMismatch(enable bool) {
	api.mu.Lock()
	defer api.mu.Unlock()
	api.autoRecoverOnFreshnessMismatch = enable
}

// RollbackSelective re-materializes heads for the specified objects to the given version counters.
// It performs a heads-only overlay: creates fresh tuples at a new global counter for each target,
// sets head pointers, writes OVM entries, and records provenance (txid/justification) and audit lines.
// Precondition: for each target (obj,j), the historical entry ovm|obj|j must exist in some state leaf;
// this function locates such a leaf, verifies its inclusion under the current checkpoint, and uses the
// committed content hash for re-materialization. Deauth gating is enforced against the latest state.
func (api *ReboundAPI) RollbackSelective(ctx context.Context, targets map[string]uint64, justification string) (bool, error) {
	if len(targets) == 0 {
		return false, fmt.Errorf("no targets provided for selective rollback")
	}

	// Authenticate against sealed, counter-bound checkpoint for freshness
	size, root, err := api.verifySealedFreshness(ctx)
	if err != nil {
		return false, err
	}
	if size == 0 {
		return false, fmt.Errorf("empty log; cannot rollback")
	}

	// Fetch current-view (head + chunks) for presence and gating checks.
	headState, err := api.fetchCurrentView(ctx, size, root)
	if err != nil {
		return false, fmt.Errorf("RollbackSelective: failed to fetch current-view: %w", err)
	}

	// Historical presence proof: locate each per-key ovm|obj|j via index and verify inclusion; capture content hash.
	type foundVersion struct {
		contentHash []byte
		leafIndex   uint64
	}
	found := make(map[string]foundVersion)
	for obj, j := range targets {
		key := fmt.Sprintf("ovm|%s|%d", obj, j)
		v, idx, err := api.fetchPerKeyValue(ctx, size, root, key)
		if err != nil {
			return false, fmt.Errorf("historical version not provable: %s: %w", key, err)
		}
		found[obj] = foundVersion{contentHash: v, leafIndex: idx}
	}

	// Gating: deny selective rollback for any target with a per-object deauth tombstone via current-view.
	for obj, j := range targets {
		key := fmt.Sprintf("%s|%s|%d", NsDeauthObjHead, obj, j)
		v, ok := headState[key]
		if !ok {
			return false, fmt.Errorf("current-view incomplete: missing %s; cannot decide authorization", key)
		}
		if string(v) == "1" {
			return false, fmt.Errorf("target %s@%d is deauthorized; selective rollback denied", obj, j)
		}
	}

	// Mutation phase: heads-only overlay on current state snapshot
	api.mu.Lock()
	defer api.mu.Unlock()
	counter := api.GetCounter() + 1
	txid := fmt.Sprintf("txid-%d", counter)
	curState := api.stateManager.GetStateCopy()
	newState := curState

	// Deterministic order for leaf append
	var targetObjs []string
	for obj := range targets {
		targetObjs = append(targetObjs, obj)
	}
	sort.Strings(targetObjs)

	for _, obj := range targetObjs {
		fv := found[obj]
		contentHash := fv.contentHash
		prevHeadCtr := "-"
		if b, ok := curState[fmt.Sprintf("%s|%s", NsOVMHead, obj)]; ok {
			prevHeadCtr = string(b)
		}
		newObjKey := fmt.Sprintf("ovm|%s|%d", obj, counter)
		newState[newObjKey] = contentHash
		newState[fmt.Sprintf("%s|%s", NsOVMHead, obj)] = []byte(strconv.FormatUint(counter, 10))
		// Explicit per-object-version authorization head defaults to "0" (authorized).
		newState[fmt.Sprintf("%s|%s|%d", NsDeauthObjHead, obj, counter)] = []byte("0")
		// Meta
		ts := strconv.FormatInt(time.Now().UnixNano(), 10)
		newState[fmt.Sprintf("meta|object|%s|%d|origin", obj, counter)] = []byte(prevHeadCtr)
		newState[fmt.Sprintf("meta|object|%s|%d|txid", obj, counter)] = []byte(txid)
		newState[fmt.Sprintf("meta|object|%s|%d|just", obj, counter)] = []byte(justification)
		newState[fmt.Sprintf("meta|object|%s|%d|ts", obj, counter)] = []byte(ts)
	}

	// Append per-key ovm leaves for each target
	for _, obj := range targetObjs {
		ovmKey := fmt.Sprintf("ovm|%s|%d", obj, counter)
		// Include metadata keys so lineage shows rollback-selective with txid/justification
		leaf := map[string][]byte{
			ovmKey: newState[ovmKey],
			fmt.Sprintf("meta|object|%s|%d|origin", obj, counter): []byte(newState[fmt.Sprintf("meta|object|%s|%d|origin", obj, counter)]),
			fmt.Sprintf("meta|object|%s|%d|txid", obj, counter):   []byte(newState[fmt.Sprintf("meta|object|%s|%d|txid", obj, counter)]),
			fmt.Sprintf("meta|object|%s|%d|just", obj, counter):   []byte(newState[fmt.Sprintf("meta|object|%s|%d|just", obj, counter)]),
			fmt.Sprintf("meta|object|%s|%d|ts", obj, counter):     []byte(newState[fmt.Sprintf("meta|object|%s|%d|ts", obj, counter)]),
		}
		b, err := json.Marshal(leaf)
		if err != nil {
			return false, fmt.Errorf("failed to marshal selective rollback ovm leaf: %w", err)
		}
		res, err := api.appender.Add(ctx, tessera.NewEntry(b))()
		if err != nil {
			return false, fmt.Errorf("append selective rollback ovm leaf: %w", err)
		}
		_ = api.indexDB.Store(ovmKey, res.Index)
	}

	// Audit
	var objs []string
	for o := range targets {
		objs = append(objs, o)
	}
	sort.Strings(objs)
	audit := []string{
		fmt.Sprintf("ROLLBACK_SELECTIVE_INTENT c=%d txid=%s objs=%v just=%q", counter, txid, objs, justification),
		fmt.Sprintf("ROLLBACK_SELECTIVE_APPLY c=%d txid=%s objs=%v", counter, txid, objs),
		fmt.Sprintf("TX_COMPLETE c=%d type=rollback_selective txid=%s count=%d", counter, txid, len(targets)),
	}
	if err := api.appendAuditLines(newState, txid, audit, counter); err != nil {
		return false, err
	}

	// Append per-key audit leaf
	auditState2 := map[string][]byte{}
	if err := api.appendAuditLines(auditState2, txid, audit, counter); err != nil {
		return false, err
	}
	for k, v := range auditState2 {
		newState[k] = v
		b, err := json.Marshal(map[string][]byte{k: v})
		if err != nil {
			return false, fmt.Errorf("failed to marshal audit leaf: %w", err)
		}
		res, err := api.appender.Add(ctx, tessera.NewEntry(b))()
		if err != nil {
			return false, fmt.Errorf("append audit leaf: %w", err)
		}
		_ = api.indexDB.Store(k, res.Index)
	}
	// Append current-view leaf last
	cvIdx, err := api.appendCurrentViewLeaf(ctx, newState)
	if err != nil {
		return false, err
	}
	if api.waitForCheckpoint {
		if err := api.syncWithExpectedSize(ctx, cvIdx+1); err != nil {
			return false, fmt.Errorf("failed waiting for checkpoint after selective rollback: %w", err)
		}
	}
	api.stateManager.LoadStateFromBytes(newState)

	if err := api.SealCurrentRoot(ctx, counter); err != nil {
		klog.Warningf("Failed to seal current root after selective rollback: %v", err)
	}
	_ = api.IncCounter()
	return true, nil
}

// PruneObjectVersion records a per-object de-authorization tombstone for a specific
// object version j. This denies selective rollback to that version in the future.
// Protocol:
//   - Writes a per-key leaf deauth|object|{name}|{j} with optional justification string as value
//   - Appends a per-key audit leaf and a current-view leaf last
func (api *ReboundAPI) PruneObjectVersion(ctx context.Context, objectName string, j uint64, justification string) ([]byte, error) {
	api.mu.Lock()
	defer api.mu.Unlock()

	counter := api.GetCounter() + 1
	txid := fmt.Sprintf("txid-%d", counter)
	klog.V(1).Infof("PruneObjectVersion: %s@%d c=%d txid=%s just=%q", objectName, j, counter, txid, justification)

	newState := api.stateManager.GetStateCopy()
	tombKey := fmt.Sprintf("deauth|object|%s|%d", objectName, j)
	if justification == "" {
		newState[tombKey] = []byte("deauth")
	} else {
		newState[tombKey] = []byte(justification)
	}
	// Update explicit per-object-version authorization head to "1" (deauthorized).
	newState[fmt.Sprintf("%s|%s|%d", NsDeauthObjHead, objectName, j)] = []byte("1")
	// No meta|deauth|... sideband: not required for gating or lineage.

	audit := []string{
		fmt.Sprintf("PRUNE_OBJECT_INTENT c=%d txid=%s obj=%s j=%d just=%q", counter, txid, objectName, j, justification),
		fmt.Sprintf("PRUNE_OBJECT_APPLY c=%d txid=%s obj=%s j=%d", counter, txid, objectName, j),
		fmt.Sprintf("TX_COMPLETE c=%d type=prune_object txid=%s obj=%s j=%d", counter, txid, objectName, j),
	}
	// Append per-key deauth object leaf
	{
		b, err := json.Marshal(map[string][]byte{tombKey: newState[tombKey]})
		if err != nil {
			return nil, fmt.Errorf("failed to marshal deauth-object leaf: %w", err)
		}
		if _, err := api.appender.Add(ctx, tessera.NewEntry(b))(); err != nil {
			return nil, fmt.Errorf("append deauth-object leaf: %w", err)
		}
		_ = api.indexDB.Store(fmt.Sprintf("deauth|object|%s", objectName), 0)
	}

	// Append per-key audit leaf and also keep it in newState
	auditState := map[string][]byte{}
	if err := api.appendAuditLines(auditState, txid, audit, counter); err != nil {
		return nil, err
	}
	for k, v := range auditState {
		newState[k] = v
		b, err := json.Marshal(map[string][]byte{k: v})
		if err != nil {
			return nil, fmt.Errorf("failed to marshal audit leaf: %w", err)
		}
		if _, err := api.appender.Add(ctx, tessera.NewEntry(b))(); err != nil {
			return nil, fmt.Errorf("append audit leaf: %w", err)
		}
		_ = api.indexDB.Store(k, 0)
	}

	// Compute return hash from newState
	stateBytes, _ := json.Marshal(newState)
	stateHash := sha256.Sum256(stateBytes)

	api.stateManager.LoadStateFromBytes(newState)

	// Append current-view leaf last
	cvIdx, err := api.appendCurrentViewLeaf(ctx, newState)
	if err != nil {
		return nil, err
	}
	if api.waitForCheckpoint {
		if err := api.syncWithExpectedSize(ctx, cvIdx+1); err != nil {
			return nil, fmt.Errorf("failed to sync after prune-object: %w", err)
		}
	}
	if err := api.SealCurrentRoot(ctx, counter); err != nil {
		klog.Warningf("Failed to seal current root after prune-object: %v", err)
	}
	_ = api.IncCounter()
	return stateHash[:], nil
}
