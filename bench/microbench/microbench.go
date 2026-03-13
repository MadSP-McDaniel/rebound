package main

import (
	"context"
	crand "crypto/rand"
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	librebound "github.com/MadSP-McDaniel/librebound"
	"golang.org/x/mod/sumdb/note"
	klog "k8s.io/klog/v2"
)

type benchPoint struct {
	NObjects int
	Metric   string
	Trial    int
	Duration time.Duration
	Bytes    int64
	NUpdates int
	SampleK  int
	TreeSize uint64 // Actual number of leaves in Tessera log
}

// progress tracks and prints per-experiment progress at 1% increments.
type progress struct {
	expIdx   int
	expTotal int
	label    string
	total    int
	done     int
	lastPct  int // stores last printed bucket (multiple of 5)
}

func (p *progress) start(expIdx, expTotal int, label string, total int) {
	p.expIdx = expIdx
	p.expTotal = expTotal
	p.label = label
	p.total = total
	p.done = 0
	p.lastPct = -1
	if p.total <= 0 {
		fmt.Printf("[exp %d/%d %s] starting (no measurable units)\n", p.expIdx, p.expTotal, p.label)
	} else {
		fmt.Printf("[exp %d/%d %s] 0%%\n", p.expIdx, p.expTotal, p.label)
		p.lastPct = 0
	}
}

func (p *progress) tick(delta int) {
	if p.total <= 0 {
		return
	}
	p.done += delta
	if p.done > p.total {
		p.done = p.total
	}
	pct := int(float64(p.done) * 100.0 / float64(p.total))
	if pct > 100 {
		pct = 100
	}
	// Print only on 5% increments (bucketed)
	bucket := (pct / 5) * 5
	if bucket != p.lastPct {
		fmt.Printf("[exp %d/%d %s] %d%%\n", p.expIdx, p.expTotal, p.label, bucket)
		p.lastPct = bucket
	}
}

func writeCSV(path string, points []benchPoint) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	_ = w.Write([]string{"metric", "n", "trial", "millis", "bytes", "n_updates", "sample_k", "tree_size"})
	for _, p := range points {
		_ = w.Write([]string{
			p.Metric,
			strconv.Itoa(p.NObjects),
			strconv.Itoa(p.Trial),
			fmt.Sprintf("%.3f", float64(p.Duration.Microseconds())/1000.0),
			strconv.FormatInt(p.Bytes, 10),
			strconv.Itoa(p.NUpdates),
			strconv.Itoa(p.SampleK),
			strconv.FormatUint(p.TreeSize, 10),
		})
	}
	return w.Error()
}

func fixedBytes(size int) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = byte((i*131 + 7) % 251)
	}
	return b
}

func buildObjects(n, objSize int) map[string][]byte {
	m := make(map[string][]byte, n)
	payload := fixedBytes(objSize)
	for i := 0; i < n; i++ {
		m[fmt.Sprintf("obj-%06d", i)] = payload
	}
	return m
}

func dirSize(path string) (int64, error) {
	var total int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	return total, err
}

func mustNewAPI(base string) *librebound.ReboundAPI {
	// Normalize to absolute path to avoid issues if CWD changes inside libraries.
	abs, err := filepath.Abs(base)
	if err != nil {
		panic(err)
	}
	base = abs

	// Prepare signer/verifier once per data directory. Persist keys so reopens use the
	// same identity; otherwise later verifications will fail with "no verifiable signatures".
	keyDir := filepath.Join(base, ".state")
	signerPath := filepath.Join(keyDir, "bench_note_signer.key")
	verifierPath := filepath.Join(keyDir, "bench_note_verifier.key")
	var signerKey, verifierKey string
	if bs, err := os.ReadFile(signerPath); err == nil {
		signerKey = strings.TrimSpace(string(bs))
	}
	if bv, err := os.ReadFile(verifierPath); err == nil {
		verifierKey = strings.TrimSpace(string(bv))
	}
	if signerKey == "" || verifierKey == "" {
		sk, vk, err := note.GenerateKey(crand.Reader, "bench")
		if err != nil {
			panic(err)
		}
		signerKey, verifierKey = sk, vk
		// Ensure key directory exists then persist keys with restricted perms.
		if err := os.MkdirAll(keyDir, 0o755); err != nil {
			panic(err)
		}
		if err := os.WriteFile(signerPath, []byte(signerKey+"\n"), 0o600); err != nil {
			panic(err)
		}
		if err := os.WriteFile(verifierPath, []byte(verifierKey+"\n"), 0o644); err != nil {
			panic(err)
		}
	}
	signer, err := note.NewSigner(signerKey)
	if err != nil {
		panic(err)
	}
	verifier, err := note.NewVerifier(verifierKey)
	if err != nil {
		panic(err)
	}

	// Guard against intermittent filesystem races by retrying initialization
	// after ensuring the required directories exist.
	var lastErr error
	for attempt := 1; attempt <= 5; attempt++ {
		if err := os.MkdirAll(base, 0o755); err != nil {
			panic(err)
		}
		if err := os.MkdirAll(filepath.Join(base, ".state"), 0o755); err != nil {
			panic(err)
		}
		api, err := librebound.NewReboundAPI(base, false, signer, verifier, true)
		if err == nil {
			api.SetWaitForCheckpoint(true)
			// DO NOT enable this for benchmarks - this is an environment-specific recovery behavior (unsafe in general)
			api.SetAutoRecoverOnFreshnessMismatch(false)
			return api
		}
		lastErr = err
		// Retry on likely transient path setup issues
		es := err.Error()
		if strings.Contains(es, ".state") || strings.Contains(es, "no such file or directory") || strings.Contains(es, "version file") {
			time.Sleep(time.Duration(50*attempt) * time.Millisecond)
			continue
		}
		// For other errors, fail fast
		panic(err)
	}
	panic(fmt.Errorf("failed to initialize API after retries: %w", lastErr))
}

func benchStateUpdate(ctx context.Context, api *librebound.ReboundAPI, n, objSize int) (time.Duration, error) {
	objects := buildObjects(n, objSize)
	start := time.Now()
	_, err := api.StateUpdateBatch(ctx, objects)
	return time.Since(start), err
}

func benchSnapshot(ctx context.Context, api *librebound.ReboundAPI, sid string) (time.Duration, error) {
	start := time.Now()
	_, err := api.TakeSnapshot(ctx, sid)
	return time.Since(start), err
}

func benchRollback(ctx context.Context, api *librebound.ReboundAPI, sid string) (time.Duration, error) {
	start := time.Now()
	_, err := api.RollbackToSnapshot(ctx, sid, "bench")
	return time.Since(start), err
}

func benchPrune(ctx context.Context, api *librebound.ReboundAPI, sid string) (time.Duration, error) {
	start := time.Now()
	_, err := api.PruneSnapshot(ctx, sid, "bench-prune")
	return time.Since(start), err
}

// Removed unused benchQueryReconstruct in favor of sample-based variants below.

// benchQueryReconstructSample measures average per-key lineage reconstruction time over K keys.
func benchQueryReconstructSample(ctx context.Context, api *librebound.ReboundAPI, names []string) (time.Duration, error) {
	if len(names) == 0 {
		return 0, nil
	}
	start := time.Now()
	for _, name := range names {
		if _, err := api.ReconstructObjectLineage(ctx, name); err != nil {
			return 0, err
		}
	}
	total := time.Since(start)
	return total / time.Duration(len(names)), nil
}

// benchQueryOVMSample measures average per-key inclusion verification using the latest snapshot id as anchor.
// It verifies that ovm|name|head content in the snapshot matches the expected payload.
func benchQueryOVMSample(ctx context.Context, api *librebound.ReboundAPI, snapshotID string, names []string, objSize int) (time.Duration, error) {
	if len(names) == 0 {
		return 0, nil
	}
	// All objects share the same payload pattern in this bench.
	expected := fixedBytes(objSize)
	start := time.Now()
	for _, name := range names {
		ok, err := api.VerifyEntryInSnapshot(ctx, snapshotID, name, expected)
		if err != nil {
			return 0, err
		}
		if !ok {
			return 0, fmt.Errorf("verification failed for %s in snapshot %s", name, snapshotID)
		}
	}
	total := time.Since(start)
	return total / time.Duration(len(names)), nil
}

// prepareQueryStateUpdates creates a fresh data directory, applies `u` updates of size `maxN`,
// takes a snapshot, and returns an OPEN API along with the snapshot ID for immediate querying.
// Caller is responsible for closing the returned API.
func prepareQueryStateUpdates(ctx context.Context, base string, maxN, u, objSize int, freshDir func(parts ...string) string) (*librebound.ReboundAPI, string) {
	dir := freshDir(base, "query_vs_updates", fmt.Sprintf("n=%d", maxN), fmt.Sprintf("updates=%d", u), "prepared")
	api := mustNewAPI(dir)
	for i := 0; i < u; i++ {
		if _, err := benchStateUpdate(ctx, api, maxN, objSize); err != nil {
			panic(err)
		}
	}
	snapID := fmt.Sprintf("snap-u%d-n%d-prep", u, maxN)
	if _, err := benchSnapshot(ctx, api, snapID); err != nil {
		panic(err)
	}
	return api, snapID
}

// prepareQueryStateN creates a fresh data directory, applies one update of size `n`,
// takes a snapshot, and returns an OPEN API along with the snapshot ID for immediate querying.
// Caller is responsible for closing the returned API.
func prepareQueryStateN(ctx context.Context, base string, n, objSize int, freshDir func(parts ...string) string) (*librebound.ReboundAPI, string) {
	dir := freshDir(base, "query_vs_n", fmt.Sprintf("n=%d", n), "prepared")
	api := mustNewAPI(dir)
	if _, err := benchStateUpdate(ctx, api, n, objSize); err != nil {
		panic(err)
	}
	snapID := fmt.Sprintf("snap-n%d-prep", n)
	if _, err := benchSnapshot(ctx, api, snapID); err != nil {
		panic(err)
	}
	return api, snapID
}

// pickFirstK returns the first k object names deterministically.
func pickFirstK(n, k int) []string {
	if k > n {
		k = n
	}
	out := make([]string, 0, k)
	for i := 0; i < k; i++ {
		out = append(out, fmt.Sprintf("obj-%06d", i))
	}
	return out
}

func main() {
	// Enable klog output so Tessera logs (including fence diagnostics) are visible during runs.
	// Initialize before parsing flags.
	klog.InitFlags(nil)
	_ = flag.CommandLine.Set("logtostderr", "true")
	_ = flag.CommandLine.Set("alsologtostderr", "true")
	// Default verbosity can be overridden with REBOUND_LOGV env var.
	if v := os.Getenv("REBOUND_LOGV"); v != "" {
		_ = flag.CommandLine.Set("v", v)
	} else {
		_ = flag.CommandLine.Set("v", "2")
	}

	// Prefer REBOUND_HOME for defaults when available so outputs land under $REBOUND_HOME/o
	home := os.Getenv("REBOUND_HOME")
	defaultWork := "./o/bench"
	defaultOut := "./o/micro"
	if home != "" {
		defaultWork = filepath.Join(home, "data", "microbench")
		defaultOut = filepath.Join(home, "o", "micro")
	}

	var (
		workDir        = flag.String("work", defaultWork, "workspace directory for log data")
		sizesCSV       = flag.String("sizes", "1,10,100", "comma-separated object counts to test")
		trials         = flag.Int("trials", 1, "trials per size (per updates point)")
		objSize        = flag.Int("obj-bytes", 1, "bytes per object payload")
		outDirFlag     = flag.String("out", defaultOut, "output directory for benchmark CSVs and plots")
		measureStore   = flag.Bool("measure-storage", true, "record storage consumption bytes after each update")
		querySample    = flag.Int("query-sample", 25, "number of keys to sample for query benchmarks (per-trial)")
		updatesCSV     = flag.String("updates", "1,10,100", "comma-separated cumulative update counts to measure (e.g., 1,10)")
		pruneKeep      = flag.Int("prune-keep", 20, "number of snapshots to keep for pruning benchmark")
		skipPruneBench = flag.Bool("skip-prune-bench", false, "skip the pruning impact benchmark (experiment 7)")
	)
	flag.Parse()

	sizeStrs := strings.Split(*sizesCSV, ",")
	sizes := make([]int, 0, len(sizeStrs))
	for _, s := range sizeStrs {
		if s == "" {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil {
			panic(err)
		}
		sizes = append(sizes, n)
	}

	// Parse updates schedule
	updStrs := strings.Split(*updatesCSV, ",")
	updates := make([]int, 0, len(updStrs))
	for _, s := range updStrs {
		if s == "" {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil {
			panic(err)
		}
		updates = append(updates, n)
	}
	// Ensure ascending and unique
	if len(updates) == 0 {
		updates = []int{1, 10}
	}
	// Simple insertion sort for small lists
	for i := 1; i < len(updates); i++ {
		j := i
		for j > 0 && updates[j-1] > updates[j] {
			updates[j-1], updates[j] = updates[j], updates[j-1]
			j--
		}
	}
	// Deduplicate
	dedup := make([]int, 0, len(updates))
	for i, v := range updates {
		if i == 0 || v != updates[i-1] {
			dedup = append(dedup, v)
		}
	}
	updates = dedup

	// Progress tracker removed for independent experiment runs.

	ctx := context.Background()
	// Resolve and create output directory
	outDir, err := filepath.Abs(*outDirFlag)
	if err != nil {
		panic(err)
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		panic(err)
	}

	// Ensure base work dir exists
	base := *workDir
	// Clean slate: remove any previous benchmark data to avoid Tessera state leakage
	klog.V(1).Infof("Cleaning previous benchmark data at %s", base)
	if err := os.RemoveAll(base); err != nil && !os.IsNotExist(err) {
		panic(fmt.Errorf("failed to clean work directory: %w", err))
	}
	if err := os.MkdirAll(base, 0o755); err != nil {
		panic(err)
	}

	// Helper to build dirs fresh
	freshDir := func(parts ...string) string {
		p := filepath.Join(parts...)
		_ = os.RemoveAll(p)
		if err := os.MkdirAll(p, 0o755); err != nil {
			panic(err)
		}
		return p
	}

	// Compute maxN once (used for exp counting and query_vs_k)
	maxN := 0
	for _, n := range sizes {
		if n > maxN {
			maxN = n
		}
	}

	// Count experiments to be run
	expTotal := 0
	expTotal++ // ops_vs_n
	expTotal++ // ops_vs_updates
	if *measureStore {
		expTotal++
	} // storage_vs_n
	if *measureStore {
		expTotal++
	} // storage_vs_updates
	expTotal++ // query_vs_updates
	expTotal++ // query_vs_n
	if !*skipPruneBench {
		expTotal++ // ops_vs_updates_with_pruning
	}
	expIdx := 0
	var prog progress

	// 1) Operation latency vs N
	klog.V(1).Infof("Starting microbenchmark [ops_vs_n]")
	expIdx++
	prog.start(expIdx, expTotal, "ops_vs_n", len(sizes)*(*trials))
	var ptsOpsVsN []benchPoint
	for _, n := range sizes {
		for t := 0; t < *trials; t++ {
			dataDir := freshDir(base, "ops_vs_n", fmt.Sprintf("n=%d", n), fmt.Sprintf("t=%d", t))
			api := mustNewAPI(dataDir)
			// Do one update of size n
			if dur, err := benchStateUpdate(ctx, api, n, *objSize); err == nil {
				var b int64
				if *measureStore {
					if bb, err2 := dirSize(dataDir); err2 == nil {
						b = bb
					}
				}
				treeSize, _ := api.GetCheckpointSize(ctx)
				ptsOpsVsN = append(ptsOpsVsN, benchPoint{NObjects: n, Metric: "update", Trial: t, Duration: dur, Bytes: b, NUpdates: 1, TreeSize: treeSize})
			} else {
				panic(err)
			}
			// Snapshot
			snapID := fmt.Sprintf("snap-n%d-t%d", n, t)
			if dur, err := benchSnapshot(ctx, api, snapID); err == nil {
				var b int64
				if *measureStore {
					if bb, err2 := dirSize(dataDir); err2 == nil {
						b = bb
					}
				}
				treeSize, _ := api.GetCheckpointSize(ctx)
				ptsOpsVsN = append(ptsOpsVsN, benchPoint{NObjects: n, Metric: "snapshot", Trial: t, Duration: dur, Bytes: b, NUpdates: 1, TreeSize: treeSize})
			} else {
				panic(err)
			}
			// Rollback to snapshot
			if dur, err := benchRollback(ctx, api, snapID); err == nil {
				var b int64
				if *measureStore {
					if bb, err2 := dirSize(dataDir); err2 == nil {
						b = bb
					}
				}
				treeSize, _ := api.GetCheckpointSize(ctx)
				ptsOpsVsN = append(ptsOpsVsN, benchPoint{NObjects: n, Metric: "rollback", Trial: t, Duration: dur, Bytes: b, NUpdates: 1, TreeSize: treeSize})
			} else {
				panic(err)
			}
			// Prune snapshot (unconditional in op-latency experiment)
			if dur, err := benchPrune(ctx, api, snapID); err == nil {
				var b int64
				if *measureStore {
					if bb, err2 := dirSize(dataDir); err2 == nil {
						b = bb
					}
				}
				treeSize, _ := api.GetCheckpointSize(ctx)
				ptsOpsVsN = append(ptsOpsVsN, benchPoint{NObjects: n, Metric: "prune", Trial: t, Duration: dur, Bytes: b, NUpdates: 1, TreeSize: treeSize})
			} else {
				panic(err)
			}
			// Close API at end of trial to stop background publisher goroutines.
			if err := api.Close(ctx); err != nil {
				panic(err)
			}
			prog.tick(1)
		}
	}
	if err := writeCSV(filepath.Join(outDir, "ops_vs_n.csv"), ptsOpsVsN); err != nil {
		panic(err)
	}

	// 2) Operation latency vs Number of Updates (all four operations)
	klog.V(1).Infof("Starting microbenchmark [ops_vs_updates]")
	expIdx++
	// 4 operations × sizes × updates × trials
	prog.start(expIdx, expTotal, "ops_vs_updates", 4*len(sizes)*len(updates)*(*trials))
	var ptsOpsVsUpd []benchPoint

	// Measure each operation type separately
	operations := []struct {
		name string
		fn   func(ctx context.Context, api *librebound.ReboundAPI, n int, u int) (time.Duration, error)
	}{
		{"update", func(ctx context.Context, api *librebound.ReboundAPI, n int, u int) (time.Duration, error) {
			// Do u-1 warmup updates, then measure the u-th update
			for i := 0; i < u-1; i++ {
				if _, err := benchStateUpdate(ctx, api, n, *objSize); err != nil {
					return 0, err
				}
			}
			return benchStateUpdate(ctx, api, n, *objSize)
		}},
		{"snapshot", func(ctx context.Context, api *librebound.ReboundAPI, n int, u int) (time.Duration, error) {
			// Do u updates as warmup, then measure snapshot
			for i := 0; i < u; i++ {
				if _, err := benchStateUpdate(ctx, api, n, *objSize); err != nil {
					return 0, err
				}
			}
			return benchSnapshot(ctx, api, "snap-measure")
		}},
		{"rollback", func(ctx context.Context, api *librebound.ReboundAPI, n int, u int) (time.Duration, error) {
			// Do u updates, take snapshot, then measure rollback
			for i := 0; i < u; i++ {
				if _, err := benchStateUpdate(ctx, api, n, *objSize); err != nil {
					return 0, err
				}
			}
			snapID := "snap-for-rollback"
			if _, err := benchSnapshot(ctx, api, snapID); err != nil {
				return 0, err
			}
			return benchRollback(ctx, api, snapID)
		}},
		{"prune", func(ctx context.Context, api *librebound.ReboundAPI, n int, u int) (time.Duration, error) {
			// Do u updates, take snapshot, then measure prune
			for i := 0; i < u; i++ {
				if _, err := benchStateUpdate(ctx, api, n, *objSize); err != nil {
					return 0, err
				}
			}
			snapID := "snap-for-prune"
			if _, err := benchSnapshot(ctx, api, snapID); err != nil {
				return 0, err
			}
			return benchPrune(ctx, api, snapID)
		}},
	}

	for _, op := range operations {
		for _, n := range sizes {
			for _, u := range updates {
				for t := 0; t < *trials; t++ {
					dataDir := freshDir(base, "ops_vs_updates", op.name, fmt.Sprintf("n=%d", n), fmt.Sprintf("updates=%d", u), fmt.Sprintf("t=%d", t))
					api := mustNewAPI(dataDir)

					dur, err := op.fn(ctx, api, n, u)
					if err != nil {
						panic(err)
					}

					var b int64
					if *measureStore {
						if bb, err2 := dirSize(dataDir); err2 == nil {
							b = bb
						}
					}
					treeSize, _ := api.GetCheckpointSize(ctx)
					ptsOpsVsUpd = append(ptsOpsVsUpd, benchPoint{NObjects: n, Metric: op.name, Trial: t, Duration: dur, Bytes: b, NUpdates: u, TreeSize: treeSize})

					// Close API at end of trial to stop background publisher goroutines.
					if err := api.Close(ctx); err != nil {
						panic(err)
					}
					prog.tick(1)
				}
			}
		}
	}
	if err := writeCSV(filepath.Join(outDir, "ops_vs_updates.csv"), ptsOpsVsUpd); err != nil {
		panic(err)
	}

	// 3) Storage vs N (after one update)
	klog.V(1).Infof("Starting microbenchmark [storage_vs_n]")
	if *measureStore {
		expIdx++
		prog.start(expIdx, expTotal, "storage_vs_n", len(sizes)*(*trials))
	}
	var ptsStorVsN []benchPoint
	if *measureStore {
		for _, n := range sizes {
			for t := 0; t < *trials; t++ {
				dataDir := freshDir(base, "storage_vs_n", fmt.Sprintf("n=%d", n), fmt.Sprintf("t=%d", t))
				api := mustNewAPI(dataDir)
				if _, err := benchStateUpdate(ctx, api, n, *objSize); err != nil {
					panic(err)
				}
				// Get tree size before closing API
				treeSize, _ := api.GetCheckpointSize(ctx)
				// Simplest correctness: close the API to ensure all on-disk data is flushed,
				// then measure directory size.
				if err := api.Close(ctx); err != nil {
					panic(err)
				}
				var b int64
				if bb, err2 := dirSize(dataDir); err2 == nil {
					b = bb
				}
				ptsStorVsN = append(ptsStorVsN, benchPoint{NObjects: n, Metric: "update", Trial: t, Duration: 0, Bytes: b, NUpdates: 1, TreeSize: treeSize})
				prog.tick(1)
			}
		}
		if err := writeCSV(filepath.Join(outDir, "storage_vs_n.csv"), ptsStorVsN); err != nil {
			panic(err)
		}
	}

	// 4) Storage vs Number of Updates (monotonic, updates only)
	klog.V(1).Infof("Starting microbenchmark [storage_vs_updates]")
	if *measureStore {
		expIdx++
		prog.start(expIdx, expTotal, "storage_vs_updates", len(sizes)*len(updates)*(*trials))
	}
	var ptsStorVsUpd []benchPoint
	if *measureStore {
		for _, n := range sizes {
			for _, u := range updates {
				for t := 0; t < *trials; t++ {
					dataDir := freshDir(base, "storage_vs_updates", fmt.Sprintf("n=%d", n), fmt.Sprintf("updates=%d", u), fmt.Sprintf("t=%d", t))
					api := mustNewAPI(dataDir)
					for i := 0; i < u; i++ {
						if _, err := benchStateUpdate(ctx, api, n, *objSize); err != nil {
							panic(err)
						}
					}
					// Get tree size before closing API
					treeSize, _ := api.GetCheckpointSize(ctx)
					// Close before measuring to avoid zero-byte readings due to unflushed state.
					if err := api.Close(ctx); err != nil {
						panic(err)
					}
					var b int64
					if bb, err2 := dirSize(dataDir); err2 == nil {
						b = bb
					}
					ptsStorVsUpd = append(ptsStorVsUpd, benchPoint{NObjects: n, Metric: "update", Trial: t, Duration: 0, Bytes: b, NUpdates: u, TreeSize: treeSize})
					prog.tick(1)
				}
			}
		}
		if err := writeCSV(filepath.Join(outDir, "storage_vs_updates.csv"), ptsStorVsUpd); err != nil {
			panic(err)
		}
	}

	// 5) Query latency vs Number of Updates (per-key at fixed N = maxN, cumulative run)
	klog.V(1).Infof("Starting microbenchmark [query_vs_updates]")
	expIdx++
	prog.start(expIdx, expTotal, "query_vs_updates", len(updates)*(*trials))
	var ptsQryVsUpd []benchPoint
	// This experiment is read-only, so we can do a cumulative run for each trial
	// to save the setup cost of rebuilding the state for each data point.
	for t := 0; t < *trials; t++ {
		dataDir := freshDir(base, "query_vs_updates", fmt.Sprintf("t=%d", t))
		api := mustNewAPI(dataDir)
		sample := pickFirstK(maxN, *querySample)
		updatesDone := 0

		for _, u := range updates {
			// Add updates to reach the current target `u`
			for i := updatesDone; i < u; i++ {
				if _, err := benchStateUpdate(ctx, api, maxN, *objSize); err != nil {
					panic(err)
				}
			}
			updatesDone = u

			// Take a snapshot to query against
			snapID := fmt.Sprintf("snap-u%d-t%d", u, t)
			if _, err := benchSnapshot(ctx, api, snapID); err != nil {
				panic(err)
			}

			// Get tree size at this measurement point
			treeSize, _ := api.GetCheckpointSize(ctx)

			// Measure query performance at this history length
			if perKey, err := benchQueryReconstructSample(ctx, api, sample); err == nil {
				ptsQryVsUpd = append(ptsQryVsUpd, benchPoint{NObjects: maxN, Metric: "query_reconstruct", Trial: t, Duration: perKey, NUpdates: u, SampleK: len(sample), TreeSize: treeSize})
			} else {
				panic(err)
			}
			if perKey, err := benchQueryOVMSample(ctx, api, snapID, sample, *objSize); err == nil {
				ptsQryVsUpd = append(ptsQryVsUpd, benchPoint{NObjects: maxN, Metric: "query_ovm", Trial: t, Duration: perKey, NUpdates: u, SampleK: len(sample), TreeSize: treeSize})
			} else {
				panic(err)
			}
			prog.tick(1)
		}
		if err := api.Close(ctx); err != nil {
			panic(err)
		}
	}
	if err := writeCSV(filepath.Join(outDir, "query_vs_updates.csv"), ptsQryVsUpd); err != nil {
		panic(err)
	}

	// 6) Query latency vs N (per-key)
	klog.V(1).Infof("Starting microbenchmark [query_vs_n]")
	expIdx++
	prog.start(expIdx, expTotal, "query_vs_n", len(sizes)*(*trials))
	var ptsQryVsN []benchPoint
	// Query latency vs N (always run)
	for _, n := range sizes {
		for t := 0; t < *trials; t++ {
			// Prepare fresh state for this trial and keep API open for queries
			api, snapID := prepareQueryStateN(ctx, base, n, *objSize, freshDir)
			sample := pickFirstK(n, *querySample)
			treeSize, _ := api.GetCheckpointSize(ctx)
			if perKey, err := benchQueryReconstructSample(ctx, api, sample); err == nil {
				ptsQryVsN = append(ptsQryVsN, benchPoint{NObjects: n, Metric: "query_reconstruct", Trial: t, Duration: perKey, SampleK: len(sample), TreeSize: treeSize})
			} else {
				panic(err)
			}
			if perKey, err := benchQueryOVMSample(ctx, api, snapID, sample, *objSize); err == nil {
				ptsQryVsN = append(ptsQryVsN, benchPoint{NObjects: n, Metric: "query_ovm", Trial: t, Duration: perKey, SampleK: len(sample), TreeSize: treeSize})
			} else {
				panic(err)
			}
			if err := api.Close(ctx); err != nil {
				panic(err)
			}
			prog.tick(1)
		}
	}
	if err := writeCSV(filepath.Join(outDir, "query_vs_n.csv"), ptsQryVsN); err != nil {
		panic(err)
	}

	// 7) Update latency and storage vs number of updates with pruning
	var ptsPruneVsUpd []benchPoint
	if !*skipPruneBench {
		klog.V(1).Infof("Starting microbenchmark [ops_vs_updates_with_pruning]")
		expIdx++
		// Use the largest value from the updates list as the run length
		pruneBenchUpdates := 0
		if len(updates) > 0 {
			pruneBenchUpdates = updates[len(updates)-1]
		}
		if pruneBenchUpdates < *pruneKeep*2 {
			pruneBenchUpdates = *pruneKeep * 2
		}
		prog.start(expIdx, expTotal, "ops_vs_updates_with_pruning", len(sizes)*pruneBenchUpdates*(*trials))
		for _, n := range sizes {
			for t := 0; t < *trials; t++ {
				dataDir := freshDir(base, "pruning_impact", fmt.Sprintf("n=%d", n), fmt.Sprintf("t=%d", t))
				api := mustNewAPI(dataDir)
				var snapshotIDs []string

				for i := 0; i < pruneBenchUpdates; i++ {
					// Prune if we have more snapshots than we want to keep.
					// This keeps the history length bounded.
					if len(snapshotIDs) > *pruneKeep {
						toPrune := snapshotIDs[0]
						snapshotIDs = snapshotIDs[1:] // Pop from front
						if _, err := benchPrune(ctx, api, toPrune); err != nil {
							panic(err)
						}
					}

					// Perform update and measure latency.
					dur, err := benchStateUpdate(ctx, api, n, *objSize)
					if err != nil {
						panic(err)
					}

					// Take a new snapshot.
					snapID := fmt.Sprintf("snap-prune-bench-%d", i)
					if _, err := benchSnapshot(ctx, api, snapID); err != nil {
						panic(err)
					}
					snapshotIDs = append(snapshotIDs, snapID)

					// Record metrics for this update.
					var b int64
					if *measureStore {
						// Note: measuring size without closing/flushing may not capture all
						// on-disk changes immediately, but is necessary to measure per-op latency.
						if bb, err2 := dirSize(dataDir); err2 == nil {
							b = bb
						}
					}
					treeSize, _ := api.GetCheckpointSize(ctx)
					ptsPruneVsUpd = append(ptsPruneVsUpd, benchPoint{NObjects: n, Metric: "update_with_prune", Trial: t, Duration: dur, Bytes: b, NUpdates: i + 1, TreeSize: treeSize})
					prog.tick(1)
				}

				// Close API at end of trial.
				if err := api.Close(ctx); err != nil {
					panic(err)
				}
			}
		}
		if err := writeCSV(filepath.Join(outDir, "ops_vs_updates_with_pruning.csv"), ptsPruneVsUpd); err != nil {
			panic(err)
		}
	}

	fmt.Println("Done. Wrote:")
	fmt.Println(" ", filepath.Join(outDir, "ops_vs_n.csv"))
	fmt.Println(" ", filepath.Join(outDir, "ops_vs_updates.csv"))
	if *measureStore {
		fmt.Println(" ", filepath.Join(outDir, "storage_vs_n.csv"))
		fmt.Println(" ", filepath.Join(outDir, "storage_vs_updates.csv"))
	}
	fmt.Println(" ", filepath.Join(outDir, "query_vs_updates.csv"))
	fmt.Println(" ", filepath.Join(outDir, "query_vs_n.csv"))
	if !*skipPruneBench {
		fmt.Println(" ", filepath.Join(outDir, "ops_vs_updates_with_pruning.csv"))
	}
}
