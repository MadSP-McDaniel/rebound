package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/MadSP-McDaniel/librebound"
	"github.com/gorilla/mux"
	"golang.org/x/mod/sumdb/note"
)

// DeploymentRequest represents a request to deploy a new version
type DeploymentRequest struct {
	Repository   string `json:"repository"`
	CommitSHA    string `json:"commit_sha"`
	ImageDigest  string `json:"image_digest"`
	SignatureURL string `json:"signature_url"`
	Actor        string `json:"actor"`
	WorkflowID   string `json:"workflow_id"`
}

// DeploymentResponse represents the response from a deployment request
type DeploymentResponse struct {
	Authorized    bool   `json:"authorized"`
	StateHash     string `json:"state_hash,omitempty"`
	SnapshotID    string `json:"snapshot_id,omitempty"`
	Message       string `json:"message"`
	RollbackToken string `json:"rollback_token,omitempty"`
}

// RollbackRequest represents a request to rollback to a previous state
type RollbackRequest struct {
	Repository    string `json:"repository"`
	SnapshotID    string `json:"snapshot_id"`
	RollbackToken string `json:"rollback_token"`
	Actor         string `json:"actor"`
	Justification string `json:"justification"`
}

// PruneRequest represents a request to prune a snapshot
type PruneRequest struct {
	SnapshotID    string `json:"snapshot_id"`
	Justification string `json:"justification"`
	Actor         string `json:"actor"`
}

// ProdServer wraps the rollback API for production usage
type ProdServer struct {
	api        *librebound.ReboundAPI
	authTokens map[string]string // Simple token-based auth for demo
}

func main() {
	// Establish REBOUND_HOME as the root for app data if provided.
	reboundHome := os.Getenv("REBOUND_HOME")
	if reboundHome != "" {
		// Create base and outputs directory early for consistency across components.
		_ = os.MkdirAll(reboundHome, 0755)
		_ = os.MkdirAll(filepath.Join(reboundHome, "o"), 0755)
		// Prefer keeping temp files on a stable, known path.
		tmpDir := filepath.Join(reboundHome, "tmp")
		if err := os.MkdirAll(tmpDir, 0755); err == nil {
			_ = os.Setenv("TMPDIR", tmpDir)
		}
	}

	storagePath := os.Getenv("ROLLBACK_STORAGE_PATH")
	if storagePath == "" {
		if reboundHome != "" {
			storagePath = filepath.Join(reboundHome, "data")
		} else {
			storagePath = "/tmp/rollback-storage"
		}
	}

	// Ensure storage directory exists
	if err := os.MkdirAll(storagePath, 0755); err != nil {
		log.Fatalf("Failed to create storage directory: %v", err)
	}

	// Create signer and verifier for the transparency log
	signer, verifier, err := createSignerVerifier()
	if err != nil {
		log.Fatalf("Failed to create signer/verifier: %v", err)
	}

	// Initialize the rollback API
	api, err := librebound.NewReboundAPI(storagePath, false, signer, verifier, false)
	if err != nil {
		log.Fatalf("Failed to initialize rollback API: %v", err)
	}

	srv := &ProdServer{
		api: api,
		authTokens: map[string]string{
			"github-actions": os.Getenv("GITHUB_TOKEN"),
		},
	}

	router := mux.NewRouter()

	// Deployment endpoints
	router.HandleFunc("/api/v1/deployment/update", srv.handleUpdateDeployment).Methods("POST")     // State update only
	router.HandleFunc("/api/v1/deployment/snapshot", srv.handleSnapshotDeployment).Methods("POST") // State update + snapshot
	router.HandleFunc("/api/v1/deployment/commit", srv.handleCommitDeployment).Methods("POST")     // Deprecated
	router.HandleFunc("/api/v1/deployment/authorize", srv.handleAuthorizeDeployment).Methods("POST")
	router.HandleFunc("/api/v1/rollback/initiate", srv.handleInitiateRollback).Methods("POST")
	router.HandleFunc("/api/v1/rollback/execute", srv.handleExecuteRollback).Methods("POST")
	router.HandleFunc("/api/v1/snapshot/prune", srv.handlePruneSnapshot).Methods("POST")

	// Query endpoints
	router.HandleFunc("/api/v1/snapshots", srv.handleListSnapshots).Methods("GET")
	router.HandleFunc("/api/v1/verify/{snapshot_id}/{key}", srv.handleVerifyEntry).Methods("GET")
	// Lineage endpoint for auditors
	// Support both path-segment and query-param forms. The query form avoids encoded-slash issues.
	router.HandleFunc("/api/v1/lineage/{object}", srv.handleLineage).Methods("GET")
	router.HandleFunc("/api/v1/lineage", srv.handleLineage).Methods("GET")

	// Health check
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
	}).Methods("GET")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting prod-server on port %s", port)
	log.Printf("Storage path: %s", storagePath)

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	log.Fatal(server.ListenAndServe())
}

// handleUpdateDeployment records a deployment state update (no snapshot)
func (g *ProdServer) handleUpdateDeployment(w http.ResponseWriter, r *http.Request) {
	var req DeploymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Repository == "" || req.CommitSHA == "" || req.ImageDigest == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	ctx := context.Background()

	// Create deployment data
	deploymentData := map[string]interface{}{
		"repository":    req.Repository,
		"commit_sha":    req.CommitSHA,
		"image_digest":  req.ImageDigest,
		"signature_url": req.SignatureURL,
		"actor":         req.Actor,
		"workflow_id":   req.WorkflowID,
		"timestamp":     time.Now().Unix(),
	}

	deploymentJSON, err := json.Marshal(deploymentData)
	if err != nil {
		http.Error(w, "Failed to serialize deployment data", http.StatusInternalServerError)
		return
	}

	// Only record state update, no snapshot
	stateHash, err := g.api.StateUpdate(ctx, req.Repository, deploymentJSON)
	if err != nil {
		log.Printf("Failed to record deployment state: %v", err)
		http.Error(w, "Failed to record deployment state", http.StatusInternalServerError)
		return
	}

	response := DeploymentResponse{
		Authorized: true,
		StateHash:  fmt.Sprintf("%x", stateHash),
		Message:    "Deployment state recorded successfully",
	}

	log.Printf("Recorded state update for %s@%s", req.Repository, req.CommitSHA)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleSnapshotDeployment records a deployment and creates a rollback snapshot
func (g *ProdServer) handleSnapshotDeployment(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DeploymentRequest
		SnapshotID string `json:"snapshot_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Repository == "" || req.CommitSHA == "" || req.ImageDigest == "" || req.SnapshotID == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	ctx := context.Background()

	// Create deployment data
	deploymentData := map[string]interface{}{
		"repository":    req.Repository,
		"commit_sha":    req.CommitSHA,
		"image_digest":  req.ImageDigest,
		"signature_url": req.SignatureURL,
		"actor":         req.Actor,
		"workflow_id":   req.WorkflowID,
		"timestamp":     time.Now().Unix(),
	}

	deploymentJSON, err := json.Marshal(deploymentData)
	if err != nil {
		http.Error(w, "Failed to serialize deployment data", http.StatusInternalServerError)
		return
	}

	// Record state update first
	stateHash, err := g.api.StateUpdate(ctx, req.Repository, deploymentJSON)
	if err != nil {
		log.Printf("Failed to record deployment state: %v", err)
		http.Error(w, "Failed to record deployment state", http.StatusInternalServerError)
		return
	}

	// Create rollback snapshot
	_, err = g.api.TakeSnapshot(ctx, req.SnapshotID)
	if err != nil {
		log.Printf("Failed to create snapshot: %v", err)
		http.Error(w, "Failed to create snapshot", http.StatusInternalServerError)
		return
	}

	response := DeploymentResponse{
		Authorized:    true,
		StateHash:     fmt.Sprintf("%x", stateHash),
		SnapshotID:    req.SnapshotID,
		Message:       "Deployment recorded and snapshot created",
		RollbackToken: generateRollbackToken(req.Repository, req.SnapshotID),
	}

	log.Printf("Created snapshot %s for %s@%s", req.SnapshotID, req.Repository, req.CommitSHA)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleCommitDeployment commits a new deployment (DEPRECATED - use /update or /snapshot)
func (g *ProdServer) handleCommitDeployment(w http.ResponseWriter, r *http.Request) {
	var req DeploymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Repository == "" || req.CommitSHA == "" || req.ImageDigest == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	ctx := context.Background()

	// Create deployment data
	deploymentData := map[string]interface{}{
		"repository":    req.Repository,
		"commit_sha":    req.CommitSHA,
		"image_digest":  req.ImageDigest,
		"signature_url": req.SignatureURL,
		"actor":         req.Actor,
		"workflow_id":   req.WorkflowID,
		"timestamp":     time.Now().Unix(),
	}

	deploymentJSON, err := json.Marshal(deploymentData)
	if err != nil {
		http.Error(w, "Failed to serialize deployment data", http.StatusInternalServerError)
		return
	}

	// Commit the deployment to the rollback log
	stateHash, err := g.api.StateUpdate(ctx, req.Repository, deploymentJSON)
	if err != nil {
		log.Printf("Failed to commit deployment: %v", err)
		http.Error(w, "Failed to commit deployment", http.StatusInternalServerError)
		return
	}

	// Take a snapshot for easy rollback
	snapshotID := fmt.Sprintf("%s-%s", req.Repository, req.CommitSHA[:8])
	_, err = g.api.TakeSnapshot(ctx, snapshotID)
	if err != nil {
		log.Printf("Failed to take snapshot: %v", err)
		// Don't fail the request, just log the error
	}

	response := DeploymentResponse{
		Authorized:    true,
		StateHash:     fmt.Sprintf("%x", stateHash),
		SnapshotID:    snapshotID,
		Message:       "Deployment committed successfully",
		RollbackToken: generateRollbackToken(req.Repository, snapshotID),
	}

	log.Printf("Committed deployment for %s@%s, snapshot: %s", req.Repository, req.CommitSHA, snapshotID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleAuthorizeDeployment checks if a deployment should be authorized
func (g *ProdServer) handleAuthorizeDeployment(w http.ResponseWriter, r *http.Request) {
	var req DeploymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Simple authorization logic - in production this would be more sophisticated
	authorized := true
	message := "Deployment authorized"

	// Example policy: deny deployments on weekends
	if time.Now().Weekday() == time.Saturday || time.Now().Weekday() == time.Sunday {
		authorized = false
		message = "Deployments not allowed on weekends"
	}

	response := DeploymentResponse{
		Authorized: authorized,
		Message:    message,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleInitiateRollback initiates a rollback operation
func (g *ProdServer) handleInitiateRollback(w http.ResponseWriter, r *http.Request) {
	var req RollbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Repository == "" || req.SnapshotID == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	ctx := context.Background()

	// Verify the snapshot exists
	snapshots, err := g.api.ListSnapshots(ctx)
	if err != nil {
		http.Error(w, "Failed to list snapshots", http.StatusInternalServerError)
		return
	}

	found := false
	for _, snapshot := range snapshots {
		if snapshot == req.SnapshotID {
			found = true
			break
		}
	}

	if !found {
		http.Error(w, "Snapshot not found", http.StatusNotFound)
		return
	}

	// Execute the rollback immediately (kept as two-step endpoints for UX)
	success, err := g.api.RollbackToSnapshot(ctx, req.SnapshotID, req.Justification)
	if err != nil {
		log.Printf("Failed to rollback: %v", err)
		http.Error(w, fmt.Sprintf("Failed to rollback: %v", err), http.StatusInternalServerError)
		return
	}

	if !success {
		http.Error(w, "Rollback failed", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success":       true,
		"message":       "Rollback completed successfully",
		"snapshot_id":   req.SnapshotID,
		"repository":    req.Repository,
		"actor":         req.Actor,
		"justification": req.Justification,
		"timestamp":     time.Now().Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleExecuteRollback kept for compatibility (delegates to initiate)
func (g *ProdServer) handleExecuteRollback(w http.ResponseWriter, r *http.Request) {
	g.handleInitiateRollback(w, r)
}

// handlePruneSnapshot marks a snapshot as pruned
func (g *ProdServer) handlePruneSnapshot(w http.ResponseWriter, r *http.Request) {
	var req PruneRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if req.SnapshotID == "" || req.Justification == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}
	ctx := context.Background()
	hash, err := g.api.PruneSnapshot(ctx, req.SnapshotID, req.Justification)
	if err != nil {
		log.Printf("Failed to prune snapshot: %v", err)
		http.Error(w, "Failed to prune snapshot", http.StatusInternalServerError)
		return
	}
	resp := map[string]interface{}{
		"success":     true,
		"snapshot_id": req.SnapshotID,
		"state_hash":  fmt.Sprintf("%x", hash),
		"message":     "Snapshot pruned",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleListSnapshots returns all available snapshots
func (g *ProdServer) handleListSnapshots(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	snapshots, err := g.api.ListSnapshots(ctx)
	if err != nil {
		http.Error(w, "Failed to list snapshots", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"snapshots": snapshots,
		"count":     len(snapshots),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleVerifyEntry verifies an entry in a snapshot
func (g *ProdServer) handleVerifyEntry(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	snapshotID := vars["snapshot_id"]
	key := vars["key"]

	ctx := context.Background()

	verified, err := g.api.VerifyEntryInSnapshot(ctx, snapshotID, key, nil)
	if err != nil {
		log.Printf("Verification error: %v", err)
		http.Error(w, "Verification failed", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"verified":    verified,
		"snapshot_id": snapshotID,
		"key":         key,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleLineage returns the reconstructed lineage for a given object
func (g *ProdServer) handleLineage(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	object := vars["object"]
	if object == "" {
		// allow fallback to query param ?object=
		object = r.URL.Query().Get("object")
	}
	if object == "" {
		http.Error(w, "missing object", http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	events, err := g.api.ReconstructObjectLineage(ctx, object)
	if err != nil {
		log.Printf("lineage error for %s: %v", object, err)
		http.Error(w, "failed to reconstruct lineage", http.StatusInternalServerError)
		return
	}

	// Optional tail limit: return only the last N events if specified
	if t := r.URL.Query().Get("tail"); t != "" {
		if n, err := strconv.Atoi(t); err == nil && n > 0 && n < len(events) {
			events = events[len(events)-n:]
		}
	}

	// Human-readable format if requested (?format=human) or Accept: text/plain
	format := r.URL.Query().Get("format")
	if format == "human" || r.Header.Get("Accept") == "text/plain" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		title := fmt.Sprintf("Lineage for %s (%d events)", object, len(events))
		pretty := g.api.FormatLineage(events)
		_, _ = w.Write([]byte(title + "\n\n" + pretty + "\n"))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"object": object,
		"count":  len(events),
		"events": events,
	})
}

// createSignerVerifier creates a signer and verifier for the transparency log
func createSignerVerifier() (note.Signer, note.Verifier, error) {
	// Generate a proper note key pair
	signerKey, verifierKey, err := note.GenerateKey(rand.Reader, "test")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key: %v", err)
	}

	signer, err := note.NewSigner(signerKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create signer: %w", err)
	}

	verifier, err := note.NewVerifier(verifierKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create verifier: %w", err)
	}

	return signer, verifier, nil
}

// generateRollbackToken generates a simple rollback token
func generateRollbackToken(repository, snapshotID string) string {
	return fmt.Sprintf("rollback-%s-%s-%d", repository, snapshotID, time.Now().Unix())
}
