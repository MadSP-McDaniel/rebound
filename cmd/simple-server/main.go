package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
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

// SimpleServer provides a simple HTTP API for demo/testing
type SimpleServer struct {
	authTokens  map[string]string
	snapshots   map[string]map[string]interface{}
	deployments map[string]interface{}
}

func main() {
	srv := &SimpleServer{
		authTokens: map[string]string{
			"github-actions": os.Getenv("GITHUB_TOKEN"),
		},
		snapshots:   make(map[string]map[string]interface{}),
		deployments: make(map[string]interface{}),
	}

	http.HandleFunc("/api/v1/deployment/update", srv.handleUpdateDeployment)
	http.HandleFunc("/api/v1/deployment/snapshot", srv.handleSnapshotDeployment)
	http.HandleFunc("/api/v1/deployment/commit", srv.handleCommitDeployment)
	http.HandleFunc("/api/v1/deployment/authorize", srv.handleAuthorizeDeployment)
	http.HandleFunc("/api/v1/rollback/initiate", srv.handleInitiateRollback)
	http.HandleFunc("/api/v1/rollback/execute", srv.handleExecuteRollback)
	http.HandleFunc("/api/v1/snapshots", srv.handleListSnapshots)
	http.HandleFunc("/health", srv.handleHealth)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting simple-server on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func (g *SimpleServer) handleUpdateDeployment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req DeploymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if req.Repository == "" || req.CommitSHA == "" || req.ImageDigest == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}
	deploymentData := map[string]interface{}{
		"repository":    req.Repository,
		"commit_sha":    req.CommitSHA,
		"image_digest":  req.ImageDigest,
		"signature_url": req.SignatureURL,
		"actor":         req.Actor,
		"workflow_id":   req.WorkflowID,
		"timestamp":     time.Now().Unix(),
	}
	g.deployments[req.Repository] = deploymentData
	stateHash := fmt.Sprintf("%x", []byte(fmt.Sprintf("%s-%s-%d", req.Repository, req.CommitSHA, time.Now().Unix())))
	resp := DeploymentResponse{Authorized: true, StateHash: stateHash, Message: "Deployment state recorded successfully"}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (g *SimpleServer) handleSnapshotDeployment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		DeploymentRequest
		SnapshotID string `json:"snapshot_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if req.Repository == "" || req.CommitSHA == "" || req.ImageDigest == "" || req.SnapshotID == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}
	deploymentData := map[string]interface{}{
		"repository": req.Repository, "commit_sha": req.CommitSHA, "image_digest": req.ImageDigest,
		"signature_url": req.SignatureURL, "actor": req.Actor, "workflow_id": req.WorkflowID, "timestamp": time.Now().Unix(),
	}
	g.deployments[req.Repository] = deploymentData
	g.snapshots[req.SnapshotID] = deploymentData
	stateHash := fmt.Sprintf("%x", []byte(fmt.Sprintf("%s-%s-%d", req.Repository, req.CommitSHA, time.Now().Unix())))
	resp := DeploymentResponse{Authorized: true, StateHash: stateHash, SnapshotID: req.SnapshotID, Message: "Deployment recorded and snapshot created", RollbackToken: generateRollbackToken(req.Repository, req.SnapshotID)}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (g *SimpleServer) handleCommitDeployment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req DeploymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if req.Repository == "" || req.CommitSHA == "" || req.ImageDigest == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}
	deploymentData := map[string]interface{}{
		"repository": req.Repository, "commit_sha": req.CommitSHA, "image_digest": req.ImageDigest,
		"signature_url": req.SignatureURL, "actor": req.Actor, "workflow_id": req.WorkflowID, "timestamp": time.Now().Unix(),
	}
	g.deployments[req.Repository] = deploymentData
	snapshotID := fmt.Sprintf("%s-%s", req.Repository, req.CommitSHA[:8])
	g.snapshots[snapshotID] = deploymentData
	stateHash := fmt.Sprintf("%x", []byte(fmt.Sprintf("%s-%s-%d", req.Repository, req.CommitSHA, time.Now().Unix())))
	resp := DeploymentResponse{Authorized: true, StateHash: stateHash, SnapshotID: snapshotID, Message: "Deployment committed successfully", RollbackToken: generateRollbackToken(req.Repository, snapshotID)}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (g *SimpleServer) handleAuthorizeDeployment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req DeploymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	authorized := true
	message := "Deployment authorized"
	if req.SignatureURL == "" {
		authorized = false
		message = "Deployment must be signed with Sigstore"
	}
	resp := DeploymentResponse{Authorized: authorized, Message: message}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (g *SimpleServer) handleInitiateRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req RollbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if req.Repository == "" || req.SnapshotID == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}
	if _, exists := g.snapshots[req.SnapshotID]; !exists {
		http.Error(w, "Snapshot not found", http.StatusNotFound)
		return
	}
	g.deployments[req.Repository] = g.snapshots[req.SnapshotID]
	resp := map[string]interface{}{"success": true, "snapshot_id": req.SnapshotID, "message": "Rollback executed successfully", "data": g.snapshots[req.SnapshotID]}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (g *SimpleServer) handleExecuteRollback(w http.ResponseWriter, r *http.Request) {
	g.handleInitiateRollback(w, r)
}

func (g *SimpleServer) handleListSnapshots(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ids := make([]string, 0, len(g.snapshots))
	for id := range g.snapshots {
		ids = append(ids, id)
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"snapshots": ids, "count": len(ids)})
}

func (g *SimpleServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}

func generateRollbackToken(repository, snapshotID string) string {
	return fmt.Sprintf("rollback-%s-%s-%d", repository, snapshotID, time.Now().Unix())
}
