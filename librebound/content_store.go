package librebound

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
)

// ContentStore provides in-memory, content-addressable storage for raw data blobs.
// It ensures that each unique piece of content is stored only once.
// Data is stored and retrieved using its SHA256 hash.
// This implementation is for demonstration; a production system would use a
// persistent storage backend (e.g., a file system or object store).
type ContentStore struct {
	mu    sync.RWMutex
	store map[string][]byte
}

// NewContentStore creates a new in-memory ContentStore.
func NewContentStore() *ContentStore {
	return &ContentStore{
		store: make(map[string][]byte),
	}
}

// Store adds a data blob to the content store.
// It calculates the SHA256 hash of the data, which serves as the key.
// If the data is already present, the operation is a no-op.
// It returns the hex-encoded SHA256 hash of the data.
func (cs *ContentStore) Store(data []byte) (string, error) {
	if data == nil {
		return "", fmt.Errorf("cannot store nil data")
	}
	hash := sha256.Sum256(data)
	hashStr := hex.EncodeToString(hash[:])

	cs.mu.Lock()
	defer cs.mu.Unlock()

	if _, exists := cs.store[hashStr]; !exists {
		// Create a copy to ensure the caller can't mutate our stored data.
		dataCopy := make([]byte, len(data))
		copy(dataCopy, data)
		cs.store[hashStr] = dataCopy
	}

	return hashStr, nil
}

// Fetch retrieves data from the content store using its hex-encoded SHA256 hash.
// It returns a copy of the data to prevent mutation by the caller.
// Returns an error if the content is not found.
func (cs *ContentStore) Fetch(hashStr string) ([]byte, error) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	data, exists := cs.store[hashStr]
	if !exists {
		return nil, fmt.Errorf("content with hash %s not found", hashStr)
	}
	// Return a copy to prevent the caller from mutating the stored data.
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)
	return dataCopy, nil
}
