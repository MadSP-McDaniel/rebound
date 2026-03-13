package librebound

import (
	"errors"
	"strings"
	"sync"
)

// IndexDB is a simple in-memory index mapping keys to Tessera leaf indices.
// TODO: replace with persistent storage (BoltDB, SQLite, etc.).
type IndexDB struct {
	mu    sync.Mutex
	index map[string]uint64
}

// NewIndexDB creates a new in-memory index.
func NewIndexDB() *IndexDB {
	return &IndexDB{
		index: make(map[string]uint64),
	}
}

// Store saves the mapping from key to leaf index.
func (db *IndexDB) Store(key string, idx uint64) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	db.index[key] = idx
	return nil
}

// GetIndex retrieves the leaf index for a given key.
func (db *IndexDB) GetIndex(key string) (uint64, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	if idx, ok := db.index[key]; ok {
		return idx, nil
	}
	return 0, errors.New("key not found")
}

// GetKeysWithPrefix returns all keys that start with the given prefix.
func (db *IndexDB) GetKeysWithPrefix(prefix string) ([]string, error) {
	var keys []string
	db.mu.Lock()
	defer db.mu.Unlock()

	for k := range db.index {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	return keys, nil
}
