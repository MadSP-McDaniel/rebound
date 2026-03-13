package librebound

import (
	"sync"

	"k8s.io/klog/v2"
)

// StateManager manages the in-memory key-value state of the system.
// It is responsible for tracking the mapping of logical keys (e.g., filenames)
// to their content hashes. The entire state is versioned in the transparency log.
// This implementation is thread-safe.
type StateManager struct {
	mu    sync.RWMutex
	state map[string][]byte
}

// NewStateManager creates and initializes a new StateManager.
func NewStateManager() *StateManager {
	return &StateManager{
		state: make(map[string][]byte),
	}
}

// Update sets or updates the content hash for a given key in the state.
func (sm *StateManager) Update(key string, contentHash []byte) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.state[key] = contentHash
}

// Get retrieves the content hash for a given key.
// It returns the hash and a boolean indicating if the key was found.
func (sm *StateManager) Get(key string) ([]byte, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	klog.Infof("Looking for key: %s", key)
	val, ok := sm.state[key]
	return val, ok
}

// GetState returns a shallow copy of the current state map.
// Note: The byte slices within the map are not copied. For a safe, deep copy
// for transactional operations, use GetStateCopy.
func (sm *StateManager) GetState() map[string][]byte {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	stateCopy := make(map[string][]byte, len(sm.state))
	for k, v := range sm.state {
		stateCopy[k] = v
	}
	return stateCopy
}

// GetStateCopy returns a deep copy of the current state map.
// This is critical for creating transactional state updates, ensuring that
// the map passed to the logger is immutable and safe from concurrent modification.
func (sm *StateManager) GetStateCopy() map[string][]byte {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	copyMap := make(map[string][]byte, len(sm.state))
	for k, v := range sm.state {
		// Create a new byte slice and copy the content to prevent aliasing.
		valueCopy := make([]byte, len(v))
		copy(valueCopy, v)
		copyMap[k] = valueCopy
	}
	return copyMap
}

// LoadState replaces the current state with the provided map of strings.
// This function is preserved for API compatibility. It converts the string
// values to byte slices.
func (sm *StateManager) LoadState(stateMap map[string]string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	newState := make(map[string][]byte, len(stateMap))
	for k, v := range stateMap {
		newState[k] = []byte(v)
	}
	sm.state = newState
}

// LoadStateFromBytes replaces the current state with the provided map.
// This is used during a rollback to atomically replace the entire in-memory state
// with a historical version from the log.
// It assumes the provided map is safe to use directly.
func (sm *StateManager) LoadStateFromBytes(stateMap map[string][]byte) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	// The provided map comes from a deserialized log entry, so it's a new allocation.
	// We can take ownership of it directly without needing another copy.
	sm.state = stateMap
}
