package revocation

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pepa65/verifall/seclog"
)

// RevokedKey represents a revoked key
type RevokedKey struct {
	KeyHash   string    `json:"key_hash"`
	RevokedAt time.Time `json:"revoked_at"`
	Reason    string    `json:"reason"`
}

// RevocationDB holds the list of revoked keys
type RevocationDB struct {
	RevokedKeys []RevokedKey `json:"revoked_keys"`
}

var (
	db     RevocationDB
	dbPath string
	mu     sync.RWMutex
	loaded bool
)

// Initialize initializes the revocation database
func Initialize(path string) error {
	mu.Lock()
	defer mu.Unlock()

	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("cannot get home directory: %w", err)
		}
		path = filepath.Join(home, ".config", "verifidod", "revoked_keys.json")
	}

	dbPath = path

	// Check if file exists
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		// Create empty DB
		err = os.MkdirAll(filepath.Dir(dbPath), 0700)
		if err != nil {
			return fmt.Errorf("cannot create revocation directory: %w", err)
		}

		db = RevocationDB{
			RevokedKeys: []RevokedKey{},
		}

		err = saveDB()
		if err != nil {
			return fmt.Errorf("cannot save empty revocation DB: %w", err)
		}
	} else {
		// Read existing DB
		data, err := ioutil.ReadFile(dbPath)
		if err != nil {
			return fmt.Errorf("cannot read revocation DB: %w", err)
		}

		err = json.Unmarshal(data, &db)
		if err != nil {
			return fmt.Errorf("cannot unmarshal revocation DB: %w", err)
		}
	}

	loaded = true
	return nil
}

// saveDB saves the revocation database
func saveDB() error {
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot marshal revocation DB: %w", err)
	}

	err = ioutil.WriteFile(dbPath, data, 0600)
	if err != nil {
		return fmt.Errorf("cannot write revocation DB: %w", err)
	}

	return nil
}

// RevokeKey revokes a key
func RevokeKey(keyHash string, reason string) error {
	mu.Lock()
	defer mu.Unlock()

	if !loaded {
		return fmt.Errorf("revocation DB not initialized")
	}

	// Check if already revoked
	for _, key := range db.RevokedKeys {
		if key.KeyHash == keyHash {
			return fmt.Errorf("key already revoked")
		}
	}

	// Add to revoked keys
	db.RevokedKeys = append(db.RevokedKeys, RevokedKey{
		KeyHash:   keyHash,
		RevokedAt: time.Now(),
		Reason:    reason,
	})

	err := saveDB()
	if err != nil {
		return fmt.Errorf("cannot save revocation DB: %w", err)
	}

	seclog.SecurityEvent("Key revoked: %s (reason: %s)", keyHash, reason)
	return nil
}

// IsRevoked checks if a key is revoked
func IsRevoked(keyHash string) (bool, error) {
	mu.RLock()
	defer mu.RUnlock()

	if !loaded {
		err := Initialize("")
		if err != nil {
			return false, fmt.Errorf("cannot initialize revocation DB: %w", err)
		}
	}

	for _, key := range db.RevokedKeys {
		if key.KeyHash == keyHash {
			return true, nil
		}
	}

	return false, nil
}
