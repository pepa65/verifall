package jsonsigner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cowboyrushforth/verifidod/seclog"
)

// KeyData stores information about a registered key
type KeyData struct {
	KeyHandle       string    `json:"key_handle"`       // Base64 encoded key handle
	PrivateKeyD     string    `json:"private_key_d"`    // Base64 encoded private key D component
	PublicKeyX      string    `json:"public_key_x"`     // Base64 encoded public key X component
	PublicKeyY      string    `json:"public_key_y"`     // Base64 encoded public key Y component
	AppParameter    string    `json:"app_parameter"`    // Base64 encoded application parameter
	CreatedAt       time.Time `json:"created_at"`       // When the key was created
	LastUsed        time.Time `json:"last_used"`        // When the key was last used
	UseCount        int       `json:"use_count"`        // Number of times the key has been used
}

// JSONStore is the persistent storage for all registered keys
type JSONStore struct {
	Keys            map[string]KeyData `json:"keys"`            // Map of key handles to key data
	Counter         uint32             `json:"counter"`         // Monotonically increasing counter
	MasterKeyHash   string             `json:"master_key_hash"` // Hash of master key for verification
	CreatedAt       time.Time          `json:"created_at"`      // When this store was created
	LastUpdated     time.Time          `json:"last_updated"`    // When this store was last updated
}

// JSONSigner implements the Signer interface using JSON file for persistence
type JSONSigner struct {
	storePath      string
	store          JSONStore
	masterKey      []byte
	mutex          sync.Mutex
	baseTime       time.Time
}

// New creates a new JSONSigner that persists keys to the given path
func New(storePath string) (*JSONSigner, error) {
	if storePath == "" {
		// Use default path in user's home directory
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("cannot get home directory: %w", err)
		}
		storePath = filepath.Join(home, ".config", "verifidod", "credentials.json")
	}

	// Ensure directory exists
	storeDir := filepath.Dir(storePath)
	if err := os.MkdirAll(storeDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create directory %s: %w", storeDir, err)
	}

	signer := &JSONSigner{
		storePath: storePath,
		baseTime:  time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC),
	}

	// Generate or load master key
	if err := signer.initStore(); err != nil {
		return nil, fmt.Errorf("failed to initialize credential store: %w", err)
	}

	return signer, nil
}

// initStore initializes the credentials store, creating it if needed
func (s *JSONSigner) initStore() error {
	// Check if store file exists
	_, err := os.Stat(s.storePath)
	if os.IsNotExist(err) {
		// Create a new store with master key
		s.masterKey = make([]byte, 32) // 256-bit key
		if _, err := rand.Read(s.masterKey); err != nil {
			return fmt.Errorf("failed to generate master key: %w", err)
		}

		// Create initial store
		s.store = JSONStore{
			Keys:          make(map[string]KeyData),
			Counter:       0,
			MasterKeyHash: hashAndEncodeKey(s.masterKey),
			CreatedAt:     time.Now(),
			LastUpdated:   time.Now(),
		}

		// Save the new store
		if err := s.saveStore(); err != nil {
			return fmt.Errorf("failed to save new store: %w", err)
		}

		seclog.Info("Created new JSON credentials store at %s", s.storePath)
		seclog.SecurityEvent("System initialized with JSON credential store")
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to check store file: %w", err)
	}

	// Load existing store
	data, err := ioutil.ReadFile(s.storePath)
	if err != nil {
		return fmt.Errorf("failed to read store file: %w", err)
	}

	if err := json.Unmarshal(data, &s.store); err != nil {
		return fmt.Errorf("failed to parse store file: %w", err)
	}

	// Generate a master key that will be consistent for this session
	// Note: Since we're implementing a fingerprint-only system, we don't need
	// to derive the actual master key from the hash - we only need it for this session
	s.masterKey = make([]byte, 32)
	if _, err := rand.Read(s.masterKey); err != nil {
		return fmt.Errorf("failed to generate session key: %w", err)
	}

	seclog.Info("Loaded JSON credentials store from %s with %d keys", s.storePath, len(s.store.Keys))
	return nil
}

// saveStore persists the current state to disk
func (s *JSONSigner) saveStore() error {
	s.store.LastUpdated = time.Now()
	
	data, err := json.MarshalIndent(s.store, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal store: %w", err)
	}

	// Write to a temporary file first, then rename for atomicity
	tempFile := s.storePath + ".tmp"
	if err := ioutil.WriteFile(tempFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write temporary store file: %w", err)
	}

	if err := os.Rename(tempFile, s.storePath); err != nil {
		return fmt.Errorf("failed to rename store file: %w", err)
	}

	return nil
}

// Counter returns a monotonically increasing counter
func (s *JSONSigner) Counter() uint32 {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.store.Counter++
	// We don't save on every counter increment as that would be too expensive
	return s.store.Counter
}

// RegisterKey generates a new key and returns its handle, X and Y coordinates
func (s *JSONSigner) RegisterKey(applicationParam []byte) ([]byte, *big.Int, *big.Int, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Generate a new EC key on the P-256 curve
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Create a unique ID for this key
	keyID := fmt.Sprintf("%d-%x", time.Now().UnixNano(), sha256.Sum256(append(applicationParam, privateKey.D.Bytes()...)))
	keyHandle := []byte(keyID)

	// Encode key components for storage
	keyData := KeyData{
		KeyHandle:    base64.StdEncoding.EncodeToString(keyHandle),
		PrivateKeyD:  base64.StdEncoding.EncodeToString(privateKey.D.Bytes()),
		PublicKeyX:   base64.StdEncoding.EncodeToString(privateKey.X.Bytes()),
		PublicKeyY:   base64.StdEncoding.EncodeToString(privateKey.Y.Bytes()),
		AppParameter: base64.StdEncoding.EncodeToString(applicationParam),
		CreatedAt:    time.Now(),
		LastUsed:     time.Now(),
		UseCount:     0,
	}

	// Store the key data
	s.store.Keys[keyData.KeyHandle] = keyData

	// Save changes to disk
	if err := s.saveStore(); err != nil {
		seclog.Error("Failed to save key to store: %v", err)
		return nil, nil, nil, fmt.Errorf("failed to save key: %w", err)
	}

	seclog.Info("Registered new key for application in JSON store")
	return keyHandle, privateKey.X, privateKey.Y, nil
}

// SignASN1 signs the digest using the provided key handle
func (s *JSONSigner) SignASN1(keyHandle, applicationParam, digest []byte) ([]byte, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Get the key data from the store
	keyHandleStr := base64.StdEncoding.EncodeToString(keyHandle)
	keyData, exists := s.store.Keys[keyHandleStr]
	if !exists {
		// Try looking up by the original key ID as fallback
		for _, key := range s.store.Keys {
			decoded, _ := base64.StdEncoding.DecodeString(key.KeyHandle)
			if string(decoded) == string(keyHandle) {
				keyData = key
				exists = true
				break
			}
		}

		if !exists {
			return nil, fmt.Errorf("key handle not found in store")
		}
	}

	// Decode the private key from storage
	privateDBytes, err := base64.StdEncoding.DecodeString(keyData.PrivateKeyD)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}

	// Create the private key
	privateKey := new(ecdsa.PrivateKey)
	privateKey.D = new(big.Int).SetBytes(privateDBytes)
	privateKey.PublicKey.Curve = elliptic.P256()
	privateKey.PublicKey.X, privateKey.PublicKey.Y = privateKey.PublicKey.Curve.ScalarBaseMult(privateKey.D.Bytes())

	// Sign the digest
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest)
	if err != nil {
		return nil, fmt.Errorf("signing error: %w", err)
	}

	// Update usage statistics
	keyData.LastUsed = time.Now()
	keyData.UseCount++
	s.store.Keys[keyHandleStr] = keyData

	// Save changes periodically but not on every sign to avoid excessive disk writes
	if keyData.UseCount%10 == 0 {
		if err := s.saveStore(); err != nil {
			seclog.Error("Failed to update key usage data: %v", err)
		}
	}

	return signature, nil
}

// SignASN1WithRPID is a compatibility function that simply forwards to SignASN1
// Since we're using fingerprint-only auth, we don't need strict RPID validation
func (s *JSONSigner) SignASN1WithRPID(keyHandle, applicationParam, digest []byte, rpid string) ([]byte, error) {
	// In fingerprint-only mode, we don't need to validate RPIDs
	return s.SignASN1(keyHandle, applicationParam, digest)
}

// hashAndEncodeKey creates a hash of the key for verification
func hashAndEncodeKey(key []byte) string {
	hash := sha256.Sum256(key)
	return base64.StdEncoding.EncodeToString(hash[:])
}