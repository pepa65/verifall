package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	
	"github.com/psanford/tpm-fido/seclog"
)

// Configuration holds the application configuration
type Configuration struct {
	// Device paths
	TPMDevicePath        string `json:"tpm_device_path"`
	
	// Security settings
	RequireFingerprint   bool   `json:"require_fingerprint"`
	RequireTPM           bool   `json:"require_tpm"`
	VerificationTimeout  int    `json:"verification_timeout_ms"`
	MaxRetries           int    `json:"max_retries"`
	
	// Logging
	LogLevel             int    `json:"log_level"`
}

var (
	config Configuration
	mu     sync.RWMutex
	loaded bool
)

// DefaultConfig returns the default configuration
func DefaultConfig() Configuration {
	return Configuration{
		TPMDevicePath:       "/dev/tpmrm0",
		RequireFingerprint:  true,
		RequireTPM:          true,
		VerificationTimeout: 5000,
		MaxRetries:          3,
		LogLevel:            seclog.LevelInfo,
	}
}

// LoadConfig loads configuration from file
func LoadConfig(configPath string) error {
	mu.Lock()
	defer mu.Unlock()
	
	// Start with defaults
	config = DefaultConfig()
	
	// Expand home directory if needed
	if configPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("cannot get home directory: %w", err)
		}
		configPath = filepath.Join(home, ".config", "tpm-fido", "config.json")
	}
	
	// Check if file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Create default config
		err = os.MkdirAll(filepath.Dir(configPath), 0700)
		if err != nil {
			return fmt.Errorf("cannot create config directory: %w", err)
		}
		
		data, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			return fmt.Errorf("cannot marshal default config: %w", err)
		}
		
		err = ioutil.WriteFile(configPath, data, 0600)
		if err != nil {
			return fmt.Errorf("cannot write default config: %w", err)
		}
		
		seclog.Info("Created default configuration at %s", configPath)
	} else {
		// Read existing config
		data, err := ioutil.ReadFile(configPath)
		if err != nil {
			return fmt.Errorf("cannot read config: %w", err)
		}
		
		err = json.Unmarshal(data, &config)
		if err != nil {
			return fmt.Errorf("cannot unmarshal config: %w", err)
		}
	}
	
	// Enforce security settings - prevent disabling dual-factor auth
	config.RequireFingerprint = true
	config.RequireTPM = true
	
	// Set log level
	seclog.SetLevel(config.LogLevel)
	
	loaded = true
	return nil
}

// Get returns the current configuration
func Get() Configuration {
	mu.RLock()
	defer mu.RUnlock()
	
	if !loaded {
		// Auto-load default config if not loaded
		mu.RUnlock()
		err := LoadConfig("")
		if err != nil {
			seclog.Error("Failed to load config: %v", err)
		}
		mu.RLock()
	}
	
	return config
}