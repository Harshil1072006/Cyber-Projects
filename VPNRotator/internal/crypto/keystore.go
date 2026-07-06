package crypto

import (
	"crypto/rand"
	"io"
	"os"
)

const keyFile = "e2ee_key.bin"

// LoadOrCreateKey loads the key from disk.
// If no key exists, generates a new 256-bit key and saves it.
func LoadOrCreateKey() ([]byte, error) {
	if data, err := os.ReadFile(keyFile); err == nil && len(data) == 32 {
		return data, nil // key exists and is valid
	}

	// First run: generate a new key
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}

	// In a real production app, use OS keychain (DPAPI / Secret Service).
	// For now, storing locally with 0600 permissions.
	_ = os.WriteFile(keyFile, key, 0600)
	return key, nil
}
