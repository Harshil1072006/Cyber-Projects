package vpn

import (
	"encoding/base64"
	"fmt"
	"os"
)

// PrepareConfig decodes the Base64 OpenVPN configuration, injects DNS leak
// protection, and writes it to a temporary file. Returns the path to the temp file.
func PrepareConfig(b64Config string) (string, error) {
	decodedBytes, err := base64.StdEncoding.DecodeString(b64Config)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 config: %w", err)
	}

	configStr := string(decodedBytes)

	// Inject DNS leak protection and block outside DNS
	dnsProtection := `
# --- VPNRotator DNS Protection ---
dhcp-option DNS 1.1.1.1
dhcp-option DNS 8.8.8.8
block-outside-dns
# ---------------------------------
`
	// Append to the configuration
	configStr = configStr + dnsProtection

	// Write to temporary file
	tempFile, err := os.CreateTemp("", "vpn_rotator_*.ovpn")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	defer tempFile.Close()

	if _, err := tempFile.WriteString(configStr); err != nil {
		return "", fmt.Errorf("failed to write to temp file: %w", err)
	}

	return tempFile.Name(), nil
}

// CleanupConfig removes the temporary OpenVPN configuration file.
func CleanupConfig(filePath string) error {
	if filePath == "" {
		return nil
	}
	return os.Remove(filePath)
}
