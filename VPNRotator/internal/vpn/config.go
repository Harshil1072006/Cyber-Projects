package vpn

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// PrepareConfig decodes the Base64 OpenVPN configuration, injects mandatory
// routing directives to ensure all traffic goes through the VPN, and writes
// it to a temporary file. Returns the path to the temp file.
func PrepareConfig(b64Config string) (string, error) {
	decodedBytes, err := base64.StdEncoding.DecodeString(b64Config)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 config: %w", err)
	}

	configStr := string(decodedBytes)

	// Remove potentially conflicting directives from the original config
	// that might prevent traffic from being routed through VPN
	linesToRemove := []string{
		"redirect-gateway",
		"block-outside-dns",
		"dhcp-option DNS",
	}
	lines := strings.Split(configStr, "\n")
	var filtered []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(strings.ToLower(line))
		skip := false
		for _, remove := range linesToRemove {
			if strings.HasPrefix(trimmed, strings.ToLower(remove)) {
				skip = true
				break
			}
		}
		if !skip {
			filtered = append(filtered, line)
		}
	}
	configStr = strings.Join(filtered, "\n")

	// Inject critical routing + DNS directives
	injected := `
# --- VPNRotator Injected Settings ---
# Route ALL traffic through VPN (this is what changes your IP)
redirect-gateway def1 bypass-dhcp

# Use VPN Gate's DNS to prevent DNS leaks
dhcp-option DNS 8.8.8.8
dhcp-option DNS 1.1.1.1

# Compatibility flags
script-security 2
route-delay 2
tun-mtu 1500
mssfix 1450
# ------------------------------------
`
	configStr = configStr + injected

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
