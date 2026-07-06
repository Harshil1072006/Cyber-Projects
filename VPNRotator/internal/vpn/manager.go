package vpn

import (
	"fmt"
	"log"
	"os/exec"
	"time"

	"github.com/NordSecurity/gopenvpn"
)

const (
	managementHost = "127.0.0.1"
	managementPort = 11940
)

type Manager struct {
	cmd          *exec.Cmd
	mgmtClient   *gopenvpn.Client
	tempConfPath string
	isConnected  bool
}

func NewManager() *Manager {
	return &Manager{}
}

// Connect prepares the config and launches openvpn.
func (m *Manager) Connect(b64Config string) error {
	// If already running, disconnect first
	if m.cmd != nil {
		m.Disconnect()
	}

	confPath, err := PrepareConfig(b64Config)
	if err != nil {
		return err
	}
	m.tempConfPath = confPath

	// Launch OpenVPN
	// Assuming openvpn.exe is in PATH or standard location
	// Note: On Windows, might need exact path or rely on PATH environment
	openvpnPath := "openvpn" 
	
	m.cmd = exec.Command(openvpnPath,
		"--config", m.tempConfPath,
		"--management", managementHost, fmt.Sprintf("%d", managementPort),
	)

	if err := m.cmd.Start(); err != nil {
		CleanupConfig(m.tempConfPath)
		return fmt.Errorf("failed to start openvpn: %w", err)
	}

	// Give OpenVPN a moment to open the management port
	time.Sleep(1 * time.Second)

	// Connect to management interface
	m.mgmtClient, err = gopenvpn.NewClient(managementHost, managementPort)
	if err != nil {
		m.Disconnect()
		return fmt.Errorf("failed to connect to openvpn management: %w", err)
	}

	// Wait for connection to establish (basic poll)
	// In a real app, we would listen to events using mgmtClient
	m.isConnected = true
	log.Println("OpenVPN started and management connected")

	// Once OpenVPN reads the config, we can technically delete it
	// But it's safer to delete on disconnect
	return nil
}

// Disconnect gracefully stops openvpn and cleans up.
func (m *Manager) Disconnect() {
	if m.mgmtClient != nil {
		// Send SIGTERM via management interface for graceful shutdown
		_ = m.mgmtClient.Signal("SIGTERM")
		m.mgmtClient.Close()
		m.mgmtClient = nil
	}

	if m.cmd != nil {
		// Wait for process to exit
		_ = m.cmd.Wait()
		m.cmd = nil
	}

	m.isConnected = false

	if m.tempConfPath != "" {
		_ = CleanupConfig(m.tempConfPath)
		m.tempConfPath = ""
	}
	log.Println("OpenVPN disconnected and config cleaned up")
}

// IsConnected returns true if we believe OpenVPN is running.
func (m *Manager) IsConnected() bool {
	return m.isConnected
}
