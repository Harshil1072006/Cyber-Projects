package vpn

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"time"
)

const (
	managementHost = "127.0.0.1"
	managementPort = 11940
)

type Manager struct {
	cmd          *exec.Cmd
	mgmtConn     net.Conn
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
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", managementHost, managementPort), 2*time.Second)
	if err != nil {
		m.Disconnect()
		return fmt.Errorf("failed to connect to openvpn management: %w", err)
	}
	m.mgmtConn = conn

	m.isConnected = true
	log.Println("OpenVPN started and management connected")

	return nil
}

// Disconnect gracefully stops openvpn and cleans up.
func (m *Manager) Disconnect() {
	if m.mgmtConn != nil {
		// Send SIGTERM via management interface for graceful shutdown
		_, _ = m.mgmtConn.Write([]byte("signal SIGTERM\r\n"))
		m.mgmtConn.Close()
		m.mgmtConn = nil
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
