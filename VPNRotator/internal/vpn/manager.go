package vpn

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	managementHost    = "127.0.0.1"
	managementPort    = 11940
	connectTimeout    = 30 * time.Second // max time to wait for tunnel to come up
	initSequenceMsg   = "Initialization Sequence Completed"
)

// findOpenVPN returns the path to openvpn.exe, checking standard install locations.
func findOpenVPN() string {
	candidates := []string{
		`C:\Program Files\OpenVPN\bin\openvpn.exe`,
		`C:\Program Files (x86)\OpenVPN\bin\openvpn.exe`,
	}
	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	if path, err := exec.LookPath("openvpn"); err == nil {
		return path
	}
	return "openvpn"
}

func resolveOpenVPN() string {
	path := findOpenVPN()
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}

type Manager struct {
	mu           sync.Mutex
	cmd          *exec.Cmd
	mgmtConn     net.Conn
	tempConfPath string
	isConnected  bool
	exitCh       chan struct{} // closed when openvpn process exits
}

func NewManager() *Manager {
	return &Manager{}
}

// Connect prepares the config, launches openvpn, and WAITS until the tunnel
// is actually established (reads "Initialization Sequence Completed" from stdout).
// Returns error if connection fails or times out.
func (m *Manager) Connect(b64Config string, onLog func(string)) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Disconnect any existing session first
	m.disconnectLocked()

	confPath, err := PrepareConfig(b64Config)
	if err != nil {
		return err
	}
	m.tempConfPath = confPath

	openvpnPath := resolveOpenVPN()
	log.Printf("Using OpenVPN binary: %s", openvpnPath)

	cmd := exec.Command(openvpnPath,
		"--config", m.tempConfPath,
		"--management", managementHost, fmt.Sprintf("%d", managementPort),
		"--management-signal",
		"--verb", "3", // 3 = enough to see connect/fail, not the full config dump
	)

	// Merge stdout + stderr into a single pipe we can read line-by-line
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw

	if err := cmd.Start(); err != nil {
		pw.Close()
		pr.Close()
		CleanupConfig(confPath)
		return fmt.Errorf("failed to start openvpn: %w", err)
	}

	m.cmd = cmd
	exitCh := make(chan struct{})
	m.exitCh = exitCh

	// Close the write-end of the pipe when the process exits (signals EOF to scanner)
	go func() {
		cmd.Wait()
		pw.Close()
		close(exitCh)
		log.Println("OpenVPN process exited")
	}()

	// Read stdout/stderr lines looking for success or fatal failure signals
	connectedCh := make(chan bool, 1)
	go func() {
		defer pr.Close()
		scanner := bufio.NewScanner(pr)
		for scanner.Scan() {
			line := scanner.Text()
			log.Printf("[openvpn] %s", line)
			if onLog != nil {
				onLog(line)
			}

			if strings.Contains(line, initSequenceMsg) {
				connectedCh <- true
				return
			}
			// Fatal error indicators — fail fast instead of waiting 30s
			if strings.Contains(line, "AUTH_FAILED") ||
				strings.Contains(line, "TLS handshake failed") ||
				strings.Contains(line, "TLS Error") ||
				strings.Contains(line, "Connection refused") ||
				strings.Contains(line, "Connection timed out") ||
				strings.Contains(line, "SIGTERM") ||
				strings.Contains(line, "Exiting due to fatal error") ||
				strings.Contains(line, "ERROR: Cannot open") ||
				strings.Contains(line, "Options error") {
				connectedCh <- false
				return
			}
		}
		// Scanner ended = pipe closed = process exited without success
		connectedCh <- false
	}()

	// Wait for either: connected, failed, or timeout
	select {
	case success := <-connectedCh:
		if !success {
			m.disconnectLocked()
			return fmt.Errorf("openvpn failed to establish tunnel (auth/TLS error)")
		}
	case <-exitCh:
		m.disconnectLocked()
		return fmt.Errorf("openvpn process exited before tunnel was established")
	case <-time.After(connectTimeout):
		m.disconnectLocked()
		return fmt.Errorf("connection timed out after %s", connectTimeout)
	}

	// Now connect management interface for future control
	conn, err := net.DialTimeout("tcp",
		fmt.Sprintf("%s:%d", managementHost, managementPort), 2*time.Second)
	if err != nil {
		log.Printf("Warning: could not connect to management interface: %v", err)
		// Non-fatal — tunnel is still up
	} else {
		m.mgmtConn = conn
	}

	m.isConnected = true
	log.Println("VPN tunnel established successfully!")
	return nil
}

// GetOpenVPNPath returns the absolute path to the openvpn executable.
func (m *Manager) GetOpenVPNPath() string {
	return resolveOpenVPN()
}

// WaitForExit blocks until the OpenVPN process exits. Returns immediately if not running.
func (m *Manager) WaitForExit() {
	m.mu.Lock()
	ch := m.exitCh
	m.mu.Unlock()
	if ch != nil {
		<-ch
	}
}

// Disconnect gracefully stops openvpn and cleans up.
func (m *Manager) Disconnect() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.disconnectLocked()
}

func (m *Manager) disconnectLocked() {
	if m.mgmtConn != nil {
		_, _ = m.mgmtConn.Write([]byte("signal SIGTERM\r\n"))
		m.mgmtConn.Close()
		m.mgmtConn = nil
	}

	if m.cmd != nil {
		if m.cmd.Process != nil {
			_ = m.cmd.Process.Kill()
		}
		m.cmd = nil
	}

	m.isConnected = false

	if m.tempConfPath != "" {
		_ = CleanupConfig(m.tempConfPath)
		m.tempConfPath = ""
	}

	if m.exitCh != nil {
		// Drain/wait briefly for clean exit
		select {
		case <-m.exitCh:
		case <-time.After(2 * time.Second):
		}
		m.exitCh = nil
	}

	log.Println("OpenVPN disconnected and config cleaned up")
}

// IsConnected returns true if the tunnel is actually up.
func (m *Manager) IsConnected() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.isConnected
}

// GetCurrentIP checks current public IP by querying an external API.
// Returns empty string on failure.
func GetCurrentIP() string {
	endpoints := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
	}
	for _, url := range endpoints {
		cmd := exec.Command("curl", "-s", "--max-time", "5", url)
		out, err := cmd.Output()
		if err == nil {
			ip := strings.TrimSpace(string(out))
			if ip != "" && !strings.Contains(ip, "<") {
				return ip
			}
		}
	}
	return ""
}

// IsAdmin checks if the process has administrator privileges on Windows.
func IsAdmin() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		return false
	}
	return true
}

// pipeToLog copies an io.Reader to the log — used for debugging.
func pipeToLog(r io.Reader, prefix string) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		log.Printf("[%s] %s", prefix, scanner.Text())
	}
}
