package vpn

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/harshil/vpnrotator/internal/cache"
	"github.com/harshil/vpnrotator/internal/killswitch"
)

const (
	maxRetries    = 5               // Try up to 5 different servers before giving up
	retryDelay    = 3 * time.Second // Wait between retries
	ipVerifyDelay = 5 * time.Second // Wait after connect before verifying IP
)

type Rotator struct {
	manager      *Manager
	cacheManager *cache.CacheManager
	ks           killswitch.KillSwitch
	interval     time.Duration
	cancelFunc   context.CancelFunc
	onStatus     func(string)
	
	// Track which server indices we've tried recently to avoid repeating
	recentlyTried map[int]bool
}

func NewRotator(mgr *Manager, cm *cache.CacheManager, interval time.Duration, statusCb func(string)) *Rotator {
	return &Rotator{
		manager:       mgr,
		cacheManager:  cm,
		ks:            killswitch.NewWindowsKillSwitch(),
		interval:      interval,
		onStatus:      statusCb,
		recentlyTried: make(map[int]bool),
	}
}

// Start begins the rotation cycle.
func (r *Rotator) Start() {
	if r.cancelFunc != nil {
		return // Already running
	}

	ctx, cancel := context.WithCancel(context.Background())
	r.cancelFunc = cancel

	go r.rotationLoop(ctx)
}

// Stop halts the rotation cycle and disconnects.
func (r *Rotator) Stop() {
	if r.cancelFunc != nil {
		r.cancelFunc()
		r.cancelFunc = nil
	}
	r.onStatus("Disconnecting...")
	r.manager.Disconnect()
	r.ks.Disable() // ensure killswitch is off if we fully stop
	r.onStatus("⬤ Disconnected")
}

func (r *Rotator) rotationLoop(ctx context.Context) {
	// Initial connection on start
	r.rotate(ctx)

	if ctx.Err() != nil {
		return
	}

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.onStatus("⟳ Rotating to new VPN server...")
			r.rotate(ctx)
		}
	}
}

// rotate attempts to connect to a new VPN server with retries.
func (r *Rotator) rotate(ctx context.Context) {
	// Wait up to 10 seconds for servers to be loaded
	var servers []cache.VPNServer
	for i := 0; i < 10; i++ {
		servers = r.cacheManager.GetServers()
		if len(servers) > 0 {
			break
		}
		r.onStatus("Waiting for servers to load...")
		select {
		case <-ctx.Done():
			return
		case <-time.After(1 * time.Second):
		}
	}

	if len(servers) == 0 {
		r.onStatus("✗ Error: No VPN servers available")
		return
	}

	// Reset recently tried if all servers have been tried
	if len(r.recentlyTried) >= len(servers) {
		r.recentlyTried = make(map[int]bool)
	}

	// Try up to maxRetries different servers
	for attempt := 1; attempt <= maxRetries; attempt++ {
		if ctx.Err() != nil {
			r.ks.Disable()
			return
		}

		// Pick a random server we haven't tried recently
		idx := r.pickServer(servers)
		server := servers[idx]
		r.recentlyTried[idx] = true

		r.onStatus(fmt.Sprintf("🛡️ Engaging Kill Switch..."))
		if err := r.ks.Enable(r.manager.GetOpenVPNPath(), server.IP); err != nil {
			log.Printf("Warning: failed to enable killswitch: %v", err)
		}

		r.onStatus(fmt.Sprintf("⟳ Connecting to %s (%s) [%d/%d]...",
			server.CountryLong, server.IP, attempt, maxRetries))

		log.Printf("Attempt %d/%d: connecting to %s (%s) — ping:%dms speed:%s",
			attempt, maxRetries,
			server.CountryLong, server.IP,
			server.Ping, formatSpeed(server.Speed))

		err := r.manager.Connect(server.OpenVPNConfigB64, func(line string) {
			// Forward key OpenVPN log lines to status
			if containsAny(line, "Connecting to", "TLS", "AUTH", "route") {
				r.onStatus("⟳ " + trimLogLine(line))
			}
		})

		if err != nil {
			log.Printf("Failed to connect to %s: %v", server.IP, err)
			r.onStatus(fmt.Sprintf("✗ %s failed: %v — retrying...", server.IP, err))

			// Wait before next retry (respect context cancellation)
			select {
			case <-ctx.Done():
				r.ks.Disable()
				return
			case <-time.After(retryDelay):
			}
			continue
		}

		// Connected! Disable transient kill switch because OpenVPN redirect-gateway takes over
		r.ks.Disable()
		r.onStatus(fmt.Sprintf("✓ Tunnel up via %s · Verifying IP...", server.CountryLong))

		select {
		case <-ctx.Done():
			return
		case <-time.After(ipVerifyDelay):
		}

		publicIP := GetCurrentIP()
		if publicIP != "" {
			r.onStatus(fmt.Sprintf("✓ Connected · %s %s · Public IP: %s",
				countryFlag(server.CountryShort), server.CountryLong, publicIP))
		} else {
			r.onStatus(fmt.Sprintf("✓ Connected · %s %s · VPN IP: %s",
				countryFlag(server.CountryShort), server.CountryLong, server.IP))
		}
		return
	}

	r.onStatus(fmt.Sprintf("✗ Could not connect after %d attempts — will retry at next interval", maxRetries))
}

// pickServer picks a random server index preferring ones not recently tried.
func (r *Rotator) pickServer(servers []cache.VPNServer) int {
	// Build list of untried candidates (prefer high-speed, low-ping)
	var untried []int
	for i := range servers {
		if !r.recentlyTried[i] {
			untried = append(untried, i)
		}
	}
	if len(untried) == 0 {
		return rand.Intn(len(servers))
	}
	// Pick randomly from untried
	return untried[rand.Intn(len(untried))]
}

// formatSpeed converts bytes/sec to human-readable string.
func formatSpeed(bps int64) string {
	switch {
	case bps >= 1_000_000_000:
		return fmt.Sprintf("%.1fGbps", float64(bps)/1e9)
	case bps >= 1_000_000:
		return fmt.Sprintf("%.1fMbps", float64(bps)/1e6)
	case bps >= 1_000:
		return fmt.Sprintf("%.1fKbps", float64(bps)/1e3)
	default:
		return fmt.Sprintf("%dbps", bps)
	}
}

// countryFlag returns a Unicode flag emoji for a 2-letter country code.
func countryFlag(code string) string {
	if len(code) != 2 {
		return ""
	}
	r1 := rune(code[0]-'A') + 0x1F1E6
	r2 := rune(code[1]-'A') + 0x1F1E6
	return string([]rune{r1, r2})
}

// containsAny returns true if s contains any of the substrings.
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) > 0 && len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}

// trimLogLine removes the OpenVPN timestamp prefix from a log line.
func trimLogLine(line string) string {
	// OpenVPN lines look like: "Mon Jan 01 00:00:00 2024 <message>"
	// Try to strip the date prefix (first 24 chars)
	if len(line) > 25 {
		return line[24:]
	}
	return line
}


