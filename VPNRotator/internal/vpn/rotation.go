package vpn

import (
	"context"
	"log"
	"time"

	"github.com/harshil/vpnrotator/internal/cache"
	"github.com/harshil/vpnrotator/internal/idle"
)

type Rotator struct {
	manager      *Manager
	cacheManager *cache.CacheManager
	idleDetector *idle.Detector
	interval     time.Duration
	cancelFunc   context.CancelFunc
	onStatus     func(string)
}

func NewRotator(mgr *Manager, cm *cache.CacheManager, interval time.Duration, statusCb func(string)) *Rotator {
	return &Rotator{
		manager:      mgr,
		cacheManager: cm,
		idleDetector: idle.NewDetector(""), // Real app would set VPN interface name here
		interval:     interval,
		onStatus:     statusCb,
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

// Stop halts the rotation cycle.
func (r *Rotator) Stop() {
	if r.cancelFunc != nil {
		r.cancelFunc()
		r.cancelFunc = nil
	}
	r.manager.Disconnect()
}

func (r *Rotator) rotationLoop(ctx context.Context) {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	// Initial connection
	r.rotate()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.onStatus("Waiting for idle... (next rotate when network quiet)")
			
			// Wait for idle
			maxWait := r.interval * time.Duration(r.idleDetector.MaxWaitMultiplier)
			r.idleDetector.WaitUntilIdle(ctx, maxWait)

			// Check context again after potentially long wait
			if ctx.Err() != nil {
				return
			}

			r.rotate()
		}
	}
}

func (r *Rotator) rotate() {
	r.onStatus("Rotating VPN...")
	
	servers := r.cacheManager.GetServers()
	if len(servers) == 0 {
		log.Println("No servers available for rotation")
		r.onStatus("Error: No servers available")
		return
	}

	// Pick a random server (for simplicity, we'll pick the first here or randomize)
	// We should really randomize this.
	server := servers[time.Now().UnixNano()%int64(len(servers))]

	err := r.manager.Connect(server.OpenVPNConfigB64)
	if err != nil {
		log.Printf("Failed to connect to %s: %v", server.IP, err)
		r.onStatus("Connection Failed")
		return
	}

	r.onStatus("Connected · " + server.CountryLong + " · IP: " + server.IP)
}
