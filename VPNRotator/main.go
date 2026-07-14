package main

import (
	"log"
	"time"

	"fyne.io/fyne/v2"
	"github.com/harshil/vpnrotator/internal/cache"
	"github.com/harshil/vpnrotator/internal/ui"
	"github.com/harshil/vpnrotator/internal/vpn"
)

func main() {
	// Auto-elevate to Administrator via UAC prompt if not already
	ensureAdmin()

	// 1. Initialize Cache Manager
	cm := cache.NewCacheManager()

	// Load servers asynchronously so UI opens immediately
	go func() {
		err := cm.LoadOrFetch()
		if err != nil {
			log.Printf("Failed to load/fetch VPN servers: %v", err)
		} else {
			log.Printf("Loaded %d VPN servers", len(cm.GetServers()))
		}
	}()
	cm.StartAutoRefresh()

	// 2. Initialize VPN Manager
	vpnMgr := vpn.NewManager()

	// 3. Initialize UI
	app := ui.NewApp()

	var rotator *vpn.Rotator
	var mainView *ui.MainView

	mainView = ui.NewMainView(func(isOn bool, interval time.Duration) {
		if mainView == nil {
			return
		}

		if isOn {
			// Enforce minimum interval
			if interval < 15*time.Second {
				interval = 15 * time.Second
			}

			mainView.UpdateStatus("⟳ Starting VPN rotation...")
			mainView.AppendLog("Starting VPN rotation...")

			rotator = vpn.NewRotator(vpnMgr, cm, interval, func(status string) {
				mainView.UpdateStatus(status)
				// Extract IP from status line for IP display
				if ip := extractIP(status); ip != "" {
					mainView.UpdateIP(ip)
				}
			})
			rotator.Start()
		} else {
			if rotator != nil {
				rotator.Stop()
				rotator = nil
			}
			mainView.UpdateStatus("⬤  Disconnected")
			mainView.UpdateIP("")
			mainView.AppendLog("VPN rotation stopped.")
		}
	})

	app.Window.SetContent(mainView.Build())
	app.Window.Resize(fyne.NewSize(480, 400))

	// 4. Run Application
	app.Run()
}

// extractIP pulls a public IP address out of a status string.
// Status lines look like: "✓ Connected · 🇯🇵 Japan · Public IP: 1.2.3.4"
func extractIP(status string) string {
	const prefix = "Public IP: "
	idx := indexOf(status, prefix)
	if idx < 0 {
		return ""
	}
	return status[idx+len(prefix):]
}

func indexOf(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
