package main

import (
	"log"
	"time"

	"github.com/harshil/vpnrotator/internal/cache"
	"github.com/harshil/vpnrotator/internal/ui"
	"github.com/harshil/vpnrotator/internal/vpn"
)

func main() {
	// 1. Initialize Cache Manager
	cm := cache.NewCacheManager()
	
	// We do an initial fetch asynchronously so the UI opens immediately
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

	mainView := ui.NewMainView(func(isOn bool, interval time.Duration) {
		if isOn {
			// Start VPN Rotation
			rotator = vpn.NewRotator(vpnMgr, cm, interval, func(status string) {
				// Safely update UI
				app.Window.Canvas().Refresh(app.Window.Content()) // This forces a redraw, though binding handles it mostly
			})
			
			// Overwrite the status callback to directly update the binding
			rotator = vpn.NewRotator(vpnMgr, cm, interval, func(status string) {
				// Need a reference to mainView to update status binding
			})
			// Actually let's just create it properly
		} else {
			// Stop VPN Rotation
			if rotator != nil {
				rotator.Stop()
				rotator = nil
			}
		}
	})

	// Fix the callback
	mainView = ui.NewMainView(func(isOn bool, interval time.Duration) {
		if isOn {
			mainView.UpdateStatus("Starting VPN...")
			rotator = vpn.NewRotator(vpnMgr, cm, interval, func(status string) {
				mainView.UpdateStatus(status)
			})
			rotator.Start()
		} else {
			if rotator != nil {
				rotator.Stop()
				rotator = nil
			}
			mainView.UpdateStatus("Status: Disconnected")
		}
	})

	app.Window.SetContent(mainView.Build())
	
	// 4. Run Application (Blocks until window is closed)
	app.Run()
}
