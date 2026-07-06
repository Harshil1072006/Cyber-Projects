package killswitch

// KillSwitch defines the interface for managing OS-level firewall rules
// to protect the user's real IP address.
type KillSwitch interface {
	// Enable blocks all outside traffic except for the OpenVPN executable
	// and traffic over the VPN tunnel adapter.
	Enable(openVpnExePath, vpnGateServerIP string) error

	// Disable removes the firewall rules and restores default connectivity.
	Disable() error
}
