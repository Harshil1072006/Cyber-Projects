package killswitch

import (
	"fmt"
	"os/exec"
)

type WindowsKillSwitch struct {
	rulePrefix string
}

func NewWindowsKillSwitch() *WindowsKillSwitch {
	return &WindowsKillSwitch{
		rulePrefix: "VPNRotator_KS_",
	}
}

// Enable blocks all outbound traffic and only allows OpenVPN to connect to the target IP
func (k *WindowsKillSwitch) Enable(openVpnExePath, vpnGateServerIP string) error {
	// 1. Remove old rules just in case
	_ = k.Disable()

	// 2. Block all outbound traffic by default on the active profile
	// NOTE: We don't change the global default-deny policy here to avoid messing up the user's OS
	// Instead, we add a block-all outbound rule, and then add specific allow rules.
	
	blockRuleCmd := fmt.Sprintf("netsh advfirewall firewall add rule name=\"%sBlockAll\" dir=out action=block", k.rulePrefix)
	if err := runCmd(blockRuleCmd); err != nil {
		return fmt.Errorf("failed to add block rule: %w", err)
	}

	// 3. Allow traffic to/from TAP adapter (the VPN interface)
	// OpenVPN tap adapter often matches 'TAP-Windows Adapter V9' or similar. 
	// A simpler approach for the kill switch is to allow the openvpn.exe to make outbound connections to the specific VPN server IP.
	allowVpnServerCmd := fmt.Sprintf("netsh advfirewall firewall add rule name=\"%sAllowServer\" dir=out action=allow program=\"%s\" remoteip=%s", k.rulePrefix, openVpnExePath, vpnGateServerIP)
	if err := runCmd(allowVpnServerCmd); err != nil {
		k.Disable()
		return fmt.Errorf("failed to allow openvpn server: %w", err)
	}

	// Allow loopback for localhost (needed for OpenVPN management socket)
	allowLocalhost := fmt.Sprintf("netsh advfirewall firewall add rule name=\"%sAllowLocal\" dir=out action=allow remoteip=127.0.0.1", k.rulePrefix)
	if err := runCmd(allowLocalhost); err != nil {
		k.Disable()
		return fmt.Errorf("failed to allow localhost: %w", err)
	}

	return nil
}

// Disable removes the firewall rules added by Enable.
func (k *WindowsKillSwitch) Disable() error {
	cmd := fmt.Sprintf("netsh advfirewall firewall delete rule name=all | findstr /C:\"%s\"", k.rulePrefix)
	// We'll just delete rules starting with the prefix
	deleteCmd := fmt.Sprintf("netsh advfirewall firewall delete rule name=\"%sBlockAll\"", k.rulePrefix)
	_ = runCmd(deleteCmd)
	
	deleteCmd = fmt.Sprintf("netsh advfirewall firewall delete rule name=\"%sAllowServer\"", k.rulePrefix)
	_ = runCmd(deleteCmd)
	
	deleteCmd = fmt.Sprintf("netsh advfirewall firewall delete rule name=\"%sAllowLocal\"", k.rulePrefix)
	_ = runCmd(deleteCmd)

	return nil
}

func runCmd(command string) error {
	cmd := exec.Command("cmd", "/C", command)
	return cmd.Run()
}
