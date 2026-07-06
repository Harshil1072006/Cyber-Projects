# 🔒 VPN Gate Auto-Rotator

> **Automatically rotate your public IP address every N seconds** using free, anonymous [VPN Gate](http://www.vpngate.net/) servers.  
> Built in Go. Runs as a native `.exe` on Windows.  
> Two controls only: **ON/OFF** and **how many seconds between rotations**.

---

## What Is This?

This tool connects your computer to a free VPN server and **automatically switches to a new server** at a regular interval — giving you a fresh IP address every time. It pulls from the **VPN Gate** academic project (run by the University of Tsukuba, Japan), which lists thousands of free volunteer-operated VPN servers worldwide.

**Think of it as:** A privacy tool that keeps swapping your internet identity automatically.

---

## What It Does

| Feature | Details |
|---------|---------|
| 🔄 **Auto IP Rotation** | Changes your public IP every N seconds (you choose N) |
| 🔐 **Kill Switch** | Blocks all internet if VPN drops — your real IP is never exposed |
| 💾 **Local Server Cache** | Saves server list locally, hits the API only once per hour |
| 🧠 **Idle-Aware Rotation** | Won't rotate mid-download — waits until your connection is idle |
| 🔒 **AES-256-GCM E2EE** | Optional extra encryption layer before data enters the VPN tunnel |
| 🛡️ **DNS Leak Protection** | Forces DNS through `1.1.1.1` and `8.8.8.8`, blocks outside DNS |
| 📦 **No Account Needed** | VPN Gate is completely free — no sign-up, no API key, no subscription |

---

## What It Does NOT Do

- ❌ Phone home or track you
- ❌ Store logs, passwords, or browsing history
- ❌ Require any account or subscription

---

## Requirements

### Software You Need to Install First

1. **Go 1.22+** — [Download from go.dev](https://go.dev/dl/)  
   Required to build the project from source.

2. **OpenVPN 2.6+** — [Download from openvpn.net](https://openvpn.net/community-downloads/)  
   The app controls OpenVPN under the hood. You just need it installed.  
   ✅ Make sure `openvpn.exe` is at: `C:\Program Files\OpenVPN\bin\openvpn.exe`

3. **TAP-Windows or Wintun Driver** — bundled with the OpenVPN installer, just make sure it's selected during install.

---

## Setup Guide (Windows Step-by-Step)

### Step 1 — Install OpenVPN

1. Download [OpenVPN Community](https://openvpn.net/community-downloads/) (Windows Installer)
2. Run the installer and when asked about drivers, make sure **TAP-Windows6** or **Wintun** is checked
3. Finish install and verify the exe exists at: `C:\Program Files\OpenVPN\bin\openvpn.exe`

### Step 2 — Install Go

1. Download [Go for Windows](https://go.dev/dl/) (the `.msi` installer)
2. Run the installer and follow defaults
3. Open a new PowerShell/Command Prompt and verify: `go version`

### Step 3 — Get the Source Code

```powershell
git clone https://github.com/harshil1072006/vpnrotator.git
cd vpnrotator
```

Or download the ZIP from GitHub → **Code → Download ZIP**, then extract it.

### Step 4 — Build the App

Open PowerShell inside the `VPNRotator` folder and run:

```powershell
go mod download
go mod tidy

# Build the Windows exe (no console window)
$env:GOOS="windows"; $env:GOARCH="amd64"
go build -ldflags="-H=windowsgui -s -w" -o vpn-rotator.exe .
```

This produces `vpn-rotator.exe` (~15 MB) in the same folder.

### Step 5 — Run as Administrator

> ⚠️ The kill switch requires admin rights to set firewall rules.

- Right-click `vpn-rotator.exe` → **Run as administrator**
- Or: Right-click → Properties → Compatibility → check **"Run this program as an administrator"**

---

## How to Use

Once the app is open, you will see this UI:

```
┌─────────────────────────────────────────┐
│         VPN Gate Auto-Rotator           │
│                                         │
│   [ ● ON / OFF ]                        │
│                                         │
│   Rotate every:  [ 30 ] seconds  ▲▼    │
│                                         │
│   ─────────────────────────────────     │
│   Status:   ● Connected                 │
│   Country:  Japan 🇯🇵                   │
│   IP:       103.152.220.x               │
│   Next rotation in:  18s               │
│   Servers available: 3,241              │
└─────────────────────────────────────────┘
```

### Controls

| Control | What it does |
|---------|-------------|
| **ON / OFF Toggle** | Starts or stops the VPN rotation |
| **Rotation Interval (seconds)** | How long between IP changes. Default: 30s |

### Status Messages

| Message | Meaning |
|---------|---------|
| `Connected · Japan · IP: 103.x.x.x` | Working normally |
| `Waiting for idle...` | Timer fired but you're mid-download — it's waiting to safely rotate |
| `Rotating VPN...` | Switching to a new server |
| `Disconnected` | VPN is off |
| `Error: No servers available` | Cache is empty — check your internet connection |

---

## How It Works (Short Version)

1. **On first launch** — fetches a list of free servers from the VPN Gate API and saves locally
2. **When you toggle ON** — connects to a random server, enables the kill switch, starts the timer
3. **Every N seconds** — checks if your connection is idle (not mid-download), then switches to a new server
4. **In the background** — refreshes the server list every hour
5. **If VPN crashes** — kill switch re-fires within 5 seconds and blocks all traffic until reconnected

---

## Security Features Explained

### Kill Switch
When the VPN is ON, Windows Firewall rules block **all outbound traffic** except through the VPN tunnel. If OpenVPN crashes, your real IP is never exposed — the kill switch kicks in within 5 seconds.

### DNS Leak Protection
Every OpenVPN config gets these lines injected automatically:
```
dhcp-option DNS 1.1.1.1
dhcp-option DNS 8.8.8.8
block-outside-dns
```
This ensures your DNS queries (website lookups) go through the VPN, not your real ISP.

### AES-256-GCM Encryption (E2EE)
A Layer 0 encryption wraps your data **before** it enters the VPN tunnel. Even if the volunteer VPN server is malicious, it only ever sees an encrypted blob — never your actual data.

### Idle Detection
The rotator does not blindly swap IPs on a fixed timer. It checks if you're actively transferring data (more than 512 bytes in 2 seconds). If you are, it waits — protecting your active downloads and connections.

---

## FAQ

**Q: Will it break my browsing?**  
A: No. The idle detector waits for quiet moments before rotating. You may notice a 1–2 second pause when it switches.

**Q: Will it break long downloads?**  
A: If a download takes longer than `2 × your interval`, it force-rotates. Set a longer interval (e.g., 300s) if you're downloading large files.

**Q: What if the VPN Gate API is down?**  
A: It falls back to the last saved `vpngate_cache.json`. The very first run needs internet, but after that it works offline using the cache.

**Q: Is this legal?**  
A: VPN Gate is a legitimate academic project from the University of Tsukuba, Japan. Using it is legal in most countries. Check your local laws.

**Q: Why can't I pick a specific country?**  
A: The UI is intentionally minimal. Country filtering can be added in a future version.

**Q: Does it work on Android?**  
A: The architecture supports Android via `gomobile`. See [ARCHITECTURE.md](./ARCHITECTURE.md) for build instructions.

**Q: Why does it need to run as Administrator?**  
A: The kill switch uses Windows Firewall (`netsh advfirewall`) which requires elevated privileges.

---

## Project Structure

```
VPNRotator/
├── main.go                         # Entry point
├── go.mod / go.sum                 # Go module files
├── internal/
│   ├── cache/
│   │   ├── models.go               # VPNServer data model
│   │   └── cache.go                # Fetch, parse, and cache VPN Gate servers
│   ├── crypto/
│   │   ├── e2ee.go                 # AES-256-GCM encryption/decryption
│   │   ├── keystore.go             # Key generation and local storage
│   │   └── pfs.go                  # ECDH X25519 + HKDF (Perfect Forward Secrecy)
│   ├── idle/
│   │   └── detector.go             # Network idle detection
│   ├── vpn/
│   │   ├── config.go               # Base64 decode + DNS injection + temp file write
│   │   ├── manager.go              # OpenVPN process control
│   │   └── rotation.go             # Rotation loop with idle-aware timing
│   ├── killswitch/
│   │   ├── killswitch.go           # Interface definition
│   │   └── killswitch_windows.go   # Windows Firewall rules (netsh)
│   └── ui/
│       ├── app.go                  # Fyne window setup
│       └── mainview.go             # Toggle + interval + status display
├── assets/
│   └── icon.png                    # App icon
├── vpngate_cache.json              # Auto-generated, do not edit
├── ARCHITECTURE.md                 # Deep technical documentation
└── README.md                       # ← This file
```

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `fyne.io/fyne/v2` | Native GUI for Windows |
| `github.com/NordSecurity/gopenvpn` | OpenVPN management socket client |
| `github.com/shirou/gopsutil/v3/net` | Network interface byte counters (idle detection) |
| `golang.org/x/crypto/hkdf` | Key derivation for PFS |
| Go standard library | Everything else (`crypto/aes`, `crypto/ecdh`, `net/http`, etc.) |

---

## Building for Other Platforms

### Linux
```bash
go build -ldflags="-s -w" -o vpn-rotator .
sudo ./vpn-rotator
```

### Android (APK)
```bash
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init
ANDROID_HOME=$HOME/Android/Sdk gomobile build -target=android -o vpn-rotator.apk .
```
> Requires Android NDK + SDK installed. Uses ICS OpenVPN on device.

---

## License

This project is open-source and educational. VPN Gate is operated by the University of Tsukuba, Japan.

---

## Deep Dive

For the full technical architecture — encryption diagrams, threat models, code walkthroughs, and security analysis — see [ARCHITECTURE.md](./ARCHITECTURE.md).
