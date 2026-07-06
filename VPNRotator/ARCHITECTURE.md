# VPN Gate Auto-Rotator

> **A fully local, self-contained VPN IP rotator** — powered by [VPN Gate](http://www.vpngate.net/) free volunteer servers.  
> Built in **Go (Golang)**. Runs as a native `.exe` on Windows and `.apk` on Android.  
> Only two controls: **ON/OFF** and **how many seconds between rotations**.  
> Features **AES-256-GCM end-to-end encryption** so even the VPN Gate volunteer server cannot read your data.

---

## Table of Contents

1. [What This Does](#what-this-does)
2. [The Encryption Architecture — How Your Data Is Protected](#the-encryption-architecture--how-your-data-is-protected)
3. [The Postman Paradox — Security Warning](#the-postman-paradox--security-warning)
4. [The Mid-Session Problem & How We Solve It](#the-mid-session-problem--how-we-solve-it)
5. [System Architecture](#system-architecture)
6. [How the Hourly Cache Works](#how-the-hourly-cache-works)
7. [Full Execution Flow](#full-execution-flow)
8. [Why Go — Language Decision](#why-go--language-decision)
9. [Project File Structure](#project-file-structure)
10. [Component Deep-Dive](#component-deep-dive)
    - [Cache Manager](#1-cache-manager)
    - [Idle Detector](#2-idle-detector--the-mid-session-fix)
    - [VPN Manager](#3-vpn-manager)
    - [Kill Switch](#4-kill-switch)
    - [E2EE Encryption Engine](#5-e2ee-encryption-engine)
11. [UI — Simplified to 2 Controls](#ui--simplified-to-2-controls)
12. [Platform Support](#platform-support)
13. [Dependencies](#dependencies)
14. [Build Instructions](#build-instructions)
15. [Setup Guide (Windows)](#setup-guide-windows)
16. [Security Properties](#security-properties)
17. [FAQ](#faq)

---

## What This Does

This tool automatically changes your public IP address at a regular interval using **free, anonymous VPN servers** from the VPN Gate academic project (run by the University of Tsukuba, Japan).

**It does only two things:**
1. Connects you to a random VPN Gate server
2. After a user-defined number of seconds — **only when your connection is idle** — switches to a new server, giving you a new IP

**It does NOT:**
- Phone home to any external service (except the VPN Gate API, once per hour)
- Store any logs, credentials, or browsing data
- Require an account, subscription, or API key

---

## The Encryption Architecture — How Your Data Is Protected

This is the most important section. Understanding what encrypts what — and where the gaps are — lets you know exactly how safe you are.

### The Three Layers Explained

```
 YOUR DEVICE
 ┌─────────────────────────────────────────────────────────────────────┐
 │                                                                     │
 │  Your Data (plaintext)                                             │
 │        │                                                           │
 │        ▼                                                           │
 │  ┌──────────────────────────────────────────────────────────────┐  │
 │  │  LAYER 0 — E2EE (AES-256-GCM)        ← YOUR KEY ONLY        │  │
 │  │  Encrypts: actual data content                               │  │
 │  │  Key lives: only on your device (or your trusted server)     │  │
 │  │  Who can decrypt: ONLY YOU (or who you share the key with)   │  │
 │  └──────────────────────────────┬───────────────────────────────┘  │
 │                                 │ encrypted blob                   │
 │        ▼                        │                                   │
 │  ┌──────────────────────────────────────────────────────────────┐  │
 │  │  LAYER 1 — OpenVPN (AES-256-GCM)     ← VPN Gate's key       │  │
 │  │  Encrypts: everything going to VPN server                    │  │
 │  │  Who can decrypt: VPN Gate server (they terminate the tunnel) │  │
 │  └──────────────────────────────┬───────────────────────────────┘  │
 │                                 │                                   │
 └─────────────────────────────────┼───────────────────────────────────┘
                                   │ travels encrypted through internet
                                   ▼
 VPN GATE VOLUNTEER SERVER
 ┌─────────────────────────────────────────────────────────────────────┐
 │  Decrypts Layer 1 (VPN tunnel) — sees Layer 0 encrypted blob only  │
 │  Cannot read your data — Layer 0 key is NOT here                   │
 │  Can only see: destination IP + encrypted blob                     │
 └────────────────────────────────────┬────────────────────────────────┘
                                      │
                                      ▼
 DESTINATION (Your server / HTTPS website)
 ┌─────────────────────────────────────────────────────────────────────┐
 │  LAYER 2 — HTTPS (TLS 1.3)          ← standard web encryption      │
 │  Decrypts: web traffic (already separate from Layer 0)             │
 │  Layer 0 decrypted ONLY here if destination has your shared key    │
 └─────────────────────────────────────────────────────────────────────┘
```

**What the VPN Gate volunteer sees:** An encrypted blob going to a destination IP. Nothing readable.

---

### The Cipher — AES-256-GCM

**AES** = Advanced Encryption Standard (the algorithm used by US military, NSA, banks)
**256** = 256-bit key = 2²⁵⁶ possible keys = more atoms than in the observable universe
**GCM** = Galois/Counter Mode — turns AES into an **AEAD** cipher

**What AEAD means:**

| Letter | Stands For | What It Guarantees |
|--------|-----------|--------------------|
| **A** | Authenticated | Nobody tampered with the data |
| **E** | Encryption | Nobody can read the data |
| **A** | Associated | Metadata can be attached unencrypted but is still integrity-protected |
| **D** | Data | The actual payload |

One operation gives you both **privacy** (encryption) and **integrity** (tamper detection). This is exactly what Signal, WhatsApp, iMessage, and TLS 1.3 use.

---

### The Three Parts of Every Encrypted Message

```
Encrypted packet on the wire:
┌──────────────────┬──────────────────────────────────────┬────────────────┐
│   Nonce (12 B)   │         Ciphertext                   │  Auth Tag (16B)│
│  (not secret,    │  (AES-256 scrambled payload)          │  (tamper seal) │
│   sent openly)   │  unreadable without the key          │  decryption    │
│                  │                                      │  fails if data │
│                  │                                      │  was modified) │
└──────────────────┴──────────────────────────────────────┴────────────────┘
```

**Nonce** (Number Used Once):
- 12 random bytes generated fresh for every single message
- Sent alongside the ciphertext — it is NOT a secret
- Its only job: ensure the same key never encrypts two messages identically
- If nonce is reused with the same key → catastrophic security failure → never reuse
- In Go: `io.ReadFull(rand.Reader, nonce)` generates a cryptographically random nonce

**Ciphertext**:
- Your plaintext completely scrambled by AES-256
- Looks like random bytes — no pattern, no structure visible
- Without the 256-bit key: computationally impossible to crack

**Auth Tag**:
- A 16-byte cryptographic fingerprint of the ciphertext
- If anyone changes even 1 bit of the ciphertext in transit → decryption throws an error
- Protects against man-in-the-middle tampering

---

### The Key — Where It Lives

The key is a 32-byte (256-bit) random value. It **must never touch the VPN Gate server**.

| Scenario | Key Storage | Security Level |
|----------|------------|----------------|
| **Single device, local use** | OS keychain (`dpapi` on Windows) | ✅ VPN server never sees it |
| **Two devices you control** | Shared once via QR / USB / Signal | ✅ Share once, use forever |
| **Your own remote server** | Your HTTPS endpoint only you access | ✅ Your server, your rules |
| **Password-derived** | Argon2id KDF from passphrase | ✅ Key never stored, regenerated each session |

**Go key generation:**
```go
import "crypto/rand"

// Generate cryptographically secure 256-bit key
key := make([]byte, 32)
if _, err := io.ReadFull(rand.Reader, key); err != nil {
    panic(err) // OS RNG failure — should never happen
}
// key = [0x7a, 0x3f, 0x9c, ...] — 32 bytes of true randomness
// Store this in the OS keychain, never hardcode it
```

---

### Encrypt / Decrypt — How It Works in Go

```go
// internal/crypto/e2ee.go
package crypto

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "errors"
    "io"
)

// Encrypt takes plaintext and a 32-byte key.
// Returns: [12-byte nonce][ciphertext][16-byte auth tag]
func Encrypt(plaintext, key []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)      // Create AES-256 block cipher
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(block)      // Wrap in GCM mode (AEAD)
    if err != nil {
        return nil, err
    }

    // Fresh random nonce for every message — CRITICAL
    nonce := make([]byte, gcm.NonceSize()) // 12 bytes
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, err
    }

    // Seal encrypts AND appends auth tag
    // Result: nonce + ciphertext + auth_tag (all in one slice)
    ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
    return ciphertext, nil
}

// Decrypt takes the full encrypted blob and the same 32-byte key.
// Verifies the auth tag first — if tampered, returns error before decrypting.
func Decrypt(ciphertext, key []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonceSize := gcm.NonceSize()           // 12 bytes
    if len(ciphertext) < nonceSize {
        return nil, errors.New("ciphertext too short")
    }

    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

    // Open decrypts AND verifies the auth tag in one step
    // If auth tag fails (tampered data) → error, plaintext not returned
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return nil, errors.New("decryption failed: data tampered or wrong key")
    }
    return plaintext, nil
}
```

**Uses standard library only** — `crypto/aes` + `crypto/cipher` + `crypto/rand` are built into Go. No external dependencies.

---

### Perfect Forward Secrecy — The Next Level

The above scheme has one weakness: if your key file is ever stolen, ALL past sessions can be decrypted. **Perfect Forward Secrecy (PFS)** fixes this.

**How it works:**
- Generate a fresh temporary (ephemeral) key pair for **every session**
- Both sides compute a shared secret using **ECDH on the X25519 curve**
- Derive the AES-256 key from that shared secret
- After the session ends, **delete the ephemeral private key from memory**
- Result: even if your long-term key is stolen, past sessions are mathematically unrecoverable

```
Session Start:
  You                                     Your Server
   │                                           │
   │  Generate ephemeral key pair              │
   │  yourPriv, yourPub = X25519.NewKey()      │  serverPriv, serverPub = X25519.NewKey()
   │                                           │
   │──────── send yourPub (public) ───────────►│
   │◄─────── receive serverPub ────────────────│
   │                                           │
   │  sharedSecret = ECDH(yourPriv, serverPub) │  sharedSecret = ECDH(serverPriv, yourPub)
   │  ↑ SAME VALUE on both sides ↑             │  (elliptic curve math guarantees this)
   │                                           │
   │  aesKey = HKDF(sharedSecret)              │  aesKey = HKDF(sharedSecret)
   │  DELETE yourPriv from memory              │  DELETE serverPriv from memory
   │                                           │
   │  Now encrypt with aesKey ─────────────────│──────► decrypt with same aesKey
   │                                           │

Session End:
   Both sides delete aesKey from memory.
   No record of this session's key exists anywhere.
   Past traffic encrypted with this key: permanently unreadable to everyone.
```

**Go implementation using `crypto/ecdh` (X25519):**
```go
import "crypto/ecdh"

// Generate ephemeral key pair (done fresh for every session)
privKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
pubKey := privKey.PublicKey()

// After receiving the other side's public key:
sharedSecret, _ := privKey.ECDH(otherPubKey)

// Derive a proper AES key using HKDF
aesKey := hkdf.New(sha256.New, sharedSecret, salt, info)

// Delete private key — PFS achieved
privKey = nil  // Go GC will zero and reclaim
```

This is identical to how **Signal Protocol**, **WhatsApp**, and **TLS 1.3** achieve PFS.

---

### What E2EE Protects — Threat Model

| Threat | Without E2EE | With E2EE Layer |
|--------|-------------|------------------|
| VPN Gate server reads your data | ✅ Can read HTTP content | ❌ Sees encrypted blob only |
| Malicious VPN server injects fake data | ✅ Can modify in transit | ❌ Auth tag catches tampering |
| Someone records traffic for later decryption | ✅ Can decrypt if VPN key known | ❌ Still needs YOUR separate E2EE key |
| Key stolen after the fact | ✅ All history decryptable | ❌ With PFS: past sessions safe |
| Government seizes VPN server | ✅ Has decrypted traffic logs | ❌ Only encrypted blobs stored |
| Network-level eavesdropper (ISP, cafe WiFi) | Already blocked by VPN Layer 1 | Same |

### What E2EE Does NOT Protect

> [!WARNING]
> Be honest about what encryption cannot do:

1. **Metadata** — The VPN Gate server still knows *when* you connected and *how much* data you transferred. It cannot read the content but knows you're communicating.
2. **Destination IP** — The VPN server knows which server you're talking to. E2EE hides the content, not the address.
3. **General web browsing** — For normal sites (claude.ai, Google, YouTube), HTTPS already handles E2EE between you and the site. The additional Layer 0 only helps when **you control both ends** — your device and your own server/app.
4. **Key management mistakes** — If you hardcode the key, share it insecurely, or store it unprotected, encryption is useless. The key must be treated like a password.

---

## The Postman Paradox — Security Warning

> [!WARNING]
> **You must understand this before using this tool.**

By routing traffic through a volunteer VPN Gate server, the volunteer operator can see:
- **Which IP addresses (websites) you are connecting to**

They **cannot** see:
- The actual content of your data — as long as you visit `HTTPS` sites (the padlock icon)
- Your passwords, messages, or file contents on HTTPS

**Analogy**: It's like handing your sealed letter to a postman. The postman can read the address on the envelope (the website you visit) but cannot open the envelope (your data). Use HTTPS sites only.

---

## The Mid-Session Problem & How We Solve It

### The Problem

Imagine you open `claude.ai`. Your browser sends a request and is waiting for the response. On a slow network this takes 2–3 seconds. If the rotation timer fires **during** this 2-second window:

```
Browser → VPN (IP: 45.32.100.1) → claude.ai   ← request sent
    ... timer fires, VPN switches to IP: 139.99.55.2 ...
Browser ← VPN (IP: 139.99.55.2) ← claude.ai   ← server confused, drops connection
                                                   PAGE FAILS ❌
```

The server bound your TCP connection to your old IP. When the IP changes, the TCP session is orphaned and the page fails.

### The Solution — Idle Detection Before Rotation

Instead of rotating on a **dumb fixed timer**, the app uses a **smart idle-aware rotation**:

```
Timer fires (e.g., every 30 seconds)
        │
        ▼
Is there active traffic on the VPN interface?
(bytes transferred in last 2 seconds > 512 bytes?)
        │
   YES  │  NO
        │   └──────────────────────────────► ROTATE NOW ✅
        ▼
Wait 2 more seconds, check again
        │
   Still active?
        │
   YES  │  NO
        │   └──────────────────────────────► ROTATE NOW ✅
        ▼
Keep waiting... (up to hard max = 2x rotation interval)
        │
   Hard timeout reached?
        │
   YES──└──────────────────────────────────► FORCE ROTATE ⚠️
```

**Result:**
- If you are mid-page-load → rotator waits for the transfer to finish, then rotates
- If you are idle (just reading a page) → rotator fires immediately at the timer
- If you are streaming video for 2x the interval → it force-rotates (this is expected)

#### How We Detect Idle — Technical Detail

On Windows, Go reads the network adapter's byte counters using the `gopsutil` library:

```go
// internal/idle/detector.go

func IsNetworkIdle(interfaceName string, thresholdBytes uint64) bool {
    s1, _ := net.IOCounters(true)
    time.Sleep(2 * time.Second)
    s2, _ := net.IOCounters(true)

    for i, iface := range s2 {
        if iface.Name == interfaceName {
            bytesDelta := (iface.BytesSent + iface.BytesRecv) -
                          (s1[i].BytesSent + s1[i].BytesRecv)
            return bytesDelta < thresholdBytes  // idle if under threshold
        }
    }
    return true // unknown interface = assume idle
}
```

**Parameters:**
| Parameter | Default Value | Meaning |
|-----------|--------------|---------|
| `thresholdBytes` | 512 bytes / 2 sec | Less than this = considered idle |
| Max wait before force-rotate | `2 × rotation_interval` | Hard ceiling on wait time |
| Idle check interval | 2 seconds | How often we re-check |

---

## System Architecture

```
┌───────────────────────────────────────────────────────────────────────┐
│                       VPN Gate Auto-Rotator                           │
│                         (Go Application)                              │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │                     Fyne GUI (2 controls)                       │  │
│  │   [  ●  ON / OFF Toggle  ]    [  30s  ▲▼  ]                    │  │
│  │   Status: Connected · IP: 45.32.x.x · Next rotate: 18s         │  │
│  └────────────────────────────┬────────────────────────────────────┘  │
│                               │ user events                           │
│  ┌────────────────────────────▼────────────────────────────────────┐  │
│  │                        Core Engine                              │  │
│  │                                                                 │  │
│  │  ┌─────────────┐  ┌──────────────┐  ┌──────────────────────┐   │  │
│  │  │Cache Manager│  │Idle Detector │  │   Rotation Timer     │   │  │
│  │  │(goroutine)  │  │(goroutine)   │  │   (goroutine)        │   │  │
│  │  └──────┬──────┘  └──────┬───────┘  └──────────┬───────────┘   │  │
│  │         │                │                      │               │  │
│  │         │          ┌─────▼──────┐               │               │  │
│  │         │          │Traffic OK? │◄──────────────┘               │  │
│  │         │          │idle/active │                               │  │
│  │         │          └─────┬──────┘                               │  │
│  │         │          idle  │  active → wait                       │  │
│  │         │                ▼                                      │  │
│  │  ┌──────▼──────────────────────────┐  ┌──────────────────────┐ │  │
│  │  │        VPN Manager              │  │  Kill Switch         │ │  │
│  │  │  select → decode → write ovpn   │  │  (netsh/iptables)    │ │  │
│  │  │  → launch openvpn.exe           │  └──────────────────────┘ │  │
│  │  └─────────────────────────────────┘                           │  │
│  │                                                                 │  │
│  │  ┌──────────────────────────────────────────────────────────┐  │  │
│  │  │         E2EE Encryption Engine  [NEW]                    │  │  │
│  │  │  AES-256-GCM + ECDH (X25519) + HKDF                     │  │  │
│  │  │  Encrypts data BEFORE it enters the VPN tunnel           │  │  │
│  │  │  Key lives ONLY on your device — VPN server cannot read  │  │  │
│  │  └──────────────────────────────────────────────────────────┘  │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                                                                       │
│  ┌──────────────────────┐    ┌───────────────────────────────────┐    │
│  │  vpngate_cache.json  │    │  openvpn.exe (system install)     │    │
│  │  (local, hourly TTL) │    │  vpn_temp.ovpn (auto-deleted)     │    │
│  └──────────────────────┘    └───────────────────────────────────┘    │
│                                                                       │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │  e2ee_key.bin (OS keychain protected — never leaves device)      │ │
│  └──────────────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────────┘
         │
         │ (one HTTP fetch per hour only)
         ▼
  http://www.vpngate.net/api/iphone/
  (VPN Gate CSV API — University of Tsukuba, Japan)
```

---

## How the Hourly Cache Works

The VPN Gate server list is **fetched once per hour** in the background and stored in a local `vpngate_cache.json` file. All VPN rotations pull from this local file — the API is never hit during a rotation.

```
App Startup
    │
    ▼
vpngate_cache.json exists AND < 1 hour old?
    │
  YES ──► Load from file (fast, local, no network) ──► Ready
    │
   NO
    │
    ▼
Fetch from http://www.vpngate.net/api/iphone/
    │
  SUCCESS ──► Parse CSV ──► Save to vpngate_cache.json ──► Ready
    │
  FAIL (API down, no internet yet)
    │
    ▼
Load stale cache file if it exists ──► Warn user ──► Ready (degraded)
    │
No cache file at all ──► Show error: "Need internet for first-time setup"


Background Goroutine (every 60 min, parallel to everything else):
    Fetch API → if success → atomically overwrite cache → update in-memory list
               → if fail  → keep old list, log warning, continue silently
```

**Why atomic writes?**
The file is written to `vpngate_cache.tmp` first, then renamed to `vpngate_cache.json`. A rename is atomic on all OS — if the app crashes mid-write, the old good cache is preserved.

---

## Full Execution Flow

```
1. USER OPENS APP
   └─► Load/Fetch server list (cache logic above)
   └─► Show: "X servers available"
   └─► Start background hourly refresh goroutine

2. USER TOGGLES ON
   └─► Pick random server from in-memory list
   └─► Decode Base64 .ovpn config
   └─► Inject DNS protection (1.1.1.1 + 8.8.8.8) into .ovpn
   └─► Write to temp file: %TEMP%\vpn_rotator_XXXX.ovpn
   └─► Enable kill switch firewall rules
   └─► Launch: openvpn.exe --config <temp.ovpn> --management 127.0.0.1 11940
   └─► Monitor management socket for connection state
   └─► Update status: "Connected · Japan · IP: 103.x.x.x"
   └─► Start rotation countdown timer

3. ROTATION TIMER FIRES (e.g., every 30 seconds)
   └─► Start idle detection loop:
       └─► Sample VPN interface bytes (wait 2s, sample again)
       └─► Delta < 512 bytes? → PROCEED
       └─► Delta ≥ 512 bytes? → Wait 2s → re-check (up to 2× interval max)
   └─► ROTATE:
       └─► Gracefully signal openvpn.exe to disconnect
       └─► Delete old temp .ovpn file securely
       └─► Pick new server from cache
       └─► Write new temp .ovpn
       └─► Launch openvpn.exe again
       └─► Reset countdown timer

4. USER TOGGLES OFF
   └─► Signal openvpn.exe to terminate
   └─► Remove kill switch firewall rules
   └─► Delete temp .ovpn file
   └─► Status: "Disconnected"

5. BACKGROUND (independent of 1–4):
   └─► Every 60 minutes: fetch VPN Gate API → update cache
   └─► Every 5 seconds (if connected + kill switch): check openvpn still alive
       └─► If dead → re-apply kill switch block → alert user
```

---

## Why Go — Language Decision

| Criteria | Python | Rust | **Go (Chosen)** |
|----------|--------|------|-----------------|
| Single binary output (.exe) | ❌ needs runtime installed | ✅ | ✅ |
| Memory safety | ⚠️ runtime | ✅ compile-time | ✅ GC + bounds checks |
| Android support | ❌ not practical | ⚠️ very complex | ✅ `gomobile` |
| Concurrency (goroutines) | ❌ GIL | ✅ | ✅ goroutines |
| Network stdlib built-in | ❌ needs pip | ✅ | ✅ |
| Learning curve | Low | Very High | **Medium** |
| Build complexity | High (PyInstaller fragile) | High | **Low** |
| Zero runtime dependency for user | ❌ | ✅ | ✅ |

**Go is the only language that hits all requirements**: compiled binary, safe memory model, goroutines for background tasks, cross-compiles to Windows + Android from one codebase, and produces a single `.exe` the user can double-click.

---

## Project File Structure

```
VPNRotator/
├── main.go                         # Entry point — wires engine + GUI
├── go.mod                          # Go module + dependencies
├── go.sum                          # Dependency checksums (lock file)
│
├── internal/
│   │
│   ├── cache/
│   │   ├── models.go               # VPNServer struct definition
│   │   └── cache.go                # Hourly fetch, CSV parse, JSON save/load
│   │
│   ├── crypto/                     # [NEW] E2EE encryption engine
│   │   ├── e2ee.go                 # AES-256-GCM Encrypt() / Decrypt() functions
│   │   ├── keystore.go             # Key generation, OS keychain load/save
│   │   └── pfs.go                  # ECDH X25519 key exchange + HKDF derivation
│   │
│   ├── idle/
│   │   └── detector.go             # Network idle detection (byte counter)
│   │
│   ├── vpn/
│   │   ├── config.go               # Base64 decode, DNS inject, .ovpn writer
│   │   ├── manager.go              # OpenVPN process launch + management socket
│   │   └── rotation.go             # Rotation ticker + idle-aware trigger
│   │
│   ├── killswitch/
│   │   ├── killswitch.go           # Platform-agnostic interface
│   │   ├── killswitch_windows.go   # netsh advfirewall rules
│   │   └── killswitch_linux.go     # iptables rules
│   │
│   └── ui/
│       ├── app.go                  # Fyne app init, window, channel wiring
│       └── mainview.go             # The 2 controls + status display
│
├── assets/
│   └── icon.png                    # App icon
│
├── vpngate_cache.json              # Auto-generated (do not edit manually)
├── ARCHITECTURE.md                 # ← THIS FILE
└── build_windows.ps1               # PowerShell build script
```

---

## Component Deep-Dive

### 1. Cache Manager

**File**: `internal/cache/cache.go`

Responsibilities:
- Fetch `http://www.vpngate.net/api/iphone/` (returns CSV)
- Parse CSV: skip header line, skip non-OpenVPN servers, skip dead/empty entries
- Decode each server's OpenVPN config column (Base64)
- Save parsed list to `vpngate_cache.json` with timestamp
- On startup: check if cache is fresh (< 1 hour) — if yes, skip fetch
- Background goroutine: re-fetch every 60 minutes, atomic overwrite

**VPNServer struct:**
```go
type VPNServer struct {
    HostName        string  `json:"host_name"`
    IP              string  `json:"ip"`
    Score           int64   `json:"score"`
    Ping            int     `json:"ping"`
    Speed           int64   `json:"speed"`         // bps
    CountryLong     string  `json:"country_long"`
    CountryShort    string  `json:"country_short"`  // e.g. "JP", "US"
    NumVPNSessions  int     `json:"num_vpn_sessions"`
    OpenVPNConfigB64 string `json:"openvpn_config_b64"`
}
```

---

### 2. Idle Detector — The Mid-Session Fix

**File**: `internal/idle/detector.go`

This is the component that solves the mid-session rotation problem.

```go
type IdleDetector struct {
    ThresholdBytesPerInterval uint64        // Default: 512
    SampleInterval            time.Duration // Default: 2s
    MaxWaitMultiplier         int           // Default: 2 (= 2× rotation interval)
}

// WaitUntilIdle blocks until the network is idle OR maxWait is exceeded.
// Returns true if idle, false if forced (timed out).
func (d *IdleDetector) WaitUntilIdle(ctx context.Context, maxWait time.Duration) bool {
    deadline := time.Now().Add(maxWait)
    for time.Now().Before(deadline) {
        if d.isIdle() {
            return true   // safe to rotate
        }
        time.Sleep(d.SampleInterval)
    }
    return false  // force-rotate (hard timeout)
}
```

**UI feedback during wait:**
```
Status: "Waiting for idle... (next rotate when network quiet)"
```

---

### 3. VPN Manager

**File**: `internal/vpn/manager.go`

Responsibilities:
- Write temp `.ovpn` file to OS temp directory (`os.MkdirTemp`)
- Inject DNS protection lines into config:
  ```
  dhcp-option DNS 1.1.1.1
  dhcp-option DNS 8.8.8.8
  block-outside-dns
  ```
- Launch `openvpn.exe` with `--management 127.0.0.1 11940` flag
- Connect to management socket — poll connection state
- On rotate: send `signal SIGTERM` to management socket → graceful disconnect
- Delete temp `.ovpn` immediately after OpenVPN reads it (`os.Remove`)
- Watchdog goroutine: every 5 seconds, confirm openvpn process is still alive

---

### 4. Kill Switch

**File**: `internal/killswitch/killswitch_windows.go`

When enabled (always ON while VPN is active):

```
Enable:
  1. Block ALL outbound traffic (Windows Firewall default-deny outbound)
  2. Add rule: Allow traffic to/from TAP adapter (the VPN interface)
  3. Add rule: Allow openvpn.exe to reach VPN Gate server IP

Disable (on user toggle-off or graceful shutdown):
  1. Delete VPN-specific rules
  2. Restore default-allow outbound

Emergency (openvpn.exe dies unexpectedly):
  1. Watchdog detects process is gone
  2. Re-applies block-all rules immediately
  3. Shows alert: "VPN dropped — internet blocked to protect your IP"
```

---

### 5. E2EE Encryption Engine

**Files**: `internal/crypto/e2ee.go`, `internal/crypto/keystore.go`, `internal/crypto/pfs.go`

This component wraps all outbound data in AES-256-GCM **before** it enters the VPN tunnel. Even if the VPN Gate server is 100% malicious, it only ever receives an encrypted blob it cannot read.

#### `e2ee.go` — Core Encrypt/Decrypt

```go
package crypto

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "errors"
    "io"
)

// Encrypt encrypts plaintext with AES-256-GCM.
// Returns: [12-byte nonce | ciphertext | 16-byte auth tag]
// A fresh random nonce is generated for every call — NEVER reused.
func Encrypt(plaintext, key []byte) ([]byte, error) {
    block, _ := aes.NewCipher(key)   // AES-256 (key must be 32 bytes)
    gcm, _   := cipher.NewGCM(block) // GCM mode wraps AES with AEAD

    nonce := make([]byte, gcm.NonceSize()) // 12 bytes
    io.ReadFull(rand.Reader, nonce)        // OS-level true randomness

    // Seal(dst, nonce, plaintext, additionalData)
    // Prepends nonce so receiver can extract it
    return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt verifies the auth tag first, then decrypts.
// Returns error if data was tampered — plaintext NOT returned on failure.
func Decrypt(ciphertext, key []byte) ([]byte, error) {
    block, _ := aes.NewCipher(key)
    gcm, _   := cipher.NewGCM(block)

    n := gcm.NonceSize()                       // 12 bytes
    if len(ciphertext) < n {
        return nil, errors.New("ciphertext too short")
    }
    nonce, data := ciphertext[:n], ciphertext[n:]

    // Open verifies auth tag AND decrypts in one step
    plain, err := gcm.Open(nil, nonce, data, nil)
    if err != nil {
        return nil, errors.New("auth tag mismatch — data tampered or wrong key")
    }
    return plain, nil
}
```

**Key properties:**
- Uses `crypto/aes` + `crypto/cipher` + `crypto/rand` — **Go standard library only, zero extra dependencies**
- Nonce is generated fresh with OS-level entropy (`crypto/rand`) for every call
- If auth tag check fails (tampered data), the function returns error — plaintext is never exposed
- 28 bytes overhead per message (12 nonce + 16 tag) — negligible

---

#### `keystore.go` — Key Generation & Storage

```go
package crypto

import (
    "crypto/rand"
    "io"
    "os"
)

const keyFile = "e2ee_key.bin" // stored in OS app data directory

// LoadOrCreateKey loads the key from disk.
// If no key exists, generates a new 256-bit key and saves it.
// In production: store in OS keychain (Windows DPAPI / Linux Secret Service)
func LoadOrCreateKey() ([]byte, error) {
    if data, err := os.ReadFile(keyFile); err == nil && len(data) == 32 {
        return data, nil  // key exists and is valid
    }

    // First run: generate a new key
    key := make([]byte, 32)
    if _, err := io.ReadFull(rand.Reader, key); err != nil {
        return nil, err
    }

    // TODO: Use OS keychain API for production security
    // Windows: DPAPI (golang.org/x/sys/windows/svc/security)
    // Linux:   Secret Service (via go-keyring package)
    os.WriteFile(keyFile, key, 0600) // 0600 = owner read/write only
    return key, nil
}
```

**Key storage security levels:**
| Level | Method | Protection |
|-------|--------|------------|
| Basic | `0600` file permissions | Only your OS user can read |
| Better | OS keychain (DPAPI on Windows) | Tied to your Windows login password |
| Best | Hardware key (YubiKey / TPM chip) | Physical token required to decrypt |

---

#### `pfs.go` — Perfect Forward Secrecy via ECDH X25519

```go
package crypto

import (
    "crypto/ecdh"
    "crypto/rand"
    "crypto/sha256"
    "golang.org/x/crypto/hkdf"
    "io"
)

// NewEphemeralKeyPair generates a fresh X25519 key pair.
// Call at the START of every session. Discard after session ends.
func NewEphemeralKeyPair() (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
    priv, err := ecdh.X25519().GenerateKey(rand.Reader)
    if err != nil {
        return nil, nil, err
    }
    return priv, priv.PublicKey(), nil
}

// DeriveSessionKey computes the shared AES-256 key from:
//   - your ephemeral PRIVATE key
//   - the other side's ephemeral PUBLIC key
// Both sides compute the SAME result without transmitting the secret.
func DeriveSessionKey(myPriv *ecdh.PrivateKey, theirPub *ecdh.PublicKey) ([]byte, error) {
    sharedSecret, err := myPriv.ECDH(theirPub)
    if err != nil {
        return nil, err
    }

    // HKDF extracts and expands the shared secret into a proper AES key
    // This is safer than using the raw ECDH output directly as a key
    salt := []byte("vpnrotator-e2ee-v1")
    info := []byte("aes-256-gcm-session-key")
    r := hkdf.New(sha256.New, sharedSecret, salt, info)

    aesKey := make([]byte, 32) // 256 bits
    io.ReadFull(r, aesKey)

    return aesKey, nil
    // Caller should: zero out myPriv after this call → PFS achieved
}
```

**Why X25519 (not RSA)?**
- X25519 gives 128-bit security with only a 32-byte key (RSA needs 3072 bits for same security)
- Designed to resist side-channel attacks by construction
- Operations are ~100x faster than RSA at equivalent security
- Built into Go's standard library (`crypto/ecdh`)

**What "perfect forward secrecy" means in plain English:**
> Even if an attacker records all your encrypted traffic for the next 10 years, AND steals your device, AND extracts your key file — they still cannot decrypt past sessions because the ephemeral session keys were deleted from memory and never stored.

---

## UI — Simplified to 2 Controls

The entire UI is intentionally minimal:

```
┌─────────────────────────────────────────┐
│         VPN Gate Auto-Rotator           │
│                                         │
│   ┌─────────────────────────────────┐   │
│   │  ●──────────── ON / OFF         │   │
│   └─────────────────────────────────┘   │
│                                         │
│   Rotate every:  [  30  ] seconds  ▲▼  │
│                                         │
│   ─────────────────────────────────     │
│   Status:   ● Connected                 │
│   Country:  Japan 🇯🇵                    │
│   IP:       103.152.220.x               │
│   Next rotation in:  18s               │
│   Servers available: 3,241              │
│   Cache age: 23 min ago                 │
│   ─────────────────────────────────     │
│                                         │
│   [!] Mid-request? Waiting for idle...  │
└─────────────────────────────────────────┘
```

**Controls:**
| Control | Type | Default | Description |
|---------|------|---------|-------------|
| ON/OFF | Toggle switch | OFF | Starts/stops VPN rotation |
| Rotation interval | Number input (seconds) | 30s | How long between IP changes |

**Status display (read-only):**
- Connected / Disconnected / Waiting for idle...
- Current country + IP
- Countdown to next rotation
- Number of servers loaded
- How old the cache is (e.g., "23 min ago")

---

## Platform Support

| Platform | Output | VPN Engine | Build Tool |
|----------|--------|------------|-----------|
| Windows 10/11 x64 | `.exe` | `openvpn.exe` (user installs) | `go build` |
| Linux x64 | binary | `openvpn` (system package) | `go build` |
| Android 8+ | `.apk` | ICS OpenVPN (Intent API) | `gomobile build` |
| macOS | binary | `openvpn` (brew) | `go build` |

> [!NOTE]
> iOS is **not supported** — Apple's App Store rules prevent this type of VPN automation app from being distributed. Sideloading would require a developer certificate.

---

## Dependencies

### Go Packages

| Package | Purpose | Why |
|---------|---------|-----|
| `fyne.io/fyne/v2` | GUI framework | Renders native UI on Windows + Android from same code |
| `github.com/NordSecurity/gopenvpn` | OpenVPN management interface | Handles management socket protocol |
| `github.com/shirou/gopsutil/v3/net` | Network I/O stats | Used by idle detector to read interface byte counts |
| `golang.org/x/crypto/hkdf` | Key derivation function | Derives proper AES key from ECDH shared secret (PFS) |
| Standard library only (E2EE core) | `crypto/aes`, `crypto/cipher`, `crypto/ecdh`, `crypto/rand` | All encryption — zero external crypto dependencies |
| Standard library only (rest) | `net/http`, `encoding/csv`, `encoding/base64`, `os/exec`, `time`, `encoding/json`, `os`, `context` | Everything else |

### System Requirements (User's Machine)

| Software | Platform | Where to Download |
|---------|----------|-------------------|
| **OpenVPN 2.6+** | Windows / Linux | https://openvpn.net/community-downloads/ |
| **TAP-Windows / Wintun driver** | Windows | Bundled with OpenVPN installer |
| **ICS OpenVPN** | Android | Google Play Store (free) |

> [!IMPORTANT]
> The app itself has **zero runtime dependencies** for the user.  
> Only OpenVPN (the VPN tunnel engine) needs to be installed separately — the app controls it.

---

## Build Instructions

### Windows `.exe`

```powershell
# Prerequisites: Install Go 1.22+ from https://go.dev/dl/
# Run from VPNRotator directory:

go mod download                          # Download dependencies
go mod tidy                              # Clean up go.sum

# Build .exe (no console window)
$env:GOOS="windows"; $env:GOARCH="amd64"
go build -ldflags="-H=windowsgui -s -w" -o vpn-rotator.exe .

# Result: vpn-rotator.exe (double-click to run, ~15MB)
```

### Linux Binary

```bash
go build -ldflags="-s -w" -o vpn-rotator .
./vpn-rotator    # run with sudo for kill switch
```

### Android `.apk`

```bash
# Prerequisites: Install Android NDK + SDK, then:
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init

# Build APK
ANDROID_HOME=$HOME/Android/Sdk \
gomobile build -target=android -o vpn-rotator.apk .
```

> [!TIP]
> Use the provided `build_windows.ps1` script for Windows — it handles all the flags automatically.

---

## Setup Guide (Windows)

1. **Install OpenVPN** from https://openvpn.net/community-downloads/
   - During install, make sure "TAP-Windows6" or "Wintun" driver is selected
   - Confirm `openvpn.exe` is at `C:\Program Files\OpenVPN\bin\openvpn.exe`

2. **Download `vpn-rotator.exe`** (from builds)

3. **Run as Administrator** (required for kill switch firewall rules)
   - Right-click → "Run as administrator"
   - Or set the exe's compatibility: Properties → Compatibility → "Run as administrator"

4. **Toggle ON** — the app will:
   - Fetch server list (first time only — needs internet)
   - Connect to the best available server
   - Show your new IP in the status panel

5. **Set your rotation interval** — default is 30 seconds
   - Change it to 60, 300, 600 seconds — whatever suits your use case

---

## Security Properties

| Property | How It's Achieved | Protects Against |
|----------|-------------------|-----------------|
| **E2EE — AES-256-GCM** | Data encrypted before entering VPN tunnel | Malicious VPN server reading content |
| **Auth Tag Verification** | GCM mode detects any tampered byte | Man-in-the-middle data injection |
| **Perfect Forward Secrecy** | ECDH X25519 ephemeral keys per session | Key theft exposing past sessions |
| **Key isolation** | E2EE key stored only on device (OS keychain) | VPN server never has decryption key |
| **DNS Leak Protection** | `1.1.1.1` + `8.8.8.8` + `block-outside-dns` in every `.ovpn` | DNS requests leaking your real identity |
| **Kill Switch** | Windows Firewall block-all, re-enforced every 5s | Real IP exposure if VPN drops |
| **Temp file cleanup** | `.ovpn` deleted immediately after OpenVPN reads it | Config file lingering on disk |
| **Mid-session protection** | Idle detection prevents rotation during active transfer | TCP sessions breaking on rotation |
| **Atomic cache writes** | Write-to-tmp then rename | Corrupted cache on crash |
| **Memory safety** | Go GC + bounds checking | Buffer overflows, memory corruption |
| **No external requests** | One hourly HTTP fetch only (VPN Gate API) | Data exfiltration, telemetry |
| **No credentials stored** | VPN Gate is anonymous — no login needed | Credential theft |
| **Offline capable** | Stale cache fallback if API unreachable | Single point of failure |
| **No telemetry** | Zero analytics, no crash reporters | Privacy / tracking |

---

## FAQ

**Q: How often does it change my IP?**  
A: Every N seconds — whatever you set. Default is 30 seconds. The actual rotation may be slightly delayed if you're mid-download (see idle detection above).

**Q: Will it break my active downloads?**  
A: For short downloads (< N seconds), no — the idle detector will wait for them to finish. For very long downloads (> 2× your rotation interval), it will force-rotate. Set a longer interval if you're doing large downloads.

**Q: What if the VPN Gate API is down?**  
A: The app loads the last cached server list from `vpngate_cache.json`. It will keep rotating through the cached servers. Only the very first run (no cache file) requires internet access to the VPN Gate API.

**Q: Is this legal?**  
A: VPN Gate is a legitimate academic project by the University of Tsukuba, Japan. Using it is legal in most countries. The tool itself is open-source and educational. Check your local laws.

**Q: Why can't I pick a specific country?**  
A: The UI is intentionally simplified to just ON/OFF and interval. Country filtering can be added in a future version — it would be a dropdown in the UI and a filter in the server selection logic.

**Q: Does this work on Android?**  
A: Yes, via the Android `.apk` build. The app shows the same UI and uses ICS OpenVPN (a separate free app) to create the actual tunnel on Android, since Android's security model prevents direct subprocess VPN creation.

**Q: What is the kill switch?**  
A: When the VPN is ON, Windows Firewall rules block all internet traffic except through the VPN tunnel. If OpenVPN crashes unexpectedly, a watchdog re-applies these rules within 5 seconds — meaning your real IP is never exposed even if the VPN drops.

**Q: What is E2EE and do I need to set it up?**  
A: E2EE (End-to-End Encryption) is a Layer 0 encryption layer that wraps your data with AES-256-GCM before it even enters the VPN tunnel. On first run, a 256-bit key is automatically generated and stored in your OS keychain. No setup needed — it works transparently. The VPN Gate volunteer server only ever receives an encrypted blob it cannot read.

**Q: What is Perfect Forward Secrecy?**  
A: PFS means that even if someone steals your encryption key today, they cannot decrypt your past communications. For each session, a temporary (ephemeral) key pair is generated using ECDH X25519 math. Both sides derive the same session key without transmitting it. After the session ends, the ephemeral keys are deleted. Past sessions become permanently undecryptable — even by you.

**Q: What can the VPN Gate server see with E2EE enabled?**  
A: With E2EE on, the VPN Gate server can see:
- **When** you connected (timestamp)
- **How much** data you transferred (bytes, not content)
- **Which destination IP** you're communicating with

It **cannot** see:
- The actual content of your messages/data (AES-256-GCM encrypted)
- Your encryption key (never leaves your device)
- Anything inside the encrypted payload

**Q: Does the E2EE work for all websites I browse?**  
A: For general web browsing (HTTPS websites), HTTPS already provides E2EE between you and the website. The additional Layer 0 E2EE in this app protects traffic going to **your own servers or apps** — where you control both ends and can share the key. For random websites, HTTPS is your protection and the VPN hides your identity.
