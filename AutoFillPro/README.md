<div align="center">

# ⚡ AutoFill Pro

**A Smart, Secure Browser Extension for Instant Form Filling**

[![Manifest V3](https://img.shields.io/badge/Manifest-V3-blue?style=for-the-badge&logo=googlechrome)](https://developer.chrome.com/docs/extensions/mv3/)
[![Version](https://img.shields.io/badge/Version-1.0.0-brightgreen?style=for-the-badge)]()
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)]()

</div>

---

## 📌 What Is AutoFill Pro?

**AutoFill Pro** is a Chrome/Chromium browser extension built with **Manifest V3** that lets you store multiple personal profiles and fill any web form instantly with a single click — or right from the context menu.

No cloud sync. No data leaving your machine. Your profiles are stored locally using the browser's secure `chrome.storage.local` API.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🗂️ **Multiple Profiles** | Save and switch between multiple fill profiles (Personal, Work, etc.) |
| ⚡ **One-Click Fill** | Fill an entire page's form fields instantly from the popup |
| 🖱️ **Context Menu** | Right-click any page and choose *AutoFill Pro — Fill this page* |
| 🔒 **100% Local** | All data stored securely via `chrome.storage.local` — never sent anywhere |
| ✏️ **Options Page** | Full-featured settings page to manage, edit, and delete profiles |
| 🎯 **Smart Field Detection** | Auto-detects name, email, phone, address, and more |

---

## 📁 Project Structure

```
AutoFillPro/
│
├── manifest.json               # Extension manifest (Manifest V3)
├── icons/                      # Extension icons (16px, 32px, 48px, 128px)
│
├── background/
│   └── background.js           # Service worker — handles context menu & messaging
│
├── content/
│   └── content.js              # Content script — injected into pages to fill forms
│
├── popup/
│   ├── popup.html              # Extension popup UI
│   ├── popup.css               # Popup styling
│   └── popup.js                # Popup logic — profile selection & fill trigger
│
└── options/
    ├── options.html            # Full settings/options page
    ├── options.css             # Options page styling
    └── options.js              # Options page logic — CRUD for profiles
```

---

## 🚀 Installation (Developer Mode)

1. Open **Google Chrome** and navigate to `chrome://extensions/`
2. Toggle **Developer mode** on (top-right)
3. Click **Load unpacked**
4. Select the `AutoFillPro/` folder
5. The extension is now active — click the puzzle icon in your toolbar to pin it

---

## 🛠️ How It Works

1. **Create a Profile** via the Options page with your details (name, email, phone, address, etc.)
2. **Click the extension popup** on any webpage and select your profile
3. Hit **Fill Page** — the content script scans all form fields and maps your profile data intelligently
4. Alternatively, **right-click** anywhere on the page and select *⚡ AutoFill Pro — Fill this page*

---

## 🔐 Security & Privacy

- Built with **Manifest V3** (the latest Chrome extension standard) for maximum security
- **No external network requests** — the extension is fully offline
- Profile data is scoped to `chrome.storage.local` and never accessible outside the extension

---

<div align="center">
  <i>Built for speed, security, and seamless productivity.</i>
</div>
