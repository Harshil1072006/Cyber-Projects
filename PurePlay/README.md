<div align="center">

# 🎵 PurePlay

**A Browser Extension That Automatically Mutes Profanity in Videos**

[![Manifest V3](https://img.shields.io/badge/Manifest-V3-blue?style=for-the-badge&logo=googlechrome)]()
[![Version](https://img.shields.io/badge/Version-1.0.0-brightgreen?style=for-the-badge)]()
[![Platforms](https://img.shields.io/badge/Works_On-YouTube%20%7C%20Netflix%20%7C%20Prime%20%7C%20Disney+-orange?style=for-the-badge)]()

</div>

---

## 📌 What Is PurePlay?

**PurePlay** is a Chrome/Chromium browser extension that automatically **mutes offensive words and profanity** in any video — silently and in real-time, without interrupting your viewing experience.

It works by monitoring video audio captions and transcripts, detecting offensive language from a customizable word list, and muting the video playback for the exact duration of the flagged word.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔇 **Auto-Mute** | Automatically mutes video audio when profanity is detected |
| 🎯 **Multi-Platform** | Works on YouTube, Netflix, Prime Video, Disney+, Hulu, Hotstar, HBO Max, and more |
| 📋 **Custom Word List** | Fully customizable list of blocked words via the shared profanity list |
| ⚡ **Real-Time Detection** | Sub-second response time using subtitle/caption analysis |
| 🔒 **100% Private** | No data sent anywhere — all processing is done locally in your browser |
| 🧩 **Manifest V3** | Built with the latest Chrome extension security standard |

---

## 📁 Project Structure

```
PurePlay/
│
├── browser-extension/           # Core Chrome extension
│   ├── manifest.json            # Extension manifest (Manifest V3)
│   ├── background.js            # Service worker
│   ├── content.js               # Injected content script — detects & mutes
│   ├── profanity-list.js        # Bundled word filter list
│   ├── popup.html               # Extension popup UI
│   ├── popup.css                # Popup styling
│   ├── popup.js                 # Popup logic
│   └── icons/                   # Extension icons (16px–128px)
│
├── shared/
│   └── profanity-list.js        # Shared word list used across extension and docs
│
├── docs/
│   └── README.md                # Detailed documentation
│
└── generate-icons.js            # Script to generate extension icons programmatically
```

---

## 🚀 Installation (Developer Mode)

1. Open **Google Chrome** and go to `chrome://extensions/`
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked**
4. Select the `PurePlay/browser-extension/` folder
5. The extension is now active — enjoy profanity-free streaming!

---

## 🌐 Supported Platforms

| Platform | Supported |
|----------|-----------|
| YouTube | ✅ |
| Netflix | ✅ |
| Amazon Prime Video | ✅ |
| Disney+ | ✅ |
| Hulu | ✅ |
| Hotstar | ✅ |
| HBO Max / Max | ✅ |
| Any other website | ✅ (generic fallback) |

---

<div align="center">
  <i>Clean audio. Uninterrupted viewing. Total peace of mind.</i>
</div>
