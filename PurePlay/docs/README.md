# PurePlay 🎬🔇

> **Clean audio, pure experience — on any screen.**

PurePlay is a Chrome browser extension that automatically detects and mutes (or beeps) offensive words and profanity in real-time during video playback on any website — YouTube, Netflix, Prime Video, Disney+, Hotstar, and more.

---

## Features

| Feature | Description |
|---|---|
| 🔇 Auto-mute | Silences audio precisely during offensive words |
| 📢 Beep mode | Replaces profanity with a beep sound |
| 🎛️ Sensitivity levels | Severe / Moderate / All Words |
| ✏️ Custom word list | Add your own words to block |
| 📊 Live stats | Tracks words blocked per session and all-time |
| 🌐 Universal | Works on any website with a `<video>` element |

---

## How It Works

```
Video is playing on any tab
        ↓
Web Speech API captures live audio (microphone)
        ↓
Transcript checked against profanity word list
        ↓
Match found? → Mute video for ~200–600ms
        ↓
Clean audio resumes automatically
```

> **Note:** PurePlay uses the browser's built-in Web Speech API — **no audio is sent to any external server**. Everything runs locally in your browser.

---

## Installation (Developer Mode)

Since PurePlay is not yet published to the Chrome Web Store, load it manually:

1. **Download / clone** this repository.

2. Open Chrome and navigate to:
   ```
   chrome://extensions/
   ```

3. Enable **Developer Mode** (toggle in top-right corner).

4. Click **"Load unpacked"**.

5. Select the `browser-extension/` folder inside this project.

6. PurePlay will appear in your extensions bar. **Pin it** for easy access.

---

## Usage

1. Navigate to any video page (YouTube, Netflix, etc.).
2. Click the **PurePlay icon** in your Chrome toolbar.
3. Make sure the toggle is **ON**.
4. Play your video — PurePlay will automatically start listening.

> ⚠️ **Microphone Permission Required:** Chrome will ask for microphone access the first time. This is needed for the Web Speech API to listen to the audio from the video. Grant permission to enable filtering.

---

## Settings

| Setting | Options |
|---|---|
| **Filter Sensitivity** | `Severe Only` — blocks the worst words only |
| | `Moderate` — blocks severe + moderate words |
| | `All Words` — blocks all profanity including mild words |
| **When Detected** | `🔇 Silence` — mutes the video for the word's duration |
| | `📢 Beep` — plays a beep sound over the word |
| **Custom Words** | Type a word and press Enter or click `+` to add custom blocked words |

---

## Project Structure

```
PurePlay/
├── browser-extension/         ← Chrome Extension (load this in chrome://extensions)
│   ├── manifest.json          ← Extension manifest (MV3)
│   ├── content.js             ← Core logic: speech recognition + audio muting
│   ├── profanity-list.js      ← Default profanity word list (categorized)
│   ├── background.js          ← Service worker (stats tracking)
│   ├── popup.html             ← Extension popup UI
│   ├── popup.css              ← Premium dark UI styles
│   ├── popup.js               ← Popup controller
│   └── icons/                 ← Extension icons (16, 32, 48, 128px)
│
├── shared/
│   └── profanity-list.js      ← Shared word list (source of truth)
│
├── generate-icons.js          ← Script to regenerate PNG icons
└── docs/
    └── README.md              ← This file
```

---

## Roadmap

### Phase 1 — Core MVP ✅ (Current)
- [x] Real-time audio capture from video
- [x] Speech-to-text via Web Speech API
- [x] Categorized profanity word list (severe/moderate/mild)
- [x] Auto-mute on bad word detection
- [x] Beep mode alternative
- [x] Custom word list (add/remove)
- [x] Premium popup UI with stats

### Phase 2 — Smart Features 🧠 (Planned)
- [ ] ML-based context detection
- [ ] Multi-language support (Hindi, Spanish, French)
- [ ] Word replacement (subtitle overlay)
- [ ] Parental control PIN lock

### Phase 3 — Platform Expansion 📡 (Future)
- [ ] React Native mobile app (Android + iOS)
- [ ] Electron desktop app (Windows/Mac/Linux)
- [ ] Smart TV app (Android TV)
- [ ] Chrome Web Store publishing

---

## Technical Notes

### Why Web Speech API?
- Built into Chrome — no server required
- Zero latency for short phrases
- Free with no API key
- Works on any website

### Limitation: Continuous Listening
Chrome's Web Speech API stops automatically after ~60 seconds of silence or when the tab loses focus. PurePlay automatically restarts recognition when the video is playing.

### Accuracy
Web Speech API is optimized for voice input, not video audio. Accuracy varies based on:
- Audio quality of the video
- Background music/noise
- Speaking speed and accent

---

## Privacy

- ✅ No data leaves your device
- ✅ No account required
- ✅ No analytics or tracking
- ✅ Open source

---

## License

MIT License — free to use, modify, and distribute.

---

*Built with ❤️ as part of the CyberArsenal project suite.*
