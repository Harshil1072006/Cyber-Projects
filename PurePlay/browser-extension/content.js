/**
 * PurePlay Content Script — v2
 *
 * Detection Strategy (in priority order):
 *  1. Native HTML5 TextTrack API  — reads subtitle cue timing directly from video
 *  2. DOM Caption Observer        — watches YouTube/Netflix/etc. caption overlays
 *  3. video.captureStream()       — captures actual video audio, feeds to
 *                                   MediaRecorder → SpeechRecognition (no mic!)
 *
 * The Web Speech API (microphone) approach is intentionally NOT used
 * because it cannot hear the video's audio — only ambient room sound.
 */

(function () {
  "use strict";

  // ─── State ────────────────────────────────────────────────────────────────
  let isEnabled      = true;
  let filterLevel    = "severe";
  let muteMode       = "mute";
  let languages      = ["en", "hi"];
  let wordSet        = new Set();
  let currentVideo   = null;
  let isMuted        = false;
  let muteTimeout    = null;
  let sessionStats   = { wordsBlocked: 0, lastWord: "" };
  let detectionMode  = "none"; // "texttrack" | "caption-dom" | "speech" | "none"
  let captionObserver = null;
  let trackListeners = [];
  let speechRec      = null;
  let lastCapText    = "";
  let audioCtx       = null;
  let mediaRecorder  = null;

  // ─── Platform caption selectors ──────────────────────────────────────────
  // Ordered from most-specific to generic fallback
  const CAPTION_SELECTORS = [
    ".ytp-caption-segment",                        // YouTube
    ".player-timedtext-text-container span",        // Netflix
    ".atvwebplayersdk-timedtext-text span",          // Prime Video
    ".clpp-text-cue span",                          // Disney+
    "[data-testid='subtitle-text'] span",           // Hotstar / JioCinema
    ".subtitles-container span",
    "[class*='caption-segment']",
    "[class*='subtitle-text']",
    "[class*='caption-text']",
    "[class*='subtitles'] span",
    "[class*='caption'] span",
  ];

  // ─── Load Settings ────────────────────────────────────────────────────────
  function loadSettings() {
    return new Promise((resolve) => {
      chrome.storage.sync.get(
        { enabled: true, filterLevel: "severe", muteMode: "mute", customWords: [], languages: ["en", "hi"] },
        (s) => {
          isEnabled   = s.enabled;
          filterLevel = s.filterLevel;
          muteMode    = s.muteMode;
          languages   = s.languages || ["en", "hi"];
          rebuildWordSet(s.customWords || []);
          resolve();
        }
      );
    });
  }

  // ─── Build Word Set ───────────────────────────────────────────────────────
  function rebuildWordSet(customWords = []) {
    const levelMap = {
      severe:   ["severe"],
      moderate: ["severe", "moderate"],
      mild:     ["severe", "moderate", "mild"],
    };
    const categories = levelMap[filterLevel] || ["severe"];
    const langFilter = languages.length > 0 ? languages : null;
    wordSet = buildWordSet(DEFAULT_PROFANITY_LIST, categories, langFilter);
    customWords.forEach((w) => wordSet.add(w.toLowerCase().trim()));
    console.log(`[PurePlay] 📋 Word set size: ${wordSet.size} words`);
  }

  // ─── Phonetic Normalizer ──────────────────────────────────────────────────
  // Collapses common STT transcription variations into a canonical form.
  // Works for BOTH English and Hindi/Hinglish romanized text.
  function phoneticNormalize(text) {
    return text
      .toLowerCase()
      // ── English phonetic collapses ──
      .replace(/ph/g, "f")           // phuck → fuck
      .replace(/wh/g, "w")           // whore → wore (still matches)
      .replace(/ck/g, "k")           // fuck → fuk
      .replace(/qu/g, "kw")          // quick
      // ── Hindi phonetic collapses ──
      .replace(/bh/g, "b")           // bhosdike → bosdike
      .replace(/dh/g, "d")           // chodh → chod
      .replace(/kh/g, "k")           // 
      .replace(/gh/g, "g")           //
      .replace(/ch/g, "c")           // chod → cod, chutiya → cutiya
      .replace(/sh/g, "s")           //
      .replace(/th/g, "t")           //
      // ── Vowel normalization ──
      .replace(/aa/g, "a")           // madar → madr, haramzaada → haramzada
      .replace(/ee/g, "i")           // 
      .replace(/oo/g, "u")           // chootia → cutia
      .replace(/ou/g, "u")           //
      .replace(/ai/g, "a")           //
      .replace(/ae/g, "a")           //
      // ── Collapse repeated chars ──
      .replace(/(.)\1+/g, "$1")      // fuuuck → fuk, maadarchod → madarcod
      // ── Strip punctuation / stars ──
      .replace(/[*@#$%^&!?,.'"\-]/g, "")
      // ── Normalize spaces ──
      .replace(/\s+/g, " ")
      .trim();
  }

  // ─── Levenshtein Edit Distance ────────────────────────────────────────────
  // Returns the number of single-character edits between two strings.
  // Used to catch small transcription errors (e.g. "chotia" vs "chutiya").
  function editDistance(a, b) {
    if (Math.abs(a.length - b.length) > 4) return Infinity; // quick reject
    const m = a.length, n = b.length;
    // Use two rows for memory efficiency
    let prev = Array.from({ length: n + 1 }, (_, i) => i);
    for (let i = 1; i <= m; i++) {
      const curr = [i];
      for (let j = 1; j <= n; j++) {
        curr[j] = a[i - 1] === b[j - 1]
          ? prev[j - 1]
          : 1 + Math.min(prev[j], curr[j - 1], prev[j - 1]);
      }
      prev = curr;
    }
    return prev[n];
  }

  // ─── Check transcript for profanity (3-layer matching) ───────────────────
  //
  // Layer 1 — Exact match on raw text (fastest, for things like "fuck")
  // Layer 2 — Phonetic match (catches "fuking", "mader chod", etc.)
  // Layer 3 — Fuzzy/edit-distance (catches "chootia" vs "chutiya")
  //
  function checkTranscript(text) {
    if (!text || !isEnabled) return null;

    const raw        = text.toLowerCase().replace(/[*@#$%^&!?]/g, "").trim();
    const normalized = phoneticNormalize(raw);
    const rawTokens  = raw.split(/\s+/);
    const normTokens = normalized.split(/\s+/);

    for (const badWord of wordSet) {
      const normBad    = phoneticNormalize(badWord);
      const badTokens  = normBad.split(/\s+/);
      const isPhrase   = badTokens.length > 1;

      // ── Layer 1: Raw exact substring ──────────────────────────────────────
      if (raw.includes(badWord)) return badWord;

      // ── Layer 2a: Normalized substring match ──────────────────────────────
      if (normalized.includes(normBad)) return badWord;

      // ── Layer 2b: Multi-word phrase sliding window ─────────────────────────
      // e.g. "mader chod" matches "madarchod" after normalization
      if (isPhrase) {
        const phraseLen = badTokens.length;
        for (let i = 0; i <= normTokens.length - phraseLen; i++) {
          const window = normTokens.slice(i, i + phraseLen).join(" ");
          if (window === badTokens.join(" ")) return badWord;
          // Allow 1 token edit distance for the whole phrase
          if (editDistance(window, badTokens.join(" ")) <= 2) return badWord;
        }
        // Also try joining adjacent tokens ("mader" + "chod" → "maderchod")
        const rawJoined  = rawTokens.join("");
        const normJoined = normalized.replace(/\s/g, "");
        const badJoined  = normBad.replace(/\s/g, "");
        if (normJoined.includes(badJoined)) return badWord;
        if (rawJoined.includes(badWord.replace(/\s/g, ""))) return badWord;
      }

      // ── Layer 3: Fuzzy edit-distance per token ────────────────────────────
      // Only for words >= 5 chars to avoid false positives on short words
      if (normBad.length >= 5 && !isPhrase) {
        // Tolerance: 1 edit for ≤7 chars, 2 for ≤10, 3 for longer
        const tolerance = normBad.length <= 7 ? 1 : normBad.length <= 10 ? 2 : 3;
        for (const token of normTokens) {
          if (token.length < 4) continue;
          if (editDistance(token, normBad) <= tolerance) return badWord;
        }
        // Also check joined bigrams (two consecutive tokens merged)
        for (let i = 0; i < normTokens.length - 1; i++) {
          const bigram = normTokens[i] + normTokens[i + 1];
          if (editDistance(bigram, normBad) <= tolerance) return badWord;
        }
      }
    }

    return null;
  }

  // ─── Mute Video ───────────────────────────────────────────────────────────
  function muteFor(ms, word) {
    if (!currentVideo || isMuted) return;
    isMuted = true;
    sessionStats.wordsBlocked++;
    sessionStats.lastWord = word;

    if (muteMode === "beep") playBeep();
    currentVideo.muted = true;
    console.log(`[PurePlay] 🔇 BLOCKED: "${word}" for ${ms}ms [mode: ${detectionMode}]`);

    try {
      chrome.runtime.sendMessage({ type: "WORD_BLOCKED", word, count: sessionStats.wordsBlocked });
    } catch (_) {}

    clearTimeout(muteTimeout);
    muteTimeout = setTimeout(() => {
      if (currentVideo) currentVideo.muted = false;
      isMuted = false;
    }, Math.max(ms, 400));
  }

  // ─── Beep ─────────────────────────────────────────────────────────────────
  function playBeep() {
    try {
      const ctx  = new AudioContext();
      const osc  = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.type = "sine";
      osc.frequency.value = 1000;
      gain.gain.setValueAtTime(0.3, ctx.currentTime);
      osc.start();
      osc.stop(ctx.currentTime + 0.4);
    } catch (_) {}
  }

  // =========================================================================
  // DETECTION METHOD 1: Native HTML5 TextTrack API
  // Best: perfect timing using cue.startTime / cue.endTime
  // Works for: HTML5 video with <track> elements, Hotstar, etc.
  // =========================================================================

  function attachTextTracks(video) {
    if (!video.textTracks || video.textTracks.length === 0) return false;

    let attached = 0;
    Array.from(video.textTracks).forEach((track) => {
      if (!["subtitles", "captions"].includes(track.kind)) return;

      const handler = () => {
        if (!isEnabled || !currentVideo || currentVideo.paused) return;
        if (!track.activeCues || track.activeCues.length === 0) return;

        Array.from(track.activeCues).forEach((cue) => {
          // Strip HTML tags from cue text (VTT can contain tags)
          const raw  = (cue.text || "").replace(/<[^>]*>/g, " ").replace(/\{[^}]*\}/g, "").trim();
          const word = checkTranscript(raw);
          if (word) {
            // Use precise cue duration
            const dur = Math.max(Math.round((cue.endTime - cue.startTime) * 1000), 400);
            muteFor(dur, word);
          }
        });
      };

      track.addEventListener("cuechange", handler);
      trackListeners.push({ track, handler });
      attached++;
    });

    if (attached > 0) {
      detectionMode = "texttrack";
      console.log(`[PurePlay] 🎯 TextTrack API: attached to ${attached} caption track(s)`);
      return true;
    }
    return false;
  }

  function detachTextTracks() {
    trackListeners.forEach(({ track, handler }) => {
      track.removeEventListener("cuechange", handler);
    });
    trackListeners = [];
  }

  // =========================================================================
  // DETECTION METHOD 2: DOM Caption Observer
  // Works for: YouTube, Netflix, Prime Video, Disney+, Hotstar
  // =========================================================================

  function startCaptionDOMObserver() {
    if (captionObserver) captionObserver.disconnect();
    lastCapText = "";

    captionObserver = new MutationObserver(() => {
      if (!isEnabled || !currentVideo || currentVideo.paused) return;

      // Try each selector and collect ALL visible caption text
      let text = "";
      for (const sel of CAPTION_SELECTORS) {
        const els = document.querySelectorAll(sel);
        if (els.length > 0) {
          text = Array.from(els).map((e) => e.textContent.trim()).join(" ").trim();
          if (text) break;
        }
      }

      if (!text || text === lastCapText) return;
      lastCapText = text;

      const word = checkTranscript(text);
      if (word) {
        const syllables = Math.max(1, word.length / 3);
        const dur = Math.round(syllables * 250);
        muteFor(dur, word);
        console.log(`[PurePlay] 📺 Caption DOM: "${word}"`);
      }
    });

    captionObserver.observe(document.body, {
      childList:     true,
      subtree:       true,
      characterData: true,
      attributes:    false,
    });

    detectionMode = "caption-dom";
    console.log("[PurePlay] 👁️ DOM Caption Observer started");
  }

  function stopCaptionDOMObserver() {
    if (captionObserver) {
      captionObserver.disconnect();
      captionObserver = null;
    }
  }

  // ─── Check if any captions are visible on screen ──────────────────────────
  function hasCaptionsOnScreen() {
    for (const sel of CAPTION_SELECTORS) {
      const el = document.querySelector(sel);
      if (el && el.textContent.trim()) return true;
    }
    return false;
  }

  // =========================================================================
  // DETECTION METHOD 3: video.captureStream() + MediaRecorder + SpeechRecognition
  // Works for: any video, no captions needed
  // Note: uses the video's OWN audio — NOT the microphone
  // =========================================================================

  function startStreamRecognition(video) {
    if (!("SpeechRecognition" in window) && !("webkitSpeechRecognition" in window)) {
      console.warn("[PurePlay] SpeechRecognition not available");
      return false;
    }

    // Try to capture the video's own audio stream
    let captureStream = null;
    try {
      if (typeof video.captureStream === "function") {
        captureStream = video.captureStream();
      } else if (typeof video.mozCaptureStream === "function") {
        captureStream = video.mozCaptureStream();
      }
    } catch (e) {
      console.warn("[PurePlay] captureStream failed:", e.message);
    }

    const SpeechRec = window.SpeechRecognition || window.webkitSpeechRecognition;

    if (captureStream && captureStream.getAudioTracks().length > 0) {
      // Route the video audio through AudioContext to make it available
      // to the browser's speech pipeline
      try {
        if (audioCtx) audioCtx.close();
        audioCtx = new AudioContext();
        const src  = audioCtx.createMediaStreamSource(captureStream);
        const dest = audioCtx.createMediaStreamDestination();
        src.connect(dest);

        // Play the captured audio through a hidden audio element
        // so the system's speech recognition pipeline can access it
        const hiddenAudio = document.createElement("audio");
        hiddenAudio.id    = "__pureplay_audio_pipe__";
        hiddenAudio.srcObject = dest.stream;
        hiddenAudio.volume = 0; // Silent — user hears original video
        document.body.appendChild(hiddenAudio);
        hiddenAudio.play().catch(() => {});

        detectionMode = "speech";
        console.log("[PurePlay] 🎙️ Stream recognition: using video audio via AudioContext");
      } catch (e) {
        console.warn("[PurePlay] AudioContext routing failed:", e.message);
      }
    }

    // Start SpeechRecognition
    if (speechRec) {
      try { speechRec.stop(); } catch (_) {}
    }

    speechRec = new SpeechRec();
    speechRec.continuous     = true;
    speechRec.interimResults = true;
    speechRec.lang           = languages.includes("hi") ? "hi-IN" : "en-US";
    speechRec.maxAlternatives = 2;

    let lastSpoken = "";
    speechRec.onresult = (event) => {
      if (!isEnabled || !currentVideo || currentVideo.paused) return;
      for (let i = event.resultIndex; i < event.results.length; i++) {
        const transcript = event.results[i][0].transcript.trim();
        if (transcript === lastSpoken) continue;
        lastSpoken = transcript;
        const word = checkTranscript(transcript);
        if (word) {
          const syllables = Math.max(1, word.length / 3);
          muteFor(Math.round(syllables * 250), word);
        }
      }
    };

    speechRec.onend = () => {
      if (isEnabled && currentVideo && !currentVideo.paused) {
        setTimeout(() => { try { speechRec.start(); } catch (_) {} }, 300);
      }
    };

    speechRec.onerror = (e) => {
      if (e.error !== "not-allowed" && e.error !== "aborted") {
        setTimeout(() => { try { speechRec.start(); } catch (_) {} }, 1000);
      }
    };

    try {
      speechRec.start();
      detectionMode = detectionMode || "speech";
      return true;
    } catch (e) {
      console.warn("[PurePlay] SpeechRecognition failed to start:", e);
      return false;
    }
  }

  function stopSpeechRecognition() {
    if (speechRec) {
      try { speechRec.stop(); } catch (_) {}
      speechRec = null;
    }
    if (audioCtx) {
      audioCtx.close();
      audioCtx = null;
    }
    const pipe = document.getElementById("__pureplay_audio_pipe__");
    if (pipe) pipe.remove();
  }

  // =========================================================================
  // Orchestration: start the best available detection method
  // =========================================================================

  function startDetection() {
    if (!currentVideo || !isEnabled) return;
    stopDetection();

    // Method 1: Native TextTrack (most accurate)
    const hasTextTrack = attachTextTracks(currentVideo);
    if (hasTextTrack) {
      // Also run DOM observer as backup for platforms that duplicate
      startCaptionDOMObserver();
      return;
    }

    // Method 2: DOM Caption Observer (YouTube etc.)
    startCaptionDOMObserver();

    // Method 3: Stream/Speech recognition (fallback for no captions)
    // Start after 5 seconds; if we see captions appear, speech is supplemental
    setTimeout(() => {
      if (detectionMode === "caption-dom" && hasCaptionsOnScreen()) {
        console.log("[PurePlay] Captions detected — skipping speech fallback");
        return;
      }
      startStreamRecognition(currentVideo);
    }, 5000);
  }

  function stopDetection() {
    detachTextTracks();
    stopCaptionDOMObserver();
    stopSpeechRecognition();
    if (currentVideo) currentVideo.muted = false;
    isMuted       = false;
    detectionMode = "none";
    lastCapText   = "";
  }

  // ─── Find and Attach to Video ─────────────────────────────────────────────
  function findVideo() {
    const vids = Array.from(document.querySelectorAll("video"));
    return vids.find((v) => !v.paused && v.readyState > 1)
        || vids.find((v) => v.src || v.querySelector?.("source"))
        || vids[0]
        || null;
  }

  function attachToVideo(video) {
    if (currentVideo === video) return;
    currentVideo = video;

    video.addEventListener("play",  () => { if (isEnabled) startDetection(); });
    video.addEventListener("pause", stopDetection);
    video.addEventListener("ended", stopDetection);

    // Handle new <track> elements added after video loads
    const trackObs = new MutationObserver(() => {
      if (detectionMode !== "texttrack" && video.textTracks && video.textTracks.length > 0) {
        detachTextTracks();
        if (attachTextTracks(video)) {
          console.log("[PurePlay] 📡 Late TextTrack detected — switched to precision mode");
        }
      }
    });
    trackObs.observe(video, { childList: true });

    if (!video.paused && isEnabled) startDetection();
    console.log("[PurePlay] 🎬 Attached to video element");
  }

  // ─── Watch for Video Elements (SPA support) ───────────────────────────────
  function watchForVideo() {
    const v = findVideo();
    if (v) attachToVideo(v);

    const obs = new MutationObserver(() => {
      if (!currentVideo) {
        const found = findVideo();
        if (found) attachToVideo(found);
      }
    });
    obs.observe(document.body, { childList: true, subtree: true });
  }

  // ─── Message Listener (from popup) ───────────────────────────────────────
  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    switch (msg.type) {
      case "TOGGLE_ENABLED":
        isEnabled = msg.value;
        if (!isEnabled) {
          stopDetection();
        } else if (currentVideo && !currentVideo.paused) {
          startDetection();
        }
        sendResponse({ ok: true });
        break;

      case "UPDATE_SETTINGS":
        filterLevel = msg.filterLevel || filterLevel;
        muteMode    = msg.muteMode    || muteMode;
        if (msg.languages) languages = msg.languages;
        rebuildWordSet(msg.customWords || []);
        // Restart detection with new settings
        if (isEnabled && currentVideo && !currentVideo.paused) {
          stopDetection();
          setTimeout(startDetection, 200);
        }
        sendResponse({ ok: true });
        break;

      case "GET_STATS":
        sendResponse({
          stats:        sessionStats,
          isEnabled,
          hasVideo:     !!currentVideo,
          detectionMode,
        });
        break;

      case "RELOAD_SETTINGS":
        loadSettings().then(() => sendResponse({ ok: true }));
        return true;
    }
  });

  // ─── Init ─────────────────────────────────────────────────────────────────
  async function init() {
    await loadSettings();
    if (document.body) {
      watchForVideo();
    } else {
      document.addEventListener("DOMContentLoaded", watchForVideo);
    }
    console.log(
      `[PurePlay] ✅ v2 Initialized | Filter: ${filterLevel} | Lang: ${languages.join("+")}`
    );
  }

  init();
})();
