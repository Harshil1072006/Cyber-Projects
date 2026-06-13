/**
 * PurePlay Popup Script
 * Handles UI interactions and communicates with the content script.
 */

"use strict";

// ─── DOM refs ────────────────────────────────────────────────────────────────
const app             = document.getElementById("app");
const toggleBtn       = document.getElementById("toggle-btn");
const toggleLabel     = document.getElementById("toggle-label");
const statusDot       = document.getElementById("status-dot");
const statusText      = document.getElementById("status-text");
const statBlocked     = document.getElementById("stat-blocked");
const statTotal       = document.getElementById("stat-total");
const statLast        = document.getElementById("stat-last");
const filterChips     = document.querySelectorAll("#filter-level-group .chip");
const muteModeChips   = document.querySelectorAll("#mute-mode-group .chip");
const langChips       = document.querySelectorAll(".lang-chip");
const customWordInput = document.getElementById("custom-word-input");
const addWordBtn      = document.getElementById("add-word-btn");
const wordTagsEl      = document.getElementById("word-tags");
const toast           = document.getElementById("toast");

// ─── State ────────────────────────────────────────────────────────────────────
let state = {
  enabled:      true,
  filterLevel:  "severe",
  muteMode:     "mute",
  customWords:  [],
  totalBlocked: 0,
  languages:    ["en", "hi"],
};

let sessionBlocked = 0;
let toastTimer = null;

// ─── Init: Load settings from chrome.storage ──────────────────────────────────
chrome.storage.sync.get(
  { enabled: true, filterLevel: "severe", muteMode: "mute", customWords: [], totalBlocked: 0, languages: ["en", "hi"] },
  (data) => {
    state = { ...state, ...data };
    applyState();
    renderWordTags();
    pollContentScript();
  }
);

// ─── Apply state to UI ────────────────────────────────────────────────────────
function applyState() {
  // Toggle
  const on = state.enabled;
  toggleBtn.classList.toggle("off", !on);
  toggleLabel.textContent = on ? "ON" : "OFF";
  toggleLabel.classList.toggle("off", !on);
  app.classList.toggle("disabled", !on);

  // Filter level chips
  filterChips.forEach((chip) => {
    chip.classList.toggle("active", chip.dataset.value === state.filterLevel);
  });

  // Mute mode chips
  muteModeChips.forEach((chip) => {
    chip.classList.toggle("active", chip.dataset.value === state.muteMode);
  });

  // Language chips (multi-select toggle)
  langChips.forEach((chip) => {
    chip.classList.toggle("active", state.languages.includes(chip.dataset.lang));
  });

  // Stats
  statTotal.textContent = state.totalBlocked;
  statBlocked.textContent = sessionBlocked;
}

// ─── Save settings to chrome.storage and notify content script ────────────────
function saveSettings() {
  chrome.storage.sync.set({
    enabled:     state.enabled,
    filterLevel: state.filterLevel,
    muteMode:    state.muteMode,
    customWords: state.customWords,
    languages:   state.languages,
  });

  // Tell the content script
  sendToActiveTab({ type: "UPDATE_SETTINGS", ...state });
}

// ─── Toggle ON/OFF ────────────────────────────────────────────────────────────
toggleBtn.addEventListener("click", () => {
  state.enabled = !state.enabled;
  applyState();
  sendToActiveTab({ type: "TOGGLE_ENABLED", value: state.enabled });
  chrome.storage.sync.set({ enabled: state.enabled });
  showToast(state.enabled ? "PurePlay enabled ✓" : "PurePlay paused");
});

// ─── Filter Level Chips ───────────────────────────────────────────────────────
filterChips.forEach((chip) => {
  chip.addEventListener("click", () => {
    state.filterLevel = chip.dataset.value;
    saveSettings();
    applyState();
    showToast(`Filter: ${chip.textContent}`);
  });
});

// ─── Language Chips (multi-select) ───────────────────────────────────────────
langChips.forEach((chip) => {
  chip.addEventListener("click", () => {
    const lang = chip.dataset.lang;
    const isActive = state.languages.includes(lang);

    if (isActive && state.languages.length === 1) {
      showToast("At least one language must be active");
      return; // prevent deselecting the last one
    }

    if (isActive) {
      state.languages = state.languages.filter((l) => l !== lang);
    } else {
      state.languages = [...state.languages, lang];
    }

    saveSettings();
    applyState();
    showToast(state.languages.includes("hi") && state.languages.includes("en")
      ? "Filtering English + Hindi 🇮🇳🇺🇸"
      : state.languages.includes("hi") ? "Filtering Hindi only 🇮🇳"
      : "Filtering English only 🇺🇸"
    );
  });
});

// ─── Mute Mode Chips ──────────────────────────────────────────────────────────
muteModeChips.forEach((chip) => {
  chip.addEventListener("click", () => {
    state.muteMode = chip.dataset.value;
    saveSettings();
    applyState();
    showToast(chip.dataset.value === "beep" ? "Mode: Beep 📢" : "Mode: Silence 🔇");
  });
});

// ─── Custom Words ─────────────────────────────────────────────────────────────
function addWord(word) {
  const cleaned = word.trim().toLowerCase();
  if (!cleaned || state.customWords.includes(cleaned)) return;
  if (cleaned.length > 30) { showToast("Word too long"); return; }
  state.customWords.push(cleaned);
  saveSettings();
  renderWordTags();
  showToast(`"${cleaned}" added`);
}

function removeWord(word) {
  state.customWords = state.customWords.filter((w) => w !== word);
  saveSettings();
  renderWordTags();
  showToast(`"${word}" removed`);
}

function renderWordTags() {
  wordTagsEl.innerHTML = "";
  state.customWords.forEach((word) => {
    const tag = document.createElement("span");
    tag.className = "word-tag";
    tag.title = "Click to remove";
    tag.innerHTML = `${word} <span class="remove-x">×</span>`;
    tag.addEventListener("click", () => removeWord(word));
    wordTagsEl.appendChild(tag);
  });
}

addWordBtn.addEventListener("click", () => {
  const val = customWordInput.value.trim();
  if (val) { addWord(val); customWordInput.value = ""; }
});

customWordInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    const val = customWordInput.value.trim();
    if (val) { addWord(val); customWordInput.value = ""; }
  }
});

// ─── Status polling ───────────────────────────────────────────────────────────
function pollContentScript() {
  sendToActiveTab({ type: "GET_STATS" }, (response) => {
    if (!response) {
      setStatus("no-video", null);
      return;
    }
    const { stats, isEnabled, hasVideo, detectionMode } = response;
    sessionBlocked = stats?.wordsBlocked || 0;
    statBlocked.textContent = sessionBlocked;

    if (!isEnabled) {
      setStatus("disabled", null);
    } else if (!hasVideo) {
      setStatus("no-video", null);
    } else {
      setStatus("active", detectionMode);
    }

    if (stats?.lastWord && stats.lastWord !== statLast.textContent) {
      statLast.textContent = stats.lastWord;
      bumpStat(statLast);
      bumpStat(statBlocked);
    }
  });
}

function setStatus(mode, detectionMode) {
  statusDot.className = "status-dot";
  const modeLabel = {
    "texttrack":   "📡 TextTrack",
    "caption-dom": "📺 Captions",
    "speech":      "🎙️ Speech",
  }[detectionMode] || "";

  if (mode === "active") {
    statusDot.classList.add("active");
    statusText.textContent = modeLabel
      ? `Active — ${modeLabel} mode`
      : "Active — filtering audio";
  } else if (mode === "no-video") {
    statusText.textContent = "Play a video to start filtering";
  } else if (mode === "disabled") {
    statusText.textContent = "Paused — click toggle to enable";
  } else {
    statusDot.classList.add("error");
    statusText.textContent = "Could not connect to page";
  }
}

function bumpStat(el) {
  el.classList.add("bump");
  setTimeout(() => el.classList.remove("bump"), 200);
}

// ─── Listen for blocked word events from content script ──────────────────────
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "WORD_BLOCKED") {
    sessionBlocked = msg.count;
    statBlocked.textContent = sessionBlocked;
    bumpStat(statBlocked);

    // Update total from storage
    chrome.storage.sync.get({ totalBlocked: 0 }, (data) => {
      statTotal.textContent = data.totalBlocked;
    });
  }
});

// ─── Helpers ──────────────────────────────────────────────────────────────────
function sendToActiveTab(msg, callback) {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs || !tabs[0]) { callback && callback(null); return; }
    try {
      chrome.tabs.sendMessage(tabs[0].id, msg, (response) => {
        if (chrome.runtime.lastError) { callback && callback(null); return; }
        callback && callback(response);
      });
    } catch (e) {
      callback && callback(null);
    }
  });
}

function showToast(msg) {
  toast.textContent = msg;
  toast.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("show"), 2000);
}

// Auto-refresh stats every 3 seconds while popup is open
setInterval(pollContentScript, 3000);
