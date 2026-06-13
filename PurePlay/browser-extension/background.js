/**
 * PurePlay Background Service Worker
 */

chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === "install") {
    // Set default settings
    chrome.storage.sync.set({
      enabled: true,
      filterLevel: "severe",
      muteMode: "mute",
      customWords: [],
      totalBlocked: 0,
      languages: ["en", "hi"],
    });
    console.log("[PurePlay] Extension installed. Default settings applied.");
  }
});

// Relay messages between popup and content scripts
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "WORD_BLOCKED") {
    // Update global counter
    chrome.storage.sync.get({ totalBlocked: 0 }, (data) => {
      chrome.storage.sync.set({ totalBlocked: data.totalBlocked + 1 });
    });
  }
});
