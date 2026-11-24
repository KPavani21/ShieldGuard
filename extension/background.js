const API_URL = "http://localhost:8000/predict";

async function checkUrl(tabId, url) {
  if (!url || !url.startsWith("http")) {
    chrome.action.setBadgeText({ text: "", tabId });
    return;
  }

  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    const data = await response.json();

    if (data.is_phishing) {
      chrome.action.setBadgeText({ text: "!", tabId });
      chrome.action.setBadgeBackgroundColor({ color: "#D93025", tabId });
    } else {
      chrome.action.setBadgeText({ text: "OK", tabId });
      chrome.action.setBadgeBackgroundColor({ color: "#188038", tabId });
    }
  } catch (err) {
    chrome.action.setBadgeText({ text: "OFF", tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#5F6368", tabId });
  }
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    checkUrl(tabId, tab.url);
  }
});

chrome.tabs.onActivated.addListener(async (activeInfo) => {
  const tab = await chrome.tabs.get(activeInfo.tabId);
  if (tab.url) {
    checkUrl(activeInfo.tabId, tab.url);
  }
});