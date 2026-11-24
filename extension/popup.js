document.addEventListener("DOMContentLoaded", async () => {
  const resultDiv = document.getElementById("result");
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  if (!tab || !tab.url || !tab.url.startsWith("http")) {
    resultDiv.innerHTML = `<div class="meta">Internal browser page — no URL scan needed.</div>`;
    return;
  }

  try {
    const res = await fetch("http://localhost:8000/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: tab.url })
    });
    const data = await res.json();

    const statusClass = data.is_phishing ? "danger" : "safe";
    const statusText = data.is_phishing ? "⚠️ PHISHING DETECTED" : "✅ SAFE WEBSITE";

    resultDiv.innerHTML = `
      <div class="status ${statusClass}">${statusText}</div>
      <div class="meta">
        <strong>Risk Level:</strong> ${data.risk_level}<br/>
        <strong>Confidence:</strong> ${data.confidence}%<br/>
        <strong>Latency:</strong> ${data.latency_ms} ms (${data.cached ? "Cached" : "Live ML"})<br/>
        <strong>URL:</strong> ${data.url}
      </div>
    `;
  } catch (err) {
    resultDiv.innerHTML = `<div class="status danger">Backend Offline</div><div class="meta">Start FastAPI server on port 8000.</div>`;
  }
});