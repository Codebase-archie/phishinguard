// background service worker
// listens for tab updates and auto-checks URLs

const API_URL = "https://phishinguard.onrender.com/predict";
const PHISHING_THRESHOLD = 0.8;

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {

    // skip chrome:// and extension pages
    if (!tab.url.startsWith("http")) return;

    fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: tab.url })
    })
    .then(res => res.json())
    .then(data => {
      if (data.score >= PHISHING_THRESHOLD) {
        // inject warning banner into the page
        chrome.scripting.executeScript({
          target: { tabId: tabId },
          func: showWarningBanner,
          args: [data.score]
        });
      }
    })
    .catch(() => {
      // silently fail - don't disrupt browsing if API is down
    });
  }
});

function showWarningBanner(score) {
  // check if banner already exists
  if (document.getElementById("phishguard-banner")) return;

  const banner = document.createElement("div");
  banner.id = "phishguard-banner";
  banner.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    z-index: 999999;
    background: #7f1d1d;
    color: white;
    padding: 12px 20px;
    font-family: -apple-system, sans-serif;
    font-size: 14px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    box-shadow: 0 2px 8px rgba(0,0,0,0.4);
  `;

  banner.innerHTML = `
    <span>⚠️ <strong>PhishGuard Warning:</strong>
    This URL has a ${Math.round(score * 100)}% phishing probability.
    Proceed with caution.</span>
    <button onclick="this.parentElement.remove()" style="
      background: transparent;
      border: 1px solid rgba(255,255,255,0.4);
      color: white;
      padding: 4px 10px;
      border-radius: 4px;
      cursor: pointer;
      font-size: 12px;
    ">Dismiss</button>
  `;

  document.body.prepend(banner);
}