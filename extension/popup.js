const API_URL = "https://phishinguard.onrender.com/predict";

let currentUrl = "";

// get current tab URL when popup opens
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  if (tabs[0] && tabs[0].url) {
    currentUrl = tabs[0].url;
    document.getElementById("urlDisplay").textContent = currentUrl;
  } else {
    document.getElementById("urlDisplay").textContent = "Could not get URL";
  }
});

document.getElementById("analyzeBtn").addEventListener("click", async () => {
  if (!currentUrl) return;

  const btn = document.getElementById("analyzeBtn");
  const resultDiv = document.getElementById("result");
  const errorDiv = document.getElementById("errorDiv");

  // reset UI
  btn.disabled = true;
  btn.textContent = "Analyzing...";
  resultDiv.style.display = "none";
  errorDiv.style.display = "none";

  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: currentUrl })
    });

    if (!response.ok) throw new Error("API error");

    const data = await response.json();
    showResult(data);

  } catch (err) {
    errorDiv.textContent = "Could not reach PhishGuard API. Check your connection.";
    errorDiv.style.display = "block";
  } finally {
    btn.disabled = false;
    btn.textContent = "Analyze URL";
  }
});

function showResult(data) {
  const resultDiv = document.getElementById("result");
  const isPhishing = data.verdict === "phishing";

  resultDiv.className = `result ${data.verdict === "phishing" ? "phishing" : "safe"}`;
  resultDiv.style.display = "block";

  document.getElementById("resultIcon").textContent = isPhishing ? "⚠️" : "✅";
  document.getElementById("resultTitle").textContent = isPhishing
    ? "Phishing Detected!" : "URL Looks Safe";

  const scorePercent = Math.round(data.score * 100);
  document.getElementById("scoreBar").style.width = scorePercent + "%";
  document.getElementById("scoreText").textContent =
    `Confidence: ${scorePercent}% ${isPhishing ? "phishing" : "safe"}`;

  // show features if phishing
  const featuresDiv = document.getElementById("featuresDiv");
  const pillsDiv = document.getElementById("featurePills");

  if (isPhishing && data.top_features && data.top_features.length > 0) {
    pillsDiv.innerHTML = "";
    data.top_features
      .filter(f => f.value > 0)
      .forEach(f => {
        const pill = document.createElement("span");
        pill.className = "feature-pill";
        pill.textContent = f.name.replace(/_/g, " ");
        pillsDiv.appendChild(pill);
      });
    featuresDiv.style.display = "block";
  } else {
    featuresDiv.style.display = "none";
  }

  // cached badge
  const cachedBadge = document.getElementById("cachedBadge");
  cachedBadge.textContent = data.bloom_cached
    ? "⚡ Fast-path: known safe domain" : "";
}