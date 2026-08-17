# URL Phishing Detection System

A premium, interactive browser-based dashboard that analyzes URLs for phishing indicators in real-time. It combines **heuristic analysis**, a **client-side machine learning engine**, and **live threat intelligence lookups** to deliver a comprehensive security score.

---

## Key Features

* **⚡ Real-Time Heuristic Rules Engine**: Evaluates 14 structural features of a URL instantly, identifying common phishing vectors (e.g., raw IP domains, suspicious TLDs, brand keyword spoofing, `@` symbol redirections, unencrypted HTTP protocols, and nested subdomain levels).
* **🧠 Client-Side Machine Learning Model**: Uses a custom Logistic Regression model running entirely in the browser to compute threat probabilities. Features are weighted according to actual patterns observed in known phishing datasets.
* **🌐 Live Intelligence Integration**:
  * **Cloudflare DNS-over-HTTPS (DoH)**: Resolves hostnames live in the browser to verify whether a domain has active IP records or is an unresolvable lookalike domain.
  * **Google Safe Browsing & VirusTotal**: Interfaces directly with public threat databases (supports user-provided API keys via a settings modal, with custom simulation logic fallback if keys are not provided).
* **🎨 Premium Dashboard UI**: 
  * **Canvas Gauge Animation**: Displays risk score (0-100%) in a custom-rendered circular gauge that changes colors dynamically based on severity (Safe, Suspicious, High Risk).
  * **ML Feature breakdown chart**: Visually represents how each heuristic feature contributed to the ML decision.
  * **Sidebar Scan Logs**: Tracks recent scans using `localStorage` for rapid comparison and retrieval.

---


## How to Run

1. **Serve the project locally** using a lightweight server (e.g., Python, Node.js, or Live Server):
   ```bash
   # Option A: Python server
   python -m http.server 8000

   # Option B: Node.js server
   npx http-server -p 8000
   ```
2. Navigate to **`http://localhost:8000/`** in your web browser.
3. Test with the suggestion links at the bottom of the scan container, or input custom URLs to evaluate their security posture.
