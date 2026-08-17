/**
 * URL Phishing Detection System
 * Main Application Coordinator & UI Controller
 */

import { HeuristicsEngine } from './heuristics.js';
import { MLModelEngine } from './ml_model.js';
import { SecurityAPIService } from './api.js';

class ApplicationController {
  constructor() {
    this.scanHistory = [];
    this.apiKeys = { google: '', virustotal: '' };
    this.currentGaugeAnimation = null;

    // DOM Elements Cache
    this.elements = {
      scanInput: document.getElementById('scan-input'),
      btnScan: document.getElementById('btn-scan'),
      idleState: document.getElementById('idle-state'),
      scanningState: document.getElementById('scanning-state'),
      resultsDashboard: document.getElementById('results-dashboard'),
      historyList: document.getElementById('history-list'),
      
      // Gauges and Badges
      gaugeCanvas: document.getElementById('gauge-canvas'),
      gaugeNumber: document.getElementById('gauge-number'),
      riskBadge: document.getElementById('risk-badge'),
      riskSummary: document.getElementById('risk-summary'),
      
      // Breakdown columns
      flagsList: document.getElementById('flags-list'),
      mlContributions: document.getElementById('ml-contributions'),
      
      // Intel Panel
      dnsStatus: document.getElementById('dns-status'),
      dnsIps: document.getElementById('dns-ips'),
      dnsResolutionCode: document.getElementById('dns-resolution-code'),
      googleIntel: document.getElementById('google-intel'),
      vtIntel: document.getElementById('vt-intel'),
      
      // Modals
      settingsModal: document.getElementById('settings-modal'),
      btnSettings: document.getElementById('btn-settings'),
      btnCloseSettings: document.getElementById('btn-close-settings'),
      btnCancelSettings: document.getElementById('btn-cancel-settings'),
      btnSaveSettings: document.getElementById('btn-save-settings'),
      googleKeyInput: document.getElementById('google-key-input'),
      vtKeyInput: document.getElementById('vt-key-input'),

      // Suggestion tips
      tipBenign: document.getElementById('tip-benign'),
      tipSuspicious: document.getElementById('tip-suspicious'),
      tipPhishing: document.getElementById('tip-phishing')
    };

    this.init();
  }

  init() {
    this.loadState();
    this.registerEvents();
    this.renderHistory();
  }

  /**
   * Load API keys and historical scans from LocalStorage.
   */
  loadState() {
    try {
      const keys = localStorage.getItem('phish_detector_api_keys');
      if (keys) {
        this.apiKeys = JSON.parse(keys);
      }

      const history = localStorage.getItem('phish_detector_scan_history');
      if (history) {
        this.scanHistory = JSON.parse(history);
      }
    } catch (e) {
      console.error('Error loading localStorage configurations', e);
    }
  }

  /**
   * Register all click, keypress, and submit event listeners.
   */
  registerEvents() {
    // Scan Trigger Actions
    this.elements.btnScan.addEventListener('click', () => this.handleScanTrigger());
    this.elements.scanInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') this.handleScanTrigger();
    });

    // Suggestion Tips
    this.elements.tipBenign.addEventListener('click', () => {
      this.elements.scanInput.value = 'https://wikipedia.org/wiki/Phishing';
      this.handleScanTrigger();
    });
    this.elements.tipSuspicious.addEventListener('click', () => {
      this.elements.scanInput.value = 'http://bank-verification-signin.net/secure/login.php';
      this.handleScanTrigger();
    });
    this.elements.tipPhishing.addEventListener('click', () => {
      this.elements.scanInput.value = 'http://login-paypal-security.com/webscr?cmd=_login-run';
      this.handleScanTrigger();
    });

    // Settings Modal
    this.elements.btnSettings.addEventListener('click', () => this.openSettings());
    this.elements.btnCloseSettings.addEventListener('click', () => this.closeSettings());
    this.elements.btnCancelSettings.addEventListener('click', () => this.closeSettings());
    this.elements.btnSaveSettings.addEventListener('click', () => this.saveSettings());
  }

  /**
   * Core workflow function coordinating heuristics, ML classification, and API lookups.
   */
  async handleScanTrigger() {
    const rawUrl = this.elements.scanInput.value.trim();
    if (!rawUrl) return;

    this.showState('scanning');

    // 1. Run Heuristic Rules (Instant)
    const heuristicResults = HeuristicsEngine.analyze(rawUrl);
    
    if (!heuristicResults.isValid) {
      this.showState('idle');
      alert(`Invalid URL format: ${heuristicResults.error}`);
      return;
    }

    const cleanUrl = heuristicResults.href;
    const hostname = heuristicResults.hostname;

    // 2. Run Machine Learning Classifier (Instant)
    const mlResults = MLModelEngine.predict(heuristicResults.features);

    // 3. Run Async Intel Queries: DNS Resolution + APIs
    let dnsReport = { exists: false, records: [], statusName: 'Failed lookup' };
    let googleReport = { isSafe: true, message: 'Google API bypassed' };
    let vtReport = { ratio: 'VirusTotal API bypassed', isThreat: false };

    try {
      // Execute live queries concurrently
      const [dnsRes, googleRes, vtRes] = await Promise.all([
        SecurityAPIService.checkDNS(hostname),
        SecurityAPIService.scanSafeBrowsing(cleanUrl, this.apiKeys.google),
        SecurityAPIService.scanVirusTotal(cleanUrl, this.apiKeys.virustotal)
      ]);

      dnsReport = dnsRes;
      googleReport = googleRes;
      vtReport = vtRes;
    } catch (err) {
      console.error('External API threat resolution failed:', err);
    }

    // 4. Synthesize Combined Risk Score (0-100)
    // Weighted combination of heuristics (40%), ML probability (40%), and DNS/Live API reports (20%)
    let baseMLScore = mlResults.probability * 100;
    let baseHeuristicScore = heuristicResults.score;
    let apiSignalScore = 0;

    // If Google Safe browsing flags it, trigger massive threat score boost
    if (googleReport.isSafe === false) apiSignalScore += 50;
    // If VirusTotal filters flags it
    if (vtReport.isThreat) apiSignalScore += 30;
    // If DNS record lookup fails entirely (NXDOMAIN) for a suspicious lookalike URL
    if (dnsReport.success && !dnsReport.exists) {
      apiSignalScore += 20; // domain is spoofed/inactive or dead
    }

    let finalScore = (baseHeuristicScore * 0.4) + (baseMLScore * 0.4) + (apiSignalScore * 0.2);
    
    // Safety thresholds validation
    if (googleReport.isSafe === false) {
      finalScore = Math.max(finalScore, 90); // Hard override to Phishing if Safe Browsing flags it
    }
    finalScore = Math.min(Math.round(finalScore), 100);

    // Establish risk level decision string
    let riskLevel = 'safe';
    if (finalScore >= 70) {
      riskLevel = 'phishing';
    } else if (finalScore >= 35) {
      riskLevel = 'suspicious';
    }

    const scanRecord = {
      url: cleanUrl,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      date: new Date().toLocaleDateString(),
      score: finalScore,
      riskLevel,
      heuristics: heuristicResults,
      ml: mlResults,
      dns: dnsReport,
      google: googleReport,
      vt: vtReport
    };

    // Update localStorage Scan history list
    this.saveScanHistory(scanRecord);

    // 5. Render dashboard graphics & details lists
    this.renderDashboard(scanRecord);
    this.showState('results');
  }

  /**
   * Renders the parsed results data to dashboard component fields.
   */
  renderDashboard(data) {
    // Render Circular gauge
    this.animateGauge(data.score);

    // Render Risk Level Badge
    this.elements.riskBadge.className = `risk-level-badge ${data.riskLevel}`;
    this.elements.riskBadge.textContent = data.riskLevel === 'phishing' ? 'High Risk' : data.riskLevel;

    // Render Risk Explainer text
    this.elements.riskSummary.textContent = this.generateSummaryText(data);

    // Render Heuristics Indicators
    this.elements.flagsList.innerHTML = '';
    if (data.heuristics.flags.length === 0) {
      this.elements.flagsList.innerHTML = `
        <div class="flag-item" style="border-left: 4px solid var(--safe);">
          <div class="flag-details">
            <span class="flag-category" style="color: var(--safe)">CLEAN STATUS</span>
            <p class="flag-message">No critical heuristic indicators or phishing patterns detected in this URL structure.</p>
          </div>
        </div>
      `;
    } else {
      data.heuristics.flags.forEach(flag => {
        const flagEl = document.createElement('div');
        flagEl.className = `flag-item ${flag.severity}`;
        flagEl.innerHTML = `
          <div class="flag-icon-container">
            ${flag.severity === 'high' ? '🚨' : '⚠️'}
          </div>
          <div class="flag-details">
            <span class="flag-category">${flag.category}</span>
            <p class="flag-message">${flag.message}</p>
          </div>
        `;
        this.elements.flagsList.appendChild(flagEl);
      });
    }

    // Render ML contributions chart
    this.elements.mlContributions.innerHTML = '';
    if (data.ml.contributions.length === 0) {
      this.elements.mlContributions.innerHTML = `
        <div style="font-size: 0.85rem; color: var(--text-muted); text-align: center; padding: 2rem 0;">
          No positive ML feature vectors triggered for this URL.
        </div>
      `;
    } else {
      // Find maximum impact score to scale widths correctly
      const maxImpact = Math.max(...data.ml.contributions.map(c => c.impact), 1.0);
      
      data.ml.contributions.forEach(contrib => {
        const percentage = Math.min(100, Math.round((contrib.impact / maxImpact) * 100));
        
        let color = 'var(--accent)';
        if (data.riskLevel === 'phishing') color = 'var(--danger)';
        else if (data.riskLevel === 'suspicious') color = 'var(--suspicious)';

        const barRow = document.createElement('div');
        barRow.className = 'feature-bar-row';
        barRow.innerHTML = `
          <div class="feature-bar-info">
            <span class="feature-bar-name">${contrib.label}</span>
            <span class="feature-bar-value">+${contrib.impact.toFixed(2)}</span>
          </div>
          <div class="feature-bar-container">
            <div class="feature-bar-fill" style="width: 0%; background-color: ${color};"></div>
          </div>
        `;
        this.elements.mlContributions.appendChild(barRow);
        
        // Trigger fill width animation shortly after addition
        setTimeout(() => {
          const fill = barRow.querySelector('.feature-bar-fill');
          if (fill) fill.style.width = `${percentage}%`;
        }, 50);
      });
    }

    // Render Threat Intelligence Data Panel
    // DNS Record
    if (data.dns.success) {
      if (data.dns.exists) {
        this.elements.dnsStatus.className = 'intel-value dns-up';
        this.elements.dnsStatus.innerHTML = '🟢 Resolves';
        this.elements.dnsIps.innerHTML = data.dns.records.slice(0, 3).map(ip => `<div>A: ${ip}</div>`).join('');
      } else {
        this.elements.dnsStatus.className = 'intel-value dns-down';
        this.elements.dnsStatus.innerHTML = '🔴 Unresolvable';
        this.elements.dnsIps.innerHTML = '<div style="color: var(--danger);">NXDOMAIN: Host is offline or unregistered</div>';
      }
      this.elements.dnsResolutionCode.textContent = data.dns.statusName;
    } else {
      this.elements.dnsStatus.className = 'intel-value dns-down';
      this.elements.dnsStatus.innerHTML = '🟡 Error';
      this.elements.dnsIps.innerHTML = `<div style="color: var(--text-muted);">${data.dns.error}</div>`;
      this.elements.dnsResolutionCode.textContent = 'CHECK_FAILED';
    }

    // Google API Info
    if (data.google.isSafe === false) {
      this.elements.googleIntel.className = 'intel-value danger';
      this.elements.googleIntel.innerHTML = `🚨 Threat (${data.google.threatType})`;
    } else if (data.google.isSafe === true) {
      this.elements.googleIntel.className = 'intel-value safe';
      this.elements.googleIntel.innerHTML = '🟢 Safe';
    } else {
      this.elements.googleIntel.className = 'intel-value';
      this.elements.googleIntel.innerHTML = '⚪ Blocked';
    }

    // VirusTotal Info
    if (data.vt.isThreat) {
      this.elements.vtIntel.className = 'intel-value danger';
      this.elements.vtIntel.innerHTML = `🚨 Flags (${data.vt.ratio})`;
    } else if (data.vt.scanned) {
      this.elements.vtIntel.className = 'intel-value safe';
      this.elements.vtIntel.innerHTML = `🟢 Clean (${data.vt.ratio})`;
    } else {
      this.elements.vtIntel.className = 'intel-value';
      this.elements.vtIntel.innerHTML = '⚪ Queued';
    }
  }

  /**
   * Canvas-based circular progress gauge rendering with smooth ticker animation.
   * @param {number} targetScore 
   */
  animateGauge(targetScore) {
    if (this.currentGaugeAnimation) {
      cancelAnimationFrame(this.currentGaugeAnimation);
    }

    const canvas = this.elements.gaugeCanvas;
    const ctx = canvas.getContext('2d');
    
    // Support High DPI displays
    const dpr = window.devicePixelRatio || 1;
    const size = 180;
    canvas.width = size * dpr;
    canvas.height = size * dpr;
    canvas.style.width = `${size}px`;
    canvas.style.height = `${size}px`;
    ctx.scale(dpr, dpr);

    const cx = size / 2;
    const cy = size / 2;
    const radius = 70;
    
    let currentScore = 0;
    const duration = 1200; // ms
    const startTime = performance.now();

    const draw = (now) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      
      // Easing function (easeOutQuad)
      const easedProgress = progress * (2 - progress);
      currentScore = easedProgress * targetScore;

      // Update HUD number
      this.elements.gaugeNumber.textContent = Math.round(currentScore);

      // Clear canvas
      ctx.clearRect(0, 0, size, size);

      // Draw background track line
      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, 2 * Math.PI);
      ctx.strokeStyle = 'hsl(222, 20%, 18%)';
      ctx.lineWidth = 10;
      ctx.lineCap = 'round';
      ctx.shadowBlur = 0;
      ctx.stroke();

      // Determine colors based on score
      let color = 'hsl(152, 75%, 48%)'; // Safe (Green)
      let glowColor = 'hsla(152, 75%, 48%, 0.4)';
      
      if (currentScore >= 70) {
        color = 'hsl(358, 85%, 58%)'; // Danger (Red)
        glowColor = 'hsla(358, 85%, 58%, 0.4)';
      } else if (currentScore >= 35) {
        color = 'hsl(38, 92%, 52%)'; // Suspicious (Orange)
        glowColor = 'hsla(38, 92%, 52%, 0.4)';
      }

      // Draw glowing active progress line
      ctx.beginPath();
      // Start progress from top (-Math.PI/2)
      const startAngle = -Math.PI / 2;
      const endAngle = startAngle + (2 * Math.PI * (currentScore / 100));
      
      ctx.arc(cx, cy, radius, startAngle, endAngle);
      ctx.strokeStyle = color;
      ctx.lineWidth = 10;
      ctx.lineCap = 'round';
      
      // Apply neon glow drop shadow
      ctx.shadowColor = glowColor;
      ctx.shadowBlur = 10;
      ctx.shadowOffsetX = 0;
      ctx.shadowOffsetY = 0;
      
      ctx.stroke();

      if (progress < 1) {
        this.currentGaugeAnimation = requestAnimationFrame(draw);
      }
    };

    this.currentGaugeAnimation = requestAnimationFrame(draw);
  }

  /**
   * Generates a structural natural-language safety summary based on results.
   */
  generateSummaryText(data) {
    if (data.score >= 70) {
      if (data.google.isSafe === false) {
        return 'CRITICAL THREAT: Google Safe Browsing has blacklisted this URL for social engineering. Do not access this page.';
      }
      return 'CRITICAL THREAT: The ML model and heuristic scans have flagged high-probability phishing elements including brand-spoofing indicators.';
    } else if (data.score >= 35) {
      let reasons = [];
      if (!data.heuristics.features.isHttps) reasons.push('unencrypted protocol');
      if (data.heuristics.features.dotCountDomain > 3) reasons.push('excessive subdomains');
      if (data.dns.success && !data.dns.exists) reasons.push('unresolvable DNS records');
      
      const reasonsStr = reasons.length > 0 ? ` due to ${reasons.join(', ')}` : '';
      return `SUSPICIOUS: Features indicate anomalies${reasonsStr}. Proceed with extreme caution and verify domain details.`;
    } else {
      return 'SAFE: The URL possesses standard structures, uses HTTPS, resolves successfully, and has no threats flagged in registry lookups.';
    }
  }

  /**
   * Switch displays between Idle, Scanning, and Dashboard views.
   */
  showState(state) {
    this.elements.idleState.style.display = state === 'idle' ? 'flex' : 'none';
    this.elements.scanningState.style.display = state === 'scanning' ? 'flex' : 'none';
    this.elements.resultsDashboard.style.display = state === 'results' ? 'flex' : 'none';
  }

  /**
   * Save analyzed URL data into local scan lists.
   */
  saveScanHistory(record) {
    // Deduplicate history: remove matching URL if present to slide to top
    this.scanHistory = this.scanHistory.filter(item => item.url !== record.url);
    
    // Add to front of log
    this.scanHistory.unshift(record);
    
    // Cap at 15 items
    if (this.scanHistory.length > 15) {
      this.scanHistory.pop();
    }

    try {
      localStorage.setItem('phish_detector_scan_history', JSON.stringify(this.scanHistory));
    } catch (e) {
      console.error(e);
    }
    
    this.renderHistory();
  }

  /**
   * Render sidebar logs lists.
   */
  renderHistory() {
    this.elements.historyList.innerHTML = '';
    
    if (this.scanHistory.length === 0) {
      this.elements.historyList.innerHTML = `
        <div style="font-size: 0.8rem; color: var(--text-muted); text-align: center; padding: 2rem 0;">
          No scanned items yet.
        </div>
      `;
      return;
    }

    this.scanHistory.forEach(record => {
      const item = document.createElement('div');
      item.className = 'history-item';
      
      // Determine score badge level
      let badgeClass = 'safe';
      if (record.score >= 70) badgeClass = 'phishing';
      else if (record.score >= 35) badgeClass = 'suspicious';

      const shortBadge = record.score >= 70 ? 'FAIL' : (record.score >= 35 ? 'SUSP' : 'PASS');

      item.innerHTML = `
        <div class="history-url-details">
          <span class="history-url" title="${record.url}">${record.url}</span>
          <span class="history-time">${record.timestamp} - Risk: ${record.score}%</span>
        </div>
        <span class="badge-risk ${badgeClass}">${shortBadge}</span>
      `;

      item.addEventListener('click', () => {
        this.elements.scanInput.value = record.url;
        this.renderDashboard(record);
        this.showState('results');
      });

      this.elements.historyList.appendChild(item);
    });
  }

  // Settings Panel actions
  openSettings() {
    this.elements.googleKeyInput.value = this.apiKeys.google || '';
    this.elements.vtKeyInput.value = this.apiKeys.virustotal || '';
    this.elements.settingsModal.classList.add('active');
  }

  closeSettings() {
    this.elements.settingsModal.classList.remove('active');
  }

  saveSettings() {
    this.apiKeys.google = this.elements.googleKeyInput.value.trim();
    this.apiKeys.virustotal = this.elements.vtKeyInput.value.trim();
    
    try {
      localStorage.setItem('phish_detector_api_keys', JSON.stringify(this.apiKeys));
    } catch (e) {
      console.error(e);
    }
    
    this.closeSettings();
  }
}

// Initialise on DOM Ready
document.addEventListener('DOMContentLoaded', () => {
  new ApplicationController();
});
