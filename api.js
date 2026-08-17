/**
 * URL Phishing Detection System
 * Live DNS Lookup & Security Threat APIs Handler
 */

export class SecurityAPIService {
  // Built-in list of common malicious domains for immediate mock matching
  static KNOWN_PHISHING_DOMAINS = [
    'login-paypal-security.com', 'secure-bank-login-verify.xyz', 
    'netflix-payment-update.top', 'office365-login-verification.club',
    'metamask-recover-wallet.net', 'coinbase-verification-support.info',
    'apple-id-verify.site', 'chase-security-alert.work'
  ];

  /**
   * Performs live DNS resolution using Cloudflare's DNS-over-HTTPS (DoH).
   * Bypasses CORS and checks if the domain actually resolves to IP addresses.
   * @param {string} hostname 
   * @returns {Promise<Object>} DNS resolution report
   */
  static async checkDNS(hostname) {
    try {
      const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=A`;
      const response = await fetch(url, {
        headers: { 'Accept': 'application/dns-json' }
      });
      
      if (!response.ok) {
        throw new Error(`DNS check failed with status: ${response.status}`);
      }

      const data = await response.json();
      
      // Status 0 means NOERROR (success), Status 3 means NXDOMAIN (domain doesn't exist)
      const exists = data.Status === 0 && Array.isArray(data.Answer) && data.Answer.length > 0;
      const records = exists ? data.Answer.map(ans => ans.data) : [];

      return {
        success: true,
        exists,
        records,
        status: data.Status,
        statusName: this.getDNSStatusName(data.Status)
      };
    } catch (error) {
      console.error('DNS Lookup Error:', error);
      return {
        success: false,
        error: error.message,
        exists: null,
        records: []
      };
    }
  }

  /**
   * Standard DNS Response code translations.
   * @param {number} status 
   * @returns {string} Status explanation.
   */
  static getDNSStatusName(status) {
    const codes = {
      0: 'NOERROR (Domain active)',
      1: 'FORMERR (Format error)',
      2: 'SERVFAIL (Server fail)',
      3: 'NXDOMAIN (Domain does not exist)',
      4: 'NOTIMP (Not implemented)',
      5: 'REFUSED (Query refused)'
    };
    return codes[status] || `UNKNOWN (${status})`;
  }

  /**
   * Scans a URL using Google Safe Browsing Lookup API (v4).
   * Performs real fetch if API key is provided, else runs custom simulation.
   * @param {string} targetUrl 
   * @param {string} apiKey 
   * @returns {Promise<Object>} Safe Browsing report
   */
  static async scanSafeBrowsing(targetUrl, apiKey = '') {
    if (!apiKey) {
      // Simulation mode
      return new Promise(resolve => {
        setTimeout(() => {
          const parsed = new URL(targetUrl);
          const isPhishingDomain = this.KNOWN_PHISHING_DOMAINS.includes(parsed.hostname.toLowerCase());
          const isHighlySuspicious = targetUrl.length > 90 && (targetUrl.includes('login') || targetUrl.includes('secure'));
          
          if (isPhishingDomain || isHighlySuspicious) {
            resolve({
              isSafe: false,
              threatType: 'SOCIAL_ENGINEERING',
              platformType: 'ANY_PLATFORM',
              source: 'Google Safe Browsing (Simulated)',
              message: 'Flagged: Social engineering/phishing site detected by threat intelligence feed.'
            });
          } else {
            resolve({
              isSafe: true,
              threatType: null,
              source: 'Google Safe Browsing (Simulated)',
              message: 'No matches in Google Safe Browsing blacklist.'
            });
          }
        }, 600); // realistic latency simulation
      });
    }

    try {
      const url = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;
      const payload = {
        client: {
          clientId: "url-phishing-detector-webapp",
          clientVersion: "1.0.0"
        },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url: targetUrl }]
        }
      };

      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        throw new Error(`Google API error: ${response.status}`);
      }

      const data = await response.json();
      const hasMatch = data && data.matches && data.matches.length > 0;

      if (hasMatch) {
        const match = data.matches[0];
        return {
          isSafe: false,
          threatType: match.threatType,
          platformType: match.platformType,
          source: 'Google Safe Browsing (Live)',
          message: `Flagged: ${match.threatType} site detected on ${match.platformType}.`
        };
      }

      return {
        isSafe: true,
        threatType: null,
        source: 'Google Safe Browsing (Live)',
        message: 'No threats found in the live registry.'
      };

    } catch (error) {
      console.error('Google Safe Browsing API Error:', error);
      return {
        success: false,
        error: error.message,
        isSafe: null,
        source: 'Google Safe Browsing (Live - Failed)',
        message: `API connection failed: ${error.message}. Check CORS settings or API key validity.`
      };
    }
  }

  /**
   * Scans a URL via VirusTotal API (v3) if key exists, otherwise mocks results.
   * @param {string} targetUrl 
   * @param {string} apiKey 
   * @returns {Promise<Object>} VirusTotal report
   */
  static async scanVirusTotal(targetUrl, apiKey = '') {
    if (!apiKey) {
      // Simulation mode
      return new Promise(resolve => {
        setTimeout(() => {
          const parsed = new URL(targetUrl);
          const matchesPhish = this.KNOWN_PHISHING_DOMAINS.includes(parsed.hostname.toLowerCase());
          
          if (matchesPhish) {
            resolve({
              scanned: true,
              malicious: 48,
              suspicious: 2,
              harmless: 12,
              undetected: 18,
              ratio: '48 / 80 engines flagged',
              source: 'VirusTotal (Simulated)',
              isThreat: true
            });
          } else {
            const hasSuspiciousHeuristics = targetUrl.length > 80 || targetUrl.includes('@');
            resolve({
              scanned: true,
              malicious: hasSuspiciousHeuristics ? 2 : 0,
              suspicious: hasSuspiciousHeuristics ? 1 : 0,
              harmless: 72,
              undetected: 6,
              ratio: hasSuspiciousHeuristics ? '2 / 78 engines flagged' : '0 / 78 engines flagged',
              source: 'VirusTotal (Simulated)',
              isThreat: hasSuspiciousHeuristics
            });
          }
        }, 800);
      });
    }

    try {
      // VirusTotal v3 requires a base64 encoded URL identifier (without padding)
      const rawBase64 = btoa(targetUrl);
      const urlId = rawBase64.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
      
      const response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
        method: 'GET',
        headers: {
          'x-apikey': apiKey,
          'Accept': 'application/json'
        }
      });

      if (response.status === 404) {
        // Domain has not been analyzed yet, we submit it for analysis
        return await this.submitVirusTotalForScan(targetUrl, apiKey);
      }

      if (!response.ok) {
        throw new Error(`VirusTotal request failed: ${response.status}`);
      }

      const data = await response.json();
      const stats = data.data.attributes.last_analysis_stats;
      const total = stats.malicious + stats.suspicious + stats.harmless + stats.undetected;
      
      return {
        scanned: true,
        malicious: stats.malicious,
        suspicious: stats.suspicious,
        harmless: stats.harmless,
        undetected: stats.undetected,
        ratio: `${stats.malicious} / ${total} engines flagged`,
        source: 'VirusTotal (Live)',
        isThreat: stats.malicious > 0 || stats.suspicious > 0
      };

    } catch (error) {
      console.error('VirusTotal API Error:', error);
      return {
        success: false,
        error: error.message,
        source: 'VirusTotal (Live - Failed)',
        isThreat: null,
        ratio: 'API connection failed'
      };
    }
  }

  /**
   * Helper to request VirusTotal scan for new/unscanned URLs.
   */
  static async submitVirusTotalForScan(targetUrl, apiKey) {
    try {
      const response = await fetch('https://www.virustotal.com/api/v3/urls', {
        method: 'POST',
        headers: {
          'x-apikey': apiKey,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({ url: targetUrl })
      });

      if (!response.ok) {
        throw new Error(`VT URL submission failed: ${response.status}`);
      }

      return {
        scanned: false,
        source: 'VirusTotal (Live - Submitted)',
        ratio: 'Queued for scan',
        message: 'The URL was submitted to VirusTotal for live analysis. Re-scan in 30 seconds for results.'
      };
    } catch (e) {
      return {
        success: false,
        error: e.message,
        source: 'VirusTotal (Live - Failed Submission)',
        ratio: 'Scan submission failed'
      };
    }
  }
}
