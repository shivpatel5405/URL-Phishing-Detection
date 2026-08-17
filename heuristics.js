/**
 * URL Phishing Detection System
 * Heuristics Analysis Engine
 */

export class HeuristicsEngine {
  // Highly abused Top-Level Domains (TLDs) frequently associated with phishing
  static SUSPICIOUS_TLDS = new Set([
    'xyz', 'top', 'info', 'work', 'tk', 'fit', 'gq', 'cf', 'ga', 'ml',
    'cc', 'club', 'site', 'vip', 'icu', 'tokyo', 'bid', 'stream', 'win',
    'men', 'loan', 'date', 'download', 'racing', 'online', 'party', 'click'
  ]);

  // Sensitive keywords commonly spoofed in phishing URLs
  static SENSITIVE_KEYWORDS = [
    'paypal', 'secure', 'login', 'bank', 'update', 'verification', 'support',
    'signin', 'ebay', 'amazon', 'netflix', 'microsoft', 'office365', 'apple',
    'google', 'account', 'verify', 'billing', 'wallet', 'blockchain', 'coinbase',
    'security', 'recover', 'confirm', 'service', 'portal', 'webscr', 'cmd'
  ];

  /**
   * Cleans and formats a raw URL string, ensuring it has a protocol.
   * @param {string} urlStr 
   * @returns {string}
   */
  static cleanURL(urlStr) {
    let cleaned = urlStr.trim();
    if (!cleaned) return '';

    // Add protocol if missing
    if (!/^https?:\/\//i.test(cleaned)) {
      cleaned = 'http://' + cleaned;
    }

    return cleaned;
  }

  /**
   * Helper to verify if hostname is an IP address.
   * @param {string} hostname 
   * @returns {boolean}
   */
  static isIPAddress(hostname) {
    // IPv4 RegEx
    const ipv4Pattern = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    // IPv6 RegEx (approximate check)
    const ipv6Pattern = /^\[?[a-fA-F0-9:]+\]?$/;

    return ipv4Pattern.test(hostname) || (hostname.includes(':') && ipv6Pattern.test(hostname));
  }

  /**
   * Parses the URL and runs heuristic checks.
   * @param {string} rawUrl 
   * @returns {Object} Analysis results containing features, flags, and score.
   */
  static analyze(rawUrl) {
    const cleaned = this.cleanURL(rawUrl);
    let parsed = null;
    const flags = [];
    const features = {};

    try {
      parsed = new URL(cleaned);
    } catch (e) {
      // Invalid URL fallback
      return {
        isValid: false,
        error: 'Invalid URL format',
        score: 0,
        flags: [{
          id: 'invalid_url',
          severity: 'high',
          category: 'Structure',
          message: 'The URL could not be parsed successfully.'
        }],
        features: {}
      };
    }

    const { href, hostname, pathname, search, protocol, port } = parsed;

    // 1. URL Length Heuristics
    features.urlLength = href.length;
    if (href.length > 75) {
      flags.push({
        id: 'url_too_long',
        severity: href.length > 100 ? 'high' : 'medium',
        category: 'Structure',
        message: `URL length is extremely long (${href.length} chars). Phishing URLs often use lengthy parameters to hide the true destination.`
      });
    }

    // 2. Domain Length
    features.domainLength = hostname.length;
    if (hostname.length > 30) {
      flags.push({
        id: 'domain_too_long',
        severity: 'medium',
        category: 'Domain',
        message: `Domain name is suspiciously long (${hostname.length} chars).`
      });
    }

    // 3. HTTPS Protocol check
    const isHttps = protocol.toLowerCase() === 'https:';
    features.isHttps = isHttps ? 1 : 0;
    if (!isHttps) {
      flags.push({
        id: 'not_https',
        severity: 'high',
        category: 'Security',
        message: 'Unencrypted connection (HTTP). Most legitimate login pages today mandate HTTPS encryption.'
      });
    }

    // 4. IP Address Domain Check
    const hasIP = this.isIPAddress(hostname);
    features.hasIPAddress = hasIP ? 1 : 0;
    if (hasIP) {
      flags.push({
        id: 'ip_address_domain',
        severity: 'high',
        category: 'Domain',
        message: 'URL domain is a raw IP address rather than a registered domain. Legitimate companies rarely use raw IPs for public sites.'
      });
    }

    // 5. At Symbol (@) Check
    const hasAt = href.includes('@');
    features.hasAtSymbol = hasAt ? 1 : 0;
    if (hasAt) {
      flags.push({
        id: 'has_at_symbol',
        severity: 'high',
        category: 'Structure',
        message: 'URL contains the "@" symbol. Browsers ignore everything before "@", directing the user to the domain that follows, which is a common obfuscation technique.'
      });
    }

    // 6. Double Slash Redirect Check
    // We check if '//' appears anywhere in the path after the initial protocol slashes
    const hasDoubleSlash = pathname.includes('//') || search.includes('//');
    features.hasDoubleSlash = hasDoubleSlash ? 1 : 0;
    if (hasDoubleSlash) {
      flags.push({
        id: 'double_slash_redirect',
        severity: 'high',
        category: 'Structure',
        message: 'URL contains "//" in the path or query, which can trigger an open redirection anomaly.'
      });
    }

    // 7. Dash in Domain (Hyphen count)
    const dashesInDomain = (hostname.match(/-/g) || []).length;
    features.dashCountDomain = dashesInDomain;
    if (dashesInDomain > 1) {
      flags.push({
        id: 'multiple_dashes_in_domain',
        severity: 'medium',
        category: 'Domain',
        message: `Domain contains multiple dashes (${dashesInDomain}). Phishing sites frequently use hyphenated combinations like 'secure-bank-login'.`
      });
    }

    // 8. Subdomains Count (Dot count in hostname)
    // For standard domains, there should be at most 2 dots (e.g. www.example.com). More than 3 is suspicious.
    const dotsInDomain = (hostname.match(/\./g) || []).length;
    features.dotCountDomain = dotsInDomain;
    if (dotsInDomain > 3) {
      flags.push({
        id: 'excessive_subdomains',
        severity: 'high',
        category: 'Domain',
        message: `URL contains an excessive number of subdomains (${dotsInDomain} dots). Phishers use nested subdomains to impersonate brand names.`
      });
    }

    // 9. Numeric digits count in domain
    const digitsInDomain = (hostname.match(/\d/g) || []).length;
    features.digitsInDomain = digitsInDomain;
    if (digitsInDomain > 3) {
      flags.push({
        id: 'excessive_digits_in_domain',
        severity: 'medium',
        category: 'Domain',
        message: `Domain name contains multiple numerical digits (${digitsInDomain}). Legitimate brands rarely use random numbers in their domains.`
      });
    }

    // 10. Non-Standard Port check
    // Safe standard ports: HTTP (80), HTTPS (443)
    features.hasPort = port ? 1 : 0;
    if (port && port !== '80' && port !== '443') {
      flags.push({
        id: 'non_standard_port',
        severity: 'medium',
        category: 'Security',
        message: `URL targets a non-standard port (${port}). Legitimate web traffic typically runs on port 80 or 443.`
      });
    }

    // 11. Suspicious TLD Check
    const parts = hostname.split('.');
    const tld = parts[parts.length - 1].toLowerCase();
    const isSuspiciousTld = this.SUSPICIOUS_TLDS.has(tld);
    features.isSuspiciousTld = isSuspiciousTld ? 1 : 0;
    if (isSuspiciousTld) {
      flags.push({
        id: 'suspicious_tld',
        severity: 'medium',
        category: 'Domain',
        message: `URL uses a highly abused TLD (.${tld}). These TLDs are cheap or free to register and commonly used in automated phishing campaigns.`
      });
    }

    // 12. Sensitive Brand/Keyword Spoofing
    let keywordCountDomain = 0;
    let keywordCountPath = 0;
    const flaggedKeywords = [];

    const domainToSearch = hostname.toLowerCase();
    const pathToSearch = (pathname + search).toLowerCase();

    // To prevent false positives on primary domains (e.g. apple.com should not flag "apple"),
    // we inspect subdomains or checks if the keyword is part of a longer hyphenated string.
    this.SENSITIVE_KEYWORDS.forEach(keyword => {
      // Check in domain
      if (domainToSearch.includes(keyword)) {
        // If it's a subdomain, or part of a hyphenated segment, it's highly suspicious.
        // e.g. "paypal.com-login.xyz" or "login-paypal-verify.com"
        const isExactPrimaryDomain = parts.length >= 2 &&
          (parts[parts.length - 2].toLowerCase() === keyword);

        if (!isExactPrimaryDomain) {
          keywordCountDomain++;
          flaggedKeywords.push(keyword);
        }
      }

      // Check in path/query
      if (pathToSearch.includes(keyword)) {
        keywordCountPath++;
        flaggedKeywords.push(keyword);
      }
    });

    features.keywordCountDomain = keywordCountDomain;
    features.keywordCountPath = keywordCountPath;

    if (keywordCountDomain > 0) {
      flags.push({
        id: 'keyword_brand_spoofing',
        severity: 'high',
        category: 'Domain',
        message: `URL contains brand spoofing keywords in the subdomain or domain name: [${flaggedKeywords.join(', ')}].`
      });
    } else if (keywordCountPath > 0) {
      flags.push({
        id: 'keyword_in_path',
        severity: 'medium',
        category: 'Structure',
        message: `URL contains sensitive login/brand keywords in path or query parameters: [${flaggedKeywords.join(', ')}].`
      });
    }

    // 13. Path Depth (Subdirectory count)
    const slashesInPath = (pathname.match(/\//g) || []).length;
    features.pathDepth = slashesInPath;
    if (slashesInPath > 4) {
      flags.push({
        id: 'deep_path',
        severity: 'medium',
        category: 'Structure',
        message: `URL has a deeply nested file path (${slashesInPath} directories). Used to bury suspicious filenames.`
      });
    }

    // Calculate Heuristics Threat Score (0 to 100)
    let heuristicScore = 0;
    flags.forEach(flag => {
      if (flag.severity === 'high') {
        heuristicScore += 25;
      } else if (flag.severity === 'medium') {
        heuristicScore += 10;
      } else {
        heuristicScore += 5;
      }
    });

    // Cap the score at 100
    heuristicScore = Math.min(heuristicScore, 100);

    return {
      isValid: true,
      href,
      hostname,
      protocol,
      tld,
      score: heuristicScore,
      flags,
      features
    };
  }
}
