/**
 * URL Phishing Detection System
 * Client-Side Machine Learning Engine (Logistic Regression)
 */

export class MLModelEngine {
  // Logistic regression weights for extracted URL features
  static WEIGHTS = {
    isHttp: 1.25,                  // HTTP protocol instead of HTTPS
    hasIPAddress: 2.5,            // Using a raw IP address as domain
    hasAtSymbol: 2.0,             // `@` symbol redirects traffic
    hasDoubleSlash: 1.8,          // Path redirection '//'
    isSuspiciousTld: 1.4,         // Cheap or abusive TLD
    keywordCountDomain: 2.2,       // Brand keywords in subdomain/domain
    keywordCountPath: 0.8,         // Brand keywords in file path
    dashCountDomain: 0.45,        // Hyphens in domain
    dotCountDomain: 0.35,         // Excessive subdomains
    digitsInDomain: 0.25,         // Random digits in domain
    urlLengthFactor: 0.012,       // Length of URL over 50 characters
    pathDepthFactor: 0.15,        // Depth of path structure
    hasPort: 0.6                  // Non-standard port number
  };

  // Model intercept (bias)
  // Ensures clean, standard URLs result in a very low probability (< 5%)
  static BIAS = -2.8;

  /**
   * Translates raw heuristic features into model-friendly numeric features.
   * @param {Object} rawFeatures 
   * @returns {Object} Normalized feature vector.
   */
  static extractModelFeatures(rawFeatures) {
    const f = {};

    f.isHttp = rawFeatures.isHttps === 0 ? 1 : 0;
    f.hasIPAddress = rawFeatures.hasIPAddress || 0;
    f.hasAtSymbol = rawFeatures.hasAtSymbol || 0;
    f.hasDoubleSlash = rawFeatures.hasDoubleSlash || 0;
    f.isSuspiciousTld = rawFeatures.isSuspiciousTld || 0;
    
    // Keywords
    f.keywordCountDomain = rawFeatures.keywordCountDomain || 0;
    f.keywordCountPath = rawFeatures.keywordCountPath || 0;

    // Counts with offsets (only trigger above typical/benign counts)
    f.dashCountDomain = Math.max(0, (rawFeatures.dashCountDomain || 0) - 1);
    f.dotCountDomain = Math.max(0, (rawFeatures.dotCountDomain || 0) - 2); // e.g. domain.co.uk is 2 dots, clean
    f.digitsInDomain = Math.max(0, (rawFeatures.digitsInDomain || 0) - 2);
    
    // Length calculations
    f.urlLengthFactor = Math.max(0, (rawFeatures.urlLength || 0) - 50);
    f.pathDepthFactor = Math.max(0, (rawFeatures.pathDepth || 0) - 2);
    
    f.hasPort = rawFeatures.hasPort || 0;

    return f;
  }

  /**
   * Applies logistic regression on the features.
   * @param {Object} rawFeatures 
   * @returns {Object} ML decision details containing probability and feature weights contributions.
   */
  static predict(rawFeatures) {
    if (!rawFeatures || Object.keys(rawFeatures).length === 0) {
      return { probability: 0, contributions: [], decision: 'Safe' };
    }

    const modelFeatures = this.extractModelFeatures(rawFeatures);
    let linearCombination = this.BIAS;
    const contributions = [];

    // Calculate w_i * x_i
    for (const [key, weight] of Object.entries(this.WEIGHTS)) {
      const val = modelFeatures[key] || 0;
      const score = val * weight;
      linearCombination += score;

      if (score > 0) {
        contributions.push({
          feature: key,
          value: val,
          weight: weight,
          impact: score,
          label: this.getFeatureLabel(key)
        });
      }
    }

    // Sigmoid function: P(Y=1) = 1 / (1 + e^-z)
    const probability = 1 / (1 + Math.exp(-linearCombination));
    
    // Sort contributions by impact descending
    contributions.sort((a, b) => b.impact - a.impact);

    let decision = 'Safe';
    if (probability > 0.75) {
      decision = 'High Risk';
    } else if (probability > 0.4) {
      decision = 'Suspicious';
    }

    return {
      probability,
      linearCombination,
      contributions,
      decision
    };
  }

  /**
   * Helper to format technical feature keys into user-friendly names.
   * @param {string} key 
   * @returns {string} Friendly label.
   */
  static getFeatureLabel(key) {
    const labels = {
      isHttp: 'Unencrypted Connection (HTTP)',
      hasIPAddress: 'IP Address as Domain',
      hasAtSymbol: 'Obfuscated Destination (@ symbol)',
      hasDoubleSlash: 'Redirection Pattern (// in path)',
      isSuspiciousTld: 'Suspicious TLD Usage',
      keywordCountDomain: 'Brand Keywords in Domain',
      keywordCountPath: 'Brand Keywords in URL Path',
      dashCountDomain: 'Excessive Dashes in Domain',
      dotCountDomain: 'Excessive Subdomains',
      digitsInDomain: 'Multiple Digits in Domain',
      urlLengthFactor: 'Long URL Structure',
      pathDepthFactor: 'Deep Subdirectories',
      hasPort: 'Non-standard Network Port'
    };
    return labels[key] || key;
  }
}
