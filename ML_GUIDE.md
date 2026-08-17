# Machine Learning Decision Weights Contribution Guide

This guide explains how the client-side Machine Learning engine in the URL Phishing Detection System works, including feature extraction, logistic regression mathematics, and how the **ML Decision Weights Contribution** is computed and visualized.

---

## 1. Architectural Overview

Phishing detection systems typically rely either on static blacklists (which fail against zero-day domains) or heavy server-side deep learning models (which introduce latency and privacy concerns). 

Our system uses a **client-side Logistic Regression Classifier** implemented in [ml_model.js](file:///c:/Users/shivp/OneDrive/Desktop/URL%20Phishing%20Detection/ml_model.js). This allows the application to:
1. Run instantly in the user's browser with zero network latency.
2. Protect user privacy by evaluating URLs locally.
3. Provide **explainable AI (XAI)** by displaying which factors led to a classification.

---

## 2. Mathematical Foundation

Logistic Regression is a classification algorithm used to predict the probability of a binary outcome (e.g., `0 = Safe`, `1 = Phishing`).

### The Sigmoid Function
The model calculates a weighted linear combination of input features ($z$), then applies the **logistic (sigmoid) function** to map the result into a probability score ($P$) between $0$ and $1$ ($0\%$ to $100\%$):

$$P(\text{Phishing}) = \sigma(z) = \frac{1}{1 + e^{-z}}$$

Where:
$$z = \beta_0 + \sum_{i=1}^{n} w_i x_i$$

* $\beta_0$ is the **Bias / Intercept** (`BIAS = -2.8` in our model).
* $w_i$ is the weight coefficient assigned to feature $i$.
* $x_i$ is the value of feature $i$.

---

## 3. Features & Weight Matrix

The features are extracted by [heuristics.js](file:///c:/Users/shivp/OneDrive/Desktop/URL%20Phishing%20Detection/heuristics.js) and normalized by `MLModelEngine.extractModelFeatures()` to create the feature vector $x$:

| Feature Key | Description | Offset / Normalization | Weight ($w_i$) |
| :--- | :--- | :--- | :---: |
| `isHttp` | Protocol is HTTP instead of HTTPS | Binary (0 or 1) | **1.25** |
| `hasIPAddress` | Domain is a raw IP address | Binary (0 or 1) | **2.50** |
| `hasAtSymbol` | URL contains `@` symbol | Binary (0 or 1) | **2.00** |
| `hasDoubleSlash` | Redirection pattern `//` in path | Binary (0 or 1) | **1.80** |
| `isSuspiciousTld` | Domain suffix matches high-abuse TLDs | Binary (0 or 1) | **1.40** |
| `keywordCountDomain` | Sensitive keywords in domain/subdomain | Count (e.g., `1`, `2`) | **2.20** |
| `keywordCountPath` | Sensitive keywords in path | Count (e.g., `1`, `2`) | **0.80** |
| `dashCountDomain` | Hyphens in domain name | Count - 1 (offset) | **0.45** |
| `dotCountDomain` | Dot characters in domain name | Count - 2 (offset) | **0.35** |
| `digitsInDomain` | Numbers in domain name | Count - 2 (offset) | **0.25** |
| `urlLengthFactor` | Excessive characters in full URL | Length - 50 (offset) | **0.012** |
| `pathDepthFactor` | Subdirectories count | Depth - 2 (offset) | **0.15** |
| `hasPort` | Targets non-standard ports | Binary (0 or 1) | **0.60** |

### Normalization Offsets
Offsets prevent standard/benign patterns from triggering warnings. For example:
* `dotCountDomain` has an offset of `-2`. A URL like `wikipedia.org` has $1$ dot, resulting in a feature value of $0$. A URL like `login.secure.paypal.com.example.com` has $5$ dots, resulting in a feature value of $3$ ($5 - 2$), contributing $3 \times 0.35 = 1.05$ to $z$.

---

## 4. Calculating Decision Weights Contribution

To make the machine learning model transparent, we decompose the linear score ($z$) to compute the **impact** ($c_i$) of each active feature:

$$c_i = w_i \times x_i$$

### Example Calculation
Let's analyze a suspicious URL: `http://login-paypal-security.com/webscr`

1. **Feature Extraction & Normalization ($x_i$)**:
   * `isHttp` = 1 (Unencrypted)
   * `keywordCountDomain` = 1 ("paypal" in domain)
   * `dashCountDomain` = 2 - 1 = 1 ("login-paypal-security" contains 2 dashes)
   * `urlLength` = 39 (under 50, so `urlLengthFactor` = 0)
   * All other features = 0
2. **Computing Linear Score ($z$)**:
   $$z = \text{BIAS} + (w_{\text{isHttp}} \cdot x_{\text{isHttp}}) + (w_{\text{keywordCountDomain}} \cdot x_{\text{keywordCountDomain}}) + (w_{\text{dashCountDomain}} \cdot x_{\text{dashCountDomain}})$$
   $$z = -2.8 + (1.25 \cdot 1) + (2.20 \cdot 1) + (0.45 \cdot 1)$$
   $$z = -2.8 + 1.25 + 2.20 + 0.45 = 1.10$$
3. **Evaluating Probability ($P$)**:
   $$P(\text{Phishing}) = \frac{1}{1 + e^{-1.10}} = \frac{1}{1 + 0.3329} \approx 0.75\% \text{ (High Risk / Suspicious boundary)}$$
4. **Active Contributions ($c_i > 0$)**:
   * Brand Keywords in Domain: $+2.20$ impact
   * Unencrypted Connection: $+1.25$ impact
   * Excessive Dashes: $+0.45$ impact

### Visualizing on the Dashboard
The dashboard captures these positive contributions ($c_i$), sorts them descending by their impact value, and scales them as a percentage relative to the maximum active feature score. These are rendered as glowing neon horizontal bar charts to show the user exactly why the ML model flagged the threat.
