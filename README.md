#  Enterprise Web Security Scanner v8.0

**A powerful automated web vulnerability scanner for penetration testing and security assessments**

[![Version](https://img.shields.io/badge/version-8.0-blue.svg)](https://github.com/RicheByte/MonkeyScripts)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tampermonkey](https://img.shields.io/badge/Tampermonkey-compatible-orange.svg)](https://www.tampermonkey.net/)


![Demo Photo](/image.png)

---

##  DISCLAIMER

**USE WITH CAUTION - BETA SOFTWARE**

This tool is currently in BETA and may contain bugs. Only use this scanner on:
-  Your own websites
-  Applications you have explicit permission to test
-  Authorized penetration testing engagements

**Unauthorized scanning of websites is ILLEGAL and UNETHICAL.**

---

##  Features

### Comprehensive Vulnerability Detection (11+ Types)

| Vulnerability Type | Detection Method | Severity |
|-------------------|------------------|----------|
| **SQL Injection** | Error-based, Boolean-blind, Time-blind | 🔴 HIGH |
| **Cross-Site Scripting (XSS)** | Reflected, DOM-based, Encoded | 🔴 HIGH |
| **XML External Entity (XXE)** | File disclosure, SSRF via XXE | 🔴 HIGH |
| **Server-Side Request Forgery (SSRF)** | AWS/GCP metadata, Internal network | 🔴 CRITICAL |
| **Command Injection** | OS command execution | 🔴 HIGH |
| **Path Traversal** | File system access | 🟠 MEDIUM |
| **SSTI (Template Injection)** | Template engine exploitation | 🔴 CRITICAL |
| **NoSQL Injection** | MongoDB, Redis, CouchDB | 🔴 HIGH |
| **LDAP Injection** | Directory service attacks | 🔴 HIGH |
| **Open Redirect** | Unvalidated redirects | 🟠 MEDIUM |
| **CRLF Injection** | HTTP response splitting | 🟠 MEDIUM |

### Advanced Features

####  **Performance Optimizations (2.5x Faster)**
- **Request Queue Manager** - Priority-based, retry logic, 5-minute response cache
- **Concurrent Requests** - 8 parallel requests (166% increase from v7.0)
- **Smart URL Deduplication** - Avoids retesting similar patterns
- **Parallel Batch Processing** - Tests multiple vulnerabilities simultaneously
- **Enhanced Coverage** - 150 pages, depth 4 (100% more than v7.0)
- **Response Caching** - Reduces redundant requests by ~40%

####  **Accuracy Improvements**
- **False Positive Filtering** - Baseline response comparison
- **Evidence-Based Confidence Scoring** - Multi-stage verification
- **Generic Error Page Detection** - Filters common false positives
- **Response Hash & Length Analysis** - Detects meaningful changes
- **Context-Aware Detection** - Understands execution context

####  **Smart Fuzzing Engine**
- **Payload Mutation** - URL/hex/unicode/base64 encoding
- **Case Variation Bypass** - Evades basic filters
- **Null Byte Injection** - Tests boundary conditions
- **Context-Aware Generation** - Adapts to application type

####  **Anti-Detection System**
- **Advanced User-Agent Rotation** - 9+ realistic browser profiles
- **IP Header Rotation** - X-Forwarded-For, X-Real-IP, CF-Connecting-IP
- **WAF Detection & Bypass** - Identifies and attempts to evade WAFs
- **Human Behavior Simulation** - Mouse movement, scrolling, reading time
- **Adaptive Rate Limiting** - Adjusts speed based on server response
- **Traffic Pattern Randomization** - Mimics natural browsing

####  **Professional PDF Reports**
- **Clean, Static PDF Format** - No HTML, no action scripts
- **Color-Coded Severity** - Visual severity indicators
- **Detailed Findings** - URL, payload, evidence, confidence
- **Security Recommendations** - Actionable remediation steps
- **Executive Summary** - Statistics and vulnerability breakdown
- **Page Numbering & Footers** - Professional formatting

---

##  Installation

### Prerequisites
- **Tampermonkey** or **Greasemonkey** browser extension
- Modern web browser (Chrome, Firefox, Edge, Safari)

### Installation Steps

1. **Install Tampermonkey**
   - [Chrome Web Store](https://chrome.google.com/webstore/detail/tampermonkey/dhdgffkkebhmkfjojejmpbldmpobfkfo)
   - [Firefox Add-ons](https://addons.mozilla.org/en-US/firefox/addon/tampermonkey/)
   - [Edge Add-ons](https://microsoftedge.microsoft.com/addons/detail/tampermonkey/iikmkjmpaadaobahmlepeloendndfphd)

2. **Install the Script**
   - Click on the Tampermonkey icon in your browser
   - Select "Create a new script"
   - Copy the entire contents of `script..ts`
   - Paste into the editor
   - Save (Ctrl+S or Cmd+S)

3. **Enable the Script**
   - Ensure the script is enabled in Tampermonkey dashboard
   - Navigate to a website you have permission to test

---

##  Usage

### Quick Start

1. **Navigate to Target Website**
   ```
   Open the website you want to scan in your browser
   ```

2. **Scanner UI Appears**
   - The scanner interface loads automatically
   - Located in the bottom-right corner of the page

3. **Start Scanning**
   - Click **"Start Scan"** button
   - Scanner begins automated deep crawl and testing

4. **Monitor Progress**
   - Watch real-time discovery feed
   - View vulnerability count
   - Track pages scanned

5. **Generate Report**
   - Scan completes automatically
   - Click **"📄 Report"** for PDF download
   - Review findings and recommendations

### Scanner Controls

| Button | Function |
|--------|----------|
| **▶️ Start Scan** | Begin automated security scan |
| **⏸️ Pause** | Pause the current scan |
| **▶️ Resume** | Resume a paused scan |
| **⏹️ Stop** | Stop the scan completely |
| **📄 Report** | Generate and download PDF report |
| **👁️ Toggle** | Show/hide scanner interface |

### Configuration Options

Edit the `scanConfig` object in the code to customize behavior:

```javascript
scanConfig: {
    maxConcurrentRequests: 8,      // Parallel requests
    requestDelay: 800,              // Delay between requests (ms)
    maxPages: 150,                  // Maximum pages to crawl
    scanDepth: 4,                   // Crawl depth
    timeout: 15000,                 // Request timeout (ms)
    autoStart: true,                // Start scan automatically
    enableCaching: true,            // Enable response caching
    aggressiveMode: false,          // Fast scanning (500ms delay)
    deepScan: true,                 // Test all 11 vulnerabilities
    smartFuzzing: true,             // Enable payload mutation
    strictDomainMode: true,         // Block cross-domain requests
    adaptiveRateLimiting: true      // Adjust speed dynamically
}
```

---

##  How It Works

### Phase 1: Deep Crawling
- Discovers all links, forms, and resources
- Extracts parameters from URLs, forms, and JavaScript
- Detects frameworks (React, Vue, Angular, WordPress, etc.)
- Finds AJAX endpoints and API routes
- Priority crawling (admin/API routes first)

### Phase 2: Vulnerability Testing
- Tests each endpoint with vulnerability-specific payloads
- Runs multiple detection methods per vulnerability type
- Collects evidence from responses
- Calculates confidence scores
- Filters false positives

### Phase 3: Security Headers Check
- Validates presence of security headers:
  - Content-Security-Policy
  - X-Frame-Options
  - X-Content-Type-Options
  - Strict-Transport-Security
  - Referrer-Policy

### Phase 4: Report Generation
- Compiles all findings
- Generates professional PDF report
- Includes recommendations
- Exports JSON data

---

##  Detection Methodologies

### SQL Injection
1. **Error-Based** - Triggers database errors (60+ payloads)
2. **Boolean-Blind** - True/false condition testing
3. **Time-Blind** - Response time analysis (SLEEP, WAITFOR)
4. **Out-of-Band** - DNS/HTTP exfiltration attempts

### XSS (Cross-Site Scripting)
1. **Reflection Detection** - Payload appears in response
2. **Context Analysis** - Script tags, event handlers
3. **DOM Sink Detection** - innerHTML, document.write, eval
4. **Encoding Bypass** - URL, hex, unicode encoding

### XXE (XML External Entity)
1. **File Disclosure** - /etc/passwd, win.ini content
2. **Error Messages** - XML parser errors
3. **SSRF via XXE** - AWS/GCP metadata access
4. **Entity Processing** - Detects XML entity expansion

### SSRF (Server-Side Request Forgery)
1. **Metadata Exposure** - AWS EC2, GCP instance data
2. **Internal Network Access** - Localhost, 127.0.0.1
3. **File Protocol** - file:// URL access
4. **Service Detection** - Internal service probing

### Command Injection
1. **Error Patterns** - Shell error messages
2. **Command Output** - Successful execution indicators
3. **Time-Based** - Sleep/delay commands
4. **Out-of-Band** - DNS/HTTP callbacks

---

## 📊 Sample Report Output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Security Scan Report
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Generated: 2025-11-02 14:30:45
  Target: https://example.com
  Duration: 127.34 seconds
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Scan Summary
  Duration: 127.34 seconds
  Pages Scanned: 87
  Total Vulnerabilities Found: 12
  Critical Severity: 2
  High Severity: 5
  Medium Severity: 4
  Low Severity: 1

Vulnerabilities by Type
  SQL Injection: 3
  Cross-Site Scripting (XSS): 4
  SSRF: 2
  Missing Security Headers: 3

[Detailed findings with color-coded severity...]
[Security recommendations...]
```

---

## 🛠️ Technical Details

### Architecture
- **Anti-Detection System** - Evades WAFs and rate limiting
- **Request Queue Manager** - Handles concurrency and retries
- **Vulnerability Database** - 200+ attack patterns
- **False Positive Filter** - Baseline comparison engine
- **Adaptive Rate Limiter** - Dynamic delay adjustment
- **Domain Filter** - Prevents cross-domain scanning

### Technologies Used
- **jQuery** - DOM manipulation
- **jsPDF** - PDF report generation
- **CryptoJS** - Hashing and fingerprinting
- **DOMPurify** - Sanitization
- **Axios** - HTTP requests
- **GM API** - Tampermonkey functions

### Browser Compatibility
-  Chrome 90+
-  Firefox 88+
-  Edge 90+
-  Safari 14+
-  Opera 76+

---

## ⚙️ Advanced Configuration

### Aggressive Mode
```javascript
aggressiveMode: true        // 500ms delay, faster scanning
deepScan: true              // Test all 11 vulnerability types
maxConcurrentRequests: 12   // More parallel requests
```

### Stealth Mode
```javascript
aggressiveMode: false       // 2000ms delay, slower and stealthier
maxConcurrentRequests: 3    // Fewer parallel requests
adaptiveRateLimiting: true  // Adjust to server response time
```

### Quick Scan
```javascript
deepScan: false             // Test only SQL, XSS, Path Traversal
maxPages: 50                // Limit page crawling
scanDepth: 2                // Shallow crawl
```

---

##  Known Issues & Limitations

### Current Limitations
-  **BETA Software** - May contain bugs, use with caution
-  **SPA Limitations** - Heavy JavaScript apps may be partially scanned
-  **CAPTCHA/Auth** - Cannot bypass authentication automatically
-  **Rate Limiting** - Some WAFs may still block requests
-  **TypeScript Errors** - Code has type annotation warnings (functional)

### Known Issues
- Some false positives may still occur
- PDF generation requires jsPDF library to be loaded
- Large sites (1000+ pages) may take extended time
- Memory usage can be high on complex sites

---

##  Security & Ethics

### Responsible Use
This tool is designed for **authorized security testing only**. You must:

1.  **Have explicit permission** from the website owner
2.  **Test only your own applications** or authorized targets
3.  **Follow responsible disclosure** for any findings
4.  **Comply with local laws** and regulations
5.  **Never use for malicious purposes**

### Legal Notice
Unauthorized computer access is illegal in most jurisdictions. The authors assume **NO LIABILITY** for misuse of this tool. By using this scanner, you agree to use it responsibly and legally.

---

## 📝 Changelog

### Version 8.0 (Current)
-  Improved XSS detection with context analysis
-  Enhanced XXE detection with 12+ payloads
-  Fixed SSRF detection (AWS/GCP metadata)
-  Improved Open Redirect detection
-  Enhanced LDAP, NoSQL, SSTI, CRLF detection
-  Added evidence-based confidence scoring
-  Professional PDF reports (no HTML/action scripts)
-  Better false positive filtering
-  Performance optimizations (2.5x faster)

### Version 7.0
- Added 11 vulnerability types
- Request queue manager
- Smart deduplication
- Framework detection

---

##  Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

##  License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

##  Author

**RicheByte**
- GitHub: [@RicheByte](https://github.com/RicheByte)
- Repository: [MonkeyScripts](https://github.com/RicheByte/MonkeyScripts)

---

##  Acknowledgments

- jsPDF library for PDF generation
- Tampermonkey community for UserScript support
- OWASP for vulnerability research and documentation
- Security researchers for testing methodologies

---

##  Support

For issues, questions, or suggestions:
-  [Report a Bug](https://github.com/RicheByte/MonkeyScripts/issues)
-  [Request a Feature](https://github.com/RicheByte/MonkeyScripts/issues)
-  Contact via GitHub

---

**Remember: With great power comes great responsibility. Use this tool ethically and legally.**

⭐ If you find this tool useful, please star the repository!


