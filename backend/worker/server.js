const express = require('express');
const { chromium } = require('playwright');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

app.post('/scan', async (req, res) => {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'URL is required' });

    console.log(`🛡️ Worker starting deep scan for: ${url}`);

    let browser;
    try {
        browser = await chromium.launch({
            headless: true,
            args: ['--no-sandbox', '--disable-setuid-sandbox']
        });

        const context = await browser.newContext();
        const page = await context.newPage();

        const media = {
            player: "Scanning...",
            streams: []
        };

        // Monitor network traffic (Requests & Responses)
        const interceptedTraffic = new Map();
        const staticAssets = { scripts: [], styles: [], images: [], fonts: [], documents: [] };

        page.on('request', request => {
            const reqUrl = request.url();
            const type = request.resourceType();

            if (['xhr', 'fetch'].includes(type) || reqUrl.includes('/api/') || reqUrl.includes('/v1/')) {
                interceptedTraffic.set(reqUrl, {
                    method: request.method(),
                    url: reqUrl,
                    type: type,
                    status: 'PENDING'
                });
            }

            if (type === 'script') staticAssets.scripts.push(reqUrl);
            if (type === 'stylesheet') staticAssets.styles.push(reqUrl);
            if (type === 'font') staticAssets.fonts.push(reqUrl);

            // Enhanced media detection
            if (type === 'image') {
                staticAssets.images.push({
                    url: reqUrl,
                    ext: reqUrl.split('.').pop().split(/[?#]/)[0],
                    size: request.headers()['content-length'] || 'N/A'
                });
            }

            // Document detection
            if (reqUrl.match(/\.(pdf|doc|docx|xls|xlsx|ppt|pptx|txt|csv)$/i)) {
                staticAssets.documents.push({
                    url: reqUrl,
                    type: reqUrl.split('.').pop().toUpperCase()
                });
            }

            if (['video', 'media'].includes(type) || reqUrl.includes('.m3u8') || reqUrl.includes('.mpd') || reqUrl.includes('.mp4') || reqUrl.includes('.webm')) {
                media.streams.push({
                    url: reqUrl,
                    type: type,
                    mime: request.headers()['content-type'] || 'unknown'
                });
            }
        });

        const securityHeaders = {};
        page.on('response', response => {
            const reqUrl = response.url();

            // Extract security headers from the main document
            if (reqUrl === url || reqUrl === url + '/') {
                const headers = response.headers();
                securityHeaders.hsts = headers['strict-transport-security'] || 'Missing';
                securityHeaders.xFrame = headers['x-frame-options'] || 'Missing';
                securityHeaders.xContent = headers['x-content-type-options'] || 'Missing';
                securityHeaders.server = headers['server'] || 'Protected';
                securityHeaders.csp = headers['content-security-policy'] || null;
            }

            if (interceptedTraffic.has(reqUrl)) {
                const data = interceptedTraffic.get(reqUrl);
                data.status = response.status();
                data.contentType = response.headers()['content-type'];
                interceptedTraffic.set(reqUrl, data);
            }
        });

        // Navigate with real behavior
        await page.goto(url, { waitUntil: 'networkidle', timeout: 60000 });

        // Final scroll to trigger lazy loads
        await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
        await new Promise(r => setTimeout(r, 3000));

        const endpoints = Array.from(interceptedTraffic.values());

        // Multi-Path Deep Discovery
        const discovery = {
            robots: "Checking...",
            securityTxt: "Checking...",
        };

        try {
            const robotsResp = await context.request.get(new URL('/robots.txt', url).href);
            discovery.robots = robotsResp.ok() ? await robotsResp.text() : 'Not Found';
        } catch (e) { discovery.robots = 'Error checking'; }

        // Deep extraction logic
        const auditData = await page.evaluate(() => {
            const getMeta = (name) => document.querySelector(`meta[name="${name}"], meta[property="${name}"]`)?.content || '';
            const getHeader = (selector) => document.querySelector(selector)?.innerText || '';

            // Simple Tech Stack Discovery
            const techs = [];
            if (window.React || document.querySelector('[data-reactroot]')) techs.push('React');
            if (window.Vue) techs.push('Vue.js');
            if (window.jQuery) techs.push('jQuery');
            if (window.next) techs.push('Next.js');
            if (document.querySelector('script[src*="tailwind"]')) techs.push('Tailwind CSS');
            if (document.querySelector('meta[name="generator"]')?.content?.includes('WordPress')) techs.push('WordPress');

            return {
                seo: {
                    title: document.title,
                    description: getMeta('description'),
                    ogTitle: getMeta('og:title'),
                    ogImage: getMeta('og:image'),
                    h1: getHeader('h1'),
                },
                structure: {
                    tags: ['HEADER', 'NAV', 'MAIN', 'FOOTER', 'ARTICLE', 'SECTION', 'ASIDE', 'FORM', 'VIDEO', 'CANVAS', 'SVG']
                        .filter(t => document.querySelector(t)),
                    links: Array.from(document.querySelectorAll('a')).map(a => ({
                        href: a.href,
                        text: a.innerText.trim(),
                        id: a.id,
                        class: a.className
                    })).filter(h => h.href.startsWith('http')).slice(0, 200),
                    images: Array.from(document.querySelectorAll('img')).map(img => ({
                        src: img.src,
                        alt: img.alt,
                        width: img.naturalWidth,
                        height: img.naturalHeight
                    })).filter(i => i.src.startsWith('http')).slice(0, 100),
                },
                performance: {
                    timing: window.performance.timing.toJSON(),
                    memory: window.performance.memory ? {
                        jsHeapSizeLimit: window.performance.memory.jsHeapSizeLimit,
                        totalJSHeapSize: window.performance.memory.totalJSHeapSize,
                        usedJSHeapSize: window.performance.memory.usedJSHeapSize
                    } : 'N/A'
                },
                security: {
                    hasHttps: window.location.protocol === 'https:',
                    hasManifest: !!document.querySelector('link[rel="manifest"]'),
                    hasCsp: !!document.querySelector('meta[http-equiv="Content-Security-Policy"]'),
                    cookies: document.cookie ? document.cookie.split(';').length : 0,
                    generator: document.querySelector('meta[name="generator"]')?.content || 'Custom Engine',
                    techStack: techs
                }
            };
        });

        media.player = await page.evaluate(() => {
            if (window.videojs) return "Video.js Engine";
            if (window.plyr) return "Plyr Engine";
            if (window.hls) return "Hls.js detected";
            if (document.querySelector('video')) return "Native HTML5 Video";
            return "No Active Video Element";
        });

        let score = 40;
        if (auditData.security.hasHttps) score += 20;
        if (auditData.security.hasCsp) score += 10;
        if (auditData.security.headers?.hsts && auditData.security.headers.hsts !== 'Missing') score += 10;
        if (auditData.security.headers?.xFrame && auditData.security.headers.xFrame !== 'Missing') score += 10;
        if (auditData.seo.description) score += 5;
        if (auditData.security.cookies > 0) score += 5;
        score = Math.min(score, 100);

        // Merge extra security info
        auditData.security.headers = securityHeaders;

        // --- PENTEST MODULE: SENSITIVE FILE PROBING (ENHANCED) ---
        const sensitiveFiles = ['.env', '.git/HEAD', 'wp-config.php.bak', 'backup.zip', 'id_rsa', 'debug.log'];
        
        // Severity classification
        const severityMap = {
            'id_rsa': 'CRITICAL',
            '.env': 'CRITICAL',
            '.git/HEAD': 'CRITICAL',
            'backup.zip': 'HIGH',
            'wp-config.php.bak': 'HIGH',
            'debug.log': 'MEDIUM',
            'robots.txt': 'INFO',
            'sitemap.xml': 'INFO',
            '.well-known/security.txt': 'INFO',
            'dashboard/': 'MEDIUM',
            'admin/': 'MEDIUM',
            'api/': 'LOW'
        };
        
        const exposedFiles = [];

        await Promise.all(sensitiveFiles.map(async (file) => {
            try {
                const probeUrl = new URL(file, url).href;
                const response = await context.request.get(probeUrl);
                
                // IMPROVEMENT 1: Validate content to avoid false positives
                if (response.ok() && response.status() === 200) {
                    const content = await response.text();
                    
                    // Check if it's not an error page
                    const isValidContent = 
                        !content.includes('404') && 
                        !content.includes('Not Found') &&
                        !content.includes('Page not found') &&
                        content.length > 100;
                    
                    if (isValidContent) {
                        exposedFiles.push({ 
                            file, 
                            status: response.status(), 
                            url: probeUrl,
                            severity: severityMap[file] || 'MEDIUM'
                        });
                    }
                }
            } catch (e) { /* ignore unreachable */ }
        }));

        // --- PENTEST MODULE: DARK MATTER SCANNER (ENHANCED) ---
        const darkMatterFiles = [
            'robots.txt', 'sitemap.xml', 'crossdomain.xml', 'clientaccesspolicy.xml',
            '.well-known/security.txt', '.well-known/apple-app-site-association',
            'admin/', 'administrator/', 'login/', 'dashboard/', 'api/',
            'config.json', 'config.js', 'package.json', 'composer.json',
            'docker-compose.yml', 'Dockerfile',
            '.DS_Store', 'thumbs.db'
        ];

        const darkMatterResults = [];

        // Concurrency limit for probes
        const batchSize = 5;
        for (let i = 0; i < darkMatterFiles.length; i += batchSize) {
            const batch = darkMatterFiles.slice(i, i + batchSize);
            await Promise.all(batch.map(async (file) => {
                try {
                    const probeUrl = new URL(file, url).href;
                    const response = await context.request.get(probeUrl, { timeout: 3000 });
                    
                    // IMPROVEMENT 1: Validate content
                    if (response.ok() && response.status() !== 404) {
                        const content = await response.text();
                        
                        const isValidContent = 
                            !content.includes('404') && 
                            !content.includes('Not Found') &&
                            content.length > 50;
                        
                        if (isValidContent) {
                            darkMatterResults.push({ 
                                file, 
                                status: response.status(), 
                                url: probeUrl,
                                severity: severityMap[file] || 'LOW'
                            });
                        }
                    }
                } catch (e) { /* ignore */ }
            }));
        }

        // Combine exposed files with dark matter results
        const finalExposedFiles = [...exposedFiles, ...darkMatterResults];

        // Remove duplicates based on URL
        const uniqueExposedFiles = finalExposedFiles.filter((v, i, a) => a.findIndex(t => (t.url === v.url)) === i);

        // --- PENTEST MODULE: SECRET DETECTION (DEEP SCAN) ---
        // 1. Scan Main Page Layout
        const pageContent = await page.content();

        const secretPatterns = [
            { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/g },
            { name: 'Google API Key', regex: /AIza[0-9A-Za-z\\-_]{35}/g },
            { name: 'Stripe Publishable Key', regex: /pk_live_[0-9a-zA-Z]{24}/g },
            { name: 'Private Key Block', regex: /-----BEGIN PRIVATE KEY-----/g },
            { name: 'Generic API Key', regex: /api_key\s*[:=]\s*['"][a-zA-Z0-9]{32,}['"]/gi },
            { name: 'JWT Token', regex: /eyJ[a-zA-Z0-9\-_]*\.[a-zA-Z0-9\-_]*\.[a-zA-Z0-9\-_]*/g },
            { name: 'Slack Webhook', regex: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+/g }
        ];

        const leakedSecrets = [];

        const scanTextForSecrets = (text, source) => {
            secretPatterns.forEach(pattern => {
                const matches = text.match(pattern.regex);
                if (matches) {
                    matches.slice(0, 3).forEach(match => { // Limit to 3 examples per pattern per source to avoid noise
                        leakedSecrets.push({
                            type: pattern.name,
                            source: source,
                            snippet: match.substring(0, 20) + '...'
                        });
                    });
                }
            });
        };

        scanTextForSecrets(pageContent, 'HTML Source');

        // 2. Scan External JS Files (Limit to first 5 to avoid timeouts)
        const scriptsToScan = staticAssets.scripts.slice(0, 5);
        for (const scriptUrl of scriptsToScan) {
            try {
                const response = await context.request.get(scriptUrl, { timeout: 2000 });
                if (response.ok()) {
                    const scriptText = await response.text();
                    scanTextForSecrets(scriptText, scriptUrl.split('/').pop());
                }
            } catch (e) { }
        }
        
        // IMPROVEMENT 3: Deduplicate secrets by snippet
        const uniqueSecrets = [];
        const seenSnippets = new Set();
        
        leakedSecrets.forEach(secret => {
            if (!seenSnippets.has(secret.snippet)) {
                seenSnippets.add(secret.snippet);
                uniqueSecrets.push(secret);
            }
        });

        // --- PENTEST MODULE: ATTACK VECTOR MAPPING ---
        const attackVectors = await page.evaluate(() => {
            const forms = Array.from(document.querySelectorAll('form')).map(f => ({
                action: f.action,
                method: f.method,
                id: f.id || 'unnamed',
                inputs: Array.from(f.querySelectorAll('input, textarea, select')).map(i => ({
                    name: i.name || i.id || 'unnamed',
                    type: i.type || 'text',
                    id: i.id,
                    placeholder: i.placeholder
                }))
            }));

            const urlParams = new URLSearchParams(window.location.search);
            const params = Array.from(urlParams.keys());

            return { forms, url_parameters: params };
        });

        // --- ACTIVE PENTEST MODULE: XSS TESTING ---
        console.log('🔍 Starting XSS vulnerability testing...');
        const xssVulnerabilities = [];
        
        const xssPayloads = [
            { payload: '<script>alert(1)</script>', type: 'Basic Script Tag' },
            { payload: '"><img src=x onerror=alert(1)>', type: 'Image Onerror' },
            { payload: '<svg onload=alert(1)>', type: 'SVG Onload' },
            { payload: 'javascript:alert(1)', type: 'JavaScript Protocol' },
            { payload: '<iframe src="javascript:alert(1)">', type: 'IFrame JavaScript' },
            { payload: '<body onload=alert(1)>', type: 'Body Onload' }
        ];

        // Test forms for XSS
        for (const form of attackVectors.forms.slice(0, 3)) { // Limit to 3 forms
            for (const input of form.inputs.slice(0, 2)) { // Limit to 2 inputs per form
                for (const xss of xssPayloads.slice(0, 3)) { // Test 3 payloads
                    try {
                        // Create a new page for each test to avoid contamination
                        const testPage = await browser.newPage();
                        await testPage.goto(url, { waitUntil: 'domcontentloaded', timeout: 5000 });

                        // Inject payload
                        const injected = await testPage.evaluate((formId, inputName, payload) => {
                            const form = document.querySelector(`form[id="${formId}"], form[action*="${formId}"]`) || document.querySelector('form');
                            if (!form) return false;

                            const input = form.querySelector(`[name="${inputName}"], [id="${inputName}"]`);
                            if (!input) return false;

                            input.value = payload;
                            return true;
                        }, form.id || form.action, input.name, xss.payload);

                        if (injected) {
                            // Check if payload is reflected in the page
                            const content = await testPage.content();
                            
                            // Check for unescaped payload
                            if (content.includes(xss.payload) && !content.includes(xss.payload.replace(/</g, '&lt;'))) {
                                xssVulnerabilities.push({
                                    type: 'XSS (Cross-Site Scripting)',
                                    severity: 'HIGH',
                                    location: `Form: ${form.action || 'inline'} → Input: ${input.name}`,
                                    payload: xss.payload,
                                    payloadType: xss.type,
                                    evidence: 'Payload reflected without sanitization',
                                    impact: 'Attackers can execute arbitrary JavaScript, steal cookies, hijack sessions',
                                    recommendation: 'Sanitize all user inputs using DOMPurify or escape HTML entities'
                                });
                                
                                console.log(`⚠️  XSS found in ${input.name}: ${xss.type}`);
                                break; // Found vulnerability, no need to test more payloads
                            }
                        }

                        await testPage.close();
                    } catch (e) {
                        // Silently fail on individual tests
                    }
                }
            }
        }

        // Test URL parameters for XSS
        if (attackVectors.url_parameters.length > 0) {
            for (const param of attackVectors.url_parameters.slice(0, 2)) {
                for (const xss of xssPayloads.slice(0, 2)) {
                    try {
                        const testPage = await browser.newPage();
                        const testUrl = new URL(url);
                        testUrl.searchParams.set(param, xss.payload);
                        
                        await testPage.goto(testUrl.href, { waitUntil: 'domcontentloaded', timeout: 5000 });
                        const content = await testPage.content();
                        
                        if (content.includes(xss.payload) && !content.includes(xss.payload.replace(/</g, '&lt;'))) {
                            xssVulnerabilities.push({
                                type: 'XSS (Reflected)',
                                severity: 'HIGH',
                                location: `URL Parameter: ${param}`,
                                payload: xss.payload,
                                payloadType: xss.type,
                                evidence: 'Parameter value reflected without sanitization',
                                impact: 'Attackers can craft malicious URLs to execute JavaScript',
                                recommendation: 'Sanitize URL parameters before rendering in HTML'
                            });
                            
                            console.log(`⚠️  Reflected XSS found in parameter: ${param}`);
                            break;
                        }
                        
                        await testPage.close();
                    } catch (e) { }
                }
            }
        }

        console.log(`✅ XSS Testing complete: ${xssVulnerabilities.length} vulnerabilities found`);

        // --- ACTIVE PENTEST MODULE: SQL INJECTION TESTING ---
        console.log('🔍 Starting SQL Injection testing...');
        const sqliVulnerabilities = [];
        
        const sqliPayloads = [
            { payload: "' OR '1'='1", type: 'Boolean-based Blind' },
            { payload: "admin'--", type: 'Comment Injection' },
            { payload: "' OR 1=1--", type: 'Classic OR Injection' },
            { payload: "1' UNION SELECT NULL--", type: 'UNION-based' },
            { payload: "1' AND SLEEP(5)--", type: 'Time-based Blind' }
        ];

        const sqlErrorPatterns = [
            /SQL syntax.*MySQL/i,
            /Warning.*mysql_/i,
            /valid MySQL result/i,
            /MySqlClient\./i,
            /PostgreSQL.*ERROR/i,
            /Warning.*pg_/i,
            /valid PostgreSQL result/i,
            /Npgsql\./i,
            /Driver.*SQL.*Server/i,
            /OLE DB.*SQL Server/i,
            /SQLServer JDBC Driver/i,
            /SqlException/i,
            /Oracle error/i,
            /Oracle.*Driver/i,
            /Warning.*oci_/i,
            /Warning.*ora_/i
        ];

        // Test forms for SQLi
        for (const form of attackVectors.forms.slice(0, 3)) {
            // Focus on login/search forms
            const isLoginForm = form.action.includes('login') || 
                               form.action.includes('auth') || 
                               form.inputs.some(i => i.type === 'password');
            
            if (isLoginForm || form.inputs.length > 0) {
                for (const input of form.inputs.slice(0, 2)) {
                    for (const sqli of sqliPayloads.slice(0, 3)) {
                        try {
                            const testPage = await browser.newPage();
                            await testPage.goto(url, { waitUntil: 'domcontentloaded', timeout: 5000 });

                            // Inject SQL payload
                            const injected = await testPage.evaluate((formId, inputName, payload) => {
                                const form = document.querySelector(`form[id="${formId}"], form[action*="${formId}"]`) || document.querySelector('form');
                                if (!form) return false;

                                const input = form.querySelector(`[name="${inputName}"], [id="${inputName}"]`);
                                if (!input) return false;

                                input.value = payload;
                                
                                // Try to submit
                                const submitBtn = form.querySelector('[type="submit"]') || form.querySelector('button');
                                if (submitBtn) {
                                    submitBtn.click();
                                    return true;
                                }
                                return false;
                            }, form.id || form.action, input.name, sqli.payload);

                            if (injected) {
                                // Wait for response
                                await testPage.waitForTimeout(1000);
                                const content = await testPage.content();
                                const responseUrl = testPage.url();

                                // Check for SQL errors
                                let sqlErrorFound = false;
                                let errorType = '';
                                
                                for (const pattern of sqlErrorPatterns) {
                                    if (pattern.test(content)) {
                                        sqlErrorFound = true;
                                        errorType = pattern.source;
                                        break;
                                    }
                                }

                                if (sqlErrorFound) {
                                    sqliVulnerabilities.push({
                                        type: 'SQL Injection',
                                        severity: 'CRITICAL',
                                        location: `Form: ${form.action || 'inline'} → Input: ${input.name}`,
                                        payload: sqli.payload,
                                        payloadType: sqli.type,
                                        evidence: `SQL error exposed: ${errorType}`,
                                        impact: 'Attackers can read/modify database, bypass authentication, execute commands',
                                        recommendation: 'Use parameterized queries (prepared statements) or ORM. Never concatenate user input into SQL queries'
                                    });
                                    
                                    console.log(`🔥 SQL Injection found in ${input.name}: ${sqli.type}`);
                                    break;
                                }
                            }

                            await testPage.close();
                        } catch (e) { }
                    }
                }
            }
        }

        console.log(`✅ SQLi Testing complete: ${sqliVulnerabilities.length} vulnerabilities found`);

        // --- ACTIVE PENTEST MODULE: AUTHENTICATION TESTING ---
        console.log('🔍 Starting Authentication security testing...');
        const authVulnerabilities = [];

        // Find login forms
        const loginForms = attackVectors.forms.filter(f => 
            f.action.includes('login') || 
            f.action.includes('auth') || 
            f.action.includes('signin') ||
            f.inputs.some(i => i.type === 'password')
        );

        if (loginForms.length > 0) {
            const loginForm = loginForms[0];
            
            // TEST 1: Weak/Common Credentials
            const commonCredentials = [
                { user: 'admin', pass: 'admin' },
                { user: 'admin', pass: '123456' },
                { user: 'admin', pass: 'password' },
                { user: 'administrator', pass: 'administrator' },
                { user: 'root', pass: 'root' },
                { user: 'test', pass: 'test' }
            ];

            for (const cred of commonCredentials.slice(0, 3)) {
                try {
                    const testPage = await browser.newPage();
                    await testPage.goto(url, { waitUntil: 'domcontentloaded', timeout: 5000 });

                    const loginSuccess = await testPage.evaluate((formAction, username, password) => {
                        const form = document.querySelector(`form[action*="login"], form[action*="auth"]`) || document.querySelector('form');
                        if (!form) return false;

                        const userInput = form.querySelector('[type="text"], [type="email"], [name*="user"], [name*="email"]');
                        const passInput = form.querySelector('[type="password"]');
                        
                        if (userInput && passInput) {
                            userInput.value = username;
                            passInput.value = password;
                            
                            const submitBtn = form.querySelector('[type="submit"]') || form.querySelector('button');
                            if (submitBtn) submitBtn.click();
                            return true;
                        }
                        return false;
                    }, loginForm.action, cred.user, cred.pass);

                    if (loginSuccess) {
                        await testPage.waitForTimeout(2000);
                        const finalUrl = testPage.url();
                        const content = await testPage.content();

                        // Check if login was successful
                        if (finalUrl !== url && 
                            (content.includes('dashboard') || 
                             content.includes('welcome') || 
                             content.includes('logout') ||
                             finalUrl.includes('dashboard') ||
                             finalUrl.includes('admin'))) {
                            
                            authVulnerabilities.push({
                                type: 'Weak Credentials Accepted',
                                severity: 'CRITICAL',
                                location: `Login Form: ${loginForm.action}`,
                                credentials: `${cred.user}:${cred.pass}`,
                                evidence: 'Default/common credentials grant access',
                                impact: 'Attackers can gain unauthorized access using common passwords',
                                recommendation: 'Enforce strong password policy, disable default accounts, implement account lockout'
                            });
                            
                            console.log(`🔥 Weak credentials accepted: ${cred.user}:${cred.pass}`);
                        }
                    }

                    await testPage.close();
                } catch (e) { }
            }

            // TEST 2: Brute Force Protection
            let bruteForceBlocked = false;
            let attemptCount = 0;

            try {
                const testPage = await browser.newPage();
                
                for (let i = 0; i < 10; i++) {
                    await testPage.goto(url, { waitUntil: 'domcontentloaded', timeout: 5000 });
                    
                    await testPage.evaluate((formAction, attempt) => {
                        const form = document.querySelector(`form[action*="login"], form[action*="auth"]`) || document.querySelector('form');
                        if (!form) return;

                        const userInput = form.querySelector('[type="text"], [type="email"], [name*="user"]');
                        const passInput = form.querySelector('[type="password"]');
                        
                        if (userInput && passInput) {
                            userInput.value = 'testuser';
                            passInput.value = `wrongpass${attempt}`;
                            
                            const submitBtn = form.querySelector('[type="submit"]') || form.querySelector('button');
                            if (submitBtn) submitBtn.click();
                        }
                    }, loginForm.action, i);

                    await testPage.waitForTimeout(500);
                    attemptCount++;

                    const content = await testPage.content();
                    const status = testPage.url();

                    // Check if blocked
                    if (content.includes('blocked') || 
                        content.includes('too many') || 
                        content.includes('rate limit') ||
                        content.includes('locked')) {
                        bruteForceBlocked = true;
                        break;
                    }
                }

                if (!bruteForceBlocked && attemptCount >= 10) {
                    authVulnerabilities.push({
                        type: 'No Brute Force Protection',
                        severity: 'HIGH',
                        location: `Login Form: ${loginForm.action}`,
                        attempts: attemptCount,
                        evidence: `${attemptCount} failed login attempts without blocking`,
                        impact: 'Attackers can perform unlimited brute force attacks',
                        recommendation: 'Implement rate limiting (e.g., 5 attempts per 15 minutes), CAPTCHA after 3 failures, account lockout'
                    });
                    
                    console.log(`⚠️  No brute force protection: ${attemptCount} attempts allowed`);
                }

                await testPage.close();
            } catch (e) { }

            // TEST 3: Password in URL
            const currentUrl = page.url();
            if (currentUrl.includes('password=') || currentUrl.includes('pass=') || currentUrl.includes('pwd=')) {
                authVulnerabilities.push({
                    type: 'Password in URL',
                    severity: 'HIGH',
                    location: currentUrl,
                    evidence: 'Password transmitted in URL query string',
                    impact: 'Passwords exposed in browser history, server logs, referrer headers',
                    recommendation: 'Always use POST method for authentication, never GET'
                });
                
                console.log(`⚠️  Password found in URL`);
            }
        }

        // TEST 4: Session Security
        const cookies = await page.context().cookies();
        
        for (const cookie of cookies) {
            // Check for insecure session cookies
            if (cookie.name.toLowerCase().includes('session') || 
                cookie.name.toLowerCase().includes('token') ||
                cookie.name.toLowerCase().includes('auth')) {
                
                // Check HttpOnly flag
                if (!cookie.httpOnly) {
                    authVulnerabilities.push({
                        type: 'Session Cookie Missing HttpOnly',
                        severity: 'MEDIUM',
                        location: `Cookie: ${cookie.name}`,
                        evidence: 'Session cookie accessible via JavaScript',
                        impact: 'XSS attacks can steal session tokens',
                        recommendation: 'Set HttpOnly flag on all session cookies'
                    });
                }

                // Check Secure flag on HTTPS sites
                if (url.startsWith('https://') && !cookie.secure) {
                    authVulnerabilities.push({
                        type: 'Session Cookie Missing Secure Flag',
                        severity: 'MEDIUM',
                        location: `Cookie: ${cookie.name}`,
                        evidence: 'Session cookie can be transmitted over HTTP',
                        impact: 'Man-in-the-middle attacks can intercept session',
                        recommendation: 'Set Secure flag on all session cookies for HTTPS sites'
                    });
                }

                // Check SameSite attribute
                if (!cookie.sameSite || cookie.sameSite === 'None') {
                    authVulnerabilities.push({
                        type: 'Session Cookie Missing SameSite',
                        severity: 'MEDIUM',
                        location: `Cookie: ${cookie.name}`,
                        evidence: 'Cookie vulnerable to CSRF attacks',
                        impact: 'Cross-site request forgery possible',
                        recommendation: 'Set SameSite=Strict or SameSite=Lax on session cookies'
                    });
                }
            }
        }

        console.log(`✅ Auth Testing complete: ${authVulnerabilities.length} vulnerabilities found`);

        // --- ACTIVE PENTEST MODULE: SSL/TLS SECURITY ANALYSIS ---
        console.log('🔍 Starting SSL/TLS security analysis...');
        const sslVulnerabilities = [];
        const sslInfo = {
            valid: false,
            issuer: 'N/A',
            validFrom: 'N/A',
            validTo: 'N/A',
            daysRemaining: 0,
            protocol: 'N/A',
            cipher: 'N/A',
            hsts: {
                present: false,
                maxAge: 0,
                includeSubDomains: false,
                preload: false,
                preloadList: false
            }
        };

        if (url.startsWith('https://')) {
            try {
                const sslChecker = require('ssl-checker');
                const hostname = new URL(url).hostname;
                
                // Check HSTS Preload List (heuristic for major domains)
                const hstsPreloadDomains = [
                    'google.com', 'youtube.com', 'gmail.com', 'facebook.com',
                    'github.com', 'twitter.com', 'linkedin.com', 'microsoft.com',
                    'apple.com', 'amazon.com', 'netflix.com', 'paypal.com'
                ];
                
                const isPreloaded = hstsPreloadDomains.some(d => hostname.includes(d));
                sslInfo.hsts.preloadList = isPreloaded;
                
                const certInfo = await sslChecker(hostname, { method: 'GET', port: 443, protocol: 'https:' });
                
                sslInfo.valid = certInfo.valid;
                sslInfo.issuer = certInfo.issuer || 'Unknown';
                sslInfo.validFrom = certInfo.valid_from;
                sslInfo.validTo = certInfo.valid_to;
                sslInfo.daysRemaining = certInfo.daysRemaining;

                // Check HSTS header from actual response
                const hstsHeader = securityHeaders.hsts;
                if (hstsHeader && hstsHeader !== 'Missing') {
                    sslInfo.hsts.present = true;
                    const maxAgeMatch = hstsHeader.match(/max-age=(\d+)/);
                    if (maxAgeMatch) {
                        sslInfo.hsts.maxAge = parseInt(maxAgeMatch[1]);
                    }
                    sslInfo.hsts.includeSubDomains = hstsHeader.includes('includeSubDomains');
                    sslInfo.hsts.preload = hstsHeader.includes('preload');
                }

                // TEST 1: Certificate Expiration
                if (certInfo.daysRemaining < 0) {
                    sslVulnerabilities.push({
                        type: 'Expired SSL Certificate',
                        severity: 'CRITICAL',
                        daysExpired: Math.abs(certInfo.daysRemaining),
                        validTo: certInfo.valid_to,
                        impact: 'Users will see security warnings, browsers will block access',
                        recommendation: 'Renew SSL certificate immediately'
                    });
                    console.log(`🔥 SSL Certificate EXPIRED ${Math.abs(certInfo.daysRemaining)} days ago`);
                } else if (certInfo.daysRemaining < 30) {
                    sslVulnerabilities.push({
                        type: 'SSL Certificate Expiring Soon',
                        severity: 'HIGH',
                        daysRemaining: certInfo.daysRemaining,
                        validTo: certInfo.valid_to,
                        impact: 'Certificate will expire soon, causing service disruption',
                        recommendation: `Renew certificate before ${certInfo.valid_to}`
                    });
                    console.log(`⚠️  SSL Certificate expires in ${certInfo.daysRemaining} days`);
                } else if (certInfo.daysRemaining < 60) {
                    sslVulnerabilities.push({
                        type: 'SSL Certificate Renewal Recommended',
                        severity: 'MEDIUM',
                        daysRemaining: certInfo.daysRemaining,
                        validTo: certInfo.valid_to,
                        impact: 'Certificate should be renewed proactively',
                        recommendation: 'Schedule certificate renewal'
                    });
                }

                // TEST 2: Self-Signed Certificate
                if (certInfo.issuer && certInfo.issuer.toLowerCase().includes('self-signed')) {
                    sslVulnerabilities.push({
                        type: 'Self-Signed Certificate',
                        severity: 'HIGH',
                        issuer: certInfo.issuer,
                        impact: 'Browsers show security warnings, users may not trust the site',
                        recommendation: 'Use certificate from trusted CA (Let\'s Encrypt, DigiCert, etc)'
                    });
                    console.log(`⚠️  Self-signed certificate detected`);
                }

                // TEST 3: HSTS Analysis (IMPROVED)
                if (!sslInfo.hsts.present && !isPreloaded) {
                    // Only report if BOTH header is missing AND not in preload list
                    sslVulnerabilities.push({
                        type: 'HSTS Header Missing',
                        severity: 'MEDIUM',
                        impact: 'Browsers not forced to use HTTPS, potential downgrade attacks',
                        recommendation: 'Implement HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
                        note: 'Not critical if domain is in browser HSTS preload lists'
                    });
                    console.log(`⚠️  HSTS header missing (not in preload list)`);
                } else if (isPreloaded) {
                    console.log(`✅ Domain in HSTS preload list (browsers enforce HTTPS)`);
                } else if (sslInfo.hsts.present) {
                    console.log(`✅ HSTS header present (max-age: ${sslInfo.hsts.maxAge}s)`);
                    
                    // Check for weak HSTS configuration
                    if (sslInfo.hsts.maxAge < 31536000) {
                        sslVulnerabilities.push({
                            type: 'Weak HSTS Configuration',
                            severity: 'LOW',
                            maxAge: sslInfo.hsts.maxAge,
                            impact: 'HSTS max-age too short, should be at least 1 year',
                            recommendation: 'Increase max-age to 31536000 (1 year) or more'
                        });
                    }
                }

                // TEST 4: Protocol and Cipher Analysis
                const testPage = await browser.newPage();
                
                await testPage.goto(url, { waitUntil: 'domcontentloaded', timeout: 5000 });
                
                await testPage.close();

                // Check for weak protocols (TLS 1.0, TLS 1.1)
                const weakProtocols = ['TLS 1.0', 'TLS 1.1', 'SSL 3.0', 'SSL 2.0'];
                if (sslInfo.protocol && weakProtocols.some(p => sslInfo.protocol.includes(p))) {
                    sslVulnerabilities.push({
                        type: 'Weak TLS Protocol',
                        severity: 'HIGH',
                        protocol: sslInfo.protocol,
                        impact: 'Vulnerable to BEAST, POODLE, and other attacks',
                        recommendation: 'Disable TLS 1.0/1.1, use only TLS 1.2 and TLS 1.3'
                    });
                    console.log(`⚠️  Weak protocol detected: ${sslInfo.protocol}`);
                }

                // Check for weak ciphers
                const weakCiphers = ['RC4', 'DES', 'MD5', '3DES', 'NULL', 'EXPORT', 'anon'];
                if (sslInfo.cipher && weakCiphers.some(c => sslInfo.cipher.includes(c))) {
                    sslVulnerabilities.push({
                        type: 'Weak Cipher Suite',
                        severity: 'HIGH',
                        cipher: sslInfo.cipher,
                        impact: 'Encryption can be broken, data can be intercepted',
                        recommendation: 'Use strong ciphers: AES-GCM, ChaCha20-Poly1305'
                    });
                    console.log(`⚠️  Weak cipher detected: ${sslInfo.cipher}`);
                }

            } catch (e) {
                console.log(`⚠️  SSL/TLS analysis error: ${e.message}`);
                sslVulnerabilities.push({
                    type: 'SSL/TLS Analysis Failed',
                    severity: 'INFO',
                    error: e.message,
                    impact: 'Could not verify SSL/TLS configuration',
                    recommendation: 'Manually verify SSL configuration using SSL Labs (ssllabs.com/ssltest)'
                });
            }
        } else {
            // HTTP site (no HTTPS)
            sslVulnerabilities.push({
                type: 'No HTTPS/SSL',
                severity: 'CRITICAL',
                protocol: 'HTTP',
                impact: 'All data transmitted in plain text, vulnerable to interception and MITM attacks',
                recommendation: 'Implement HTTPS with valid SSL certificate (use Let\'s Encrypt for free)',
                cwe: 'CWE-319',
                owasp: 'A02:2021 - Cryptographic Failures'
            });
            console.log(`🔥 Site uses HTTP (no encryption)`);
        }

        console.log(`✅ SSL/TLS Testing complete: ${sslVulnerabilities.length} issues found`);

        // --- PENTEST MODULE: GHOST PROTOCOL (Route Discovery) - ENHANCED ---
        const routePatterns = /["'](\/(api|v1|v2|auth|login|user|admin|dashboard|settings)[a-zA-Z0-9\/_\-]*)["']/g;
        const ghostRoutes = new Set();

        // Scan main page source
        const pageContentSource = await page.content();
        let match;
        while ((match = routePatterns.exec(pageContentSource)) !== null) {
            ghostRoutes.add(match[1]);
        }

        // Scan intercepted scripts (Max 10)
        for (const scriptUrl of staticAssets.scripts.slice(0, 10)) {
            try {
                const response = await context.request.get(scriptUrl, { timeout: 1500 });
                if (response.ok()) {
                    const text = await response.text();
                    while ((match = routePatterns.exec(text)) !== null) {
                        ghostRoutes.add(match[1]);
                    }
                }
            } catch (e) { }
        }
        
        // IMPROVEMENT 4: Validate ghost routes (test if they exist)
        console.log(`🔍 Validating ${ghostRoutes.size} ghost routes...`);
        const validatedRoutes = [];
        const routesToTest = Array.from(ghostRoutes).slice(0, 15); // Limit to 15 to avoid timeout
        
        for (const route of routesToTest) {
            try {
                const testUrl = new URL(route, url).href;
                const response = await context.request.get(testUrl, { timeout: 2000 });
                
                // Consider valid if not 404
                if (response.status() !== 404) {
                    validatedRoutes.push({
                        route: route,
                        status: response.status(),
                        validated: true
                    });
                }
            } catch (e) {
                // If error, still include but mark as unvalidated
                validatedRoutes.push({
                    route: route,
                    status: 'unknown',
                    validated: false
                });
            }
        }
        
        console.log(`✅ Validated ${validatedRoutes.filter(r => r.validated).length}/${routesToTest.length} routes`);

        // --- PROFESSIONAL CSP ANALYSIS ---
        console.log('🔍 Analyzing Content Security Policy...');
        const cspAnalysis = {
            present: false,
            header: null,
            meta: null,
            directives: {},
            issues: []
        };

        // Check CSP from HTTP header
        cspAnalysis.header = securityHeaders.csp || null;
        
        // Check CSP from meta tag
        cspAnalysis.meta = await page.evaluate(() => {
            const meta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
            return meta ? meta.content : null;
        });

        const cspSource = cspAnalysis.header || cspAnalysis.meta;
        
        if (cspSource) {
            cspAnalysis.present = true;
            
            // Parse directives
            const directives = cspSource.split(';').map(d => d.trim()).filter(d => d);
            directives.forEach(directive => {
                const parts = directive.split(/\s+/);
                const name = parts[0];
                const values = parts.slice(1);
                cspAnalysis.directives[name] = values;
            });

            // Analyze critical directives
            const criticalDirectives = {
                'script-src': {
                    unsafe: ['unsafe-inline', 'unsafe-eval', '*', 'data:'],
                    recommendation: 'Use nonce or hash-based CSP for scripts'
                },
                'object-src': {
                    unsafe: ['*'],
                    recommendation: 'Set to \'none\' to prevent Flash/plugin attacks'
                },
                'base-uri': {
                    unsafe: ['*'],
                    recommendation: 'Restrict to \'self\' to prevent base tag injection'
                },
                'frame-ancestors': {
                    unsafe: ['*'],
                    recommendation: 'Use \'none\' or specific origins to prevent clickjacking'
                },
                'default-src': {
                    unsafe: ['*', 'unsafe-inline', 'unsafe-eval'],
                    recommendation: 'Avoid wildcards, be specific with allowed sources'
                }
            };

            for (const [directive, config] of Object.entries(criticalDirectives)) {
                const values = cspAnalysis.directives[directive];
                
                if (!values) {
                    cspAnalysis.issues.push({
                        type: 'CSP Directive Missing',
                        severity: 'MEDIUM',
                        directive: directive,
                        recommendation: config.recommendation
                    });
                    continue;
                }

                for (const unsafe of config.unsafe) {
                    if (values.includes(unsafe)) {
                        cspAnalysis.issues.push({
                            type: 'Unsafe CSP Directive',
                            severity: directive === 'script-src' ? 'HIGH' : 'MEDIUM',
                            directive: directive,
                            unsafe: unsafe,
                            recommendation: config.recommendation
                        });
                    }
                }
            }
        } else {
            cspAnalysis.issues.push({
                type: 'CSP Missing',
                severity: 'HIGH',
                impact: 'No browser-level XSS protection',
                recommendation: 'Implement strict CSP with nonce-based scripts',
                example: "Content-Security-Policy: default-src 'self'; script-src 'nonce-{random}'; object-src 'none'"
            });
        }

        console.log(`✅ CSP Analysis complete: ${cspAnalysis.issues.length} issues found`);

        // --- DEEP NAVIGATION: SMART CRAWLER ---
        console.log("🗺️ Starting Smart Batch Crawling...");
        const siteMap = {
            nodes: []
        };

        // Extract internal links (with safety checks)
        const allLinks = auditData.structure?.links || [];
        const internalLinks = allLinks
            .filter(l => {
                try {
                    if (!l || !l.href) return false;
                    const linkUrl = new URL(l.href);
                    const targetUrl = new URL(url);
                    return linkUrl.hostname === targetUrl.hostname && 
                           !l.href.includes('#') && 
                           l.href !== url;
                } catch {
                    return false;
                }
            })
            .map(l => l.href);

        // Smart Filter: Deduplicate and pick distinctive paths
        const distinctivePaths = new Set();
        const smartLinks = internalLinks.filter(l => {
            try {
                const path = new URL(l).pathname;
                const pathSegments = path.split('/').filter(Boolean);
                // Heuristic: convert numbers to 'ID' to group similar routes
                const template = pathSegments.map(s => /^\d+$/.test(s) ? '{ID}' : s).join('/');
                if (distinctivePaths.has(template)) return false;
                distinctivePaths.add(template);
                return true;
            } catch { return false; }
        }).slice(0, 4); // Limit to 4 key sub-pages for API efficiency

        // Add Root Node
        try {
            const screenshotBuffer = await page.screenshot({ fullPage: true, type: 'jpeg', quality: 50 });
            siteMap.nodes.push({
                url: url,
                title: await page.title(),
                screenshot: screenshotBuffer.toString('base64'),
                type: 'ROOT'
            });
        } catch (e) {
            console.log(`⚠️  Screenshot failed: ${e.message}`);
            siteMap.nodes.push({
                url: url,
                title: await page.title(),
                screenshot: null,
                type: 'ROOT'
            });
        }

        // Batch Crawl (Sequential to save resources, fast timeout)
        for (const linkUrl of smartLinks) {
            let childPage;
            try {
                childPage = await browser.newPage();
                // Block heavy assets on crawlers
                await childPage.route('**/*.{png,jpg,jpeg,gif,svg,css,woff,woff2}', route => route.abort());

                await childPage.goto(linkUrl, { waitUntil: 'domcontentloaded', timeout: 6000 });

                const title = await childPage.title();
                const childScreenshot = await childPage.screenshot({ fullPage: false, type: 'jpeg', quality: 50 });

                siteMap.nodes.push({
                    url: linkUrl,
                    title: title || 'Untitled Page',
                    screenshot: childScreenshot.toString('base64'),
                    type: 'CHILD'
                });
            } catch (e) {
                // Silently fail on specific sub-pages to keep flow moving
                console.log(`⚠️  Failed to crawl ${linkUrl}: ${e.message}`);
            } finally {
                if (childPage) await childPage.close();
            }
        }

        console.log(`✅ Smart Crawling complete: ${siteMap.nodes.length} pages mapped`);

        // Prepare response
        const response = {
            endpoints: endpoints,
            media,
            schema: auditData.structure.tags,
            score,
            tech: auditData.security,
            seo: auditData.seo,
            performance: auditData.performance,
            assets: staticAssets,
            full_links: auditData.structure.links,
            dom_images: auditData.structure.images,
            discovery: discovery,
            screenshot: siteMap.nodes[0]?.screenshot || null,
            site_map: siteMap,
            security_audit: {
                exposed_files: uniqueExposedFiles,
                leaked_secrets: uniqueSecrets,
                attack_vectors: attackVectors,
                ghost_routes: validatedRoutes,
                csp_analysis: cspAnalysis,
                // Active vulnerability testing results
                vulnerabilities: {
                    xss: xssVulnerabilities,
                    sqli: sqliVulnerabilities,
                    auth: authVulnerabilities,
                    ssl: sslVulnerabilities,
                    total: xssVulnerabilities.length + sqliVulnerabilities.length + authVulnerabilities.length + sslVulnerabilities.length,
                    critical: [...xssVulnerabilities, ...sqliVulnerabilities, ...authVulnerabilities, ...sslVulnerabilities]
                        .filter(v => v.severity === 'CRITICAL').length,
                    high: [...xssVulnerabilities, ...sqliVulnerabilities, ...authVulnerabilities, ...sslVulnerabilities]
                        .filter(v => v.severity === 'HIGH').length,
                    medium: [...xssVulnerabilities, ...sqliVulnerabilities, ...authVulnerabilities, ...sslVulnerabilities]
                        .filter(v => v.severity === 'MEDIUM').length
                },
                ssl_info: sslInfo
            }
        };

        console.log(`✅ Sending response to backend...`);
        res.json(response);
        console.log(`✅ Response sent successfully`);
    } catch (err) {
        console.error("❌ Scan Error:", err);
        console.error("Stack:", err.stack);
        res.status(500).json({ error: "Playwright scan failed", details: err.message });
    } finally {
        if (browser) await browser.close();
    }
});

const PORT = 3001;
app.listen(PORT, () => {
    console.log(`🚀 Playwright Worker listening on port ${PORT}`);
});
