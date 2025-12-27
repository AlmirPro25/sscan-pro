/**
 * MÓDULO DE SCAN AUTENTICADO - "Os Andares de Cima"
 * Testa a aplicação com credenciais de usuário
 * - Login automation
 * - Session management testing
 * - IDOR detection
 * - Privilege escalation testing
 */

class AuthenticatedScanner {
    constructor(browser) {
        this.browser = browser;
    }

    /**
     * Perform authenticated scan
     * @param {string} url - Target URL
     * @param {object} credentials - { username, password, loginUrl?, usernameField?, passwordField? }
     */
    async scan(url, credentials) {
        const startTime = Date.now();
        console.log(`🔍 [AUTH] Starting authenticated scan for: ${url}`);

        if (!credentials || !credentials.username || !credentials.password) {
            return {
                error: 'Credentials required for authenticated scan',
                hint: 'Provide { username, password, loginUrl?, usernameField?, passwordField? }'
            };
        }

        const results = {
            url,
            scanTime: new Date().toISOString(),
            loginSuccess: false,
            sessionInfo: null,
            vulnerabilities: [],
            accessiblePages: [],
            idorTests: [],
            summary: {}
        };

        let context;
        let page;

        try {
            // Create new browser context for isolated session
            context = await this.browser.newContext();
            page = await context.newPage();

            // Step 1: Attempt login
            const loginResult = await this.performLogin(page, url, credentials);
            results.loginSuccess = loginResult.success;
            results.loginDetails = loginResult;

            if (!loginResult.success) {
                results.error = 'Login failed';
                return results;
            }

            console.log(`✅ [AUTH] Login successful`);

            // Step 2: Analyze session
            results.sessionInfo = await this.analyzeSession(page, context);

            // Step 3: Discover authenticated pages
            results.accessiblePages = await this.discoverPages(page, url);

            // Step 4: Test for IDOR vulnerabilities
            results.idorTests = await this.testIDOR(page, url, results.accessiblePages);

            // Step 5: Test session security
            const sessionVulns = await this.testSessionSecurity(page, context, url);
            results.vulnerabilities.push(...sessionVulns);

            // Step 6: Test for privilege escalation
            const privEscVulns = await this.testPrivilegeEscalation(page, url);
            results.vulnerabilities.push(...privEscVulns);

            // Calculate summary
            results.summary = this.calculateSummary(results);

        } catch (e) {
            results.error = e.message;
            console.error(`❌ [AUTH] Error: ${e.message}`);
        } finally {
            if (page) await page.close().catch(() => {});
            if (context) await context.close().catch(() => {});
        }

        results.scanDuration = Date.now() - startTime;
        console.log(`✅ [AUTH] Scan complete. Found ${results.vulnerabilities.length} vulnerabilities`);
        return results;
    }

    /**
     * Perform login
     */
    async performLogin(page, url, credentials) {
        const result = {
            success: false,
            method: null,
            loginUrl: null,
            error: null
        };

        try {
            // Determine login URL
            const loginUrl = credentials.loginUrl || await this.findLoginPage(page, url);
            result.loginUrl = loginUrl;

            if (!loginUrl) {
                result.error = 'Could not find login page';
                return result;
            }

            // Navigate to login page
            await page.goto(loginUrl, { waitUntil: 'domcontentloaded', timeout: 15000 });

            // Find login form
            const loginForm = await this.findLoginForm(page, credentials);
            
            if (!loginForm) {
                result.error = 'Could not find login form';
                return result;
            }

            // Fill credentials
            await page.fill(loginForm.usernameSelector, credentials.username);
            await page.fill(loginForm.passwordSelector, credentials.password);

            // Submit form
            const submitButton = await page.$('button[type="submit"], input[type="submit"], button:has-text("Login"), button:has-text("Entrar"), button:has-text("Sign in")');
            
            if (submitButton) {
                await Promise.all([
                    page.waitForNavigation({ timeout: 10000 }).catch(() => {}),
                    submitButton.click()
                ]);
            } else {
                await page.press(loginForm.passwordSelector, 'Enter');
                await page.waitForTimeout(3000);
            }

            // Check if login was successful
            const currentUrl = page.url();
            const pageContent = await page.content();

            // Success indicators
            const successIndicators = [
                currentUrl !== loginUrl,
                pageContent.includes('dashboard'),
                pageContent.includes('logout'),
                pageContent.includes('sair'),
                pageContent.includes('minha conta'),
                pageContent.includes('my account'),
                pageContent.includes('welcome'),
                pageContent.includes('bem-vindo'),
                await page.$('a[href*="logout"], a[href*="signout"], button:has-text("Sair")') !== null
            ];

            // Failure indicators
            const failureIndicators = [
                pageContent.includes('invalid'),
                pageContent.includes('incorrect'),
                pageContent.includes('failed'),
                pageContent.includes('erro'),
                pageContent.includes('inválido'),
                pageContent.includes('incorreto')
            ];

            result.success = successIndicators.some(i => i) && !failureIndicators.some(i => i);
            result.method = 'form';
            result.finalUrl = currentUrl;

        } catch (e) {
            result.error = e.message;
        }

        return result;
    }

    /**
     * Find login page
     */
    async findLoginPage(page, baseUrl) {
        const loginPaths = [
            '/login', '/signin', '/auth', '/authenticate',
            '/user/login', '/users/login', '/account/login',
            '/admin/login', '/admin', '/painel',
            '/entrar', '/acesso', '/acessar'
        ];

        // First check if current page has login form
        await page.goto(baseUrl, { waitUntil: 'domcontentloaded', timeout: 10000 });
        
        const hasLoginForm = await page.$('input[type="password"]');
        if (hasLoginForm) {
            return baseUrl;
        }

        // Look for login link
        const loginLink = await page.$('a[href*="login"], a[href*="signin"], a[href*="entrar"], a:has-text("Login"), a:has-text("Entrar")');
        if (loginLink) {
            const href = await loginLink.getAttribute('href');
            if (href) {
                return new URL(href, baseUrl).href;
            }
        }

        // Try common paths
        for (const path of loginPaths) {
            try {
                const testUrl = new URL(path, baseUrl).href;
                await page.goto(testUrl, { waitUntil: 'domcontentloaded', timeout: 5000 });
                
                const hasPassword = await page.$('input[type="password"]');
                if (hasPassword) {
                    return testUrl;
                }
            } catch (e) {
                // Continue to next path
            }
        }

        return null;
    }

    /**
     * Find login form elements
     */
    async findLoginForm(page, credentials) {
        // Use provided selectors or find automatically
        let usernameSelector = credentials.usernameField;
        let passwordSelector = credentials.passwordField;

        if (!usernameSelector) {
            // Try common username field selectors
            const usernameSelectors = [
                'input[name="username"]',
                'input[name="email"]',
                'input[name="user"]',
                'input[name="login"]',
                'input[type="email"]',
                'input[id*="user"]',
                'input[id*="email"]',
                'input[id*="login"]',
                'input[placeholder*="email"]',
                'input[placeholder*="usuário"]',
                'input[placeholder*="user"]'
            ];

            for (const selector of usernameSelectors) {
                const element = await page.$(selector);
                if (element) {
                    usernameSelector = selector;
                    break;
                }
            }
        }

        if (!passwordSelector) {
            passwordSelector = 'input[type="password"]';
        }

        // Verify both fields exist
        const usernameField = await page.$(usernameSelector);
        const passwordField = await page.$(passwordSelector);

        if (usernameField && passwordField) {
            return { usernameSelector, passwordSelector };
        }

        return null;
    }

    /**
     * Analyze session security
     */
    async analyzeSession(page, context) {
        const sessionInfo = {
            cookies: [],
            localStorage: {},
            sessionStorage: {},
            issues: []
        };

        try {
            // Get cookies
            const cookies = await context.cookies();
            sessionInfo.cookies = cookies.map(c => ({
                name: c.name,
                domain: c.domain,
                secure: c.secure,
                httpOnly: c.httpOnly,
                sameSite: c.sameSite,
                expires: c.expires
            }));

            // Check for session cookie issues
            const sessionCookies = cookies.filter(c => 
                c.name.toLowerCase().includes('session') ||
                c.name.toLowerCase().includes('token') ||
                c.name.toLowerCase().includes('auth') ||
                c.name.toLowerCase().includes('jwt')
            );

            for (const cookie of sessionCookies) {
                if (!cookie.secure) {
                    sessionInfo.issues.push({
                        type: 'INSECURE_COOKIE',
                        severity: 'HIGH',
                        cookie: cookie.name,
                        issue: 'Cookie de sessão sem flag Secure',
                        recommendation: 'Adicionar flag Secure para prevenir transmissão via HTTP'
                    });
                }
                if (!cookie.httpOnly) {
                    sessionInfo.issues.push({
                        type: 'NO_HTTPONLY',
                        severity: 'MEDIUM',
                        cookie: cookie.name,
                        issue: 'Cookie de sessão sem flag HttpOnly',
                        recommendation: 'Adicionar flag HttpOnly para prevenir acesso via JavaScript (XSS)'
                    });
                }
                if (cookie.sameSite === 'None' || !cookie.sameSite) {
                    sessionInfo.issues.push({
                        type: 'WEAK_SAMESITE',
                        severity: 'MEDIUM',
                        cookie: cookie.name,
                        issue: 'Cookie sem SameSite ou com SameSite=None',
                        recommendation: 'Usar SameSite=Strict ou SameSite=Lax para prevenir CSRF'
                    });
                }
            }

            // Get localStorage and sessionStorage
            sessionInfo.localStorage = await page.evaluate(() => {
                const items = {};
                for (let i = 0; i < localStorage.length; i++) {
                    const key = localStorage.key(i);
                    items[key] = localStorage.getItem(key)?.substring(0, 50) + '...';
                }
                return items;
            });

            sessionInfo.sessionStorage = await page.evaluate(() => {
                const items = {};
                for (let i = 0; i < sessionStorage.length; i++) {
                    const key = sessionStorage.key(i);
                    items[key] = sessionStorage.getItem(key)?.substring(0, 50) + '...';
                }
                return items;
            });

            // Check for sensitive data in storage
            const sensitiveKeys = ['token', 'jwt', 'auth', 'password', 'secret', 'key', 'credential'];
            
            for (const [key, value] of Object.entries(sessionInfo.localStorage)) {
                if (sensitiveKeys.some(s => key.toLowerCase().includes(s))) {
                    sessionInfo.issues.push({
                        type: 'SENSITIVE_IN_LOCALSTORAGE',
                        severity: 'MEDIUM',
                        key,
                        issue: 'Dados sensíveis em localStorage',
                        recommendation: 'Evitar armazenar tokens/credenciais em localStorage (vulnerável a XSS)'
                    });
                }
            }

        } catch (e) {
            sessionInfo.error = e.message;
        }

        return sessionInfo;
    }

    /**
     * Discover accessible pages after login
     */
    async discoverPages(page, baseUrl) {
        const pages = [];
        
        try {
            // Get all links on the page
            const links = await page.$$eval('a[href]', anchors => 
                anchors.map(a => a.href).filter(href => href.startsWith('http'))
            );

            // Filter to same domain
            const baseHostname = new URL(baseUrl).hostname;
            const sameOriginLinks = [...new Set(links)]
                .filter(link => {
                    try {
                        return new URL(link).hostname === baseHostname;
                    } catch {
                        return false;
                    }
                })
                .slice(0, 20); // Limit to 20 pages

            for (const link of sameOriginLinks) {
                try {
                    await page.goto(link, { waitUntil: 'domcontentloaded', timeout: 5000 });
                    
                    const pageInfo = await page.evaluate(() => ({
                        title: document.title,
                        hasForm: document.querySelectorAll('form').length > 0,
                        hasFileUpload: document.querySelector('input[type="file"]') !== null,
                        hasIdInUrl: window.location.href.match(/[?&\/](id|user_id|order_id|account)=?\d+/i) !== null
                    }));

                    pages.push({
                        url: link,
                        ...pageInfo
                    });
                } catch (e) {
                    // Skip inaccessible pages
                }
            }

        } catch (e) {
            console.error(`[AUTH] Error discovering pages: ${e.message}`);
        }

        return pages;
    }

    /**
     * Test for IDOR vulnerabilities
     */
    async testIDOR(page, baseUrl, accessiblePages) {
        const idorTests = [];

        // Find pages with IDs in URL
        const pagesWithIds = accessiblePages.filter(p => p.hasIdInUrl);

        for (const pageInfo of pagesWithIds.slice(0, 5)) {
            try {
                // Extract ID from URL
                const idMatch = pageInfo.url.match(/[?&\/](id|user_id|order_id|account)[=\/]?(\d+)/i);
                if (!idMatch) continue;

                const paramName = idMatch[1];
                const originalId = parseInt(idMatch[2]);

                // Try adjacent IDs
                const testIds = [originalId - 1, originalId + 1, originalId + 100];

                for (const testId of testIds) {
                    if (testId <= 0) continue;

                    const testUrl = pageInfo.url.replace(
                        new RegExp(`(${paramName})[=\\/]?${originalId}`, 'i'),
                        `$1=${testId}`
                    );

                    await page.goto(testUrl, { waitUntil: 'domcontentloaded', timeout: 5000 });
                    
                    const response = await page.evaluate(() => ({
                        status: 'loaded',
                        hasContent: document.body.innerText.length > 100,
                        hasError: document.body.innerText.toLowerCase().includes('error') ||
                                  document.body.innerText.toLowerCase().includes('denied') ||
                                  document.body.innerText.toLowerCase().includes('unauthorized')
                    }));

                    if (response.hasContent && !response.hasError) {
                        idorTests.push({
                            vulnerable: true,
                            severity: 'HIGH',
                            originalUrl: pageInfo.url,
                            testedUrl: testUrl,
                            parameter: paramName,
                            originalId,
                            testedId: testId,
                            issue: `Possível IDOR: Acesso a recurso de outro usuário (${paramName}=${testId})`,
                            recommendation: 'Implementar verificação de autorização no backend'
                        });
                        break; // Found vulnerability, no need to test more IDs
                    }
                }

            } catch (e) {
                // Skip on error
            }
        }

        return idorTests;
    }

    /**
     * Test session security
     */
    async testSessionSecurity(page, context, url) {
        const vulnerabilities = [];

        try {
            // Test 1: Session fixation
            const cookies = await context.cookies();
            const sessionCookie = cookies.find(c => 
                c.name.toLowerCase().includes('session') ||
                c.name.toLowerCase().includes('sid')
            );

            if (sessionCookie) {
                // Check if session ID changed after login (it should)
                // This is a simplified check - real test would compare pre/post login
                vulnerabilities.push({
                    type: 'SESSION_FIXATION_CHECK',
                    severity: 'INFO',
                    title: 'Verificar regeneração de sessão',
                    description: `Cookie de sessão: ${sessionCookie.name}`,
                    recommendation: 'Garantir que o ID de sessão é regenerado após login'
                });
            }

            // Test 2: Concurrent sessions
            // Would need to login from another context to fully test

            // Test 3: Session timeout
            // Would need to wait - just flag for manual testing
            vulnerabilities.push({
                type: 'SESSION_TIMEOUT_CHECK',
                severity: 'INFO',
                title: 'Verificar timeout de sessão',
                description: 'Teste manual necessário',
                recommendation: 'Sessões devem expirar após período de inatividade (15-30 min recomendado)'
            });

        } catch (e) {
            // Ignore errors
        }

        return vulnerabilities;
    }

    /**
     * Test for privilege escalation
     */
    async testPrivilegeEscalation(page, url) {
        const vulnerabilities = [];

        try {
            // Try to access admin pages
            const adminPaths = [
                '/admin', '/administrator', '/admin/dashboard',
                '/manage', '/management', '/backend',
                '/api/admin', '/api/users', '/api/config'
            ];

            for (const path of adminPaths) {
                try {
                    const testUrl = new URL(path, url).href;
                    const response = await page.goto(testUrl, { 
                        waitUntil: 'domcontentloaded', 
                        timeout: 5000 
                    });

                    if (response && response.status() === 200) {
                        const content = await page.content();
                        
                        // Check if it's a real admin page (not redirect to login)
                        const isAdminPage = 
                            content.includes('admin') &&
                            !content.includes('login') &&
                            !content.includes('denied');

                        if (isAdminPage) {
                            vulnerabilities.push({
                                type: 'PRIVILEGE_ESCALATION',
                                severity: 'CRITICAL',
                                url: testUrl,
                                title: 'Acesso a área administrativa sem privilégios',
                                description: `Usuário comum conseguiu acessar ${path}`,
                                recommendation: 'Implementar verificação de roles/permissões no backend'
                            });
                        }
                    }
                } catch (e) {
                    // Expected - page not accessible
                }
            }

        } catch (e) {
            // Ignore errors
        }

        return vulnerabilities;
    }

    /**
     * Calculate summary
     */
    calculateSummary(results) {
        const summary = {
            loginSuccess: results.loginSuccess,
            pagesDiscovered: results.accessiblePages.length,
            vulnerabilitiesFound: results.vulnerabilities.length,
            idorVulnerabilities: results.idorTests.filter(t => t.vulnerable).length,
            sessionIssues: results.sessionInfo?.issues?.length || 0,
            overallRisk: 'LOW'
        };

        // Calculate risk
        const criticalCount = results.vulnerabilities.filter(v => v.severity === 'CRITICAL').length +
                             results.idorTests.filter(t => t.vulnerable).length;
        const highCount = results.vulnerabilities.filter(v => v.severity === 'HIGH').length +
                         (results.sessionInfo?.issues?.filter(i => i.severity === 'HIGH').length || 0);

        if (criticalCount > 0) {
            summary.overallRisk = 'CRITICAL';
        } else if (highCount > 0) {
            summary.overallRisk = 'HIGH';
        } else if (summary.sessionIssues > 0) {
            summary.overallRisk = 'MEDIUM';
        }

        return summary;
    }
}

module.exports = { AuthenticatedScanner };
