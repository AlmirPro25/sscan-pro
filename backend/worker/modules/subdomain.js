/**
 * MÓDULO DE SUBDOMÍNIOS - "Os Fundos do Prédio"
 * Enumera subdomínios e detecta riscos de takeover
 * - Subdomain enumeration
 * - Takeover detection
 * - DNS misconfiguration
 */

const dns = require('dns').promises;
const https = require('https');
const http = require('http');

class SubdomainScanner {
    constructor() {
        // Common subdomains to check
        this.commonSubdomains = [
            // Development & Staging
            'dev', 'develop', 'development', 'staging', 'stage', 'stg',
            'test', 'testing', 'qa', 'uat', 'sandbox', 'demo', 'preview',
            'beta', 'alpha', 'canary', 'next', 'new', 'old', 'legacy',
            
            // Infrastructure
            'api', 'api2', 'api-v2', 'rest', 'graphql', 'ws', 'websocket',
            'cdn', 'static', 'assets', 'media', 'images', 'img', 'files',
            'download', 'downloads', 'upload', 'uploads', 'storage',
            
            // Admin & Internal
            'admin', 'administrator', 'adm', 'panel', 'dashboard', 'console',
            'manage', 'manager', 'management', 'cms', 'backend', 'backoffice',
            'internal', 'intranet', 'extranet', 'portal', 'staff', 'employee',
            
            // Email & Communication
            'mail', 'email', 'webmail', 'smtp', 'pop', 'imap', 'mx',
            'newsletter', 'marketing', 'campaign', 'chat', 'support',
            
            // Database & Services
            'db', 'database', 'mysql', 'postgres', 'mongo', 'redis', 'elastic',
            'search', 'solr', 'cache', 'memcached', 'queue', 'mq', 'rabbit',
            
            // Monitoring & Logs
            'monitor', 'monitoring', 'status', 'health', 'metrics', 'grafana',
            'kibana', 'logs', 'logging', 'sentry', 'newrelic', 'datadog',
            
            // CI/CD & DevOps
            'jenkins', 'ci', 'cd', 'build', 'deploy', 'git', 'gitlab', 'github',
            'bitbucket', 'docker', 'k8s', 'kubernetes', 'rancher', 'terraform',
            
            // Security
            'vpn', 'proxy', 'gateway', 'firewall', 'waf', 'auth', 'sso',
            'login', 'signin', 'oauth', 'identity', 'ldap', 'ad',
            
            // Geographic
            'br', 'us', 'eu', 'asia', 'latam', 'global', 'local',
            
            // Mobile & Apps
            'app', 'mobile', 'm', 'ios', 'android', 'pwa',
            
            // E-commerce
            'shop', 'store', 'cart', 'checkout', 'payment', 'pay',
            
            // Common variations
            'www', 'www2', 'www3', 'web', 'web2', 'site', 'home',
            'blog', 'news', 'docs', 'documentation', 'help', 'faq',
            'forum', 'community', 'social', 'connect',
        ];

        // Services vulnerable to subdomain takeover
        this.takeoverSignatures = {
            'github.io': {
                fingerprint: "There isn't a GitHub Pages site here",
                service: 'GitHub Pages',
                severity: 'HIGH'
            },
            'herokuapp.com': {
                fingerprint: 'No such app',
                service: 'Heroku',
                severity: 'HIGH'
            },
            's3.amazonaws.com': {
                fingerprint: 'NoSuchBucket',
                service: 'AWS S3',
                severity: 'CRITICAL'
            },
            'cloudfront.net': {
                fingerprint: "The request could not be satisfied",
                service: 'AWS CloudFront',
                severity: 'HIGH'
            },
            'azurewebsites.net': {
                fingerprint: 'Web App - Pair Not Found',
                service: 'Azure',
                severity: 'HIGH'
            },
            'blob.core.windows.net': {
                fingerprint: 'BlobNotFound',
                service: 'Azure Blob',
                severity: 'CRITICAL'
            },
            'cloudapp.net': {
                fingerprint: 'NXDOMAIN',
                service: 'Azure Cloud',
                severity: 'HIGH'
            },
            'zendesk.com': {
                fingerprint: 'Help Center Closed',
                service: 'Zendesk',
                severity: 'MEDIUM'
            },
            'shopify.com': {
                fingerprint: 'Sorry, this shop is currently unavailable',
                service: 'Shopify',
                severity: 'MEDIUM'
            },
            'tumblr.com': {
                fingerprint: "There's nothing here",
                service: 'Tumblr',
                severity: 'MEDIUM'
            },
            'wordpress.com': {
                fingerprint: 'Do you want to register',
                service: 'WordPress.com',
                severity: 'MEDIUM'
            },
            'ghost.io': {
                fingerprint: 'The thing you were looking for is no longer here',
                service: 'Ghost',
                severity: 'MEDIUM'
            },
            'surge.sh': {
                fingerprint: 'project not found',
                service: 'Surge.sh',
                severity: 'MEDIUM'
            },
            'bitbucket.io': {
                fingerprint: 'Repository not found',
                service: 'Bitbucket',
                severity: 'HIGH'
            },
            'netlify.app': {
                fingerprint: 'Not Found',
                service: 'Netlify',
                severity: 'HIGH'
            },
            'vercel.app': {
                fingerprint: 'NOT_FOUND',
                service: 'Vercel',
                severity: 'HIGH'
            },
            'firebaseapp.com': {
                fingerprint: 'Firebase Hosting Setup Complete',
                service: 'Firebase',
                severity: 'HIGH'
            },
        };
    }

    /**
     * Full subdomain scan
     */
    async scan(domain) {
        const startTime = Date.now();
        console.log(`🔍 [SUBDOMAIN] Starting subdomain enumeration for: ${domain}`);

        // Extract base domain (remove www if present)
        const baseDomain = domain.replace(/^www\./, '');

        const results = {
            baseDomain,
            scanTime: new Date().toISOString(),
            subdomains: [],
            takeoverRisks: [],
            dnsIssues: [],
            summary: {}
        };

        // Enumerate subdomains
        const foundSubdomains = await this.enumerateSubdomains(baseDomain);
        results.subdomains = foundSubdomains;

        // Check for takeover vulnerabilities
        for (const subdomain of foundSubdomains) {
            const takeoverRisk = await this.checkTakeover(subdomain.fqdn);
            if (takeoverRisk) {
                results.takeoverRisks.push({
                    subdomain: subdomain.fqdn,
                    ...takeoverRisk
                });
            }
        }

        // Check for DNS misconfigurations
        results.dnsIssues = await this.checkDNSIssues(baseDomain, foundSubdomains);

        // Calculate summary
        results.summary = this.calculateSummary(results);
        results.scanDuration = Date.now() - startTime;

        console.log(`✅ [SUBDOMAIN] Found ${foundSubdomains.length} subdomains, ${results.takeoverRisks.length} takeover risks`);
        return results;
    }

    /**
     * Enumerate subdomains by DNS resolution
     */
    async enumerateSubdomains(baseDomain) {
        const found = [];
        const batchSize = 10;

        console.log(`🔍 [SUBDOMAIN] Checking ${this.commonSubdomains.length} common subdomains...`);

        for (let i = 0; i < this.commonSubdomains.length; i += batchSize) {
            const batch = this.commonSubdomains.slice(i, i + batchSize);
            
            const results = await Promise.all(
                batch.map(async (sub) => {
                    const fqdn = `${sub}.${baseDomain}`;
                    try {
                        const addresses = await dns.resolve4(fqdn);
                        return {
                            subdomain: sub,
                            fqdn,
                            exists: true,
                            ipAddresses: addresses,
                            type: this.categorizeSubdomain(sub)
                        };
                    } catch (e) {
                        // Check if it's a CNAME that doesn't resolve
                        try {
                            const cname = await dns.resolveCname(fqdn);
                            return {
                                subdomain: sub,
                                fqdn,
                                exists: true,
                                cname: cname[0],
                                danglingCname: true, // CNAME exists but doesn't resolve
                                type: this.categorizeSubdomain(sub)
                            };
                        } catch (e2) {
                            return null;
                        }
                    }
                })
            );

            found.push(...results.filter(r => r !== null));
        }

        return found;
    }

    /**
     * Categorize subdomain by purpose
     */
    categorizeSubdomain(sub) {
        const categories = {
            development: ['dev', 'develop', 'development', 'staging', 'stage', 'stg', 'test', 'testing', 'qa', 'uat', 'sandbox', 'demo', 'beta', 'alpha'],
            admin: ['admin', 'administrator', 'adm', 'panel', 'dashboard', 'console', 'manage', 'cms', 'backend', 'backoffice'],
            api: ['api', 'api2', 'api-v2', 'rest', 'graphql', 'ws', 'websocket'],
            infrastructure: ['cdn', 'static', 'assets', 'media', 'images', 'files', 'storage', 'db', 'cache'],
            email: ['mail', 'email', 'webmail', 'smtp', 'pop', 'imap', 'mx'],
            security: ['vpn', 'proxy', 'gateway', 'auth', 'sso', 'login'],
            monitoring: ['monitor', 'status', 'health', 'metrics', 'grafana', 'kibana', 'logs'],
        };

        for (const [category, keywords] of Object.entries(categories)) {
            if (keywords.includes(sub.toLowerCase())) {
                return category;
            }
        }
        return 'other';
    }

    /**
     * Check for subdomain takeover vulnerability
     */
    async checkTakeover(fqdn) {
        try {
            // First check CNAME
            let cname;
            try {
                const cnames = await dns.resolveCname(fqdn);
                cname = cnames[0];
            } catch (e) {
                return null; // No CNAME, not vulnerable to typical takeover
            }

            // Check if CNAME points to vulnerable service
            for (const [service, info] of Object.entries(this.takeoverSignatures)) {
                if (cname.includes(service)) {
                    // Try to fetch the page and check fingerprint
                    const response = await this.fetchPage(fqdn);
                    if (response && response.body.includes(info.fingerprint)) {
                        return {
                            vulnerable: true,
                            service: info.service,
                            severity: info.severity,
                            cname,
                            fingerprint: info.fingerprint,
                            recommendation: `O subdomínio ${fqdn} aponta para ${info.service} mas o recurso não existe. Um atacante pode registrar esse recurso e assumir controle do subdomínio.`
                        };
                    }
                }
            }

            // Check for dangling CNAME (CNAME exists but target doesn't resolve)
            try {
                await dns.resolve4(cname);
            } catch (e) {
                if (e.code === 'ENOTFOUND' || e.code === 'ENODATA') {
                    return {
                        vulnerable: true,
                        service: 'Unknown (Dangling CNAME)',
                        severity: 'HIGH',
                        cname,
                        recommendation: `O subdomínio ${fqdn} tem um CNAME para ${cname} que não resolve. Isso pode indicar um serviço desativado vulnerável a takeover.`
                    };
                }
            }

        } catch (e) {
            // Ignore errors
        }

        return null;
    }

    /**
     * Fetch page content for fingerprint matching
     */
    fetchPage(hostname) {
        return new Promise((resolve) => {
            const options = {
                hostname,
                port: 443,
                path: '/',
                method: 'GET',
                timeout: 5000,
                rejectUnauthorized: false
            };

            const req = https.request(options, (res) => {
                let body = '';
                res.on('data', chunk => body += chunk);
                res.on('end', () => resolve({ status: res.statusCode, body }));
            });

            req.on('error', () => resolve(null));
            req.on('timeout', () => {
                req.destroy();
                resolve(null);
            });

            req.end();
        });
    }

    /**
     * Check for DNS misconfigurations
     */
    async checkDNSIssues(baseDomain, subdomains) {
        const issues = [];

        // Check for zone transfer vulnerability (usually blocked, but worth checking)
        // This is informational only

        // Check for wildcard DNS
        try {
            const randomSub = `aegis-test-${Date.now()}.${baseDomain}`;
            await dns.resolve4(randomSub);
            issues.push({
                type: 'WILDCARD_DNS',
                severity: 'MEDIUM',
                title: 'Wildcard DNS detectado',
                description: 'O domínio responde para qualquer subdomínio. Isso pode dificultar a detecção de subdomínios legítimos.',
                recommendation: 'Avaliar se wildcard DNS é necessário. Pode mascarar subdomínios abandonados.'
            });
        } catch (e) {
            // Good - no wildcard
        }

        // Check for exposed development/staging subdomains
        const sensitiveTypes = ['development', 'admin', 'monitoring'];
        const exposedSensitive = subdomains.filter(s => sensitiveTypes.includes(s.type));
        
        if (exposedSensitive.length > 0) {
            issues.push({
                type: 'SENSITIVE_SUBDOMAINS_EXPOSED',
                severity: 'MEDIUM',
                title: `${exposedSensitive.length} subdomínios sensíveis expostos`,
                description: `Subdomínios de desenvolvimento/admin encontrados: ${exposedSensitive.map(s => s.fqdn).join(', ')}`,
                recommendation: 'Restringir acesso a subdomínios de desenvolvimento e admin via VPN ou IP whitelist.'
            });
        }

        // Check for dangling CNAMEs
        const danglingCnames = subdomains.filter(s => s.danglingCname);
        if (danglingCnames.length > 0) {
            issues.push({
                type: 'DANGLING_CNAMES',
                severity: 'HIGH',
                title: `${danglingCnames.length} CNAMEs órfãos detectados`,
                description: `Subdomínios com CNAME que não resolve: ${danglingCnames.map(s => s.fqdn).join(', ')}`,
                recommendation: 'Remover registros DNS de subdomínios que não estão mais em uso.'
            });
        }

        return issues;
    }

    /**
     * Calculate summary
     */
    calculateSummary(results) {
        return {
            totalSubdomains: results.subdomains.length,
            takeoverVulnerabilities: results.takeoverRisks.length,
            dnsIssues: results.dnsIssues.length,
            byCategory: this.groupByCategory(results.subdomains),
            overallRisk: results.takeoverRisks.length > 0 ? 'HIGH' : 
                         results.dnsIssues.some(i => i.severity === 'HIGH') ? 'MEDIUM' : 'LOW'
        };
    }

    /**
     * Group subdomains by category
     */
    groupByCategory(subdomains) {
        const groups = {};
        for (const sub of subdomains) {
            if (!groups[sub.type]) {
                groups[sub.type] = [];
            }
            groups[sub.type].push(sub.fqdn);
        }
        return groups;
    }
}

module.exports = { SubdomainScanner };
