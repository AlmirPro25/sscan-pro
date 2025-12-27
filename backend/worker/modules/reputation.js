/**
 * MÓDULO DE REPUTAÇÃO - "A Vizinhança"
 * Verifica a reputação do IP e domínio
 * - Blacklist checking
 * - IP geolocation
 * - Domain age
 * - Abuse history
 */

const dns = require('dns').promises;
const https = require('https');

class ReputationScanner {
    constructor() {
        // DNS-based blacklists (DNSBL)
        this.dnsBlacklists = [
            { name: 'Spamhaus ZEN', zone: 'zen.spamhaus.org', type: 'spam' },
            { name: 'Spamhaus SBL', zone: 'sbl.spamhaus.org', type: 'spam' },
            { name: 'Spamhaus XBL', zone: 'xbl.spamhaus.org', type: 'exploit' },
            { name: 'Barracuda', zone: 'b.barracudacentral.org', type: 'spam' },
            { name: 'SpamCop', zone: 'bl.spamcop.net', type: 'spam' },
            { name: 'SORBS', zone: 'dnsbl.sorbs.net', type: 'spam' },
            { name: 'UCEPROTECT L1', zone: 'dnsbl-1.uceprotect.net', type: 'spam' },
            { name: 'Composite BL', zone: 'cbl.abuseat.org', type: 'exploit' },
            { name: 'Invaluement', zone: 'dnsbl.invaluement.com', type: 'spam' },
            { name: 'PSBL', zone: 'psbl.surriel.com', type: 'spam' },
        ];

        // Known malicious IP ranges (simplified - in production use threat intel feeds)
        this.knownBadRanges = [
            // These are example ranges - in production, use real threat intel
        ];
    }

    /**
     * Full reputation scan
     */
    async scan(url) {
        const startTime = Date.now();
        const hostname = new URL(url).hostname;

        console.log(`🔍 [REPUTATION] Starting reputation scan for: ${hostname}`);

        // Resolve IP
        let ip;
        try {
            const ips = await dns.resolve4(hostname);
            ip = ips[0];
        } catch (e) {
            return {
                error: 'Could not resolve hostname',
                hostname
            };
        }

        const results = {
            hostname,
            ip,
            scanTime: new Date().toISOString(),
            blacklists: await this.checkBlacklists(ip),
            ipInfo: await this.getIPInfo(ip),
            domainInfo: await this.getDomainInfo(hostname),
            emailSecurity: await this.checkEmailSecurity(hostname),
            summary: {}
        };

        // Calculate summary
        results.summary = this.calculateSummary(results);
        results.scanDuration = Date.now() - startTime;

        console.log(`✅ [REPUTATION] Scan complete. Listed on ${results.blacklists.listed.length} blacklists`);
        return results;
    }

    /**
     * Check IP against DNS blacklists
     */
    async checkBlacklists(ip) {
        const results = {
            ip,
            checked: [],
            listed: [],
            clean: []
        };

        // Reverse IP for DNSBL query
        const reversedIP = ip.split('.').reverse().join('.');

        console.log(`🔍 [REPUTATION] Checking ${this.dnsBlacklists.length} blacklists for ${ip}...`);

        const checks = await Promise.all(
            this.dnsBlacklists.map(async (bl) => {
                const query = `${reversedIP}.${bl.zone}`;
                try {
                    await dns.resolve4(query);
                    // If resolves, IP is listed
                    return {
                        name: bl.name,
                        zone: bl.zone,
                        type: bl.type,
                        listed: true
                    };
                } catch (e) {
                    // NXDOMAIN means not listed (good)
                    return {
                        name: bl.name,
                        zone: bl.zone,
                        type: bl.type,
                        listed: false
                    };
                }
            })
        );

        for (const check of checks) {
            results.checked.push(check.name);
            if (check.listed) {
                results.listed.push({
                    name: check.name,
                    type: check.type,
                    severity: check.type === 'exploit' ? 'CRITICAL' : 'HIGH'
                });
                console.log(`  ⚠️ Listed on ${check.name} (${check.type})`);
            } else {
                results.clean.push(check.name);
            }
        }

        return results;
    }

    /**
     * Get IP information (geolocation, ASN, etc.)
     * Using ip-api.com free tier
     */
    async getIPInfo(ip) {
        return new Promise((resolve) => {
            // Using ip-api.com (free, no API key needed)
            const options = {
                hostname: 'ip-api.com',
                path: `/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,hosting`,
                method: 'GET',
                timeout: 5000
            };

            const req = http.request(options, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    try {
                        const info = JSON.parse(data);
                        if (info.status === 'success') {
                            resolve({
                                country: info.country,
                                countryCode: info.countryCode,
                                region: info.regionName,
                                city: info.city,
                                isp: info.isp,
                                organization: info.org,
                                asn: info.as,
                                asnName: info.asname,
                                isHosting: info.hosting, // True if datacenter/hosting
                                coordinates: {
                                    lat: info.lat,
                                    lon: info.lon
                                },
                                timezone: info.timezone
                            });
                        } else {
                            resolve({ error: info.message || 'Unknown error' });
                        }
                    } catch (e) {
                        resolve({ error: 'Failed to parse response' });
                    }
                });
            });

            req.on('error', (e) => resolve({ error: e.message }));
            req.on('timeout', () => {
                req.destroy();
                resolve({ error: 'Timeout' });
            });

            req.end();
        });
    }

    /**
     * Get domain information
     */
    async getDomainInfo(hostname) {
        const info = {
            hostname,
            registrar: null,
            creationDate: null,
            expirationDate: null,
            age: null,
            nameServers: []
        };

        try {
            // Get nameservers
            info.nameServers = await dns.resolveNs(hostname).catch(() => []);

            // Note: WHOIS requires external service or library
            // For now, we'll just return what we can get from DNS
            
        } catch (e) {
            info.error = e.message;
        }

        return info;
    }

    /**
     * Check email security (SPF, DKIM, DMARC)
     */
    async checkEmailSecurity(hostname) {
        const results = {
            spf: { exists: false, record: null, issues: [] },
            dmarc: { exists: false, record: null, issues: [] },
            dkim: { exists: false, note: 'DKIM requires selector knowledge' }
        };

        try {
            // Check SPF
            const txtRecords = await dns.resolveTxt(hostname).catch(() => []);
            const spfRecord = txtRecords.flat().find(r => r.startsWith('v=spf1'));
            
            if (spfRecord) {
                results.spf.exists = true;
                results.spf.record = spfRecord;

                // Analyze SPF
                if (spfRecord.includes('+all')) {
                    results.spf.issues.push({
                        severity: 'CRITICAL',
                        issue: 'SPF com +all permite qualquer servidor enviar emails',
                        recommendation: 'Usar -all ou ~all para restringir'
                    });
                }
                if (!spfRecord.includes('-all') && !spfRecord.includes('~all')) {
                    results.spf.issues.push({
                        severity: 'MEDIUM',
                        issue: 'SPF não tem política de rejeição definida',
                        recommendation: 'Adicionar -all ao final do registro SPF'
                    });
                }
            } else {
                results.spf.issues.push({
                    severity: 'HIGH',
                    issue: 'Registro SPF não encontrado',
                    recommendation: 'Implementar SPF para prevenir email spoofing'
                });
            }

            // Check DMARC
            const dmarcRecords = await dns.resolveTxt(`_dmarc.${hostname}`).catch(() => []);
            const dmarcRecord = dmarcRecords.flat().find(r => r.startsWith('v=DMARC1'));

            if (dmarcRecord) {
                results.dmarc.exists = true;
                results.dmarc.record = dmarcRecord;

                // Analyze DMARC
                if (dmarcRecord.includes('p=none')) {
                    results.dmarc.issues.push({
                        severity: 'MEDIUM',
                        issue: 'DMARC com p=none não bloqueia emails falsificados',
                        recommendation: 'Migrar para p=quarantine ou p=reject'
                    });
                }
            } else {
                results.dmarc.issues.push({
                    severity: 'HIGH',
                    issue: 'Registro DMARC não encontrado',
                    recommendation: 'Implementar DMARC para proteção contra phishing'
                });
            }

        } catch (e) {
            results.error = e.message;
        }

        return results;
    }

    /**
     * Calculate summary
     */
    calculateSummary(results) {
        const summary = {
            overallReputation: 'GOOD',
            riskScore: 0,
            findings: []
        };

        // Blacklist findings
        if (results.blacklists.listed.length > 0) {
            const criticalListings = results.blacklists.listed.filter(l => l.severity === 'CRITICAL');
            
            if (criticalListings.length > 0) {
                summary.overallReputation = 'CRITICAL';
                summary.riskScore += 40;
                summary.findings.push({
                    type: 'BLACKLIST_CRITICAL',
                    severity: 'CRITICAL',
                    title: `IP listado em ${criticalListings.length} blacklist(s) de exploit/malware`,
                    description: `Blacklists: ${criticalListings.map(l => l.name).join(', ')}`,
                    recommendation: 'Investigar imediatamente. O servidor pode estar comprometido ou enviando spam/malware.'
                });
            }

            const spamListings = results.blacklists.listed.filter(l => l.type === 'spam');
            if (spamListings.length > 0) {
                if (summary.overallReputation !== 'CRITICAL') {
                    summary.overallReputation = 'POOR';
                }
                summary.riskScore += 20;
                summary.findings.push({
                    type: 'BLACKLIST_SPAM',
                    severity: 'HIGH',
                    title: `IP listado em ${spamListings.length} blacklist(s) de spam`,
                    description: `Blacklists: ${spamListings.map(l => l.name).join(', ')}`,
                    recommendation: 'Emails do domínio podem ir para spam. Solicitar remoção das blacklists.'
                });
            }
        }

        // Email security findings
        if (results.emailSecurity) {
            if (!results.emailSecurity.spf.exists) {
                summary.riskScore += 15;
                summary.findings.push({
                    type: 'NO_SPF',
                    severity: 'HIGH',
                    title: 'Sem proteção SPF',
                    description: 'Domínio vulnerável a email spoofing',
                    recommendation: 'Implementar registro SPF'
                });
            }
            if (!results.emailSecurity.dmarc.exists) {
                summary.riskScore += 15;
                summary.findings.push({
                    type: 'NO_DMARC',
                    severity: 'HIGH',
                    title: 'Sem proteção DMARC',
                    description: 'Domínio vulnerável a phishing',
                    recommendation: 'Implementar registro DMARC'
                });
            }
        }

        // IP info findings
        if (results.ipInfo && results.ipInfo.isHosting) {
            summary.findings.push({
                type: 'HOSTING_IP',
                severity: 'INFO',
                title: 'IP de datacenter/hosting detectado',
                description: `Hospedado em: ${results.ipInfo.isp || results.ipInfo.organization}`,
                recommendation: 'Informativo - IP é de provedor de hosting (normal para websites)'
            });
        }

        // Determine overall reputation
        if (summary.riskScore >= 40) {
            summary.overallReputation = 'CRITICAL';
        } else if (summary.riskScore >= 25) {
            summary.overallReputation = 'POOR';
        } else if (summary.riskScore >= 10) {
            summary.overallReputation = 'FAIR';
        }

        return summary;
    }
}

// Need http module for ip-api
const http = require('http');

module.exports = { ReputationScanner };
