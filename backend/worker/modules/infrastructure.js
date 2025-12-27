/**
 * MÓDULO DE INFRAESTRUTURA - "O Porão"
 * Analisa a infraestrutura por baixo do aplicativo web
 * - Port Scanning (portas comuns)
 * - Detecção de Cloud Provider
 * - Detecção de WAF/CDN
 * - DNS Information
 */

const dns = require('dns').promises;
const https = require('https');
const http = require('http');
const net = require('net');

class InfrastructureScanner {
    constructor() {
        // Portas comuns para scan (não intrusivo)
        this.commonPorts = [
            { port: 21, service: 'FTP', risk: 'HIGH', description: 'File Transfer Protocol - pode expor arquivos' },
            { port: 22, service: 'SSH', risk: 'MEDIUM', description: 'Secure Shell - acesso remoto' },
            { port: 23, service: 'Telnet', risk: 'CRITICAL', description: 'Telnet não criptografado - NUNCA deve estar aberto' },
            { port: 25, service: 'SMTP', risk: 'MEDIUM', description: 'Email server' },
            { port: 53, service: 'DNS', risk: 'LOW', description: 'DNS Server' },
            { port: 80, service: 'HTTP', risk: 'LOW', description: 'Web server não criptografado' },
            { port: 110, service: 'POP3', risk: 'MEDIUM', description: 'Email retrieval' },
            { port: 143, service: 'IMAP', risk: 'MEDIUM', description: 'Email retrieval' },
            { port: 443, service: 'HTTPS', risk: 'LOW', description: 'Web server criptografado' },
            { port: 445, service: 'SMB', risk: 'CRITICAL', description: 'Windows File Sharing - alto risco de ransomware' },
            { port: 1433, service: 'MSSQL', risk: 'CRITICAL', description: 'Microsoft SQL Server - banco de dados exposto!' },
            { port: 1521, service: 'Oracle', risk: 'CRITICAL', description: 'Oracle Database - banco de dados exposto!' },
            { port: 3306, service: 'MySQL', risk: 'CRITICAL', description: 'MySQL Database - banco de dados exposto!' },
            { port: 3389, service: 'RDP', risk: 'HIGH', description: 'Remote Desktop - acesso remoto Windows' },
            { port: 5432, service: 'PostgreSQL', risk: 'CRITICAL', description: 'PostgreSQL Database - banco de dados exposto!' },
            { port: 5900, service: 'VNC', risk: 'HIGH', description: 'Virtual Network Computing - acesso remoto' },
            { port: 6379, service: 'Redis', risk: 'CRITICAL', description: 'Redis Cache - frequentemente sem autenticação!' },
            { port: 8080, service: 'HTTP-Alt', risk: 'MEDIUM', description: 'HTTP alternativo - pode ser painel admin' },
            { port: 8443, service: 'HTTPS-Alt', risk: 'MEDIUM', description: 'HTTPS alternativo' },
            { port: 9200, service: 'Elasticsearch', risk: 'CRITICAL', description: 'Elasticsearch - dados podem estar expostos!' },
            { port: 27017, service: 'MongoDB', risk: 'CRITICAL', description: 'MongoDB - frequentemente sem autenticação!' },
        ];

        // Cloud providers signatures
        this.cloudSignatures = {
            'amazonaws.com': { provider: 'AWS', services: ['EC2', 'ELB', 'CloudFront'] },
            'cloudfront.net': { provider: 'AWS CloudFront', services: ['CDN'] },
            'elasticbeanstalk.com': { provider: 'AWS Elastic Beanstalk', services: ['PaaS'] },
            's3.amazonaws.com': { provider: 'AWS S3', services: ['Storage'] },
            'azure.com': { provider: 'Microsoft Azure', services: ['Cloud'] },
            'azurewebsites.net': { provider: 'Azure App Service', services: ['PaaS'] },
            'blob.core.windows.net': { provider: 'Azure Blob Storage', services: ['Storage'] },
            'googleusercontent.com': { provider: 'Google Cloud', services: ['Cloud'] },
            'appspot.com': { provider: 'Google App Engine', services: ['PaaS'] },
            'storage.googleapis.com': { provider: 'Google Cloud Storage', services: ['Storage'] },
            'cloudflare.com': { provider: 'Cloudflare', services: ['CDN', 'WAF', 'DDoS Protection'] },
            'fastly.net': { provider: 'Fastly', services: ['CDN'] },
            'akamai.net': { provider: 'Akamai', services: ['CDN', 'WAF'] },
            'edgecastcdn.net': { provider: 'Verizon EdgeCast', services: ['CDN'] },
            'vercel.app': { provider: 'Vercel', services: ['Serverless', 'CDN'] },
            'netlify.app': { provider: 'Netlify', services: ['Serverless', 'CDN'] },
            'herokuapp.com': { provider: 'Heroku', services: ['PaaS'] },
            'digitalocean.com': { provider: 'DigitalOcean', services: ['Cloud'] },
            'linode.com': { provider: 'Linode', services: ['Cloud'] },
        };

        // WAF signatures (response headers)
        this.wafSignatures = {
            'cf-ray': 'Cloudflare',
            'x-sucuri-id': 'Sucuri WAF',
            'x-sucuri-cache': 'Sucuri WAF',
            'server: cloudflare': 'Cloudflare',
            'server: AkamaiGHost': 'Akamai',
            'x-akamai-transformed': 'Akamai',
            'x-cdn': 'Generic CDN',
            'x-cache': 'CDN/Cache',
            'x-amz-cf-id': 'AWS CloudFront',
            'x-amz-cf-pop': 'AWS CloudFront',
            'x-azure-ref': 'Azure Front Door',
            'x-ms-ref': 'Azure CDN',
            'x-fw-protection': 'Fortinet FortiWeb',
            'x-denied-reason': 'Imperva Incapsula',
            'x-iinfo': 'Imperva Incapsula',
        };
    }

    /**
     * Scan completo de infraestrutura
     */
    async scan(url) {
        const startTime = Date.now();
        const hostname = new URL(url).hostname;

        console.log(`🔍 [INFRA] Starting infrastructure scan for: ${hostname}`);

        const results = {
            hostname,
            scanTime: new Date().toISOString(),
            dns: await this.scanDNS(hostname),
            ports: await this.scanPorts(hostname),
            cloud: await this.detectCloud(hostname, url),
            waf: null, // Will be filled by response headers
            ssl: await this.checkSSL(hostname),
            summary: {}
        };

        // Calculate risk summary
        results.summary = this.calculateRiskSummary(results);
        results.scanDuration = Date.now() - startTime;

        console.log(`✅ [INFRA] Scan complete in ${results.scanDuration}ms`);
        return results;
    }

    /**
     * DNS Information gathering
     */
    async scanDNS(hostname) {
        const dnsInfo = {
            ipAddresses: [],
            ipv6Addresses: [],
            nameServers: [],
            mxRecords: [],
            txtRecords: [],
            cname: null
        };

        try {
            // A records (IPv4)
            try {
                dnsInfo.ipAddresses = await dns.resolve4(hostname);
            } catch (e) { }

            // AAAA records (IPv6)
            try {
                dnsInfo.ipv6Addresses = await dns.resolve6(hostname);
            } catch (e) { }

            // NS records
            try {
                dnsInfo.nameServers = await dns.resolveNs(hostname);
            } catch (e) { }

            // MX records
            try {
                const mx = await dns.resolveMx(hostname);
                dnsInfo.mxRecords = mx.map(r => ({ exchange: r.exchange, priority: r.priority }));
            } catch (e) { }

            // TXT records (can contain SPF, DKIM, etc)
            try {
                const txt = await dns.resolveTxt(hostname);
                dnsInfo.txtRecords = txt.flat().slice(0, 10); // Limit to 10
            } catch (e) { }

            // CNAME
            try {
                dnsInfo.cname = await dns.resolveCname(hostname);
            } catch (e) { }

        } catch (e) {
            console.log(`⚠️ [INFRA] DNS scan error: ${e.message}`);
        }

        return dnsInfo;
    }

    /**
     * Port scanning (non-intrusive, TCP connect only)
     */
    async scanPorts(hostname) {
        const openPorts = [];
        const timeout = 2000; // 2 seconds timeout per port

        // Resolve hostname to IP first
        let ip;
        try {
            const ips = await dns.resolve4(hostname);
            ip = ips[0];
        } catch (e) {
            console.log(`⚠️ [INFRA] Could not resolve hostname for port scan`);
            return { scanned: false, reason: 'DNS resolution failed', openPorts: [] };
        }

        console.log(`🔍 [INFRA] Scanning ${this.commonPorts.length} common ports on ${ip}...`);

        // Scan ports in parallel batches
        const batchSize = 5;
        for (let i = 0; i < this.commonPorts.length; i += batchSize) {
            const batch = this.commonPorts.slice(i, i + batchSize);
            const results = await Promise.all(
                batch.map(portInfo => this.checkPort(ip, portInfo.port, timeout))
            );

            results.forEach((isOpen, idx) => {
                if (isOpen) {
                    const portInfo = batch[idx];
                    openPorts.push({
                        port: portInfo.port,
                        service: portInfo.service,
                        risk: portInfo.risk,
                        description: portInfo.description
                    });
                    console.log(`  ⚠️ Port ${portInfo.port} (${portInfo.service}) is OPEN - Risk: ${portInfo.risk}`);
                }
            });
        }

        return {
            scanned: true,
            ip,
            totalScanned: this.commonPorts.length,
            openPorts,
            criticalExposures: openPorts.filter(p => p.risk === 'CRITICAL'),
            highExposures: openPorts.filter(p => p.risk === 'HIGH')
        };
    }

    /**
     * Check if a single port is open
     */
    checkPort(host, port, timeout) {
        return new Promise((resolve) => {
            const socket = new net.Socket();

            socket.setTimeout(timeout);

            socket.on('connect', () => {
                socket.destroy();
                resolve(true);
            });

            socket.on('timeout', () => {
                socket.destroy();
                resolve(false);
            });

            socket.on('error', () => {
                socket.destroy();
                resolve(false);
            });

            socket.connect(port, host);
        });
    }

    /**
     * Detect cloud provider from DNS and headers
     */
    async detectCloud(hostname, url) {
        const cloudInfo = {
            detected: false,
            providers: [],
            services: []
        };

        // Check DNS records for cloud signatures
        try {
            const cname = await dns.resolveCname(hostname).catch(() => []);
            const allRecords = [...cname];

            for (const record of allRecords) {
                for (const [signature, info] of Object.entries(this.cloudSignatures)) {
                    if (record.toLowerCase().includes(signature)) {
                        cloudInfo.detected = true;
                        if (!cloudInfo.providers.includes(info.provider)) {
                            cloudInfo.providers.push(info.provider);
                            cloudInfo.services.push(...info.services);
                        }
                    }
                }
            }

            // Also check the hostname itself
            for (const [signature, info] of Object.entries(this.cloudSignatures)) {
                if (hostname.toLowerCase().includes(signature)) {
                    cloudInfo.detected = true;
                    if (!cloudInfo.providers.includes(info.provider)) {
                        cloudInfo.providers.push(info.provider);
                        cloudInfo.services.push(...info.services);
                    }
                }
            }

        } catch (e) {
            console.log(`⚠️ [INFRA] Cloud detection error: ${e.message}`);
        }

        // Remove duplicate services
        cloudInfo.services = [...new Set(cloudInfo.services)];

        return cloudInfo;
    }

    /**
     * Detect WAF from response headers
     */
    detectWAF(headers) {
        const wafInfo = {
            detected: false,
            providers: [],
            evidence: []
        };

        const headerStr = JSON.stringify(headers).toLowerCase();

        for (const [signature, provider] of Object.entries(this.wafSignatures)) {
            if (headerStr.includes(signature.toLowerCase())) {
                wafInfo.detected = true;
                if (!wafInfo.providers.includes(provider)) {
                    wafInfo.providers.push(provider);
                    wafInfo.evidence.push(signature);
                }
            }
        }

        return wafInfo;
    }

    /**
     * Check SSL certificate information
     */
    async checkSSL(hostname) {
        return new Promise((resolve) => {
            const options = {
                hostname,
                port: 443,
                method: 'GET',
                rejectUnauthorized: false, // Allow self-signed for inspection
                timeout: 5000
            };

            const req = https.request(options, (res) => {
                const cert = res.socket.getPeerCertificate();

                if (cert && Object.keys(cert).length > 0) {
                    const now = new Date();
                    const validFrom = new Date(cert.valid_from);
                    const validTo = new Date(cert.valid_to);
                    const daysUntilExpiry = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));

                    resolve({
                        valid: res.socket.authorized,
                        issuer: cert.issuer?.O || cert.issuer?.CN || 'Unknown',
                        subject: cert.subject?.CN || hostname,
                        validFrom: cert.valid_from,
                        validTo: cert.valid_to,
                        daysUntilExpiry,
                        expiryWarning: daysUntilExpiry < 30,
                        selfSigned: cert.issuer?.CN === cert.subject?.CN,
                        protocol: res.socket.getProtocol?.() || 'TLS',
                        serialNumber: cert.serialNumber
                    });
                } else {
                    resolve({ valid: false, error: 'No certificate found' });
                }
            });

            req.on('error', (e) => {
                resolve({ valid: false, error: e.message });
            });

            req.on('timeout', () => {
                req.destroy();
                resolve({ valid: false, error: 'Connection timeout' });
            });

            req.end();
        });
    }

    /**
     * Calculate overall risk summary
     */
    calculateRiskSummary(results) {
        const summary = {
            overallRisk: 'LOW',
            criticalFindings: 0,
            highFindings: 0,
            mediumFindings: 0,
            findings: []
        };

        // Check for critical port exposures
        if (results.ports.criticalExposures?.length > 0) {
            summary.criticalFindings += results.ports.criticalExposures.length;
            results.ports.criticalExposures.forEach(p => {
                summary.findings.push({
                    type: 'CRITICAL_PORT_EXPOSURE',
                    severity: 'CRITICAL',
                    title: `${p.service} (porta ${p.port}) exposto à internet`,
                    description: p.description,
                    recommendation: `Fechar porta ${p.port} ou restringir acesso via firewall`
                });
            });
        }

        // Check for high risk port exposures
        if (results.ports.highExposures?.length > 0) {
            summary.highFindings += results.ports.highExposures.length;
            results.ports.highExposures.forEach(p => {
                summary.findings.push({
                    type: 'HIGH_PORT_EXPOSURE',
                    severity: 'HIGH',
                    title: `${p.service} (porta ${p.port}) exposto`,
                    description: p.description,
                    recommendation: `Avaliar necessidade de expor porta ${p.port}`
                });
            });
        }

        // Check SSL issues
        if (results.ssl) {
            if (!results.ssl.valid) {
                summary.highFindings++;
                summary.findings.push({
                    type: 'SSL_INVALID',
                    severity: 'HIGH',
                    title: 'Certificado SSL inválido',
                    description: results.ssl.error || 'Certificado não é confiável',
                    recommendation: 'Obter certificado SSL válido de uma CA confiável'
                });
            } else if (results.ssl.selfSigned) {
                summary.mediumFindings++;
                summary.findings.push({
                    type: 'SSL_SELF_SIGNED',
                    severity: 'MEDIUM',
                    title: 'Certificado SSL auto-assinado',
                    description: 'Certificado não é emitido por uma CA confiável',
                    recommendation: 'Usar certificado de CA confiável (Let\'s Encrypt é gratuito)'
                });
            } else if (results.ssl.expiryWarning) {
                summary.mediumFindings++;
                summary.findings.push({
                    type: 'SSL_EXPIRING',
                    severity: 'MEDIUM',
                    title: `Certificado SSL expira em ${results.ssl.daysUntilExpiry} dias`,
                    description: 'Certificado próximo da expiração',
                    recommendation: 'Renovar certificado SSL antes da expiração'
                });
            }
        }

        // Determine overall risk
        if (summary.criticalFindings > 0) {
            summary.overallRisk = 'CRITICAL';
        } else if (summary.highFindings > 0) {
            summary.overallRisk = 'HIGH';
        } else if (summary.mediumFindings > 0) {
            summary.overallRisk = 'MEDIUM';
        }

        return summary;
    }
}

module.exports = { InfrastructureScanner };
