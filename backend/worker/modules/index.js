/**
 * AegisScan Advanced Modules
 * 
 * Módulos avançados para análise de segurança enterprise:
 * 
 * 1. InfrastructureScanner - "O Porão"
 *    - Port scanning
 *    - Cloud detection
 *    - WAF detection
 *    - SSL analysis
 * 
 * 2. SubdomainScanner - "Os Fundos"
 *    - Subdomain enumeration
 *    - Takeover detection
 *    - DNS misconfiguration
 * 
 * 3. ReputationScanner - "A Vizinhança"
 *    - Blacklist checking
 *    - IP geolocation
 *    - Email security (SPF/DMARC)
 * 
 * 4. AuthenticatedScanner - "Os Andares de Cima"
 *    - Login automation
 *    - Session security
 *    - IDOR detection
 *    - Privilege escalation
 */

const { InfrastructureScanner } = require('./infrastructure');
const { SubdomainScanner } = require('./subdomain');
const { ReputationScanner } = require('./reputation');
const { AuthenticatedScanner } = require('./authenticated');

module.exports = {
    InfrastructureScanner,
    SubdomainScanner,
    ReputationScanner,
    AuthenticatedScanner
};
