export interface ScanResult {
    id?: number;
    target: string;
    timestamp: string;
    score: number;
    endpoints: Endpoint[];
    media?: MediaInfo;
    seo?: SeoInfo;
    assets?: AssetInfo;
    dom_images?: { src: string }[];
    full_links?: string[];
    tech?: TechStackInfo;
    security_audit?: SecurityAudit;
    performance?: PerformanceMetrics;
    discovery?: DiscoveryInfo;
    screenshot?: string; // Base64
    site_map?: SiteMap;
    // Legacy support
    created_at?: string;
}

export interface Endpoint {
    method: string;
    url: string;
    status: number;
    type?: string;
    contentType?: string;
}

export interface MediaInfo {
    player: string;
    streams: { type: string; url: string }[];
    encryption?: string;
}

export interface SeoInfo {
    title: string;
    description: string;
}

export interface AssetInfo {
    scripts: string[];
    styles: string[];
    images: { url: string }[];
    fonts: string[];
    documents: { type: string; url: string }[];
}

export interface TechStackInfo {
    techStack: string[];
    headers: {
        hsts: string;
        xFrame: string;
        server: string;
    };
    hasHttps: boolean;
    hasCsp: boolean;
    cookies: number;
}

export interface SecurityAudit {
    exposed_files: ExposedFile[];
    leaked_secrets: LeakedSecret[];
    attack_vectors: {
        forms: { method: string; action: string }[];
        url_parameters: string[];
    };
    ghost_routes: (string | { route: string; status: number; validated: boolean })[];
    ssl_info?: SSLInfo;
    vulnerabilities?: VulnerabilitySummary;
}

export interface ExposedFile {
    file: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
    status: string;
    url: string;
}

export interface LeakedSecret {
    type: string;
    source: string;
    snippet: string;
}

export interface SSLInfo {
    valid: boolean;
    daysRemaining: number;
    issuer: string;
    protocol: string;
    validFrom: string;
    validTo: string;
    cipher?: string;
}

export interface VulnerabilitySummary {
    total: number;
    critical: number;
    high: number;
    medium: number;
    xss: VulnerabilityDetail[];
    sqli: VulnerabilityDetail[];
    auth: VulnerabilityDetail[];
    ssl: any[];
}

export interface VulnerabilityDetail {
    severity: string;
    type: string;
    location: string;
    payload?: string;
    payloadType?: string;
    impact: string;
    recommendation: string;
    evidence?: string;
}

export interface PerformanceMetrics {
    timing?: {
        loadEventEnd: number;
        navigationStart: number;
        domContentLoadedEventEnd: number;
    };
    memory?: {
        usedJSHeapSize: number;
    };
}

export interface DiscoveryInfo {
    robots: string;
}

export interface SiteMap {
    nodes: { type: string; url: string; title: string; screenshot?: string }[];
}

export interface ScanDiff {
    diff: {
        score_change: number;
        endpoints_change: number;
        time_between: number;
    };
    scan1: ScanResult;
    scan2: ScanResult;
}

export interface DashboardStats {
    total_scans: number;
    avg_score: number;
    total_endpoints: number;
    score_trend: number[];
}

export enum ScreenState {
    DASHBOARD = 'dashboard',
    SCANNING = 'scanning',
    REPORT = 'report',
    HISTORY = 'history',
    SETTINGS = 'settings',
    CODE_SCANNER = 'code_scanner',
    PROJECTS = 'projects',
    ADVANCED_SCAN = 'advanced_scan',
    SCA_SCAN = 'sca_scan',
    CORRELATION = 'correlation'
}