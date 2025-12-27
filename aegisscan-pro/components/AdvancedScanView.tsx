import React, { useState, useEffect } from 'react';

interface AdvancedScanResult {
    id: number;
    url: string;
    modules_run: string[];
    modules: {
        infrastructure?: any;
        subdomains?: any;
        reputation?: any;
        authenticated?: any;
    };
    summary: {
        overallRisk: string;
        criticalFindings: number;
        highFindings: number;
        mediumFindings: number;
        highlights: string[];
    };
    created_at: string;
}

interface Props {
    onBack: () => void;
}

export const AdvancedScanView: React.FC<Props> = ({ onBack }) => {
    const [url, setUrl] = useState('');
    const [scanning, setScanning] = useState(false);
    const [result, setResult] = useState<AdvancedScanResult | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [activeModule, setActiveModule] = useState<string>('summary');
    const [history, setHistory] = useState<AdvancedScanResult[]>([]);
    const [showHistory, setShowHistory] = useState(false);
    
    // Module toggles
    const [modules, setModules] = useState({
        infrastructure: true,
        subdomains: true,
        reputation: true,
        authenticated: false
    });
    
    // Credentials for authenticated scan
    const [credentials, setCredentials] = useState({
        username: '',
        password: '',
        loginUrl: ''
    });

    useEffect(() => {
        loadHistory();
    }, []);

    const loadHistory = async () => {
        try {
            const response = await fetch('http://localhost:8080/api/v1/scan/advanced/history');
            if (response.ok) {
                const data = await response.json();
                setHistory(data);
            }
        } catch (e) {
            console.error('Failed to load history');
        }
    };

    const handleScan = async () => {
        if (!url.trim()) {
            setError('Digite a URL do alvo');
            return;
        }

        setScanning(true);
        setError(null);
        setResult(null);

        try {
            const payload: any = {
                url: url.trim(),
                modules
            };

            if (modules.authenticated && credentials.username) {
                payload.credentials = credentials;
            }

            const response = await fetch('http://localhost:8080/api/v1/scan/advanced', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            if (!response.ok) {
                const err = await response.json();
                throw new Error(err.error || 'Scan failed');
            }

            const data = await response.json();
            setResult(data);
            loadHistory();
        } catch (e: any) {
            setError(e.message);
        } finally {
            setScanning(false);
        }
    };

    const getRiskColor = (risk: string) => {
        switch (risk) {
            case 'CRITICAL': return 'bg-red-600 text-white';
            case 'HIGH': return 'bg-orange-500 text-white';
            case 'MEDIUM': return 'bg-yellow-500 text-black';
            case 'LOW': return 'bg-green-500 text-white';
            default: return 'bg-slate-500 text-white';
        }
    };

    const getRiskBgColor = (risk: string) => {
        switch (risk) {
            case 'CRITICAL': return 'bg-red-50 border-red-200';
            case 'HIGH': return 'bg-orange-50 border-orange-200';
            case 'MEDIUM': return 'bg-yellow-50 border-yellow-200';
            case 'LOW': return 'bg-green-50 border-green-200';
            default: return 'bg-slate-50 border-slate-200';
        }
    };

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                    <button onClick={onBack} className="p-2 hover:bg-slate-100 rounded-lg transition-colors">
                        <i className="fas fa-arrow-left text-slate-600"></i>
                    </button>
                    <div>
                        <h2 className="text-2xl font-bold text-slate-900">Advanced Security Scan</h2>
                        <p className="text-sm text-slate-500">Infraestrutura, Subdomínios, Reputação e Autenticação</p>
                    </div>
                </div>
                <button
                    onClick={() => setShowHistory(!showHistory)}
                    className={`px-4 py-2 rounded-lg transition-colors ${
                        showHistory ? 'bg-indigo-100 text-indigo-700' : 'bg-slate-100 text-slate-700 hover:bg-slate-200'
                    }`}
                >
                    <i className="fas fa-history mr-2"></i>
                    Histórico
                </button>
            </div>

            {/* Input Section */}
            <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm">
                <div className="space-y-4">
                    {/* URL Input */}
                    <div>
                        <label className="block text-sm font-medium text-slate-700 mb-2">
                            <i className="fas fa-globe mr-2"></i>
                            URL do Alvo
                        </label>
                        <input
                            type="text"
                            value={url}
                            onChange={(e) => setUrl(e.target.value)}
                            placeholder="https://exemplo.com"
                            className="w-full px-4 py-3 border border-slate-300 rounded-xl focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                            onKeyDown={(e) => e.key === 'Enter' && handleScan()}
                        />
                    </div>

                    {/* Module Selection */}
                    <div>
                        <label className="block text-sm font-medium text-slate-700 mb-3">
                            <i className="fas fa-cubes mr-2"></i>
                            Módulos de Scan
                        </label>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                            {[
                                { key: 'infrastructure', label: 'Infraestrutura', icon: 'fa-server', desc: 'Portas, Cloud, SSL' },
                                { key: 'subdomains', label: 'Subdomínios', icon: 'fa-sitemap', desc: 'Enumeração, Takeover' },
                                { key: 'reputation', label: 'Reputação', icon: 'fa-shield-alt', desc: 'Blacklists, Email' },
                                { key: 'authenticated', label: 'Autenticado', icon: 'fa-lock', desc: 'Login, IDOR, Session' },
                            ].map(mod => (
                                <button
                                    key={mod.key}
                                    onClick={() => setModules(prev => ({ ...prev, [mod.key]: !prev[mod.key as keyof typeof prev] }))}
                                    className={`p-4 rounded-xl border-2 transition-all text-left ${
                                        modules[mod.key as keyof typeof modules]
                                            ? 'border-indigo-500 bg-indigo-50'
                                            : 'border-slate-200 hover:border-slate-300'
                                    }`}
                                >
                                    <div className="flex items-center gap-2 mb-1">
                                        <i className={`fas ${mod.icon} ${modules[mod.key as keyof typeof modules] ? 'text-indigo-600' : 'text-slate-400'}`}></i>
                                        <span className={`font-medium ${modules[mod.key as keyof typeof modules] ? 'text-indigo-700' : 'text-slate-700'}`}>
                                            {mod.label}
                                        </span>
                                    </div>
                                    <span className="text-xs text-slate-500">{mod.desc}</span>
                                </button>
                            ))}
                        </div>
                    </div>

                    {/* Credentials (if authenticated module selected) */}
                    {modules.authenticated && (
                        <div className="p-4 bg-amber-50 border border-amber-200 rounded-xl">
                            <h4 className="font-medium text-amber-800 mb-3">
                                <i className="fas fa-key mr-2"></i>
                                Credenciais de Teste
                            </h4>
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                                <input
                                    type="text"
                                    value={credentials.username}
                                    onChange={(e) => setCredentials(prev => ({ ...prev, username: e.target.value }))}
                                    placeholder="Usuário"
                                    className="px-3 py-2 border border-amber-300 rounded-lg bg-white"
                                />
                                <input
                                    type="password"
                                    value={credentials.password}
                                    onChange={(e) => setCredentials(prev => ({ ...prev, password: e.target.value }))}
                                    placeholder="Senha"
                                    className="px-3 py-2 border border-amber-300 rounded-lg bg-white"
                                />
                                <input
                                    type="text"
                                    value={credentials.loginUrl}
                                    onChange={(e) => setCredentials(prev => ({ ...prev, loginUrl: e.target.value }))}
                                    placeholder="URL de Login (opcional)"
                                    className="px-3 py-2 border border-amber-300 rounded-lg bg-white"
                                />
                            </div>
                            <p className="text-xs text-amber-600 mt-2">
                                ⚠️ Use apenas credenciais de teste. Nunca use credenciais de produção.
                            </p>
                        </div>
                    )}

                    {/* Scan Button */}
                    <div className="flex justify-end">
                        <button
                            onClick={handleScan}
                            disabled={scanning || !Object.values(modules).some(v => v)}
                            className="px-6 py-3 bg-gradient-to-r from-indigo-600 to-purple-600 text-white rounded-xl font-semibold hover:from-indigo-700 hover:to-purple-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center gap-2"
                        >
                            {scanning ? (
                                <>
                                    <i className="fas fa-spinner fa-spin"></i>
                                    Escaneando...
                                </>
                            ) : (
                                <>
                                    <i className="fas fa-rocket"></i>
                                    Iniciar Scan Avançado
                                </>
                            )}
                        </button>
                    </div>
                </div>

                {error && (
                    <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-xl text-red-700 flex items-center gap-2">
                        <i className="fas fa-exclamation-circle"></i>
                        {error}
                    </div>
                )}
            </div>

            {/* History Panel */}
            {showHistory && history.length > 0 && (
                <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm">
                    <h3 className="font-semibold text-slate-900 mb-4">Histórico de Scans Avançados</h3>
                    <div className="space-y-2 max-h-60 overflow-y-auto">
                        {history.map((scan) => (
                            <button
                                key={scan.id}
                                onClick={async () => {
                                    const response = await fetch(`http://localhost:8080/api/v1/scan/advanced/${scan.id}`);
                                    if (response.ok) {
                                        const data = await response.json();
                                        setResult(data);
                                        setUrl(data.url);
                                        setShowHistory(false);
                                    }
                                }}
                                className="w-full p-3 bg-slate-50 border border-slate-200 rounded-xl hover:bg-indigo-50 hover:border-indigo-300 transition-colors text-left flex items-center gap-3"
                            >
                                <div className={`w-10 h-10 rounded-lg flex items-center justify-center text-white text-xs font-bold ${getRiskColor(scan.summary?.overallRisk || 'LOW')}`}>
                                    {scan.summary?.overallRisk?.charAt(0) || 'L'}
                                </div>
                                <div className="flex-1 min-w-0">
                                    <div className="font-medium text-slate-700 truncate">{scan.url}</div>
                                    <div className="text-xs text-slate-400">
                                        {scan.modules_run?.join(', ')} • {new Date(scan.created_at).toLocaleString()}
                                    </div>
                                </div>
                                <i className="fas fa-chevron-right text-slate-400"></i>
                            </button>
                        ))}
                    </div>
                </div>
            )}

            {/* Results Section */}
            {result && (
                <>
                    {/* Summary Card */}
                    <div className={`rounded-2xl border p-6 ${getRiskBgColor(result.summary?.overallRisk || 'LOW')}`}>
                        <div className="flex items-center justify-between mb-4">
                            <div>
                                <h3 className="text-lg font-bold text-slate-900">Resultado do Scan</h3>
                                <p className="text-sm text-slate-500">{result.url}</p>
                            </div>
                            <span className={`px-4 py-2 rounded-lg font-bold ${getRiskColor(result.summary?.overallRisk || 'LOW')}`}>
                                {result.summary?.overallRisk || 'LOW'} RISK
                            </span>
                        </div>
                        
                        <div className="grid grid-cols-4 gap-4 mb-4">
                            <div className="text-center p-3 bg-white/50 rounded-lg">
                                <div className="text-2xl font-bold text-red-600">{result.summary?.criticalFindings || 0}</div>
                                <div className="text-xs text-slate-500">Critical</div>
                            </div>
                            <div className="text-center p-3 bg-white/50 rounded-lg">
                                <div className="text-2xl font-bold text-orange-500">{result.summary?.highFindings || 0}</div>
                                <div className="text-xs text-slate-500">High</div>
                            </div>
                            <div className="text-center p-3 bg-white/50 rounded-lg">
                                <div className="text-2xl font-bold text-yellow-500">{result.summary?.mediumFindings || 0}</div>
                                <div className="text-xs text-slate-500">Medium</div>
                            </div>
                            <div className="text-center p-3 bg-white/50 rounded-lg">
                                <div className="text-2xl font-bold text-green-500">{result.summary?.lowFindings || 0}</div>
                                <div className="text-xs text-slate-500">Low</div>
                            </div>
                        </div>

                        {result.summary?.highlights && result.summary.highlights.length > 0 && (
                            <div className="space-y-2">
                                <h4 className="font-medium text-slate-700">Destaques:</h4>
                                {result.summary.highlights.map((h, i) => (
                                    <div key={i} className="flex items-center gap-2 text-sm text-slate-600">
                                        <i className="fas fa-exclamation-triangle text-amber-500"></i>
                                        {h}
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>

                    {/* Module Tabs */}
                    <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
                        <div className="flex border-b border-slate-200 overflow-x-auto">
                            {[
                                { key: 'summary', label: 'Resumo', icon: 'fa-chart-pie' },
                                { key: 'infrastructure', label: 'Infraestrutura', icon: 'fa-server' },
                                { key: 'subdomains', label: 'Subdomínios', icon: 'fa-sitemap' },
                                { key: 'reputation', label: 'Reputação', icon: 'fa-shield-alt' },
                                { key: 'authenticated', label: 'Autenticado', icon: 'fa-lock' },
                            ].map(tab => (
                                <button
                                    key={tab.key}
                                    onClick={() => setActiveModule(tab.key)}
                                    disabled={tab.key !== 'summary' && !result.modules?.[tab.key as keyof typeof result.modules]}
                                    className={`flex-shrink-0 px-6 py-4 text-sm font-medium transition-colors ${
                                        activeModule === tab.key
                                            ? 'bg-indigo-50 text-indigo-700 border-b-2 border-indigo-600'
                                            : 'text-slate-600 hover:bg-slate-50 disabled:opacity-40 disabled:cursor-not-allowed'
                                    }`}
                                >
                                    <i className={`fas ${tab.icon} mr-2`}></i>
                                    {tab.label}
                                </button>
                            ))}
                        </div>

                        <div className="p-6 max-h-[600px] overflow-y-auto">
                            {/* Summary Tab */}
                            {activeModule === 'summary' && (
                                <div className="space-y-4">
                                    <h4 className="font-semibold text-slate-900">Visão Geral do Scan</h4>
                                    <div className="grid grid-cols-2 gap-4">
                                        <div className="p-4 bg-slate-50 rounded-xl">
                                            <div className="text-sm text-slate-500 mb-1">URL Alvo</div>
                                            <div className="font-mono text-sm text-slate-700 break-all">{result.url}</div>
                                        </div>
                                        <div className="p-4 bg-slate-50 rounded-xl">
                                            <div className="text-sm text-slate-500 mb-1">Módulos Executados</div>
                                            <div className="flex flex-wrap gap-2">
                                                {result.modules_run?.map(m => (
                                                    <span key={m} className="px-2 py-1 bg-indigo-100 text-indigo-700 rounded text-xs font-medium">
                                                        {m}
                                                    </span>
                                                ))}
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            )}

                            {/* Infrastructure Tab */}
                            {activeModule === 'infrastructure' && result.modules?.infrastructure && (
                                <div className="space-y-6">
                                    {/* Ports */}
                                    {result.modules.infrastructure.ports && (
                                        <div>
                                            <h4 className="font-semibold text-slate-900 mb-3">
                                                <i className="fas fa-network-wired mr-2 text-indigo-500"></i>
                                                Portas Abertas
                                            </h4>
                                            {result.modules.infrastructure.ports.openPorts?.length > 0 ? (
                                                <div className="space-y-2">
                                                    {result.modules.infrastructure.ports.openPorts.map((port: any, i: number) => (
                                                        <div key={i} className={`p-3 rounded-lg border ${
                                                            port.risk === 'CRITICAL' ? 'bg-red-50 border-red-200' :
                                                            port.risk === 'HIGH' ? 'bg-orange-50 border-orange-200' :
                                                            'bg-slate-50 border-slate-200'
                                                        }`}>
                                                            <div className="flex items-center justify-between">
                                                                <div className="flex items-center gap-3">
                                                                    <span className="font-mono font-bold text-slate-700">{port.port}</span>
                                                                    <span className="font-medium text-slate-600">{port.service}</span>
                                                                </div>
                                                                <span className={`px-2 py-1 rounded text-xs font-bold ${getRiskColor(port.risk)}`}>
                                                                    {port.risk}
                                                                </span>
                                                            </div>
                                                            <p className="text-sm text-slate-500 mt-1">{port.description}</p>
                                                        </div>
                                                    ))}
                                                </div>
                                            ) : (
                                                <div className="p-4 bg-green-50 border border-green-200 rounded-lg text-green-700">
                                                    <i className="fas fa-check-circle mr-2"></i>
                                                    Nenhuma porta crítica exposta
                                                </div>
                                            )}
                                        </div>
                                    )}

                                    {/* SSL */}
                                    {result.modules.infrastructure.ssl && (
                                        <div>
                                            <h4 className="font-semibold text-slate-900 mb-3">
                                                <i className="fas fa-lock mr-2 text-green-500"></i>
                                                Certificado SSL
                                            </h4>
                                            <div className="p-4 bg-slate-50 rounded-lg space-y-2">
                                                <div className="flex justify-between">
                                                    <span className="text-slate-500">Válido:</span>
                                                    <span className={result.modules.infrastructure.ssl.valid ? 'text-green-600' : 'text-red-600'}>
                                                        {result.modules.infrastructure.ssl.valid ? 'Sim' : 'Não'}
                                                    </span>
                                                </div>
                                                <div className="flex justify-between">
                                                    <span className="text-slate-500">Emissor:</span>
                                                    <span className="text-slate-700">{result.modules.infrastructure.ssl.issuer}</span>
                                                </div>
                                                <div className="flex justify-between">
                                                    <span className="text-slate-500">Expira em:</span>
                                                    <span className={result.modules.infrastructure.ssl.daysUntilExpiry < 30 ? 'text-amber-600' : 'text-slate-700'}>
                                                        {result.modules.infrastructure.ssl.daysUntilExpiry} dias
                                                    </span>
                                                </div>
                                            </div>
                                        </div>
                                    )}

                                    {/* Cloud */}
                                    {result.modules.infrastructure.cloud && (
                                        <div>
                                            <h4 className="font-semibold text-slate-900 mb-3">
                                                <i className="fas fa-cloud mr-2 text-blue-500"></i>
                                                Cloud Provider
                                            </h4>
                                            <div className="p-4 bg-slate-50 rounded-lg">
                                                {result.modules.infrastructure.cloud.detected ? (
                                                    <div className="space-y-2">
                                                        <div className="flex flex-wrap gap-2">
                                                            {result.modules.infrastructure.cloud.providers?.map((p: string, i: number) => (
                                                                <span key={i} className="px-3 py-1 bg-blue-100 text-blue-700 rounded-full text-sm font-medium">
                                                                    {p}
                                                                </span>
                                                            ))}
                                                        </div>
                                                        <div className="text-sm text-slate-500">
                                                            Serviços: {result.modules.infrastructure.cloud.services?.join(', ')}
                                                        </div>
                                                    </div>
                                                ) : (
                                                    <span className="text-slate-500">Nenhum cloud provider detectado</span>
                                                )}
                                            </div>
                                        </div>
                                    )}
                                </div>
                            )}

                            {/* Subdomains Tab */}
                            {activeModule === 'subdomains' && result.modules?.subdomains && (
                                <div className="space-y-6">
                                    {/* Stats */}
                                    <div className="grid grid-cols-3 gap-4">
                                        <div className="p-4 bg-slate-50 rounded-lg text-center">
                                            <div className="text-2xl font-bold text-slate-700">
                                                {result.modules.subdomains.summary?.totalSubdomains || 0}
                                            </div>
                                            <div className="text-xs text-slate-500">Subdomínios</div>
                                        </div>
                                        <div className="p-4 bg-red-50 rounded-lg text-center">
                                            <div className="text-2xl font-bold text-red-600">
                                                {result.modules.subdomains.summary?.takeoverVulnerabilities || 0}
                                            </div>
                                            <div className="text-xs text-slate-500">Takeover Risks</div>
                                        </div>
                                        <div className="p-4 bg-amber-50 rounded-lg text-center">
                                            <div className="text-2xl font-bold text-amber-600">
                                                {result.modules.subdomains.summary?.dnsIssues || 0}
                                            </div>
                                            <div className="text-xs text-slate-500">DNS Issues</div>
                                        </div>
                                    </div>

                                    {/* Takeover Risks */}
                                    {result.modules.subdomains.takeoverRisks?.length > 0 && (
                                        <div>
                                            <h4 className="font-semibold text-red-700 mb-3">
                                                <i className="fas fa-exclamation-triangle mr-2"></i>
                                                Subdomain Takeover Vulnerabilities
                                            </h4>
                                            <div className="space-y-2">
                                                {result.modules.subdomains.takeoverRisks.map((risk: any, i: number) => (
                                                    <div key={i} className="p-4 bg-red-50 border border-red-200 rounded-lg">
                                                        <div className="flex items-center justify-between mb-2">
                                                            <span className="font-mono font-medium text-red-700">{risk.subdomain}</span>
                                                            <span className={`px-2 py-1 rounded text-xs font-bold ${getRiskColor(risk.severity)}`}>
                                                                {risk.severity}
                                                            </span>
                                                        </div>
                                                        <p className="text-sm text-red-600">{risk.recommendation}</p>
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    )}

                                    {/* Found Subdomains */}
                                    {result.modules.subdomains.subdomains?.length > 0 && (
                                        <div>
                                            <h4 className="font-semibold text-slate-900 mb-3">
                                                <i className="fas fa-sitemap mr-2 text-indigo-500"></i>
                                                Subdomínios Encontrados
                                            </h4>
                                            <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                                                {result.modules.subdomains.subdomains.map((sub: any, i: number) => (
                                                    <div key={i} className={`p-2 rounded-lg text-sm ${
                                                        sub.danglingCname ? 'bg-amber-50 border border-amber-200' : 'bg-slate-50'
                                                    }`}>
                                                        <span className="font-mono text-slate-700">{sub.fqdn}</span>
                                                        <span className={`ml-2 text-xs px-1 rounded ${
                                                            sub.type === 'admin' ? 'bg-red-100 text-red-600' :
                                                            sub.type === 'development' ? 'bg-amber-100 text-amber-600' :
                                                            sub.type === 'api' ? 'bg-blue-100 text-blue-600' :
                                                            'bg-slate-100 text-slate-500'
                                                        }`}>
                                                            {sub.type}
                                                        </span>
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    )}
                                </div>
                            )}

                            {/* Reputation Tab */}
                            {activeModule === 'reputation' && result.modules?.reputation && (
                                <div className="space-y-6">
                                    {/* IP Info */}
                                    {result.modules.reputation.ipInfo && (
                                        <div>
                                            <h4 className="font-semibold text-slate-900 mb-3">
                                                <i className="fas fa-map-marker-alt mr-2 text-blue-500"></i>
                                                Informações do IP
                                            </h4>
                                            <div className="p-4 bg-slate-50 rounded-lg grid grid-cols-2 gap-4">
                                                <div>
                                                    <span className="text-slate-500 text-sm">IP:</span>
                                                    <span className="ml-2 font-mono text-slate-700">{result.modules.reputation.ip}</span>
                                                </div>
                                                <div>
                                                    <span className="text-slate-500 text-sm">País:</span>
                                                    <span className="ml-2 text-slate-700">{result.modules.reputation.ipInfo.country}</span>
                                                </div>
                                                <div>
                                                    <span className="text-slate-500 text-sm">ISP:</span>
                                                    <span className="ml-2 text-slate-700">{result.modules.reputation.ipInfo.isp}</span>
                                                </div>
                                                <div>
                                                    <span className="text-slate-500 text-sm">ASN:</span>
                                                    <span className="ml-2 text-slate-700">{result.modules.reputation.ipInfo.asn}</span>
                                                </div>
                                            </div>
                                        </div>
                                    )}

                                    {/* Blacklists */}
                                    {result.modules.reputation.blacklists && (
                                        <div>
                                            <h4 className="font-semibold text-slate-900 mb-3">
                                                <i className="fas fa-ban mr-2 text-red-500"></i>
                                                Blacklists ({result.modules.reputation.blacklists.listed?.length || 0} listagens)
                                            </h4>
                                            {result.modules.reputation.blacklists.listed?.length > 0 ? (
                                                <div className="space-y-2">
                                                    {result.modules.reputation.blacklists.listed.map((bl: any, i: number) => (
                                                        <div key={i} className="p-3 bg-red-50 border border-red-200 rounded-lg flex items-center justify-between">
                                                            <span className="font-medium text-red-700">{bl.name}</span>
                                                            <span className={`px-2 py-1 rounded text-xs font-bold ${getRiskColor(bl.severity)}`}>
                                                                {bl.type}
                                                            </span>
                                                        </div>
                                                    ))}
                                                </div>
                                            ) : (
                                                <div className="p-4 bg-green-50 border border-green-200 rounded-lg text-green-700">
                                                    <i className="fas fa-check-circle mr-2"></i>
                                                    IP não está em nenhuma blacklist verificada
                                                </div>
                                            )}
                                        </div>
                                    )}

                                    {/* Email Security */}
                                    {result.modules.reputation.emailSecurity && (
                                        <div>
                                            <h4 className="font-semibold text-slate-900 mb-3">
                                                <i className="fas fa-envelope mr-2 text-indigo-500"></i>
                                                Segurança de Email
                                            </h4>
                                            <div className="grid grid-cols-2 gap-4">
                                                <div className={`p-4 rounded-lg ${
                                                    result.modules.reputation.emailSecurity.spf?.exists 
                                                        ? 'bg-green-50 border border-green-200' 
                                                        : 'bg-red-50 border border-red-200'
                                                }`}>
                                                    <div className="flex items-center gap-2 mb-1">
                                                        <i className={`fas ${result.modules.reputation.emailSecurity.spf?.exists ? 'fa-check text-green-500' : 'fa-times text-red-500'}`}></i>
                                                        <span className="font-medium">SPF</span>
                                                    </div>
                                                    <p className="text-xs text-slate-500">
                                                        {result.modules.reputation.emailSecurity.spf?.exists ? 'Configurado' : 'Não configurado'}
                                                    </p>
                                                </div>
                                                <div className={`p-4 rounded-lg ${
                                                    result.modules.reputation.emailSecurity.dmarc?.exists 
                                                        ? 'bg-green-50 border border-green-200' 
                                                        : 'bg-red-50 border border-red-200'
                                                }`}>
                                                    <div className="flex items-center gap-2 mb-1">
                                                        <i className={`fas ${result.modules.reputation.emailSecurity.dmarc?.exists ? 'fa-check text-green-500' : 'fa-times text-red-500'}`}></i>
                                                        <span className="font-medium">DMARC</span>
                                                    </div>
                                                    <p className="text-xs text-slate-500">
                                                        {result.modules.reputation.emailSecurity.dmarc?.exists ? 'Configurado' : 'Não configurado'}
                                                    </p>
                                                </div>
                                            </div>
                                        </div>
                                    )}
                                </div>
                            )}

                            {/* Authenticated Tab */}
                            {activeModule === 'authenticated' && result.modules?.authenticated && (
                                <div className="space-y-6">
                                    {/* Login Status */}
                                    <div className={`p-4 rounded-lg ${
                                        result.modules.authenticated.loginSuccess 
                                            ? 'bg-green-50 border border-green-200' 
                                            : 'bg-red-50 border border-red-200'
                                    }`}>
                                        <div className="flex items-center gap-2">
                                            <i className={`fas ${result.modules.authenticated.loginSuccess ? 'fa-check-circle text-green-500' : 'fa-times-circle text-red-500'}`}></i>
                                            <span className="font-medium">
                                                {result.modules.authenticated.loginSuccess ? 'Login bem-sucedido' : 'Login falhou'}
                                            </span>
                                        </div>
                                    </div>

                                    {/* IDOR Vulnerabilities */}
                                    {result.modules.authenticated.idorTests?.filter((t: any) => t.vulnerable).length > 0 && (
                                        <div>
                                            <h4 className="font-semibold text-red-700 mb-3">
                                                <i className="fas fa-user-secret mr-2"></i>
                                                Vulnerabilidades IDOR
                                            </h4>
                                            <div className="space-y-2">
                                                {result.modules.authenticated.idorTests.filter((t: any) => t.vulnerable).map((idor: any, i: number) => (
                                                    <div key={i} className="p-4 bg-red-50 border border-red-200 rounded-lg">
                                                        <div className="flex items-center justify-between mb-2">
                                                            <span className="font-medium text-red-700">{idor.parameter}</span>
                                                            <span className={`px-2 py-1 rounded text-xs font-bold ${getRiskColor(idor.severity)}`}>
                                                                {idor.severity}
                                                            </span>
                                                        </div>
                                                        <p className="text-sm text-red-600 mb-2">{idor.issue}</p>
                                                        <p className="text-xs text-slate-500">{idor.recommendation}</p>
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    )}

                                    {/* Session Issues */}
                                    {result.modules.authenticated.sessionInfo?.issues?.length > 0 && (
                                        <div>
                                            <h4 className="font-semibold text-amber-700 mb-3">
                                                <i className="fas fa-cookie mr-2"></i>
                                                Problemas de Sessão
                                            </h4>
                                            <div className="space-y-2">
                                                {result.modules.authenticated.sessionInfo.issues.map((issue: any, i: number) => (
                                                    <div key={i} className="p-3 bg-amber-50 border border-amber-200 rounded-lg">
                                                        <div className="flex items-center justify-between mb-1">
                                                            <span className="font-medium text-amber-700">{issue.issue}</span>
                                                            <span className={`px-2 py-1 rounded text-xs font-bold ${getRiskColor(issue.severity)}`}>
                                                                {issue.severity}
                                                            </span>
                                                        </div>
                                                        <p className="text-xs text-slate-500">{issue.recommendation}</p>
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    )}

                                    {/* Discovered Pages */}
                                    {result.modules.authenticated.accessiblePages?.length > 0 && (
                                        <div>
                                            <h4 className="font-semibold text-slate-900 mb-3">
                                                <i className="fas fa-file-alt mr-2 text-indigo-500"></i>
                                                Páginas Descobertas ({result.modules.authenticated.accessiblePages.length})
                                            </h4>
                                            <div className="max-h-40 overflow-y-auto space-y-1">
                                                {result.modules.authenticated.accessiblePages.map((page: any, i: number) => (
                                                    <div key={i} className="p-2 bg-slate-50 rounded text-sm font-mono text-slate-600 truncate">
                                                        {page.url}
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    )}
                                </div>
                            )}
                        </div>
                    </div>
                </>
            )}
        </div>
    );
};
