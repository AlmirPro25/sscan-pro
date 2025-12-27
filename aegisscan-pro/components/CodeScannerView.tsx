import React, { useState, useEffect } from 'react';
import { FileBrowser } from './FileBrowser';

interface CodeVulnerability {
    type: string;
    severity: string;
    cwe: string;
    owasp: string;
    file: string;
    line: number;
    code: string;
    description: string;
    remediation: string;
    confidence: string;
}

interface CodeScanSummary {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
}

interface DependencyVulnerability {
    package: string;
    version: string;
    severity: string;
    title: string;
    description: string;
    cve: string;
    cwe: string;
    cvss: number;
    fix_version: string;
    url: string;
    ecosystem: string;
}

interface DependencyScanResult {
    ecosystem: string;
    total_deps: number;
    vulnerabilities: DependencyVulnerability[];
    summary: {
        critical: number;
        high: number;
        medium: number;
        low: number;
    };
}

interface DependencyScanResponse {
    id: number;
    path: string;
    ecosystems: number;
    total_deps: number;
    total_vulns: number;
    summary: {
        critical: number;
        high: number;
        medium: number;
        low: number;
    };
    results: DependencyScanResult[];
    created_at: string;
}

interface LocalScanResult {
    id: number;
    path: string;
    files_scanned: number;
    lines_scanned: number;
    score: number;
    vulnerabilities: CodeVulnerability[];
    summary: CodeScanSummary;
    created_at: string;
}

interface Props {
    onBack: () => void;
    apiKey: string;
}

const AVAILABLE_MODELS = [
    { id: 'models/gemini-2.5-flash', name: 'Gemini 2.5 Flash' },
    { id: 'models/gemini-3-flash-preview', name: 'Gemini 3 Flash (Preview)' },
    { id: 'models/gemini-2.0-flash-lite', name: 'Gemini 2.0 Flash Lite' },
];

export const CodeScannerView: React.FC<Props> = ({ onBack, apiKey }) => {
    const [path, setPath] = useState('');
    const [scanning, setScanning] = useState(false);
    const [result, setResult] = useState<LocalScanResult | null>(null);
    const [aiReport, setAiReport] = useState<string | null>(null);
    const [generatingAI, setGeneratingAI] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [activeTab, setActiveTab] = useState<'vulnerabilities' | 'dependencies' | 'ai-report'>('vulnerabilities');
    const [selectedModel, setSelectedModel] = useState('models/gemini-2.5-flash');
    const [showFileBrowser, setShowFileBrowser] = useState(false);
    const [scanHistory, setScanHistory] = useState<LocalScanResult[]>([]);
    const [showHistory, setShowHistory] = useState(false);
    const [depScanResult, setDepScanResult] = useState<DependencyScanResponse | null>(null);
    const [scanningDeps, setScanningDeps] = useState(false);

    // Load scan history on mount
    useEffect(() => {
        loadScanHistory();
    }, []);

    const loadScanHistory = async () => {
        try {
            const response = await fetch('http://localhost:8080/api/v1/scan-local/history');
            if (response.ok) {
                const data = await response.json();
                setScanHistory(data);
            }
        } catch (e) {
            console.error('Failed to load scan history');
        }
    };

    const handleSelectFromHistory = async (scan: LocalScanResult) => {
        // Parse vulnerabilities if string
        if (typeof scan.vulnerabilities === 'string') {
            scan.vulnerabilities = JSON.parse(scan.vulnerabilities);
        }
        if (typeof scan.summary === 'string') {
            scan.summary = JSON.parse(scan.summary);
        }
        setResult(scan);
        setPath(scan.path);
        setShowHistory(false);
        setAiReport(null);
        
        // Try to load AI report if exists
        try {
            const response = await fetch(`http://localhost:8080/api/v1/ai/report/${scan.id}`);
            if (response.ok) {
                const report = await response.json();
                setAiReport(report.content);
            }
        } catch (e) {
            // No AI report yet
        }
    };

    const handleScan = async () => {
        if (!path.trim()) {
            setError('Digite o caminho da pasta');
            return;
        }

        setScanning(true);
        setError(null);
        setResult(null);
        setAiReport(null);

        try {
            const response = await fetch('http://localhost:8080/api/v1/scan-local', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ path: path.trim() })
            });

            if (!response.ok) {
                const err = await response.json();
                throw new Error(err.error || 'Scan failed');
            }

            const data = await response.json();
            
            // Parse vulnerabilities if string
            if (typeof data.vulnerabilities === 'string') {
                data.vulnerabilities = JSON.parse(data.vulnerabilities);
            }
            if (typeof data.summary === 'string') {
                data.summary = JSON.parse(data.summary);
            }

            setResult(data);
            loadScanHistory(); // Reload history after scan
        } catch (e: any) {
            setError(e.message);
        } finally {
            setScanning(false);
        }
    };

    const handleGenerateAI = async () => {
        if (!result) return;

        setGeneratingAI(true);
        try {
            const response = await fetch('http://localhost:8080/api/v1/scan-local/ai-report', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    scan_id: result.id,
                    api_key: apiKey,
                    model: selectedModel
                })
            });

            if (!response.ok) {
                const err = await response.json();
                throw new Error(err.error || 'AI report failed');
            }

            const data = await response.json();
            setAiReport(data.content);
            setActiveTab('ai-report');
        } catch (e: any) {
            setError(e.message);
        } finally {
            setGeneratingAI(false);
        }
    };

    const handleDependencyScan = async () => {
        if (!path.trim()) {
            setError('Digite o caminho da pasta');
            return;
        }

        setScanningDeps(true);
        setError(null);

        try {
            const response = await fetch('http://localhost:8080/api/v1/scan-local/dependencies', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    path: path.trim(),
                    local_scan_id: result?.id || 0
                })
            });

            if (!response.ok) {
                const err = await response.json();
                throw new Error(err.error || 'Dependency scan failed');
            }

            const data = await response.json();
            setDepScanResult(data);
            setActiveTab('dependencies');
        } catch (e: any) {
            setError(e.message);
        } finally {
            setScanningDeps(false);
        }
    };

    const getSeverityColor = (severity: string) => {
        switch (severity) {
            case 'CRITICAL': return 'bg-red-600 text-white';
            case 'HIGH': return 'bg-orange-500 text-white';
            case 'MEDIUM': return 'bg-yellow-500 text-black';
            case 'LOW': return 'bg-green-500 text-white';
            default: return 'bg-gray-500 text-white';
        }
    };

    const getScoreColor = (score: number) => {
        if (score >= 80) return 'text-emerald-500';
        if (score >= 60) return 'text-yellow-500';
        if (score >= 40) return 'text-orange-500';
        return 'text-red-500';
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
                        <h2 className="text-2xl font-bold text-slate-900">Code Scanner</h2>
                        <p className="text-sm text-slate-500">SAST - Análise estática de código local</p>
                    </div>
                </div>
            </div>

            {/* Input Section */}
            <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm">
                <div className="flex gap-4">
                    <div className="flex-1">
                        <label className="block text-sm font-medium text-slate-700 mb-2">
                            <i className="fas fa-folder-open mr-2"></i>
                            Caminho do Projeto
                        </label>
                        <div className="flex gap-2">
                            <input
                                type="text"
                                value={path}
                                onChange={(e) => setPath(e.target.value)}
                                placeholder="C:\Users\seu-usuario\projetos\meu-app"
                                className="flex-1 px-4 py-3 border border-slate-300 rounded-xl focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 font-mono text-sm"
                                onKeyDown={(e) => e.key === 'Enter' && handleScan()}
                            />
                            <button
                                onClick={() => setShowFileBrowser(true)}
                                className="px-4 py-3 bg-slate-100 border border-slate-300 rounded-xl hover:bg-slate-200 transition-colors"
                                title="Procurar pasta"
                            >
                                <i className="fas fa-folder-open text-slate-600"></i>
                            </button>
                            <button
                                onClick={() => setShowHistory(!showHistory)}
                                className={`px-4 py-3 border rounded-xl transition-colors ${
                                    showHistory 
                                        ? 'bg-indigo-100 border-indigo-300 text-indigo-600' 
                                        : 'bg-slate-100 border-slate-300 hover:bg-slate-200'
                                }`}
                                title="Histórico de scans"
                            >
                                <i className="fas fa-history text-slate-600"></i>
                            </button>
                        </div>
                        <p className="mt-2 text-xs text-slate-500">
                            Digite o caminho ou clique no ícone para navegar nas pastas
                        </p>
                    </div>
                    <div className="flex items-end">
                        <button
                            onClick={handleScan}
                            disabled={scanning}
                            className="px-6 py-3 bg-indigo-600 text-white rounded-xl font-semibold hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center gap-2"
                        >
                            {scanning ? (
                                <>
                                    <i className="fas fa-spinner fa-spin"></i>
                                    Escaneando...
                                </>
                            ) : (
                                <>
                                    <i className="fas fa-search"></i>
                                    Escanear
                                </>
                            )}
                        </button>
                    </div>
                </div>

                {/* History Panel */}
                {showHistory && scanHistory.length > 0 && (
                    <div className="mt-4 border-t border-slate-200 pt-4">
                        <h4 className="text-sm font-medium text-slate-700 mb-3">
                            <i className="fas fa-history mr-2"></i>
                            Histórico de Scans
                        </h4>
                        <div className="space-y-2 max-h-60 overflow-y-auto">
                            {scanHistory.map((scan) => (
                                <button
                                    key={scan.id}
                                    onClick={() => handleSelectFromHistory(scan)}
                                    className="w-full p-3 bg-slate-50 border border-slate-200 rounded-xl hover:bg-indigo-50 hover:border-indigo-300 transition-colors text-left flex items-center gap-3"
                                >
                                    <div className={`w-10 h-10 rounded-lg flex items-center justify-center font-bold text-white ${
                                        scan.score >= 80 ? 'bg-emerald-500' :
                                        scan.score >= 60 ? 'bg-yellow-500' :
                                        scan.score >= 40 ? 'bg-orange-500' : 'bg-red-500'
                                    }`}>
                                        {scan.score}
                                    </div>
                                    <div className="flex-1 min-w-0">
                                        <div className="font-mono text-sm text-slate-700 truncate">{scan.path}</div>
                                        <div className="text-xs text-slate-400">
                                            {scan.files_scanned} arquivos • {new Date(scan.created_at).toLocaleString()}
                                        </div>
                                    </div>
                                    <i className="fas fa-chevron-right text-slate-400"></i>
                                </button>
                            ))}
                        </div>
                    </div>
                )}

                {error && (
                    <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-xl text-red-700 flex items-center gap-2">
                        <i className="fas fa-exclamation-circle"></i>
                        {error}
                    </div>
                )}
            </div>

            {/* File Browser Modal */}
            {showFileBrowser && (
                <FileBrowser
                    onSelect={(selectedPath) => {
                        setPath(selectedPath);
                        setShowFileBrowser(false);
                    }}
                    onClose={() => setShowFileBrowser(false)}
                />
            )}

            {/* Results Section */}
            {result && (
                <>
                    {/* Stats Cards */}
                    <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                        <div className="bg-white rounded-xl border border-slate-200 p-4 text-center">
                            <div className={`text-3xl font-bold ${getScoreColor(result.score)}`}>
                                {result.score}
                            </div>
                            <div className="text-xs text-slate-500 mt-1">Score</div>
                        </div>
                        <div className="bg-white rounded-xl border border-slate-200 p-4 text-center">
                            <div className="text-3xl font-bold text-slate-700">{result.files_scanned}</div>
                            <div className="text-xs text-slate-500 mt-1">Arquivos</div>
                        </div>
                        <div className="bg-white rounded-xl border border-slate-200 p-4 text-center">
                            <div className="text-3xl font-bold text-slate-700">{result.lines_scanned.toLocaleString()}</div>
                            <div className="text-xs text-slate-500 mt-1">Linhas</div>
                        </div>
                        <div className="bg-white rounded-xl border border-slate-200 p-4 text-center">
                            <div className="text-3xl font-bold text-red-500">
                                {result.summary.critical + result.summary.high}
                            </div>
                            <div className="text-xs text-slate-500 mt-1">Critical/High</div>
                        </div>
                        <div className="bg-white rounded-xl border border-slate-200 p-4 text-center">
                            <div className="text-3xl font-bold text-yellow-500">
                                {result.summary.medium + result.summary.low}
                            </div>
                            <div className="text-xs text-slate-500 mt-1">Medium/Low</div>
                        </div>
                    </div>

                    {/* Severity Breakdown */}
                    <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm">
                        <div className="flex items-center justify-between mb-4">
                            <h3 className="font-semibold text-slate-900">Distribuição por Severidade</h3>
                            <div className="flex items-center gap-3">
                                <select
                                    value={selectedModel}
                                    onChange={(e) => setSelectedModel(e.target.value)}
                                    className="px-3 py-2 border border-slate-300 rounded-lg text-sm focus:ring-2 focus:ring-indigo-500"
                                >
                                    {AVAILABLE_MODELS.map(m => (
                                        <option key={m.id} value={m.id}>{m.name}</option>
                                    ))}
                                </select>
                                <button
                                    onClick={handleGenerateAI}
                                    disabled={generatingAI}
                                    className="px-4 py-2 bg-gradient-to-r from-purple-600 to-indigo-600 text-white rounded-lg text-sm font-medium hover:from-purple-700 hover:to-indigo-700 disabled:opacity-50 flex items-center gap-2"
                                >
                                    {generatingAI ? (
                                        <>
                                            <i className="fas fa-spinner fa-spin"></i>
                                            Gerando...
                                        </>
                                    ) : (
                                        <>
                                            <i className="fas fa-robot"></i>
                                            Análise AI
                                        </>
                                    )}
                                </button>
                                <button
                                    onClick={() => window.open(`http://localhost:8080/api/v1/scan-local/pdf/${result.id}`, '_blank')}
                                    className="px-4 py-2 bg-slate-700 text-white rounded-lg text-sm font-medium hover:bg-slate-800 flex items-center gap-2"
                                >
                                    <i className="fas fa-file-pdf"></i>
                                    Download PDF
                                </button>
                            </div>
                        </div>
                        <div className="flex gap-4">
                            {[
                                { label: 'Critical', count: result.summary.critical, color: 'bg-red-600' },
                                { label: 'High', count: result.summary.high, color: 'bg-orange-500' },
                                { label: 'Medium', count: result.summary.medium, color: 'bg-yellow-500' },
                                { label: 'Low', count: result.summary.low, color: 'bg-green-500' },
                            ].map(item => (
                                <div key={item.label} className="flex-1">
                                    <div className="flex items-center gap-2 mb-2">
                                        <div className={`w-3 h-3 rounded-full ${item.color}`}></div>
                                        <span className="text-sm text-slate-600">{item.label}</span>
                                    </div>
                                    <div className="text-2xl font-bold text-slate-900">{item.count}</div>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Tabs */}
                    <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
                        <div className="flex border-b border-slate-200">
                            <button
                                onClick={() => setActiveTab('vulnerabilities')}
                                className={`flex-1 px-6 py-4 text-sm font-medium transition-colors ${
                                    activeTab === 'vulnerabilities'
                                        ? 'bg-indigo-50 text-indigo-700 border-b-2 border-indigo-600'
                                        : 'text-slate-600 hover:bg-slate-50'
                                }`}
                            >
                                <i className="fas fa-bug mr-2"></i>
                                Código ({result.vulnerabilities.length})
                            </button>
                            <button
                                onClick={() => setActiveTab('dependencies')}
                                className={`flex-1 px-6 py-4 text-sm font-medium transition-colors ${
                                    activeTab === 'dependencies'
                                        ? 'bg-indigo-50 text-indigo-700 border-b-2 border-indigo-600'
                                        : 'text-slate-600 hover:bg-slate-50'
                                }`}
                            >
                                <i className="fas fa-cubes mr-2"></i>
                                Dependências {depScanResult ? `(${depScanResult.total_vulns})` : ''}
                            </button>
                            <button
                                onClick={() => setActiveTab('ai-report')}
                                disabled={!aiReport}
                                className={`flex-1 px-6 py-4 text-sm font-medium transition-colors ${
                                    activeTab === 'ai-report'
                                        ? 'bg-indigo-50 text-indigo-700 border-b-2 border-indigo-600'
                                        : 'text-slate-600 hover:bg-slate-50 disabled:opacity-50'
                                }`}
                            >
                                <i className="fas fa-robot mr-2"></i>
                                Relatório AI
                            </button>
                        </div>

                        <div className="p-6 max-h-[600px] overflow-y-auto">
                            {activeTab === 'vulnerabilities' && (
                                <div className="space-y-4">
                                    {result.vulnerabilities.length === 0 ? (
                                        <div className="text-center py-12 text-slate-500">
                                            <i className="fas fa-check-circle text-4xl text-emerald-500 mb-4"></i>
                                            <p className="font-medium">Nenhuma vulnerabilidade encontrada!</p>
                                            <p className="text-sm">Seu código está limpo.</p>
                                        </div>
                                    ) : (
                                        result.vulnerabilities.map((vuln, idx) => (
                                            <div key={idx} className="border border-slate-200 rounded-xl p-4 hover:border-slate-300 transition-colors">
                                                <div className="flex items-start justify-between mb-3">
                                                    <div className="flex items-center gap-3">
                                                        <span className={`px-2 py-1 rounded text-xs font-bold ${getSeverityColor(vuln.severity)}`}>
                                                            {vuln.severity}
                                                        </span>
                                                        <span className="font-semibold text-slate-900">{vuln.type}</span>
                                                    </div>
                                                    <span className="text-xs text-slate-500">{vuln.cwe}</span>
                                                </div>
                                                
                                                <div className="text-sm text-slate-600 mb-3">{vuln.description}</div>
                                                
                                                <div className="bg-slate-50 rounded-lg p-3 mb-3">
                                                    <div className="flex items-center gap-2 text-xs text-slate-500 mb-2">
                                                        <i className="fas fa-file-code"></i>
                                                        <span className="font-mono">{vuln.file}:{vuln.line}</span>
                                                    </div>
                                                    <code className="text-xs text-slate-700 font-mono block whitespace-pre-wrap break-all">
                                                        {vuln.code}
                                                    </code>
                                                </div>
                                                
                                                <div className="flex items-start gap-2 text-sm">
                                                    <i className="fas fa-lightbulb text-yellow-500 mt-0.5"></i>
                                                    <span className="text-slate-600">{vuln.remediation}</span>
                                                </div>
                                            </div>
                                        ))
                                    )}
                                </div>
                            )}

                            {activeTab === 'dependencies' && (
                                <div className="space-y-4">
                                    {!depScanResult ? (
                                        <div className="text-center py-12">
                                            <i className="fas fa-cubes text-4xl text-slate-300 mb-4"></i>
                                            <p className="font-medium text-slate-700 mb-2">Análise de Dependências</p>
                                            <p className="text-sm text-slate-500 mb-4">
                                                Detecta vulnerabilidades em package.json, go.mod, requirements.txt, composer.json
                                            </p>
                                            <button
                                                onClick={handleDependencyScan}
                                                disabled={scanningDeps}
                                                className="px-6 py-3 bg-indigo-600 text-white rounded-xl font-semibold hover:bg-indigo-700 disabled:opacity-50 transition-colors flex items-center gap-2 mx-auto"
                                            >
                                                {scanningDeps ? (
                                                    <>
                                                        <i className="fas fa-spinner fa-spin"></i>
                                                        Escaneando dependências...
                                                    </>
                                                ) : (
                                                    <>
                                                        <i className="fas fa-search"></i>
                                                        Escanear Dependências
                                                    </>
                                                )}
                                            </button>
                                        </div>
                                    ) : (
                                        <>
                                            {/* Dependency Stats */}
                                            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
                                                <div className="bg-slate-50 rounded-lg p-3 text-center">
                                                    <div className="text-2xl font-bold text-slate-700">{depScanResult.ecosystems}</div>
                                                    <div className="text-xs text-slate-500">Ecosystems</div>
                                                </div>
                                                <div className="bg-slate-50 rounded-lg p-3 text-center">
                                                    <div className="text-2xl font-bold text-slate-700">{depScanResult.total_deps}</div>
                                                    <div className="text-xs text-slate-500">Dependências</div>
                                                </div>
                                                <div className="bg-red-50 rounded-lg p-3 text-center">
                                                    <div className="text-2xl font-bold text-red-600">
                                                        {depScanResult.summary.critical + depScanResult.summary.high}
                                                    </div>
                                                    <div className="text-xs text-slate-500">Critical/High</div>
                                                </div>
                                                <div className="bg-yellow-50 rounded-lg p-3 text-center">
                                                    <div className="text-2xl font-bold text-yellow-600">
                                                        {depScanResult.summary.medium + depScanResult.summary.low}
                                                    </div>
                                                    <div className="text-xs text-slate-500">Medium/Low</div>
                                                </div>
                                            </div>

                                            {/* Rescan button */}
                                            <div className="flex justify-end mb-4">
                                                <button
                                                    onClick={handleDependencyScan}
                                                    disabled={scanningDeps}
                                                    className="px-4 py-2 bg-slate-100 text-slate-700 rounded-lg text-sm hover:bg-slate-200 disabled:opacity-50 flex items-center gap-2"
                                                >
                                                    <i className={`fas ${scanningDeps ? 'fa-spinner fa-spin' : 'fa-sync'}`}></i>
                                                    Re-escanear
                                                </button>
                                            </div>

                                            {/* Results by ecosystem */}
                                            {depScanResult.results.map((ecosystemResult, ecosystemIdx) => (
                                                <div key={ecosystemIdx} className="border border-slate-200 rounded-xl overflow-hidden">
                                                    <div className="bg-slate-50 px-4 py-3 flex items-center justify-between">
                                                        <div className="flex items-center gap-3">
                                                            <span className={`w-8 h-8 rounded-lg flex items-center justify-center text-white text-sm font-bold ${
                                                                ecosystemResult.ecosystem === 'npm' ? 'bg-red-500' :
                                                                ecosystemResult.ecosystem === 'go' ? 'bg-cyan-500' :
                                                                ecosystemResult.ecosystem === 'pip' ? 'bg-blue-500' :
                                                                ecosystemResult.ecosystem === 'composer' ? 'bg-purple-500' :
                                                                'bg-slate-500'
                                                            }`}>
                                                                {ecosystemResult.ecosystem === 'npm' ? 'N' :
                                                                 ecosystemResult.ecosystem === 'go' ? 'Go' :
                                                                 ecosystemResult.ecosystem === 'pip' ? 'Py' :
                                                                 ecosystemResult.ecosystem === 'composer' ? 'PHP' :
                                                                 ecosystemResult.ecosystem.charAt(0).toUpperCase()}
                                                            </span>
                                                            <div>
                                                                <div className="font-semibold text-slate-900 capitalize">{ecosystemResult.ecosystem}</div>
                                                                <div className="text-xs text-slate-500">{ecosystemResult.total_deps} dependências</div>
                                                            </div>
                                                        </div>
                                                        <div className="flex items-center gap-2">
                                                            {ecosystemResult.summary.critical > 0 && (
                                                                <span className="px-2 py-1 bg-red-100 text-red-700 rounded text-xs font-bold">
                                                                    {ecosystemResult.summary.critical} CRITICAL
                                                                </span>
                                                            )}
                                                            {ecosystemResult.summary.high > 0 && (
                                                                <span className="px-2 py-1 bg-orange-100 text-orange-700 rounded text-xs font-bold">
                                                                    {ecosystemResult.summary.high} HIGH
                                                                </span>
                                                            )}
                                                        </div>
                                                    </div>
                                                    
                                                    {ecosystemResult.vulnerabilities.length === 0 ? (
                                                        <div className="p-4 text-center text-slate-500 text-sm">
                                                            <i className="fas fa-check-circle text-emerald-500 mr-2"></i>
                                                            Nenhuma vulnerabilidade conhecida
                                                        </div>
                                                    ) : (
                                                        <div className="divide-y divide-slate-100">
                                                            {ecosystemResult.vulnerabilities.map((vuln, vulnIdx) => (
                                                                <div key={vulnIdx} className="p-4 hover:bg-slate-50 transition-colors">
                                                                    <div className="flex items-start justify-between mb-2">
                                                                        <div className="flex items-center gap-2">
                                                                            <span className={`px-2 py-0.5 rounded text-xs font-bold ${getSeverityColor(vuln.severity)}`}>
                                                                                {vuln.severity}
                                                                            </span>
                                                                            <span className="font-mono text-sm font-semibold text-slate-900">
                                                                                {vuln.package}
                                                                            </span>
                                                                            <span className="text-xs text-slate-400">
                                                                                {vuln.version}
                                                                            </span>
                                                                        </div>
                                                                        {vuln.cvss > 0 && (
                                                                            <span className="text-xs text-slate-500">
                                                                                CVSS: {vuln.cvss.toFixed(1)}
                                                                            </span>
                                                                        )}
                                                                    </div>
                                                                    
                                                                    <div className="text-sm text-slate-700 mb-2">{vuln.title}</div>
                                                                    
                                                                    {vuln.description && (
                                                                        <div className="text-xs text-slate-500 mb-2">{vuln.description}</div>
                                                                    )}
                                                                    
                                                                    <div className="flex items-center gap-4 text-xs">
                                                                        {vuln.cve && (
                                                                            <a 
                                                                                href={vuln.url || `https://nvd.nist.gov/vuln/detail/${vuln.cve}`}
                                                                                target="_blank"
                                                                                rel="noopener noreferrer"
                                                                                className="text-indigo-600 hover:underline"
                                                                            >
                                                                                <i className="fas fa-external-link-alt mr-1"></i>
                                                                                {vuln.cve}
                                                                            </a>
                                                                        )}
                                                                        {vuln.cwe && (
                                                                            <span className="text-slate-400">{vuln.cwe}</span>
                                                                        )}
                                                                        {vuln.fix_version && (
                                                                            <span className="text-emerald-600">
                                                                                <i className="fas fa-arrow-up mr-1"></i>
                                                                                Fix: {vuln.fix_version}
                                                                            </span>
                                                                        )}
                                                                    </div>
                                                                </div>
                                                            ))}
                                                        </div>
                                                    )}
                                                </div>
                                            ))}
                                        </>
                                    )}
                                </div>
                            )}

                            {activeTab === 'ai-report' && aiReport && (
                                <div className="prose prose-slate max-w-none">
                                    <div 
                                        className="markdown-content"
                                        dangerouslySetInnerHTML={{ 
                                            __html: aiReport
                                                .replace(/^### (.*$)/gim, '<h3 class="text-lg font-bold text-slate-900 mt-6 mb-3">$1</h3>')
                                                .replace(/^## (.*$)/gim, '<h2 class="text-xl font-bold text-slate-900 mt-8 mb-4">$1</h2>')
                                                .replace(/^# (.*$)/gim, '<h1 class="text-2xl font-bold text-slate-900 mt-8 mb-4">$1</h1>')
                                                .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                                                .replace(/\*(.*?)\*/g, '<em>$1</em>')
                                                .replace(/`(.*?)`/g, '<code class="bg-slate-100 px-1 rounded text-sm">$1</code>')
                                                .replace(/\n/g, '<br/>')
                                        }}
                                    />
                                </div>
                            )}
                        </div>
                    </div>
                </>
            )}

            {/* CLI Instructions */}
            {!result && !scanning && (
                <div className="bg-slate-50 rounded-2xl border border-slate-200 p-6">
                    <h3 className="font-semibold text-slate-900 mb-4">
                        <i className="fas fa-terminal mr-2"></i>
                        Também disponível via CLI
                    </h3>
                    <div className="bg-slate-900 rounded-xl p-4 font-mono text-sm text-slate-100">
                        <div className="text-slate-500"># Scan básico</div>
                        <div className="text-emerald-400">aegis scan-local C:\meu-projeto</div>
                        <br/>
                        <div className="text-slate-500"># Com relatório AI</div>
                        <div className="text-emerald-400">aegis scan-local C:\meu-projeto --ai-report</div>
                        <br/>
                        <div className="text-slate-500"># Falhar em vulnerabilidades HIGH+</div>
                        <div className="text-emerald-400">aegis scan-local C:\meu-projeto --fail-on high</div>
                    </div>
                </div>
            )}
        </div>
    );
};
