import React, { useState, useEffect } from 'react';

interface CorrelatedVuln {
    id: string;
    type: string;
    severity: string;
    confidence_level: string;
    dast_evidence: any;
    sast_evidence: any[];
    iac_evidence: any[];
    root_cause: string;
    attack_vector: string;
    business_impact: string;
    remediation: {
        priority: number;
        files: string[];
        description: string;
    };
}

interface AttackChain {
    name: string;
    vulnerabilities: string[];
    description: string;
    severity: string;
}

interface RemediationStep {
    priority: number;
    timeframe: string;
    title: string;
    description: string;
    files: string[];
    effort: string;
    impact: string;
}

interface CorrelationReport {
    target: string;
    correlated_vulnerabilities: CorrelatedVuln[];
    unmatched_dast: any[];
    unmatched_sast: any[];
    attack_chains: AttackChain[];
    risk_score: number;
    executive_summary: string;
    technical_summary: string;
    compliance_impact: {
        lgpd: string[];
        pci_dss: string[];
        owasp: string[];
    };
    remediation_roadmap: RemediationStep[];
}


interface DastScan {
    id: number;
    target: string;
    score: number;
    created_at: string;
}

interface SastScan {
    id: number;
    path: string;
    score: number;
    created_at: string;
}

interface Props {
    onBack: () => void;
}

export const CorrelationView: React.FC<Props> = ({ onBack }) => {
    const [dastScans, setDastScans] = useState<DastScan[]>([]);
    const [sastScans, setSastScans] = useState<SastScan[]>([]);
    const [selectedDast, setSelectedDast] = useState<number | null>(null);
    const [selectedSast, setSelectedSast] = useState<number | null>(null);
    const [scaPath, setScaPath] = useState('');
    const [correlating, setCorrelating] = useState(false);
    const [report, setReport] = useState<CorrelationReport | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [activeTab, setActiveTab] = useState('summary');
    const [apiKey, setApiKey] = useState('');

    useEffect(() => {
        loadScans();
        const savedKey = localStorage.getItem('gemini_api_key');
        if (savedKey) setApiKey(savedKey);
    }, []);

    const loadScans = async () => {
        try {
            const [dastRes, sastRes] = await Promise.all([
                fetch('http://localhost:8080/api/v1/history'),
                fetch('http://localhost:8080/api/v1/scan-local/history')
            ]);
            if (dastRes.ok) setDastScans(await dastRes.json());
            if (sastRes.ok) setSastScans(await sastRes.json());
        } catch (e) {
            console.error('Failed to load scans');
        }
    };


    const handleCorrelate = async () => {
        if (!selectedDast && !selectedSast) {
            setError('Selecione pelo menos um scan DAST ou SAST');
            return;
        }

        setCorrelating(true);
        setError(null);
        setReport(null);

        try {
            const target = selectedDast 
                ? dastScans.find(s => s.id === selectedDast)?.target 
                : sastScans.find(s => s.id === selectedSast)?.path;

            const payload: any = {
                target: target || 'Unknown',
                model: 'models/gemini-2.5-flash'
            };
            if (selectedDast) payload.dast_scan_id = selectedDast;
            if (selectedSast) payload.sast_scan_id = selectedSast;
            if (scaPath) payload.sca_scan_path = scaPath;
            if (apiKey) payload.api_key = apiKey;

            const response = await fetch('http://localhost:8080/api/v1/correlate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            if (!response.ok) {
                const err = await response.json();
                throw new Error(err.error || 'Correlation failed');
            }

            const data = await response.json();
            setReport(data);
        } catch (e: any) {
            setError(e.message);
        } finally {
            setCorrelating(false);
        }
    };

    const getSeverityColor = (severity: string) => {
        switch (severity?.toUpperCase()) {
            case 'CRITICAL': return 'bg-red-600 text-white';
            case 'HIGH': return 'bg-orange-500 text-white';
            case 'MEDIUM': return 'bg-yellow-500 text-black';
            case 'LOW': return 'bg-green-500 text-white';
            default: return 'bg-slate-500 text-white';
        }
    };

    const getConfidenceColor = (level: string) => {
        switch (level) {
            case 'CONFIRMED': return 'bg-green-100 text-green-700 border-green-300';
            case 'LIKELY': return 'bg-yellow-100 text-yellow-700 border-yellow-300';
            case 'POSSIBLE': return 'bg-slate-100 text-slate-700 border-slate-300';
            default: return 'bg-slate-100 text-slate-600';
        }
    };

    const getScoreColor = (score: number) => {
        if (score >= 80) return 'text-green-600';
        if (score >= 60) return 'text-yellow-600';
        if (score >= 40) return 'text-orange-600';
        return 'text-red-600';
    };


    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-center gap-4">
                <button onClick={onBack} className="p-2 hover:bg-slate-100 rounded-lg transition-colors">
                    <i className="fas fa-arrow-left text-slate-600"></i>
                </button>
                <div>
                    <h2 className="text-2xl font-bold text-slate-900">DAST + SAST Correlation</h2>
                    <p className="text-sm text-slate-500">Correlação inteligente de vulnerabilidades</p>
                </div>
            </div>

            {/* Input Section */}
            {!report && (
                <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm space-y-6">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        {/* DAST Selection */}
                        <div className="p-4 bg-blue-50 rounded-xl border border-blue-200">
                            <label className="block text-sm font-medium text-blue-700 mb-2">
                                <i className="fas fa-globe mr-2"></i>
                                Scan DAST (Dynamic)
                            </label>
                            <select
                                value={selectedDast || ''}
                                onChange={(e) => setSelectedDast(e.target.value ? Number(e.target.value) : null)}
                                className="w-full px-3 py-2 border border-blue-300 rounded-lg bg-white"
                            >
                                <option value="">Selecione um scan DAST</option>
                                {dastScans.map(scan => (
                                    <option key={scan.id} value={scan.id}>
                                        {scan.target} (Score: {scan.score})
                                    </option>
                                ))}
                            </select>
                            <p className="text-xs text-blue-600 mt-2">
                                Vulnerabilidades encontradas em runtime (XSS, SQLi, etc)
                            </p>
                        </div>

                        {/* SAST Selection */}
                        <div className="p-4 bg-green-50 rounded-xl border border-green-200">
                            <label className="block text-sm font-medium text-green-700 mb-2">
                                <i className="fas fa-code mr-2"></i>
                                Scan SAST (Static)
                            </label>
                            <select
                                value={selectedSast || ''}
                                onChange={(e) => setSelectedSast(e.target.value ? Number(e.target.value) : null)}
                                className="w-full px-3 py-2 border border-green-300 rounded-lg bg-white"
                            >
                                <option value="">Selecione um scan SAST</option>
                                {sastScans.map(scan => (
                                    <option key={scan.id} value={scan.id}>
                                        {scan.path} (Score: {scan.score})
                                    </option>
                                ))}
                            </select>
                            <p className="text-xs text-green-600 mt-2">
                                Vulnerabilidades encontradas no código-fonte
                            </p>
                        </div>
                    </div>

                    {/* IAC Path (Optional) */}
                    <div className="p-4 bg-purple-50 rounded-xl border border-purple-200">
                        <label className="block text-sm font-medium text-purple-700 mb-2">
                            <i className="fas fa-server mr-2"></i>
                            Caminho IAC (Opcional)
                        </label>
                        <input
                            type="text"
                            value={scaPath}
                            onChange={(e) => setScaPath(e.target.value)}
                            placeholder="C:\projeto ou /home/user/projeto"
                            className="w-full px-3 py-2 border border-purple-300 rounded-lg bg-white"
                        />
                        <p className="text-xs text-purple-600 mt-2">
                            Analisa Dockerfile, docker-compose, Kubernetes, Terraform
                        </p>
                    </div>

                    {/* Info Box */}
                    <div className="p-4 bg-indigo-50 border border-indigo-200 rounded-xl">
                        <h4 className="font-medium text-indigo-700 mb-2">
                            <i className="fas fa-brain mr-2"></i>
                            O que a correlação faz:
                        </h4>
                        <ul className="text-sm text-indigo-600 space-y-1">
                            <li>• Liga vulnerabilidades DAST ao código-fonte que as causa</li>
                            <li>• Identifica cadeias de ataque (attack chains)</li>
                            <li>• Analisa impacto em compliance (LGPD, PCI-DSS, OWASP)</li>
                            <li>• Gera roadmap de remediação priorizado</li>
                            <li>• Sugere correções específicas com arquivos e linhas</li>
                        </ul>
                    </div>

                    {error && (
                        <div className="p-4 bg-red-50 border border-red-200 rounded-xl text-red-700">
                            <i className="fas fa-exclamation-circle mr-2"></i>
                            {error}
                        </div>
                    )}

                    <button
                        onClick={handleCorrelate}
                        disabled={correlating || (!selectedDast && !selectedSast)}
                        className="w-full py-4 bg-gradient-to-r from-indigo-600 to-purple-600 text-white rounded-xl font-semibold hover:from-indigo-700 hover:to-purple-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center justify-center gap-2"
                    >
                        {correlating ? (
                            <>
                                <i className="fas fa-spinner fa-spin"></i>
                                Correlacionando...
                            </>
                        ) : (
                            <>
                                <i className="fas fa-link"></i>
                                Correlacionar DAST + SAST
                            </>
                        )}
                    </button>
                </div>
            )}

            {/* Results */}
            {report && (
                <>
                    {/* Score Card */}
                    <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm">
                        <div className="flex items-center justify-between mb-4">
                            <div>
                                <h3 className="text-lg font-bold text-slate-900">Relatório de Correlação</h3>
                                <p className="text-sm text-slate-500">{report.target}</p>
                            </div>
                            <div className="flex items-center gap-4">
                                <button
                                    onClick={() => setReport(null)}
                                    className="px-4 py-2 bg-slate-100 text-slate-700 rounded-lg hover:bg-slate-200"
                                >
                                    <i className="fas fa-redo mr-2"></i>
                                    Nova Análise
                                </button>
                                <div className="text-center">
                                    <div className={`text-4xl font-bold ${getScoreColor(report.risk_score)}`}>
                                        {report.risk_score}
                                    </div>
                                    <div className="text-xs text-slate-500">Risk Score</div>
                                </div>
                            </div>
                        </div>

                        {/* Stats */}
                        <div className="grid grid-cols-4 gap-4">
                            <div className="text-center p-3 bg-purple-50 rounded-xl">
                                <div className="text-2xl font-bold text-purple-600">
                                    {report.correlated_vulnerabilities?.length || 0}
                                </div>
                                <div className="text-xs text-slate-500">Correlacionadas</div>
                            </div>
                            <div className="text-center p-3 bg-red-50 rounded-xl">
                                <div className="text-2xl font-bold text-red-600">
                                    {report.attack_chains?.length || 0}
                                </div>
                                <div className="text-xs text-slate-500">Attack Chains</div>
                            </div>
                            <div className="text-center p-3 bg-blue-50 rounded-xl">
                                <div className="text-2xl font-bold text-blue-600">
                                    {report.unmatched_dast?.length || 0}
                                </div>
                                <div className="text-xs text-slate-500">DAST Only</div>
                            </div>
                            <div className="text-center p-3 bg-green-50 rounded-xl">
                                <div className="text-2xl font-bold text-green-600">
                                    {report.unmatched_sast?.length || 0}
                                </div>
                                <div className="text-xs text-slate-500">SAST Only</div>
                            </div>
                        </div>
                    </div>

                    {/* Tabs */}
                    <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
                        <div className="flex border-b border-slate-200 overflow-x-auto">
                            {[
                                { key: 'summary', label: 'Resumo', icon: 'fa-file-alt' },
                                { key: 'correlated', label: 'Correlacionadas', icon: 'fa-link' },
                                { key: 'chains', label: 'Attack Chains', icon: 'fa-project-diagram' },
                                { key: 'compliance', label: 'Compliance', icon: 'fa-shield-alt' },
                                { key: 'roadmap', label: 'Roadmap', icon: 'fa-road' },
                            ].map(tab => (
                                <button
                                    key={tab.key}
                                    onClick={() => setActiveTab(tab.key)}
                                    className={`flex-1 px-4 py-4 text-sm font-medium transition-colors flex items-center justify-center gap-2 ${
                                        activeTab === tab.key
                                            ? 'bg-indigo-50 text-indigo-700 border-b-2 border-indigo-600'
                                            : 'text-slate-600 hover:bg-slate-50'
                                    }`}
                                >
                                    <i className={`fas ${tab.icon}`}></i>
                                    {tab.label}
                                </button>
                            ))}
                        </div>

                        <div className="p-6 max-h-[500px] overflow-y-auto">
                            {/* Summary Tab */}
                            {activeTab === 'summary' && (
                                <div className="space-y-6">
                                    {report.executive_summary && (
                                        <div>
                                            <h4 className="font-semibold text-slate-900 mb-2">
                                                <i className="fas fa-briefcase mr-2 text-indigo-500"></i>
                                                Resumo Executivo
                                            </h4>
                                            <p className="text-slate-600 bg-slate-50 p-4 rounded-xl">
                                                {report.executive_summary}
                                            </p>
                                        </div>
                                    )}
                                    {report.technical_summary && (
                                        <div>
                                            <h4 className="font-semibold text-slate-900 mb-2">
                                                <i className="fas fa-cogs mr-2 text-indigo-500"></i>
                                                Resumo Técnico
                                            </h4>
                                            <p className="text-slate-600 bg-slate-50 p-4 rounded-xl">
                                                {report.technical_summary}
                                            </p>
                                        </div>
                                    )}
                                </div>
                            )}

                            {/* Correlated Tab */}
                            {activeTab === 'correlated' && (
                                <div className="space-y-4">
                                    {report.correlated_vulnerabilities?.length > 0 ? (
                                        report.correlated_vulnerabilities.map((vuln, i) => (
                                            <div key={i} className="p-4 bg-slate-50 rounded-xl border border-slate-200">
                                                <div className="flex items-center justify-between mb-3">
                                                    <div className="flex items-center gap-2">
                                                        <span className="font-bold text-slate-700">{vuln.type}</span>
                                                        <span className={`px-2 py-0.5 rounded text-xs border ${getConfidenceColor(vuln.confidence_level)}`}>
                                                            {vuln.confidence_level}
                                                        </span>
                                                    </div>
                                                    <span className={`px-3 py-1 rounded text-sm font-bold ${getSeverityColor(vuln.severity)}`}>
                                                        {vuln.severity}
                                                    </span>
                                                </div>
                                                
                                                <div className="grid grid-cols-2 gap-4 mb-3">
                                                    <div className="p-3 bg-blue-50 rounded-lg">
                                                        <div className="text-xs text-blue-600 font-medium mb-1">DAST Evidence</div>
                                                        <div className="text-sm text-slate-700">{vuln.attack_vector}</div>
                                                    </div>
                                                    <div className="p-3 bg-green-50 rounded-lg">
                                                        <div className="text-xs text-green-600 font-medium mb-1">SAST Root Cause</div>
                                                        <div className="text-sm text-slate-700">{vuln.root_cause}</div>
                                                    </div>
                                                </div>

                                                {vuln.business_impact && (
                                                    <div className="p-3 bg-amber-50 rounded-lg mb-3">
                                                        <div className="text-xs text-amber-600 font-medium mb-1">Business Impact</div>
                                                        <div className="text-sm text-slate-700">{vuln.business_impact}</div>
                                                    </div>
                                                )}

                                                {vuln.remediation && (
                                                    <div className="p-3 bg-indigo-50 rounded-lg">
                                                        <div className="text-xs text-indigo-600 font-medium mb-1">
                                                            Remediação (Prioridade {vuln.remediation.priority})
                                                        </div>
                                                        <div className="text-sm text-slate-700">{vuln.remediation.description}</div>
                                                        {vuln.remediation.files?.length > 0 && (
                                                            <div className="flex flex-wrap gap-1 mt-2">
                                                                {vuln.remediation.files.map((f, fi) => (
                                                                    <span key={fi} className="px-2 py-0.5 bg-indigo-100 text-indigo-700 rounded text-xs font-mono">
                                                                        {f}
                                                                    </span>
                                                                ))}
                                                            </div>
                                                        )}
                                                    </div>
                                                )}
                                            </div>
                                        ))
                                    ) : (
                                        <div className="text-center text-slate-500 py-8">
                                            <i className="fas fa-check-circle text-4xl text-green-500 mb-3"></i>
                                            <p>Nenhuma vulnerabilidade correlacionada encontrada</p>
                                        </div>
                                    )}
                                </div>
                            )}

                            {/* Attack Chains Tab */}
                            {activeTab === 'chains' && (
                                <div className="space-y-4">
                                    {report.attack_chains?.length > 0 ? (
                                        report.attack_chains.map((chain, i) => (
                                            <div key={i} className="p-4 bg-red-50 rounded-xl border border-red-200">
                                                <div className="flex items-center justify-between mb-2">
                                                    <span className="font-bold text-red-700">{chain.name}</span>
                                                    <span className={`px-3 py-1 rounded text-sm font-bold ${getSeverityColor(chain.severity)}`}>
                                                        {chain.severity}
                                                    </span>
                                                </div>
                                                <p className="text-sm text-slate-600 mb-3">{chain.description}</p>
                                                <div className="flex flex-wrap gap-2">
                                                    {chain.vulnerabilities?.map((v, vi) => (
                                                        <span key={vi} className="px-2 py-1 bg-red-100 text-red-700 rounded text-xs">
                                                            {v}
                                                        </span>
                                                    ))}
                                                </div>
                                            </div>
                                        ))
                                    ) : (
                                        <div className="text-center text-slate-500 py-8">
                                            <i className="fas fa-shield-alt text-4xl text-green-500 mb-3"></i>
                                            <p>Nenhuma cadeia de ataque identificada</p>
                                        </div>
                                    )}
                                </div>
                            )}

                            {/* Compliance Tab */}
                            {activeTab === 'compliance' && (
                                <div className="space-y-4">
                                    {[
                                        { key: 'lgpd', label: 'LGPD', icon: 'fa-user-shield', color: 'blue' },
                                        { key: 'pci_dss', label: 'PCI-DSS', icon: 'fa-credit-card', color: 'green' },
                                        { key: 'owasp', label: 'OWASP Top 10', icon: 'fa-bug', color: 'red' },
                                    ].map(comp => {
                                        const items = report.compliance_impact?.[comp.key as keyof typeof report.compliance_impact] || [];
                                        return (
                                            <div key={comp.key} className={`p-4 bg-${comp.color}-50 rounded-xl border border-${comp.color}-200`}>
                                                <h4 className={`font-semibold text-${comp.color}-700 mb-2`}>
                                                    <i className={`fas ${comp.icon} mr-2`}></i>
                                                    {comp.label}
                                                </h4>
                                                {items.length > 0 ? (
                                                    <ul className="space-y-1">
                                                        {items.map((item, ii) => (
                                                            <li key={ii} className="text-sm text-slate-600 flex items-start gap-2">
                                                                <i className="fas fa-exclamation-triangle text-amber-500 mt-0.5"></i>
                                                                {item}
                                                            </li>
                                                        ))}
                                                    </ul>
                                                ) : (
                                                    <p className="text-sm text-slate-500">Nenhum impacto identificado</p>
                                                )}
                                            </div>
                                        );
                                    })}
                                </div>
                            )}

                            {/* Roadmap Tab */}
                            {activeTab === 'roadmap' && (
                                <div className="space-y-4">
                                    {report.remediation_roadmap?.length > 0 ? (
                                        report.remediation_roadmap.map((step, i) => (
                                            <div key={i} className="p-4 bg-slate-50 rounded-xl border border-slate-200 flex gap-4">
                                                <div className={`w-12 h-12 rounded-full flex items-center justify-center text-white font-bold ${
                                                    step.priority === 1 ? 'bg-red-500' :
                                                    step.priority === 2 ? 'bg-orange-500' :
                                                    step.priority === 3 ? 'bg-yellow-500' :
                                                    'bg-green-500'
                                                }`}>
                                                    {step.priority}
                                                </div>
                                                <div className="flex-1">
                                                    <div className="flex items-center gap-2 mb-1">
                                                        <span className="font-bold text-slate-700">{step.title}</span>
                                                        <span className="px-2 py-0.5 bg-slate-200 rounded text-xs">{step.timeframe}</span>
                                                        <span className={`px-2 py-0.5 rounded text-xs ${
                                                            step.effort === 'low' ? 'bg-green-100 text-green-700' :
                                                            step.effort === 'medium' ? 'bg-yellow-100 text-yellow-700' :
                                                            'bg-red-100 text-red-700'
                                                        }`}>
                                                            Esforço: {step.effort}
                                                        </span>
                                                    </div>
                                                    <p className="text-sm text-slate-600">{step.description}</p>
                                                    {step.files?.length > 0 && (
                                                        <div className="flex flex-wrap gap-1 mt-2">
                                                            {step.files.map((f, fi) => (
                                                                <span key={fi} className="px-2 py-0.5 bg-indigo-100 text-indigo-700 rounded text-xs font-mono">
                                                                    {f}
                                                                </span>
                                                            ))}
                                                        </div>
                                                    )}
                                                </div>
                                            </div>
                                        ))
                                    ) : (
                                        <div className="text-center text-slate-500 py-8">
                                            <i className="fas fa-check-circle text-4xl text-green-500 mb-3"></i>
                                            <p>Nenhuma ação de remediação necessária</p>
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
