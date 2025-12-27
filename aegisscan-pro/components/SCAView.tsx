import React, { useState } from 'react';

interface LicenseVuln {
    package: string;
    version: string;
    license: string;
    risk: string;
    type: string;
    description: string;
    viral: boolean;
    ecosystem: string;
}

interface TyposquattingVuln {
    package: string;
    similar_to: string;
    similarity: number;
    risk: string;
    description: string;
    ecosystem: string;
    recommendation: string;
}

interface IACVuln {
    type: string;
    severity: string;
    file: string;
    line: number;
    code: string;
    description: string;
    remediation: string;
    cwe: string;
    resource: string;
}

interface SCAResult {
    path: string;
    dependencies: any[];
    licenses: {
        total_packages: number;
        vulnerabilities: LicenseVuln[];
        summary: { high_risk: number; medium_risk: number; low_risk: number; safe: number; unknown: number };
        license_breakdown: Record<string, number>;
    };
    typosquatting: {
        total_packages: number;
        vulnerabilities: TyposquattingVuln[];
        summary: { high_risk: number; medium_risk: number; low_risk: number };
    };
    iac: {
        files_scanned: number;
        vulnerabilities: IACVuln[];
        summary: { critical: number; high: number; medium: number; low: number };
        resources: { dockerfiles: number; docker_compose_files: number; kubernetes_files: number; terraform_files: number };
    };
    summary: {
        total_vulnerabilities: number;
        critical: number;
        high: number;
        medium: number;
        low: number;
        license_issues: number;
        typosquatting_risks: number;
        iac_issues: number;
    };
    score: number;
}

interface Props {
    onBack: () => void;
}

export const SCAView: React.FC<Props> = ({ onBack }) => {
    const [path, setPath] = useState('');
    const [scanning, setScanning] = useState(false);
    const [result, setResult] = useState<SCAResult | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [activeTab, setActiveTab] = useState<string>('summary');

    const handleScan = async () => {
        if (!path.trim()) {
            setError('Digite o caminho do projeto');
            return;
        }

        setScanning(true);
        setError(null);
        setResult(null);

        try {
            const response = await fetch('http://localhost:8080/api/v1/sca/full', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ path: path.trim() })
            });

            if (!response.ok) {
                const err = await response.json();
                throw new Error(err.error || 'Scan failed');
            }

            const data = await response.json();
            setResult(data);
        } catch (e: any) {
            setError(e.message);
        } finally {
            setScanning(false);
        }
    };

    const getRiskColor = (risk: string) => {
        switch (risk?.toUpperCase()) {
            case 'CRITICAL': return 'bg-red-600 text-white';
            case 'HIGH': return 'bg-orange-500 text-white';
            case 'MEDIUM': return 'bg-yellow-500 text-black';
            case 'LOW': return 'bg-green-500 text-white';
            default: return 'bg-slate-500 text-white';
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
                    <h2 className="text-2xl font-bold text-slate-900">SCA - Software Composition Analysis</h2>
                    <p className="text-sm text-slate-500">Licenças, Typosquatting, Infrastructure as Code</p>
                </div>
            </div>

            {/* Input Section */}
            <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm">
                <div className="space-y-4">
                    <div>
                        <label className="block text-sm font-medium text-slate-700 mb-2">
                            <i className="fas fa-folder-open mr-2"></i>
                            Caminho do Projeto
                        </label>
                        <div className="flex gap-3">
                            <input
                                type="text"
                                value={path}
                                onChange={(e) => setPath(e.target.value)}
                                placeholder="C:\Users\projeto ou /home/user/projeto"
                                className="flex-1 px-4 py-3 border border-slate-300 rounded-xl focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                                onKeyDown={(e) => e.key === 'Enter' && handleScan()}
                            />
                            <button
                                onClick={handleScan}
                                disabled={scanning}
                                className="px-6 py-3 bg-gradient-to-r from-emerald-600 to-teal-600 text-white rounded-xl font-semibold hover:from-emerald-700 hover:to-teal-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center gap-2"
                            >
                                {scanning ? (
                                    <>
                                        <i className="fas fa-spinner fa-spin"></i>
                                        Analisando...
                                    </>
                                ) : (
                                    <>
                                        <i className="fas fa-search"></i>
                                        Analisar
                                    </>
                                )}
                            </button>
                        </div>
                    </div>

                    {/* What it scans */}
                    <div className="grid grid-cols-4 gap-3">
                        {[
                            { icon: 'fa-balance-scale', label: 'Licenças', desc: 'GPL, AGPL, MIT...' },
                            { icon: 'fa-user-secret', label: 'Typosquatting', desc: 'Pacotes maliciosos' },
                            { icon: 'fa-docker', label: 'Docker', desc: 'Dockerfile, Compose' },
                            { icon: 'fa-cloud', label: 'IAC', desc: 'K8s, Terraform' },
                        ].map(item => (
                            <div key={item.label} className="p-3 bg-slate-50 rounded-xl text-center">
                                <i className={`fas ${item.icon} text-2xl text-indigo-500 mb-2`}></i>
                                <div className="font-medium text-slate-700">{item.label}</div>
                                <div className="text-xs text-slate-500">{item.desc}</div>
                            </div>
                        ))}
                    </div>
                </div>

                {error && (
                    <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-xl text-red-700 flex items-center gap-2">
                        <i className="fas fa-exclamation-circle"></i>
                        {error}
                    </div>
                )}
            </div>

            {/* Results */}
            {result && (
                <>
                    {/* Score Card */}
                    <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm">
                        <div className="flex items-center justify-between">
                            <div>
                                <h3 className="text-lg font-bold text-slate-900">Resultado da Análise</h3>
                                <p className="text-sm text-slate-500">{result.path}</p>
                            </div>
                            <div className="text-center">
                                <div className={`text-5xl font-bold ${getScoreColor(result.score)}`}>
                                    {result.score}
                                </div>
                                <div className="text-sm text-slate-500">Score</div>
                            </div>
                        </div>

                        <div className="grid grid-cols-4 gap-4 mt-6">
                            <div className="text-center p-4 bg-red-50 rounded-xl">
                                <div className="text-3xl font-bold text-red-600">{result.summary.critical}</div>
                                <div className="text-sm text-slate-500">Critical</div>
                            </div>
                            <div className="text-center p-4 bg-orange-50 rounded-xl">
                                <div className="text-3xl font-bold text-orange-500">{result.summary.high}</div>
                                <div className="text-sm text-slate-500">High</div>
                            </div>
                            <div className="text-center p-4 bg-yellow-50 rounded-xl">
                                <div className="text-3xl font-bold text-yellow-600">{result.summary.medium}</div>
                                <div className="text-sm text-slate-500">Medium</div>
                            </div>
                            <div className="text-center p-4 bg-green-50 rounded-xl">
                                <div className="text-3xl font-bold text-green-600">{result.summary.low}</div>
                                <div className="text-sm text-slate-500">Low</div>
                            </div>
                        </div>

                        <div className="grid grid-cols-3 gap-4 mt-4">
                            <div className="p-3 bg-purple-50 rounded-xl flex items-center gap-3">
                                <i className="fas fa-balance-scale text-purple-500 text-xl"></i>
                                <div>
                                    <div className="font-bold text-purple-700">{result.summary.license_issues}</div>
                                    <div className="text-xs text-slate-500">Problemas de Licença</div>
                                </div>
                            </div>
                            <div className="p-3 bg-amber-50 rounded-xl flex items-center gap-3">
                                <i className="fas fa-user-secret text-amber-500 text-xl"></i>
                                <div>
                                    <div className="font-bold text-amber-700">{result.summary.typosquatting_risks}</div>
                                    <div className="text-xs text-slate-500">Riscos Typosquatting</div>
                                </div>
                            </div>
                            <div className="p-3 bg-blue-50 rounded-xl flex items-center gap-3">
                                <i className="fas fa-server text-blue-500 text-xl"></i>
                                <div>
                                    <div className="font-bold text-blue-700">{result.summary.iac_issues}</div>
                                    <div className="text-xs text-slate-500">Problemas IAC</div>
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Tabs */}
                    <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
                        <div className="flex border-b border-slate-200">
                            {[
                                { key: 'summary', label: 'Resumo', icon: 'fa-chart-pie' },
                                { key: 'licenses', label: 'Licenças', icon: 'fa-balance-scale', count: result.licenses?.vulnerabilities?.length },
                                { key: 'typosquatting', label: 'Typosquatting', icon: 'fa-user-secret', count: result.typosquatting?.vulnerabilities?.length },
                                { key: 'iac', label: 'IAC', icon: 'fa-server', count: result.iac?.vulnerabilities?.length },
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
                                    {tab.count !== undefined && tab.count > 0 && (
                                        <span className="px-2 py-0.5 bg-red-100 text-red-700 rounded-full text-xs">
                                            {tab.count}
                                        </span>
                                    )}
                                </button>
                            ))}
                        </div>

                        <div className="p-6 max-h-[500px] overflow-y-auto">
                            {/* Summary Tab */}
                            {activeTab === 'summary' && (
                                <div className="space-y-6">
                                    {/* Dependencies */}
                                    {result.dependencies && result.dependencies.length > 0 && (
                                        <div>
                                            <h4 className="font-semibold text-slate-900 mb-3">
                                                <i className="fas fa-cubes mr-2 text-indigo-500"></i>
                                                Dependências por Ecossistema
                                            </h4>
                                            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                                                {result.dependencies.map((dep, i) => (
                                                    <div key={i} className="p-3 bg-slate-50 rounded-lg">
                                                        <div className="font-medium text-slate-700">{dep.ecosystem}</div>
                                                        <div className="text-sm text-slate-500">{dep.total_deps} pacotes</div>
                                                        {dep.vulnerabilities?.length > 0 && (
                                                            <div className="text-xs text-red-600 mt-1">
                                                                {dep.vulnerabilities.length} vulnerabilidades
                                                            </div>
                                                        )}
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    )}

                                    {/* IAC Resources */}
                                    {result.iac?.resources && (
                                        <div>
                                            <h4 className="font-semibold text-slate-900 mb-3">
                                                <i className="fas fa-server mr-2 text-blue-500"></i>
                                                Recursos IAC Detectados
                                            </h4>
                                            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                                                {result.iac.resources.dockerfiles > 0 && (
                                                    <div className="p-3 bg-blue-50 rounded-lg flex items-center gap-2">
                                                        <i className="fab fa-docker text-blue-500"></i>
                                                        <span>{result.iac.resources.dockerfiles} Dockerfiles</span>
                                                    </div>
                                                )}
                                                {result.iac.resources.docker_compose_files > 0 && (
                                                    <div className="p-3 bg-blue-50 rounded-lg flex items-center gap-2">
                                                        <i className="fab fa-docker text-blue-500"></i>
                                                        <span>{result.iac.resources.docker_compose_files} Compose</span>
                                                    </div>
                                                )}
                                                {result.iac.resources.kubernetes_files > 0 && (
                                                    <div className="p-3 bg-blue-50 rounded-lg flex items-center gap-2">
                                                        <i className="fas fa-dharmachakra text-blue-500"></i>
                                                        <span>{result.iac.resources.kubernetes_files} K8s</span>
                                                    </div>
                                                )}
                                                {result.iac.resources.terraform_files > 0 && (
                                                    <div className="p-3 bg-purple-50 rounded-lg flex items-center gap-2">
                                                        <i className="fas fa-cloud text-purple-500"></i>
                                                        <span>{result.iac.resources.terraform_files} Terraform</span>
                                                    </div>
                                                )}
                                            </div>
                                        </div>
                                    )}

                                    {/* License Breakdown */}
                                    {result.licenses?.license_breakdown && Object.keys(result.licenses.license_breakdown).length > 0 && (
                                        <div>
                                            <h4 className="font-semibold text-slate-900 mb-3">
                                                <i className="fas fa-balance-scale mr-2 text-purple-500"></i>
                                                Distribuição de Licenças
                                            </h4>
                                            <div className="flex flex-wrap gap-2">
                                                {Object.entries(result.licenses.license_breakdown).slice(0, 10).map(([license, count]) => (
                                                    <span key={license} className="px-3 py-1 bg-slate-100 rounded-full text-sm">
                                                        {license}: {count}
                                                    </span>
                                                ))}
                                            </div>
                                        </div>
                                    )}
                                </div>
                            )}

                            {/* Licenses Tab */}
                            {activeTab === 'licenses' && (
                                <div className="space-y-3">
                                    {result.licenses?.vulnerabilities?.length > 0 ? (
                                        result.licenses.vulnerabilities.map((vuln, i) => (
                                            <div key={i} className={`p-4 rounded-xl border ${
                                                vuln.risk === 'HIGH' ? 'bg-red-50 border-red-200' : 'bg-yellow-50 border-yellow-200'
                                            }`}>
                                                <div className="flex items-center justify-between mb-2">
                                                    <div className="flex items-center gap-2">
                                                        <span className="font-mono font-bold text-slate-700">{vuln.package}</span>
                                                        <span className="text-sm text-slate-500">v{vuln.version}</span>
                                                        <span className="px-2 py-0.5 bg-slate-200 rounded text-xs">{vuln.ecosystem}</span>
                                                    </div>
                                                    <div className="flex items-center gap-2">
                                                        {vuln.viral && (
                                                            <span className="px-2 py-0.5 bg-red-100 text-red-700 rounded text-xs">
                                                                <i className="fas fa-virus mr-1"></i>VIRAL
                                                            </span>
                                                        )}
                                                        <span className={`px-2 py-1 rounded text-xs font-bold ${getRiskColor(vuln.risk)}`}>
                                                            {vuln.risk}
                                                        </span>
                                                    </div>
                                                </div>
                                                <div className="flex items-center gap-2 mb-2">
                                                    <span className="px-2 py-1 bg-purple-100 text-purple-700 rounded text-sm font-medium">
                                                        {vuln.license}
                                                    </span>
                                                    <span className="text-xs text-slate-500">({vuln.type})</span>
                                                </div>
                                                <p className="text-sm text-slate-600">{vuln.description}</p>
                                            </div>
                                        ))
                                    ) : (
                                        <div className="p-6 text-center text-slate-500">
                                            <i className="fas fa-check-circle text-4xl text-green-500 mb-3"></i>
                                            <p>Nenhum problema de licença detectado</p>
                                        </div>
                                    )}
                                </div>
                            )}

                            {/* Typosquatting Tab */}
                            {activeTab === 'typosquatting' && (
                                <div className="space-y-3">
                                    {result.typosquatting?.vulnerabilities?.length > 0 ? (
                                        result.typosquatting.vulnerabilities.map((vuln, i) => (
                                            <div key={i} className={`p-4 rounded-xl border ${
                                                vuln.risk === 'HIGH' ? 'bg-red-50 border-red-200' : 'bg-amber-50 border-amber-200'
                                            }`}>
                                                <div className="flex items-center justify-between mb-2">
                                                    <div className="flex items-center gap-2">
                                                        <span className="font-mono font-bold text-red-700">{vuln.package}</span>
                                                        <i className="fas fa-arrow-right text-slate-400"></i>
                                                        <span className="font-mono text-green-700">{vuln.similar_to}</span>
                                                    </div>
                                                    <span className={`px-2 py-1 rounded text-xs font-bold ${getRiskColor(vuln.risk)}`}>
                                                        {(vuln.similarity * 100).toFixed(0)}% similar
                                                    </span>
                                                </div>
                                                <p className="text-sm text-slate-600 mb-2">{vuln.description}</p>
                                                <p className="text-xs text-amber-700 bg-amber-100 p-2 rounded">
                                                    <i className="fas fa-lightbulb mr-1"></i>
                                                    {vuln.recommendation}
                                                </p>
                                            </div>
                                        ))
                                    ) : (
                                        <div className="p-6 text-center text-slate-500">
                                            <i className="fas fa-shield-alt text-4xl text-green-500 mb-3"></i>
                                            <p>Nenhum risco de typosquatting detectado</p>
                                        </div>
                                    )}
                                </div>
                            )}

                            {/* IAC Tab */}
                            {activeTab === 'iac' && (
                                <div className="space-y-3">
                                    {result.iac?.vulnerabilities?.length > 0 ? (
                                        result.iac.vulnerabilities.map((vuln, i) => (
                                            <div key={i} className={`p-4 rounded-xl border ${
                                                vuln.severity === 'CRITICAL' ? 'bg-red-50 border-red-200' :
                                                vuln.severity === 'HIGH' ? 'bg-orange-50 border-orange-200' :
                                                vuln.severity === 'MEDIUM' ? 'bg-yellow-50 border-yellow-200' :
                                                'bg-slate-50 border-slate-200'
                                            }`}>
                                                <div className="flex items-center justify-between mb-2">
                                                    <div className="flex items-center gap-2">
                                                        <span className="font-medium text-slate-700">{vuln.type}</span>
                                                        <span className="px-2 py-0.5 bg-blue-100 text-blue-700 rounded text-xs">
                                                            {vuln.resource}
                                                        </span>
                                                    </div>
                                                    <span className={`px-2 py-1 rounded text-xs font-bold ${getRiskColor(vuln.severity)}`}>
                                                        {vuln.severity}
                                                    </span>
                                                </div>
                                                <div className="text-xs text-slate-500 mb-2">
                                                    <i className="fas fa-file mr-1"></i>
                                                    {vuln.file}
                                                    {vuln.line > 0 && <span className="ml-2">Linha {vuln.line}</span>}
                                                </div>
                                                {vuln.code && (
                                                    <pre className="text-xs bg-slate-800 text-green-400 p-2 rounded mb-2 overflow-x-auto">
                                                        {vuln.code}
                                                    </pre>
                                                )}
                                                <p className="text-sm text-slate-600 mb-2">{vuln.description}</p>
                                                <p className="text-xs text-blue-700 bg-blue-50 p-2 rounded">
                                                    <i className="fas fa-wrench mr-1"></i>
                                                    {vuln.remediation}
                                                </p>
                                            </div>
                                        ))
                                    ) : (
                                        <div className="p-6 text-center text-slate-500">
                                            <i className="fas fa-server text-4xl text-green-500 mb-3"></i>
                                            <p>Nenhum problema de IAC detectado</p>
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
