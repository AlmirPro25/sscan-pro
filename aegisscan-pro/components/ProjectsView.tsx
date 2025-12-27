import React, { useState, useEffect } from 'react';
import { FileBrowser } from './FileBrowser';

interface Project {
    id: number;
    name: string;
    description: string;
    local_path: string;
    production_url: string;
    staging_url: string;
    created_at: string;
    updated_at: string;
}

interface ProjectCorrelation {
    id: number;
    sast_vuln_type: string;
    dast_vuln_type: string;
    correlation_type: string;
    risk_level: string;
    description: string;
}

interface RiskSummary {
    total_vulns: number;
    confirmed_in_prod: number;
    code_only: number;
    prod_only: number;
    critical_risks: number;
}

interface ScorePoint {
    date: string;
    sast_score: number;
    dast_score: number;
}

interface ProjectDashboard {
    project: Project;
    latest_sast: any;
    latest_dast: any;
    correlations: ProjectCorrelation[];
    score_history: ScorePoint[];
    risk_summary: RiskSummary;
}

interface Props {
    onBack: () => void;
}

export const ProjectsView: React.FC<Props> = ({ onBack }) => {
    const [projects, setProjects] = useState<Project[]>([]);
    const [selectedProject, setSelectedProject] = useState<Project | null>(null);
    const [dashboard, setDashboard] = useState<ProjectDashboard | null>(null);
    const [loading, setLoading] = useState(true);
    const [showCreateModal, setShowCreateModal] = useState(false);
    const [showFileBrowser, setShowFileBrowser] = useState(false);
    const [correlating, setCorrelating] = useState(false);

    // Form state
    const [formName, setFormName] = useState('');
    const [formDescription, setFormDescription] = useState('');
    const [formLocalPath, setFormLocalPath] = useState('');
    const [formProdUrl, setFormProdUrl] = useState('');

    useEffect(() => {
        loadProjects();
    }, []);

    const loadProjects = async () => {
        try {
            const response = await fetch('http://localhost:8080/api/v1/projects');
            if (response.ok) {
                const data = await response.json();
                setProjects(data || []);
            }
        } catch (e) {
            console.error('Failed to load projects');
        } finally {
            setLoading(false);
        }
    };

    const loadProjectDashboard = async (project: Project) => {
        setSelectedProject(project);
        try {
            const response = await fetch(`http://localhost:8080/api/v1/projects/${project.id}/dashboard`);
            if (response.ok) {
                const data = await response.json();
                setDashboard(data);
            }
        } catch (e) {
            console.error('Failed to load dashboard');
        }
    };

    const handleCreateProject = async () => {
        if (!formName.trim()) return;

        try {
            const response = await fetch('http://localhost:8080/api/v1/projects', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    name: formName,
                    description: formDescription,
                    local_path: formLocalPath,
                    production_url: formProdUrl,
                })
            });

            if (response.ok) {
                setShowCreateModal(false);
                setFormName('');
                setFormDescription('');
                setFormLocalPath('');
                setFormProdUrl('');
                loadProjects();
            }
        } catch (e) {
            console.error('Failed to create project');
        }
    };

    const handleCorrelate = async () => {
        if (!selectedProject) return;
        setCorrelating(true);

        try {
            const response = await fetch(`http://localhost:8080/api/v1/projects/${selectedProject.id}/correlate`, {
                method: 'POST'
            });

            if (response.ok) {
                // Reload dashboard to show new correlations
                loadProjectDashboard(selectedProject);
            }
        } catch (e) {
            console.error('Failed to correlate');
        } finally {
            setCorrelating(false);
        }
    };

    const getRiskColor = (level: string) => {
        switch (level) {
            case 'CRITICAL': return 'bg-red-600 text-white';
            case 'HIGH': return 'bg-orange-500 text-white';
            case 'MEDIUM': return 'bg-yellow-500 text-black';
            case 'LOW': return 'bg-green-500 text-white';
            default: return 'bg-slate-500 text-white';
        }
    };

    const getScoreColor = (score: number) => {
        if (score >= 80) return 'text-emerald-500';
        if (score >= 60) return 'text-yellow-500';
        if (score >= 40) return 'text-orange-500';
        return 'text-red-500';
    };

    // Project List View
    if (!selectedProject) {
        return (
            <div className="space-y-6">
                {/* Header */}
                <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                        <button onClick={onBack} className="p-2 hover:bg-slate-100 rounded-lg transition-colors">
                            <i className="fas fa-arrow-left text-slate-600"></i>
                        </button>
                        <div>
                            <h2 className="text-2xl font-bold text-slate-900">Projetos</h2>
                            <p className="text-sm text-slate-500">Gerencie projetos com SAST + DAST unificado</p>
                        </div>
                    </div>
                    <button
                        onClick={() => setShowCreateModal(true)}
                        className="px-4 py-2 bg-indigo-600 text-white rounded-xl font-medium hover:bg-indigo-700 flex items-center gap-2"
                    >
                        <i className="fas fa-plus"></i>
                        Novo Projeto
                    </button>
                </div>

                {/* Projects Grid */}
                {loading ? (
                    <div className="flex items-center justify-center py-20">
                        <i className="fas fa-spinner fa-spin text-3xl text-indigo-500"></i>
                    </div>
                ) : projects.length === 0 ? (
                    <div className="text-center py-20 bg-white rounded-2xl border border-slate-200">
                        <i className="fas fa-project-diagram text-5xl text-slate-300 mb-4"></i>
                        <h3 className="text-lg font-medium text-slate-700 mb-2">Nenhum projeto ainda</h3>
                        <p className="text-slate-500 mb-6">Crie um projeto para unificar análises SAST e DAST</p>
                        <button
                            onClick={() => setShowCreateModal(true)}
                            className="px-6 py-3 bg-indigo-600 text-white rounded-xl font-medium hover:bg-indigo-700"
                        >
                            Criar Primeiro Projeto
                        </button>
                    </div>
                ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                        {projects.map(project => (
                            <div
                                key={project.id}
                                onClick={() => loadProjectDashboard(project)}
                                className="bg-white rounded-2xl border border-slate-200 p-6 hover:border-indigo-300 hover:shadow-lg transition-all cursor-pointer"
                            >
                                <div className="flex items-start justify-between mb-4">
                                    <div className="w-12 h-12 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-xl flex items-center justify-center text-white font-bold text-lg">
                                        {project.name.charAt(0).toUpperCase()}
                                    </div>
                                    <div className="flex gap-2">
                                        {project.local_path && (
                                            <span className="px-2 py-1 bg-blue-100 text-blue-700 text-xs rounded-full font-medium">
                                                SAST
                                            </span>
                                        )}
                                        {project.production_url && (
                                            <span className="px-2 py-1 bg-green-100 text-green-700 text-xs rounded-full font-medium">
                                                DAST
                                            </span>
                                        )}
                                    </div>
                                </div>
                                <h3 className="font-bold text-slate-900 mb-1">{project.name}</h3>
                                <p className="text-sm text-slate-500 mb-4 line-clamp-2">{project.description || 'Sem descrição'}</p>
                                <div className="text-xs text-slate-400">
                                    Atualizado {new Date(project.updated_at).toLocaleDateString()}
                                </div>
                            </div>
                        ))}
                    </div>
                )}

                {/* Create Modal */}
                {showCreateModal && (
                    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
                        <div className="bg-white rounded-2xl shadow-2xl w-full max-w-lg">
                            <div className="p-6 border-b border-slate-200">
                                <h3 className="text-xl font-bold text-slate-900">Novo Projeto</h3>
                                <p className="text-sm text-slate-500">Configure um projeto para análise unificada</p>
                            </div>
                            <div className="p-6 space-y-4">
                                <div>
                                    <label className="block text-sm font-medium text-slate-700 mb-1">Nome do Projeto *</label>
                                    <input
                                        type="text"
                                        value={formName}
                                        onChange={(e) => setFormName(e.target.value)}
                                        placeholder="Meu App"
                                        className="w-full px-4 py-2 border border-slate-300 rounded-xl focus:ring-2 focus:ring-indigo-500"
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-slate-700 mb-1">Descrição</label>
                                    <textarea
                                        value={formDescription}
                                        onChange={(e) => setFormDescription(e.target.value)}
                                        placeholder="Descrição do projeto..."
                                        className="w-full px-4 py-2 border border-slate-300 rounded-xl focus:ring-2 focus:ring-indigo-500 h-20"
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-slate-700 mb-1">
                                        <i className="fas fa-folder mr-2 text-blue-500"></i>
                                        Caminho Local (SAST)
                                    </label>
                                    <div className="flex gap-2">
                                        <input
                                            type="text"
                                            value={formLocalPath}
                                            onChange={(e) => setFormLocalPath(e.target.value)}
                                            placeholder="C:\projetos\meu-app"
                                            className="flex-1 px-4 py-2 border border-slate-300 rounded-xl focus:ring-2 focus:ring-indigo-500 font-mono text-sm"
                                        />
                                        <button
                                            onClick={() => setShowFileBrowser(true)}
                                            className="px-3 py-2 bg-slate-100 border border-slate-300 rounded-xl hover:bg-slate-200"
                                        >
                                            <i className="fas fa-folder-open"></i>
                                        </button>
                                    </div>
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-slate-700 mb-1">
                                        <i className="fas fa-globe mr-2 text-green-500"></i>
                                        URL de Produção (DAST)
                                    </label>
                                    <input
                                        type="url"
                                        value={formProdUrl}
                                        onChange={(e) => setFormProdUrl(e.target.value)}
                                        placeholder="https://meuapp.com"
                                        className="w-full px-4 py-2 border border-slate-300 rounded-xl focus:ring-2 focus:ring-indigo-500"
                                    />
                                </div>
                            </div>
                            <div className="p-6 border-t border-slate-200 flex justify-end gap-3">
                                <button
                                    onClick={() => setShowCreateModal(false)}
                                    className="px-4 py-2 text-slate-600 hover:bg-slate-100 rounded-xl"
                                >
                                    Cancelar
                                </button>
                                <button
                                    onClick={handleCreateProject}
                                    disabled={!formName.trim()}
                                    className="px-6 py-2 bg-indigo-600 text-white rounded-xl font-medium hover:bg-indigo-700 disabled:opacity-50"
                                >
                                    Criar Projeto
                                </button>
                            </div>
                        </div>
                    </div>
                )}

                {/* File Browser */}
                {showFileBrowser && (
                    <FileBrowser
                        onSelect={(path) => {
                            setFormLocalPath(path);
                            setShowFileBrowser(false);
                        }}
                        onClose={() => setShowFileBrowser(false)}
                    />
                )}
            </div>
        );
    }


    // Project Dashboard View
    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                    <button onClick={() => { setSelectedProject(null); setDashboard(null); }} className="p-2 hover:bg-slate-100 rounded-lg transition-colors">
                        <i className="fas fa-arrow-left text-slate-600"></i>
                    </button>
                    <div>
                        <h2 className="text-2xl font-bold text-slate-900">{selectedProject.name}</h2>
                        <p className="text-sm text-slate-500">{selectedProject.description || 'Security Intelligence Dashboard'}</p>
                    </div>
                </div>
                <button
                    onClick={handleCorrelate}
                    disabled={correlating}
                    className="px-4 py-2 bg-purple-600 text-white rounded-xl font-medium hover:bg-purple-700 disabled:opacity-50 flex items-center gap-2"
                >
                    {correlating ? (
                        <>
                            <i className="fas fa-spinner fa-spin"></i>
                            Analisando...
                        </>
                    ) : (
                        <>
                            <i className="fas fa-brain"></i>
                            Correlacionar SAST + DAST
                        </>
                    )}
                </button>
            </div>

            {/* Project Info Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* SAST Card */}
                <div className="bg-white rounded-2xl border border-slate-200 p-6">
                    <div className="flex items-center gap-3 mb-4">
                        <div className="w-10 h-10 bg-blue-100 rounded-xl flex items-center justify-center">
                            <i className="fas fa-code text-blue-600"></i>
                        </div>
                        <div>
                            <h3 className="font-bold text-slate-900">Análise de Código (SAST)</h3>
                            <p className="text-xs text-slate-500">Static Application Security Testing</p>
                        </div>
                    </div>
                    
                    {dashboard?.latest_sast ? (
                        <div className="space-y-3">
                            <div className="flex items-center justify-between">
                                <span className="text-sm text-slate-600">Score</span>
                                <span className={`text-2xl font-bold ${getScoreColor(dashboard.latest_sast.score)}`}>
                                    {dashboard.latest_sast.score}/100
                                </span>
                            </div>
                            <div className="flex items-center justify-between text-sm">
                                <span className="text-slate-600">Arquivos</span>
                                <span className="font-medium">{dashboard.latest_sast.files_scanned}</span>
                            </div>
                            <div className="flex items-center justify-between text-sm">
                                <span className="text-slate-600">Último scan</span>
                                <span className="font-medium">{new Date(dashboard.latest_sast.created_at).toLocaleDateString()}</span>
                            </div>
                            <div className="pt-3 border-t border-slate-100">
                                <div className="font-mono text-xs text-slate-500 truncate">{selectedProject.local_path}</div>
                            </div>
                        </div>
                    ) : (
                        <div className="text-center py-6 text-slate-400">
                            <i className="fas fa-folder-open text-3xl mb-2"></i>
                            <p className="text-sm">Nenhum scan SAST ainda</p>
                            <p className="text-xs">Vá em Code Scanner e escaneie o projeto</p>
                        </div>
                    )}
                </div>

                {/* DAST Card */}
                <div className="bg-white rounded-2xl border border-slate-200 p-6">
                    <div className="flex items-center gap-3 mb-4">
                        <div className="w-10 h-10 bg-green-100 rounded-xl flex items-center justify-center">
                            <i className="fas fa-globe text-green-600"></i>
                        </div>
                        <div>
                            <h3 className="font-bold text-slate-900">Análise de Produção (DAST)</h3>
                            <p className="text-xs text-slate-500">Dynamic Application Security Testing</p>
                        </div>
                    </div>
                    
                    {dashboard?.latest_dast ? (
                        <div className="space-y-3">
                            <div className="flex items-center justify-between">
                                <span className="text-sm text-slate-600">Score</span>
                                <span className={`text-2xl font-bold ${getScoreColor(dashboard.latest_dast.score)}`}>
                                    {dashboard.latest_dast.score}/100
                                </span>
                            </div>
                            <div className="flex items-center justify-between text-sm">
                                <span className="text-slate-600">Endpoints</span>
                                <span className="font-medium">{JSON.parse(dashboard.latest_dast.endpoints || '[]').length}</span>
                            </div>
                            <div className="flex items-center justify-between text-sm">
                                <span className="text-slate-600">Último scan</span>
                                <span className="font-medium">{new Date(dashboard.latest_dast.created_at).toLocaleDateString()}</span>
                            </div>
                            <div className="pt-3 border-t border-slate-100">
                                <div className="font-mono text-xs text-slate-500 truncate">{selectedProject.production_url}</div>
                            </div>
                        </div>
                    ) : (
                        <div className="text-center py-6 text-slate-400">
                            <i className="fas fa-globe text-3xl mb-2"></i>
                            <p className="text-sm">Nenhum scan DAST ainda</p>
                            <p className="text-xs">Vá em Monitor e escaneie a URL</p>
                        </div>
                    )}
                </div>
            </div>

            {/* Risk Summary */}
            {dashboard?.risk_summary && (
                <div className="bg-gradient-to-r from-slate-900 to-slate-800 rounded-2xl p-6 text-white">
                    <h3 className="font-bold mb-4 flex items-center gap-2">
                        <i className="fas fa-shield-halved"></i>
                        Resumo de Risco Unificado
                    </h3>
                    <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                        <div className="text-center">
                            <div className="text-3xl font-bold">{dashboard.risk_summary.total_vulns}</div>
                            <div className="text-xs text-slate-400">Total Vulns</div>
                        </div>
                        <div className="text-center">
                            <div className="text-3xl font-bold text-red-400">{dashboard.risk_summary.confirmed_in_prod}</div>
                            <div className="text-xs text-slate-400">Confirmadas em Prod</div>
                        </div>
                        <div className="text-center">
                            <div className="text-3xl font-bold text-blue-400">{dashboard.risk_summary.code_only}</div>
                            <div className="text-xs text-slate-400">Só no Código</div>
                        </div>
                        <div className="text-center">
                            <div className="text-3xl font-bold text-green-400">{dashboard.risk_summary.prod_only}</div>
                            <div className="text-xs text-slate-400">Só em Produção</div>
                        </div>
                        <div className="text-center">
                            <div className="text-3xl font-bold text-red-500">{dashboard.risk_summary.critical_risks}</div>
                            <div className="text-xs text-slate-400">Riscos Críticos</div>
                        </div>
                    </div>
                </div>
            )}

            {/* Correlations */}
            {dashboard?.correlations && dashboard.correlations.length > 0 && (
                <div className="bg-white rounded-2xl border border-slate-200 p-6">
                    <h3 className="font-bold text-slate-900 mb-4 flex items-center gap-2">
                        <i className="fas fa-link text-purple-500"></i>
                        Correlações SAST ↔ DAST
                        <span className="px-2 py-0.5 bg-purple-100 text-purple-700 text-xs rounded-full">
                            {dashboard.correlations.length} encontradas
                        </span>
                    </h3>
                    <div className="space-y-3">
                        {dashboard.correlations.map((corr, idx) => (
                            <div key={idx} className="flex items-center gap-4 p-4 bg-slate-50 rounded-xl">
                                <span className={`px-3 py-1 rounded-lg text-xs font-bold ${getRiskColor(corr.risk_level)}`}>
                                    {corr.risk_level}
                                </span>
                                <div className="flex-1">
                                    <div className="flex items-center gap-2 text-sm">
                                        <span className="px-2 py-0.5 bg-blue-100 text-blue-700 rounded text-xs">SAST</span>
                                        <span className="font-medium">{corr.sast_vuln_type}</span>
                                        <i className="fas fa-arrow-right text-slate-400"></i>
                                        <span className="px-2 py-0.5 bg-green-100 text-green-700 rounded text-xs">DAST</span>
                                        <span className="font-medium">{corr.dast_vuln_type}</span>
                                    </div>
                                    <p className="text-xs text-slate-500 mt-1">{corr.description}</p>
                                </div>
                                <span className={`px-2 py-1 rounded text-xs font-medium ${
                                    corr.correlation_type === 'confirmed' 
                                        ? 'bg-red-100 text-red-700' 
                                        : 'bg-yellow-100 text-yellow-700'
                                }`}>
                                    {corr.correlation_type === 'confirmed' ? '⚠️ Confirmado' : '🔍 Potencial'}
                                </span>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* No correlations yet */}
            {(!dashboard?.correlations || dashboard.correlations.length === 0) && dashboard?.latest_sast && dashboard?.latest_dast && (
                <div className="bg-white rounded-2xl border border-slate-200 p-6 text-center">
                    <i className="fas fa-link text-4xl text-slate-300 mb-3"></i>
                    <h3 className="font-medium text-slate-700 mb-2">Nenhuma correlação encontrada</h3>
                    <p className="text-sm text-slate-500 mb-4">
                        Clique em "Correlacionar SAST + DAST" para analisar vulnerabilidades em comum
                    </p>
                </div>
            )}

            {/* Instructions if missing scans */}
            {(!dashboard?.latest_sast || !dashboard?.latest_dast) && (
                <div className="bg-amber-50 border border-amber-200 rounded-2xl p-6">
                    <h3 className="font-bold text-amber-800 mb-2 flex items-center gap-2">
                        <i className="fas fa-info-circle"></i>
                        Para correlacionar, você precisa de ambos os scans
                    </h3>
                    <ul className="text-sm text-amber-700 space-y-2">
                        {!dashboard?.latest_sast && (
                            <li className="flex items-center gap-2">
                                <i className="fas fa-times-circle text-red-500"></i>
                                <span>Falta scan SAST - Vá em <strong>Code Scanner</strong> e escaneie: <code className="bg-amber-100 px-1 rounded">{selectedProject.local_path || 'configure o path'}</code></span>
                            </li>
                        )}
                        {!dashboard?.latest_dast && (
                            <li className="flex items-center gap-2">
                                <i className="fas fa-times-circle text-red-500"></i>
                                <span>Falta scan DAST - Vá em <strong>Monitor</strong> e escaneie: <code className="bg-amber-100 px-1 rounded">{selectedProject.production_url || 'configure a URL'}</code></span>
                            </li>
                        )}
                    </ul>
                </div>
            )}
        </div>
    );
};
