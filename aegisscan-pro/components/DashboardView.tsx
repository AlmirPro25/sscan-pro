import React, { useState, useEffect } from 'react';
import { DashboardStats, ScreenState } from '../types';
import { AreaChart, Area, ResponsiveContainer, CartesianGrid, XAxis, Tooltip } from 'recharts';

interface DashboardViewProps {
    stats: DashboardStats | null;
    onStartScan: (url: string) => void;
    onNavigate: (screen: ScreenState) => void;
}

const Icons = {
    Radar: ({ className }: { className?: string }) => <i className={`fas fa-satellite-dish ${className || ''}`}></i>,
    Diagram: ({ className }: { className?: string }) => <i className={`fas fa-network-wired ${className || ''}`}></i>,
    Shield: ({ className }: { className?: string }) => <i className={`fas fa-shield-halved ${className || ''}`}></i>,
    Bolt: ({ className }: { className?: string }) => <i className={`fas fa-bolt ${className || ''}`}></i>,
    ArrowLeft: ({ className }: { className?: string }) => <i className={`fas fa-chevron-left ${className || ''}`}></i>,
    Code: ({ className }: { className?: string }) => <i className={`fas fa-code ${className || ''}`}></i>,
};

const StatCard = ({ label, value, icon, color = 'indigo', progress = 70, subtitle }: any) => (
    <div className={`p-6 cyber-card rounded-2xl shadow-sm relative overflow-hidden group hover:border-${color}-300 transition-all`}>
        <div className={`absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity text-${color}-600`}>
            {icon}
        </div>
        <div className="text-[10px] text-slate-400 font-bold uppercase tracking-widest mb-2">{label}</div>
        <div className="text-3xl font-black text-slate-900 data-value">{value}</div>
        {subtitle && <div className="text-[10px] text-slate-400 mt-1">{subtitle}</div>}
        <div className={`h-1 w-full bg-slate-100 mt-4 rounded-full overflow-hidden`}>
            <div
                className={`h-full bg-${color}-500 transition-all duration-1000 ease-out`}
                style={{ width: `${progress}%` }}
            ></div>
        </div>
    </div>
);

export const DashboardView: React.FC<DashboardViewProps> = ({ stats, onStartScan, onNavigate }) => {
    const [url, setUrl] = useState('');
    const [isLoading, setIsLoading] = useState(false);

    const handleSubmit = () => {
        if (url.trim()) {
            setIsLoading(true);
            onStartScan(url);
        }
    };

    // Reset loading when stats change (scan completed)
    useEffect(() => {
        setIsLoading(false);
    }, [stats]);

    const getScoreColor = (score: number) => {
        if (score >= 80) return 'emerald';
        if (score >= 50) return 'amber';
        return 'red';
    };

    return (
        <div className="space-y-8 animate-[fadeIn_0.5s_ease-out]">
            {/* Header Section */}
            <div className="flex flex-col md:flex-row justify-between items-end gap-4 border-b border-slate-200 pb-6">
                <div>
                    <h2 className="text-3xl font-black text-slate-900 uppercase tracking-tight mb-2">Centro de Comando</h2>
                    <p className="text-sm text-slate-500 font-medium">Análise de superfície e avaliação de vulnerabilidades.</p>
                </div>
                <div className="flex items-center gap-2">
                    <div className={`px-3 py-1.5 rounded-full text-[10px] font-bold uppercase tracking-wide flex items-center gap-2 ${stats ? 'bg-emerald-50 text-emerald-600 border border-emerald-200' : 'bg-slate-100 text-slate-400'}`}>
                        <div className={`w-2 h-2 rounded-full ${stats ? 'bg-emerald-500 animate-pulse' : 'bg-slate-300'}`}></div>
                        {stats ? 'Dados Sincronizados' : 'Carregando...'}
                    </div>
                </div>
            </div>

            {/* URL Input - DAST Scanner */}
            <div className="bg-white p-1 rounded-2xl shadow-xl shadow-indigo-100/50 border border-slate-200">
                <div className="bg-slate-50 rounded-xl p-8 border border-slate-100">
                    <div className="flex items-center justify-between mb-4">
                        <label className="block text-[10px] font-bold text-indigo-500 uppercase tracking-[0.2em]">
                            <i className="fas fa-globe mr-2"></i>Scanner DAST - URL de Produção
                        </label>
                        <span className="text-[9px] bg-indigo-100 text-indigo-600 px-2 py-1 rounded font-bold">ANÁLISE EXTERNA</span>
                    </div>
                    <div className="flex flex-col md:flex-row gap-4">
                        <div className="relative flex-1 group">
                            <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                                <i className="fas fa-link text-slate-400 group-focus-within:text-indigo-500 transition-colors"></i>
                            </div>
                            <input
                                type="url"
                                value={url}
                                onChange={(e) => setUrl(e.target.value)}
                                placeholder="https://meu-app.com.br"
                                className="w-full bg-white border border-slate-200 pl-11 pr-4 py-4 rounded-xl text-sm font-bold text-slate-800 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all shadow-sm"
                                onKeyDown={(e) => e.key === 'Enter' && handleSubmit()}
                            />
                        </div>
                        <button
                            onClick={handleSubmit}
                            disabled={isLoading || !url.trim()}
                            className="bg-indigo-600 text-white px-8 py-4 rounded-xl font-bold text-sm uppercase tracking-wider hover:bg-indigo-700 active:scale-95 transition-all shadow-lg shadow-indigo-200 flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                            {isLoading ? (
                                <><i className="fas fa-circle-notch fa-spin"></i> Analisando...</>
                            ) : (
                                <><Icons.Bolt /> Iniciar Scan</>
                            )}
                        </button>
                    </div>
                    <p className="mt-3 text-[10px] text-slate-400 font-medium">
                        <i className="fas fa-info-circle mr-1"></i> Analisa endpoints, headers de segurança, SSL/TLS e vulnerabilidades web.
                    </p>
                </div>
            </div>

            {/* Quick Actions */}
            <div className="grid grid-cols-2 gap-4">
                <button
                    onClick={() => onNavigate(ScreenState.CODE_SCANNER)}
                    className="p-6 bg-gradient-to-br from-purple-500 to-indigo-600 rounded-2xl text-white text-left group hover:shadow-xl hover:shadow-purple-200 transition-all"
                >
                    <div className="flex items-center justify-between mb-4">
                        <div className="w-12 h-12 bg-white/20 rounded-xl flex items-center justify-center">
                            <Icons.Code className="text-xl" />
                        </div>
                        <i className="fas fa-arrow-right opacity-50 group-hover:translate-x-1 transition-transform"></i>
                    </div>
                    <h3 className="font-black text-lg uppercase tracking-tight">Scanner SAST</h3>
                    <p className="text-[10px] text-white/70 font-medium mt-1">Análise de código local</p>
                </button>
                <button
                    onClick={() => onNavigate(ScreenState.PROJECTS)}
                    className="p-6 bg-gradient-to-br from-emerald-500 to-teal-600 rounded-2xl text-white text-left group hover:shadow-xl hover:shadow-emerald-200 transition-all"
                >
                    <div className="flex items-center justify-between mb-4">
                        <div className="w-12 h-12 bg-white/20 rounded-xl flex items-center justify-center">
                            <i className="fas fa-project-diagram text-xl"></i>
                        </div>
                        <i className="fas fa-arrow-right opacity-50 group-hover:translate-x-1 transition-transform"></i>
                    </div>
                    <h3 className="font-black text-lg uppercase tracking-tight">Projetos</h3>
                    <p className="text-[10px] text-white/70 font-medium mt-1">SAST + DAST unificado</p>
                </button>
            </div>

            {/* Stats Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <StatCard 
                    label="Total de Auditorias" 
                    value={stats?.total_scans || 0} 
                    icon={<Icons.Radar className="text-4xl" />} 
                    color="indigo" 
                    progress={stats?.total_scans ? Math.min(stats.total_scans * 10, 100) : 0}
                    subtitle="Scans realizados"
                />
                <StatCard 
                    label="Endpoints Mapeados" 
                    value={stats?.total_endpoints || 0} 
                    icon={<Icons.Diagram className="text-4xl" />} 
                    color="emerald" 
                    progress={Math.min((stats?.total_endpoints || 0) / 5, 100)}
                    subtitle="Rotas descobertas"
                />
                <StatCard 
                    label="Score Médio" 
                    value={`${stats?.avg_score || 0}%`} 
                    icon={<Icons.Shield className="text-4xl" />} 
                    color={getScoreColor(stats?.avg_score || 0)} 
                    progress={stats?.avg_score || 0}
                    subtitle={stats?.avg_score && stats.avg_score >= 80 ? 'Excelente' : stats?.avg_score && stats.avg_score >= 50 ? 'Atenção' : 'Crítico'}
                />
                <div className="p-6 bg-slate-900 rounded-2xl text-white relative overflow-hidden flex flex-col justify-center group cursor-pointer hover:bg-slate-800 transition-all" onClick={() => onNavigate(ScreenState.HISTORY)}>
                    <div className="absolute inset-0 bg-gradient-to-br from-indigo-600 to-purple-600 opacity-20 group-hover:opacity-30 transition-opacity"></div>
                    <div className="relative z-10 flex items-center justify-between">
                        <div>
                            <div className="text-3xl font-black mb-1">Vault</div>
                            <div className="text-[10px] text-slate-400 font-bold uppercase tracking-widest">Ver Histórico</div>
                        </div>
                        <div className="w-10 h-10 rounded-full bg-white/10 flex items-center justify-center group-hover:bg-white/20 transition-colors">
                            <Icons.ArrowLeft className="rotate-180" />
                        </div>
                    </div>
                </div>
            </div>

            {/* Chart Area */}
            {stats && stats.total_scans > 0 && stats.score_trend && stats.score_trend.length > 0 && (
                <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
                    <div className="flex justify-between items-center mb-6">
                        <div>
                            <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest">Evolução do Score de Segurança</h3>
                            <p className="text-[10px] text-slate-400 mt-1">Últimas {stats.score_trend.length} auditorias</p>
                        </div>
                        <span className="text-[10px] bg-emerald-50 text-emerald-600 px-2 py-1 rounded font-bold flex items-center gap-1">
                            <span className="w-1.5 h-1.5 bg-emerald-500 rounded-full animate-pulse"></span>
                            DADOS EM TEMPO REAL
                        </span>
                    </div>
                    <div style={{ width: '100%', height: 250 }}>
                        <ResponsiveContainer width="100%" height="100%">
                            <AreaChart data={stats.score_trend.map((s, i) => ({ idx: `Scan ${i + 1}`, score: s }))}>
                                <defs>
                                    <linearGradient id="colorScore" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="5%" stopColor="#4f46e5" stopOpacity={0.2} />
                                        <stop offset="95%" stopColor="#4f46e5" stopOpacity={0} />
                                    </linearGradient>
                                </defs>
                                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#f1f5f9" />
                                <XAxis dataKey="idx" tick={{ fontSize: 10, fill: '#94a3b8' }} />
                                <Tooltip
                                    contentStyle={{ backgroundColor: '#fff', borderRadius: '8px', border: '1px solid #e2e8f0', fontSize: '12px', fontWeight: 'bold' }}
                                    formatter={(value: number) => [`${value}%`, 'Score']}
                                />
                                <Area type="monotone" dataKey="score" stroke="#4f46e5" strokeWidth={3} fillOpacity={1} fill="url(#colorScore)" />
                            </AreaChart>
                        </ResponsiveContainer>
                    </div>
                </div>
            )}

            {/* Empty State */}
            {(!stats || stats.total_scans === 0) && (
                <div className="bg-white p-12 rounded-2xl border-2 border-dashed border-slate-200 text-center">
                    <div className="w-20 h-20 bg-slate-100 rounded-2xl flex items-center justify-center mx-auto mb-6">
                        <i className="fas fa-shield-halved text-3xl text-slate-300"></i>
                    </div>
                    <h3 className="text-lg font-black text-slate-800 mb-2">Nenhuma Auditoria Ainda</h3>
                    <p className="text-sm text-slate-500 mb-6">Comece inserindo uma URL acima ou use o Scanner SAST para analisar código local.</p>
                    <div className="flex justify-center gap-4">
                        <button
                            onClick={() => onNavigate(ScreenState.CODE_SCANNER)}
                            className="px-6 py-3 bg-purple-600 text-white rounded-xl font-bold text-sm hover:bg-purple-700 transition-all"
                        >
                            <i className="fas fa-code mr-2"></i> Scanner SAST
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
};