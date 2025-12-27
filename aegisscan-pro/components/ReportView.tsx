import React, { useState } from 'react';
import { ScanResult, ScreenState } from '../types';
import { NetworkTopology } from './NetworkTopology';
import { VulnerabilityDistribution, StatusCodeDistribution } from './Visualizations';
import { AssetExplorer } from './AssetExplorer';
import { apiService } from '../services/apiService';
import { marked } from 'marked';
import html2canvas from 'html2canvas';
import { jsPDF } from 'jspdf';

interface ReportViewProps {
    scan: ScanResult;
    onBack: () => void;
    model: string;
    apiKey: string;
}

type ReportTab = 'overview' | 'network' | 'assets' | 'security' | 'ai';

export const ReportView: React.FC<ReportViewProps> = ({ scan, onBack, model, apiKey }) => {
    const [activeTab, setActiveTab] = useState<ReportTab>('overview');

    // AI State
    const [aiReport, setAiReport] = useState<string | null>(null);
    const [aiLoading, setAiLoading] = useState(false);
    const [chatMessages, setChatMessages] = useState<{ role: 'user' | 'assistant', content: string }[]>([]);
    const [chatInput, setChatInput] = useState('');
    const [isChatLoading, setIsChatLoading] = useState(false);

    const handleExportPdf = async () => {
        const content = document.getElementById('report-container');
        if (!content) return;

        try {
            const canvas = await html2canvas(content, { scale: 2, useCORS: true, backgroundColor: '#f8fafc', logging: false });
            const imgData = canvas.toDataURL('image/jpeg', 0.9);
            const pdf = new jsPDF('p', 'mm', 'a4');
            const pdfWidth = pdf.internal.pageSize.getWidth();
            const pdfHeight = pdf.internal.pageSize.getHeight();
            const imgHeight = canvas.height * pdfWidth / canvas.width;

            let heightLeft = imgHeight;
            let position = 0;

            pdf.addImage(imgData, 'JPEG', 0, position, pdfWidth, imgHeight);
            heightLeft -= pdfHeight;

            while (heightLeft >= 0) {
                position = heightLeft - imgHeight;
                pdf.addPage();
                pdf.addImage(imgData, 'JPEG', 0, position, pdfWidth, imgHeight);
                heightLeft -= pdfHeight;
            }
            pdf.save(`AEGIS_LOG_${scan.id}_${Date.now()}.pdf`);
        } catch (e) {
            console.error(e);
            alert("Export Failed");
        }
    };

    const handleGenerateAiReport = async () => {
        if (!scan.id) return;
        setAiLoading(true);
        try {
            const res = await apiService.generateAIReport(scan.id, model, apiKey);
            setAiReport(res.content);
        } catch (e: any) {
            alert(e.message);
        } finally {
            setAiLoading(false);
        }
    };

    const handleChatSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!chatInput.trim() || !scan.id) return;
        const msg = chatInput;
        setChatInput('');
        setChatMessages(prev => [...prev, { role: 'user', content: msg }]);
        setIsChatLoading(true);
        try {
            const res = await apiService.sendAIChatMessage(scan.id, msg, model, apiKey);
            setChatMessages(prev => [...prev, { role: 'assistant', content: res.message }]);
        } catch (e) {
            setChatMessages(prev => [...prev, { role: 'assistant', content: "LINK OFFLINE." }]);
        } finally {
            setIsChatLoading(false);
        }
    };

    return (
        <div className="animate-[fadeIn_0.5s_ease-out] pb-32" id="report-container">
            {/* Header - Resumo Principal */}
            <div className="cyber-card rounded-3xl p-8 mb-8 border-slate-200">
                <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-8">
                    <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-3 mb-4">
                            <button onClick={onBack} className="glass-btn px-3 py-1.5 rounded-lg text-[9px] font-black uppercase tracking-widest flex items-center gap-2 hover:bg-slate-100 transition-colors">
                                <i className="fas fa-chevron-left"></i> Voltar
                            </button>
                            <div className="h-4 w-px bg-slate-200"></div>
                            <span className="text-[10px] font-black text-slate-400 uppercase tracking-[0.2em]">Relatório #{scan.id}</span>
                        </div>
                        <h2 className="text-2xl md:text-3xl font-black text-slate-900 tracking-tight mb-3 truncate w-full">{scan.target}</h2>
                        <div className="flex flex-wrap gap-2">
                            <div className="px-3 py-1 bg-slate-900 text-white text-[9px] font-black rounded-full uppercase tracking-widest flex items-center gap-2">
                                <i className="fas fa-clock opacity-50"></i> {new Date(scan.timestamp).toLocaleString('pt-BR')}
                            </div>
                            <div className="px-3 py-1 bg-indigo-50 text-indigo-600 border border-indigo-100 text-[9px] font-black rounded-full uppercase tracking-widest flex items-center gap-2">
                                <i className="fas fa-network-wired"></i> {scan.endpoints?.length || 0} Endpoints
                            </div>
                        </div>
                    </div>

                    <div className="flex items-center gap-6 self-end md:self-center">
                        <div className="flex flex-col items-end">
                            <div className="text-[10px] text-slate-400 font-black uppercase tracking-[0.2em] mb-1">Score de Segurança</div>
                            <div className={`text-5xl font-black data-value drop-shadow-sm ${scan.score >= 80 ? 'text-emerald-500' : scan.score >= 50 ? 'text-amber-500' : 'text-red-500'}`}>
                                {scan.score}<span className="text-xl opacity-30">%</span>
                            </div>
                            <div className={`text-[10px] font-bold mt-1 ${scan.score >= 80 ? 'text-emerald-600' : scan.score >= 50 ? 'text-amber-600' : 'text-red-600'}`}>
                                {scan.score >= 80 ? '✓ Excelente' : scan.score >= 50 ? '⚠ Atenção Necessária' : '✗ Crítico'}
                            </div>
                        </div>
                        <button onClick={handleExportPdf} className="w-14 h-14 rounded-2xl bg-slate-900 text-white flex items-center justify-center hover:bg-indigo-600 transition-all shadow-xl group" title="Exportar PDF">
                            <i className="fas fa-file-export text-lg group-hover:scale-110 transition-transform"></i>
                        </button>
                    </div>
                </div>
            </div>

            {/* Tabs de Navegação */}
            <div className="flex bg-slate-200/30 p-1 rounded-2xl mb-8 backdrop-blur-sm border border-slate-200 overflow-x-auto no-scrollbar">
                {[
                    { id: 'overview', label: 'Visão Geral', icon: 'crosshairs' },
                    { id: 'network', label: 'Endpoints', icon: 'project-diagram' },
                    { id: 'assets', label: 'Assets', icon: 'box-open' },
                    { id: 'security', label: 'Vulnerabilidades', icon: 'biohazard' },
                    { id: 'ai', label: 'Análise IA', icon: 'microchip' },
                ].map(tab => (
                    <button
                        key={tab.id}
                        onClick={() => setActiveTab(tab.id as ReportTab)}
                        className={`flex-1 min-w-[120px] px-4 py-3 rounded-xl text-[10px] font-black uppercase tracking-[0.1em] flex items-center justify-center gap-2 transition-all ${activeTab === tab.id ? 'bg-white text-indigo-600 shadow-sm border border-slate-200' : 'text-slate-500 hover:text-slate-900'}`}
                    >
                        <i className={`fas fa-${tab.icon}`}></i> {tab.label}
                    </button>
                ))}
            </div>


            {/* Content */}
            <div className="space-y-6">
                {activeTab === 'overview' && (
                    <div className="space-y-6">
                        {/* Resumo Rápido */}
                        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                            {[
                                { label: 'Tempo de Resposta', value: scan.performance?.timing ? (scan.performance.timing.loadEventEnd - scan.performance.timing.navigationStart) + 'ms' : 'N/A', icon: 'bolt', color: 'indigo', desc: 'Latência do servidor' },
                                { label: 'Certificado SSL', value: scan.security_audit?.ssl_info?.valid ? 'Válido' : 'Inválido', icon: 'lock', color: scan.security_audit?.ssl_info?.valid ? 'emerald' : 'red', desc: scan.security_audit?.ssl_info?.valid ? 'Conexão segura' : 'Atenção necessária' },
                                { label: 'Tecnologia', value: scan.tech?.techStack?.[0] || 'Detectando...', icon: 'server', color: 'blue', desc: 'Stack principal' },
                                { label: 'Cookies', value: scan.tech?.cookies || 0, icon: 'cookie', color: 'amber', desc: 'Tokens de sessão' }
                            ].map((stat, i) => (
                                <div key={i} className="cyber-card p-5 rounded-2xl shadow-sm group border-slate-200 hover:border-slate-300 transition-all">
                                    <div className="flex items-center gap-2 mb-3">
                                        <div className={`w-8 h-8 rounded-lg bg-${stat.color}-50 flex items-center justify-center`}>
                                            <i className={`fas fa-${stat.icon} text-${stat.color}-500 text-sm`}></i>
                                        </div>
                                        <div className="text-[9px] font-black text-slate-400 uppercase tracking-wide">{stat.label}</div>
                                    </div>
                                    <div className={`text-lg font-black text-slate-800`}>{stat.value}</div>
                                    <div className="text-[10px] text-slate-400 mt-1">{stat.desc}</div>
                                </div>
                            ))}
                        </div>

                        {/* Gráficos */}
                        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                            <div className="lg:col-span-2 cyber-card rounded-2xl p-6 border-slate-200">
                                <h4 className="text-[10px] font-black text-slate-400 uppercase tracking-[0.2em] mb-6">Distribuição de Status HTTP</h4>
                                <p className="text-[10px] text-slate-400 mb-4">Códigos de resposta dos endpoints descobertos</p>
                                <StatusCodeDistribution scan={scan} />
                            </div>
                            <div className="cyber-card rounded-2xl p-6 border-slate-200">
                                <h4 className="text-[10px] font-black text-slate-400 uppercase tracking-[0.2em] mb-6">Severidade das Ameaças</h4>
                                <p className="text-[10px] text-slate-400 mb-4">Classificação por nível de risco</p>
                                <VulnerabilityDistribution scan={scan} />
                            </div>
                        </div>
                    </div>
                )}

                {activeTab === 'network' && (
                    <div className="space-y-6">
                        <div className="cyber-card rounded-2xl p-6 border-slate-200">
                            <div className="flex justify-between items-center mb-6">
                                <div>
                                    <h4 className="text-sm font-black text-slate-800 mb-1">Mapa de Rede</h4>
                                    <p className="text-[10px] text-slate-400">Visualização da topologia de endpoints</p>
                                </div>
                                <div className="px-3 py-1 bg-indigo-50 text-indigo-600 rounded-full text-[9px] font-black uppercase">Grafo Interativo</div>
                            </div>
                            <div className="h-[400px] bg-slate-50/50 rounded-2xl border border-slate-100 p-4">
                                <NetworkTopology scan={scan} />
                            </div>
                        </div>
                        <div className="cyber-card rounded-2xl overflow-hidden border-slate-200">
                            <div className="p-5 bg-slate-900 border-b border-slate-800 flex justify-between items-center">
                                <div>
                                    <h4 className="text-sm font-black text-white mb-1">Endpoints Descobertos</h4>
                                    <p className="text-[10px] text-slate-400">Rotas interceptadas durante o scan</p>
                                </div>
                                <span className="text-[9px] font-black text-indigo-400 bg-indigo-400/10 px-3 py-1.5 rounded-lg">{scan.endpoints?.length || 0} rotas</span>
                            </div>
                            <div className="max-h-96 overflow-y-auto custom-scroll bg-white">
                                {scan.endpoints.map((ep, i) => (
                                    <div key={i} className="flex items-center justify-between p-4 border-b border-slate-100 hover:bg-slate-50 transition-colors group">
                                        <div className="flex items-center gap-4 overflow-hidden">
                                            <span className={`px-2 py-1 rounded text-[9px] font-black w-14 text-center ${ep.method === 'GET' ? 'bg-blue-500 text-white' : ep.method === 'POST' ? 'bg-emerald-500 text-white' : 'bg-amber-500 text-white'}`}>{ep.method}</span>
                                            <span className="text-xs font-mono text-slate-600 truncate group-hover:text-indigo-600 transition-colors">{ep.url}</span>
                                        </div>
                                        <div className="flex items-center gap-4">
                                            <span className={`data-value text-sm font-black ${ep.status >= 400 ? 'text-red-500' : 'text-emerald-500'}`}>{ep.status}</span>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>
                )}

                {activeTab === 'assets' && (
                    <div className="cyber-card rounded-2xl overflow-hidden border-slate-200">
                        <AssetExplorer scan={scan} />
                    </div>
                )}

                {activeTab === 'security' && (
                    <div className="space-y-6">
                        {/* Status Geral */}
                        <div className={`p-6 rounded-2xl border-2 flex items-center gap-6 ${scan.security_audit?.vulnerabilities?.total ? 'bg-red-50 border-red-200' : 'bg-emerald-50 border-emerald-200'}`}>
                            <div className={`w-14 h-14 rounded-2xl flex items-center justify-center text-xl shadow-lg ${scan.security_audit?.vulnerabilities?.total ? 'bg-red-500 text-white' : 'bg-emerald-500 text-white'}`}>
                                <i className={`fas fa-${scan.security_audit?.vulnerabilities?.total ? 'exclamation-triangle' : 'shield-check'}`}></i>
                            </div>
                            <div>
                                <h4 className={`font-black text-xl mb-1 ${scan.security_audit?.vulnerabilities?.total ? 'text-red-800' : 'text-emerald-800'}`}>
                                    {scan.security_audit?.vulnerabilities?.total ? 'Vulnerabilidades Detectadas' : 'Nenhuma Vulnerabilidade Crítica'}
                                </h4>
                                <p className={`text-sm ${scan.security_audit?.vulnerabilities?.total ? 'text-red-600' : 'text-emerald-600'}`}>
                                    {scan.security_audit?.vulnerabilities?.total 
                                        ? `Foram encontradas ${scan.security_audit.vulnerabilities.total} vulnerabilidades que precisam de atenção.`
                                        : 'O scan não identificou vulnerabilidades de alta prioridade nesta análise.'}
                                </p>
                            </div>
                        </div>

                        {/* Lista de Vulnerabilidades */}
                        {scan.security_audit?.vulnerabilities?.total > 0 && (
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                {[
                                    ...(scan.security_audit?.vulnerabilities?.xss || []),
                                    ...(scan.security_audit?.vulnerabilities?.sqli || []),
                                    ...(scan.security_audit?.vulnerabilities?.auth || [])
                                ].map((v, i) => (
                                    <div key={i} className="cyber-card p-6 rounded-2xl border-slate-200 hover:border-red-200 transition-all">
                                        <div className="flex justify-between items-start mb-4">
                                            <div className="flex items-center gap-3">
                                                <span className={`px-2 py-1 text-[9px] font-black rounded uppercase ${
                                                    v.severity === 'CRITICAL' ? 'bg-red-100 text-red-600 border border-red-200' :
                                                    v.severity === 'HIGH' ? 'bg-orange-100 text-orange-600 border border-orange-200' :
                                                    v.severity === 'MEDIUM' ? 'bg-amber-100 text-amber-600 border border-amber-200' :
                                                    'bg-blue-100 text-blue-600 border border-blue-200'
                                                }`}>{v.severity}</span>
                                                <h5 className="font-black text-slate-800 text-sm">{v.type}</h5>
                                            </div>
                                        </div>
                                        <div className="space-y-3">
                                            <div className="p-3 bg-slate-50 rounded-xl border border-slate-100">
                                                <div className="text-[9px] font-bold text-slate-400 uppercase mb-1">Localização</div>
                                                <div className="font-mono text-[11px] text-slate-700 truncate">{v.location}</div>
                                            </div>
                                            <div>
                                                <div className="text-[9px] font-bold text-indigo-500 uppercase mb-1">Recomendação</div>
                                                <p className="text-xs text-slate-600 leading-relaxed">{v.recommendation}</p>
                                            </div>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        )}

                        {/* Estado vazio */}
                        {(!scan.security_audit?.vulnerabilities?.total || scan.security_audit.vulnerabilities.total === 0) && (
                            <div className="text-center py-12 cyber-card rounded-2xl border-slate-200">
                                <div className="w-16 h-16 bg-emerald-100 rounded-2xl flex items-center justify-center mx-auto mb-4">
                                    <i className="fas fa-check-circle text-2xl text-emerald-500"></i>
                                </div>
                                <h4 className="font-black text-slate-800 mb-2">Análise Concluída</h4>
                                <p className="text-sm text-slate-500">Nenhuma vulnerabilidade crítica foi identificada neste scan.</p>
                            </div>
                        )}
                    </div>
                )}

                {activeTab === 'ai' && (
                    <div className="space-y-6">
                        {!aiReport ? (
                            <div className="text-center py-20 cyber-card rounded-2xl border-slate-200 bg-white relative overflow-hidden">
                                <div className="absolute inset-0 bg-gradient-to-b from-indigo-50/30 to-transparent"></div>
                                <div className="relative z-10 max-w-md mx-auto px-6">
                                    <div className="w-20 h-20 bg-indigo-600 text-white rounded-2xl flex items-center justify-center mx-auto mb-6 shadow-xl">
                                        {aiLoading ? <i className="fas fa-sync fa-spin text-2xl"></i> : <i className="fas fa-brain text-2xl"></i>}
                                    </div>
                                    <h3 className="text-xl font-black text-slate-900 mb-3">Análise com Inteligência Artificial</h3>
                                    <p className="text-sm text-slate-500 mb-8">
                                        Gere um relatório detalhado usando o Gemini AI para interpretar os dados do scan e fornecer recomendações personalizadas.
                                    </p>
                                    <button
                                        onClick={handleGenerateAiReport}
                                        disabled={aiLoading}
                                        className="w-full py-4 bg-indigo-600 text-white rounded-xl font-bold text-sm uppercase tracking-wide shadow-lg hover:bg-indigo-700 transition-all active:scale-95 disabled:opacity-50 flex items-center justify-center gap-3"
                                    >
                                        {aiLoading ? (
                                            <><i className="fas fa-circle-notch fa-spin"></i> Gerando Relatório...</>
                                        ) : (
                                            <><i className="fas fa-sparkles"></i> Gerar Relatório IA</>
                                        )}
                                    </button>
                                </div>
                            </div>
                        ) : (
                            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                                {/* Relatório IA */}
                                <div className="lg:col-span-2 cyber-card rounded-2xl overflow-hidden flex flex-col border-slate-200 max-h-[600px]">
                                    <div className="p-4 bg-slate-900 border-b border-slate-800 flex justify-between items-center">
                                        <div className="flex items-center gap-3">
                                            <i className="fas fa-microchip text-indigo-400"></i>
                                            <h3 className="font-bold text-white text-sm">Relatório de Inteligência</h3>
                                        </div>
                                        <button onClick={() => setAiReport(null)} className="text-[10px] font-bold text-slate-400 uppercase hover:text-white transition-colors px-3 py-1 rounded bg-slate-800">
                                            <i className="fas fa-redo mr-1"></i> Regenerar
                                        </button>
                                    </div>
                                    <div className="p-6 flex-1 overflow-y-auto custom-scroll bg-white">
                                        <div className="prose prose-sm max-w-none prose-slate leading-relaxed ai-content" dangerouslySetInnerHTML={{ __html: marked.parse(aiReport) as string }}></div>
                                    </div>
                                </div>

                                {/* Chat com IA */}
                                <div className="lg:col-span-1">
                                    <div className="bg-slate-900 rounded-2xl flex flex-col h-[600px] shadow-xl border border-slate-800 overflow-hidden">
                                        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
                                            <div className="flex items-center gap-2">
                                                <span className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse"></span>
                                                <h3 className="text-sm font-bold text-white">Chat com Aegis IA</h3>
                                            </div>
                                            <i className="fas fa-comment-dots text-slate-600"></i>
                                        </div>
                                        <div className="flex-1 overflow-y-auto p-4 space-y-4 custom-scroll">
                                            {chatMessages.length === 0 && (
                                                <div className="text-center py-8">
                                                    <i className="fas fa-comments text-2xl text-slate-700 mb-3"></i>
                                                    <p className="text-xs text-slate-500">Faça perguntas sobre o relatório</p>
                                                </div>
                                            )}
                                            {chatMessages.map((msg, i) => (
                                                <div key={i} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                                                    <div className={`max-w-[85%] p-3 rounded-xl text-xs leading-relaxed ${msg.role === 'user' ? 'bg-indigo-600 text-white' : 'bg-slate-800 text-slate-300 border border-slate-700'}`}>
                                                        {msg.role === 'assistant' ? <div className="ai-chat-content" dangerouslySetInnerHTML={{ __html: marked.parse(msg.content) as string }} /> : msg.content}
                                                    </div>
                                                </div>
                                            ))}
                                            {isChatLoading && (
                                                <div className="flex items-center gap-2 text-[10px] font-bold text-indigo-400 animate-pulse">
                                                    <i className="fas fa-circle-notch fa-spin"></i> Processando...
                                                </div>
                                            )}
                                        </div>
                                        <div className="p-4 bg-slate-800/50 border-t border-slate-800">
                                            <form onSubmit={handleChatSubmit} className="flex gap-2">
                                                <input
                                                    type="text"
                                                    value={chatInput}
                                                    onChange={e => setChatInput(e.target.value)}
                                                    className="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-3 py-2.5 text-xs text-white focus:outline-none focus:border-indigo-500 placeholder:text-slate-600 transition-all"
                                                    placeholder="Pergunte sobre vulnerabilidades..."
                                                />
                                                <button type="submit" className="w-10 h-10 bg-indigo-600 text-white rounded-lg hover:bg-indigo-500 transition-all flex items-center justify-center">
                                                    <i className="fas fa-paper-plane text-sm"></i>
                                                </button>
                                            </form>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
};