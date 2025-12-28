import React, { useState, useRef, useEffect } from 'react';

interface Tool {
    name: string;
    description: string;
    category: string;
    risk_level: string;
    requires_approval: boolean;
}

interface ToolResult {
    tool_name: string;
    success: boolean;
    result: any;
    error?: string;
    duration_ms: number;
}

interface PolicyViolation {
    rule: string;
    description: string;
    severity: string;
    suggestion: string;
}

interface PendingApproval {
    id: string;
    tool_name: string;
    reason: string;
    requested_at: string;
    status: string;
}

interface ExecutionPlan {
    intent: string;
    plan: string[];
    reasoning: string;
}

interface ChatMessage {
    role: 'user' | 'assistant' | 'tool';
    content: string;
    tools_called?: ToolResult[];
    policy_violations?: PolicyViolation[];
    pending_approvals?: PendingApproval[];
    plan?: ExecutionPlan;
    thinking?: string;
    timestamp: Date;
}

interface OrchestratorViewProps {
    onBack: () => void;
}

const API_BASE = 'http://localhost:8080/api/v1';

export const OrchestratorView: React.FC<OrchestratorViewProps> = ({ onBack }) => {
    const [messages, setMessages] = useState<ChatMessage[]>([]);
    const [input, setInput] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [sessionId, setSessionId] = useState<string | null>(null);
    const [tools, setTools] = useState<Tool[]>([]);
    const [showTools, setShowTools] = useState(false);
    const [showApprovals, setShowApprovals] = useState(false);
    const [pendingApprovals, setPendingApprovals] = useState<PendingApproval[]>([]);
    const [apiKey, setApiKey] = useState(localStorage.getItem('aegis_key') || '');
    const messagesEndRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        loadTools();
        loadPendingApprovals();
        // Add welcome message
        setMessages([{
            role: 'assistant',
            content: `🛡️ **AEGIS Central Intelligence Orchestrator v2.0**

Olá! Sou o orquestrador central de segurança do AEGIS com **Policy Engine** integrado.

## Novidades v2.0:
- ✅ **Plano Obrigatório**: Explico meu raciocínio antes de executar
- 🔐 **Gate de Aprovação**: Ferramentas de alto risco requerem aprovação
- 📊 **Meta-Análise**: Identifico padrões e fraquezas sistêmicas
- 📝 **Audit Trail**: Todas as ações são registradas

## Ferramentas Disponíveis:
- **Scanning**: DAST, SAST, SCA, IAC, Infraestrutura
- **Browser**: Navegação, Screenshots, Interação
- **Database**: Histórico, Projetos, Correlações
- **Analysis**: Meta-análise, Maturidade de Segurança
- **Reports**: Relatórios AI, PDFs, Comparações

**Como posso ajudar?** Alguns exemplos:
- "Faça uma auditoria completa em https://exemplo.com"
- "Analise as fraquezas do sistema"
- "Qual o score de maturidade de segurança?"`,
            timestamp: new Date()
        }]);
    }, []);

    useEffect(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [messages]);

    const loadTools = async () => {
        try {
            const res = await fetch(`${API_BASE}/orchestrator/tools`);
            const data = await res.json();
            setTools(data);
        } catch (e) {
            console.error('Failed to load tools:', e);
        }
    };

    const loadPendingApprovals = async () => {
        try {
            const res = await fetch(`${API_BASE}/orchestrator/approvals`);
            const data = await res.json();
            setPendingApprovals(data || []);
        } catch (e) {
            console.error('Failed to load approvals:', e);
        }
    };

    const approveRequest = async (approvalId: string) => {
        try {
            await fetch(`${API_BASE}/orchestrator/approvals/${approvalId}/approve`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ approved_by: 'user' })
            });
            loadPendingApprovals();
            setMessages(prev => [...prev, {
                role: 'assistant',
                content: `✅ Aprovação ${approvalId} concedida. A ferramenta pode ser executada agora.`,
                timestamp: new Date()
            }]);
        } catch (e) {
            console.error('Failed to approve:', e);
        }
    };

    const denyRequest = async (approvalId: string) => {
        try {
            await fetch(`${API_BASE}/orchestrator/approvals/${approvalId}/deny`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ denied_by: 'user' })
            });
            loadPendingApprovals();
            setMessages(prev => [...prev, {
                role: 'assistant',
                content: `❌ Aprovação ${approvalId} negada.`,
                timestamp: new Date()
            }]);
        } catch (e) {
            console.error('Failed to deny:', e);
        }
    };

    const sendMessage = async () => {
        if (!input.trim() || isLoading) return;

        const userMessage: ChatMessage = {
            role: 'user',
            content: input,
            timestamp: new Date()
        };
        setMessages(prev => [...prev, userMessage]);
        setInput('');
        setIsLoading(true);

        try {
            const res = await fetch(`${API_BASE}/orchestrator/chat`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    session_id: sessionId,
                    message: input,
                    api_key: apiKey
                })
            });

            const data = await res.json();

            if (data.error) {
                setMessages(prev => [...prev, {
                    role: 'assistant',
                    content: `❌ Erro: ${data.error}`,
                    timestamp: new Date()
                }]);
            } else {
                setSessionId(data.session_id);
                
                const assistantMessage: ChatMessage = {
                    role: 'assistant',
                    content: data.message,
                    tools_called: data.tools_called,
                    policy_violations: data.policy_violations,
                    pending_approvals: data.pending_approvals,
                    plan: data.plan,
                    thinking: data.thinking,
                    timestamp: new Date()
                };
                setMessages(prev => [...prev, assistantMessage]);
                
                // Reload pending approvals if any were created
                if (data.pending_approvals?.length > 0) {
                    loadPendingApprovals();
                }
            }
        } catch (e: any) {
            setMessages(prev => [...prev, {
                role: 'assistant',
                content: `❌ Erro de conexão: ${e.message}`,
                timestamp: new Date()
            }]);
        } finally {
            setIsLoading(false);
        }
    };

    const handleKeyPress = (e: React.KeyboardEvent) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    };

    const clearChat = () => {
        setMessages([{
            role: 'assistant',
            content: '🔄 Chat reiniciado. Como posso ajudar?',
            timestamp: new Date()
        }]);
        setSessionId(null);
    };

    const getCategoryColor = (category: string) => {
        const colors: Record<string, string> = {
            scanning: 'bg-blue-100 text-blue-700',
            browser: 'bg-purple-100 text-purple-700',
            database: 'bg-green-100 text-green-700',
            analysis: 'bg-orange-100 text-orange-700',
            report: 'bg-cyan-100 text-cyan-700',
            autofix: 'bg-red-100 text-red-700',
            utility: 'bg-gray-100 text-gray-700'
        };
        return colors[category] || 'bg-gray-100 text-gray-700';
    };

    const getRiskColor = (risk: string) => {
        const colors: Record<string, string> = {
            low: 'text-green-600',
            medium: 'text-yellow-600',
            high: 'text-orange-600',
            critical: 'text-red-600'
        };
        return colors[risk] || 'text-gray-600';
    };

    return (
        <div className="space-y-4">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                    <button onClick={onBack} className="p-2 hover:bg-slate-100 rounded-lg">
                        <i className="fas fa-arrow-left text-slate-600"></i>
                    </button>
                    <div>
                        <h2 className="text-xl font-bold text-slate-800 flex items-center gap-2">
                            <i className="fas fa-brain text-indigo-600"></i>
                            Central Intelligence Orchestrator
                        </h2>
                        <p className="text-sm text-slate-500">Chat com IA que controla todas as ferramentas</p>
                    </div>
                </div>
                <div className="flex items-center gap-2">
                    <button
                        onClick={() => setShowApprovals(!showApprovals)}
                        className={`px-3 py-2 rounded-lg text-sm font-medium transition-all relative ${
                            showApprovals ? 'bg-purple-100 text-purple-700' : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                        }`}
                    >
                        <i className="fas fa-shield-alt mr-2"></i>
                        Aprovações
                        {pendingApprovals.length > 0 && (
                            <span className="absolute -top-1 -right-1 w-5 h-5 bg-red-500 text-white text-[10px] rounded-full flex items-center justify-center">
                                {pendingApprovals.length}
                            </span>
                        )}
                    </button>
                    <button
                        onClick={() => setShowTools(!showTools)}
                        className={`px-3 py-2 rounded-lg text-sm font-medium transition-all ${
                            showTools ? 'bg-indigo-100 text-indigo-700' : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                        }`}
                    >
                        <i className="fas fa-tools mr-2"></i>
                        {tools.length} Tools
                    </button>
                    <button
                        onClick={clearChat}
                        className="px-3 py-2 bg-slate-100 text-slate-600 rounded-lg text-sm font-medium hover:bg-slate-200"
                    >
                        <i className="fas fa-trash mr-2"></i>
                        Limpar
                    </button>
                </div>
            </div>

            <div className="flex gap-4">
                {/* Chat Area */}
                <div className={`flex-1 bg-white rounded-xl shadow-sm border border-slate-200 flex flex-col ${showTools ? 'w-2/3' : 'w-full'}`} style={{ height: 'calc(100vh - 280px)' }}>
                    {/* Messages */}
                    <div className="flex-1 overflow-y-auto p-4 space-y-4">
                        {messages.map((msg, idx) => (
                            <div key={idx} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                                <div className={`max-w-[80%] rounded-xl p-4 ${
                                    msg.role === 'user' 
                                        ? 'bg-indigo-600 text-white' 
                                        : 'bg-slate-100 text-slate-800'
                                }`}>
                                    {msg.role === 'assistant' && (
                                        <div className="flex items-center gap-2 mb-2 text-xs text-slate-500">
                                            <i className="fas fa-robot"></i>
                                            <span>AEGIS AI</span>
                                        </div>
                                    )}
                                    <div className="whitespace-pre-wrap text-sm">
                                        {msg.content}
                                    </div>
                                    
                                    {/* Tool Results */}
                                    {msg.tools_called && msg.tools_called.length > 0 && (
                                        <div className="mt-3 pt-3 border-t border-slate-200 space-y-2">
                                            <div className="text-xs font-medium text-slate-500">
                                                <i className="fas fa-cog mr-1"></i>
                                                Ferramentas executadas:
                                            </div>
                                            {msg.tools_called.map((tool, tidx) => (
                                                <div key={tidx} className={`text-xs p-2 rounded ${
                                                    tool.success ? 'bg-green-50 text-green-700' : 'bg-red-50 text-red-700'
                                                }`}>
                                                    <div className="flex items-center justify-between">
                                                        <span className="font-mono">{tool.tool_name}</span>
                                                        <span>{tool.duration_ms}ms</span>
                                                    </div>
                                                    {tool.error && (
                                                        <div className="mt-1 text-red-600">{tool.error}</div>
                                                    )}
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                    
                                    {/* Policy Violations */}
                                    {msg.policy_violations && msg.policy_violations.length > 0 && (
                                        <div className="mt-3 pt-3 border-t border-slate-200 space-y-2">
                                            <div className="text-xs font-medium text-orange-600">
                                                <i className="fas fa-shield-alt mr-1"></i>
                                                Violações de Política:
                                            </div>
                                            {msg.policy_violations.map((v, vidx) => (
                                                <div key={vidx} className={`text-xs p-2 rounded ${
                                                    v.severity === 'BLOCK' ? 'bg-red-50 text-red-700' : 'bg-yellow-50 text-yellow-700'
                                                }`}>
                                                    <div className="font-medium">{v.rule}</div>
                                                    <div>{v.description}</div>
                                                    <div className="text-[10px] mt-1 opacity-75">💡 {v.suggestion}</div>
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                    
                                    {/* Pending Approvals */}
                                    {msg.pending_approvals && msg.pending_approvals.length > 0 && (
                                        <div className="mt-3 pt-3 border-t border-slate-200 space-y-2">
                                            <div className="text-xs font-medium text-purple-600">
                                                <i className="fas fa-clock mr-1"></i>
                                                Aguardando Aprovação:
                                            </div>
                                            {msg.pending_approvals.map((a, aidx) => (
                                                <div key={aidx} className="text-xs p-2 rounded bg-purple-50 text-purple-700">
                                                    <div className="font-mono">{a.tool_name}</div>
                                                    <div className="text-[10px]">{a.reason}</div>
                                                    <div className="flex gap-2 mt-2">
                                                        <button
                                                            onClick={() => approveRequest(a.id)}
                                                            className="px-2 py-1 bg-green-500 text-white rounded text-[10px] hover:bg-green-600"
                                                        >
                                                            ✓ Aprovar
                                                        </button>
                                                        <button
                                                            onClick={() => denyRequest(a.id)}
                                                            className="px-2 py-1 bg-red-500 text-white rounded text-[10px] hover:bg-red-600"
                                                        >
                                                            ✗ Negar
                                                        </button>
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                    
                                    {/* Thinking (collapsed) */}
                                    {msg.thinking && (
                                        <details className="mt-3 pt-3 border-t border-slate-200">
                                            <summary className="text-xs text-slate-500 cursor-pointer hover:text-slate-700">
                                                <i className="fas fa-brain mr-1"></i>
                                                Ver raciocínio interno
                                            </summary>
                                            <pre className="text-[10px] mt-2 p-2 bg-slate-50 rounded overflow-x-auto whitespace-pre-wrap">
                                                {msg.thinking}
                                            </pre>
                                        </details>
                                    )}
                                    
                                    <div className="text-[10px] mt-2 opacity-60">
                                        {msg.timestamp.toLocaleTimeString()}
                                    </div>
                                </div>
                            </div>
                        ))}
                        
                        {isLoading && (
                            <div className="flex justify-start">
                                <div className="bg-slate-100 rounded-xl p-4">
                                    <div className="flex items-center gap-2 text-slate-500">
                                        <div className="animate-spin w-4 h-4 border-2 border-indigo-600 border-t-transparent rounded-full"></div>
                                        <span className="text-sm">Processando...</span>
                                    </div>
                                </div>
                            </div>
                        )}
                        
                        <div ref={messagesEndRef} />
                    </div>

                    {/* Input */}
                    <div className="p-4 border-t border-slate-200">
                        <div className="flex gap-2">
                            <textarea
                                value={input}
                                onChange={(e) => setInput(e.target.value)}
                                onKeyPress={handleKeyPress}
                                placeholder="Digite sua mensagem... (Enter para enviar)"
                                className="flex-1 px-4 py-3 bg-slate-50 border border-slate-200 rounded-xl resize-none focus:outline-none focus:ring-2 focus:ring-indigo-500 text-sm"
                                rows={2}
                                disabled={isLoading}
                            />
                            <button
                                onClick={sendMessage}
                                disabled={isLoading || !input.trim()}
                                className="px-6 bg-indigo-600 text-white rounded-xl font-medium hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
                            >
                                <i className="fas fa-paper-plane"></i>
                            </button>
                        </div>
                    </div>
                </div>

                {/* Tools Panel */}
                {showTools && (
                    <div className="w-1/3 bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden" style={{ height: 'calc(100vh - 280px)' }}>
                        <div className="p-4 border-b border-slate-200 bg-slate-50">
                            <h3 className="font-bold text-slate-800">
                                <i className="fas fa-toolbox mr-2 text-indigo-600"></i>
                                Ferramentas Disponíveis
                            </h3>
                        </div>
                        <div className="overflow-y-auto p-4 space-y-3" style={{ height: 'calc(100% - 60px)' }}>
                            {tools.map((tool, idx) => (
                                <div key={idx} className="p-3 bg-slate-50 rounded-lg border border-slate-100 hover:border-indigo-200 transition-all">
                                    <div className="flex items-start justify-between">
                                        <div className="font-mono text-sm font-medium text-slate-800">
                                            {tool.name}
                                            {tool.requires_approval && (
                                                <i className="fas fa-lock ml-2 text-orange-500 text-xs" title="Requer aprovação"></i>
                                            )}
                                        </div>
                                        <span className={`text-[10px] px-2 py-0.5 rounded-full ${getCategoryColor(tool.category)}`}>
                                            {tool.category}
                                        </span>
                                    </div>
                                    <p className="text-xs text-slate-500 mt-1 line-clamp-2">
                                        {tool.description}
                                    </p>
                                    <div className={`text-[10px] mt-2 ${getRiskColor(tool.risk_level)}`}>
                                        <i className="fas fa-shield-alt mr-1"></i>
                                        Risco: {tool.risk_level}
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                {/* Approvals Panel */}
                {showApprovals && (
                    <div className="w-1/3 bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden" style={{ height: 'calc(100vh - 280px)' }}>
                        <div className="p-4 border-b border-slate-200 bg-purple-50">
                            <h3 className="font-bold text-purple-800">
                                <i className="fas fa-shield-alt mr-2"></i>
                                Aprovações Pendentes
                            </h3>
                        </div>
                        <div className="overflow-y-auto p-4 space-y-3" style={{ height: 'calc(100% - 60px)' }}>
                            {pendingApprovals.length === 0 ? (
                                <div className="text-center text-slate-400 py-8">
                                    <i className="fas fa-check-circle text-4xl mb-2"></i>
                                    <p className="text-sm">Nenhuma aprovação pendente</p>
                                </div>
                            ) : (
                                pendingApprovals.map((approval, idx) => (
                                    <div key={idx} className="p-3 bg-purple-50 rounded-lg border border-purple-200">
                                        <div className="font-mono text-sm font-medium text-purple-800">
                                            {approval.tool_name}
                                        </div>
                                        <p className="text-xs text-purple-600 mt-1">
                                            {approval.reason}
                                        </p>
                                        <div className="text-[10px] text-purple-400 mt-1">
                                            ID: {approval.id}
                                        </div>
                                        <div className="flex gap-2 mt-3">
                                            <button
                                                onClick={() => approveRequest(approval.id)}
                                                className="flex-1 px-3 py-1.5 bg-green-500 text-white rounded text-xs font-medium hover:bg-green-600 transition-all"
                                            >
                                                <i className="fas fa-check mr-1"></i>
                                                Aprovar
                                            </button>
                                            <button
                                                onClick={() => denyRequest(approval.id)}
                                                className="flex-1 px-3 py-1.5 bg-red-500 text-white rounded text-xs font-medium hover:bg-red-600 transition-all"
                                            >
                                                <i className="fas fa-times mr-1"></i>
                                                Negar
                                            </button>
                                        </div>
                                    </div>
                                ))
                            )}
                        </div>
                    </div>
                )}
            </div>

            {/* Quick Actions */}
            <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-4">
                <div className="text-xs font-medium text-slate-500 mb-3">
                    <i className="fas fa-bolt mr-1"></i>
                    Ações Rápidas
                </div>
                <div className="flex flex-wrap gap-2">
                    {[
                        { label: 'Status do Sistema', cmd: 'Verifique o status do sistema' },
                        { label: 'Histórico de Scans', cmd: 'Mostre o histórico de scans' },
                        { label: 'Listar Projetos', cmd: 'Liste todos os projetos' },
                        { label: 'Meta-Análise', cmd: 'Analise as fraquezas sistêmicas do sistema' },
                        { label: 'Score de Maturidade', cmd: 'Qual o score de maturidade de segurança?' },
                        { label: 'Insights de Segurança', cmd: 'Gere insights de segurança baseados na memória' },
                        { label: 'Stats da Memória', cmd: 'Mostre as estatísticas da memória de segurança' },
                    ].map((action, idx) => (
                        <button
                            key={idx}
                            onClick={() => setInput(action.cmd)}
                            className="px-3 py-1.5 bg-slate-100 text-slate-600 rounded-lg text-xs font-medium hover:bg-indigo-100 hover:text-indigo-700 transition-all"
                        >
                            {action.label}
                        </button>
                    ))}
                </div>
            </div>
        </div>
    );
};
