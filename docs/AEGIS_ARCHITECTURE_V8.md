# AEGIS - Autonomous Security Orchestrator
## Arquitetura v8.0 - Central Intelligence with Human-in-the-Loop Governance

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        AEGIS SECURITY PLATFORM                               │
│                    "Autonomous Security Orchestrator"                        │
│                         with Security Brain Memory                           │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                           FRONTEND (React + Vite)                            │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────────────────┐│
│  │  Dashboard  │ │ Code Scanner│ │ Advanced    │ │   ORCHESTRATOR VIEW     ││
│  │   Monitor   │ │   (SAST)    │ │   Scan      │ │  ┌─────────────────────┐││
│  └─────────────┘ └─────────────┘ └─────────────┘ │  │   AI Chat Central   │││
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ │  │   ───────────────   │││
│  │    SCA      │ │ Correlation │ │   History   │ │  │ • Policy Violations│││
│  │  Analysis   │ │   Engine    │ │    Vault    │ │  │ • Pending Approvals│││
│  └─────────────┘ └─────────────┘ └─────────────┘ │  │ • Thinking Log     │││
│                                                   │  │ • Tool Execution   │││
│                                                   │  │ • Memory Insights  │││
│                                                   │  └─────────────────────┘││
│                                                   └─────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         BACKEND (Go + Gin)                                   │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                    CENTRAL INTELLIGENCE ORCHESTRATOR                   │  │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────────┐│  │
│  │  │  PLANNER (AI)   │  │    EXECUTOR     │  │    POLICY ENGINE        ││  │
│  │  │  ─────────────  │  │  ─────────────  │  │  ─────────────────────  ││  │
│  │  │ • Gemini API    │  │ • Tool Runner   │  │ • Plan Validation       ││  │
│  │  │ • Function Call │──│ • HTTP Calls    │──│ • Approval Gates        ││  │
│  │  │ • Plan Creation │  │ • Result Parse  │  │ • Path/URL Guards       ││  │
│  │  │ • Reasoning     │  │ • Error Handle  │  │ • Environment Control   ││  │
│  │  │ • Memory-Aware  │  │ • Schema Valid  │  │ • Registry Validation   ││  │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────────────┘│  │
│  │                                                                        │  │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────────┐│  │
│  │  │  META ANALYZER  │  │ SECURITY MEMORY │  │    TOOL REGISTRY        ││  │
│  │  │  ─────────────  │  │  (Brain)        │  │  ─────────────────────  ││  │
│  │  │ • Weaknesses    │  │  ─────────────  │  │ • 38 Tools Metadata     ││  │
│  │  │ • Coverage Gaps │  │ • Vuln History  │  │ • Risk Levels           ││  │
│  │  │ • Maturity Score│  │ • Target Memory │  │ • Schema Validation     ││  │
│  │  │ • Action Items  │  │ • Pattern Detect│  │ • HITL Requirements     ││  │
│  │  │ • Trend Analysis│  │ • Insights Gen  │  │ • Impact Classification ││  │
│  │  │                 │  │ • Learning Store│  │ • Execution Time Est    ││  │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────────────┘│  │
│  │                                                                        │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │  │
│  │  │                      AUDIT LOGGER                                │  │  │
│  │  │  • Action Trail • Thinking Log • Explainability • Compliance    │  │  │
│  │  └─────────────────────────────────────────────────────────────────┘  │  │
│  │                                                                        │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │  │
│  │  │                 DECISION INTELLIGENCE LAYER (v8.4)               │  │  │
│  │  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌─────────┐ │  │  │
│  │  │  │ Risk Score   │ │  Approval    │ │   Policy     │ │Feedback │ │  │  │
│  │  │  │ Calculator   │ │   Tokens     │ │  Versioning  │ │  Loop   │ │  │  │
│  │  │  │ (0-100)      │ │ (Scoped)     │ │ (Diff+Hist)  │ │(Learn)  │ │  │  │
│  │  │  └──────────────┘ └──────────────┘ └──────────────┘ └─────────┘ │  │  │
│  │  └─────────────────────────────────────────────────────────────────┘  │  │
│  │                                                                        │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │  │
│  │  │                   SECURITY HARDENING (v8.5)                      │  │  │
│  │  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌─────────┐ │  │  │
│  │  │  │ CORS Secure  │ │  API Key     │ │   Input      │ │  DoS    │ │  │  │
│  │  │  │ (Allowlist)  │ │  Protection  │ │  Validation  │ │ Prevent │ │  │  │
│  │  │  └──────────────┘ └──────────────┘ └──────────────┘ └─────────┘ │  │  │
│  │  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐             │  │  │
│  │  │  │ Secure       │ │   Audit      │ │    Path      │             │  │  │
│  │  │  │ Headers      │ │   Logger     │ │  Traversal   │             │  │  │
│  │  │  └──────────────┘ └──────────────┘ └──────────────┘             │  │  │
│  │  └─────────────────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                         38 TOOLS (8 Categories)                         ││
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐      ││
│  │  │ SCANNING │ │ BROWSER  │ │ DATABASE │ │ ANALYSIS │ │  REPORT  │      ││
│  │  │   (10)   │ │   (7)    │ │   (4)    │ │   (4)    │ │   (3)    │      ││
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘      ││
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐                                ││
│  │  │ AUTOFIX  │ │ UTILITY  │ │  MEMORY  │                                ││
│  │  │   (2)    │ │   (4)    │ │   (4)    │                                ││
│  │  └──────────┘ └──────────┘ └──────────┘                                ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                         SCANNER MODULES                                  ││
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐      ││
│  │  │   SAST   │ │   SCA    │ │   IAC    │ │ LICENSE  │ │TYPOSQUAT │      ││
│  │  │ Code Scan│ │ Deps CVE │ │ Docker/K8│ │ GPL/AGPL │ │ Detector │      ││
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘      ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                      AI MODULES                                          ││
│  │  ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐        ││
│  │  │ DAST+SAST        │ │ AI Report        │ │ AutoFix          │        ││
│  │  │ Correlator       │ │ Generator        │ │ Generator        │        ││
│  │  └──────────────────┘ └──────────────────┘ └──────────────────┘        ││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      WORKER (Node.js + Playwright)                           │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                         DAST ENGINE                                      ││
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐      ││
│  │  │   XSS    │ │   SQLi   │ │   Auth   │ │   SSL    │ │  Secrets │      ││
│  │  │  Tester  │ │  Tester  │ │  Tester  │ │ Analyzer │ │ Detector │      ││
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘      ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                      ADVANCED MODULES                                    ││
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐                   ││
│  │  │ Infra    │ │Subdomain │ │Reputation│ │  Auth    │                   ││
│  │  │ Scanner  │ │ Enum     │ │ Check    │ │  Scan    │                   ││
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘                   ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                    BROWSER CONTROL (Orchestrator)                        ││
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐      ││
│  │  │ Navigate │ │Screenshot│ │Contextual│ │  Click   │ │   Fill   │      ││
│  │  │          │ │          │ │Screenshot│ │          │ │          │      ││
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘      ││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           DATA LAYER                                         │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐          │
│  │    SQLite DB     │  │   IndexedDB      │  │  In-Memory       │          │
│  │  (Backend)       │  │  (Frontend)      │  │  (Sessions)      │          │
│  │  • Scans         │  │  • Local Cache   │  │  • Approvals     │          │
│  │  • Reports       │  │  • Offline       │  │  • Memory        │          │
│  │  • Projects      │  │                  │  │  • Audit Logs    │          │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘          │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Fluxo de Execução (Two-Caller Architecture)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        TWO-CALLER EXECUTION FLOW                             │
└─────────────────────────────────────────────────────────────────────────────┘

  USER                PLANNER (AI)              POLICY              EXECUTOR
   │                      │                       │                     │
   │  "Audite site X"     │                       │                     │
   │─────────────────────>│                       │                     │
   │                      │                       │                     │
   │                      │ 1. Cria PLANO         │                     │
   │                      │    Intent: Auditoria  │                     │
   │                      │    Tools: [scan_web,  │                     │
   │                      │            scan_infra]│                     │
   │                      │    Reasoning: ...     │                     │
   │                      │                       │                     │
   │                      │ 2. Valida Plano       │                     │
   │                      │──────────────────────>│                     │
   │                      │                       │                     │
   │                      │      ✓ Plano OK       │                     │
   │                      │<──────────────────────│                     │
   │                      │                       │                     │
   │                      │ 3. Function Call      │                     │
   │                      │    scan_website(url)  │                     │
   │                      │                       │                     │
   │                      │ 4. Valida Tool Call   │                     │
   │                      │──────────────────────>│                     │
   │                      │                       │                     │
   │                      │      ✓ Tool OK        │                     │
   │                      │<──────────────────────│                     │
   │                      │                       │                     │
   │                      │ 5. Executa            │                     │
   │                      │───────────────────────────────────────────>│
   │                      │                       │                     │
   │                      │                       │      Resultado      │
   │                      │<───────────────────────────────────────────│
   │                      │                       │                     │
   │                      │ 6. Analisa Resultado  │                     │
   │                      │    Próximo passo...   │                     │
   │                      │                       │                     │
   │   Resposta Final     │                       │                     │
   │<─────────────────────│                       │                     │
   │                      │                       │                     │
```

## Ferramentas Disponíveis (38 total)

### Scanning (10)
| Tool | Descrição | Risco |
|------|-----------|-------|
| scan_website | DAST completo | medium |
| scan_code | SAST código-fonte | low |
| scan_dependencies | CVEs em deps | low |
| scan_infrastructure | Portas, SSL, Cloud | medium |
| scan_subdomains | Enumeração | medium |
| scan_reputation | Blacklists | low |
| scan_authenticated | Login/IDOR | high ⚠️ |
| scan_iac | Docker/K8s/Terraform | low |
| scan_licenses | GPL/AGPL | low |
| scan_typosquatting | Pacotes maliciosos | low |

### Browser (7)
| Tool | Descrição | Risco |
|------|-----------|-------|
| navigate_to | Navegar URL | low |
| take_screenshot | Screenshot simples | low |
| take_contextual_screenshot | Screenshot + DOM + metadata | low |
| click_element | Clicar elemento | medium |
| fill_input | Preencher input | medium |
| get_page_content | Obter HTML | low |
| execute_javascript | Executar JS | high ⚠️ |

### Database (4)
| Tool | Descrição | Risco |
|------|-----------|-------|
| query_scan_history | Histórico de scans | low |
| get_scan_details | Detalhes de scan | low |
| get_project_data | Dados de projeto | low |
| list_projects | Listar projetos | low |

### Analysis (5)
| Tool | Descrição | Risco |
|------|-----------|-------|
| correlate_dast_sast | Correlação DAST+SAST | low |
| analyze_attack_surface | Superfície de ataque | medium |
| analyze_system_weaknesses | Meta-análise de fraquezas | low |
| get_maturity_score | Score de maturidade | low |
| get_coverage_gaps | Gaps de cobertura | low |

### Report (3)
| Tool | Descrição | Risco |
|------|-----------|-------|
| generate_ai_report | Relatório AI | low |
| generate_pdf | PDF do scan | low |
| compare_scans | Comparar scans | low |

### AutoFix (2)
| Tool | Descrição | Risco |
|------|-----------|-------|
| generate_autofix | Gerar correções | low |
| create_pull_request | Criar PR | high ⚠️ |

### Utility (4)
| Tool | Descrição | Risco |
|------|-----------|-------|
| get_system_status | Status dos serviços | low |
| get_dashboard_stats | Estatísticas | low |
| get_audit_logs | Logs de auditoria | low |
| get_pending_approvals | Aprovações pendentes | low |

### Memory (5)
| Tool | Descrição | Risco |
|------|-----------|-------|
| remember_vulnerability | Registrar vuln | low |
| query_memory | Consultar memória | low |
| get_security_insights | Gerar insights | low |
| get_memory_stats | Stats da memória | low |
| record_learning | Registrar aprendizado | low |

## Tool Registry

O sistema agora possui um **Tool Registry** centralizado com metadados estendidos:

```go
type ToolMetadata struct {
    Name          string      // Nome da ferramenta
    Description   string      // Descrição
    Category      string      // Categoria
    RiskLevel     string      // low, medium, high, critical
    RequiresHITL  bool        // Human-in-the-loop
    ImpactLevel   string      // read-only, write, destructive
    ExecutionTime string      // fast (<1s), medium (<30s), slow (>30s)
    Schema        *ToolSchema // Validação de argumentos
    Tags          []string    // Tags para busca
}
```

### Validação de Argumentos
Antes de executar qualquer ferramenta, o sistema valida:
- Campos obrigatórios presentes
- Tipos de dados corretos
- Valores dentro de enums permitidos
- Padrões de URL/path válidos

## Security Memory (Brain)

O sistema possui memória de longo prazo que:

1. **Registra vulnerabilidades** encontradas
2. **Detecta padrões** recorrentes
3. **Gera insights** para o Planner
4. **Influencia decisões** do AI

### Fluxo de Memória
```
Scan → Vulnerabilidade → Memory.Record() → Pattern Detection → Insights
                                                    ↓
                                            Planner.buildSystemPrompt()
                                                    ↓
                                            AI recebe contexto histórico
```

## Policy Engine

### Guardrails Implementados
- ✅ Plano obrigatório antes de execução
- ✅ Validação de URLs permitidas
- ✅ Bloqueio de paths sensíveis
- ✅ Controle por ambiente (lab/staging/prod)
- ✅ Gate de aprovação para ferramentas de alto risco
- ✅ Audit trail completo

### Paths Bloqueados
```
C:\Windows
C:\Program Files
/etc
/var
/usr
/root
~/.ssh
~/.aws
~/.config
```

## Próximos Passos (Roadmap)

### Fase 2.1 - Multi-Agent
- [ ] Agent especializado em Recon
- [ ] Agent especializado em Exploit Reasoning
- [ ] Agent especializado em Defense Architecture
- [ ] Chief Orchestrator coordenando agentes

### Fase 2.2 - Persistência
- [ ] Memória em banco de dados
- [ ] Indexação semântica de vulnerabilidades
- [ ] Histórico de decisões do AI

### Fase 2.3 - SOC Autônomo
- [ ] Execução paralela de scans
- [ ] Score de maturidade por sistema
- [ ] Alertas automáticos
- [ ] Integração com SIEM

---

**Versão**: 8.5  
**Data**: 2025-12-27  
**Status**: Production-Ready with Security Hardening

## Changelog v8.5 - Security Hardening

### CORS Seguro
- Removido `AllowOrigins: ["*"]` com `AllowCredentials: true` (inválido por spec)
- Allowlist dinâmica baseada em ambiente (dev/staging/prod)
- Configurável via `AEGIS_ALLOWED_ORIGINS` env var

### API Key Protection
- API keys do frontend bloqueadas em produção
- Hash de keys em logs (nunca expõe key completa)
- Função `security.GetAPIKey()` centralizada

### Input Validation
- `ValidateScanID()` - Valida e parseia IDs numéricos
- `ValidateURL()` - Valida formato e tamanho de URLs
- `ValidateSessionID()` - Valida formato UUID
- `ValidateTokenID()` - Valida formato de tokens
- `ValidatePath()` - Proteção contra path traversal

### DoS Prevention
- `ContentLimits` - Limites configuráveis para conteúdo
- `TruncateContent()` - Trunca conteúdo antes de processar
- PDF limitado a 500 linhas (configurável)
- Report content limitado a 100KB

### Security Middlewares
- `SecureHeaders()` - X-Frame-Options, X-Content-Type-Options, CSP
- `AuditMiddleware()` - Log de todas as requisições
- `RequestValidator()` - Valida Content-Length e Content-Type

### Audit Logging
- `AuditEntry` com timestamp, IP, method, path, status, duration
- `AuditLogger` com rotação automática (max 10k entries)
- Request ID para correlação

### Path Traversal Protection
- Detecção de padrões `..`, `%2e%2e`, etc
- Bloqueio de paths sensíveis (`/etc`, `C:\Windows`, `.ssh`, etc)

### Novo Módulo
- `backend/security/security.go` - Módulo centralizado de segurança

## Changelog v8.4 - Decision Intelligence Layer

### Risk Score Numérico (0-100)
- `RiskCalculator` com breakdown detalhado:
  - BaseRisk (0-40): Risco inerente da ferramenta
  - ContextRisk (0-30): Ambiente, target, domínios
  - MemoryRisk (0-20): Padrões históricos de vulnerabilidades
  - ArgumentRisk (0-10): Dados sensíveis nos argumentos
- Níveis: low (<40), medium (40-59), high (60-79), critical (80+)
- Recomendações automáticas por nível

### Approval Tokens (Delegação Segura)
- Tokens com escopo, tempo limite e máximo de execuções
- `AllowedTools`: Lista de ferramentas permitidas
- `MaxRiskScore`: Score máximo permitido
- `MaxExecutions`: Limite de usos
- Revogação com audit trail

### Policy Versioning
- Histórico completo de alterações de política
- Diff entre versões com classificação de impacto
- Snapshots para rollback
- Audit trail de quem alterou

### Planner Feedback Loop
- `ExecutionFeedback` registra resultado de cada execução
- Métricas: steps executados, bloqueados, falhos
- `PlannerInsights` com:
  - Taxa de sucesso
  - Ferramentas mais bloqueadas
  - Violações comuns
  - Recomendações automáticas

### Novos Endpoints
- `POST /orchestrator/risk/calculate` - Calcular risk score
- `POST /orchestrator/tokens` - Criar approval token
- `POST /orchestrator/tokens/:token_id/validate` - Validar token
- `POST /orchestrator/tokens/:token_id/revoke` - Revogar token
- `GET /orchestrator/tokens` - Listar tokens ativos
- `GET /orchestrator/policy/history` - Histórico de políticas
- `POST /orchestrator/policy/compare` - Comparar versões
- `GET /orchestrator/planner/insights` - Insights do planner
- `GET /orchestrator/feedback/:execution_id` - Feedback de execução

## Changelog v8.3

### Middleware por RiskLevel
- Timeout diferenciado por nível de risco (60s-180s)
- Retry automático apenas para low/medium risk
- Logging level configurável por risco

### Dry-Run Mode
- `POST /orchestrator/dry-run` - Simula execução sem executar
- Análise de risco do plano completo
- Detecção de ferramentas bloqueadas
- Estimativa de tempo

### Execution Graph ID
- Cada execução gera `execution_id` único
- `parent_step` para trace de dependências
- Suporte a replay e auditoria

### Novos Endpoints
- `POST /orchestrator/dry-run` - Simulação de plano
- `POST /orchestrator/execute-plan` - Execução com graph ID

## Changelog v8.2

### Executor Refatorado
- Handler Map substitui switch gigante (escalável)
- Typed Args para ferramentas críticas (type safety)
- ExecutionID e ParentStep para trace completo

### Policy Engine Robusto
- RiskLevel enforcement real
- MaxRiskLevel configurável
- IsPrivileged para sessões elevadas
- SetEnvironment/SetMaxRiskLevel/SetPrivileged

### Novos Endpoints
- `GET /orchestrator/registry` - Export completo do registry
- `GET /orchestrator/policy` - Status da política
- `POST /orchestrator/policy` - Configurar política
- `GET /orchestrator/memory/insights` - Insights da memória

### 39 Ferramentas Totais
- 10 Scanning, 8 Browser, 4 Database, 5 Analysis
- 3 Report, 2 Autofix, 2 Utility, 5 Memory

## Changelog v8.1

### Planner Aprimorado
- Two-Caller Architecture formalizada (Planner → Policy → Executor)
- Plano estruturado JSON obrigatório antes de execução
- Memory Integration: insights influenciam decisões do AI
- ExecutionSummary com métricas de execução

### Policy Engine Robusto
- Validação de schema antes de execução
- HITL (Human-in-the-Loop) enforcement real
- Bloqueio por risk level e environment
- Audit trail completo

### Nova Ferramenta: take_forensic_screenshot
- Captura evidência forense completa
- Inclui: viewport, full-page, DOM, console, network, cookies, storage
- Ideal para pentest e análise de segurança

### 39 Ferramentas Totais
- 10 Scanning, 8 Browser, 4 Database, 5 Analysis
- 3 Report, 2 Autofix, 2 Utility, 5 Memory
