# AEGIS - Autonomous Security Orchestrator 🛡️

<div align="center">

![Version](https://img.shields.io/badge/version-8.5-blue)
![Status](https://img.shields.io/badge/status-production--ready-green)
![License](https://img.shields.io/badge/license-MIT-yellow)

**Plataforma de segurança autônoma com inteligência artificial**

*SOC automatizado que pensa, age, aprende e se governa*

</div>

---

## 🎯 O que é o AEGIS?

AEGIS é um **Security Operations Center (SOC) autônomo** que combina:

- 🔍 **Scanners de segurança** (DAST, SAST, SCA, IAC)
- 🤖 **Inteligência Artificial** (Gemini) para análise e relatórios
- 🧠 **Orchestrator autônomo** que planeja e executa ações
- 📚 **Memória de longo prazo** que aprende com cada scan
- 🔐 **Governança** com aprovações e controle de risco

---

## ✨ Capacidades

### Scanners de Segurança

| Tipo | Descrição |
|------|-----------|
| **DAST** | Testa aplicações web em execução (XSS, SQLi, Auth, SSL) |
| **SAST** | Analisa código-fonte (secrets, injection, eval) |
| **SCA** | Analisa dependências (CVEs, licenças, typosquatting) |
| **IAC** | Analisa infraestrutura (Docker, K8s, Terraform) |
| **Infrastructure** | Portas, SSL, cloud misconfigs |
| **Subdomain** | Enumeração de subdomínios |
| **Reputation** | Blacklists e reputação |

### Inteligência Artificial

- **Relatórios AI**: Análise profunda com Gemini
- **Chat contextual**: Perguntas sobre vulnerabilidades
- **Multimodal**: Analisa screenshots + dados
- **Tom profissional**: Sanitização de linguagem

### Central Intelligence Orchestrator

- **Planner**: AI que raciocina e cria planos de ação
- **Executor**: Executa ferramentas de forma controlada
- **Policy Engine**: Valida ações contra regras de segurança
- **Memory**: Lembra vulnerabilidades, detecta padrões

### Decision Intelligence Layer

- **Risk Score (0-100)**: Cálculo numérico de risco
- **Approval Tokens**: Delegação segura com escopo
- **Policy Versioning**: Histórico de mudanças
- **Feedback Loop**: Aprende com execuções

### AutoFix

- Gera correções de código automaticamente
- Cria Pull Requests no GitHub

---

## 🚀 Quick Start

### 1. Backend
```bash
cd backend
go build -o aegis-backend.exe .
./aegis-backend.exe
```

### 2. Worker (Playwright)
```bash
cd backend/worker
npm install
node server.js
```

### 3. Frontend
```bash
cd aegisscan-pro
npm install
npm run dev
```

### 4. Configurar API Key
```bash
# Windows
set GEMINI_API_KEY=sua_api_key

# Linux/Mac
export GEMINI_API_KEY=sua_api_key
```

---

## 📦 Arquitetura

```
┌─────────────────────────────────────────────────────────────┐
│                      FRONTEND (React)                        │
│   Dashboard │ Code Scanner │ SCA │ Correlation │ Orchestrator│
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      BACKEND (Go)                            │
│  ┌─────────────────────────────────────────────────────────┐│
│  │              CENTRAL INTELLIGENCE ORCHESTRATOR           ││
│  │   Planner (AI) → Policy Engine → Executor → Memory      ││
│  └─────────────────────────────────────────────────────────┘│
│  ┌─────────────────────────────────────────────────────────┐│
│  │   39 TOOLS │ SCANNERS │ AI MODULES │ SECURITY HARDENING ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   WORKER (Node.js + Playwright)              │
│   DAST Engine │ Browser Control │ Screenshots │ Auth Scan   │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔧 API Endpoints

### Scans
```bash
POST /api/v1/scan                    # DAST scan
POST /api/v1/scan-local              # SAST scan
POST /api/v1/sca/full                # SCA completo
POST /api/v1/scan/advanced           # Scan avançado
```

### AI
```bash
POST /api/v1/ai/report               # Gerar relatório AI
POST /api/v1/ai/chat                 # Chat contextual
POST /api/v1/ai/enhanced-report      # Relatório combinado
```

### Orchestrator
```bash
POST /api/v1/orchestrator/chat       # Chat com orchestrator
GET  /api/v1/orchestrator/tools      # Listar ferramentas
POST /api/v1/orchestrator/execute    # Executar ferramenta
POST /api/v1/orchestrator/dry-run    # Simular plano
```

### Decision Layer
```bash
POST /api/v1/orchestrator/risk/calculate    # Calcular risco
POST /api/v1/orchestrator/tokens            # Criar token
GET  /api/v1/orchestrator/planner/insights  # Insights do planner
```

---

## 🛡️ Security Hardening (v8.5)

- ✅ CORS seguro (allowlist, não wildcard)
- ✅ API keys protegidas (bloqueadas em produção)
- ✅ Input validation (scan_id, URL, session_id)
- ✅ DoS prevention (limites de conteúdo)
- ✅ Security headers (X-Frame-Options, CSP, etc)
- ✅ Audit logging (todas as requisições)
- ✅ Path traversal protection

---

## 📊 39 Ferramentas Disponíveis

| Categoria | Ferramentas |
|-----------|-------------|
| **Scanning** | scan_website, scan_code, scan_dependencies, scan_infrastructure, scan_subdomains, scan_reputation, scan_authenticated, scan_iac, scan_licenses, scan_typosquatting |
| **Browser** | navigate_to, take_screenshot, take_contextual_screenshot, click_element, fill_input, get_page_content, execute_javascript, take_forensic_screenshot |
| **Database** | query_scan_history, get_scan_details, get_project_data, list_projects |
| **Analysis** | correlate_dast_sast, analyze_attack_surface, analyze_system_weaknesses, get_maturity_score, get_coverage_gaps |
| **Report** | generate_ai_report, generate_pdf, compare_scans |
| **AutoFix** | generate_autofix, create_pull_request |
| **Memory** | remember_vulnerability, query_memory, get_security_insights, get_memory_stats, record_learning |

---

## 🔌 CI/CD Integration

### GitHub Actions
```yaml
- name: Security Scan
  run: aegis scan ${{ secrets.TARGET_URL }} --fail-on high
```

### GitLab CI
```yaml
security:
  script:
    - aegis scan ${TARGET_URL} --fail-on high
```

### Jenkins
```groovy
sh 'aegis scan ${TARGET_URL} --fail-on high'
```

---

## 📚 Documentação

- [Arquitetura v8](docs/AEGIS_ARCHITECTURE_V8.md)
- [AutoFix Guide](docs/AUTOFIX_GUIDE.md)
- [CLI & CI/CD](docs/CLI_CICD_INTEGRATION.md)
- [Changelogs](docs/changelogs/)

---

## 🏗️ Stack Tecnológico

| Componente | Tecnologia |
|------------|------------|
| Backend | Go (Gin) + GORM + SQLite |
| Frontend | React + Vite + TailwindCSS |
| Worker | Node.js + Playwright |
| AI | Google Gemini |
| CLI | Go + Cobra |

---

## ⚖️ Licença

MIT License - Use com responsabilidade.

---

## 🤝 Contribuindo

Pull requests são bem-vindos! Para mudanças maiores, abra uma issue primeiro.

---

<div align="center">

**AEGIS v8.5** | Autonomous Security Orchestrator

*Criado com 🛡️ para segurança real*

</div>
