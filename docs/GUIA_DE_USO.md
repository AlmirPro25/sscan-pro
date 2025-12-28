# AEGIS - Guia de Uso Completo

## 🚀 Iniciando o Sistema

### Passo 1: Configurar API Key do Gemini

```bash
# Windows (CMD)
set GEMINI_API_KEY=sua_api_key_aqui

# Windows (PowerShell)
$env:GEMINI_API_KEY="sua_api_key_aqui"

# Linux/Mac
export GEMINI_API_KEY=sua_api_key_aqui
```

> Obtenha sua API key em: https://makersuite.google.com/app/apikey

---

### Passo 2: Iniciar o Backend (Go)

```bash
cd backend
go build -o aegis-backend.exe .
./aegis-backend.exe
```

**Saída esperada:**
```
🛡️ Aegis Backend Running on :8080
🔒 Rate Limiting: 10 requests/minute per IP
```

---

### Passo 3: Iniciar o Worker (Playwright)

**Em outro terminal:**

```bash
cd backend/worker
npm install
node server.js
```

**Saída esperada:**
```
🚀 Aegis Worker running on port 3001
```

---

### Passo 4: Iniciar o Frontend (React)

**Em outro terminal:**

```bash
cd aegisscan-pro
npm install
npm run dev
```

**Saída esperada:**
```
VITE v5.x.x ready in xxx ms
➜ Local: http://localhost:3000/
```

---

## 🖥️ Usando a Interface Web

Acesse: **http://localhost:3000**

### Tela Principal (Dashboard)

Mostra estatísticas gerais:
- Total de scans realizados
- Vulnerabilidades encontradas
- Score médio de segurança

---

## 🔍 Funcionalidades

### 1. DAST Scan (Scan de Website)

**O que faz:** Testa aplicações web em execução

**Como usar:**
1. Clique em "Scan" no menu
2. Digite a URL (ex: `https://exemplo.com`)
3. Clique em "Iniciar Scan"
4. Aguarde 30-60 segundos

**Resultado:**
- Score de segurança (0-100)
- Lista de vulnerabilidades (XSS, SQLi, etc)
- Screenshot da página
- Headers de segurança

---

### 2. SAST Scan (Análise de Código)

**O que faz:** Analisa código-fonte estático

**Como usar:**
1. Clique em "Code Scanner" no menu
2. Selecione a pasta do projeto
3. Clique em "Analisar"

**Detecta:**
- Hardcoded secrets (API keys, senhas)
- SQL Injection
- Eval/exec perigosos
- Imports inseguros

---

### 3. SCA (Análise de Dependências)

**O que faz:** Analisa bibliotecas e pacotes

**Como usar:**
1. Clique em "SCA" no menu
2. Selecione a pasta com package.json/requirements.txt/go.mod
3. Clique em "Analisar"

**Detecta:**
- CVEs conhecidas
- Licenças problemáticas (GPL, AGPL)
- Typosquatting (pacotes maliciosos)
- Vulnerabilidades em Docker/K8s

---

### 4. Correlação DAST + SAST

**O que faz:** Cruza vulnerabilidades de runtime com código-fonte

**Como usar:**
1. Clique em "Correlation" no menu
2. Selecione um projeto que tenha DAST e SAST
3. Clique em "Correlacionar"

**Resultado:**
- Qual linha de código causa a vulnerabilidade
- Attack chains completas
- Impacto em compliance (OWASP, PCI-DSS)

---

### 5. Relatório AI

**O que faz:** Gera relatório profissional com IA

**Como usar:**
1. Após um scan, clique em "Gerar Relatório AI"
2. Aguarde 10-30 segundos
3. Relatório em Markdown aparece na tela

**Inclui:**
- Resumo executivo
- Vulnerabilidades detalhadas
- Recomendações de correção
- Análise de risco

---

### 6. Chat com AI

**O que faz:** Conversa sobre o scan

**Como usar:**
1. Após gerar relatório, clique em "Chat"
2. Faça perguntas como:
   - "Qual a vulnerabilidade mais crítica?"
   - "Como corrigir o XSS encontrado?"
   - "Esse site é seguro para produção?"

---

### 7. Orchestrator (Chat Central)

**O que faz:** Agente autônomo que planeja e executa ações

**Como usar:**
1. Clique em "Orchestrator" no menu
2. Digite comandos em linguagem natural:
   - "Faça uma auditoria completa do site example.com"
   - "Analise o código da pasta /meu-projeto"
   - "Quais vulnerabilidades encontramos essa semana?"

**O AI vai:**
1. Entender seu pedido
2. Criar um plano de ação
3. Executar as ferramentas necessárias
4. Retornar o resultado

---

### 8. AutoFix

**O que faz:** Gera correções de código automaticamente

**Como usar:**
1. Após um scan com vulnerabilidades
2. Clique em "AutoFix"
3. Veja as correções sugeridas
4. Clique em "Criar PR" para enviar ao GitHub

---

## 💻 Usando via CLI

### Instalação

```bash
cd cli
go build -o aegis.exe aegis.go

# Windows - copiar para PATH
copy aegis.exe C:\Windows\System32\

# Linux/Mac
chmod +x aegis
sudo mv aegis /usr/local/bin/
```

### Comandos

```bash
# Scan básico
aegis scan https://exemplo.com

# Scan com fail condition (para CI/CD)
aegis scan https://exemplo.com --fail-on high

# Ver histórico
aegis history

# Gerar relatório
aegis report 123

# AutoFix
aegis autofix 123

# Criar PR
aegis create-pr 123 "HSTS Missing" --github-token TOKEN --owner user --repo repo
```

---

## 🔌 Usando via API

### Health Check
```bash
curl http://localhost:8080/api/v1/health
```

### DAST Scan
```bash
curl -X POST http://localhost:8080/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://exemplo.com"}'
```

### SAST Scan
```bash
curl -X POST http://localhost:8080/api/v1/scan-local \
  -H "Content-Type: application/json" \
  -d '{"path": "C:/meu-projeto"}'
```

### Relatório AI
```bash
curl -X POST http://localhost:8080/api/v1/ai/report \
  -H "Content-Type: application/json" \
  -d '{"scan_id": 1}'
```

### Orchestrator Chat
```bash
curl -X POST http://localhost:8080/api/v1/orchestrator/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Faça uma auditoria do site example.com"}'
```

---

## 📊 Portas do Sistema

| Serviço | Porta | Descrição |
|---------|-------|-----------|
| Backend | 8080 | API principal (Go) |
| Worker | 3001 | Scanner Playwright (Node.js) |
| Frontend | 3000 | Interface web (React) |

---

## 🔧 Troubleshooting

### "GEMINI_API_KEY not configured"
→ Configure a variável de ambiente com sua API key

### "Worker server unreachable"
→ Inicie o worker: `cd backend/worker && node server.js`

### "Scan timeout"
→ O site pode estar lento. Tente novamente ou aumente o timeout.

### "Rate limit exceeded"
→ Aguarde 60 segundos entre scans

---

## 🎯 Casos de Uso

### 1. Auditoria de Site
```
1. Abrir http://localhost:3000
2. Scan → digitar URL → Iniciar
3. Gerar Relatório AI
4. Exportar PDF
```

### 2. Análise de Código Antes de Deploy
```
1. Code Scanner → selecionar pasta
2. Analisar
3. Corrigir vulnerabilidades encontradas
4. Re-analisar até limpo
```

### 3. CI/CD Pipeline
```bash
# No GitHub Actions / GitLab CI
aegis scan $URL --fail-on high
# Pipeline falha se encontrar vulnerabilidades HIGH ou CRITICAL
```

### 4. Auditoria Completa com AI
```
1. Orchestrator
2. "Faça uma auditoria completa do site X e do código Y"
3. AI planeja e executa tudo automaticamente
4. Resultado consolidado
```

---

## 📚 Documentação Adicional

- [Arquitetura v8](AEGIS_ARCHITECTURE_V8.md)
- [AutoFix Guide](AUTOFIX_GUIDE.md)
- [CLI & CI/CD](CLI_CICD_INTEGRATION.md)
- [Configuração API Key](CONFIGURACAO_API_KEY.md)

---

**AEGIS v8.5** | Autonomous Security Orchestrator
