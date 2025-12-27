# CLI e CI/CD Integration - AegisScan

**Versão**: 5.0  
**Data**: 2024-12-27  
**Status**: ✅ IMPLEMENTADO

---

## 🎯 OBJETIVO

Transformar AegisScan de "ferramenta boa" para "indispensável no dia a dia" através de:
1. ✅ CLI para uso local e CI/CD
2. ✅ Integração com GitHub Actions, GitLab CI, Jenkins
3. ✅ Bloqueio de deploy em caso de vulnerabilidades
4. ✅ Relatórios automáticos em PRs

---

## 📦 COMPONENTES

### 1. CLI (`cli/aegis.go`)
- Scan via linha de comando
- Fail conditions configuráveis
- Output em Markdown ou JSON
- Integração com CI/CD

### 2. GitHub Actions (`.github/workflows/aegis-scan.yml`)
- Scan automático em push/PR
- Comentário automático em PRs
- Upload de relatórios como artifacts

### 3. GitLab CI (`.gitlab-ci.yml`)
- Pipeline de segurança
- Artifacts e reports
- Fail on vulnerabilities

### 4. Jenkins (`Jenkinsfile`)
- Pipeline declarativo
- Notificações por email
- Publicação de relatórios HTML

### 5. Docker Compose CI (`docker-compose.ci.yml`)
- Ambiente isolado para CI
- Health checks
- Volumes para relatórios

---

## 🚀 INSTALAÇÃO

### Opção 1: Build Local
```bash
cd cli
go build -o aegis aegis.go

# Windows
move aegis.exe C:\Windows\System32\

# Linux/Mac
chmod +x aegis
sudo mv aegis /usr/local/bin/
```

### Opção 2: Docker
```bash
docker build -t aegis-cli:latest -f cli/Dockerfile cli/
```

### Opção 3: Go Install
```bash
go install github.com/seu-usuario/aegis-cli@latest
```

---

## 💻 USO DO CLI

### Scan Básico
```bash
aegis scan https://meusite.com
```

### Scan com Fail Condition
```bash
# Falha se encontrar HIGH ou CRITICAL
aegis scan https://meusite.com --fail-on high

# Falha apenas em CRITICAL
aegis scan https://meusite.com --fail-on critical

# Falha em qualquer vulnerabilidade
aegis scan https://meusite.com --fail-on low
```

### Output Customizado
```bash
# Salvar em Markdown
aegis scan https://meusite.com --output report.md

# Salvar em JSON
aegis scan https://meusite.com --output report.json --json
```

### API Customizada
```bash
# Usar API remota
aegis scan https://meusite.com --api https://aegis.empresa.com

# Timeout customizado
aegis scan https://meusite.com --timeout 600
```

### Modelo AI Customizado
```bash
aegis scan https://meusite.com \
  --model gemini-3-flash-preview \
  --api-key AIzaSy...
```

---

## 🔧 INTEGRAÇÃO CI/CD

### GitHub Actions

**1. Adicionar Secrets**
```
Settings > Secrets and variables > Actions > New repository secret

GEMINI_API_KEY: sua_chave_aqui
TARGET_URL: https://staging.meusite.com (opcional)
```

**2. Criar Workflow**
```bash
# Arquivo já criado em .github/workflows/aegis-scan.yml
git add .github/workflows/aegis-scan.yml
git commit -m "Add AegisScan security check"
git push
```

**3. Resultado**
- ✅ Scan automático em cada push/PR
- ✅ Comentário em PR com resumo
- ✅ Relatório completo em artifacts
- ✅ Build falha se vulnerabilidades HIGH+

**Exemplo de Comentário em PR**:
```markdown
## 🛡️ AegisScan Security Report

Target: https://staging.meusite.com
Score: 75/100

Vulnerabilities Found:
  🟠 HIGH: 2
  🟡 MEDIUM: 5

❌ Build failed: Found vulnerabilities at or above 'high' severity

[Full report in artifacts]
```

---

### GitLab CI

**1. Adicionar Variables**
```
Settings > CI/CD > Variables > Add variable

GEMINI_API_KEY: sua_chave_aqui (Protected, Masked)
TARGET_URL: https://staging.meusite.com
```

**2. Criar Pipeline**
```bash
# Arquivo já criado em .gitlab-ci.yml
git add .gitlab-ci.yml
git commit -m "Add AegisScan security pipeline"
git push
```

**3. Resultado**
- ✅ Stage de segurança no pipeline
- ✅ Artifacts com relatório
- ✅ Pipeline falha se vulnerabilidades HIGH+

---

### Jenkins

**1. Adicionar Credentials**
```
Manage Jenkins > Credentials > Add Credentials

ID: gemini-api-key
Secret: sua_chave_aqui
```

**2. Criar Job**
```bash
# Arquivo já criado em Jenkinsfile
# Criar novo Pipeline Job apontando para Jenkinsfile
```

**3. Resultado**
- ✅ Pipeline com stages paralelos
- ✅ Relatório HTML publicado
- ✅ Email em caso de falha

---

### Docker Compose (CI Local)

**1. Configurar Environment**
```bash
export GEMINI_API_KEY=sua_chave_aqui
export TARGET_URL=https://meusite.com
```

**2. Executar**
```bash
docker-compose -f docker-compose.ci.yml up --abort-on-container-exit
```

**3. Resultado**
- ✅ Ambiente isolado
- ✅ Relatório em `./reports/report.md`
- ✅ Exit code 1 se vulnerabilidades

---

## 📊 FAIL CONDITIONS

### Níveis de Severidade
```
CRITICAL (9.0-10.0) → Exposição de credenciais, RCE
HIGH     (7.0-8.9) → SQL Injection, XSS persistente
MEDIUM   (4.0-6.9) → Headers faltantes, CSRF
LOW      (0.1-3.9) → Information disclosure menor
```

### Estratégias Recomendadas

**Produção (main branch)**:
```bash
--fail-on high
```
Bloqueia deploy se HIGH ou CRITICAL

**Staging (develop branch)**:
```bash
--fail-on medium
```
Mais rigoroso para catch early

**Feature Branches**:
```bash
--fail-on critical
```
Permite desenvolvimento, bloqueia apenas críticos

**Scan Informativo (não bloqueia)**:
```bash
# Sem --fail-on
aegis scan https://meusite.com --output report.md
```

---

## 🎯 EXEMPLOS REAIS

### Exemplo 1: E-commerce
```yaml
# .github/workflows/security.yml
name: Security Check

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Security Scan
        run: |
          aegis scan https://staging.loja.com \
            --fail-on high \
            --output security-report.md
        env:
          GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
      
      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: security-report.md
```

### Exemplo 2: SaaS Multi-tenant
```yaml
# .gitlab-ci.yml
security-scan:
  stage: security
  script:
    - |
      for tenant in tenant1 tenant2 tenant3; do
        aegis scan https://${tenant}.saas.com \
          --fail-on high \
          --output report-${tenant}.md
      done
  artifacts:
    paths:
      - report-*.md
```

### Exemplo 3: Microservices
```groovy
// Jenkinsfile
pipeline {
    stages {
        stage('Security Scan') {
            parallel {
                stage('API Gateway') {
                    steps {
                        sh 'aegis scan https://api.empresa.com --fail-on high'
                    }
                }
                stage('Auth Service') {
                    steps {
                        sh 'aegis scan https://auth.empresa.com --fail-on critical'
                    }
                }
                stage('Payment Service') {
                    steps {
                        sh 'aegis scan https://payment.empresa.com --fail-on high'
                    }
                }
            }
        }
    }
}
```

---

## 🐛 TROUBLESHOOTING

### CLI não encontra API
```bash
# Verificar se backend está rodando
curl http://localhost:8080/api/v1/health

# Usar API remota
aegis scan https://site.com --api https://aegis.empresa.com
```

### Timeout em scans grandes
```bash
# Aumentar timeout (padrão: 300s)
aegis scan https://site.com --timeout 600
```

### API Key não configurada
```bash
# Opção 1: Environment variable
export GEMINI_API_KEY=sua_chave_aqui

# Opção 2: Flag
aegis scan https://site.com --api-key sua_chave_aqui
```

### Build não falha em vulnerabilidades
```bash
# Verificar exit code
echo $?  # Linux/Mac
echo %ERRORLEVEL%  # Windows

# Deve ser 1 se vulnerabilidades encontradas
```

---

## 📈 MÉTRICAS E MONITORAMENTO

### Coletar Métricas
```bash
# Salvar em JSON para análise
aegis scan https://site.com --json --output metrics.json

# Extrair score
cat metrics.json | jq '.scan.score'

# Contar vulnerabilidades
cat metrics.json | jq '.vulnerabilities | length'
```

### Dashboard (Futuro)
```bash
# Enviar para sistema de métricas
aegis scan https://site.com --json | \
  curl -X POST https://metrics.empresa.com/aegis \
  -H "Content-Type: application/json" \
  -d @-
```

---

## 🚀 PRÓXIMOS PASSOS

### Fase 1: CLI Básico ✅
- [x] Scan via CLI
- [x] Fail conditions
- [x] Output customizado
- [x] Integração CI/CD

### Fase 2: Auto-fix (Próximo)
- [ ] Geração de patches
- [ ] Pull Request automático
- [ ] Sugestões de código

### Fase 3: Timeline (Futuro)
- [ ] Histórico de vulnerabilidades
- [ ] Trending de score
- [ ] Alertas proativos

---

## 💡 DICAS

### Performance
- Use `--timeout` adequado para sites grandes
- Cache de scans (futuro)
- Scan paralelo de múltiplos alvos

### Segurança
- Nunca commite API keys no código
- Use secrets do CI/CD
- Rotacione keys periodicamente

### Manutenção
- Atualize CLI regularmente
- Monitore logs do backend
- Revise fail conditions por projeto

---

**Criado por**: Kiro AI  
**Data**: 2024-12-27  
**Versão**: 5.0  
**Status**: ✅ PRONTO PARA USO
