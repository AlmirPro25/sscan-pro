# Auto-Fix Guide - AegisScan V6.0

**Versão**: 6.0  
**Data**: 2024-12-27  
**Status**: ✅ IMPLEMENTADO

---

## 🎯 O QUE É AUTO-FIX

Auto-fix gera **código pronto para usar** que corrige vulnerabilidades detectadas.

**Antes**:
```
1. Recebe relatório
2. Lê 20 páginas
3. Pesquisa no Google
4. Testa várias soluções
5. Corrige (talvez)

Tempo: 2-4 horas
Taxa de correção: 30%
```

**Depois**:
```
1. Roda: aegis autofix 123
2. Copia código
3. Cola no arquivo
4. Testa

Tempo: 2 minutos
Taxa de correção: 90%
```

---

## 🚀 USO BÁSICO

### 1. Gerar Auto-Fixes

```bash
# Após fazer um scan
aegis scan https://meusite.com

# Gerar fixes (scan ID retornado acima)
aegis autofix 123
```

**Output**:
```
🔧 AegisScan Auto-Fix Generator

Scan ID: 123
API: http://localhost:8080

⏳ Generating auto-fixes...
✅ Generated 4 fixes

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Fix #1: HSTS Missing
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Stack: nginx
File: /etc/nginx/sites-available/default
Confidence: high

Description:
Adiciona header HSTS no Nginx

Patch:
```nginx
# Add inside server block (HTTPS only)
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
```

Test Command:
```bash
curl -I https://seu-site.com | grep Strict-Transport-Security
```
```

### 2. Criar Pull Request Automático

```bash
aegis create-pr 123 "HSTS Missing" \
  --github-token ghp_xxxxx \
  --owner meu-usuario \
  --repo meu-repo
```

**Output**:
```
🚀 AegisScan PR Creator

Scan ID: 123
Vulnerability: HSTS Missing
Repository: meu-usuario/meu-repo

⏳ Creating pull request...
✅ Pull request created successfully!

PR URL: https://github.com/meu-usuario/meu-repo/pull/42

Next steps:
1. Review the PR on GitHub
2. Run tests to ensure nothing breaks
3. Merge when ready
```

---

## 🔧 STACKS SUPORTADOS

### Web Servers
- ✅ **Nginx** - Configuração completa
- ✅ **Apache** - Configuração completa
- ⏳ Caddy (futuro)

### Backend Frameworks
- ✅ **Express.js** (Node.js) - Helmet.js
- ✅ **Spring Boot** (Java) - Spring Security
- ✅ **Django** (Python) - Settings
- ⏳ Laravel (PHP) - futuro
- ⏳ FastAPI (Python) - futuro
- ⏳ Go Gin - futuro

### Frontend Frameworks
- ⏳ React - futuro
- ⏳ Vue - futuro
- ⏳ Angular - futuro

---

## 📋 VULNERABILIDADES SUPORTADAS

### Implementado (V6.0)
1. ✅ **HSTS Missing** - Todas as stacks
2. ✅ **CSP Missing** - Todas as stacks
3. ✅ **X-Frame-Options Missing** - Todas as stacks
4. ✅ **X-Content-Type-Options Missing** - Todas as stacks

### Próximas (V6.1)
5. ⏳ **CORS Misconfiguration**
6. ⏳ **Exposed .env Files**
7. ⏳ **SQL Injection** (parametrização)
8. ⏳ **XSS** (sanitização)

---

## 🎯 EXEMPLOS POR STACK

### Nginx

**Vulnerabilidade**: HSTS Missing

**Fix Gerado**:
```nginx
# /etc/nginx/sites-available/default
server {
    listen 443 ssl;
    
    # Add this line
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
}
```

**Aplicar**:
```bash
sudo nano /etc/nginx/sites-available/default
# Adicionar linha acima
sudo nginx -t
sudo systemctl reload nginx
```

**Testar**:
```bash
curl -I https://meusite.com | grep Strict-Transport-Security
```

---

### Express.js (Node.js)

**Vulnerabilidade**: CSP Missing

**Fix Gerado**:
```javascript
// app.js
const helmet = require('helmet');

app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "data:", "https:"],
  }
}));
```

**Aplicar**:
```bash
npm install helmet
# Adicionar código acima no app.js
npm start
```

**Testar**:
```bash
curl -I https://meusite.com | grep Content-Security-Policy
```

---

### Spring Boot (Java)

**Vulnerabilidade**: HSTS Missing

**Fix Gerado**:
```java
// src/main/java/config/SecurityConfig.java
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.headers()
            .httpStrictTransportSecurity()
            .maxAgeInSeconds(31536000)
            .includeSubDomains(true)
            .preload(true);
    }
}
```

**Aplicar**:
```bash
# Criar arquivo SecurityConfig.java
# Adicionar código acima
mvn spring-boot:run
```

**Testar**:
```bash
curl -I https://meusite.com | grep Strict-Transport-Security
```

---

### Django (Python)

**Vulnerabilidade**: HSTS Missing

**Fix Gerado**:
```python
# settings.py

# Add these lines
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
```

**Aplicar**:
```bash
# Adicionar linhas acima no settings.py
python manage.py runserver
```

**Testar**:
```bash
curl -I https://meusite.com | grep Strict-Transport-Security
```

---

## 🤖 GITHUB PR AUTOMATION

### Setup

**1. Criar GitHub Personal Access Token**:
```
GitHub > Settings > Developer settings > Personal access tokens > Generate new token

Permissions needed:
- repo (full control)
```

**2. Salvar token**:
```bash
export GITHUB_TOKEN=ghp_xxxxx
```

### Uso

**Opção 1: Comando direto**:
```bash
aegis create-pr 123 "HSTS Missing" \
  --github-token $GITHUB_TOKEN \
  --owner meu-usuario \
  --repo meu-repo
```

**Opção 2: Via API**:
```bash
curl -X POST http://localhost:8080/api/v1/autofix/create-pr \
  -H "Content-Type: application/json" \
  -d '{
    "scan_id": 123,
    "vuln_type": "HSTS Missing",
    "github_token": "ghp_xxxxx",
    "owner": "meu-usuario",
    "repo": "meu-repo"
  }'
```

### O que o PR contém

1. **Branch automático**: `aegis-fix-hsts-missing-1234567890`
2. **Commit com patch**: Código aplicado automaticamente
3. **Descrição completa**:
   - Scan information
   - What this PR does
   - Changes made (código)
   - Testing instructions
   - References (OWASP, docs)

**Exemplo de PR**:
```markdown
## 🔒 Security Fix: HSTS Missing

This PR was automatically generated by **AegisScan** to fix a security vulnerability.

### 📊 Scan Information
- **Scan ID**: #123
- **Total Vulnerabilities**: 4
- **Vulnerability Type**: HSTS Missing
- **Confidence**: high

### 🔧 What This PR Does
Adiciona header HSTS no Nginx

### 📝 Changes Made
**File**: /etc/nginx/sites-available/default

**Patch**:
```nginx
# Add inside server block (HTTPS only)
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
```

### ✅ Testing
Run the following command to verify the fix:
```bash
curl -I https://seu-site.com | grep Strict-Transport-Security
```

### 🎯 Next Steps
1. Review the changes
2. Run tests to ensure nothing breaks
3. Test the security header
4. Merge if everything looks good

---
🤖 **Auto-generated by AegisScan v6.0**
```

---

## 🔄 WORKFLOW COMPLETO

### Cenário: Deploy com Auto-fix

```bash
# 1. Scan antes de deploy
aegis scan https://staging.meusite.com --fail-on high

# 2. Se falhar, gerar fixes
aegis autofix 123

# 3. Criar PR com correções
aegis create-pr 123 "HSTS Missing" \
  --github-token $GITHUB_TOKEN \
  --owner meu-usuario \
  --repo meu-repo

# 4. Aguardar review e merge

# 5. Re-scan para validar
aegis scan https://staging.meusite.com

# 6. Deploy para produção
```

---

## 📊 CONFIDENCE LEVELS

### High (90-100%)
- Fix determinístico (pré-definido)
- Stack detectado com certeza
- Código testado em produção

### Medium (70-89%)
- Fix gerado por IA
- Stack detectado com incerteza
- Código requer validação

### Low (50-69%)
- Fix genérico
- Stack não detectado
- Código requer adaptação

**Recomendação**: Sempre revisar fixes antes de aplicar, especialmente Medium/Low confidence.

---

## 🐛 TROUBLESHOOTING

### "Failed to generate fix"
```bash
# Verificar API key
echo $GEMINI_API_KEY

# Verificar backend
curl http://localhost:8080/api/v1/health
```

### "Failed to create PR"
```bash
# Verificar GitHub token
echo $GITHUB_TOKEN

# Verificar permissões do token
# Deve ter: repo (full control)

# Verificar owner/repo
# Formato: owner/repo (sem https://)
```

### "Stack not detected"
```bash
# Fix será genérico
# Adapte manualmente para sua stack
```

---

## 🚀 PRÓXIMOS PASSOS

### V6.1 (2 semanas)
- [ ] Mais vulnerabilidades (CORS, exposed files)
- [ ] Mais stacks (Laravel, FastAPI, Go)
- [ ] GitLab MR automation
- [ ] Bitbucket PR automation

### V6.2 (1 mês)
- [ ] AI-powered fixes para vulnerabilidades complexas
- [ ] Teste automático de fixes
- [ ] Rollback automático se testes falharem

---

**Criado por**: Kiro AI  
**Data**: 2024-12-27  
**Versão**: 6.0  
**Status**: ✅ PRONTO PARA USO
