# 💬 Exemplos de Uso do Chat AI

## Cenário 1: Entendendo Vulnerabilidades

### Usuário:
```
O que significa "CSP ausente" e por que é crítico?
```

### Aegis AI:
```
Content Security Policy (CSP) ausente é uma vulnerabilidade crítica porque:

1. **Sem Proteção contra XSS**: Permite que scripts maliciosos sejam 
   injetados e executados no contexto da sua aplicação.

2. **Vetores de Ataque**:
   - Injeção de código via inputs não sanitizados
   - Scripts inline maliciosos
   - Carregamento de recursos de domínios não confiáveis

3. **Impacto no seu caso**:
   - Score atual: 60/100
   - Aplicação usa Monaco Editor (processa código)
   - Alto risco de XSS stored/reflected

**Recomendação Imediata**:
```http
Content-Security-Policy: default-src 'self'; 
  script-src 'self' https://cdn.tailwindcss.com; 
  frame-ancestors 'none'
```

Isso bloqueia 90% dos ataques XSS comuns.
```

---

## Cenário 2: Priorizando Correções

### Usuário:
```
Tenho budget limitado. Qual vulnerabilidade corrigir primeiro?
```

### Aegis AI:
```
Baseado na análise do scan, priorize nesta ordem:

**🔴 CRÍTICO (Corrigir HOJE)**
1. **CSP ausente** 
   - Custo: ZERO (só adicionar header)
   - Impacto: Bloqueia XSS
   - Tempo: 5 minutos

2. **X-Frame-Options ausente**
   - Custo: ZERO
   - Impacto: Previne clickjacking
   - Tempo: 2 minutos

**🟡 ALTO (Esta semana)**
3. **Server header exposto** (Vercel)
   - Custo: ZERO
   - Impacto: Dificulta fingerprinting
   - Tempo: 5 minutos

**🟢 MÉDIO (Próximo sprint)**
4. **HSTS não configurado**
   - Custo: ZERO
   - Impacto: Força HTTPS
   - Tempo: 10 minutos

**ROI**: 4 vulnerabilidades corrigidas em < 30 minutos, custo zero.
```

---

## Cenário 3: Detalhes Técnicos

### Usuário:
```
Como explorar o endpoint /api/users que você encontrou?
```

### Aegis AI:
```
⚠️ **AVISO ÉTICO**: Só teste em sistemas que você possui ou tem 
autorização explícita.

**Endpoint Detectado**:
```
POST /api/users
Status: 200
Content-Type: application/json
```

**Vetores de Teste**:

1. **Enumeração de Usuários**:
```bash
curl -X POST https://alvo.com/api/users \
  -H "Content-Type: application/json" \
  -d '{"id": 1}'
```

2. **SQL Injection**:
```bash
curl -X POST https://alvo.com/api/users \
  -d '{"id": "1 OR 1=1--"}'
```

3. **NoSQL Injection**:
```json
{"id": {"$ne": null}}
```

4. **IDOR (Insecure Direct Object Reference)**:
```bash
# Testar IDs sequenciais
for i in {1..100}; do
  curl -s "https://alvo.com/api/users/$i"
done
```

**Recomendação de Defesa**:
- Validação de input rigorosa
- Rate limiting (10 req/min)
- Autenticação obrigatória
- Logs de acesso
```

---

## Cenário 4: Contexto de Negócio

### Usuário:
```
Sou CEO não-técnico. Explique o risco em termos de negócio.
```

### Aegis AI:
```
**Resumo Executivo - Análise de Risco**

**Situação Atual**: Score 60/100 (RISCO ALTO)

**Impactos no Negócio**:

💰 **Financeiro**
- Multa LGPD: até R$ 50 milhões (2% faturamento)
- Custo de breach: R$ 1.2M média (IBM Security)
- Perda de clientes: 65% abandonam após vazamento

🏢 **Reputacional**
- Manchetes negativas em mídia
- Perda de confiança do mercado
- Dificuldade em captar investimento

⚖️ **Legal**
- Responsabilidade civil por danos
- Processos de clientes afetados
- Investigação de autoridades (ANPD)

📊 **Operacional**
- Downtime durante ataque: R$ 50k/hora
- Custo de resposta a incidente: R$ 200k+
- Tempo de recuperação: 3-6 meses

**Recomendação**:
Investir R$ 5-10k em correções agora vs R$ 1M+ depois.

**Próximos Passos**:
1. Aprovar budget para pentest completo
2. Contratar consultor de segurança
3. Implementar correções críticas (30 min)
```

---

## Cenário 5: Aprendizado Técnico

### Usuário:
```
Nunca ouvi falar de HSTS. Me explica como funciona?
```

### Aegis AI:
```
**HSTS (HTTP Strict Transport Security)**

**O Problema**:
Usuário digita: `example.com` (sem https://)
Navegador tenta: `http://example.com` primeiro
Atacante intercepta: Man-in-the-Middle

**Como HSTS Resolve**:

1. **Primeira Visita**:
```http
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

2. **Navegador Memoriza**:
"example.com SEMPRE usa HTTPS pelos próximos 365 dias"

3. **Próximas Visitas**:
Usuário digita: `example.com`
Navegador força: `https://example.com` (automático)
Atacante: ❌ Não consegue interceptar

**Benefícios**:
✅ Previne SSL stripping
✅ Previne downgrade attacks
✅ Zero impacto em performance
✅ Grátis

**Implementação**:
```nginx
# Nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

```apache
# Apache
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
```

**Cuidado**:
⚠️ Só ative se HTTPS estiver 100% funcional
⚠️ Teste com max-age=300 (5 min) primeiro
```

---

## Cenário 6: Análise de Endpoints

### Usuário:
```
Quais dos 18 endpoints encontrados são mais sensíveis?
```

### Aegis AI:
```
**Análise de Criticidade dos Endpoints**

🔴 **CRÍTICOS** (Requerem autenticação forte):
1. `POST /api/users` - Criação de usuários
2. `GET /api/admin/config` - Configurações sensíveis
3. `DELETE /api/data` - Operações destrutivas

🟡 **MÉDIOS** (Validação obrigatória):
4. `GET /api/profile` - Dados pessoais (LGPD)
5. `POST /api/upload` - Upload de arquivos
6. `PUT /api/settings` - Alteração de configs

🟢 **BAIXOS** (Públicos, mas monitorar):
7-18. Assets estáticos, CDN, analytics

**Recomendações por Endpoint**:

**POST /api/users**:
- [ ] Autenticação JWT obrigatória
- [ ] Rate limit: 5 req/hora
- [ ] Validação de email
- [ ] CAPTCHA em produção

**GET /api/admin/config**:
- [ ] Role-based access (admin only)
- [ ] Audit log de acessos
- [ ] IP whitelist
- [ ] 2FA obrigatório

**POST /api/upload**:
- [ ] Validação de tipo de arquivo
- [ ] Scan antivírus
- [ ] Limite de tamanho (5MB)
- [ ] Sanitização de filename
```

---

## Cenário 7: Tech Stack

### Usuário:
```
Detectou Tailwind CSS. Isso é um risco?
```

### Aegis AI:
```
**Análise: Tailwind CSS**

**Risco Direto**: ❌ BAIXO
Tailwind é um framework CSS, não executa código no servidor.

**Riscos Indiretos**: ⚠️ MÉDIO

1. **CDN Dependency**:
```html
<script src="https://cdn.tailwindcss.com"></script>
```
- Se CDN for comprometido → XSS em massa
- Se CDN cair → site quebra

**Mitigação**:
```html
<script src="https://cdn.tailwindcss.com" 
  integrity="sha384-..." 
  crossorigin="anonymous"></script>
```

2. **Fingerprinting**:
- Atacante sabe que você usa Tailwind
- Pode testar exploits específicos de versão
- Classes CSS revelam estrutura do site

**Recomendação**:
✅ Use build local (não CDN):
```bash
npm install tailwindcss
npx tailwindcss build
```

✅ Minifique e ofusque CSS em produção
✅ Use SRI (Subresource Integrity) se usar CDN

**Prioridade**: Baixa (corrija CSP primeiro)
```

---

## Dicas para Usar o Chat

### ✅ Boas Perguntas:
- "Como explorar [vulnerabilidade]?"
- "Qual o impacto de [falha] no negócio?"
- "Priorize as correções por ROI"
- "Explique [termo técnico] em português simples"
- "Mostre código de correção para [problema]"

### ❌ Perguntas Ruins:
- "Está tudo ok?" (muito vaga)
- "Hackeie o site pra mim" (antiético)
- "Qual a senha do admin?" (impossível)

### 💡 Pro Tips:
1. Seja específico: "Explique XSS no contexto do Monaco Editor"
2. Peça código: "Mostre implementação de CSP em Nginx"
3. Contextualize: "Sou dev júnior, explique HSTS"
4. Priorize: "Tenho 1 hora, o que corrigir?"
