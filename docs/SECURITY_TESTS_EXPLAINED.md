# 🛡️ Testes de Segurança Explicados (Para Leigos)

## 1. 🔴 XSS + SQLi Testing (+10 pontos)

### **XSS (Cross-Site Scripting)**

**O que é:** Injetar código JavaScript malicioso em um site

**Exemplo Real:**
```
Site tem campo de busca: [Digite aqui]
Hacker digita: <script>alert('Hackeado!')</script>
Se o site não filtrar, o código roda e pode roubar cookies/senhas
```

**Como seu sistema testaria:**
```javascript
// Encontrar todos os inputs
const inputs = document.querySelectorAll('input, textarea');

// Payloads de teste
const xssPayloads = [
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    'javascript:alert(1)'
];

// Testar cada input
for (const input of inputs) {
    for (const payload of xssPayloads) {
        // 1. Inserir payload
        input.value = payload;
        input.form.submit();
        
        // 2. Verificar se o payload aparece na resposta
        const response = await page.content();
        if (response.includes(payload)) {
            // VULNERÁVEL! ⚠️
            vulnerabilities.push({
                type: 'XSS',
                severity: 'HIGH',
                location: input.name,
                payload: payload
            });
        }
    }
}
```

**Resultado no relatório:**
```
⚠️ VULNERABILIDADE CRÍTICA: XSS Refletido
Local: Campo de busca (/search?q=)
Payload: <script>alert(1)</script>
Impacto: Atacante pode roubar sessões de usuários
Solução: Sanitizar inputs com DOMPurify ou escapar HTML
```

---

### **SQLi (SQL Injection)**

**O que é:** Injetar comandos SQL para acessar/modificar banco de dados

**Exemplo Real:**
```
Login normal:
SELECT * FROM users WHERE email='user@email.com' AND password='123456'

Hacker digita no email: admin'--
Query vira:
SELECT * FROM users WHERE email='admin'--' AND password='123456'
(O -- comenta o resto, fazendo login sem senha!)
```

**Como seu sistema testaria:**
```javascript
// Payloads de SQLi
const sqliPayloads = [
    "' OR '1'='1",           // Bypass de login
    "admin'--",              // Comentar resto da query
    "1' UNION SELECT NULL--", // Extrair dados
    "'; DROP TABLE users--"   // Deletar tabela (perigoso!)
];

// Testar forms de login/busca
for (const form of attackVectors.forms) {
    for (const payload of sqliPayloads) {
        // Enviar payload
        const response = await submitForm(form, payload);
        
        // Detectar erros SQL
        if (response.includes('SQL syntax') || 
            response.includes('mysql_fetch') ||
            response.includes('ORA-') ||
            response.status === 500) {
            
            // VULNERÁVEL! 🔥
            vulnerabilities.push({
                type: 'SQL Injection',
                severity: 'CRITICAL',
                form: form.action,
                payload: payload
            });
        }
    }
}
```

**Resultado no relatório:**
```
🔥 VULNERABILIDADE CRÍTICA: SQL Injection
Local: Formulário de login (/api/auth/login)
Payload: ' OR '1'='1
Impacto: Atacante pode acessar TODOS os dados do banco
Solução: Usar prepared statements ou ORM (Sequelize, Prisma)
```

---

## 2. 🔵 Port Scanning (+5 pontos)

### **O que é:** Descobrir quais portas/serviços estão abertos no servidor

**Exemplo Real:**
```
Servidor deveria ter só:
- Porta 80 (HTTP)
- Porta 443 (HTTPS)

Mas o scan descobre:
- Porta 22 (SSH) - Pode tentar brute force
- Porta 3306 (MySQL) - Banco exposto!
- Porta 6379 (Redis) - Cache sem senha!
- Porta 27017 (MongoDB) - NoSQL exposto!
```

**Como seu sistema testaria:**
```javascript
const nmap = require('node-nmap');

// Escanear portas comuns
const scan = new nmap.NmapScan(targetHost, '1-10000');

scan.on('complete', (data) => {
    data.forEach(host => {
        host.openPorts.forEach(port => {
            const risk = assessPortRisk(port);
            
            openPorts.push({
                port: port.port,
                service: port.service,
                version: port.version,
                risk: risk,
                recommendation: getRecommendation(port)
            });
        });
    });
});

function assessPortRisk(port) {
    const criticalPorts = {
        22: 'SSH - Alvo de brute force',
        3306: 'MySQL - Banco exposto',
        5432: 'PostgreSQL - Banco exposto',
        6379: 'Redis - Cache sem auth',
        27017: 'MongoDB - NoSQL exposto',
        9200: 'Elasticsearch - Dados expostos'
    };
    
    return criticalPorts[port.port] || 'Verificar necessidade';
}
```

**Resultado no relatório:**
```
🔥 PORTAS CRÍTICAS EXPOSTAS:

Porta 3306 (MySQL) - CRÍTICO
├─ Versão: MySQL 5.7.32
├─ Risco: Banco de dados acessível pela internet
├─ Impacto: Atacante pode tentar acessar dados
└─ Solução: Fechar porta ou usar firewall (só localhost)

Porta 6379 (Redis) - ALTO
├─ Versão: Redis 6.0.9
├─ Risco: Cache sem autenticação
├─ Impacto: Atacante pode ler/modificar cache
└─ Solução: Configurar requirepass no redis.conf
```

---

## 3. 🟢 SSL/TLS Analysis (+5 pontos)

### **O que é:** Verificar se a criptografia HTTPS está configurada corretamente

**Exemplo Real:**
```
Site tem HTTPS ✅
MAS:
- Certificado expirado há 30 dias ❌
- Usa TLS 1.0 (protocolo antigo/inseguro) ❌
- Aceita ciphers fracos (RC4, MD5) ❌
- Vulnerável a BEAST, POODLE, Heartbleed ❌
```

**Como seu sistema testaria:**
```javascript
const sslChecker = require('ssl-checker');
const testssl = require('node-testssl');

// 1. Verificar certificado
const certInfo = await sslChecker(hostname);

if (certInfo.daysRemaining < 30) {
    sslIssues.push({
        type: 'Certificado Expirando',
        severity: 'HIGH',
        days: certInfo.daysRemaining,
        message: `Certificado expira em ${certInfo.daysRemaining} dias`
    });
}

// 2. Testar protocolos
const protocols = await testssl.checkProtocols(hostname);

if (protocols.includes('TLSv1.0') || protocols.includes('SSLv3')) {
    sslIssues.push({
        type: 'Protocolo Inseguro',
        severity: 'CRITICAL',
        protocol: 'TLS 1.0 / SSL 3.0',
        message: 'Protocolos antigos vulneráveis a ataques'
    });
}

// 3. Testar ciphers
const ciphers = await testssl.checkCiphers(hostname);

const weakCiphers = ciphers.filter(c => 
    c.includes('RC4') || 
    c.includes('MD5') || 
    c.includes('DES')
);

if (weakCiphers.length > 0) {
    sslIssues.push({
        type: 'Ciphers Fracos',
        severity: 'HIGH',
        ciphers: weakCiphers,
        message: 'Algoritmos de criptografia fracos detectados'
    });
}

// 4. Testar vulnerabilidades conhecidas
const vulns = await testssl.checkVulnerabilities(hostname);

if (vulns.heartbleed) {
    sslIssues.push({
        type: 'Heartbleed',
        severity: 'CRITICAL',
        cve: 'CVE-2014-0160',
        message: 'Vulnerabilidade permite roubo de memória do servidor'
    });
}
```

**Resultado no relatório:**
```
🔒 ANÁLISE SSL/TLS

✅ Certificado Válido
├─ Emissor: Let's Encrypt
├─ Validade: 89 dias restantes
└─ Domínio: *.exemplo.com

⚠️ PROBLEMAS DETECTADOS:

1. Protocolo TLS 1.0 Ativo - CRÍTICO
   ├─ Risco: Vulnerável a ataques BEAST e POODLE
   ├─ Impacto: Atacante pode descriptografar tráfego
   └─ Solução: Desabilitar TLS 1.0/1.1, usar apenas TLS 1.2+

2. Cipher RC4 Aceito - ALTO
   ├─ Risco: Algoritmo de criptografia fraco
   ├─ Impacto: Dados podem ser descriptografados
   └─ Solução: Remover RC4 da lista de ciphers aceitos

Grade SSL Labs: C (era A+)
```

---

## 4. 🟡 Auth Testing (+5 pontos)

### **O que é:** Testar se o sistema de login/autenticação é seguro

**Exemplo Real:**
```
Problemas comuns:
1. Senha fraca aceita (123456, admin, password)
2. Sem limite de tentativas (brute force)
3. Token de sessão previsível
4. Senha enviada em URL (?password=123)
5. Sem logout adequado
```

**Como seu sistema testaria:**
```javascript
// 1. TESTE DE SENHAS FRACAS
const commonPasswords = [
    'admin', '123456', 'password', '12345678',
    'qwerty', '123456789', 'letmein', 'welcome'
];

const loginForm = attackVectors.forms.find(f => 
    f.action.includes('login') || 
    f.inputs.includes('password')
);

if (loginForm) {
    // Testar credenciais comuns
    for (const pass of commonPasswords) {
        const response = await submitLogin('admin', pass);
        
        if (response.status === 200 && response.includes('dashboard')) {
            authIssues.push({
                type: 'Credenciais Fracas',
                severity: 'CRITICAL',
                username: 'admin',
                password: pass,
                message: 'Sistema aceita senha comum/fraca'
            });
        }
    }
}

// 2. TESTE DE BRUTE FORCE
let attempts = 0;
let blocked = false;

for (let i = 0; i < 20; i++) {
    const response = await submitLogin('admin', `wrong${i}`);
    attempts++;
    
    if (response.status === 429 || response.includes('bloqueado')) {
        blocked = true;
        break;
    }
}

if (!blocked) {
    authIssues.push({
        type: 'Sem Rate Limiting',
        severity: 'HIGH',
        attempts: attempts,
        message: `Sistema permitiu ${attempts} tentativas sem bloqueio`
    });
}

// 3. TESTE DE SESSION FIXATION
const initialSession = await page.cookies();
await page.goto(loginUrl);
const preLoginSession = await page.cookies();

await submitLogin('user@test.com', 'password123');
const postLoginSession = await page.cookies();

if (preLoginSession[0].value === postLoginSession[0].value) {
    authIssues.push({
        type: 'Session Fixation',
        severity: 'HIGH',
        message: 'Token de sessão não muda após login'
    });
}

// 4. TESTE DE TOKEN JWT
const token = localStorage.getItem('token');

if (token) {
    const decoded = jwt.decode(token);
    
    // Verificar expiração
    if (!decoded.exp) {
        authIssues.push({
            type: 'JWT sem Expiração',
            severity: 'HIGH',
            message: 'Token nunca expira'
        });
    }
    
    // Verificar algoritmo
    if (decoded.alg === 'none') {
        authIssues.push({
            type: 'JWT Algorithm None',
            severity: 'CRITICAL',
            message: 'Token pode ser forjado sem assinatura'
        });
    }
}

// 5. TESTE DE SENHA NA URL
if (window.location.href.includes('password=')) {
    authIssues.push({
        type: 'Senha na URL',
        severity: 'CRITICAL',
        url: window.location.href,
        message: 'Senha exposta em logs/histórico do navegador'
    });
}
```

**Resultado no relatório:**
```
🔐 ANÁLISE DE AUTENTICAÇÃO

🔥 VULNERABILIDADES CRÍTICAS:

1. Credenciais Padrão Aceitas
   ├─ Usuário: admin
   ├─ Senha: admin
   ├─ Impacto: Qualquer um pode fazer login
   └─ Solução: Forçar troca de senha no primeiro acesso

2. Sem Limite de Tentativas
   ├─ Tentativas testadas: 100
   ├─ Bloqueio: Nenhum
   ├─ Impacto: Atacante pode fazer brute force
   └─ Solução: Implementar rate limiting (5 tentativas/minuto)

⚠️ PROBLEMAS DE SEGURANÇA:

3. JWT sem Expiração
   ├─ Token: eyJhbGc...
   ├─ Expiração: Nunca
   ├─ Impacto: Token roubado funciona para sempre
   └─ Solução: Adicionar exp: Date.now() + 3600 (1 hora)

4. Session Fixation
   ├─ Token antes do login: abc123
   ├─ Token depois do login: abc123 (mesmo!)
   ├─ Impacto: Atacante pode fixar sessão da vítima
   └─ Solução: Regenerar session ID após login

Grade de Segurança: D (era A)
```

---

## 📊 Resumo Visual

### **Antes (Seu sistema atual):**
```
[Scan] → Mapeia → Relatório
         ↓
    - Endpoints ✅
    - Arquivos expostos ✅
    - Secrets ✅
    - Rotas ocultas ✅
```

### **Depois (Com os 4 testes):**
```
[Scan] → Mapeia → TESTA → Relatório
         ↓         ↓
    Mapeia ✅   XSS ✅
                SQLi ✅
                Ports ✅
                SSL ✅
                Auth ✅
```

---

## 💰 Impacto no Valor do Produto

### **Sem os testes (atual):**
- Cliente: "Legal, mas só mapeia. Eu preciso saber SE É VULNERÁVEL"
- Valor percebido: R$ 50-100/mês
- Concorrência: Ferramentas grátis (Nikto, Wapiti)

### **Com os testes:**
- Cliente: "Uau! Encontrou XSS, SQLi, portas abertas E me diz como corrigir!"
- Valor percebido: R$ 200-500/mês
- Concorrência: Burp Suite ($449/ano), Acunetix ($4,500/ano)

---

## 🎯 Priorização

### **Implementar PRIMEIRO (1 mês):**
1. **XSS Testing** - Mais comum, fácil de testar
2. **SQLi Testing** - Crítico, fácil de testar
3. **Auth Testing** - Muito comum, médio esforço

### **Implementar DEPOIS (2-3 meses):**
4. **SSL/TLS Analysis** - Importante mas menos urgente
5. **Port Scanning** - Útil mas requer mais infra

---

## 🚀 Código Pronto para Começar

Quer que eu implemente algum desses testes no seu sistema agora? Posso começar pelo XSS + SQLi que são os mais críticos e valiosos! 🎯
