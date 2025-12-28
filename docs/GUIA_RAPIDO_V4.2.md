# Guia Rápido - AegisScan V4.2

**Versão**: 4.2 - Tom Profissional e Contexto Enterprise  
**Data**: 2024-12-27

---

## 🚀 INÍCIO RÁPIDO

### 1. Iniciar Backend
```bash
cd backend
./aegis-backend-v4.2.exe
```
✅ Aguarde: `🛡️ Aegis Backend Running on :8080`

### 2. Iniciar Worker (nova janela)
```bash
cd backend/worker
node server.js
```
✅ Aguarde: `🔍 Aegis Worker Running on :3000`

### 3. Abrir Frontend
- Abrir `index.html` no navegador
- Ou usar Live Server no VS Code

---

## 🎯 TESTAR MELHORIAS V4.2

### Teste 1: MercadoLivre (Enterprise)
1. URL: `https://www.mercadolivre.com.br/`
2. Clicar em **SCAN**
3. Aguardar conclusão (30-60 segundos)
4. Clicar em **Gerar Relatório AI**
5. Modelo: **gemini-3-flash-preview** (Recomendado)
6. Aguardar geração (20-40 segundos)

**Validar**:
- ✅ Tom profissional (não "Red Team Commander")
- ✅ Severidades realistas (MEDIUM para headers)
- ✅ Contexto enterprise mencionado
- ✅ Reconhece WAF, equipe de segurança
- ✅ 9 seções presentes

### Teste 2: Site Standard
1. URL: `http://testphp.vulnweb.com`
2. Repetir processo acima

**Validar**:
- ✅ Análise mais rigorosa
- ✅ Sem contexto enterprise
- ✅ Foco em OWASP Top 10

---

## 📊 O QUE MUDOU NA V4.2

### ANTES (V4.1)
```
🚨 RELATÓRIO DE PENTEST OFFENSIVO
COMANDANTE: AEGIS RED TEAM COMMANDER
DESTRUINDO A FALSA SENSAÇÃO DE SEGURANÇA
Vulnerabilidade CATASTRÓFICA
```

### DEPOIS (V4.2)
```
Relatório de Auditoria de Segurança
Auditor: Security Researcher Sênior
Postura de segurança robusta
Vulnerabilidade MEDIUM (CVSS 5.3)
Contexto Enterprise: WAF, IDS/IPS, equipe dedicada
```

---

## 🎯 PRINCIPAIS MELHORIAS

1. **Tom Profissional**
   - Linguagem de consultor de segurança
   - Sem termos sensacionalistas
   - Baseado em evidências

2. **Severidades Realistas**
   - Headers faltantes = MEDIUM (não CRITICAL)
   - CVSS scores corretos (5.3, 6.1, 5.4)
   - Contexto considerado

3. **Contexto Enterprise**
   - Detecta automaticamente (mercadolivre, google, etc)
   - Reconhece defesas não visíveis
   - Menciona limitações da análise passiva

4. **Sanitização Automática**
   - Remove 30+ termos sensacionalistas
   - Remove emojis excessivos
   - Padroniza linguagem

---

## 🔧 CONFIGURAÇÃO API KEY

### Opção 1: Frontend (Recomendado)
1. Abrir `index.html`
2. Procurar por `apiKey`
3. Substituir pela sua chave

### Opção 2: Backend (Variável de Ambiente)
```bash
# Windows
set GEMINI_API_KEY=sua_chave_aqui

# Linux/Mac
export GEMINI_API_KEY=sua_chave_aqui
```

### Opção 3: Interface (Futuro)
- Configuração via UI (em desenvolvimento)

---

## 📝 MODELOS DISPONÍVEIS

1. **gemini-3-flash-preview** ⭐ RECOMENDADO
   - Melhor para relatórios profissionais
   - Tom adequado
   - Velocidade boa

2. **gemini-robotics-er-1.5-preview**
   - Alternativa robusta
   - Boa qualidade

3. **gemini-2.0-flash-exp**
   - Experimental
   - Mais rápido

---

## 🐛 TROUBLESHOOTING

### Backend não inicia
```bash
# Verificar porta 8080
netstat -ano | findstr :8080

# Matar processo se necessário
taskkill /PID <PID> /F

# Reiniciar
./aegis-backend-v4.2.exe
```

### Worker não inicia
```bash
# Verificar porta 3000
netstat -ano | findstr :3000

# Instalar dependências
npm install

# Reiniciar
node server.js
```

### Relatório ainda sensacionalista
1. Verificar se backend V4.2 está rodando
2. Verificar logs: `🧹 Sanitizing report content...`
3. Verificar modelo selecionado

### Sem contexto enterprise
1. Verificar se domínio está na lista
2. Verificar logs: `Contexto Enterprise detectado`
3. Adicionar domínio se necessário

---

## 📚 DOCUMENTAÇÃO COMPLETA

- **CHANGELOG_V4.2_PROFESSIONAL_TONE.md**: Mudanças detalhadas
- **TESTE_V4.2_MERCADOLIVRE.md**: Guia de teste
- **MELHORIAS_V4.2_RESUMO.md**: Resumo executivo

---

## 🎯 CHECKLIST DE VALIDAÇÃO

### Relatório Profissional
- [ ] Sem "Red Team Commander"
- [ ] Sem "destruindo", "gravíssimo", "catastrófico"
- [ ] Severidades realistas (MEDIUM para headers)
- [ ] Contexto enterprise (se aplicável)
- [ ] 9 seções presentes
- [ ] Evidências concretas
- [ ] Disclaimer presente

### Funcionalidades
- [ ] Scan completa com sucesso
- [ ] Relatório AI gera sem erros
- [ ] Chat funciona
- [ ] PDF exporta corretamente
- [ ] Histórico salva

---

## 💡 DICAS

### Para Melhores Resultados
1. Use **gemini-3-flash-preview**
2. Aguarde scan completo antes de gerar relatório
3. Teste com alvos enterprise (mercadolivre, google)
4. Teste com alvos standard (testphp.vulnweb.com)
5. Compare relatórios V4.1 vs V4.2

### Domínios Enterprise Suportados
- mercadolivre.com, mercadolibre.com
- google.com, microsoft.com, amazon.com
- nubank.com, itau.com, bradesco.com
- globo.com, uol.com, terra.com
- magazineluiza.com, americanas.com
- E mais...

---

## 🚀 PRÓXIMOS PASSOS

1. ✅ Testar com mercadolivre.com.br
2. ⏳ Testar com outros alvos enterprise
3. ⏳ Testar com alvos standard
4. ⏳ Validar qualidade dos relatórios
5. ⏳ Ajustes finos se necessário

---

**Criado por**: Kiro AI  
**Data**: 2024-12-27  
**Versão**: 4.2  
**Status**: ✅ PRONTO PARA USO
