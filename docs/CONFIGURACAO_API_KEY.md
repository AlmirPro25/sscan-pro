# 🔑 CONFIGURAÇÃO DA API KEY GEMINI

**Data**: 27 de Dezembro de 2025  
**Status**: ✅ CONFIGURADO E TESTADO

---

## 📋 CHAVE API CONFIGURADA

### Chave Atual
```
AIzaSyD5fRNYxE2IaE40SMd7OgkUnVTIFwXME30
```

**Status**: ✅ Testada e funcionando  
**Modelos Disponíveis**:
- `models/gemini-3-flash-preview` (Recomendado) ✅
- `models/gemini-robotics-er-1.5-preview` ✅
- `models/gemini-2.0-flash-exp` (Pode ter quota limitada)

---

## 🎯 CONFIGURAÇÃO NO SISTEMA

### 1. Frontend (index.html)

**Seletor de Modelo**:
```html
<select id="ai-model-select">
    <option value="models/gemini-3-flash-preview">Gemini 3 Flash Preview (Recomendado)</option>
    <option value="models/gemini-robotics-er-1.5-preview">Gemini Robotics ER 1.5 Preview</option>
    <option value="models/gemini-2.0-flash-exp">Gemini 2.0 Flash Experimental</option>
</select>
```

**Chave API Padrão**:
```javascript
this.settings = {
    model: 'models/gemini-3-flash-preview',
    key: 'AIzaSyD5fRNYxE2IaE40SMd7OgkUnVTIFwXME30'
}
```

### 2. Backend (main.go)

**Uso da Chave**:
```go
// Use API key from frontend or environment variable
apiKey := input.ApiKey
if apiKey == "" {
    apiKey = os.Getenv("GEMINI_API_KEY")
}
```

**Modelo Padrão**:
```go
if input.Model == "" {
    input.Model = "models/gemini-3-flash-preview"
}
```

### 3. Variável de Ambiente (Opcional)

**Windows (PowerShell)**:
```powershell
$env:GEMINI_API_KEY = "AIzaSyD5fRNYxE2IaE40SMd7OgkUnVTIFwXME30"
```

**Windows (CMD)**:
```cmd
set GEMINI_API_KEY=AIzaSyD5fRNYxE2IaE40SMd7OgkUnVTIFwXME30
```

**Linux/Mac**:
```bash
export GEMINI_API_KEY="AIzaSyD5fRNYxE2IaE40SMd7OgkUnVTIFwXME30"
```

---

## 🧪 TESTE DA CHAVE API

### Comando de Teste
```powershell
$body = @{ 
    scan_id = 14
    model = "models/gemini-3-flash-preview"
    api_key = "AIzaSyD5fRNYxE2IaE40SMd7OgkUnVTIFwXME30"
} | ConvertTo-Json

curl -Method POST `
     -Uri "http://localhost:8080/api/v1/ai/report" `
     -ContentType "application/json" `
     -Body $body
```

### Resultado Esperado
```json
{
  "id": 22,
  "scan_result_id": 14,
  "model": "models/gemini-3-flash-preview",
  "content": "# Relatório de Auditoria de Segurança...",
  "created_at": "2025-12-27T13:17:49Z"
}
```

**Status**: ✅ **SUCESSO** (Testado em 27/12/2025)

---

## 📊 MODELOS DISPONÍVEIS

### 1. Gemini 3 Flash Preview (Recomendado) ✅
- **ID**: `models/gemini-3-flash-preview`
- **Velocidade**: Rápido
- **Qualidade**: Excelente
- **Custo**: Gratuito (com limites)
- **Uso**: Relatórios AI, Chat interativo

### 2. Gemini Robotics ER 1.5 Preview
- **ID**: `models/gemini-robotics-er-1.5-preview`
- **Velocidade**: Médio
- **Qualidade**: Boa (mas ignora instruções de estrutura)
- **Custo**: Gratuito (com limites)
- **Uso**: Análise técnica especializada

### 3. Gemini 2.0 Flash Experimental
- **ID**: `models/gemini-2.0-flash-exp`
- **Velocidade**: Muito Rápido
- **Qualidade**: Excelente
- **Custo**: Gratuito (quota limitada)
- **Uso**: Testes e experimentação

---

## 🔒 SEGURANÇA DA CHAVE API

### ⚠️ IMPORTANTE

1. **Não compartilhe** a chave API publicamente
2. **Não commite** a chave no Git (use .gitignore)
3. **Use variáveis de ambiente** em produção
4. **Rotacione** a chave periodicamente

### Proteção no Git

**Adicionar ao .gitignore**:
```gitignore
# API Keys
.env
*.key
config/secrets.json

# Frontend com chave hardcoded
index.html.backup
```

### Uso em Produção

**Recomendação**: Use variáveis de ambiente em vez de hardcode

```javascript
// Frontend (NÃO recomendado para produção)
key: 'AIzaSyD5fRNYxE2IaE40SMd7OgkUnVTIFwXME30'

// Backend (RECOMENDADO)
apiKey := os.Getenv("GEMINI_API_KEY")
```

---

## 📈 LIMITES E QUOTAS

### Gemini API Free Tier

**Limites por Minuto**:
- Requests: 15 req/min
- Tokens: 1M tokens/min
- Tokens por dia: 1.5M tokens/day

**Limites por Modelo**:
- `gemini-3-flash-preview`: 15 req/min
- `gemini-robotics-er-1.5-preview`: 10 req/min
- `gemini-2.0-flash-exp`: 10 req/min

### Monitoramento

**Verificar uso**:
https://ai.google.dev/usage

**Erro de Quota**:
```json
{
  "error": "You exceeded your current quota",
  "details": "Quota exceeded for metric: generativelanguage.googleapis.com/generate_content_free_tier_requests"
}
```

**Solução**: Aguardar reset (geralmente 1 minuto) ou usar outro modelo

---

## 🚀 COMO USAR NO FRONTEND

### 1. Abrir Configurações
1. Clicar no ícone de engrenagem (⚙️)
2. Ir para seção "AI Configuration"

### 2. Selecionar Modelo
```
Gemini 3 Flash Preview (Recomendado) ← Selecionar este
```

### 3. Configurar Chave API (Opcional)
```
API Key: AIzaSyD5fRNYxE2IaE40SMd7OgkUnVTIFwXME30
```

### 4. Salvar Configurações
- Configurações são salvas automaticamente no localStorage
- Backend usa a chave do frontend se fornecida
- Caso contrário, usa variável de ambiente

---

## 🔧 TROUBLESHOOTING

### Erro: "GEMINI_API_KEY is not configured"

**Causa**: Chave API não encontrada

**Solução**:
1. Configurar no frontend (Settings)
2. OU definir variável de ambiente:
   ```powershell
   $env:GEMINI_API_KEY = "AIzaSyD5fRNYxE2IaE40SMd7OgkUnVTIFwXME30"
   ```

### Erro: "Model not found" (404)

**Causa**: Modelo não disponível na API v1beta

**Solução**: Usar um dos modelos testados:
- ✅ `models/gemini-3-flash-preview`
- ✅ `models/gemini-robotics-er-1.5-preview`

### Erro: "Quota exceeded" (429)

**Causa**: Limite de requests excedido

**Solução**:
1. Aguardar 1 minuto
2. Usar outro modelo
3. Verificar uso em: https://ai.google.dev/usage

---

## ✅ CHECKLIST DE CONFIGURAÇÃO

- [x] Chave API configurada no frontend
- [x] Chave API testada e funcionando
- [x] Modelo padrão: `gemini-3-flash-preview`
- [x] Backend aceita chave do frontend
- [x] Backend usa variável de ambiente como fallback
- [x] Seletor de modelo no frontend
- [x] 3 modelos disponíveis para seleção
- [x] Logs de debug no backend

---

## 📞 SUPORTE

### Obter Nova Chave API

1. Acessar: https://ai.google.dev/
2. Fazer login com conta Google
3. Ir para "Get API Key"
4. Criar novo projeto
5. Copiar chave gerada

### Documentação Oficial

- **Gemini API**: https://ai.google.dev/docs
- **Modelos**: https://ai.google.dev/models
- **Quotas**: https://ai.google.dev/pricing
- **Rate Limits**: https://ai.google.dev/gemini-api/docs/rate-limits

---

**Status**: ✅ CONFIGURADO E FUNCIONANDO  
**Chave**: AIzaSyD5fRNYxE2IaE40SMd7OgkUnVTIFwXME30  
**Modelo Recomendado**: gemini-3-flash-preview  
**Última Atualização**: 27 de Dezembro de 2025
