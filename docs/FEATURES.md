# 🆕 Novas Features - AegisScan Enterprise

## 1. 🤖 Relatórios AI com Gemini

### O que faz?
Gera análise técnica profunda usando Google Gemini AI, identificando:
- Vulnerabilidades críticas (XSS, Clickjacking, etc)
- Análise contextual do tech stack
- Recomendações de hardening específicas
- Avaliação de risco empresarial

### Como usar?
1. Após o scan, clique em **"GERAR RELATÓRIO MASTER"**
2. Aguarde processamento (15-30 segundos)
3. Relatório aparece em Markdown formatado
4. Relatório é salvo automaticamente no banco

### Modelos disponíveis:
- `gemini-2.0-flash` ⭐ (Recomendado)
- `gemini-1.5-flash` (Estável)
- `gemini-2.5-flash-lite` (Rápido)
- Custom (ID manual)

---

## 2. 💬 Chat Interativo com IA

### O que faz?
Permite conversar com a IA sobre o relatório gerado, esclarecendo:
- Detalhes técnicos de vulnerabilidades
- Como explorar falhas encontradas
- Priorização de correções
- Contexto de negócio

### Como usar?
1. Gere o relatório AI primeiro
2. Seção de chat aparece automaticamente
3. Digite sua pergunta (ex: "Como explorar o XSS encontrado?")
4. Pressione Enter ou clique no botão de enviar
5. IA responde com contexto completo do scan

### Exemplos de perguntas:
```
- "Explique a vulnerabilidade de CSP ausente"
- "Qual a prioridade de correção dos problemas?"
- "Como implementar HSTS corretamente?"
- "O que significa o score de 60%?"
- "Quais endpoints são mais críticos?"
```

### Recursos:
- ✅ Histórico de conversa mantido
- ✅ Contexto completo do scan
- ✅ Respostas em Markdown
- ✅ Scroll automático
- ✅ Persistência no banco

---

## 3. 🎬 Media Player Integrado

### O que faz?
Reproduz streams de mídia encontrados durante o scan:
- HLS (.m3u8) com HLS.js
- DASH (.mpd) - link externo
- MP4 direto no player

### Como usar?
1. No relatório, clique no ícone **roxo de play** (topo direito)
2. Modal abre com lista de streams detectados
3. Streams MP4/HLS reproduzem diretamente
4. DASH abre em nova aba

### Informações exibidas:
- Tipo de stream (HLS/DASH/MP4)
- URL completa do stream
- Player detectado no site
- Preview de vídeo (quando possível)

### Suporte:
- ✅ HLS (Apple HTTP Live Streaming)
- ✅ MP4 (Progressive download)
- ⚠️ DASH (Link externo - requer player específico)

---

## 4. 💾 Persistência de Relatórios

### O que mudou?
Relatórios AI agora são salvos no banco SQLite e recuperáveis.

### Benefícios:
- Acesse relatórios antigos sem regerar
- Chat mantém histórico completo
- Comparação entre scans
- Auditoria de análises

### Estrutura do banco:
```
ScanResult (scan básico)
  ├── AIReport (relatório gerado)
  └── ChatMessage[] (histórico de chat)
```

### API:
```bash
# Buscar relatório existente
GET /api/v1/ai/report/:scan_id

# Histórico de chat
# Incluído na resposta de /ai/chat
```

---

## 🎯 Fluxo Completo de Uso

```
1. SCAN
   └─> Digite URL → Clique SCAN → Aguarde análise

2. RELATÓRIO
   └─> Clique "GERAR RELATÓRIO MASTER" → Aguarde IA

3. CHAT
   └─> Pergunte sobre vulnerabilidades → IA responde

4. MÍDIA
   └─> Clique ícone play → Veja streams encontrados

5. VAULT
   └─> Acesse histórico → Relatórios salvos aparecem
```

---

## 🔧 Configuração Necessária

### API Key do Gemini (Obrigatória para IA)
1. Acesse: https://makersuite.google.com/app/apikey
2. Crie projeto no Google Cloud
3. Ative Gemini API
4. Copie a chave
5. Cole em Settings → Google API Key

### Armazenamento Local
- API key: `localStorage.aegis_key`
- Modelo: `localStorage.aegis_model`
- Scans: `IndexedDB.AegisVault`

---

## 🚨 Troubleshooting

### Chat não aparece
- ✅ Gere o relatório AI primeiro
- ✅ Verifique API key configurada
- ✅ Veja console do browser (F12)

### Vídeo não reproduz
- ✅ Verifique CORS do stream
- ✅ HLS requer HLS.js (já incluído)
- ✅ Alguns streams precisam autenticação

### Relatório não salva
- ✅ Backend rodando?
- ✅ Banco SQLite criado?
- ✅ Verifique logs do Go

### IA demora muito
- ✅ Troque para modelo mais rápido
- ✅ Gemini 2.5 Flash Lite é o mais rápido
- ✅ Verifique quota da API

---

## 📊 Comparação de Modelos

| Modelo | Velocidade | Qualidade | Custo | Uso |
|--------|-----------|-----------|-------|-----|
| Gemini 2.0 Flash | ⚡⚡⚡ | ⭐⭐⭐⭐ | 💰💰 | Produção |
| Gemini 1.5 Flash | ⚡⚡ | ⭐⭐⭐⭐⭐ | 💰💰💰 | Análise profunda |
| Gemini 2.5 Flash Lite | ⚡⚡⚡⚡ | ⭐⭐⭐ | 💰 | Testes rápidos |

---

## 🎨 UI/UX

### Chat
- Mensagens do usuário: azul, alinhadas à direita
- Respostas da IA: cinza, alinhadas à esquerda
- Markdown renderizado automaticamente
- Scroll automático para última mensagem

### Media Player
- Modal fullscreen com backdrop escuro
- Lista de streams com badges coloridos
- Player inline para MP4/HLS
- Links externos para DASH

### Relatório AI
- Card destacado com borda verde
- Ícone de cérebro animado
- Markdown com syntax highlighting
- Badge "CONFIDENCIAL"

---

## 🔐 Segurança

### API Keys
- ⚠️ Armazenadas no localStorage (client-side)
- ✅ Nunca enviadas para backend por padrão
- ✅ Opcional: enviar via body para proxy
- 🔒 Produção: use backend proxy

### Dados Sensíveis
- Relatórios podem conter info confidencial
- Chat mantém histórico completo
- Recomendado: limpar vault periodicamente

---

## 💡 Dicas Pro

1. **Use chat para aprender**: Pergunte "Como funciona XSS?" para entender vulnerabilidades
2. **Compare scans**: Rode scan antes/depois de correções
3. **Exporte JSON**: Integre com outras ferramentas
4. **Modelos custom**: Teste Gemini experimental
5. **Media discovery**: Útil para OSINT de plataformas de vídeo

---

## 🚀 Próximos Passos

- [ ] Export de chat em PDF
- [ ] Sugestões de perguntas automáticas
- [ ] Análise comparativa entre scans
- [ ] Integração com Burp Suite
- [ ] Plugin para navegador
