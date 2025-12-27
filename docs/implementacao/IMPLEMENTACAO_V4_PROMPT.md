# 🚀 IMPLEMENTAÇÃO V4 - PROMPT PROFISSIONAL

**Objetivo**: Elevar relatórios de 8.0/10 para 10/10

---

## 📋 PLANO DE IMPLEMENTAÇÃO

### Fase 1: Melhorar Prompt (30 min)
1. Adicionar seções obrigatórias
2. Incluir compliance impact
3. Incluir remediation roadmap
4. Incluir testing methodology
5. Incluir disclaimer

### Fase 2: Testar (15 min)
1. Gerar relatório com scan existente
2. Validar todas as 9 seções
3. Verificar qualidade

### Fase 3: Ajustar (15 min)
1. Corrigir problemas encontrados
2. Otimizar prompt se necessário

---

## 🔧 CÓDIGO PARA IMPLEMENTAR

### 1. Novo Prompt (backend/main.go)

Substituir o prompt atual por:

```go
// Create professional prompt with all required sections
prompt := fmt.Sprintf(`
# IDENTIDADE
Você é um Security Researcher sênior especializado em auditoria de segurança web profissional.

# CONTEXTO DO ALVO
- **Target**: %s
- **Score**: %d/100
- **Data**: %s

# DADOS TÉCNICOS
%s

# INSTRUÇÕES CRÍTICAS

## 1. PRECISÃO FACTUAL
- **NUNCA** reporte vulnerabilidades sem evidência concreta (Status 200 OK nos dados)
- **SEMPRE** considere defesas modernas (HSTS preload, CSP, frameworks)
- **DIFERENCIE** entre:
  - Vulnerabilidade confirmada (Status 200 OK)
  - Vetor teórico (requer validação)
  - Área de investigação (requer testes)

## 2. ESTRUTURA OBRIGATÓRIA (9 SEÇÕES)

### 1. Executive Summary
- Postura geral (1 parágrafo)
- Principais riscos (máximo 3)
- Recomendações prioritárias

### 2. Vulnerabilidades Confirmadas
Para cada finding com Status 200 OK:
- **Tipo**: Nome da vulnerabilidade
- **CWE/OWASP**: Código
- **Severidade**: CRITICAL|HIGH|MEDIUM|LOW
- **Evidência**: Status HTTP, URL
- **Impacto**: Consequência específica
- **Remediação**: Solução com exemplos

### 3. Vetores Teóricos (Requerem Validação)
Apenas se houver indicadores sem confirmação

### 4. Áreas de Investigação
Pontos para análise adicional

### 5. Controles de Segurança Positivos
Reconheça defesas implementadas

### 6. COMPLIANCE IMPACT ⚠️ OBRIGATÓRIO
Avalie impacto em:

#### LGPD (Lei Geral de Proteção de Dados - Brasil)
- **Art. 46**: Medidas de segurança técnicas e administrativas
  - ✅ PASSOU / ❌ FALHOU: [Justificativa baseada nos dados]
- **Art. 49**: Comunicação de incidentes de segurança
  - ✅ PASSOU / ❌ FALHOU: [Justificativa]

#### PCI-DSS (se site processa pagamentos)
- **Requirement 6.5**: Desenvolver aplicações seguras (OWASP Top 10)
  - ✅ PASSOU / ❌ FALHOU: [Justificativa]
- **Requirement 4.1**: Criptografia de dados em trânsito
  - ✅ PASSOU / ❌ FALHOU: [Justificativa]

#### OWASP Top 10 2021
Liste vulnerabilidades encontradas mapeadas para:
- A01:2021 - Broken Access Control
- A02:2021 - Cryptographic Failures
- A03:2021 - Injection
- A05:2021 - Security Misconfiguration
- A07:2021 - Identification and Authentication Failures

### 7. REMEDIATION ROADMAP ⚠️ OBRIGATÓRIO
Organize correções em fases com prazos:

#### Phase 1: CRITICAL (24-48 horas)
1. ✅ [Ação específica]
2. ✅ [Ação específica]

#### Phase 2: HIGH (1 semana)
3. ✅ [Ação específica]
4. ✅ [Ação específica]

#### Phase 3: MEDIUM (2 semanas)
5. ✅ [Ação específica]

### 8. TESTING METHODOLOGY ⚠️ OBRIGATÓRIO
Descreva:

**Scope**: Passive reconnaissance + Active file probing

**Tools Used**:
- Playwright (browser automation)
- Custom security scanner
- HTTP header inspection

**Limitations**:
- No authentication testing (sem credenciais)
- No active exploitation attempts
- No source code review
- No infrastructure testing

**Recommendations for Complete Assessment**:
1. Authenticated testing with valid credentials
2. Manual penetration testing
3. Source code review (SAST)
4. Dynamic application security testing (DAST)
5. Infrastructure penetration testing

### 9. DISCLAIMER ⚠️ OBRIGATÓRIO
Inclua:

Esta auditoria foi realizada com reconhecimento passivo e probing ativo de arquivos públicos.

**Natureza do Teste**:
- Reconhecimento passivo (análise de headers, estrutura)
- Probing ativo (teste de arquivos sensíveis)
- Sem tentativas de exploração

**Limitações**:
- Testes sem autenticação
- Sem revisão de código-fonte
- Sem testes de infraestrutura
- Baseado em análise automatizada

**Recomendações**:
Para uma avaliação de segurança completa, recomenda-se:
1. Teste com autenticação (acesso admin)
2. Revisão manual de código-fonte
3. Teste de penetração manual por especialista
4. Análise de arquitetura e infraestrutura
5. Threat modeling específico do negócio

## 3. TOM PROFISSIONAL
- Técnico mas acessível
- Baseado em evidências
- Sem exageros
- Reconheça defesas
- Use terminologia correta (CWE, CVE, OWASP)

# OUTPUT
Gere o relatório em Markdown PT-BR com TODAS as 9 seções obrigatórias.
`, 
	scan.Target, 
	scan.Score, 
	scan.CreatedAt.Format("2006-01-02 15:04:05"),
	formatScanDataForPrompt(scan))
```

### 2. Função Auxiliar para Formatar Dados

Adicionar antes de `handleAIReport`:

```go
func formatScanDataForPrompt(scan ScanResult) string {
	var metaMap map[string]interface{}
	json.Unmarshal([]byte(scan.Metadata), &metaMap)
	
	// Extract key information
	var exposedFiles []string
	if secAudit, ok := metaMap["security_audit"].(map[string]interface{}); ok {
		if exposed, ok := secAudit["exposed_files"].([]interface{}); ok {
			for _, file := range exposed {
				if fileMap, ok := file.(map[string]interface{}); ok {
					exposedFiles = append(exposedFiles, fmt.Sprintf("- %s (Status: %v, Severity: %s)", 
						fileMap["file"], fileMap["status"], fileMap["severity"]))
				}
			}
		}
	}
	
	result := fmt.Sprintf(`
## Arquivos Expostos (Status 200 OK)
%s

## Endpoints Detectados
%s

## Headers de Segurança
%s

## Metadados Completos
%s
`, 
		strings.Join(exposedFiles, "\n"),
		scan.Endpoints,
		extractSecurityHeaders(metaMap),
		scan.Metadata)
	
	return result
}

func extractSecurityHeaders(metaMap map[string]interface{}) string {
	if tech, ok := metaMap["tech"].(map[string]interface{}); ok {
		if headers, ok := tech["headers"].(map[string]interface{}); ok {
			return fmt.Sprintf(`
- HSTS: %v
- X-Frame-Options: %v
- X-Content-Type-Options: %v
- Server: %v
`, headers["hsts"], headers["xFrame"], headers["xContent"], headers["server"])
		}
	}
	return "Não disponível"
}
```

---

## ✅ CHECKLIST DE IMPLEMENTAÇÃO

### Antes de Implementar:
- [ ] Backup do main.go atual
- [ ] Ler código atual completo
- [ ] Entender estrutura de dados

### Durante Implementação:
- [ ] Substituir prompt
- [ ] Adicionar funções auxiliares
- [ ] Compilar e verificar erros
- [ ] Testar com scan existente

### Após Implementação:
- [ ] Gerar relatório de teste
- [ ] Verificar 9 seções presentes
- [ ] Validar qualidade do conteúdo
- [ ] Comparar com template VRP

---

## 🎯 RESULTADO ESPERADO

### Relatório Gerado Deve Ter:

1. ✅ Executive Summary
2. ✅ Vulnerabilidades Confirmadas (com CWE, evidências)
3. ✅ Vetores Teóricos (se houver)
4. ✅ Áreas de Investigação
5. ✅ Controles Positivos
6. ✅ **COMPLIANCE IMPACT** (LGPD, PCI-DSS, OWASP)
7. ✅ **REMEDIATION ROADMAP** (Fases 1, 2, 3)
8. ✅ **TESTING METHODOLOGY** (Scope, Tools, Limitations)
9. ✅ **DISCLAIMER** (Natureza, Limitações, Recomendações)

### Score Esperado:
- **Antes**: 8.0/10
- **Depois**: 10/10

---

## 🚀 PRÓXIMOS PASSOS

1. **Agora**: Implementar novo prompt
2. **Testar**: Gerar relatório com pobreflix.makeup
3. **Validar**: Verificar todas as 9 seções
4. **Ajustar**: Corrigir se necessário
5. **Documentar**: Atualizar CHANGELOG

---

**Status**: Pronto para implementação  
**Tempo estimado**: 1 hora  
**Impacto**: Eleva qualidade de 8.0 para 10/10
