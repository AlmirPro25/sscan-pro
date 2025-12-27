package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/google/generative-ai-go/genai"
	"google.golang.org/api/option"
)

// EnhancedReportRequest for generating AI report with advanced scan data
type EnhancedReportRequest struct {
	ScanID         uint   `json:"scan_id"`          // Main DAST scan ID
	AdvancedScanID uint   `json:"advanced_scan_id"` // Advanced scan ID
	LocalScanID    uint   `json:"local_scan_id"`    // Local SAST scan ID (optional)
	Model          string `json:"model"`
	ApiKey         string `json:"api_key"`
}

// handleEnhancedAIReport generates a comprehensive AI report combining all scan data
func handleEnhancedAIReport(c *gin.Context) {
	var input EnhancedReportRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	if input.Model == "" {
		input.Model = "models/gemini-2.5-flash"
	}

	// Collect all available data
	var dastData *ScanResult
	var advancedData *AdvancedScanResult
	var sastData *LocalScanResult

	// Fetch DAST scan if provided
	if input.ScanID > 0 {
		var scan ScanResult
		if err := db.First(&scan, input.ScanID).Error; err == nil {
			dastData = &scan
		}
	}

	// Fetch Advanced scan if provided
	if input.AdvancedScanID > 0 {
		var advanced AdvancedScanResult
		if err := db.First(&advanced, input.AdvancedScanID).Error; err == nil {
			advancedData = &advanced
		}
	}

	// Fetch SAST scan if provided
	if input.LocalScanID > 0 {
		var local LocalScanResult
		if err := db.First(&local, input.LocalScanID).Error; err == nil {
			sastData = &local
		}
	}

	if dastData == nil && advancedData == nil && sastData == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "At least one scan ID is required"})
		return
	}

	// Get API key
	apiKey := input.ApiKey
	if apiKey == "" {
		apiKey = os.Getenv("GEMINI_API_KEY")
	}

	if apiKey == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "GEMINI_API_KEY is not configured"})
		return
	}

	// Build comprehensive prompt
	prompt := buildEnhancedPrompt(dastData, advancedData, sastData)

	log.Printf("🤖 Generating enhanced AI report...")

	ctx := c.Request.Context()
	client, err := genai.NewClient(ctx, option.WithAPIKey(apiKey))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create Gemini client"})
		return
	}
	defer client.Close()

	model := client.GenerativeModel(input.Model)
	model.SetTemperature(0.3)
	model.SetMaxOutputTokens(16384) // Larger output for comprehensive report

	resp, err := model.GenerateContent(ctx, genai.Text(prompt))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate AI report: " + err.Error()})
		return
	}

	var reportContent string
	for _, cand := range resp.Candidates {
		if cand.Content != nil {
			for _, part := range cand.Content.Parts {
				reportContent += fmt.Sprintf("%v", part)
			}
		}
	}

	// Save report
	var scanResultID uint
	if dastData != nil {
		scanResultID = dastData.ID
	} else if advancedData != nil {
		scanResultID = advancedData.ID
	}

	aiReport := AIReport{
		ScanResultID: scanResultID,
		Model:        input.Model,
		Content:      reportContent,
	}

	if err := db.Create(&aiReport).Error; err != nil {
		log.Printf("⚠️ Failed to save AI report: %v", err)
	}

	c.JSON(http.StatusOK, gin.H{
		"id":      aiReport.ID,
		"model":   input.Model,
		"content": reportContent,
	})
}

func buildEnhancedPrompt(dast *ScanResult, advanced *AdvancedScanResult, sast *LocalScanResult) string {
	var target string
	if dast != nil {
		target = dast.Target
	} else if advanced != nil {
		target = advanced.URL
	} else if sast != nil {
		target = sast.Path
	}

	prompt := fmt.Sprintf(`Você é um Security Researcher Sênior especializado em auditoria de segurança enterprise.

**ALVO**: %s
**DATA**: %s

Você tem acesso a dados de múltiplas fontes de análise. Use TODOS os dados disponíveis para gerar um relatório completo e correlacionado.

`, target, "2025-12-27")

	// Add DAST data
	if dast != nil {
		var metadata map[string]interface{}
		json.Unmarshal([]byte(dast.Metadata), &metadata)
		
		prompt += fmt.Sprintf(`
## DADOS DE DAST (Dynamic Application Security Testing)

**Score**: %d/100
**Endpoints Detectados**: %s

**Metadados**:
%s

`, dast.Score, dast.Endpoints, dast.Metadata)
	}

	// Add Advanced scan data
	if advanced != nil {
		prompt += `
## DADOS DE ANÁLISE AVANÇADA

`
		// Infrastructure
		if advanced.Infrastructure != "" && advanced.Infrastructure != "null" {
			var infra map[string]interface{}
			json.Unmarshal([]byte(advanced.Infrastructure), &infra)
			infraJSON, _ := json.MarshalIndent(infra, "", "  ")
			prompt += fmt.Sprintf(`### Infraestrutura (Portas, Cloud, SSL)
%s

`, string(infraJSON))
		}

		// Subdomains
		if advanced.Subdomains != "" && advanced.Subdomains != "null" {
			var subs map[string]interface{}
			json.Unmarshal([]byte(advanced.Subdomains), &subs)
			subsJSON, _ := json.MarshalIndent(subs, "", "  ")
			prompt += fmt.Sprintf(`### Subdomínios
%s

`, string(subsJSON))
		}

		// Reputation
		if advanced.Reputation != "" && advanced.Reputation != "null" {
			var rep map[string]interface{}
			json.Unmarshal([]byte(advanced.Reputation), &rep)
			repJSON, _ := json.MarshalIndent(rep, "", "  ")
			prompt += fmt.Sprintf(`### Reputação (Blacklists, Email Security)
%s

`, string(repJSON))
		}

		// Authenticated
		if advanced.Authenticated != "" && advanced.Authenticated != "null" {
			var auth map[string]interface{}
			json.Unmarshal([]byte(advanced.Authenticated), &auth)
			authJSON, _ := json.MarshalIndent(auth, "", "  ")
			prompt += fmt.Sprintf(`### Análise Autenticada (Session, IDOR)
%s

`, string(authJSON))
		}
	}

	// Add SAST data
	if sast != nil {
		prompt += fmt.Sprintf(`
## DADOS DE SAST (Static Application Security Testing)

**Caminho**: %s
**Arquivos Escaneados**: %d
**Linhas de Código**: %d
**Score**: %d/100

**Vulnerabilidades no Código**:
%s

`, sast.Path, sast.FilesScanned, sast.LinesScanned, sast.Score, sast.Vulnerabilities)
	}

	// Instructions
	prompt += `
## INSTRUÇÕES PARA O RELATÓRIO

Gere um relatório de segurança COMPLETO e CORRELACIONADO em Markdown PT-BR com as seguintes seções:

### 1. Executive Summary
- Visão geral do estado de segurança
- Principais riscos identificados
- Score geral e justificativa

### 2. Correlação de Vulnerabilidades
**IMPORTANTE**: Correlacione dados de diferentes fontes. Por exemplo:
- Se SAST encontrou API key hardcoded E DAST encontrou endpoint usando essa API → CRITICAL
- Se Infrastructure encontrou porta de DB aberta E SAST tem connection string → CRITICAL
- Se Subdomains encontrou dev.site.com E DAST encontrou dados sensíveis → HIGH

### 3. Vulnerabilidades por Categoria
Agrupe por:
- Infraestrutura (portas, SSL, cloud)
- Aplicação (XSS, SQLi, IDOR)
- Código (secrets, injection patterns)
- Configuração (headers, CORS, cookies)

### 4. Análise de Superfície de Ataque
- Subdomínios expostos
- Endpoints descobertos
- Vetores de ataque identificados

### 5. Impacto no Negócio
- Riscos de compliance (LGPD, PCI-DSS)
- Impacto financeiro potencial
- Riscos reputacionais

### 6. Roadmap de Remediação
Priorizado por:
1. CRITICAL (24-48h)
2. HIGH (1 semana)
3. MEDIUM (2 semanas)
4. LOW (1 mês)

### 7. Controles Positivos
Liste as boas práticas já implementadas.

### 8. Recomendações Estratégicas
Sugestões de longo prazo para melhorar a postura de segurança.

**TOM**: Profissional, técnico, baseado em evidências. Sem sensacionalismo.
**FORMATO**: Markdown bem estruturado com emojis profissionais (✅, ⚠️, 🔴, etc.)
`

	return prompt
}
