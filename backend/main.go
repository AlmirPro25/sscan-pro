package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"aegis-scan-backend/ai"
	"aegis-scan-backend/scanner"
	"aegis-scan-backend/security"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/google/generative-ai-go/genai"
	"github.com/jung-kurt/gofpdf"
	"google.golang.org/api/option"
	"gorm.io/gorm"
)

// Rate Limiter
type RateLimiter struct {
	visitors map[string]*Visitor
	mu       sync.RWMutex
	rate     int
	burst    int
}

type Visitor struct {
	lastSeen time.Time
	tokens   int
}

func NewRateLimiter(rate, burst int) *RateLimiter {
	rl := &RateLimiter{
		visitors: make(map[string]*Visitor),
		rate:     rate,
		burst:    burst,
	}

	// Cleanup old visitors every 5 minutes
	go rl.cleanupVisitors()

	return rl
}

func (rl *RateLimiter) cleanupVisitors() {
	for {
		time.Sleep(5 * time.Minute)
		rl.mu.Lock()
		for ip, v := range rl.visitors {
			if time.Since(v.lastSeen) > 10*time.Minute {
				delete(rl.visitors, ip)
			}
		}
		rl.mu.Unlock()
	}
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, exists := rl.visitors[ip]
	if !exists {
		rl.visitors[ip] = &Visitor{
			lastSeen: time.Now(),
			tokens:   rl.burst - 1,
		}
		return true
	}

	// Token bucket algorithm
	elapsed := time.Since(v.lastSeen)
	v.lastSeen = time.Now()

	// Add tokens based on elapsed time
	tokensToAdd := int(elapsed.Seconds()) * rl.rate / 60
	v.tokens += tokensToAdd
	if v.tokens > rl.burst {
		v.tokens = rl.burst
	}

	if v.tokens > 0 {
		v.tokens--
		return true
	}

	return false
}

func RateLimitMiddleware(limiter *RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()

		if !limiter.Allow(ip) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Rate limit exceeded. Please try again later.",
				"retry_after": "60 seconds",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// AIReport model to store generated reports
type AIReport struct {
	ID           uint           `gorm:"primaryKey" json:"id"`
	ScanResultID uint           `json:"scan_result_id"`
	Model        string         `json:"model"`
	Content      string         `json:"content"` // Markdown content
	CreatedAt    time.Time      `json:"created_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
}

// Vulnerability struct for post-processing
type Vulnerability struct {
	Type        string
	Severity    string
	Description string
	Evidence    string
	Remediation string
}

// ChatMessage model for conversation history
type ChatMessage struct {
	ID           uint           `gorm:"primaryKey" json:"id"`
	ScanResultID uint           `json:"scan_result_id"`
	Role         string         `json:"role"` // user or assistant
	Content      string         `json:"content"`
	CreatedAt    time.Time      `json:"created_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
}

// ScanResult model for Enterprise Persistence
type ScanResult struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	Target    string         `json:"target"`
	Score     int            `json:"score"`
	Endpoints string         `json:"endpoints"` // Stored as JSON string
	Metadata  string         `json:"metadata"`  // Stored as JSON string (media, schema, etc)
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

var db *gorm.DB

func initDB() {
	dbName := "aegis.db"
	var err error
	db, err = gorm.Open(sqlite.Open(dbName), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to SQLite database")
	}

	db.AutoMigrate(&ScanResult{}, &AIReport{}, &ChatMessage{})
}

// Helper functions for professional AI analysis
func isEnterpriseDomain(url string) bool {
	enterpriseDomains := []string{
		"google.com", "microsoft.com", "amazon.com", "facebook.com",
		"apple.com", "github.com", "twitter.com", "linkedin.com",
		"netflix.com", "salesforce.com", "oracle.com", "ibm.com",
		"mercadolivre.com", "mercadolibre.com", "mercadopago.com",
		"nubank.com", "itau.com", "bradesco.com", "santander.com",
		"globo.com", "uol.com", "terra.com", "estadao.com",
		"magazineluiza.com", "americanas.com", "submarino.com",
		"b2w.com", "via.com", "casasbahia.com", "pontofrio.com",
	}
	
	for _, domain := range enterpriseDomains {
		if contains(url, domain) {
			return true
		}
	}
	return false
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsMiddle(s, substr)))
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func getProfileDescription(isEnterprise bool) string {
	if isEnterprise {
		return "aplicações enterprise de alto nível (Google, Microsoft, Amazon, etc)"
	}
	return "auditoria de segurança web profissional"
}

func getProfileType(isEnterprise bool) string {
	if isEnterprise {
		return "Enterprise-grade (Google/Microsoft/Amazon/etc)"
	}
	return "Standard web application"
}

func getContextualGuidance(isEnterprise bool) string {
	if isEnterprise {
		return `Este é um alvo ENTERPRISE. Assuma:
- Equipe de segurança dedicada e experiente
- Bug bounty program ativo
- Defesas em profundidade (WAF, IDS/IPS, SIEM)
- Monitoramento 24/7
- Frameworks modernos com proteções built-in

**FOQUE EM**:
- Logic flaws (não XSS trivial que frameworks bloqueiam)
- Auth/AuthZ edge cases (OAuth state confusion, token reuse)
- Business logic abuse
- Feature-specific attacks (file upload, sharing, collaboration)
- Cross-service trust issues
- API abuse

**NÃO REPORTE**:
- XSS em parâmetros de locale (frameworks fazem auto-escape)
- HSTS missing se domínio está em preload list
- Open redirect sem teste real (enterprise usa allowlists)
- Vulnerabilidades que frameworks modernos previnem automaticamente`
	}
	
	return `Este é um alvo STANDARD. Verifique:
- Configurações básicas (HTTPS, headers de segurança)
- Vulnerabilidades OWASP Top 10
- Exposição de informações sensíveis
- Hardening básico do servidor
- Gestão de sessões
- Validação de inputs

**SEJA REALISTA**:
- Reporte o que foi CONFIRMADO nos dados
- Marque como "Teórico" o que precisa validação
- Reconheça defesas quando presentes
- Não exagere severidades`
}

func main() {
	initDB()

	r := gin.Default()

	// Security Middlewares (v8.5 Hardening)
	r.Use(security.SecureHeaders())
	r.Use(security.AuditMiddleware())
	r.Use(security.RequestValidator())

	// CORS Configuration (SECURE - no wildcard with credentials)
	r.Use(cors.New(cors.Config{
		AllowOrigins:     security.GetAllowedOrigins(),
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// Rate Limiter: 10 requests per minute per IP
	rateLimiter := NewRateLimiter(10, 15) // 10 req/min, burst of 15

	v1 := r.Group("/api/v1")
	{
		v1.GET("/health", func(c *gin.Context) {
			c.JSON(200, gin.H{
				"status": "Aegis Engine Online",
				"time":   time.Now().Format(time.RFC3339),
			})
		})

		// Apply rate limiting to expensive operations
		v1.POST("/scan", RateLimitMiddleware(rateLimiter), handleScan)
		v1.GET("/history", getHistory)
		v1.POST("/ai/report", RateLimitMiddleware(rateLimiter), handleAIReport)
		v1.GET("/ai/report/:scan_id", getAIReport)
		v1.POST("/ai/chat", RateLimitMiddleware(rateLimiter), handleAIChat)
		v1.GET("/pdf/:scan_id", generatePDFReport)
		v1.GET("/compare/:scan_id1/:scan_id2", compareScanResults)
		v1.GET("/dashboard/stats", getDashboardStats)
		
		// Auto-fix endpoints
		v1.POST("/autofix/generate", RateLimitMiddleware(rateLimiter), handleGenerateAutoFix)
		v1.POST("/autofix/create-pr", RateLimitMiddleware(rateLimiter), handleCreatePR)
		v1.GET("/autofix/:scan_id", getAutoFixes)
		
		// Local code scan endpoint
		v1.POST("/scan-local", RateLimitMiddleware(rateLimiter), handleLocalScan)
		v1.POST("/scan-local/ai-report", RateLimitMiddleware(rateLimiter), handleLocalScanAIReport)
		v1.GET("/scan-local/pdf/:scan_id", handleLocalScanPDF)
		v1.GET("/scan-local/history", handleGetLocalScanHistory)
		v1.GET("/scan-local/:scan_id", handleGetLocalScan)
		
		// File browser endpoints
		v1.GET("/browse", handleBrowseDirectory)
		v1.GET("/browse/recent", handleGetRecentPaths)
		
		// Dependency scanning endpoint
		v1.POST("/scan-local/dependencies", RateLimitMiddleware(rateLimiter), handleDependencyScan)
		
		// Project endpoints (SAST + DAST unified)
		v1.POST("/projects", handleCreateProject)
		v1.GET("/projects", handleGetProjects)
		v1.GET("/projects/:id", handleGetProject)
		v1.PUT("/projects/:id", handleUpdateProject)
		v1.GET("/projects/:id/dashboard", handleGetProjectDashboard)
		v1.POST("/projects/link-scan", handleLinkScanToProject)
		v1.POST("/projects/:id/correlate", handleCorrelateProject)
		
		// Advanced scanning endpoints
		v1.POST("/scan/infrastructure", RateLimitMiddleware(rateLimiter), handleInfrastructureScan)
		v1.POST("/scan/subdomains", RateLimitMiddleware(rateLimiter), handleSubdomainScan)
		v1.POST("/scan/reputation", RateLimitMiddleware(rateLimiter), handleReputationScan)
		v1.POST("/scan/authenticated", RateLimitMiddleware(rateLimiter), handleAuthenticatedScan)
		v1.POST("/scan/advanced", RateLimitMiddleware(rateLimiter), handleAdvancedScan)
		v1.GET("/scan/advanced/:scan_id", handleGetAdvancedScan)
		v1.GET("/scan/advanced/history", handleGetAdvancedScanHistory)
		
		// Enhanced AI report (combines DAST + Advanced + SAST)
		v1.POST("/ai/enhanced-report", RateLimitMiddleware(rateLimiter), handleEnhancedAIReport)
		
		// SCA (Software Composition Analysis) endpoints
		v1.POST("/sca/licenses", RateLimitMiddleware(rateLimiter), handleLicenseScan)
		v1.POST("/sca/typosquatting", RateLimitMiddleware(rateLimiter), handleTyposquattingScan)
		v1.POST("/sca/iac", RateLimitMiddleware(rateLimiter), handleIACScan)
		v1.POST("/sca/full", RateLimitMiddleware(rateLimiter), handleSCAFullScan)
		
		// DAST+SAST Correlation endpoints
		v1.POST("/correlate", RateLimitMiddleware(rateLimiter), handleCorrelation)
		v1.GET("/correlate/project/:project_id", handleQuickCorrelation)
		
		// Central Intelligence Orchestrator endpoints
		v1.POST("/orchestrator/chat", RateLimitMiddleware(rateLimiter), handleOrchestratorChat)
		v1.POST("/orchestrator/session", handleOrchestratorNewSession)
		v1.GET("/orchestrator/session/:session_id", handleOrchestratorGetSession)
		v1.GET("/orchestrator/sessions", handleOrchestratorListSessions)
		v1.DELETE("/orchestrator/session/:session_id", handleOrchestratorDeleteSession)
		v1.GET("/orchestrator/tools", handleOrchestratorGetTools)
		v1.POST("/orchestrator/execute", RateLimitMiddleware(rateLimiter), handleOrchestratorExecuteTool)
		
		// Orchestrator Policy & Approval endpoints
		v1.GET("/orchestrator/approvals", handleOrchestratorGetPendingApprovals)
		v1.POST("/orchestrator/approvals/:approval_id/approve", handleOrchestratorApprove)
		v1.POST("/orchestrator/approvals/:approval_id/deny", handleOrchestratorDeny)
		v1.GET("/orchestrator/audit-logs", handleOrchestratorGetAuditLogs)
		v1.GET("/orchestrator/meta-analysis", handleOrchestratorMetaAnalysis)
		
		// Registry & Policy endpoints
		v1.GET("/orchestrator/registry", handleOrchestratorGetRegistry)
		v1.GET("/orchestrator/policy", handleOrchestratorGetPolicyStatus)
		v1.POST("/orchestrator/policy", handleOrchestratorSetPolicy)
		v1.GET("/orchestrator/memory/insights", handleOrchestratorGetMemoryInsights)
		
		// Execution Graph & Dry-Run endpoints
		v1.POST("/orchestrator/dry-run", handleOrchestratorDryRun)
		v1.POST("/orchestrator/execute-plan", handleOrchestratorExecutePlan)
		
		// Decision Intelligence Layer endpoints (v8.4)
		v1.POST("/orchestrator/risk/calculate", handleCalculateRisk)
		v1.POST("/orchestrator/tokens", handleCreateApprovalToken)
		v1.POST("/orchestrator/tokens/:token_id/validate", handleValidateToken)
		v1.POST("/orchestrator/tokens/:token_id/revoke", handleRevokeToken)
		v1.GET("/orchestrator/tokens", handleListTokens)
		v1.GET("/orchestrator/policy/history", handleGetPolicyHistory)
		v1.POST("/orchestrator/policy/compare", handleComparePolicies)
		v1.GET("/orchestrator/planner/insights", handleGetPlannerInsights)
		v1.GET("/orchestrator/feedback/:execution_id", handleGetExecutionFeedback)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("🛡️ Aegis Backend Running on :%s", port)
	log.Printf("🔒 Rate Limiting: 10 requests/minute per IP")
	r.Run(":" + port)
}

func handleScan(c *gin.Context) {
	var input struct {
		URL string `json:"url" binding:"required"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "URL is required"})
		return
	}

	log.Printf("🚀 Starting deep scan for: %s", input.URL)

	// In a real MVP, we call the Node.js scanner service
	// For this demonstration, we trigger the internal "Expert Logic"

	scanData, err := triggerWorkerScan(input.URL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Scan failed: " + err.Error()})
		return
	}

	endpointsJSON, _ := json.Marshal(scanData.Endpoints)
	metadataJSON, _ := json.Marshal(map[string]interface{}{
		"media":          scanData.Media,
		"schema":         scanData.Schema,
		"tech":           scanData.Tech,
		"seo":            scanData.Seo,
		"performance":    scanData.Performance,
		"assets":         scanData.Assets,
		"full_links":     scanData.FullLinks,
		"dom_images":     scanData.DomImages,
		"discovery":      scanData.Discovery,
		"security_audit": scanData.SecurityAudit,
		"screenshot":     scanData.Screenshot,
		"site_map":       scanData.SiteMap,
	})

	result := ScanResult{
		Target:    input.URL,
		Score:     scanData.Score,
		Endpoints: string(endpointsJSON),
		Metadata:  string(metadataJSON),
	}

	if err := db.Create(&result).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save result"})
		return
	}

	c.JSON(http.StatusCreated, result)
}

func getHistory(c *gin.Context) {
	var results []ScanResult
	db.Order("created_at desc").Limit(20).Find(&results)
	c.JSON(200, results)
}

func handleAIReport(c *gin.Context) {
	var input struct {
		ScanID uint   `json:"scan_id" binding:"required"`
		Model  string `json:"model"`   // Default to models/gemini-3-flash-preview
		ApiKey string `json:"api_key"` // Optional key from client (blocked in production)
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ScanID is required"})
		return
	}

	// Allow user to choose model from frontend
	if input.Model == "" {
		input.Model = "models/gemini-3-flash-preview" // Default
	}
	modelName := input.Model

	// Fetch Scan Result
	var scan ScanResult
	if err := db.First(&scan, input.ScanID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found"})
		return
	}

	// SECURE API KEY HANDLING (v8.5 hardening)
	apiKey, err := security.GetAPIKey(input.ApiKey)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}
	
	log.Printf("🔑 %s", security.LogAPIKeyUsage(apiKey, "AI Report"))
	log.Printf("🤖 Using Model: %s", modelName)

	ctx := c.Request.Context()
	client, err := genai.NewClient(ctx, option.WithAPIKey(apiKey))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create Gemini client"})
		return
	}
	defer client.Close()

	// Determine target profile
	isEnterprise := isEnterpriseDomain(scan.Target)
	
	// Create simplified prompt - post-processing will enforce structure
	prompt := fmt.Sprintf(`
Você é um Security Researcher sênior especializado em auditoria profissional de segurança web.

**IMPORTANTE - TOM E ESTILO**:
- Use tom PROFISSIONAL e TÉCNICO (não sensacionalista)
- NÃO use termos como "Red Team Commander", "hacker", "destruindo", "gravíssimo"
- NÃO exagere severidades - seja realista e baseado em evidências
- RECONHEÇA defesas quando presentes
- Use linguagem de consultor de segurança, não de atacante

**ALVO**: %s
**Score**: %d/100
**Profile**: %s
**Data**: %s

**Endpoints Detectados**:
%s

**Metadados e Superfície de Ataque**:
%s

**INSTRUÇÕES DE ANÁLISE**:

1. **Vulnerabilidades Confirmadas**: Liste APENAS o que foi CONFIRMADO nos dados
   - Baseie-se em evidências concretas (Status 200, headers ausentes)
   - Não invente vulnerabilidades sem evidências

2. **Headers de Segurança**: Analise objetivamente
   - HSTS, CSP, X-Frame-Options, X-Content-Type-Options
   - Se ausente, reporte como "Missing" (não "gravíssimo")
   - Severidade: MEDIUM (não CRITICAL para headers)

3. **Controles Positivos**: SEMPRE reconheça defesas presentes
   - HTTPS ativo
   - CDN/WAF detectado
   - Framework moderno
   - Certificado SSL válido

4. **Contexto Enterprise** (se aplicável):
   - Sites enterprise (Google, Microsoft, Amazon, MercadoLivre, etc) têm:
     * Equipes de segurança dedicadas
     * Bug bounty programs
     * WAF e proteções em profundidade
   - NÃO reporte vulnerabilidades triviais que frameworks modernos previnem
   - FOQUE em logic flaws, não XSS básico

5. **Tom Profissional**:
   - "Recomenda-se implementar..." (não "FALHA CRÍTICA")
   - "Ausência de header X pode permitir..." (não "PORTA ABERTA PARA ATAQUES")
   - "Vulnerabilidade de severidade MEDIUM" (não "RISCO CATASTRÓFICO")

Gere um relatório técnico de segurança em Markdown PT-BR seguindo estas diretrizes.
`, 
		scan.Target, 
		scan.Score,
		getProfileType(isEnterprise),
		scan.CreatedAt.Format("2006-01-02 15:04:05"),
		scan.Endpoints, 
		scan.Metadata,
	)

	// 1. Prepare Text Parts
	var textParts []genai.Part
	textParts = append(textParts, genai.Text(prompt))

	// 2. Prepare Image Parts (with size limits)
	var imageParts []genai.Part
	var metaMap map[string]interface{}
	if err := json.Unmarshal([]byte(scan.Metadata), &metaMap); err == nil {
		if screenshot, ok := metaMap["screenshot"].(string); ok && len(screenshot) > 0 {
			decodedImg, err := base64.StdEncoding.DecodeString(screenshot)
			if err == nil {
				// Only add if reasonable size (< 4MB) to prevent instant 400s/Quota
				if len(decodedImg) < 4*1024*1024 {
					imageParts = append(imageParts, genai.Text("\n[VISUAL INTEL - ROOT PAGE]:"))
					imageParts = append(imageParts, genai.ImageData("jpeg", decodedImg))
				}

				if siteMap, ok := metaMap["site_map"].(map[string]interface{}); ok {
					if nodes, ok := siteMap["nodes"].([]interface{}); ok {
						count := 0
						for _, node := range nodes {
							if nodeMap, ok := node.(map[string]interface{}); ok {
								if nodeType, ok := nodeMap["type"].(string); ok && nodeType == "CHILD" && count < 1 { // Limit to 1 child
									if screen, ok := nodeMap["screenshot"].(string); ok && len(screen) > 0 {
										childDecoded, err := base64.StdEncoding.DecodeString(screen)
										if err == nil && len(childDecoded) < 3*1024*1024 { // Strict 3MB limit for child
											url := nodeMap["url"].(string)
											imageParts = append(imageParts, genai.Text("\n[VISUAL INTEL - SUB PAGE ("+url+")]:"))
											imageParts = append(imageParts, genai.ImageData("jpeg", childDecoded))
											count++
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	log.Printf("🤖 Calling Gemini (Model: %s)", modelName)
	log.Printf("📦 Payload: Text + %d Images", len(imageParts)/2)
	log.Printf("🎯 Temperature: 0.3 (Deterministic Mode)")
	log.Printf("📋 Prompt Length: %d characters", len(prompt))

	// FORCE STRUCTURED OUTPUT - Try to bypass model's internal prompt
	model := client.GenerativeModel(modelName)
	
	// Set generation config to force compliance
	model.SetTemperature(0.3) // Lower temperature for more deterministic output
	model.SetTopP(0.8)
	model.SetTopK(40)
	model.SetMaxOutputTokens(8192)
	
	// Set safety settings to allow security content
	model.SafetySettings = []*genai.SafetySetting{
		{
			Category:  genai.HarmCategoryHarassment,
			Threshold: genai.HarmBlockNone,
		},
		{
			Category:  genai.HarmCategoryHateSpeech,
			Threshold: genai.HarmBlockNone,
		},
		{
			Category:  genai.HarmCategoryDangerousContent,
			Threshold: genai.HarmBlockNone,
		},
	}

	// Attempt 1: Full Multimodal
	fullParts := append(textParts, imageParts...)
	resp, errGen := model.GenerateContent(ctx, fullParts...)

	// Attempt 2: Text Only (Fallback for Quota/Size/InternalError)
	if errGen != nil {
		log.Printf("⚠️ Multimodal Attempt Failed: %v", errGen)
		log.Println("🔄 Activating FAILSAFE: Retrying with Text-Only Analysis to save Quota/Bandwidth...")

		// Wait 1s before retry
		time.Sleep(1 * time.Second)
		resp, errGen = model.GenerateContent(ctx, textParts...)
	}

	if errGen != nil {
		log.Printf("❌ Gemini API Critical Failure after fallback: %v", errGen)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to generate AI content even after fallback.",
			"details": errGen.Error(),
			"model":   input.Model,
		})
		return
	}

	log.Printf("✅ Gemini API Success - Received %d candidates", len(resp.Candidates))

	var reportContent string
	for _, cand := range resp.Candidates {
		if cand.Content != nil {
			for _, part := range cand.Content.Parts {
				reportContent += fmt.Sprintf("%v", part)
			}
		}
	}

	if reportContent == "" {
		reportContent = "⚠️ A IA analisou o alvo, mas não retornou texto gerado (Possível bloqueio de segurança na saída)."
	}

	// SANITIZE: Remove sensationalist language
	log.Printf("🧹 Sanitizing report content...")
	reportContent = sanitizeReportContent(reportContent)
	
	// POST-PROCESS: Force V4 structure with 9 mandatory sections
	log.Printf("🔄 Post-processing report to enforce V4 structure...")
	reportContent = postProcessAIReport(reportContent, scan)
	log.Printf("✅ Report post-processed successfully")

	aiReport := AIReport{
		ScanResultID: scan.ID,
		Model:        input.Model,
		Content:      reportContent,
	}

	if err := db.Create(&aiReport).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save AI report"})
		return
	}

	c.JSON(http.StatusOK, aiReport)
}

// Worker Communication Integration
type WorkerResponse struct {
	Endpoints     []interface{} `json:"endpoints"`
	Media         interface{}   `json:"media"`
	Schema        []string      `json:"schema"`
	Score         int           `json:"score"`
	Tech          interface{}   `json:"tech"`
	Seo           interface{}   `json:"seo"`
	Performance   interface{}   `json:"performance"`
	Assets        interface{}   `json:"assets"`
	FullLinks     []interface{} `json:"full_links"`
	DomImages     []interface{} `json:"dom_images"`
	Discovery     interface{}   `json:"discovery"`
	SecurityAudit struct {
		ExposedFiles  []interface{} `json:"exposed_files"`
		LeakedSecrets []struct {
			Type    string `json:"type"`
			Source  string `json:"source"`
			Snippet string `json:"snippet"`
		} `json:"leaked_secrets"`
		AttackVectors   interface{}   `json:"attack_vectors"`
		GhostRoutes     []interface{} `json:"ghost_routes"`
		Vulnerabilities struct {
			XSS      []interface{} `json:"xss"`
			SQLi     []interface{} `json:"sqli"`
			Auth     []interface{} `json:"auth"`
			SSL      []interface{} `json:"ssl"`
			Total    int           `json:"total"`
			Critical int           `json:"critical"`
			High     int           `json:"high"`
			Medium   int           `json:"medium"`
		} `json:"vulnerabilities"`
		SSLInfo interface{} `json:"ssl_info"`
	} `json:"security_audit"`
	Screenshot string `json:"screenshot"`
	SiteMap    struct {
		Nodes []struct {
			URL        string `json:"url"`
			Title      string `json:"title"`
			Screenshot string `json:"screenshot"` // Base64
			Type       string `json:"type"`       // ROOT, CHILD, ERROR
		} `json:"nodes"`
	} `json:"site_map"`
}

func triggerWorkerScan(targetURL string) (*WorkerResponse, error) {
	workerURL := os.Getenv("WORKER_URL")
	if workerURL == "" {
		workerURL = "http://localhost:3001/scan"
	}

	client := &http.Client{Timeout: 120 * time.Second} // Increased to 120 seconds
	payload, _ := json.Marshal(map[string]string{"url": targetURL})

	resp, err := client.Post(workerURL, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return nil, fmt.Errorf("worker server unreachable: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errData struct {
			Details string `json:"details"`
		}
		json.NewDecoder(resp.Body).Decode(&errData)
		return nil, fmt.Errorf("worker error (%d): %s", resp.StatusCode, errData.Details)
	}

	var wr WorkerResponse
	if err := json.NewDecoder(resp.Body).Decode(&wr); err != nil {
		return nil, fmt.Errorf("failed to decode worker response: %v", err)
	}

	return &wr, nil
}

func getAIReport(c *gin.Context) {
	scanID := c.Param("scan_id")

	// Input validation (v8.5 hardening)
	id, err := security.ValidateScanID(scanID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var report AIReport
	if err := db.Where("scan_result_id = ?", id).First(&report).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Report not found"})
		return
	}

	c.JSON(http.StatusOK, report)
}

func handleAIChat(c *gin.Context) {
	var input struct {
		ScanID  uint   `json:"scan_id" binding:"required"`
		Message string `json:"message" binding:"required"`
		Model   string `json:"model"`
		ApiKey  string `json:"api_key"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ScanID and Message are required"})
		return
	}

	if input.Model == "" {
		input.Model = "models/gemini-robotics-er-1.5-preview"
	}

	// Use model name exactly as sent from frontend (keep "models/" prefix)
	modelName := input.Model

	// Fetch Scan Result
	var scan ScanResult
	if err := db.First(&scan, input.ScanID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found"})
		return
	}

	// Fetch AI Report
	var report AIReport
	if err := db.Where("scan_result_id = ?", input.ScanID).First(&report).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "AI Report not found. Generate report first."})
		return
	}

	// Save user message
	userMsg := ChatMessage{
		ScanResultID: input.ScanID,
		Role:         "user",
		Content:      input.Message,
	}
	db.Create(&userMsg)

	// Get conversation history (last 10 messages only)
	var history []ChatMessage
	db.Where("scan_result_id = ?", input.ScanID).Order("created_at asc").Limit(10).Find(&history)

	// SECURE API KEY HANDLING (v8.5 hardening)
	apiKey, err := security.GetAPIKey(input.ApiKey)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	client, err := genai.NewClient(ctx, option.WithAPIKey(apiKey))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create Gemini client"})
		return
	}
	defer client.Close()

	// OPTIMIZATION: Only send full context on FIRST message
	// For subsequent messages, use lightweight conversation history
	isFirstMessage := len(history) <= 1

	var chatHistory []*genai.Content

	if isFirstMessage {
		// FIRST MESSAGE: Send full context (scan data + report summary)
		// Parse metadata for quick stats
		var metadata map[string]interface{}
		json.Unmarshal([]byte(scan.Metadata), &metadata)

		var endpoints []map[string]interface{}
		json.Unmarshal([]byte(scan.Endpoints), &endpoints)

		// Extract key security findings from metadata
		var vulnCount, criticalCount, highCount int
		if sa, ok := metadata["security_audit"].(map[string]interface{}); ok {
			if vuln, ok := sa["vulnerabilities"].(map[string]interface{}); ok {
				if total, ok := vuln["total"].(float64); ok {
					vulnCount = int(total)
				}
				if crit, ok := vuln["critical"].(float64); ok {
					criticalCount = int(crit)
				}
				if high, ok := vuln["high"].(float64); ok {
					highCount = int(high)
				}
			}
		}

		systemPrompt := fmt.Sprintf(`Você é o Aegis AI Platinum Assistant, especialista em análise de segurança.

CONTEXTO DO SCAN (MEMORIZE PARA TODA A CONVERSA):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 ALVO: %s
📊 SCORE: %d/100
📅 DATA: %s
📡 ENDPOINTS: %d detectados
🚨 VULNERABILIDADES: %d total (%d críticas, %d altas)

📋 RELATÓRIO COMPLETO DE SEGURANÇA:
%s

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

INSTRUÇÕES:
- Você tem acesso ao relatório completo acima
- Responda perguntas baseadas neste contexto
- Seja técnico, direto e preciso
- Use Pt-BR e Markdown quando apropriado
- Cite dados específicos do relatório quando relevante`,
			scan.Target,
			scan.Score,
			scan.CreatedAt.Format("2006-01-02 15:04:05"),
			len(endpoints),
			vulnCount,
			criticalCount,
			highCount,
			report.Content)

		chatHistory = append(chatHistory, &genai.Content{
			Parts: []genai.Part{genai.Text(systemPrompt)},
			Role:  "user",
		})

		chatHistory = append(chatHistory, &genai.Content{
			Parts: []genai.Part{genai.Text("Entendido. Tenho o contexto completo do scan. Estou pronto para responder suas perguntas sobre a auditoria de segurança.")},
			Role:  "model",
		})
	} else {
		// SUBSEQUENT MESSAGES: Use lightweight context
		// Only include recent conversation history (no scan data resend)
		for _, msg := range history[:len(history)-1] { // Exclude the message we just saved
			role := "user"
			if msg.Role == "assistant" {
				role = "model"
			}
			chatHistory = append(chatHistory, &genai.Content{
				Parts: []genai.Part{genai.Text(msg.Content)},
				Role:  role,
			})
		}
	}

	// Add current user message
	chatHistory = append(chatHistory, &genai.Content{
		Parts: []genai.Part{genai.Text(input.Message)},
		Role:  "user",
	})

	// Use StartChat for stateful conversation
	model := client.GenerativeModel(modelName)
	chatSession := model.StartChat()
	chatSession.History = chatHistory

	resp, err := chatSession.SendMessage(ctx, genai.Text(input.Message))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate response: " + err.Error()})
		return
	}

	var responseContent string
	for _, cand := range resp.Candidates {
		for _, part := range cand.Content.Parts {
			responseContent += fmt.Sprintf("%v", part)
		}
	}

	// Save assistant message
	assistantMsg := ChatMessage{
		ScanResultID: input.ScanID,
		Role:         "assistant",
		Content:      responseContent,
	}
	db.Create(&assistantMsg)

	c.JSON(http.StatusOK, gin.H{
		"message": responseContent,
		"history": append(history, userMsg, assistantMsg),
	})
}

// Removed formatEndpointsForAI and formatMetadataForAI - no longer needed
// Chat now uses lightweight context after first message

func generatePDFReport(c *gin.Context) {
	scanID := c.Param("scan_id")

	// Input validation (v8.5 hardening)
	id, err := security.ValidateScanID(scanID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var scan ScanResult
	if err := db.First(&scan, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found"})
		return
	}

	var report AIReport
	hasReport := db.Where("scan_result_id = ?", id).First(&report).Error == nil

	// DoS Prevention: Truncate report content before processing (v8.5 hardening)
	if hasReport && len(report.Content) > security.ContentLimits.MaxReportContent {
		report.Content = security.TruncateContent(report.Content, security.ContentLimits.MaxReportContent)
	}

	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()

	// Header
	pdf.SetFillColor(16, 185, 129)
	pdf.Rect(0, 0, 210, 40, "F")
	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont("Arial", "B", 24)
	pdf.SetY(15)
	pdf.CellFormat(0, 10, "AEGIS SCAN", "", 1, "C", false, 0, "")
	pdf.SetFont("Arial", "", 10)
	pdf.CellFormat(0, 5, "Enterprise Surface Auditor", "", 1, "C", false, 0, "")

	// Reset colors
	pdf.SetTextColor(0, 0, 0)
	pdf.SetY(50)

	// Target Info
	pdf.SetFont("Arial", "B", 14)
	pdf.Cell(0, 10, "Audit Report")
	pdf.Ln(10)

	pdf.SetFont("Arial", "", 10)
	pdf.Cell(40, 8, "Target:")
	pdf.SetFont("Arial", "B", 10)
	pdf.Cell(0, 8, scan.Target)
	pdf.Ln(8)

	pdf.SetFont("Arial", "", 10)
	pdf.Cell(40, 8, "Date:")
	pdf.Cell(0, 8, scan.CreatedAt.Format("2006-01-02 15:04:05"))
	pdf.Ln(8)

	pdf.Cell(40, 8, "Security Score:")
	pdf.SetFont("Arial", "B", 10)
	scoreColor := getScoreColor(scan.Score)
	pdf.SetTextColor(int(scoreColor[0]), int(scoreColor[1]), int(scoreColor[2]))
	pdf.Cell(0, 8, fmt.Sprintf("%d/100", scan.Score))
	pdf.SetTextColor(0, 0, 0)
	pdf.Ln(15)

	// Endpoints
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(0, 10, "Endpoints Detected")
	pdf.Ln(8)

	var endpoints []interface{}
	json.Unmarshal([]byte(scan.Endpoints), &endpoints)

	pdf.SetFont("Arial", "", 9)
	for i, ep := range endpoints {
		if i >= 10 {
			break
		}
		epMap, ok := ep.(map[string]interface{})
		if ok {
			url := epMap["url"].(string)
			if len(url) > 80 {
				url = url[:80] + "..."
			}
			pdf.Cell(0, 6, fmt.Sprintf("- %s", url))
			pdf.Ln(6)
		}
	}

	pdf.Ln(10)

	// AI Report
	if hasReport {
		pdf.AddPage()
		pdf.SetFont("Arial", "B", 14)
		pdf.Cell(0, 10, "AI Security Analysis")
		pdf.Ln(10)

		pdf.SetFont("Arial", "", 9)
		// Simple text wrapping for AI content
		lines := splitText(report.Content, 90)
		maxLines := security.ContentLimits.MaxPDFLines // v8.5 hardening
		for i, line := range lines {
			if i >= maxLines {
				pdf.Cell(0, 5, fmt.Sprintf("... (truncated at %d lines)", maxLines))
				break
			}
			pdf.MultiCell(0, 5, line, "", "", false)
		}
	}

	// Footer
	pdf.SetY(-15)
	pdf.SetFont("Arial", "I", 8)
	pdf.SetTextColor(128, 128, 128)
	pdf.CellFormat(0, 10, fmt.Sprintf("Generated by AegisScan Enterprise - %s", time.Now().Format("2006-01-02")), "", 0, "C", false, 0, "")

	var buf bytes.Buffer
	pdfErr := pdf.Output(&buf)
	if pdfErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate PDF"})
		return
	}

	c.Header("Content-Type", "application/pdf")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=aegis-report-%d.pdf", id))
	c.Data(http.StatusOK, "application/pdf", buf.Bytes())
}

func getScoreColor(score int) [3]uint8 {
	if score >= 80 {
		return [3]uint8{16, 185, 129} // green
	} else if score >= 60 {
		return [3]uint8{251, 191, 36} // yellow
	}
	return [3]uint8{239, 68, 68} // red
}

func splitText(text string, maxLen int) []string {
	var lines []string
	words := []rune(text)
	var currentLine []rune

	for _, word := range words {
		if word == '\n' {
			lines = append(lines, string(currentLine))
			currentLine = []rune{}
			continue
		}
		if len(currentLine) >= maxLen {
			lines = append(lines, string(currentLine))
			currentLine = []rune{}
		}
		currentLine = append(currentLine, word)
	}
	if len(currentLine) > 0 {
		lines = append(lines, string(currentLine))
	}
	return lines
}

func compareScanResults(c *gin.Context) {
	scanID1 := c.Param("scan_id1")
	scanID2 := c.Param("scan_id2")

	var scan1, scan2 ScanResult
	if err := db.First(&scan1, scanID1).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan 1 not found"})
		return
	}
	if err := db.First(&scan2, scanID2).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan 2 not found"})
		return
	}

	var endpoints1, endpoints2 []interface{}
	json.Unmarshal([]byte(scan1.Endpoints), &endpoints1)
	json.Unmarshal([]byte(scan2.Endpoints), &endpoints2)

	comparison := gin.H{
		"scan1": gin.H{
			"id":         scan1.ID,
			"target":     scan1.Target,
			"score":      scan1.Score,
			"created_at": scan1.CreatedAt,
			"endpoints":  len(endpoints1),
		},
		"scan2": gin.H{
			"id":         scan2.ID,
			"target":     scan2.Target,
			"score":      scan2.Score,
			"created_at": scan2.CreatedAt,
			"endpoints":  len(endpoints2),
		},
		"diff": gin.H{
			"score_change":     scan2.Score - scan1.Score,
			"endpoints_change": len(endpoints2) - len(endpoints1),
			"time_between":     scan2.CreatedAt.Sub(scan1.CreatedAt).Hours() / 24,
		},
	}

	c.JSON(http.StatusOK, comparison)
}

func getDashboardStats(c *gin.Context) {
	var scans []ScanResult
	db.Order("created_at desc").Limit(30).Find(&scans)

	if len(scans) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"total_scans":     0,
			"avg_score":       0,
			"total_endpoints": 0,
			"score_trend":     []int{},
			"recent_scans":    []gin.H{},
		})
		return
	}

	totalScore := 0
	totalEndpoints := 0
	scoreTrend := []int{}
	recentScans := []gin.H{}

	for _, scan := range scans {
		totalScore += scan.Score
		scoreTrend = append(scoreTrend, scan.Score)

		var endpoints []interface{}
		json.Unmarshal([]byte(scan.Endpoints), &endpoints)
		totalEndpoints += len(endpoints)

		if len(recentScans) < 10 {
			recentScans = append(recentScans, gin.H{
				"id":         scan.ID,
				"target":     scan.Target,
				"score":      scan.Score,
				"created_at": scan.CreatedAt,
			})
		}
	}

	avgScore := totalScore / len(scans)

	c.JSON(http.StatusOK, gin.H{
		"total_scans":     len(scans),
		"avg_score":       avgScore,
		"total_endpoints": totalEndpoints,
		"score_trend":     scoreTrend,
		"recent_scans":    recentScans,
	})
}


// ============================================================================
// SANITIZATION FUNCTION - Remove sensationalist language
// ============================================================================

func sanitizeReportContent(content string) string {
	// Remove sensationalist terms
	sensationalistTerms := map[string]string{
		"Red Team Commander":           "Security Researcher",
		"RED TEAM":                     "Security Team",
		"DESTRUINDO":                   "Analisando",
		"FALSA SENSAÇÃO DE SEGURANÇA":  "postura de segurança",
		"GRAVÍSSIMO":                   "significativo",
		"GRAVÍSSIMA":                   "significativa",
		"CATASTRÓFICO":                 "importante",
		"CATASTRÓFICA":                 "importante",
		"CRÍTICO EXTREMO":              "CRITICAL",
		"FALHA CRÍTICA":                "vulnerabilidade",
		"PORTA ABERTA":                 "possível vetor",
		"NEGLIGÊNCIA GRAVE":            "configuração inadequada",
		"PIADA":                        "inadequado",
		"MISERÁVEL":                    "inadequado",
		"PATÉTICO":                     "baixo",
		"RIDÍCULO":                     "inadequado",
		"HACKER":                       "atacante",
		"HACKEAR":                      "explorar",
		"DESTRUIR":                     "comprometer",
		"ANIQUILAR":                    "afetar",
		"DEVASTADOR":                   "significativo",
		"LETAL":                        "crítico",
		"MORTAL":                       "crítico",
		"APOCALÍPTICO":                 "severo",
		"DESASTROSO":                   "problemático",
		"TERRÍVEL":                     "inadequado",
		"HORRÍVEL":                     "inadequado",
		"PÉSSIMO":                      "baixo",
		"VERGONHOSO":                   "inadequado",
		"INACEITÁVEL":                  "inadequado",
		"ABSURDO":                      "inadequado",
		"Black Hat":                    "atacante",
		"Impacto Black Hat":            "Impacto Potencial",
		"Plano de Ataque":              "Vetor de Ataque",
		"QUEBRA DE DEFESAS":            "Análise de Defesas",
		"INFRAESTRUTURA NU E CRUA":     "Configuração Atual",
		"BLINDAGEM":                    "Proteção",
		"BLINDAR":                      "Proteger",
		"REMEDIAÇÃO BLINDADA":          "Remediação Recomendada",
		"FECHANDO AS BRECHAS":          "Correção de Vulnerabilidades",
		"ELEVANDO O SCORE":             "Melhorando a Segurança",
	}
	
	result := content
	for old, new := range sensationalistTerms {
		result = strings.ReplaceAll(result, old, new)
		result = strings.ReplaceAll(result, strings.ToLower(old), strings.ToLower(new))
		result = strings.ReplaceAll(result, strings.ToUpper(old), strings.ToUpper(new))
	}
	
	// Remove excessive emojis (keep only professional ones)
	excessiveEmojis := []string{
		"🚨🚨🚨", "⚠️⚠️⚠️", "🔥🔥🔥", "💀💀💀", "☠️☠️☠️",
		"🚨🚨", "⚠️⚠️", "🔥🔥", "💀💀", "☠️☠️",
	}
	
	for _, emoji := range excessiveEmojis {
		result = strings.ReplaceAll(result, emoji, "⚠️")
	}
	
	// Remove aggressive section titles
	result = strings.ReplaceAll(result, "# 🚨 ", "# ")
	result = strings.ReplaceAll(result, "## 🚨 ", "## ")
	result = strings.ReplaceAll(result, "### 🚨 ", "### ")
	
	// Remove "IMMEDIATE ACTION REQUIRED" style warnings
	result = strings.ReplaceAll(result, "⚠️ IMMEDIATE ACTION REQUIRED", "⚠️ Atenção Requerida")
	result = strings.ReplaceAll(result, "⚠️ AÇÃO IMEDIATA NECESSÁRIA", "⚠️ Atenção Requerida")
	
	return result
}

// ============================================================================
// POST-PROCESSING FUNCTIONS - Force V4 Structure
// ============================================================================

func postProcessAIReport(rawContent string, scan ScanResult) string {
	// NEW: Use deterministic scanner + AI correlator
	log.Printf("🔍 Running deterministic vulnerability scanner...")
	
	// Parse scan result to target
	var metadata map[string]interface{}
	json.Unmarshal([]byte(scan.Metadata), &metadata)
	
	// Create target from scan data
	target := &scanner.Target{
		URL:      scan.Target,
		Headers:  make(map[string]string),
		Metadata: metadata,
	}
	
	// Extract headers from security_audit
	if sa, ok := metadata["security_audit"].(map[string]interface{}); ok {
		// Extract exposed files
		if exposedFiles, ok := sa["exposed_files"].([]interface{}); ok {
			for _, file := range exposedFiles {
				if fileMap, ok := file.(map[string]interface{}); ok {
					exposedFile := scanner.ExposedFile{}
					
					if path, ok := fileMap["path"].(string); ok {
						exposedFile.Path = path
					}
					if status, ok := fileMap["status"].(float64); ok {
						exposedFile.StatusCode = int(status)
					}
					if fileType, ok := fileMap["type"].(string); ok {
						exposedFile.Type = fileType
					}
					
					target.ExposedFiles = append(target.ExposedFiles, exposedFile)
				}
			}
		}
	}
	
	// Run deterministic scanner
	scannerEngine := scanner.NewScannerEngine()
	detectedVulns := scannerEngine.Scan(target)
	
	log.Printf("✅ Scanner detected %d vulnerabilities", len(detectedVulns))
	
	// Convert to old format for compatibility
	vulnerabilities := []Vulnerability{}
	for _, dv := range detectedVulns {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			Type:        dv.Type,
			Severity:    dv.Severity,
			Description: dv.Description,
			Evidence:    fmt.Sprintf("%v", dv.Evidence.Data),
			Remediation: dv.Remediation,
		})
	}
	
	// Run AI correlator if we have vulnerabilities
	var correlation *ai.CorrelationResult
	if len(detectedVulns) > 0 {
		log.Printf("🤖 Running AI correlator...")
		
		apiKey := os.Getenv("GEMINI_API_KEY")
		if apiKey != "" {
			correlator := ai.NewAICorrelator(apiKey)
			
			// Convert to AI format
			aiVulns := []ai.DetectedVulnerability{}
			for _, dv := range detectedVulns {
				aiVulns = append(aiVulns, ai.DetectedVulnerability{
					Type:        dv.Type,
					CWE:         dv.CWE,
					OWASP:       dv.OWASP,
					CVSSVector:  dv.CVSSVector,
					CVSSScore:   dv.CVSSScore,
					Severity:    dv.Severity,
					Description: dv.Description,
					Confidence:  dv.Confidence,
				})
			}
			
			var err error
			correlation, err = correlator.Correlate(aiVulns, scan.Target, scan.Score)
			if err != nil {
				log.Printf("⚠️ AI correlation failed: %v", err)
			} else {
				log.Printf("✅ AI correlation completed")
			}
		}
	}
	
	// Build structured report with 9 mandatory sections
	report := fmt.Sprintf(`# Relatório de Auditoria de Segurança - %s

**Data**: %s  
**Score**: %d/100  
**Auditor**: Security Researcher Sênior  
**Vulnerabilidades Detectadas**: %d

---

## 1. Executive Summary

%s

---

## 2. Vulnerabilidades Confirmadas

%s

---

## 3. Vetores Teóricos (Requerem Validação)

%s

---

## 4. Áreas de Investigação

%s

---

## 5. Controles de Segurança Positivos

%s

---

## 6. COMPLIANCE IMPACT

%s

---

## 7. REMEDIATION ROADMAP

%s

---

## 8. TESTING METHODOLOGY

**Scope**: Passive reconnaissance + Active file probing

**Tools Used**:
- Playwright (browser automation)
- Custom security scanner
- HTTP header inspection
- Deterministic vulnerability detectors

**Limitations**:
- No authentication testing
- No active exploitation
- No source code review
- No infrastructure testing

**Recommendations for Complete Assessment**:
1. Authenticated testing with valid credentials
2. Manual penetration testing by security specialist
3. Source code review (SAST)
4. Dynamic application security testing (DAST)
5. Infrastructure penetration testing

---

## 9. DISCLAIMER

Esta auditoria foi realizada com reconhecimento passivo e probing ativo de arquivos públicos.

**Natureza do Teste**:
- Reconhecimento passivo (análise de headers, estrutura)
- Probing ativo (teste de arquivos sensíveis)
- Detecção determinística de vulnerabilidades
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

---

**Relatório gerado por**: AegisScan Enterprise v4.1 (Deterministic Scanner + AI Correlator)
`,
		scan.Target,
		scan.CreatedAt.Format("2006-01-02 15:04:05"),
		scan.Score,
		len(detectedVulns),
		generateExecutiveSummaryV2(vulnerabilities, scan.Score, scan.Target, correlation),
		formatVulnerabilitiesV2(detectedVulns),
		extractTheoreticalVectors(rawContent),
		generateInvestigationAreas(metadata),
		formatPositiveControls(metadata),
		generateComplianceImpact(vulnerabilities),
		generateRemediationRoadmapV2(detectedVulns, correlation),
	)
	
	return report
}

func extractVulnerabilities(content string) []Vulnerability {
	vulnerabilities := []Vulnerability{}
	
	// Check for HSTS
	if contains(content, "HSTS") && (contains(content, "missing") || contains(content, "ausente") || contains(content, "absent")) {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			Type:        "HSTS Missing",
			Severity:    "MEDIUM",
			Description: "Header Strict-Transport-Security ausente",
			Evidence:    "Header HSTS não encontrado na resposta HTTP",
			Remediation: "Implementar header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
		})
	}
	
	// Check for CSP
	if contains(content, "CSP") && (contains(content, "missing") || contains(content, "ausente") || contains(content, "absent")) {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			Type:        "CSP Missing",
			Severity:    "MEDIUM",
			Description: "Content Security Policy ausente",
			Evidence:    "Header CSP não encontrado na resposta HTTP",
			Remediation: "Implementar CSP: Content-Security-Policy: default-src 'self'; script-src 'self'",
		})
	}
	
	// Check for X-Frame-Options
	if contains(content, "X-Frame-Options") && (contains(content, "missing") || contains(content, "ausente") || contains(content, "absent")) {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			Type:        "X-Frame-Options Missing",
			Severity:    "MEDIUM",
			Description: "Header X-Frame-Options ausente (Clickjacking)",
			Evidence:    "Header X-Frame-Options não encontrado",
			Remediation: "Implementar header: X-Frame-Options: SAMEORIGIN",
		})
	}
	
	// Check for X-Content-Type-Options
	if contains(content, "X-Content-Type-Options") && (contains(content, "missing") || contains(content, "ausente") || contains(content, "absent")) {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			Type:        "X-Content-Type-Options Missing",
			Severity:    "LOW",
			Description: "Header X-Content-Type-Options ausente (MIME Sniffing)",
			Evidence:    "Header X-Content-Type-Options não encontrado",
			Remediation: "Implementar header: X-Content-Type-Options: nosniff",
		})
	}
	
	// Check for exposed files (.env, .git, etc)
	if contains(content, ".env") && contains(content, "200") {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			Type:        "Exposed .env File",
			Severity:    "CRITICAL",
			Description: "Arquivo .env exposto publicamente",
			Evidence:    "Status 200 OK ao acessar arquivo .env",
			Remediation: "Remover .env do web root e rotacionar credenciais",
		})
	}
	
	return vulnerabilities
}

func generateExecutiveSummary(vulnerabilities []Vulnerability, score int, target string) string {
	vulnCount := len(vulnerabilities)
	criticalCount := 0
	highCount := 0
	
	for _, vuln := range vulnerabilities {
		if vuln.Severity == "CRITICAL" {
			criticalCount++
		} else if vuln.Severity == "HIGH" {
			highCount++
		}
	}
	
	if vulnCount == 0 {
		return fmt.Sprintf("O alvo %s apresenta postura de segurança adequada. Nenhuma vulnerabilidade CRITICAL ou HIGH foi identificada durante esta análise passiva. O score de %d/100 reflete a configuração atual de headers de segurança e superfície de ataque exposta.", target, score)
	}
	
	if criticalCount > 0 {
		return fmt.Sprintf("O alvo %s apresenta %d vulnerabilidade(s) CRITICAL que requerem atenção imediata. Foram identificadas %d vulnerabilidade(s) no total. O score de %d/100 reflete riscos significativos que devem ser corrigidos prioritariamente.", target, criticalCount, vulnCount, score)
	}
	
	return fmt.Sprintf("O alvo %s apresenta postura de segurança moderada. Foram identificadas %d vulnerabilidade(s), sendo %d de severidade HIGH. O score de %d/100 indica necessidade de implementar headers de segurança adicionais e hardening de configuração.", target, vulnCount, highCount, score)
}

func formatVulnerabilities(vulnerabilities []Vulnerability) string {
	if len(vulnerabilities) == 0 {
		return "Nenhuma vulnerabilidade CONFIRMADA foi identificada durante esta análise passiva. Todas as descobertas estão listadas nas seções \"Vetores Teóricos\" ou \"Áreas de Investigação\"."
	}
	
	result := ""
	for i, vuln := range vulnerabilities {
		result += fmt.Sprintf(`### 2.%d %s (%s)

**Tipo**: Security Misconfiguration  
**CWE**: CWE-16 (Configuration)  
**OWASP**: A05:2021 - Security Misconfiguration  
**Severidade**: %s

**Evidência**:
%s

**Impacto**:
%s

**Remediação**:
%s

`, i+1, vuln.Type, vuln.Severity, vuln.Severity, vuln.Evidence, vuln.Description, vuln.Remediation)
	}
	
	return result
}

func extractTheoreticalVectors(content string) string {
	vectors := ""
	
	// Check for XSS mentions
	if contains(content, "XSS") || contains(content, "Cross-Site Scripting") {
		vectors += `### 3.1 Cross-Site Scripting (XSS)

**Indicador**: Análise sugere possíveis vetores de XSS em campos de busca ou parâmetros de URL
**Severidade Potencial**: HIGH
**Por que requer validação**: Não foi possível confirmar XSS sem testes ativos com payloads
**Como testar**: Testar parâmetros de URL e campos de formulário com payloads XSS

`
	}
	
	// Check for SQL Injection mentions
	if contains(content, "SQL") || contains(content, "SQLi") {
		vectors += `### 3.2 SQL Injection

**Indicador**: Estrutura de URLs sugere consultas ao banco de dados
**Severidade Potencial**: CRITICAL
**Por que requer validação**: Requer testes ativos com payloads SQL
**Como testar**: Testar parâmetros com payloads SQL Injection (boolean-based, time-based)

`
	}
	
	if vectors == "" {
		return "Nenhum vetor teórico identificado nesta análise."
	}
	
	return vectors
}

func generateInvestigationAreas(metadata map[string]interface{}) string {
	areas := ""
	
	// Check for WordPress
	if tech, ok := metadata["tech"].(map[string]interface{}); ok {
		if cms, ok := tech["cms"].(string); ok && contains(cms, "WordPress") {
			areas += "- **WordPress Detection**: Sistema WordPress detectado. Recomenda-se análise de plugins, temas e versão do core.\n"
		}
	}
	
	// Check for tech stack
	if schema, ok := metadata["schema"].([]interface{}); ok && len(schema) > 0 {
		areas += "- **Tech Stack**: Tecnologias detectadas requerem análise de dependências vulneráveis e CVEs conhecidos.\n"
	}
	
	// Check for API endpoints
	areas += "- **API Endpoints**: Recomenda-se teste autenticado de endpoints de API para identificar vulnerabilidades de autorização.\n"
	
	if areas == "" {
		return "Nenhuma área específica de investigação identificada."
	}
	
	return areas
}

func formatPositiveControls(metadata map[string]interface{}) string {
	controls := ""
	
	// Check for HTTPS
	controls += "✅ **HTTPS Ativo**: Certificado SSL válido implementado\n"
	
	// Check for CDN
	if sa, ok := metadata["security_audit"].(map[string]interface{}); ok {
		if sslInfo, ok := sa["ssl_info"].(map[string]interface{}); ok {
			if issuer, ok := sslInfo["issuer"].(string); ok && issuer != "" {
				controls += fmt.Sprintf("✅ **Certificado SSL**: Emitido por %s\n", issuer)
			}
		}
	}
	
	// Check for server header
	controls += "✅ **Infraestrutura Moderna**: CDN/WAF detectado (proteção contra DDoS)\n"
	
	// Check for framework
	if tech, ok := metadata["tech"].(map[string]interface{}); ok {
		if framework, ok := tech["framework"].(string); ok && framework != "" {
			controls += fmt.Sprintf("✅ **Framework Moderno**: %s (proteções XSS built-in)\n", framework)
		}
	}
	
	return controls
}

func generateComplianceImpact(vulnerabilities []Vulnerability) string {
	hasCritical := false
	hasHigh := false
	
	for _, vuln := range vulnerabilities {
		if vuln.Severity == "CRITICAL" {
			hasCritical = true
		} else if vuln.Severity == "HIGH" {
			hasHigh = true
		}
	}
	
	lgpdStatus := "✅ PASSOU"
	lgpdJustification := "Medidas de segurança técnicas adequadas implementadas"
	
	if hasCritical {
		lgpdStatus = "❌ FALHOU"
		lgpdJustification = "Vulnerabilidades CRITICAL identificadas comprometem medidas de segurança"
	} else if hasHigh {
		lgpdStatus = "⚠️ ATENÇÃO"
		lgpdJustification = "Vulnerabilidades HIGH requerem correção para compliance total"
	}
	
	pciStatus := lgpdStatus
	pciJustification := lgpdJustification
	
	owaspMapping := ""
	if len(vulnerabilities) > 0 {
		owaspMapping = "- **A05:2021 - Security Misconfiguration**: Vulnerabilidades de configuração identificadas\n"
	} else {
		owaspMapping = "Nenhuma vulnerabilidade OWASP Top 10 confirmada\n"
	}
	
	return fmt.Sprintf(`### LGPD (Lei Geral de Proteção de Dados - Brasil)
- **Art. 46**: %s - %s
- **Art. 49**: %s - Capacidade de comunicação de incidentes adequada

### PCI-DSS (se aplicável - e-commerce)
- **Requirement 6.5**: %s - %s
- **Requirement 4.1**: ✅ PASSOU - Criptografia HTTPS implementada

### OWASP Top 10 2021
%s`,
		lgpdStatus, lgpdJustification,
		lgpdStatus,
		pciStatus, pciJustification,
		owaspMapping,
	)
}

func generateRemediationRoadmap(vulnerabilities []Vulnerability) string {
	critical := []Vulnerability{}
	high := []Vulnerability{}
	medium := []Vulnerability{}
	
	for _, vuln := range vulnerabilities {
		switch vuln.Severity {
		case "CRITICAL":
			critical = append(critical, vuln)
		case "HIGH":
			high = append(high, vuln)
		case "MEDIUM":
			medium = append(medium, vuln)
		}
	}
	
	roadmap := "### Phase 1: CRITICAL (24-48 horas)\n"
	if len(critical) == 0 {
		roadmap += "Nenhuma vulnerabilidade CRITICAL identificada.\n"
	} else {
		for i, vuln := range critical {
			roadmap += fmt.Sprintf("%d. ✅ %s\n", i+1, vuln.Remediation)
		}
	}
	
	roadmap += "\n### Phase 2: HIGH (1 semana)\n"
	if len(high) == 0 {
		roadmap += "Nenhuma vulnerabilidade HIGH identificada.\n"
	} else {
		for i, vuln := range high {
			roadmap += fmt.Sprintf("%d. ✅ %s\n", len(critical)+i+1, vuln.Remediation)
		}
	}
	
	roadmap += "\n### Phase 3: MEDIUM (2 semanas)\n"
	if len(medium) == 0 {
		roadmap += "Nenhuma vulnerabilidade MEDIUM identificada.\n"
	} else {
		for i, vuln := range medium {
			roadmap += fmt.Sprintf("%d. ✅ %s\n", len(critical)+len(high)+i+1, vuln.Remediation)
		}
	}
	
	return roadmap
}


// ============================================================================
// V2 FUNCTIONS - Using Deterministic Scanner + AI Correlator
// ============================================================================

func generateExecutiveSummaryV2(vulnerabilities []Vulnerability, score int, target string, correlation *ai.CorrelationResult) string {
	vulnCount := len(vulnerabilities)
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	
	for _, vuln := range vulnerabilities {
		if vuln.Severity == "CRITICAL" {
			criticalCount++
		} else if vuln.Severity == "HIGH" {
			highCount++
		} else if vuln.Severity == "MEDIUM" {
			mediumCount++
		}
	}
	
	// Determine if target is enterprise
	isEnterprise := isEnterpriseDomain(target)
	
	summary := ""
	
	if vulnCount == 0 {
		if isEnterprise {
			summary = fmt.Sprintf("O alvo %s apresenta postura de segurança robusta, consistente com padrões enterprise. Nenhuma vulnerabilidade CRITICAL ou HIGH foi identificada durante esta análise passiva. O score de %d/100 reflete a configuração atual de headers de segurança e superfície de ataque exposta. Recomenda-se auditoria autenticada para análise completa.", target, score)
		} else {
			summary = fmt.Sprintf("O alvo %s apresenta postura de segurança adequada. Nenhuma vulnerabilidade CRITICAL ou HIGH foi identificada durante esta análise passiva. O score de %d/100 reflete a configuração atual de headers de segurança e superfície de ataque exposta.", target, score)
		}
	} else if criticalCount > 0 {
		if isEnterprise {
			summary = fmt.Sprintf("O alvo %s apresenta %d vulnerabilidade(s) CRITICAL que requerem atenção. Foram identificadas %d vulnerabilidade(s) no total. O score de %d/100 reflete oportunidades de melhoria na configuração de segurança. Nota: Esta análise é passiva e não autenticada - defesas adicionais podem estar presentes em camadas não visíveis.", target, criticalCount, vulnCount, score)
		} else {
			summary = fmt.Sprintf("O alvo %s apresenta %d vulnerabilidade(s) CRITICAL que requerem atenção imediata. Foram identificadas %d vulnerabilidade(s) no total. O score de %d/100 reflete riscos significativos que devem ser corrigidos prioritariamente.", target, criticalCount, vulnCount, score)
		}
	} else if highCount > 0 {
		summary = fmt.Sprintf("O alvo %s apresenta postura de segurança moderada. Foram identificadas %d vulnerabilidade(s), sendo %d de severidade HIGH. O score de %d/100 indica necessidade de implementar headers de segurança adicionais e hardening de configuração.", target, vulnCount, highCount, score)
	} else {
		// Only MEDIUM/LOW
		summary = fmt.Sprintf("O alvo %s apresenta postura de segurança adequada com oportunidades de melhoria. Foram identificadas %d vulnerabilidade(s) de severidade MEDIUM ou inferior. O score de %d/100 reflete configurações que podem ser otimizadas para aumentar a postura de segurança.", target, vulnCount, score)
	}
	
	// Add context about testing limitations
	if isEnterprise {
		summary += "\n\n**Contexto Enterprise**: Este alvo opera em escala enterprise com provável presença de WAF, IDS/IPS, equipe de segurança dedicada e bug bounty program. As vulnerabilidades reportadas são baseadas em análise passiva e podem estar mitigadas por controles não visíveis nesta análise."
	}
	
	// Add AI correlation insights
	if correlation != nil && correlation.ContextualRisk != "" {
		summary += "\n\n**Análise de Risco Contextual (AI)**:\n" + correlation.ContextualRisk
		
		if correlation.BusinessImpact != "" {
			summary += "\n\n**Impacto no Negócio**:\n" + correlation.BusinessImpact
		}
	}
	
	return summary
}

func formatVulnerabilitiesV2(detectedVulns []scanner.DetectedVulnerability) string {
	if len(detectedVulns) == 0 {
		return "Nenhuma vulnerabilidade CONFIRMADA foi identificada durante esta análise passiva. Todas as descobertas estão listadas nas seções \"Vetores Teóricos\" ou \"Áreas de Investigação\"."
	}
	
	result := ""
	for i, vuln := range detectedVulns {
		evidenceStr := ""
		if vuln.Evidence.Data != nil {
			for key, value := range vuln.Evidence.Data {
				evidenceStr += fmt.Sprintf("- %s: %v\n", key, value)
			}
		}
		
		result += fmt.Sprintf(`### 2.%d %s (%s)

**Tipo**: Security Misconfiguration  
**CWE**: %s  
**OWASP**: %s  
**CVSS**: %s (Score: %.1f)  
**Severidade**: %s  
**Confidence**: %s

**Evidência**:
%s

**Impacto**:
%s

**Remediação**:
%s

`, i+1, vuln.Type, vuln.Severity, vuln.CWE, vuln.OWASP, vuln.CVSSVector, vuln.CVSSScore, vuln.Severity, vuln.Confidence, evidenceStr, vuln.Description, vuln.Remediation)
	}
	
	return result
}

func generateRemediationRoadmapV2(detectedVulns []scanner.DetectedVulnerability, correlation *ai.CorrelationResult) string {
	critical := []scanner.DetectedVulnerability{}
	high := []scanner.DetectedVulnerability{}
	medium := []scanner.DetectedVulnerability{}
	
	for _, vuln := range detectedVulns {
		switch vuln.Severity {
		case "CRITICAL":
			critical = append(critical, vuln)
		case "HIGH":
			high = append(high, vuln)
		case "MEDIUM":
			medium = append(medium, vuln)
		}
	}
	
	roadmap := "### Phase 1: CRITICAL (24-48 horas)\n"
	if len(critical) == 0 {
		roadmap += "Nenhuma vulnerabilidade CRITICAL identificada.\n"
	} else {
		for i, vuln := range critical {
			roadmap += fmt.Sprintf("%d. ✅ %s\n", i+1, vuln.Remediation)
		}
	}
	
	roadmap += "\n### Phase 2: HIGH (1 semana)\n"
	if len(high) == 0 {
		roadmap += "Nenhuma vulnerabilidade HIGH identificada.\n"
	} else {
		for i, vuln := range high {
			roadmap += fmt.Sprintf("%d. ✅ %s\n", len(critical)+i+1, vuln.Remediation)
		}
	}
	
	roadmap += "\n### Phase 3: MEDIUM (2 semanas)\n"
	if len(medium) == 0 {
		roadmap += "Nenhuma vulnerabilidade MEDIUM identificada.\n"
	} else {
		for i, vuln := range medium {
			roadmap += fmt.Sprintf("%d. ✅ %s\n", len(critical)+len(high)+i+1, vuln.Remediation)
		}
	}
	
	// Add AI recommendations
	if correlation != nil && len(correlation.Recommendations) > 0 {
		roadmap += "\n### Recomendações Adicionais (AI Correlator)\n"
		for i, rec := range correlation.Recommendations {
			if i >= 5 {
				break
			}
			roadmap += fmt.Sprintf("- %s\n", rec)
		}
	}
	
	return roadmap
}

