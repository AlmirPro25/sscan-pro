# Script para adicionar handlers de auto-fix ao main.go
# Execute: .\add-autofix-handlers.ps1

$handlersCode = @'

// ============================================================================
// AUTO-FIX HANDLERS
// ============================================================================

func handleGenerateAutoFix(c *gin.Context) {
	var input struct {
		ScanID uint   `json:"scan_id" binding:"required"`
		ApiKey string `json:"api_key"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ScanID is required"})
		return
	}

	var scan ScanResult
	if err := db.First(&scan, input.ScanID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found"})
		return
	}

	var metadata map[string]interface{}
	json.Unmarshal([]byte(scan.Metadata), &metadata)

	stack := autofix.DetectStack(metadata)
	log.Printf("🔍 Detected stack: WebServer=%s, Backend=%s, Language=%s", stack.WebServer, stack.Backend, stack.Language)

	target := &scanner.Target{
		URL:      scan.Target,
		Headers:  make(map[string]string),
		Metadata: metadata,
	}

	scannerEngine := scanner.NewScannerEngine()
	detectedVulns := scannerEngine.Scan(target)

	if len(detectedVulns) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"message": "No vulnerabilities found to fix",
			"fixes":   []interface{}{},
		})
		return
	}

	apiKey := input.ApiKey
	if apiKey == "" {
		apiKey = os.Getenv("GEMINI_API_KEY")
	}

	generator := autofix.NewAutoFixGenerator(apiKey)
	fixes := []autofix.AutoFix{}

	for _, vuln := range detectedVulns {
		log.Printf("🔧 Generating fix for: %s", vuln.Type)
		
		fix, err := generator.GenerateAutoFix(vuln.Type, stack, "")
		if err != nil {
			log.Printf("⚠️ Failed to generate fix for %s: %v", vuln.Type, err)
			continue
		}

		fixes = append(fixes, *fix)
		log.Printf("✅ Fix generated for %s (confidence: %s)", vuln.Type, fix.Confidence)
	}

	c.JSON(http.StatusOK, gin.H{
		"scan_id":             scan.ID,
		"target":              scan.Target,
		"vulnerabilities":     len(detectedVulns),
		"fixes_generated":     len(fixes),
		"stack":               stack,
		"fixes":               fixes,
	})
}

func handleCreatePR(c *gin.Context) {
	var input struct {
		ScanID      uint   `json:"scan_id" binding:"required"`
		VulnType    string `json:"vuln_type" binding:"required"`
		GitHubToken string `json:"github_token" binding:"required"`
		Owner       string `json:"owner" binding:"required"`
		Repo        string `json:"repo" binding:"required"`
		ApiKey      string `json:"api_key"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var scan ScanResult
	if err := db.First(&scan, input.ScanID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found"})
		return
	}

	var metadata map[string]interface{}
	json.Unmarshal([]byte(scan.Metadata), &metadata)

	stack := autofix.DetectStack(metadata)

	apiKey := input.ApiKey
	if apiKey == "" {
		apiKey = os.Getenv("GEMINI_API_KEY")
	}

	generator := autofix.NewAutoFixGenerator(apiKey)
	fix, err := generator.GenerateAutoFix(input.VulnType, stack, "")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate fix: " + err.Error()})
		return
	}

	prCreator := autofix.NewGitHubPRCreator(input.GitHubToken, input.Owner, input.Repo)
	
	target := &scanner.Target{
		URL:      scan.Target,
		Headers:  make(map[string]string),
		Metadata: metadata,
	}
	scannerEngine := scanner.NewScannerEngine()
	detectedVulns := scannerEngine.Scan(target)
	
	prURL, err := prCreator.CreatePRWithFix(fix, scan.ID, len(detectedVulns))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create PR: " + err.Error()})
		return
	}

	log.Printf("✅ PR created: %s", prURL)

	c.JSON(http.StatusOK, gin.H{
		"message":  "Pull request created successfully",
		"pr_url":   prURL,
		"fix":      fix,
	})
}

func getAutoFixes(c *gin.Context) {
	scanID := c.Param("scan_id")

	var scan ScanResult
	if err := db.First(&scan, scanID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found"})
		return
	}

	var metadata map[string]interface{}
	json.Unmarshal([]byte(scan.Metadata), &metadata)

	stack := autofix.DetectStack(metadata)

	target := &scanner.Target{
		URL:      scan.Target,
		Headers:  make(map[string]string),
		Metadata: metadata,
	}
	scannerEngine := scanner.NewScannerEngine()
	detectedVulns := scannerEngine.Scan(target)

	generator := autofix.NewAutoFixGenerator("")
	fixes := []autofix.AutoFix{}

	for _, vuln := range detectedVulns {
		fix, err := generator.GenerateAutoFix(vuln.Type, stack, "")
		if err != nil {
			continue
		}
		fixes = append(fixes, *fix)
	}

	c.JSON(http.StatusOK, gin.H{
		"scan_id":         scan.ID,
		"target":          scan.Target,
		"stack":           stack,
		"vulnerabilities": len(detectedVulns),
		"fixes":           fixes,
	})
}
'@

Write-Host "🔧 Adicionando handlers de auto-fix ao main.go..." -ForegroundColor Cyan

# Ler conteúdo atual
$content = Get-Content "main.go" -Raw

# Verificar se já existe
if ($content -match "func handleGenerateAutoFix") {
    Write-Host "⚠️  Handlers já existem no arquivo!" -ForegroundColor Yellow
    exit 0
}

# Adicionar ao final
$content += $handlersCode

# Salvar
Set-Content "main.go" -Value $content -NoNewline

Write-Host "✅ Handlers adicionados com sucesso!" -ForegroundColor Green
Write-Host ""
Write-Host "Próximos passos:" -ForegroundColor Cyan
Write-Host "1. go build -o aegis-backend-v6.0-final.exe"
Write-Host "2. Reiniciar backend"
Write-Host "3. Testar com CLI"

