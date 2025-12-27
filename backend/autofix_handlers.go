package main

import (
	"aegis-scan-backend/autofix"
	"aegis-scan-backend/scanner"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

func handleGenerateAutoFix(c *gin.Context) {
	var input struct {
		ScanID uint   `json:"scan_id" binding:"required"`
		ApiKey string `json:"api_key"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ScanID is required"})
		return
	}

	// Fetch scan result
	var scan ScanResult
	if err := db.First(&scan, input.ScanID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found"})
		return
	}

	// Parse metadata
	var metadata map[string]interface{}
	json.Unmarshal([]byte(scan.Metadata), &metadata)

	// Detect stack
	stack := autofix.DetectStack(metadata)
	log.Printf("🔍 Detected stack: WebServer=%s, Backend=%s, Language=%s", stack.WebServer, stack.Backend, stack.Language)

	// Create target for scanner
	target := &scanner.Target{
		URL:      scan.Target,
		Headers:  make(map[string]string),
		Metadata: metadata,
	}

	// Run scanner to get vulnerabilities
	scannerEngine := scanner.NewScannerEngine()
	detectedVulns := scannerEngine.Scan(target)

	if len(detectedVulns) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"message": "No vulnerabilities found to fix",
			"fixes":   []interface{}{},
		})
		return
	}

	// Generate auto-fixes
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

	// Fetch scan result
	var scan ScanResult
	if err := db.First(&scan, input.ScanID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found"})
		return
	}

	// Parse metadata
	var metadata map[string]interface{}
	json.Unmarshal([]byte(scan.Metadata), &metadata)

	// Detect stack
	stack := autofix.DetectStack(metadata)

	// Generate fix
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

	// Create PR
	prCreator := autofix.NewGitHubPRCreator(input.GitHubToken, input.Owner, input.Repo)
	
	// Count total vulnerabilities
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

	// Fetch scan result
	var scan ScanResult
	if err := db.First(&scan, scanID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found"})
		return
	}

	// Parse metadata
	var metadata map[string]interface{}
	json.Unmarshal([]byte(scan.Metadata), &metadata)

	// Detect stack
	stack := autofix.DetectStack(metadata)

	// Get vulnerabilities
	target := &scanner.Target{
		URL:      scan.Target,
		Headers:  make(map[string]string),
		Metadata: metadata,
	}
	scannerEngine := scanner.NewScannerEngine()
	detectedVulns := scannerEngine.Scan(target)

	// Generate fixes (deterministic only for speed)
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
