package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"aegis-scan-backend/scanner"

	"github.com/gin-gonic/gin"
	"github.com/google/generative-ai-go/genai"
	"github.com/jung-kurt/gofpdf"
	"google.golang.org/api/option"
)

// LocalScanResult model for storing local code scan results
type LocalScanResult struct {
	ID              uint           `gorm:"primaryKey" json:"id"`
	Path            string         `json:"path"`
	FilesScanned    int            `json:"files_scanned"`
	LinesScanned    int            `json:"lines_scanned"`
	Score           int            `json:"score"`
	Vulnerabilities string         `json:"vulnerabilities"` // JSON string
	Summary         string         `json:"summary"`         // JSON string
	CreatedAt       time.Time      `json:"created_at"`
}

func init() {
	// Auto-migrate LocalScanResult when package loads
	// This will be called after initDB() in main()
}

func handleLocalScan(c *gin.Context) {
	var input struct {
		Path string `json:"path" binding:"required"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Path is required"})
		return
	}

	// Validate path exists
	if _, err := os.Stat(input.Path); os.IsNotExist(err) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Path does not exist: " + input.Path})
		return
	}

	log.Printf("🔍 Starting local code scan for: %s", input.Path)

	// Create scanner and scan directory
	codeScanner := scanner.NewCodeScanner()
	result, err := codeScanner.ScanDirectory(input.Path)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Scan failed: " + err.Error()})
		return
	}

	log.Printf("✅ Scan complete: %d files, %d vulnerabilities found", result.FilesScanned, len(result.Vulnerabilities))

	// Convert to JSON for storage
	vulnsJSON, _ := json.Marshal(result.Vulnerabilities)
	summaryJSON, _ := json.Marshal(result.Summary)

	// Save to database
	localResult := LocalScanResult{
		Path:            result.Path,
		FilesScanned:    result.FilesScanned,
		LinesScanned:    result.LinesScanned,
		Score:           result.Score,
		Vulnerabilities: string(vulnsJSON),
		Summary:         string(summaryJSON),
	}

	// Auto-migrate if not exists
	db.AutoMigrate(&LocalScanResult{})
	
	if err := db.Create(&localResult).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save result"})
		return
	}

	// Return full result
	c.JSON(http.StatusCreated, gin.H{
		"id":              localResult.ID,
		"path":            result.Path,
		"files_scanned":   result.FilesScanned,
		"lines_scanned":   result.LinesScanned,
		"score":           result.Score,
		"vulnerabilities": result.Vulnerabilities,
		"summary":         result.Summary,
		"created_at":      localResult.CreatedAt,
	})
}

func handleLocalScanAIReport(c *gin.Context) {
	var input struct {
		ScanID uint   `json:"scan_id" binding:"required"`
		Model  string `json:"model"`
		ApiKey string `json:"api_key"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ScanID is required"})
		return
	}

	if input.Model == "" {
		input.Model = "models/gemini-2.5-flash"
	}

	// Fetch local scan result
	var localScan LocalScanResult
	if err := db.First(&localScan, input.ScanID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Local scan not found"})
		return
	}

	// Parse vulnerabilities
	var vulns []scanner.CodeVulnerability
	json.Unmarshal([]byte(localScan.Vulnerabilities), &vulns)

	var summary scanner.CodeScanSummary
	json.Unmarshal([]byte(localScan.Summary), &summary)

	// Get API key
	apiKey := input.ApiKey
	if apiKey == "" {
		apiKey = os.Getenv("GEMINI_API_KEY")
	}

	if apiKey == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "GEMINI_API_KEY is not configured"})
		return
	}

	ctx := c.Request.Context()
	client, err := genai.NewClient(ctx, option.WithAPIKey(apiKey))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create Gemini client"})
		return
	}
	defer client.Close()

	// Build prompt
	prompt := buildLocalScanPrompt(localScan, vulns, summary)

	log.Printf("🤖 Generating AI report for local scan %d", input.ScanID)

	model := client.GenerativeModel(input.Model)
	model.SetTemperature(0.3)
	model.SetMaxOutputTokens(8192)

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

	// Save AI report
	aiReport := AIReport{
		ScanResultID: localScan.ID,
		Model:        input.Model,
		Content:      reportContent,
	}

	if err := db.Create(&aiReport).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save AI report"})
		return
	}

	c.JSON(http.StatusOK, aiReport)
}

func buildLocalScanPrompt(scan LocalScanResult, vulns []scanner.CodeVulnerability, summary scanner.CodeScanSummary) string {
	vulnsJSON, _ := json.MarshalIndent(vulns, "", "  ")

	return fmt.Sprintf(`Você é um Security Researcher especializado em SAST (Static Application Security Testing).

**ANÁLISE DE CÓDIGO LOCAL**

**Projeto**: %s
**Arquivos Escaneados**: %d
**Linhas de Código**: %d
**Score de Segurança**: %d/100

**Resumo de Vulnerabilidades**:
- CRITICAL: %d
- HIGH: %d
- MEDIUM: %d
- LOW: %d

**Vulnerabilidades Detectadas**:
%s

**INSTRUÇÕES**:

1. **Executive Summary**: Resumo executivo do estado de segurança do código

2. **Análise por Categoria**: Agrupe vulnerabilidades por tipo (Secrets, Injection, XSS, etc)

3. **Top 5 Riscos**: Liste os 5 maiores riscos encontrados com:
   - Severidade
   - Arquivo e linha
   - Impacto potencial
   - Remediação específica

4. **Recomendações Prioritárias**: O que corrigir primeiro

5. **Boas Práticas**: Sugestões para melhorar a postura de segurança

**TOM**: Profissional, técnico, direto. Sem sensacionalismo.

Gere o relatório em Markdown PT-BR.`,
		scan.Path,
		scan.FilesScanned,
		scan.LinesScanned,
		scan.Score,
		summary.Critical,
		summary.High,
		summary.Medium,
		summary.Low,
		string(vulnsJSON),
	)
}


// PDF Generation for Local Scan
func handleLocalScanPDF(c *gin.Context) {
	scanID := c.Param("scan_id")

	var localScan LocalScanResult
	if err := db.First(&localScan, scanID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Local scan not found"})
		return
	}

	// Parse vulnerabilities
	var vulns []scanner.CodeVulnerability
	json.Unmarshal([]byte(localScan.Vulnerabilities), &vulns)

	var summary scanner.CodeScanSummary
	json.Unmarshal([]byte(localScan.Summary), &summary)

	// Check for AI report
	var aiReport AIReport
	hasAIReport := db.Where("scan_result_id = ?", scanID).First(&aiReport).Error == nil

	// Generate PDF
	pdf := gofpdf.New("P", "mm", "A4", "")
	
	// ==================== PAGE 1: Cover ====================
	pdf.AddPage()
	
	// Header gradient effect (dark blue)
	pdf.SetFillColor(30, 41, 59) // slate-800
	pdf.Rect(0, 0, 210, 60, "F")
	
	// Logo area
	pdf.SetFillColor(99, 102, 241) // indigo-500
	pdf.Rect(20, 15, 8, 30, "F")
	
	// Title
	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont("Arial", "B", 28)
	pdf.SetXY(35, 20)
	pdf.Cell(0, 10, "AEGISSCAN")
	
	pdf.SetFont("Arial", "", 12)
	pdf.SetXY(35, 32)
	pdf.SetTextColor(148, 163, 184) // slate-400
	pdf.Cell(0, 8, "Static Application Security Testing Report")
	
	// Score badge
	pdf.SetXY(150, 20)
	scoreColor := getLocalScoreColor(localScan.Score)
	pdf.SetFillColor(scoreColor[0], scoreColor[1], scoreColor[2])
	pdf.RoundedRect(150, 18, 40, 25, 3, "1234", "F")
	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont("Arial", "B", 20)
	pdf.SetXY(150, 22)
	pdf.CellFormat(40, 10, fmt.Sprintf("%d", localScan.Score), "", 0, "C", false, 0, "")
	pdf.SetFont("Arial", "", 8)
	pdf.SetXY(150, 33)
	pdf.CellFormat(40, 5, "SCORE", "", 0, "C", false, 0, "")
	
	// Reset colors
	pdf.SetTextColor(30, 41, 59)
	
	// Project Info Box
	pdf.SetY(75)
	pdf.SetFillColor(248, 250, 252) // slate-50
	pdf.RoundedRect(15, 70, 180, 45, 3, "1234", "F")
	
	pdf.SetFont("Arial", "B", 11)
	pdf.SetXY(20, 75)
	pdf.Cell(0, 8, "PROJECT INFORMATION")
	
	pdf.SetFont("Arial", "", 10)
	pdf.SetXY(20, 85)
	pdf.SetTextColor(100, 116, 139) // slate-500
	pdf.Cell(35, 6, "Path:")
	pdf.SetTextColor(30, 41, 59)
	pdf.SetFont("Arial", "B", 9)
	
	// Truncate path if too long
	displayPath := localScan.Path
	if len(displayPath) > 70 {
		displayPath = "..." + displayPath[len(displayPath)-67:]
	}
	pdf.Cell(0, 6, displayPath)
	
	pdf.SetFont("Arial", "", 10)
	pdf.SetXY(20, 93)
	pdf.SetTextColor(100, 116, 139)
	pdf.Cell(35, 6, "Scan Date:")
	pdf.SetTextColor(30, 41, 59)
	pdf.Cell(0, 6, localScan.CreatedAt.Format("2006-01-02 15:04:05"))
	
	pdf.SetXY(20, 101)
	pdf.SetTextColor(100, 116, 139)
	pdf.Cell(35, 6, "Files Scanned:")
	pdf.SetTextColor(30, 41, 59)
	pdf.Cell(30, 6, fmt.Sprintf("%d", localScan.FilesScanned))
	
	pdf.SetTextColor(100, 116, 139)
	pdf.Cell(35, 6, "Lines of Code:")
	pdf.SetTextColor(30, 41, 59)
	pdf.Cell(0, 6, fmt.Sprintf("%d", localScan.LinesScanned))
	
	// Severity Summary
	pdf.SetY(130)
	pdf.SetFont("Arial", "B", 11)
	pdf.SetTextColor(30, 41, 59)
	pdf.Cell(0, 8, "VULNERABILITY SUMMARY")
	pdf.Ln(12)
	
	// Severity boxes
	severities := []struct {
		label string
		count int
		r, g, b int
	}{
		{"CRITICAL", summary.Critical, 220, 38, 38},   // red-600
		{"HIGH", summary.High, 249, 115, 22},          // orange-500
		{"MEDIUM", summary.Medium, 234, 179, 8},       // yellow-500
		{"LOW", summary.Low, 34, 197, 94},             // green-500
	}
	
	boxWidth := float64(42)
	startX := float64(15)
	
	for i, sev := range severities {
		x := startX + float64(i)*(boxWidth+5)
		
		// Box background
		pdf.SetFillColor(248, 250, 252)
		pdf.RoundedRect(x, 142, boxWidth, 35, 2, "1234", "F")
		
		// Severity indicator
		pdf.SetFillColor(sev.r, sev.g, sev.b)
		pdf.Rect(x, 142, boxWidth, 4, "F")
		
		// Count
		pdf.SetFont("Arial", "B", 18)
		pdf.SetTextColor(30, 41, 59)
		pdf.SetXY(x, 152)
		pdf.CellFormat(boxWidth, 10, fmt.Sprintf("%d", sev.count), "", 0, "C", false, 0, "")
		
		// Label
		pdf.SetFont("Arial", "", 8)
		pdf.SetTextColor(100, 116, 139)
		pdf.SetXY(x, 165)
		pdf.CellFormat(boxWidth, 6, sev.label, "", 0, "C", false, 0, "")
	}
	
	// ==================== PAGE 2: Vulnerabilities ====================
	if len(vulns) > 0 {
		pdf.AddPage()
		
		// Header
		pdf.SetFillColor(30, 41, 59)
		pdf.Rect(0, 0, 210, 20, "F")
		pdf.SetTextColor(255, 255, 255)
		pdf.SetFont("Arial", "B", 14)
		pdf.SetXY(15, 6)
		pdf.Cell(0, 8, "DETECTED VULNERABILITIES")
		
		pdf.SetY(30)
		pdf.SetTextColor(30, 41, 59)
		
		// Table header
		pdf.SetFillColor(241, 245, 249) // slate-100
		pdf.SetFont("Arial", "B", 9)
		pdf.SetX(15)
		pdf.CellFormat(25, 8, "Severity", "1", 0, "C", true, 0, "")
		pdf.CellFormat(45, 8, "Type", "1", 0, "C", true, 0, "")
		pdf.CellFormat(80, 8, "File", "1", 0, "C", true, 0, "")
		pdf.CellFormat(15, 8, "Line", "1", 0, "C", true, 0, "")
		pdf.CellFormat(15, 8, "CWE", "1", 1, "C", true, 0, "")
		
		pdf.SetFont("Arial", "", 8)
		
		for i, vuln := range vulns {
			if i >= 25 { // Limit per page
				pdf.AddPage()
				pdf.SetY(20)
				i = 0
			}
			
			// Severity color
			switch vuln.Severity {
			case "CRITICAL":
				pdf.SetFillColor(254, 226, 226) // red-100
				pdf.SetTextColor(185, 28, 28)   // red-700
			case "HIGH":
				pdf.SetFillColor(255, 237, 213) // orange-100
				pdf.SetTextColor(194, 65, 12)   // orange-700
			case "MEDIUM":
				pdf.SetFillColor(254, 249, 195) // yellow-100
				pdf.SetTextColor(161, 98, 7)    // yellow-700
			case "LOW":
				pdf.SetFillColor(220, 252, 231) // green-100
				pdf.SetTextColor(21, 128, 61)   // green-700
			default:
				pdf.SetFillColor(241, 245, 249)
				pdf.SetTextColor(71, 85, 105)
			}
			
			pdf.SetX(15)
			pdf.CellFormat(25, 7, vuln.Severity, "1", 0, "C", true, 0, "")
			
			pdf.SetFillColor(255, 255, 255)
			pdf.SetTextColor(30, 41, 59)
			
			// Truncate type if needed
			vulnType := vuln.Type
			if len(vulnType) > 22 {
				vulnType = vulnType[:19] + "..."
			}
			pdf.CellFormat(45, 7, vulnType, "1", 0, "L", false, 0, "")
			
			// Truncate file path
			filePath := vuln.File
			if len(filePath) > 40 {
				filePath = "..." + filePath[len(filePath)-37:]
			}
			pdf.CellFormat(80, 7, filePath, "1", 0, "L", false, 0, "")
			
			pdf.CellFormat(15, 7, fmt.Sprintf("%d", vuln.Line), "1", 0, "C", false, 0, "")
			
			// Extract CWE number
			cwe := vuln.CWE
			if len(cwe) > 8 {
				cwe = cwe[4:] // Remove "CWE-" prefix if too long
			}
			pdf.CellFormat(15, 7, cwe, "1", 1, "C", false, 0, "")
		}
	}
	
	// ==================== PAGE 3+: AI Report ====================
	if hasAIReport && aiReport.Content != "" {
		pdf.AddPage()
		
		// Header
		pdf.SetFillColor(99, 102, 241) // indigo-500
		pdf.Rect(0, 0, 210, 20, "F")
		pdf.SetTextColor(255, 255, 255)
		pdf.SetFont("Arial", "B", 14)
		pdf.SetXY(15, 6)
		pdf.Cell(0, 8, "AI SECURITY ANALYSIS")
		
		pdf.SetY(30)
		pdf.SetTextColor(30, 41, 59)
		pdf.SetFont("Arial", "", 9)
		
		// Process markdown content
		lines := strings.Split(aiReport.Content, "\n")
		for _, line := range lines {
			if pdf.GetY() > 270 {
				pdf.AddPage()
				pdf.SetY(20)
			}
			
			trimmedLine := strings.TrimSpace(line)
			
			// Headers
			if strings.HasPrefix(trimmedLine, "### ") {
				pdf.SetFont("Arial", "B", 10)
				pdf.SetTextColor(99, 102, 241)
				pdf.Ln(3)
				pdf.MultiCell(180, 5, strings.TrimPrefix(trimmedLine, "### "), "", "", false)
				pdf.SetFont("Arial", "", 9)
				pdf.SetTextColor(30, 41, 59)
			} else if strings.HasPrefix(trimmedLine, "## ") {
				pdf.SetFont("Arial", "B", 11)
				pdf.SetTextColor(30, 41, 59)
				pdf.Ln(5)
				pdf.MultiCell(180, 6, strings.TrimPrefix(trimmedLine, "## "), "", "", false)
				pdf.SetFont("Arial", "", 9)
			} else if strings.HasPrefix(trimmedLine, "# ") {
				pdf.SetFont("Arial", "B", 12)
				pdf.SetTextColor(30, 41, 59)
				pdf.Ln(6)
				pdf.MultiCell(180, 7, strings.TrimPrefix(trimmedLine, "# "), "", "", false)
				pdf.SetFont("Arial", "", 9)
			} else if strings.HasPrefix(trimmedLine, "* ") || strings.HasPrefix(trimmedLine, "- ") {
				// Bullet points
				pdf.SetX(20)
				bullet := strings.TrimPrefix(strings.TrimPrefix(trimmedLine, "* "), "- ")
				pdf.MultiCell(170, 5, "• "+bullet, "", "", false)
			} else if strings.HasPrefix(trimmedLine, "**") && strings.HasSuffix(trimmedLine, "**") {
				// Bold text
				pdf.SetFont("Arial", "B", 9)
				text := strings.Trim(trimmedLine, "*")
				pdf.MultiCell(180, 5, text, "", "", false)
				pdf.SetFont("Arial", "", 9)
			} else if trimmedLine == "---" {
				// Horizontal rule
				pdf.Ln(3)
				pdf.SetDrawColor(226, 232, 240)
				pdf.Line(15, pdf.GetY(), 195, pdf.GetY())
				pdf.Ln(3)
			} else if trimmedLine != "" {
				// Regular text
				pdf.MultiCell(180, 5, trimmedLine, "", "", false)
			} else {
				pdf.Ln(2)
			}
		}
	}
	
	// ==================== Footer on all pages ====================
	totalPages := pdf.PageCount()
	for i := 1; i <= totalPages; i++ {
		pdf.SetPage(i)
		pdf.SetY(-15)
		pdf.SetFont("Arial", "I", 8)
		pdf.SetTextColor(148, 163, 184)
		pdf.CellFormat(0, 10, fmt.Sprintf("AegisScan SAST Report | Page %d of %d | Generated %s", 
			i, totalPages, time.Now().Format("2006-01-02 15:04")), "", 0, "C", false, 0, "")
	}
	
	var buf bytes.Buffer
	err := pdf.Output(&buf)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate PDF"})
		return
	}

	c.Header("Content-Type", "application/pdf")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=aegis-sast-report-%s.pdf", scanID))
	c.Data(http.StatusOK, "application/pdf", buf.Bytes())
}

func getLocalScoreColor(score int) [3]int {
	if score >= 80 {
		return [3]int{34, 197, 94}   // green-500
	} else if score >= 60 {
		return [3]int{234, 179, 8}   // yellow-500
	} else if score >= 40 {
		return [3]int{249, 115, 22}  // orange-500
	}
	return [3]int{239, 68, 68}       // red-500
}

// ============================================================================
// DEPENDENCY SCANNING HANDLERS
// ============================================================================

// DependencyScanResult model for storing dependency scan results
type DependencyScanDBResult struct {
	ID              uint      `gorm:"primaryKey" json:"id"`
	LocalScanID     uint      `json:"local_scan_id"` // Link to code scan
	Path            string    `json:"path"`
	Results         string    `json:"results"` // JSON string of scan results
	TotalDeps       int       `json:"total_deps"`
	TotalVulns      int       `json:"total_vulns"`
	CriticalCount   int       `json:"critical_count"`
	HighCount       int       `json:"high_count"`
	MediumCount     int       `json:"medium_count"`
	LowCount        int       `json:"low_count"`
	CreatedAt       time.Time `json:"created_at"`
}

func handleDependencyScan(c *gin.Context) {
	var input struct {
		Path        string `json:"path" binding:"required"`
		LocalScanID uint   `json:"local_scan_id"` // Optional: link to existing code scan
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Path is required"})
		return
	}

	// Validate path exists
	if _, err := os.Stat(input.Path); os.IsNotExist(err) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Path does not exist: " + input.Path})
		return
	}

	log.Printf("📦 Starting dependency scan for: %s", input.Path)

	// Create dependency scanner and scan directory
	depScanner := scanner.NewDependencyScanner()
	results, err := depScanner.ScanDirectory(input.Path)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Dependency scan failed: " + err.Error()})
		return
	}

	// Calculate totals
	totalDeps := 0
	totalVulns := 0
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0

	for _, result := range results {
		totalDeps += result.TotalDeps
		totalVulns += len(result.Vulnerabilities)
		criticalCount += result.Summary.Critical
		highCount += result.Summary.High
		mediumCount += result.Summary.Medium
		lowCount += result.Summary.Low
	}

	log.Printf("✅ Dependency scan complete: %d ecosystems, %d deps, %d vulnerabilities", 
		len(results), totalDeps, totalVulns)

	// Convert results to JSON for storage
	resultsJSON, _ := json.Marshal(results)

	// Auto-migrate if not exists
	db.AutoMigrate(&DependencyScanDBResult{})

	// Save to database
	dbResult := DependencyScanDBResult{
		LocalScanID:   input.LocalScanID,
		Path:          input.Path,
		Results:       string(resultsJSON),
		TotalDeps:     totalDeps,
		TotalVulns:    totalVulns,
		CriticalCount: criticalCount,
		HighCount:     highCount,
		MediumCount:   mediumCount,
		LowCount:      lowCount,
	}

	if err := db.Create(&dbResult).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save dependency scan result"})
		return
	}

	// Return full result
	c.JSON(http.StatusCreated, gin.H{
		"id":             dbResult.ID,
		"local_scan_id":  dbResult.LocalScanID,
		"path":           input.Path,
		"ecosystems":     len(results),
		"total_deps":     totalDeps,
		"total_vulns":    totalVulns,
		"summary": gin.H{
			"critical": criticalCount,
			"high":     highCount,
			"medium":   mediumCount,
			"low":      lowCount,
		},
		"results":    results,
		"created_at": dbResult.CreatedAt,
	})
}
