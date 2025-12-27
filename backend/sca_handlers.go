package main

import (
	"log"
	"net/http"

	"aegis-scan-backend/scanner"

	"github.com/gin-gonic/gin"
)

// ============================================================================
// SCA (Software Composition Analysis) HANDLERS
// License Scanning, Typosquatting Detection, IAC Analysis
// ============================================================================

// SCAFullScanRequest for comprehensive SCA scan
type SCAFullScanRequest struct {
	Path string `json:"path" binding:"required"`
}

// SCAFullScanResult combines all SCA scan results
type SCAFullScanResult struct {
	Path          string                         `json:"path"`
	Dependencies  []scanner.DependencyScanResult `json:"dependencies"`
	Licenses      *scanner.LicenseScanResult     `json:"licenses"`
	Typosquatting *scanner.TyposquattingScanResult `json:"typosquatting"`
	IAC           *scanner.IACScanResult         `json:"iac"`
	Summary       SCAFullSummary                 `json:"summary"`
	Score         int                            `json:"score"`
}

type SCAFullSummary struct {
	TotalVulnerabilities int `json:"total_vulnerabilities"`
	Critical             int `json:"critical"`
	High                 int `json:"high"`
	Medium               int `json:"medium"`
	Low                  int `json:"low"`
	LicenseIssues        int `json:"license_issues"`
	TyposquattingRisks   int `json:"typosquatting_risks"`
	IACIssues            int `json:"iac_issues"`
}

// handleLicenseScan handles license compliance scanning
func handleLicenseScan(c *gin.Context) {
	var input struct {
		Path string `json:"path" binding:"required"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Path is required"})
		return
	}

	log.Printf("📜 Starting license scan for: %s", input.Path)

	licenseScanner := scanner.NewLicenseScanner()
	result, err := licenseScanner.ScanDirectory(input.Path)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "License scan failed: " + err.Error()})
		return
	}

	log.Printf("✅ License scan complete: %d packages, %d issues", result.TotalPackages, len(result.Vulnerabilities))

	c.JSON(http.StatusOK, result)
}

// handleTyposquattingScan handles typosquatting detection
func handleTyposquattingScan(c *gin.Context) {
	var input struct {
		Path string `json:"path" binding:"required"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Path is required"})
		return
	}

	log.Printf("🔍 Starting typosquatting scan for: %s", input.Path)

	typoScanner := scanner.NewTyposquattingScanner()
	result, err := typoScanner.ScanDirectory(input.Path)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Typosquatting scan failed: " + err.Error()})
		return
	}

	log.Printf("✅ Typosquatting scan complete: %d packages, %d risks", result.TotalPackages, len(result.Vulnerabilities))

	c.JSON(http.StatusOK, result)
}

// handleIACScan handles Infrastructure as Code scanning
func handleIACScan(c *gin.Context) {
	var input struct {
		Path string `json:"path" binding:"required"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Path is required"})
		return
	}

	log.Printf("🏗️ Starting IAC scan for: %s", input.Path)

	iacScanner := scanner.NewIACScanner()
	result, err := iacScanner.ScanDirectory(input.Path)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "IAC scan failed: " + err.Error()})
		return
	}

	log.Printf("✅ IAC scan complete: %d files, %d issues", result.FilesScanned, len(result.Vulnerabilities))

	c.JSON(http.StatusOK, result)
}

// handleSCAFullScan handles comprehensive SCA scan (all modules)
func handleSCAFullScan(c *gin.Context) {
	var input SCAFullScanRequest

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Path is required"})
		return
	}

	log.Printf("🔬 Starting full SCA scan for: %s", input.Path)

	result := SCAFullScanResult{
		Path: input.Path,
	}

	// 1. Dependency Scan
	depScanner := scanner.NewDependencyScanner()
	depResults, err := depScanner.ScanDirectory(input.Path)
	if err == nil {
		result.Dependencies = depResults
		for _, dep := range depResults {
			result.Summary.Critical += dep.Summary.Critical
			result.Summary.High += dep.Summary.High
			result.Summary.Medium += dep.Summary.Medium
			result.Summary.Low += dep.Summary.Low
			result.Summary.TotalVulnerabilities += len(dep.Vulnerabilities)
		}
	}

	// 2. License Scan
	licenseScanner := scanner.NewLicenseScanner()
	licenseResult, err := licenseScanner.ScanDirectory(input.Path)
	if err == nil {
		result.Licenses = licenseResult
		result.Summary.LicenseIssues = len(licenseResult.Vulnerabilities)
		result.Summary.Critical += licenseResult.Summary.HighRisk
		result.Summary.Medium += licenseResult.Summary.MediumRisk
	}

	// 3. Typosquatting Scan
	typoScanner := scanner.NewTyposquattingScanner()
	typoResult, err := typoScanner.ScanDirectory(input.Path)
	if err == nil {
		result.Typosquatting = typoResult
		result.Summary.TyposquattingRisks = len(typoResult.Vulnerabilities)
		result.Summary.High += typoResult.Summary.HighRisk
		result.Summary.Medium += typoResult.Summary.MediumRisk
	}

	// 4. IAC Scan
	iacScanner := scanner.NewIACScanner()
	iacResult, err := iacScanner.ScanDirectory(input.Path)
	if err == nil {
		result.IAC = iacResult
		result.Summary.IACIssues = len(iacResult.Vulnerabilities)
		result.Summary.Critical += iacResult.Summary.Critical
		result.Summary.High += iacResult.Summary.High
		result.Summary.Medium += iacResult.Summary.Medium
		result.Summary.Low += iacResult.Summary.Low
	}

	// Calculate score
	result.Score = calculateSCAScore(result.Summary)

	log.Printf("✅ Full SCA scan complete - Score: %d/100", result.Score)

	c.JSON(http.StatusOK, result)
}

func calculateSCAScore(summary SCAFullSummary) int {
	score := 100

	// Penalties
	score -= summary.Critical * 25
	score -= summary.High * 15
	score -= summary.Medium * 5
	score -= summary.Low * 2
	score -= summary.LicenseIssues * 10
	score -= summary.TyposquattingRisks * 20

	if score < 0 {
		score = 0
	}

	return score
}
