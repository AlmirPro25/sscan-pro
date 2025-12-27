package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"aegis-scan-backend/ai"
	"aegis-scan-backend/scanner"

	"github.com/gin-gonic/gin"
)

// ============================================================================
// DAST + SAST CORRELATION HANDLERS
// Enterprise-grade vulnerability correlation
// ============================================================================

// CorrelationRequest for DAST+SAST correlation
type CorrelationRequest struct {
	Target       string `json:"target"`
	DastScanID   uint   `json:"dast_scan_id"`   // ID of DAST scan
	SastScanID   uint   `json:"sast_scan_id"`   // ID of SAST scan
	SCAScanPath  string `json:"sca_scan_path"`  // Path for SCA/IAC scan
	Model        string `json:"model"`
	ApiKey       string `json:"api_key"`
}

// handleCorrelation performs DAST+SAST correlation
func handleCorrelation(c *gin.Context) {
	var input CorrelationRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	log.Printf("🔗 Starting DAST+SAST correlation for: %s", input.Target)

	// Collect DAST findings
	var dastFindings []ai.DASTFinding
	if input.DastScanID > 0 {
		var scan ScanResult
		if err := db.First(&scan, input.DastScanID).Error; err == nil {
			dastFindings = extractDASTFindings(scan)
		}
	}

	// Collect SAST findings
	var sastFindings []ai.SASTFinding
	if input.SastScanID > 0 {
		var localScan LocalScanResult
		if err := db.First(&localScan, input.SastScanID).Error; err == nil {
			sastFindings = extractSASTFindings(localScan)
		}
	}

	// Collect IAC findings
	var iacFindings []ai.IACFinding
	if input.SCAScanPath != "" {
		iacScanner := scanner.NewIACScanner()
		iacResult, err := iacScanner.ScanDirectory(input.SCAScanPath)
		if err == nil {
			iacFindings = convertIACFindings(iacResult)
		}
	}

	// Get API key
	apiKey := input.ApiKey
	if apiKey == "" {
		apiKey = os.Getenv("GEMINI_API_KEY")
	}

	model := input.Model
	if model == "" {
		model = "models/gemini-2.5-flash"
	}

	// Perform correlation
	correlator := ai.NewDASTSASTCorrelator(apiKey, model)
	report, err := correlator.Correlate(input.Target, dastFindings, sastFindings, iacFindings)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Correlation failed: " + err.Error()})
		return
	}

	log.Printf("✅ Correlation complete: %d correlated vulns, %d attack chains, score: %d",
		len(report.CorrelatedVulns), len(report.AttackChains), report.RiskScore)

	c.JSON(http.StatusOK, report)
}

// handleQuickCorrelation performs correlation from existing project
func handleQuickCorrelation(c *gin.Context) {
	projectID := c.Param("project_id")

	var project Project
	if err := db.First(&project, projectID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Project not found"})
		return
	}

	log.Printf("🔗 Quick correlation for project: %s", project.Name)

	// Get latest DAST scan for this project
	var dastFindings []ai.DASTFinding
	var dastScans []ScanResult
	db.Where("target LIKE ?", "%"+project.ProductionURL+"%").Order("created_at desc").Limit(1).Find(&dastScans)
	if len(dastScans) > 0 {
		dastFindings = extractDASTFindings(dastScans[0])
	}

	// Get latest SAST scan for this project
	var sastFindings []ai.SASTFinding
	var sastScans []LocalScanResult
	db.Where("path LIKE ?", "%"+project.LocalPath+"%").Order("created_at desc").Limit(1).Find(&sastScans)
	if len(sastScans) > 0 {
		sastFindings = extractSASTFindings(sastScans[0])
	}

	// Get IAC findings
	var iacFindings []ai.IACFinding
	if project.LocalPath != "" {
		iacScanner := scanner.NewIACScanner()
		iacResult, err := iacScanner.ScanDirectory(project.LocalPath)
		if err == nil {
			iacFindings = convertIACFindings(iacResult)
		}
	}

	// Get API key from environment
	apiKey := os.Getenv("GEMINI_API_KEY")

	// Perform correlation
	correlator := ai.NewDASTSASTCorrelator(apiKey, "models/gemini-2.5-flash")
	report, err := correlator.Correlate(project.ProductionURL, dastFindings, sastFindings, iacFindings)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Correlation failed: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, report)
}

// extractDASTFindings converts ScanResult to DASTFinding slice
func extractDASTFindings(scan ScanResult) []ai.DASTFinding {
	findings := []ai.DASTFinding{}

	var metadata map[string]interface{}
	if err := json.Unmarshal([]byte(scan.Metadata), &metadata); err != nil {
		return findings
	}

	// Extract from security_audit
	if secAudit, ok := metadata["security_audit"].(map[string]interface{}); ok {
		// XSS vulnerabilities
		if vulns, ok := secAudit["vulnerabilities"].(map[string]interface{}); ok {
			if xss, ok := vulns["xss"].([]interface{}); ok {
				for _, v := range xss {
					if vMap, ok := v.(map[string]interface{}); ok {
						findings = append(findings, ai.DASTFinding{
							Type:        "XSS",
							Severity:    getString(vMap, "severity"),
							URL:         getString(vMap, "location"),
							Parameter:   getString(vMap, "payload"),
							Evidence:    getString(vMap, "evidence"),
							Description: getString(vMap, "impact"),
							CWE:         "CWE-79",
						})
					}
				}
			}

			// SQLi vulnerabilities
			if sqli, ok := vulns["sqli"].([]interface{}); ok {
				for _, v := range sqli {
					if vMap, ok := v.(map[string]interface{}); ok {
						findings = append(findings, ai.DASTFinding{
							Type:        "SQL Injection",
							Severity:    getString(vMap, "severity"),
							URL:         getString(vMap, "location"),
							Parameter:   getString(vMap, "payload"),
							Evidence:    getString(vMap, "evidence"),
							Description: getString(vMap, "impact"),
							CWE:         "CWE-89",
						})
					}
				}
			}

			// Auth vulnerabilities
			if auth, ok := vulns["auth"].([]interface{}); ok {
				for _, v := range auth {
					if vMap, ok := v.(map[string]interface{}); ok {
						findings = append(findings, ai.DASTFinding{
							Type:        "Authentication Issue",
							Severity:    getString(vMap, "severity"),
							URL:         getString(vMap, "location"),
							Description: getString(vMap, "impact"),
							CWE:         "CWE-287",
						})
					}
				}
			}
		}

		// Leaked secrets
		if secrets, ok := secAudit["leaked_secrets"].([]interface{}); ok {
			for _, s := range secrets {
				if sMap, ok := s.(map[string]interface{}); ok {
					findings = append(findings, ai.DASTFinding{
						Type:        "Exposed Secret",
						Severity:    "HIGH",
						URL:         getString(sMap, "source"),
						Evidence:    getString(sMap, "snippet"),
						Description: "Secret exposed: " + getString(sMap, "type"),
						CWE:         "CWE-798",
					})
				}
			}
		}

		// Exposed files
		if files, ok := secAudit["exposed_files"].([]interface{}); ok {
			for _, f := range files {
				if fMap, ok := f.(map[string]interface{}); ok {
					findings = append(findings, ai.DASTFinding{
						Type:        "Exposed File",
						Severity:    getString(fMap, "severity"),
						URL:         getString(fMap, "url"),
						Description: "Sensitive file exposed: " + getString(fMap, "file"),
						CWE:         "CWE-538",
					})
				}
			}
		}
	}

	return findings
}

// extractSASTFindings converts LocalScanResult to SASTFinding slice
func extractSASTFindings(scan LocalScanResult) []ai.SASTFinding {
	findings := []ai.SASTFinding{}

	var vulns []map[string]interface{}
	if err := json.Unmarshal([]byte(scan.Vulnerabilities), &vulns); err != nil {
		return findings
	}

	for _, v := range vulns {
		findings = append(findings, ai.SASTFinding{
			Type:        getString(v, "type"),
			Severity:    getString(v, "severity"),
			File:        getString(v, "file"),
			Line:        getInt(v, "line"),
			Code:        getString(v, "code"),
			Description: getString(v, "description"),
			Remediation: getString(v, "remediation"),
			CWE:         getString(v, "cwe"),
			Confidence:  getString(v, "confidence"),
		})
	}

	return findings
}

// convertIACFindings converts scanner.IACScanResult to ai.IACFinding slice
func convertIACFindings(result *scanner.IACScanResult) []ai.IACFinding {
	findings := []ai.IACFinding{}

	for _, v := range result.Vulnerabilities {
		findings = append(findings, ai.IACFinding{
			Type:        v.Type,
			Severity:    v.Severity,
			File:        v.File,
			Line:        v.Line,
			Code:        v.Code,
			Description: v.Description,
			Remediation: v.Remediation,
			Resource:    v.Resource,
		})
	}

	return findings
}

// Helper functions
func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func getInt(m map[string]interface{}, key string) int {
	if v, ok := m[key].(float64); ok {
		return int(v)
	}
	return 0
}
