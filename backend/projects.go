package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// Project represents a security project that can have both SAST and DAST scans
type Project struct {
	ID          uint           `gorm:"primaryKey" json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	LocalPath   string         `json:"local_path"`   // Path for SAST scans
	ProductionURL string       `json:"production_url"` // URL for DAST scans
	StagingURL  string         `json:"staging_url"`  // Optional staging URL
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
}

// ProjectScan links a scan (SAST or DAST) to a project
type ProjectScan struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	ProjectID    uint      `json:"project_id"`
	ScanType     string    `json:"scan_type"` // "SAST" or "DAST"
	ScanID       uint      `json:"scan_id"`   // ID from LocalScanResult or ScanResult
	Score        int       `json:"score"`
	Summary      string    `json:"summary"` // JSON summary
	CreatedAt    time.Time `json:"created_at"`
}

// ProjectCorrelation stores correlations between SAST and DAST findings
type ProjectCorrelation struct {
	ID              uint      `gorm:"primaryKey" json:"id"`
	ProjectID       uint      `json:"project_id"`
	SASTVulnType    string    `json:"sast_vuln_type"`
	DASTVulnType    string    `json:"dast_vuln_type"`
	CorrelationType string    `json:"correlation_type"` // "confirmed", "potential", "mitigated"
	RiskLevel       string    `json:"risk_level"`       // "CRITICAL", "HIGH", "MEDIUM", "LOW"
	Description     string    `json:"description"`
	CreatedAt       time.Time `json:"created_at"`
}

// ProjectDashboard represents the unified view of a project's security
type ProjectDashboard struct {
	Project       Project              `json:"project"`
	LatestSAST    *LocalScanResult     `json:"latest_sast"`
	LatestDAST    *ScanResult          `json:"latest_dast"`
	Correlations  []ProjectCorrelation `json:"correlations"`
	ScoreHistory  []ScorePoint         `json:"score_history"`
	RiskSummary   RiskSummary          `json:"risk_summary"`
}

type ScorePoint struct {
	Date     string `json:"date"`
	SASTScore int   `json:"sast_score"`
	DASTScore int   `json:"dast_score"`
}

type RiskSummary struct {
	TotalVulns       int `json:"total_vulns"`
	ConfirmedInProd  int `json:"confirmed_in_prod"`
	CodeOnly         int `json:"code_only"`
	ProdOnly         int `json:"prod_only"`
	CriticalRisks    int `json:"critical_risks"`
}

// ==================== HANDLERS ====================

func handleCreateProject(c *gin.Context) {
	var input struct {
		Name          string `json:"name" binding:"required"`
		Description   string `json:"description"`
		LocalPath     string `json:"local_path"`
		ProductionURL string `json:"production_url"`
		StagingURL    string `json:"staging_url"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Name is required"})
		return
	}

	project := Project{
		Name:          input.Name,
		Description:   input.Description,
		LocalPath:     input.LocalPath,
		ProductionURL: input.ProductionURL,
		StagingURL:    input.StagingURL,
	}

	// Auto-migrate if needed
	db.AutoMigrate(&Project{}, &ProjectScan{}, &ProjectCorrelation{})

	if err := db.Create(&project).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create project"})
		return
	}

	c.JSON(http.StatusCreated, project)
}

func handleGetProjects(c *gin.Context) {
	var projects []Project
	db.Order("updated_at desc").Find(&projects)
	c.JSON(http.StatusOK, projects)
}

func handleGetProject(c *gin.Context) {
	projectID := c.Param("id")

	var project Project
	if err := db.First(&project, projectID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Project not found"})
		return
	}

	c.JSON(http.StatusOK, project)
}

func handleUpdateProject(c *gin.Context) {
	projectID := c.Param("id")

	var project Project
	if err := db.First(&project, projectID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Project not found"})
		return
	}

	var input struct {
		Name          string `json:"name"`
		Description   string `json:"description"`
		LocalPath     string `json:"local_path"`
		ProductionURL string `json:"production_url"`
		StagingURL    string `json:"staging_url"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if input.Name != "" {
		project.Name = input.Name
	}
	if input.Description != "" {
		project.Description = input.Description
	}
	if input.LocalPath != "" {
		project.LocalPath = input.LocalPath
	}
	if input.ProductionURL != "" {
		project.ProductionURL = input.ProductionURL
	}
	if input.StagingURL != "" {
		project.StagingURL = input.StagingURL
	}

	db.Save(&project)
	c.JSON(http.StatusOK, project)
}

func handleGetProjectDashboard(c *gin.Context) {
	projectID := c.Param("id")

	var project Project
	if err := db.First(&project, projectID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Project not found"})
		return
	}

	dashboard := ProjectDashboard{
		Project: project,
	}

	// Get latest SAST scan for this project's path
	if project.LocalPath != "" {
		var sastScan LocalScanResult
		if err := db.Where("path = ?", project.LocalPath).Order("created_at desc").First(&sastScan).Error; err == nil {
			dashboard.LatestSAST = &sastScan
		}
	}

	// Get latest DAST scan for this project's URL
	if project.ProductionURL != "" {
		var dastScan ScanResult
		if err := db.Where("target LIKE ?", "%"+extractDomain(project.ProductionURL)+"%").Order("created_at desc").First(&dastScan).Error; err == nil {
			dashboard.LatestDAST = &dastScan
		}
	}

	// Get correlations
	db.Where("project_id = ?", projectID).Order("created_at desc").Find(&dashboard.Correlations)

	// Calculate risk summary
	dashboard.RiskSummary = calculateRiskSummary(dashboard.LatestSAST, dashboard.LatestDAST, dashboard.Correlations)

	// Get score history
	dashboard.ScoreHistory = getScoreHistory(project)

	c.JSON(http.StatusOK, dashboard)
}

func handleLinkScanToProject(c *gin.Context) {
	var input struct {
		ProjectID uint   `json:"project_id" binding:"required"`
		ScanType  string `json:"scan_type" binding:"required"` // "SAST" or "DAST"
		ScanID    uint   `json:"scan_id" binding:"required"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify project exists
	var project Project
	if err := db.First(&project, input.ProjectID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Project not found"})
		return
	}

	// Get scan details
	var score int
	var summary string

	if input.ScanType == "SAST" {
		var scan LocalScanResult
		if err := db.First(&scan, input.ScanID).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "SAST scan not found"})
			return
		}
		score = scan.Score
		summary = scan.Summary
		
		// Update project's local path if not set
		if project.LocalPath == "" {
			project.LocalPath = scan.Path
			db.Save(&project)
		}
	} else if input.ScanType == "DAST" {
		var scan ScanResult
		if err := db.First(&scan, input.ScanID).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "DAST scan not found"})
			return
		}
		score = scan.Score
		
		// Update project's production URL if not set
		if project.ProductionURL == "" {
			project.ProductionURL = scan.Target
			db.Save(&project)
		}
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid scan type. Use 'SAST' or 'DAST'"})
		return
	}

	projectScan := ProjectScan{
		ProjectID: input.ProjectID,
		ScanType:  input.ScanType,
		ScanID:    input.ScanID,
		Score:     score,
		Summary:   summary,
	}

	db.Create(&projectScan)

	// Trigger correlation analysis if we have both SAST and DAST
	go analyzeCorrelations(input.ProjectID)

	c.JSON(http.StatusCreated, projectScan)
}

func handleCorrelateProject(c *gin.Context) {
	projectID := c.Param("id")

	var project Project
	if err := db.First(&project, projectID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Project not found"})
		return
	}

	correlations := analyzeCorrelations(project.ID)
	c.JSON(http.StatusOK, gin.H{
		"correlations_found": len(correlations),
		"correlations":       correlations,
	})
}

// ==================== HELPER FUNCTIONS ====================

func extractDomain(url string) string {
	// Simple domain extraction
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	parts := strings.Split(url, "/")
	return parts[0]
}

func calculateRiskSummary(sast *LocalScanResult, dast *ScanResult, correlations []ProjectCorrelation) RiskSummary {
	summary := RiskSummary{}

	// Count SAST vulns
	if sast != nil {
		var sastSummary struct {
			Critical int `json:"critical"`
			High     int `json:"high"`
			Medium   int `json:"medium"`
			Low      int `json:"low"`
		}
		json.Unmarshal([]byte(sast.Summary), &sastSummary)
		summary.CodeOnly = sastSummary.Critical + sastSummary.High + sastSummary.Medium + sastSummary.Low
	}

	// Count DAST vulns
	if dast != nil {
		var metadata map[string]interface{}
		json.Unmarshal([]byte(dast.Metadata), &metadata)
		if sa, ok := metadata["security_audit"].(map[string]interface{}); ok {
			if vulns, ok := sa["vulnerabilities"].(map[string]interface{}); ok {
				if total, ok := vulns["total"].(float64); ok {
					summary.ProdOnly = int(total)
				}
			}
		}
	}

	// Count correlations
	for _, corr := range correlations {
		if corr.CorrelationType == "confirmed" {
			summary.ConfirmedInProd++
			if corr.RiskLevel == "CRITICAL" {
				summary.CriticalRisks++
			}
		}
	}

	summary.TotalVulns = summary.CodeOnly + summary.ProdOnly

	return summary
}

func getScoreHistory(project Project) []ScorePoint {
	var history []ScorePoint

	// Get SAST history
	var sastScans []LocalScanResult
	if project.LocalPath != "" {
		db.Where("path = ?", project.LocalPath).Order("created_at asc").Limit(10).Find(&sastScans)
	}

	// Get DAST history
	var dastScans []ScanResult
	if project.ProductionURL != "" {
		db.Where("target LIKE ?", "%"+extractDomain(project.ProductionURL)+"%").Order("created_at asc").Limit(10).Find(&dastScans)
	}

	// Merge into timeline (simplified - just use SAST dates)
	for _, scan := range sastScans {
		point := ScorePoint{
			Date:      scan.CreatedAt.Format("2006-01-02"),
			SASTScore: scan.Score,
		}
		
		// Find closest DAST scan
		for _, dast := range dastScans {
			if dast.CreatedAt.Before(scan.CreatedAt.Add(24 * time.Hour)) {
				point.DASTScore = dast.Score
			}
		}
		
		history = append(history, point)
	}

	return history
}

func analyzeCorrelations(projectID uint) []ProjectCorrelation {
	var project Project
	if err := db.First(&project, projectID).Error; err != nil {
		return nil
	}

	var correlations []ProjectCorrelation

	// Get latest SAST
	var sastScan LocalScanResult
	if project.LocalPath == "" {
		return correlations
	}
	if err := db.Where("path = ?", project.LocalPath).Order("created_at desc").First(&sastScan).Error; err != nil {
		return correlations
	}

	// Get latest DAST
	var dastScan ScanResult
	if project.ProductionURL == "" {
		return correlations
	}
	if err := db.Where("target LIKE ?", "%"+extractDomain(project.ProductionURL)+"%").Order("created_at desc").First(&dastScan).Error; err != nil {
		return correlations
	}

	// Parse SAST vulnerabilities
	var sastVulns []struct {
		Type     string `json:"type"`
		Severity string `json:"severity"`
	}
	json.Unmarshal([]byte(sastScan.Vulnerabilities), &sastVulns)

	// Parse DAST metadata for vulnerabilities
	var dastMeta map[string]interface{}
	json.Unmarshal([]byte(dastScan.Metadata), &dastMeta)

	// Correlation rules
	correlationRules := map[string][]string{
		"Google API Key":     {"API", "Authentication", "Key"},
		"AWS Access Key":     {"AWS", "Cloud", "Credentials"},
		"Password in Code":   {"Authentication", "Login", "Password"},
		"SQL Injection":      {"SQL", "Database", "Injection"},
		"XSS":                {"XSS", "Script", "Cross-Site"},
		"Private Key":        {"SSL", "Certificate", "TLS"},
		"JWT Secret":         {"JWT", "Token", "Authentication"},
	}

	// Check for correlations
	for _, sastVuln := range sastVulns {
		if keywords, ok := correlationRules[sastVuln.Type]; ok {
			// Check if any DAST finding relates
			dastRelated := checkDASTForKeywords(dastMeta, keywords)
			
			if dastRelated {
				corr := ProjectCorrelation{
					ProjectID:       projectID,
					SASTVulnType:    sastVuln.Type,
					DASTVulnType:    "Related finding in production",
					CorrelationType: "confirmed",
					RiskLevel:       escalateRisk(sastVuln.Severity),
					Description:     "Vulnerability found in code is potentially active in production",
				}
				
				// Save correlation
				db.Create(&corr)
				correlations = append(correlations, corr)
			}
		}
	}

	return correlations
}

func checkDASTForKeywords(metadata map[string]interface{}, keywords []string) bool {
	// Convert metadata to string for simple keyword search
	metaJSON, _ := json.Marshal(metadata)
	metaStr := strings.ToLower(string(metaJSON))

	for _, keyword := range keywords {
		if strings.Contains(metaStr, strings.ToLower(keyword)) {
			return true
		}
	}
	return false
}

func escalateRisk(severity string) string {
	// When code vuln is confirmed in production, escalate risk
	switch severity {
	case "HIGH":
		return "CRITICAL"
	case "MEDIUM":
		return "HIGH"
	case "LOW":
		return "MEDIUM"
	default:
		return severity
	}
}
