package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// ============================================================================
// ADVANCED SCAN HANDLERS - Integration with Worker Modules
// ============================================================================

// AdvancedScanResult stores results from advanced scanning modules
type AdvancedScanResult struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	ScanResultID   uint      `json:"scan_result_id"` // Link to main DAST scan
	URL            string    `json:"url"`
	ModulesRun     string    `json:"modules_run"` // JSON array of module names
	Infrastructure string    `json:"infrastructure"` // JSON
	Subdomains     string    `json:"subdomains"` // JSON
	Reputation     string    `json:"reputation"` // JSON
	Authenticated  string    `json:"authenticated"` // JSON
	Summary        string    `json:"summary"` // JSON
	CreatedAt      time.Time `json:"created_at"`
}

// InfrastructureScanRequest for infrastructure scanning
type InfrastructureScanRequest struct {
	URL string `json:"url" binding:"required"`
}

// SubdomainScanRequest for subdomain enumeration
type SubdomainScanRequest struct {
	URL string `json:"url" binding:"required"`
}

// ReputationScanRequest for reputation checking
type ReputationScanRequest struct {
	URL string `json:"url" binding:"required"`
}

// AuthenticatedScanRequest for authenticated testing
type AuthenticatedScanRequest struct {
	URL         string `json:"url" binding:"required"`
	Credentials struct {
		Username      string `json:"username" binding:"required"`
		Password      string `json:"password" binding:"required"`
		LoginURL      string `json:"login_url"`
		UsernameField string `json:"username_field"`
		PasswordField string `json:"password_field"`
	} `json:"credentials" binding:"required"`
}

// AdvancedScanRequest for full advanced scan
type AdvancedScanRequest struct {
	URL         string `json:"url" binding:"required"`
	ScanResultID uint  `json:"scan_result_id"` // Optional: link to existing DAST scan
	Modules     struct {
		Infrastructure bool `json:"infrastructure"`
		Subdomains     bool `json:"subdomains"`
		Reputation     bool `json:"reputation"`
		Authenticated  bool `json:"authenticated"`
	} `json:"modules"`
	Credentials *struct {
		Username      string `json:"username"`
		Password      string `json:"password"`
		LoginURL      string `json:"login_url"`
		UsernameField string `json:"username_field"`
		PasswordField string `json:"password_field"`
	} `json:"credentials"`
}

// handleInfrastructureScan handles infrastructure scanning
func handleInfrastructureScan(c *gin.Context) {
	var input InfrastructureScanRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "URL is required"})
		return
	}

	log.Printf("🔍 Starting infrastructure scan for: %s", input.URL)

	result, err := callWorkerModule("infrastructure", map[string]interface{}{
		"url": input.URL,
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

// handleSubdomainScan handles subdomain enumeration
func handleSubdomainScan(c *gin.Context) {
	var input SubdomainScanRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "URL is required"})
		return
	}

	log.Printf("🔍 Starting subdomain scan for: %s", input.URL)

	result, err := callWorkerModule("subdomains", map[string]interface{}{
		"url": input.URL,
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

// handleReputationScan handles reputation checking
func handleReputationScan(c *gin.Context) {
	var input ReputationScanRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "URL is required"})
		return
	}

	log.Printf("🔍 Starting reputation scan for: %s", input.URL)

	result, err := callWorkerModule("reputation", map[string]interface{}{
		"url": input.URL,
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

// handleAuthenticatedScan handles authenticated testing
func handleAuthenticatedScan(c *gin.Context) {
	var input AuthenticatedScanRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "URL and credentials are required"})
		return
	}

	log.Printf("🔍 Starting authenticated scan for: %s", input.URL)

	result, err := callWorkerModule("authenticated", map[string]interface{}{
		"url": input.URL,
		"credentials": map[string]interface{}{
			"username":       input.Credentials.Username,
			"password":       input.Credentials.Password,
			"loginUrl":       input.Credentials.LoginURL,
			"usernameField":  input.Credentials.UsernameField,
			"passwordField":  input.Credentials.PasswordField,
		},
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

// handleAdvancedScan handles full advanced scan with all modules
func handleAdvancedScan(c *gin.Context) {
	var input AdvancedScanRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "URL is required"})
		return
	}

	log.Printf("🔍 Starting advanced scan for: %s", input.URL)

	// Build request for worker
	workerRequest := map[string]interface{}{
		"url": input.URL,
		"modules": map[string]bool{
			"infrastructure": input.Modules.Infrastructure,
			"subdomains":     input.Modules.Subdomains,
			"reputation":     input.Modules.Reputation,
			"authenticated":  input.Modules.Authenticated,
		},
	}

	// Add credentials if provided
	if input.Credentials != nil && input.Credentials.Username != "" {
		workerRequest["credentials"] = map[string]interface{}{
			"username":      input.Credentials.Username,
			"password":      input.Credentials.Password,
			"loginUrl":      input.Credentials.LoginURL,
			"usernameField": input.Credentials.UsernameField,
			"passwordField": input.Credentials.PasswordField,
		}
	}

	result, err := callWorkerModule("advanced", workerRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Save to database
	modulesRun := []string{}
	if input.Modules.Infrastructure {
		modulesRun = append(modulesRun, "infrastructure")
	}
	if input.Modules.Subdomains {
		modulesRun = append(modulesRun, "subdomains")
	}
	if input.Modules.Reputation {
		modulesRun = append(modulesRun, "reputation")
	}
	if input.Modules.Authenticated {
		modulesRun = append(modulesRun, "authenticated")
	}

	modulesJSON, _ := json.Marshal(modulesRun)

	// Extract module results
	resultMap, ok := result.(map[string]interface{})
	if !ok {
		c.JSON(http.StatusOK, result)
		return
	}

	modules, _ := resultMap["modules"].(map[string]interface{})
	summary, _ := resultMap["summary"].(map[string]interface{})

	infraJSON, _ := json.Marshal(modules["infrastructure"])
	subdomainsJSON, _ := json.Marshal(modules["subdomains"])
	reputationJSON, _ := json.Marshal(modules["reputation"])
	authJSON, _ := json.Marshal(modules["authenticated"])
	summaryJSON, _ := json.Marshal(summary)

	// Auto-migrate if not exists
	db.AutoMigrate(&AdvancedScanResult{})

	advancedResult := AdvancedScanResult{
		ScanResultID:   input.ScanResultID,
		URL:            input.URL,
		ModulesRun:     string(modulesJSON),
		Infrastructure: string(infraJSON),
		Subdomains:     string(subdomainsJSON),
		Reputation:     string(reputationJSON),
		Authenticated:  string(authJSON),
		Summary:        string(summaryJSON),
	}

	if err := db.Create(&advancedResult).Error; err != nil {
		log.Printf("⚠️ Failed to save advanced scan result: %v", err)
	}

	// Add ID to response
	resultMap["id"] = advancedResult.ID

	c.JSON(http.StatusOK, resultMap)
}

// handleGetAdvancedScan retrieves an advanced scan result
func handleGetAdvancedScan(c *gin.Context) {
	scanID := c.Param("scan_id")

	var result AdvancedScanResult
	if err := db.First(&result, scanID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Advanced scan not found"})
		return
	}

	// Parse JSON fields
	var infrastructure, subdomains, reputation, authenticated, summary interface{}
	json.Unmarshal([]byte(result.Infrastructure), &infrastructure)
	json.Unmarshal([]byte(result.Subdomains), &subdomains)
	json.Unmarshal([]byte(result.Reputation), &reputation)
	json.Unmarshal([]byte(result.Authenticated), &authenticated)
	json.Unmarshal([]byte(result.Summary), &summary)

	var modulesRun []string
	json.Unmarshal([]byte(result.ModulesRun), &modulesRun)

	c.JSON(http.StatusOK, gin.H{
		"id":             result.ID,
		"scan_result_id": result.ScanResultID,
		"url":            result.URL,
		"modules_run":    modulesRun,
		"modules": gin.H{
			"infrastructure": infrastructure,
			"subdomains":     subdomains,
			"reputation":     reputation,
			"authenticated":  authenticated,
		},
		"summary":    summary,
		"created_at": result.CreatedAt,
	})
}

// handleGetAdvancedScanHistory retrieves advanced scan history
func handleGetAdvancedScanHistory(c *gin.Context) {
	var results []AdvancedScanResult
	db.Order("created_at desc").Limit(20).Find(&results)

	response := make([]gin.H, 0)
	for _, r := range results {
		var summary map[string]interface{}
		json.Unmarshal([]byte(r.Summary), &summary)

		var modulesRun []string
		json.Unmarshal([]byte(r.ModulesRun), &modulesRun)

		response = append(response, gin.H{
			"id":          r.ID,
			"url":         r.URL,
			"modules_run": modulesRun,
			"summary":     summary,
			"created_at":  r.CreatedAt,
		})
	}

	c.JSON(http.StatusOK, response)
}

// callWorkerModule calls a specific worker module
func callWorkerModule(module string, payload map[string]interface{}) (interface{}, error) {
	workerURL := fmt.Sprintf("http://localhost:3001/scan/%s", module)

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %v", err)
	}

	client := &http.Client{Timeout: 180 * time.Second} // 3 minutes for advanced scans
	resp, err := client.Post(workerURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, fmt.Errorf("worker unreachable: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&errResp)
		return nil, fmt.Errorf("worker error: %v", errResp["details"])
	}

	var result interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return result, nil
}
