package orchestrator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ============================================================================
// AEGIS CENTRAL INTELLIGENCE ORCHESTRATOR - EXECUTOR (Caller 2)
// Executes tool calls from the AI planner - NEVER decides, only acts
// ============================================================================

// ToolHandler is the function signature for tool handlers
type ToolHandler func(args map[string]interface{}) (interface{}, error)

// ExecutionConfig defines execution parameters based on risk level
type ExecutionConfig struct {
	Timeout     time.Duration
	MaxRetries  int
	LogLevel    string // minimal, standard, verbose
	AllowRetry  bool
}

// RiskConfigs maps risk levels to execution configurations
var RiskConfigs = map[string]ExecutionConfig{
	"low": {
		Timeout:    60 * time.Second,
		MaxRetries: 2,
		LogLevel:   "minimal",
		AllowRetry: true,
	},
	"medium": {
		Timeout:    90 * time.Second,
		MaxRetries: 1,
		LogLevel:   "standard",
		AllowRetry: true,
	},
	"high": {
		Timeout:    120 * time.Second,
		MaxRetries: 0,
		LogLevel:   "verbose",
		AllowRetry: false,
	},
	"critical": {
		Timeout:    180 * time.Second,
		MaxRetries: 0,
		LogLevel:   "verbose",
		AllowRetry: false,
	},
}

// ToolExecutor executes tool calls
type ToolExecutor struct {
	backendURL   string
	workerURL    string
	httpClient   *http.Client
	toolHandlers map[string]ToolHandler
	DryRunMode   bool   // If true, simulates execution without actually running
	ExecutionID  string // Current execution graph ID
}

// ToolCall represents a tool invocation request
type ToolCall struct {
	Name        string                 `json:"name"`
	Arguments   map[string]interface{} `json:"arguments"`
	ExecutionID string                 `json:"execution_id,omitempty"`
	ParentStep  int                    `json:"parent_step,omitempty"`
	DryRun      bool                   `json:"dry_run,omitempty"`
}

// ToolResult represents the result of a tool execution
type ToolResult struct {
	ToolName    string      `json:"tool_name"`
	Success     bool        `json:"success"`
	Result      interface{} `json:"result"`
	Error       string      `json:"error,omitempty"`
	Duration    int64       `json:"duration_ms"`
	Timestamp   time.Time   `json:"timestamp"`
	ExecutionID string      `json:"execution_id,omitempty"`
	ParentStep  int         `json:"parent_step,omitempty"`
	DryRun      bool        `json:"dry_run,omitempty"`
	RiskLevel   string      `json:"risk_level,omitempty"`
	Retries     int         `json:"retries,omitempty"`
}

// NewToolExecutor creates a new executor with handler map
func NewToolExecutor(backendURL, workerURL string) *ToolExecutor {
	if backendURL == "" {
		backendURL = "http://localhost:8080"
	}
	if workerURL == "" {
		workerURL = "http://localhost:3001"
	}
	
	e := &ToolExecutor{
		backendURL: backendURL,
		workerURL:  workerURL,
		httpClient: &http.Client{Timeout: 120 * time.Second},
	}
	
	// Initialize handler map - eliminates giant switch statement
	e.toolHandlers = map[string]ToolHandler{
		// Scanning tools
		"scan_website":       e.scanWebsite,
		"scan_code":          e.scanCode,
		"scan_dependencies":  e.scanDependencies,
		"scan_infrastructure": e.scanInfrastructure,
		"scan_subdomains":    e.scanSubdomains,
		"scan_reputation":    e.scanReputation,
		"scan_authenticated": e.scanAuthenticated,
		"scan_iac":           e.scanIAC,
		"scan_licenses":      e.scanLicenses,
		"scan_typosquatting": e.scanTyposquatting,
		
		// Browser tools
		"navigate_to":               e.navigateTo,
		"take_screenshot":           e.takeScreenshot,
		"take_contextual_screenshot": e.takeContextualScreenshot,
		"take_forensic_screenshot":  e.takeForensicScreenshot,
		"click_element":             e.clickElement,
		"fill_input":                e.fillInput,
		"get_page_content":          e.getPageContent,
		"execute_javascript":        e.executeJavaScript,
		
		// Database tools
		"query_scan_history": e.queryScanHistory,
		"get_scan_details":   e.getScanDetails,
		"get_project_data":   e.getProjectData,
		"list_projects":      e.listProjects,
		
		// Correlation tools
		"correlate_dast_sast":   e.correlateDastSast,
		"analyze_attack_surface": e.analyzeAttackSurface,
		
		// Report tools
		"generate_ai_report": e.generateAIReport,
		"generate_pdf":       e.generatePDF,
		"compare_scans":      e.compareScans,
		
		// Autofix tools
		"generate_autofix":     e.generateAutofix,
		"create_pull_request":  e.createPullRequest,
		
		// Utility tools
		"get_system_status":   e.getSystemStatus,
		"get_dashboard_stats": e.getDashboardStats,
		
		// Memory tools
		"remember_vulnerability": e.rememberVulnerability,
		"query_memory":          e.queryMemory,
		"get_security_insights": e.getSecurityInsights,
		"get_memory_stats":      e.getMemoryStats,
		"record_learning":       e.recordLearning,
		
		// Meta-analysis tools
		"analyze_system_weaknesses": e.analyzeSystemWeaknesses,
		"get_maturity_score":        e.getMaturityScore,
		"get_coverage_gaps":         e.getCoverageGaps,
	}
	
	return e
}

// Execute runs a tool call and returns the result
func (e *ToolExecutor) Execute(call ToolCall) ToolResult {
	start := time.Now()
	
	// Generate execution ID if not provided
	execID := call.ExecutionID
	if execID == "" {
		execID = e.ExecutionID
	}
	if execID == "" {
		execID = fmt.Sprintf("exec-%d", time.Now().UnixNano())
	}
	
	result := ToolResult{
		ToolName:    call.Name,
		Timestamp:   start,
		ExecutionID: execID,
		ParentStep:  call.ParentStep,
		DryRun:      call.DryRun || e.DryRunMode,
	}

	// Get tool metadata for risk-based config
	toolDef := GetToolByName(call.Name)
	if toolDef != nil {
		result.RiskLevel = toolDef.RiskLevel
	}

	// ========== REGISTRY VALIDATION ==========
	validationErrors := ValidateToolArguments(call.Name, call.Arguments)
	if len(validationErrors) > 0 {
		result.Duration = time.Since(start).Milliseconds()
		result.Success = false
		result.Error = fmt.Sprintf("Validação falhou: %v", validationErrors)
		return result
	}

	// ========== HANDLER MAP LOOKUP ==========
	handler, exists := e.toolHandlers[call.Name]
	if !exists {
		result.Duration = time.Since(start).Milliseconds()
		result.Success = false
		result.Error = fmt.Sprintf("ferramenta desconhecida: %s", call.Name)
		return result
	}

	// ========== DRY-RUN MODE ==========
	if result.DryRun {
		result.Duration = time.Since(start).Milliseconds()
		result.Success = true
		result.Result = map[string]interface{}{
			"dry_run":     true,
			"tool":        call.Name,
			"args":        call.Arguments,
			"would_execute": true,
			"risk_level":  result.RiskLevel,
			"message":     fmt.Sprintf("DRY-RUN: %s seria executado com args: %v", call.Name, call.Arguments),
		}
		return result
	}

	// ========== RISK-BASED EXECUTION CONFIG ==========
	config := RiskConfigs["medium"] // default
	if toolDef != nil {
		if cfg, ok := RiskConfigs[toolDef.RiskLevel]; ok {
			config = cfg
		}
	}

	// ========== EXECUTE WITH RETRY LOGIC ==========
	var res interface{}
	var err error
	retries := 0

	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		if attempt > 0 {
			retries = attempt
			time.Sleep(time.Duration(attempt) * time.Second) // Backoff
		}

		// Execute with timeout
		done := make(chan bool, 1)
		go func() {
			res, err = handler(call.Arguments)
			done <- true
		}()

		select {
		case <-done:
			if err == nil {
				// Success
				result.Duration = time.Since(start).Milliseconds()
				result.Success = true
				result.Result = res
				result.Retries = retries
				return result
			}
			// Error - check if retry allowed
			if !config.AllowRetry || attempt >= config.MaxRetries {
				break
			}
		case <-time.After(config.Timeout):
			err = fmt.Errorf("timeout após %v", config.Timeout)
			if !config.AllowRetry || attempt >= config.MaxRetries {
				break
			}
		}
	}

	// Final result (error case)
	result.Duration = time.Since(start).Milliseconds()
	result.Success = false
	result.Error = err.Error()
	result.Retries = retries

	return result
}

// SetDryRunMode enables or disables dry-run mode
func (e *ToolExecutor) SetDryRunMode(enabled bool) {
	e.DryRunMode = enabled
}

// SetExecutionID sets the current execution graph ID
func (e *ToolExecutor) SetExecutionID(id string) {
	e.ExecutionID = id
}

// NewExecutionID generates a new execution graph ID
func NewExecutionID() string {
	return fmt.Sprintf("exec-%d", time.Now().UnixNano())
}

// ============================================================================
// TYPED ARGUMENT STRUCTS FOR CRITICAL TOOLS
// Provides type safety after initial map[string]interface{} validation
// ============================================================================

// ScanAuthenticatedArgs for scan_authenticated (high risk)
type ScanAuthenticatedArgs struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
	LoginURL string `json:"login_url,omitempty"`
}

// CreatePullRequestArgs for create_pull_request (critical risk)
type CreatePullRequestArgs struct {
	RepoURL    string        `json:"repo_url"`
	Fixes      []interface{} `json:"fixes"`
	BranchName string        `json:"branch_name,omitempty"`
}

// ExecuteJavaScriptArgs for execute_javascript (critical risk)
type ExecuteJavaScriptArgs struct {
	Code string `json:"code"`
}

// parseTypedArgs converts map to typed struct with validation
func parseTypedArgs[T any](args map[string]interface{}) (*T, error) {
	jsonBytes, err := json.Marshal(args)
	if err != nil {
		return nil, fmt.Errorf("falha ao serializar argumentos: %v", err)
	}
	
	var typed T
	if err := json.Unmarshal(jsonBytes, &typed); err != nil {
		return nil, fmt.Errorf("falha ao converter argumentos: %v", err)
	}
	
	return &typed, nil
}

// ============================================================================
// SCANNING TOOL IMPLEMENTATIONS
// ============================================================================

func (e *ToolExecutor) scanWebsite(args map[string]interface{}) (interface{}, error) {
	url, ok := args["url"].(string)
	if !ok {
		return nil, fmt.Errorf("url é obrigatório")
	}
	return e.postJSON("/api/v1/scan", map[string]string{"url": url})
}

func (e *ToolExecutor) scanCode(args map[string]interface{}) (interface{}, error) {
	path, ok := args["path"].(string)
	if !ok {
		return nil, fmt.Errorf("path é obrigatório")
	}
	return e.postJSON("/api/v1/scan-local", map[string]string{"path": path})
}

func (e *ToolExecutor) scanDependencies(args map[string]interface{}) (interface{}, error) {
	path, ok := args["path"].(string)
	if !ok {
		return nil, fmt.Errorf("path é obrigatório")
	}
	return e.postJSON("/api/v1/scan-local/dependencies", map[string]string{"path": path})
}

func (e *ToolExecutor) scanInfrastructure(args map[string]interface{}) (interface{}, error) {
	url, ok := args["url"].(string)
	if !ok {
		return nil, fmt.Errorf("url é obrigatório")
	}
	return e.postWorkerJSON("/scan/infrastructure", map[string]string{"url": url})
}

func (e *ToolExecutor) scanSubdomains(args map[string]interface{}) (interface{}, error) {
	url, ok := args["url"].(string)
	if !ok {
		return nil, fmt.Errorf("url é obrigatório")
	}
	return e.postWorkerJSON("/scan/subdomains", map[string]string{"url": url})
}

func (e *ToolExecutor) scanReputation(args map[string]interface{}) (interface{}, error) {
	url, ok := args["url"].(string)
	if !ok {
		return nil, fmt.Errorf("url é obrigatório")
	}
	return e.postWorkerJSON("/scan/reputation", map[string]string{"url": url})
}

func (e *ToolExecutor) scanAuthenticated(args map[string]interface{}) (interface{}, error) {
	// Parse to typed struct for critical tool
	typed, err := parseTypedArgs[ScanAuthenticatedArgs](args)
	if err != nil {
		return nil, err
	}
	
	if typed.URL == "" || typed.Username == "" || typed.Password == "" {
		return nil, fmt.Errorf("url, username e password são obrigatórios")
	}
	
	return e.postWorkerJSON("/scan/authenticated", map[string]interface{}{
		"url":       typed.URL,
		"username":  typed.Username,
		"password":  typed.Password,
		"login_url": typed.LoginURL,
	})
}

func (e *ToolExecutor) scanIAC(args map[string]interface{}) (interface{}, error) {
	path, ok := args["path"].(string)
	if !ok {
		return nil, fmt.Errorf("path é obrigatório")
	}
	return e.postJSON("/api/v1/sca/iac", map[string]string{"path": path})
}

func (e *ToolExecutor) scanLicenses(args map[string]interface{}) (interface{}, error) {
	path, ok := args["path"].(string)
	if !ok {
		return nil, fmt.Errorf("path é obrigatório")
	}
	return e.postJSON("/api/v1/sca/licenses", map[string]string{"path": path})
}

func (e *ToolExecutor) scanTyposquatting(args map[string]interface{}) (interface{}, error) {
	path, ok := args["path"].(string)
	if !ok {
		return nil, fmt.Errorf("path é obrigatório")
	}
	return e.postJSON("/api/v1/sca/typosquatting", map[string]string{"path": path})
}

// ============================================================================
// BROWSER TOOL IMPLEMENTATIONS
// ============================================================================

func (e *ToolExecutor) navigateTo(args map[string]interface{}) (interface{}, error) {
	url, ok := args["url"].(string)
	if !ok {
		return nil, fmt.Errorf("url é obrigatório")
	}
	return e.postWorkerJSON("/browser/navigate", map[string]string{"url": url})
}

func (e *ToolExecutor) takeScreenshot(args map[string]interface{}) (interface{}, error) {
	fullPage := true
	if fp, ok := args["full_page"].(bool); ok {
		fullPage = fp
	}
	return e.postWorkerJSON("/browser/screenshot", map[string]interface{}{"full_page": fullPage})
}

func (e *ToolExecutor) takeContextualScreenshot(args map[string]interface{}) (interface{}, error) {
	includeDom := true
	includeConsole := false
	if dom, ok := args["include_dom"].(bool); ok {
		includeDom = dom
	}
	if console, ok := args["include_console"].(bool); ok {
		includeConsole = console
	}
	return e.postWorkerJSON("/browser/contextual-screenshot", map[string]interface{}{
		"include_dom":     includeDom,
		"include_console": includeConsole,
	})
}

func (e *ToolExecutor) takeForensicScreenshot(args map[string]interface{}) (interface{}, error) {
	includeNetwork := true
	includeCookies := true
	includeStorage := true
	if network, ok := args["include_network"].(bool); ok {
		includeNetwork = network
	}
	if cookies, ok := args["include_cookies"].(bool); ok {
		includeCookies = cookies
	}
	if storage, ok := args["include_storage"].(bool); ok {
		includeStorage = storage
	}
	return e.postWorkerJSON("/browser/forensic-screenshot", map[string]interface{}{
		"include_network": includeNetwork,
		"include_cookies": includeCookies,
		"include_storage": includeStorage,
	})
}

func (e *ToolExecutor) clickElement(args map[string]interface{}) (interface{}, error) {
	return e.postWorkerJSON("/browser/click", args)
}

func (e *ToolExecutor) fillInput(args map[string]interface{}) (interface{}, error) {
	return e.postWorkerJSON("/browser/fill", args)
}

func (e *ToolExecutor) getPageContent(args map[string]interface{}) (interface{}, error) {
	return e.getWorkerJSON("/browser/content")
}

func (e *ToolExecutor) executeJavaScript(args map[string]interface{}) (interface{}, error) {
	// Parse to typed struct for critical tool
	typed, err := parseTypedArgs[ExecuteJavaScriptArgs](args)
	if err != nil {
		return nil, err
	}
	
	if typed.Code == "" {
		return nil, fmt.Errorf("code é obrigatório")
	}
	
	return e.postWorkerJSON("/browser/execute", map[string]string{"code": typed.Code})
}

// ============================================================================
// DATABASE TOOL IMPLEMENTATIONS
// ============================================================================

func (e *ToolExecutor) queryScanHistory(args map[string]interface{}) (interface{}, error) {
	return e.getJSON("/api/v1/history")
}

func (e *ToolExecutor) getScanDetails(args map[string]interface{}) (interface{}, error) {
	scanID, ok := args["scan_id"].(float64)
	if !ok {
		return nil, fmt.Errorf("scan_id é obrigatório")
	}
	return e.getJSON(fmt.Sprintf("/api/v1/ai/report/%d", int(scanID)))
}

func (e *ToolExecutor) getProjectData(args map[string]interface{}) (interface{}, error) {
	projectID, ok := args["project_id"].(float64)
	if !ok {
		return nil, fmt.Errorf("project_id é obrigatório")
	}
	return e.getJSON(fmt.Sprintf("/api/v1/projects/%d", int(projectID)))
}

func (e *ToolExecutor) listProjects(args map[string]interface{}) (interface{}, error) {
	return e.getJSON("/api/v1/projects")
}

// ============================================================================
// CORRELATION TOOL IMPLEMENTATIONS
// ============================================================================

func (e *ToolExecutor) correlateDastSast(args map[string]interface{}) (interface{}, error) {
	projectID, ok := args["project_id"].(float64)
	if !ok {
		return nil, fmt.Errorf("project_id é obrigatório")
	}
	return e.getJSON(fmt.Sprintf("/api/v1/correlate/project/%d", int(projectID)))
}

func (e *ToolExecutor) analyzeAttackSurface(args map[string]interface{}) (interface{}, error) {
	url, ok := args["url"].(string)
	if !ok {
		return nil, fmt.Errorf("url é obrigatório")
	}
	return e.postJSON("/api/v1/scan/advanced", map[string]interface{}{
		"url":            url,
		"infrastructure": true,
		"subdomains":     true,
		"reputation":     true,
	})
}

// ============================================================================
// REPORT TOOL IMPLEMENTATIONS
// ============================================================================

func (e *ToolExecutor) generateAIReport(args map[string]interface{}) (interface{}, error) {
	scanID, ok := args["scan_id"].(float64)
	if !ok {
		return nil, fmt.Errorf("scan_id é obrigatório")
	}
	model := "models/gemini-2.5-flash"
	if m, ok := args["model"].(string); ok {
		model = m
	}
	return e.postJSON("/api/v1/ai/report", map[string]interface{}{
		"scan_id": int(scanID),
		"model":   model,
	})
}

func (e *ToolExecutor) generatePDF(args map[string]interface{}) (interface{}, error) {
	scanID, ok := args["scan_id"].(float64)
	if !ok {
		return nil, fmt.Errorf("scan_id é obrigatório")
	}
	return map[string]string{
		"pdf_url": fmt.Sprintf("%s/api/v1/pdf/%d", e.backendURL, int(scanID)),
	}, nil
}

func (e *ToolExecutor) compareScans(args map[string]interface{}) (interface{}, error) {
	scanID1, ok1 := args["scan_id_1"].(float64)
	scanID2, ok2 := args["scan_id_2"].(float64)
	if !ok1 || !ok2 {
		return nil, fmt.Errorf("scan_id_1 e scan_id_2 são obrigatórios")
	}
	return e.getJSON(fmt.Sprintf("/api/v1/compare/%d/%d", int(scanID1), int(scanID2)))
}

// ============================================================================
// AUTOFIX TOOL IMPLEMENTATIONS
// ============================================================================

func (e *ToolExecutor) generateAutofix(args map[string]interface{}) (interface{}, error) {
	scanID, ok := args["scan_id"].(float64)
	if !ok {
		return nil, fmt.Errorf("scan_id é obrigatório")
	}
	return e.postJSON("/api/v1/autofix/generate", map[string]interface{}{
		"scan_id": int(scanID),
	})
}

func (e *ToolExecutor) createPullRequest(args map[string]interface{}) (interface{}, error) {
	// Parse to typed struct for critical tool
	typed, err := parseTypedArgs[CreatePullRequestArgs](args)
	if err != nil {
		return nil, err
	}
	
	if typed.RepoURL == "" || len(typed.Fixes) == 0 {
		return nil, fmt.Errorf("repo_url e fixes são obrigatórios")
	}
	
	branchName := typed.BranchName
	if branchName == "" {
		branchName = "aegis-autofix"
	}
	
	return e.postJSON("/api/v1/autofix/create-pr", map[string]interface{}{
		"repo_url":    typed.RepoURL,
		"fixes":       typed.Fixes,
		"branch_name": branchName,
	})
}

// ============================================================================
// UTILITY TOOL IMPLEMENTATIONS
// ============================================================================

func (e *ToolExecutor) getSystemStatus(args map[string]interface{}) (interface{}, error) {
	status := map[string]interface{}{
		"backend": "checking...",
		"worker":  "checking...",
	}

	// Check backend
	resp, err := e.httpClient.Get(e.backendURL + "/api/v1/health")
	if err == nil && resp.StatusCode == 200 {
		status["backend"] = "online"
	} else {
		status["backend"] = "offline"
	}

	// Check worker
	resp, err = e.httpClient.Get(e.workerURL + "/health")
	if err == nil && resp.StatusCode == 200 {
		status["worker"] = "online"
	} else {
		status["worker"] = "offline"
	}

	return status, nil
}

func (e *ToolExecutor) getDashboardStats(args map[string]interface{}) (interface{}, error) {
	return e.getJSON("/api/v1/dashboard/stats")
}

// ============================================================================
// MEMORY TOOL IMPLEMENTATIONS
// ============================================================================

func (e *ToolExecutor) rememberVulnerability(args map[string]interface{}) (interface{}, error) {
	vulnType, _ := args["type"].(string)
	severity, _ := args["severity"].(string)
	target, _ := args["target"].(string)
	location, _ := args["location"].(string)
	description, _ := args["description"].(string)

	if vulnType == "" || target == "" {
		return nil, fmt.Errorf("type e target são obrigatórios")
	}

	memory := GetSecurityMemory()
	memory.RecordVulnerability(VulnerabilityMemory{
		Type:        vulnType,
		Severity:    severity,
		Target:      target,
		Location:    location,
		Description: description,
	})

	return map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Vulnerabilidade %s registrada na memória", vulnType),
	}, nil
}

func (e *ToolExecutor) queryMemory(args map[string]interface{}) (interface{}, error) {
	queryType, _ := args["type"].(string)
	if queryType == "" {
		queryType = "vulnerability"
	}

	filters := make(map[string]string)
	if ft, ok := args["filter_type"].(string); ok && ft != "" {
		filters["type"] = ft
	}
	if fs, ok := args["filter_severity"].(string); ok && fs != "" {
		filters["severity"] = fs
	}
	if ftg, ok := args["filter_target"].(string); ok && ftg != "" {
		filters["target"] = ftg
	}

	limit := 20
	if l, ok := args["limit"].(float64); ok {
		limit = int(l)
	}

	memory := GetSecurityMemory()
	return memory.Query(MemoryQuery{
		Type:    queryType,
		Filters: filters,
		Limit:   limit,
	}), nil
}

func (e *ToolExecutor) getSecurityInsights(args map[string]interface{}) (interface{}, error) {
	memory := GetSecurityMemory()
	return memory.GenerateInsights(), nil
}

func (e *ToolExecutor) getMemoryStats(args map[string]interface{}) (interface{}, error) {
	memory := GetSecurityMemory()
	return memory.GetStats(), nil
}

func (e *ToolExecutor) recordLearning(args map[string]interface{}) (interface{}, error) {
	learningType, _ := args["learning_type"].(string)
	description, _ := args["description"].(string)
	context, _ := args["context"].(string)
	impact, _ := args["impact"].(string)

	if learningType == "" || description == "" {
		return nil, fmt.Errorf("learning_type e description são obrigatórios")
	}

	memory := GetSecurityMemory()
	memory.RecordLearning(learningType, description, context, impact)

	return map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Aprendizado '%s' registrado na memória", learningType),
	}, nil
}

func (e *ToolExecutor) analyzeSystemWeaknesses(args map[string]interface{}) (interface{}, error) {
	target, _ := args["target"].(string)
	
	memory := GetSecurityMemory()
	insights := memory.GenerateInsights()
	
	// Filter by target if specified
	if target != "" {
		filtered := []MemoryInsight{}
		for _, insight := range insights {
			for _, evidence := range insight.Evidence {
				if containsString([]string{evidence}, target) {
					filtered = append(filtered, insight)
					break
				}
			}
		}
		insights = filtered
	}

	// Analyze patterns
	patterns := memory.Query(MemoryQuery{Type: "pattern"})
	
	return map[string]interface{}{
		"insights":   insights,
		"patterns":   patterns,
		"target":     target,
		"analysis":   "Meta-análise de fraquezas do sistema",
	}, nil
}

func (e *ToolExecutor) getMaturityScore(args map[string]interface{}) (interface{}, error) {
	target, ok := args["target"].(string)
	if !ok || target == "" {
		return nil, fmt.Errorf("target é obrigatório")
	}

	memory := GetSecurityMemory()
	
	// Find target in memory
	targets := memory.Query(MemoryQuery{
		Type:    "target",
		Filters: map[string]string{"target": target},
		Limit:   1,
	})

	targetList, ok := targets.([]TargetMemory)
	if !ok || len(targetList) == 0 {
		return map[string]interface{}{
			"target":         target,
			"maturity_score": 0,
			"level":          "UNKNOWN",
			"message":        "Alvo não encontrado na memória. Execute scans primeiro.",
		}, nil
	}

	t := targetList[0]
	
	// Calculate maturity score based on various factors
	score := t.AvgScore
	level := "UNKNOWN"
	
	switch {
	case score >= 90:
		level = "EXCELLENT"
	case score >= 75:
		level = "GOOD"
	case score >= 50:
		level = "MODERATE"
	case score >= 25:
		level = "POOR"
	default:
		level = "CRITICAL"
	}

	return map[string]interface{}{
		"target":           target,
		"maturity_score":   score,
		"level":            level,
		"scan_count":       t.ScanCount,
		"best_score":       t.BestScore,
		"worst_score":      t.WorstScore,
		"critical_vulns":   t.CriticalCount,
		"total_vulns":      t.VulnCount,
		"technologies":     t.Technologies,
		"trend":            getTrend(t.BestScore, t.WorstScore),
	}, nil
}

func (e *ToolExecutor) getCoverageGaps(args map[string]interface{}) (interface{}, error) {
	target, _ := args["target"].(string)
	
	memory := GetSecurityMemory()
	
	// Define all possible test categories
	allCategories := []string{
		"DAST Web Scan",
		"SAST Code Analysis",
		"Dependency Scan (SCA)",
		"Infrastructure Scan",
		"Subdomain Enumeration",
		"Authenticated Testing",
		"IAC Security",
		"License Compliance",
		"Typosquatting Check",
	}

	// Get what has been tested
	testedCategories := make(map[string]bool)
	
	vulns := memory.Query(MemoryQuery{Type: "vulnerability"})
	if vulnList, ok := vulns.([]VulnerabilityMemory); ok {
		for _, v := range vulnList {
			if target == "" || containsString([]string{v.Target}, target) {
				// Infer category from vulnerability type
				for _, tag := range v.Tags {
					testedCategories[tag] = true
				}
			}
		}
	}

	// Find gaps
	gaps := []string{}
	for _, cat := range allCategories {
		if !testedCategories[cat] {
			gaps = append(gaps, cat)
		}
	}

	return map[string]interface{}{
		"target":             target,
		"total_categories":   len(allCategories),
		"tested_categories":  len(testedCategories),
		"coverage_percent":   float64(len(testedCategories)) / float64(len(allCategories)) * 100,
		"gaps":               gaps,
		"recommendations":    generateGapRecommendations(gaps),
	}, nil
}

func getTrend(best, worst int) string {
	diff := best - worst
	if diff > 20 {
		return "IMPROVING"
	} else if diff < -20 {
		return "DECLINING"
	}
	return "STABLE"
}

func generateGapRecommendations(gaps []string) []string {
	recommendations := []string{}
	for _, gap := range gaps {
		switch gap {
		case "DAST Web Scan":
			recommendations = append(recommendations, "Execute scan_website para análise DAST")
		case "SAST Code Analysis":
			recommendations = append(recommendations, "Execute scan_code para análise estática")
		case "Dependency Scan (SCA)":
			recommendations = append(recommendations, "Execute scan_dependencies para verificar CVEs")
		case "Infrastructure Scan":
			recommendations = append(recommendations, "Execute scan_infrastructure para portas e SSL")
		case "Subdomain Enumeration":
			recommendations = append(recommendations, "Execute scan_subdomains para descobrir ativos")
		case "Authenticated Testing":
			recommendations = append(recommendations, "Execute scan_authenticated para testes com login")
		case "IAC Security":
			recommendations = append(recommendations, "Execute scan_iac para Terraform/K8s")
		case "License Compliance":
			recommendations = append(recommendations, "Execute scan_licenses para compliance")
		case "Typosquatting Check":
			recommendations = append(recommendations, "Execute scan_typosquatting para supply chain")
		}
	}
	return recommendations
}

// ============================================================================
// HTTP HELPERS
// ============================================================================

func (e *ToolExecutor) postJSON(path string, body interface{}) (interface{}, error) {
	jsonBody, _ := json.Marshal(body)
	resp, err := e.httpClient.Post(e.backendURL+path, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	var result interface{}
	json.Unmarshal(data, &result)
	return result, nil
}

func (e *ToolExecutor) getJSON(path string) (interface{}, error) {
	resp, err := e.httpClient.Get(e.backendURL + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	var result interface{}
	json.Unmarshal(data, &result)
	return result, nil
}

func (e *ToolExecutor) postWorkerJSON(path string, body interface{}) (interface{}, error) {
	jsonBody, _ := json.Marshal(body)
	resp, err := e.httpClient.Post(e.workerURL+path, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	var result interface{}
	json.Unmarshal(data, &result)
	return result, nil
}

func (e *ToolExecutor) getWorkerJSON(path string) (interface{}, error) {
	resp, err := e.httpClient.Get(e.workerURL + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	var result interface{}
	json.Unmarshal(data, &result)
	return result, nil
}
