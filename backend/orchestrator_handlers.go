package main

import (
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"aegis-scan-backend/orchestrator"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ============================================================================
// AEGIS CENTRAL INTELLIGENCE ORCHESTRATOR - API HANDLERS
// ============================================================================

// In-memory session storage (in production, use Redis or database)
var (
	orchestratorSessions = make(map[string]*orchestrator.OrchestratorSession)
	sessionsMutex        = sync.RWMutex{}
)

// OrchestratorChatRequest is the request body for chat
type OrchestratorChatRequest struct {
	SessionID string `json:"session_id"`
	Message   string `json:"message" binding:"required"`
	Model     string `json:"model"`
	ApiKey    string `json:"api_key"`
}

// OrchestratorChatResponse is the response from chat
type OrchestratorChatResponse struct {
	SessionID   string                       `json:"session_id"`
	Message     string                       `json:"message"`
	ToolsCalled []orchestrator.ToolResult    `json:"tools_called,omitempty"`
	Thinking    string                       `json:"thinking,omitempty"`
	Timestamp   time.Time                    `json:"timestamp"`
}

// handleOrchestratorChat handles chat messages to the orchestrator
func handleOrchestratorChat(c *gin.Context) {
	var req OrchestratorChatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "message é obrigatório"})
		return
	}

	// Get or create session
	session := getOrCreateSession(req.SessionID)

	// Get API key
	apiKey := req.ApiKey
	if apiKey == "" {
		apiKey = getEnvOrDefault("GEMINI_API_KEY", "")
	}
	if apiKey == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "GEMINI_API_KEY não configurada"})
		return
	}

	// Get model
	model := req.Model
	if model == "" {
		model = "models/gemini-2.5-flash"
	}

	// Create planner and process message
	planner := orchestrator.NewPlanner(apiKey, model)
	response, err := planner.Chat(session, req.Message)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Save session
	saveSession(session)

	c.JSON(http.StatusOK, OrchestratorChatResponse{
		SessionID:   session.ID,
		Message:     response.Message,
		ToolsCalled: response.ToolsCalled,
		Thinking:    response.Thinking,
		Timestamp:   time.Now(),
	})
}

// handleOrchestratorNewSession creates a new session
func handleOrchestratorNewSession(c *gin.Context) {
	session := createNewSession()
	c.JSON(http.StatusOK, gin.H{
		"session_id": session.ID,
		"created_at": session.CreatedAt,
	})
}

// handleOrchestratorGetSession gets session history
func handleOrchestratorGetSession(c *gin.Context) {
	sessionID := c.Param("session_id")
	
	sessionsMutex.RLock()
	session, exists := orchestratorSessions[sessionID]
	sessionsMutex.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "sessão não encontrada"})
		return
	}

	c.JSON(http.StatusOK, session)
}

// handleOrchestratorListSessions lists all sessions
func handleOrchestratorListSessions(c *gin.Context) {
	sessionsMutex.RLock()
	defer sessionsMutex.RUnlock()

	sessions := []map[string]interface{}{}
	for id, session := range orchestratorSessions {
		sessions = append(sessions, map[string]interface{}{
			"id":           id,
			"message_count": len(session.Messages),
			"created_at":   session.CreatedAt,
			"updated_at":   session.UpdatedAt,
		})
	}

	c.JSON(http.StatusOK, sessions)
}

// handleOrchestratorDeleteSession deletes a session
func handleOrchestratorDeleteSession(c *gin.Context) {
	sessionID := c.Param("session_id")
	
	sessionsMutex.Lock()
	delete(orchestratorSessions, sessionID)
	sessionsMutex.Unlock()

	c.JSON(http.StatusOK, gin.H{"message": "sessão deletada"})
}

// handleOrchestratorGetTools returns available tools
func handleOrchestratorGetTools(c *gin.Context) {
	category := c.Query("category")
	
	var tools []orchestrator.Tool
	if category != "" {
		tools = orchestrator.GetToolsByCategory(category)
	} else {
		tools = orchestrator.GetAllTools()
	}

	c.JSON(http.StatusOK, tools)
}

// handleOrchestratorExecuteTool executes a single tool directly
func handleOrchestratorExecuteTool(c *gin.Context) {
	var req struct {
		ToolName  string                 `json:"tool_name" binding:"required"`
		Arguments map[string]interface{} `json:"arguments"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tool_name é obrigatório"})
		return
	}

	// Check if tool exists
	tool := orchestrator.GetToolByName(req.ToolName)
	if tool == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "ferramenta não encontrada"})
		return
	}

	// Check if tool requires approval
	if tool.RequiresApproval {
		c.JSON(http.StatusForbidden, gin.H{
			"error":    "esta ferramenta requer aprovação",
			"tool":     tool.Name,
			"risk":     tool.RiskLevel,
		})
		return
	}

	// Execute tool
	executor := orchestrator.NewToolExecutor("", "")
	result := executor.Execute(orchestrator.ToolCall{
		Name:      req.ToolName,
		Arguments: req.Arguments,
	})

	c.JSON(http.StatusOK, result)
}

// handleOrchestratorGetPendingApprovals returns pending approval requests
func handleOrchestratorGetPendingApprovals(c *gin.Context) {
	// Get planner from a session or create new one
	planner := orchestrator.NewPlanner("", "")
	pending := planner.GetPolicy().GetPendingApprovals()
	c.JSON(http.StatusOK, pending)
}

// handleOrchestratorApprove approves a pending request
func handleOrchestratorApprove(c *gin.Context) {
	approvalID := c.Param("approval_id")
	
	var req struct {
		ApprovedBy string `json:"approved_by"`
	}
	c.ShouldBindJSON(&req)
	
	if req.ApprovedBy == "" {
		req.ApprovedBy = "admin"
	}

	planner := orchestrator.NewPlanner("", "")
	if err := planner.GetPolicy().ApproveRequest(approvalID, req.ApprovedBy); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "aprovado", "approval_id": approvalID})
}

// handleOrchestratorDeny denies a pending request
func handleOrchestratorDeny(c *gin.Context) {
	approvalID := c.Param("approval_id")
	
	var req struct {
		DeniedBy string `json:"denied_by"`
	}
	c.ShouldBindJSON(&req)
	
	if req.DeniedBy == "" {
		req.DeniedBy = "admin"
	}

	planner := orchestrator.NewPlanner("", "")
	if err := planner.GetPolicy().DenyRequest(approvalID, req.DeniedBy); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "negado", "approval_id": approvalID})
}

// handleOrchestratorGetAuditLogs returns audit logs
func handleOrchestratorGetAuditLogs(c *gin.Context) {
	sessionID := c.Query("session_id")
	
	planner := orchestrator.NewPlanner("", "")
	logs := planner.GetMetaAnalyzer().GetAuditLogs(sessionID)
	
	c.JSON(http.StatusOK, logs)
}

// handleOrchestratorMetaAnalysis performs meta-analysis
func handleOrchestratorMetaAnalysis(c *gin.Context) {
	// This would normally pull data from the database
	// For now, return a sample analysis
	analyzer := orchestrator.NewMetaAnalyzer()
	
	// Sample vulnerability data (would come from DB)
	vulnData := []map[string]interface{}{
		{"type": "XSS", "severity": "HIGH", "location": "/api/search"},
		{"type": "XSS", "severity": "MEDIUM", "location": "/api/comments"},
		{"type": "SQL Injection", "severity": "CRITICAL", "location": "/api/users"},
		{"type": "Hardcoded Secret", "severity": "HIGH", "file": "config.js"},
	}
	
	weaknesses := analyzer.AnalyzeWeaknesses(vulnData)
	gaps := analyzer.IdentifyCoverageGaps([]string{"DAST - Web Application", "SAST - Source Code"})
	
	maturityData := map[string]interface{}{
		"has_dast":        true,
		"has_sast":        true,
		"has_sca":         true,
		"has_iac":         true,
		"has_correlation": true,
		"has_autofix":     true,
		"has_cicd":        false,
		"regular_scans":   false,
		"critical_vulns":  1,
	}
	score, level := analyzer.CalculateMaturityScore(maturityData)
	
	insights := analyzer.GenerateStrategicInsights(weaknesses, gaps, score)
	actions := analyzer.GenerateActionItems(weaknesses, gaps)
	
	report := orchestrator.MetaAnalysisReport{
		GeneratedAt:       time.Now(),
		AnalysisPeriod:    "últimos 30 dias",
		TotalScans:        15,
		TotalVulns:        len(vulnData),
		TopWeaknesses:     weaknesses,
		CoverageGaps:      gaps,
		MaturityScore:     score,
		MaturityLevel:     level,
		StrategicInsights: insights,
		ActionItems:       actions,
	}
	
	c.JSON(http.StatusOK, report)
}

// Session management helpers
func getOrCreateSession(sessionID string) *orchestrator.OrchestratorSession {
	if sessionID == "" {
		return createNewSession()
	}

	sessionsMutex.RLock()
	session, exists := orchestratorSessions[sessionID]
	sessionsMutex.RUnlock()

	if !exists {
		return createNewSession()
	}

	return session
}

func createNewSession() *orchestrator.OrchestratorSession {
	session := &orchestrator.OrchestratorSession{
		ID:        uuid.New().String(),
		Messages:  []orchestrator.ChatMessage{},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	sessionsMutex.Lock()
	orchestratorSessions[session.ID] = session
	sessionsMutex.Unlock()

	return session
}

func saveSession(session *orchestrator.OrchestratorSession) {
	sessionsMutex.Lock()
	orchestratorSessions[session.ID] = session
	sessionsMutex.Unlock()
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := getEnv(key); value != "" {
		return value
	}
	return defaultValue
}

// handleOrchestratorGetRegistry returns the full tool registry with schemas
func handleOrchestratorGetRegistry(c *gin.Context) {
	registry := orchestrator.ToolRegistry
	
	// Convert to exportable format
	exportable := make(map[string]interface{})
	for name, meta := range registry {
		exportable[name] = map[string]interface{}{
			"name":           meta.Name,
			"description":    meta.Description,
			"category":       meta.Category,
			"risk_level":     meta.RiskLevel,
			"requires_hitl":  meta.RequiresHITL,
			"impact_level":   meta.ImpactLevel,
			"execution_time": meta.ExecutionTime,
			"schema":         meta.Schema,
			"tags":           meta.Tags,
		}
	}
	
	c.JSON(http.StatusOK, gin.H{
		"version":     "8.1",
		"total_tools": len(registry),
		"registry":    exportable,
	})
}

// handleOrchestratorGetPolicyStatus returns current policy configuration
func handleOrchestratorGetPolicyStatus(c *gin.Context) {
	planner := orchestrator.NewPlanner("", "")
	status := planner.GetPolicy().GetPolicyStatus()
	c.JSON(http.StatusOK, status)
}

// handleOrchestratorSetPolicy updates policy configuration
func handleOrchestratorSetPolicy(c *gin.Context) {
	var req struct {
		Environment    string `json:"environment"`
		MaxRiskLevel   string `json:"max_risk_level"`
		IsPrivileged   bool   `json:"is_privileged"`
		RequirePlan    bool   `json:"require_plan"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	planner := orchestrator.NewPlanner("", "")
	policy := planner.GetPolicy()
	
	if req.Environment != "" {
		if err := policy.SetEnvironment(req.Environment); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}
	
	if req.MaxRiskLevel != "" {
		if err := policy.SetMaxRiskLevel(req.MaxRiskLevel); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}
	
	policy.SetPrivileged(req.IsPrivileged)
	policy.RequirePlan = req.RequirePlan
	
	c.JSON(http.StatusOK, gin.H{
		"message": "política atualizada",
		"status":  policy.GetPolicyStatus(),
	})
}

// handleOrchestratorGetMemoryInsights returns security memory insights
func handleOrchestratorGetMemoryInsights(c *gin.Context) {
	memory := orchestrator.GetSecurityMemory()
	
	c.JSON(http.StatusOK, gin.H{
		"insights": memory.GenerateInsights(),
		"stats":    memory.GetStats(),
		"patterns": memory.Query(orchestrator.MemoryQuery{Type: "pattern"}),
	})
}

// handleOrchestratorDryRun executes a plan in dry-run mode
func handleOrchestratorDryRun(c *gin.Context) {
	var req struct {
		Plan []struct {
			Tool string                 `json:"tool"`
			Args map[string]interface{} `json:"args"`
		} `json:"plan"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	if len(req.Plan) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "plano vazio"})
		return
	}
	
	// Create executor in dry-run mode
	executor := orchestrator.NewToolExecutor("", "")
	executor.SetDryRunMode(true)
	executionID := orchestrator.NewExecutionID()
	executor.SetExecutionID(executionID)
	
	results := []orchestrator.ToolResult{}
	
	for i, step := range req.Plan {
		result := executor.Execute(orchestrator.ToolCall{
			Name:        step.Tool,
			Arguments:   step.Args,
			ExecutionID: executionID,
			ParentStep:  i + 1,
			DryRun:      true,
		})
		results = append(results, result)
	}
	
	// Analyze plan
	totalRisk := "low"
	requiresApproval := false
	blockedTools := []string{}
	
	for _, step := range req.Plan {
		tool := orchestrator.GetToolByName(step.Tool)
		if tool != nil {
			if tool.RiskLevel == "critical" {
				totalRisk = "critical"
			} else if tool.RiskLevel == "high" && totalRisk != "critical" {
				totalRisk = "high"
			} else if tool.RiskLevel == "medium" && totalRisk == "low" {
				totalRisk = "medium"
			}
			if tool.RequiresApproval {
				requiresApproval = true
				blockedTools = append(blockedTools, tool.Name)
			}
		}
	}
	
	c.JSON(http.StatusOK, gin.H{
		"execution_id":      executionID,
		"dry_run":           true,
		"total_steps":       len(req.Plan),
		"results":           results,
		"analysis": gin.H{
			"total_risk":        totalRisk,
			"requires_approval": requiresApproval,
			"blocked_tools":     blockedTools,
			"estimated_time":    fmt.Sprintf("%ds", len(req.Plan)*30),
		},
	})
}

// handleOrchestratorExecutePlan executes a full plan with execution graph
func handleOrchestratorExecutePlan(c *gin.Context) {
	var req struct {
		Plan []struct {
			Tool string                 `json:"tool"`
			Args map[string]interface{} `json:"args"`
		} `json:"plan"`
		DryRun bool `json:"dry_run"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	if len(req.Plan) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "plano vazio"})
		return
	}
	
	// Create executor
	executor := orchestrator.NewToolExecutor("", "")
	executor.SetDryRunMode(req.DryRun)
	executionID := orchestrator.NewExecutionID()
	executor.SetExecutionID(executionID)
	
	// Check policy for each tool
	planner := orchestrator.NewPlanner("", "")
	policy := planner.GetPolicy()
	
	// Risk calculator
	riskCalc := orchestrator.NewRiskCalculator(orchestrator.GetSecurityMemory(), policy)
	
	results := []orchestrator.ToolResult{}
	blocked := []string{}
	riskScores := make(map[string]int)
	
	for i, step := range req.Plan {
		call := orchestrator.ToolCall{
			Name:      step.Tool,
			Arguments: step.Args,
		}
		
		// Calculate risk score
		risk := riskCalc.CalculateRisk(call)
		riskScores[step.Tool] = risk.FinalScore
		
		// Validate against policy
		violations := policy.ValidateToolCall(call)
		
		hasBlock := false
		for _, v := range violations {
			if v.Severity == "BLOCK" {
				hasBlock = true
				blocked = append(blocked, fmt.Sprintf("%s: %s (risk: %d)", step.Tool, v.Description, risk.FinalScore))
			}
		}
		
		if hasBlock && !req.DryRun {
			results = append(results, orchestrator.ToolResult{
				ToolName:    step.Tool,
				Success:     false,
				Error:       "bloqueado por política",
				ExecutionID: executionID,
				ParentStep:  i + 1,
				Timestamp:   time.Now(),
				RiskLevel:   risk.Level,
			})
			continue
		}
		
		// Execute
		result := executor.Execute(orchestrator.ToolCall{
			Name:        step.Tool,
			Arguments:   step.Args,
			ExecutionID: executionID,
			ParentStep:  i + 1,
		})
		results = append(results, result)
	}
	
	// Calculate summary
	executed := 0
	failed := 0
	totalDuration := int64(0)
	failedTools := []string{}
	
	for _, r := range results {
		if r.Success {
			executed++
		} else {
			failed++
			failedTools = append(failedTools, r.ToolName)
		}
		totalDuration += r.Duration
	}
	
	// Record feedback for learning
	orchestrator.GetFeedbackStore().RecordFeedback(orchestrator.ExecutionFeedback{
		ExecutionID:   executionID,
		TotalSteps:    len(req.Plan),
		ExecutedSteps: executed,
		BlockedSteps:  len(blocked),
		FailedSteps:   failed,
		BlockedTools:  blocked,
		FailedTools:   failedTools,
		TotalDuration: totalDuration,
		RiskScores:    riskScores,
	})
	
	c.JSON(http.StatusOK, gin.H{
		"execution_id":   executionID,
		"dry_run":        req.DryRun,
		"total_steps":    len(req.Plan),
		"executed":       executed,
		"failed":         failed,
		"blocked":        blocked,
		"risk_scores":    riskScores,
		"total_duration": totalDuration,
		"results":        results,
	})
}

// ============================================================================
// DECISION INTELLIGENCE LAYER ENDPOINTS
// ============================================================================

// handleCalculateRisk calculates risk score for a tool call
func handleCalculateRisk(c *gin.Context) {
	var req struct {
		Tool string                 `json:"tool"`
		Args map[string]interface{} `json:"args"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	planner := orchestrator.NewPlanner("", "")
	riskCalc := orchestrator.NewRiskCalculator(orchestrator.GetSecurityMemory(), planner.GetPolicy())
	
	risk := riskCalc.CalculateRisk(orchestrator.ToolCall{
		Name:      req.Tool,
		Arguments: req.Args,
	})
	
	c.JSON(http.StatusOK, risk)
}

// handleCreateApprovalToken creates a new approval token
func handleCreateApprovalToken(c *gin.Context) {
	var req orchestrator.CreateTokenRequest
	
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	if req.CreatedBy == "" {
		req.CreatedBy = "admin"
	}
	if req.Scope == "" {
		req.Scope = "execution"
	}
	
	token := orchestrator.GetTokenStore().CreateToken(req)
	c.JSON(http.StatusOK, token)
}

// handleValidateToken validates an approval token
func handleValidateToken(c *gin.Context) {
	tokenID := c.Param("token_id")
	
	var req struct {
		Tool string                 `json:"tool"`
		Args map[string]interface{} `json:"args"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	// Calculate risk
	planner := orchestrator.NewPlanner("", "")
	riskCalc := orchestrator.NewRiskCalculator(orchestrator.GetSecurityMemory(), planner.GetPolicy())
	risk := riskCalc.CalculateRisk(orchestrator.ToolCall{Name: req.Tool, Arguments: req.Args})
	
	valid, reason := orchestrator.GetTokenStore().ValidateToken(tokenID, orchestrator.ToolCall{
		Name:      req.Tool,
		Arguments: req.Args,
	}, risk.FinalScore)
	
	c.JSON(http.StatusOK, gin.H{
		"valid":      valid,
		"reason":     reason,
		"risk_score": risk.FinalScore,
	})
}

// handleRevokeToken revokes an approval token
func handleRevokeToken(c *gin.Context) {
	tokenID := c.Param("token_id")
	
	var req struct {
		RevokedBy string `json:"revoked_by"`
	}
	c.ShouldBindJSON(&req)
	
	if req.RevokedBy == "" {
		req.RevokedBy = "admin"
	}
	
	if err := orchestrator.GetTokenStore().RevokeToken(tokenID, req.RevokedBy); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{"message": "token revogado", "token_id": tokenID})
}

// handleListTokens lists active approval tokens
func handleListTokens(c *gin.Context) {
	tokens := orchestrator.GetTokenStore().ListActiveTokens()
	c.JSON(http.StatusOK, tokens)
}

// handleGetPolicyHistory returns policy version history
func handleGetPolicyHistory(c *gin.Context) {
	history := orchestrator.GetPolicyVersionStore().GetHistory()
	c.JSON(http.StatusOK, gin.H{
		"current_version": orchestrator.GetPolicyVersionStore().GetCurrentVersion(),
		"history":         history,
	})
}

// handleComparePolicies compares two policy versions
func handleComparePolicies(c *gin.Context) {
	var req struct {
		Version1 int `json:"version1"`
		Version2 int `json:"version2"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	changes, err := orchestrator.GetPolicyVersionStore().ComparePolicies(req.Version1, req.Version2)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"version1": req.Version1,
		"version2": req.Version2,
		"changes":  changes,
	})
}

// handleGetPlannerInsights returns planner learning insights
func handleGetPlannerInsights(c *gin.Context) {
	insights := orchestrator.GetFeedbackStore().GetPlannerInsights()
	c.JSON(http.StatusOK, insights)
}

// handleGetExecutionFeedback returns feedback for an execution
func handleGetExecutionFeedback(c *gin.Context) {
	executionID := c.Param("execution_id")
	
	feedback := orchestrator.GetFeedbackStore().GetFeedbackByExecution(executionID)
	if feedback == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "feedback não encontrado"})
		return
	}
	
	c.JSON(http.StatusOK, feedback)
}

func getEnv(key string) string {
	return os.Getenv(key)
}
