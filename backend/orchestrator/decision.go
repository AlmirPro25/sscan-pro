package orchestrator

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// ============================================================================
// AEGIS DECISION INTELLIGENCE LAYER v8.4
// Risk Scoring, Approval Tokens, Policy Versioning, Feedback Loop
// ============================================================================

// ============================================================================
// 1. RISK SCORE NUMÉRICO (0-100)
// ============================================================================

// RiskScore represents a calculated risk score with breakdown
type RiskScore struct {
	BaseRisk       int    `json:"base_risk"`       // Tool inherent risk (0-40)
	ContextRisk    int    `json:"context_risk"`    // Environment, target (0-30)
	MemoryRisk     int    `json:"memory_risk"`     // Historical patterns (0-20)
	ArgumentRisk   int    `json:"argument_risk"`   // Argument sensitivity (0-10)
	FinalScore     int    `json:"final_score"`     // Total (0-100)
	Level          string `json:"level"`           // low/medium/high/critical
	Explanation    string `json:"explanation"`     // Human-readable
	Recommendation string `json:"recommendation"`  // Action suggestion
}

// RiskCalculator calculates risk scores
type RiskCalculator struct {
	memory *SecurityMemory
	policy *PolicyEngine
}

// NewRiskCalculator creates a new risk calculator
func NewRiskCalculator(memory *SecurityMemory, policy *PolicyEngine) *RiskCalculator {
	return &RiskCalculator{
		memory: memory,
		policy: policy,
	}
}

// CalculateRisk computes a detailed risk score for a tool call
func (rc *RiskCalculator) CalculateRisk(call ToolCall) RiskScore {
	score := RiskScore{}
	explanations := []string{}

	// 1. Base Risk (from tool definition)
	tool := GetToolByName(call.Name)
	if tool != nil {
		switch tool.RiskLevel {
		case "low":
			score.BaseRisk = 10
		case "medium":
			score.BaseRisk = 25
		case "high":
			score.BaseRisk = 35
		case "critical":
			score.BaseRisk = 40
		}
		if tool.RequiresApproval {
			score.BaseRisk += 5
		}
		explanations = append(explanations, fmt.Sprintf("Tool '%s' base risk: %d", call.Name, score.BaseRisk))
	}

	// 2. Context Risk (environment, target)
	if rc.policy != nil {
		switch rc.policy.Environment {
		case "prod":
			score.ContextRisk += 20
			explanations = append(explanations, "Ambiente PROD: +20")
		case "staging":
			score.ContextRisk += 10
			explanations = append(explanations, "Ambiente STAGING: +10")
		case "lab":
			score.ContextRisk += 0
		}

		// Check if target is external
		if url, ok := call.Arguments["url"].(string); ok {
			if len(rc.policy.AllowedDomains) > 0 {
				isAllowed := false
				for _, d := range rc.policy.AllowedDomains {
					if containsString([]string{url}, d) {
						isAllowed = true
						break
					}
				}
				if !isAllowed {
					score.ContextRisk += 10
					explanations = append(explanations, "URL externa não autorizada: +10")
				}
			}
		}
	}

	// 3. Memory Risk (historical patterns)
	if rc.memory != nil {
		// Check if target has history of vulnerabilities
		if target, ok := call.Arguments["url"].(string); ok {
			targets := rc.memory.Query(MemoryQuery{Type: "target"})
			if targetList, ok := targets.([]TargetMemory); ok {
				for _, t := range targetList {
					if containsString([]string{target}, t.Domain) {
						if t.CriticalCount > 0 {
							score.MemoryRisk += 15
							explanations = append(explanations, fmt.Sprintf("Alvo com %d vulns críticas: +15", t.CriticalCount))
						} else if t.VulnCount > 5 {
							score.MemoryRisk += 10
							explanations = append(explanations, fmt.Sprintf("Alvo com %d vulns: +10", t.VulnCount))
						}
						break
					}
				}
			}
		}

		// Check for recurring vulnerability patterns
		patterns := rc.memory.Query(MemoryQuery{Type: "pattern"})
		if patternList, ok := patterns.([]PatternMemory); ok {
			if len(patternList) > 3 {
				score.MemoryRisk += 5
				explanations = append(explanations, "Múltiplos padrões de vuln detectados: +5")
			}
		}
	}

	// 4. Argument Risk (sensitive data)
	if _, ok := call.Arguments["password"]; ok {
		score.ArgumentRisk += 5
		explanations = append(explanations, "Argumento sensível (password): +5")
	}
	if _, ok := call.Arguments["token"]; ok {
		score.ArgumentRisk += 5
		explanations = append(explanations, "Argumento sensível (token): +5")
	}
	if code, ok := call.Arguments["code"].(string); ok && len(code) > 100 {
		score.ArgumentRisk += 5
		explanations = append(explanations, "Código extenso para execução: +5")
	}

	// Calculate final score
	score.FinalScore = score.BaseRisk + score.ContextRisk + score.MemoryRisk + score.ArgumentRisk
	if score.FinalScore > 100 {
		score.FinalScore = 100
	}

	// Determine level
	switch {
	case score.FinalScore >= 80:
		score.Level = "critical"
		score.Recommendation = "BLOQUEAR - Requer aprovação explícita e justificativa"
	case score.FinalScore >= 60:
		score.Level = "high"
		score.Recommendation = "APROVAR - Requer token de aprovação"
	case score.FinalScore >= 40:
		score.Level = "medium"
		score.Recommendation = "MONITORAR - Execução permitida com logging extra"
	default:
		score.Level = "low"
		score.Recommendation = "PERMITIR - Execução normal"
	}

	score.Explanation = fmt.Sprintf("Score %d/100 (%s): %v", score.FinalScore, score.Level, explanations)

	return score
}


// ============================================================================
// 2. APPROVAL TOKENS (Delegação Segura)
// ============================================================================

// ApprovalToken represents a scoped, time-limited approval
type ApprovalToken struct {
	ID            string    `json:"id"`
	ExecutionID   string    `json:"execution_id"`
	AllowedTools  []string  `json:"allowed_tools"`
	MaxRiskScore  int       `json:"max_risk_score"`
	MaxExecutions int       `json:"max_executions"`
	UsedCount     int       `json:"used_count"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	CreatedBy     string    `json:"created_by"`
	Scope         string    `json:"scope"` // session, execution, tool
	Revoked       bool      `json:"revoked"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	RevokedBy     string    `json:"revoked_by,omitempty"`
}

// TokenStore manages approval tokens
type TokenStore struct {
	mu     sync.RWMutex
	tokens map[string]*ApprovalToken
}

// Global token store
var globalTokenStore = &TokenStore{
	tokens: make(map[string]*ApprovalToken),
}

// GetTokenStore returns the global token store
func GetTokenStore() *TokenStore {
	return globalTokenStore
}

// CreateToken creates a new approval token
func (ts *TokenStore) CreateToken(req CreateTokenRequest) *ApprovalToken {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	// Generate token ID
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s-%d", req.ExecutionID, time.Now().UnixNano())))
	tokenID := "tok_" + hex.EncodeToString(hash[:8])

	// Default expiration: 1 hour
	expiresAt := time.Now().Add(time.Hour)
	if req.TTLMinutes > 0 {
		expiresAt = time.Now().Add(time.Duration(req.TTLMinutes) * time.Minute)
	}

	// Default max executions
	maxExec := 10
	if req.MaxExecutions > 0 {
		maxExec = req.MaxExecutions
	}

	token := &ApprovalToken{
		ID:            tokenID,
		ExecutionID:   req.ExecutionID,
		AllowedTools:  req.AllowedTools,
		MaxRiskScore:  req.MaxRiskScore,
		MaxExecutions: maxExec,
		UsedCount:     0,
		CreatedAt:     time.Now(),
		ExpiresAt:     expiresAt,
		CreatedBy:     req.CreatedBy,
		Scope:         req.Scope,
		Revoked:       false,
	}

	ts.tokens[tokenID] = token
	return token
}

// CreateTokenRequest is the request to create a token
type CreateTokenRequest struct {
	ExecutionID   string   `json:"execution_id"`
	AllowedTools  []string `json:"allowed_tools"`
	MaxRiskScore  int      `json:"max_risk_score"`
	MaxExecutions int      `json:"max_executions"`
	TTLMinutes    int      `json:"ttl_minutes"`
	CreatedBy     string   `json:"created_by"`
	Scope         string   `json:"scope"`
}

// ValidateToken checks if a token is valid for a tool call
func (ts *TokenStore) ValidateToken(tokenID string, call ToolCall, riskScore int) (bool, string) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	token, exists := ts.tokens[tokenID]
	if !exists {
		return false, "token não encontrado"
	}

	if token.Revoked {
		return false, "token revogado"
	}

	if time.Now().After(token.ExpiresAt) {
		return false, "token expirado"
	}

	if token.UsedCount >= token.MaxExecutions {
		return false, "limite de execuções atingido"
	}

	// Check if tool is allowed
	if len(token.AllowedTools) > 0 {
		allowed := false
		for _, t := range token.AllowedTools {
			if t == call.Name || t == "*" {
				allowed = true
				break
			}
		}
		if !allowed {
			return false, fmt.Sprintf("ferramenta '%s' não autorizada neste token", call.Name)
		}
	}

	// Check risk score
	if token.MaxRiskScore > 0 && riskScore > token.MaxRiskScore {
		return false, fmt.Sprintf("risk score %d excede máximo permitido %d", riskScore, token.MaxRiskScore)
	}

	return true, "token válido"
}

// UseToken increments the usage count
func (ts *TokenStore) UseToken(tokenID string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if token, exists := ts.tokens[tokenID]; exists {
		token.UsedCount++
	}
}

// RevokeToken revokes a token
func (ts *TokenStore) RevokeToken(tokenID, revokedBy string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	token, exists := ts.tokens[tokenID]
	if !exists {
		return fmt.Errorf("token não encontrado")
	}

	now := time.Now()
	token.Revoked = true
	token.RevokedAt = &now
	token.RevokedBy = revokedBy
	return nil
}

// GetToken returns a token by ID
func (ts *TokenStore) GetToken(tokenID string) *ApprovalToken {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	return ts.tokens[tokenID]
}

// ListActiveTokens returns all active tokens
func (ts *TokenStore) ListActiveTokens() []*ApprovalToken {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	active := []*ApprovalToken{}
	now := time.Now()
	for _, token := range ts.tokens {
		if !token.Revoked && now.Before(token.ExpiresAt) {
			active = append(active, token)
		}
	}
	return active
}


// ============================================================================
// 3. POLICY VERSIONING (Diff + Histórico)
// ============================================================================

// PolicyVersion represents a versioned policy snapshot
type PolicyVersion struct {
	Version     int                    `json:"version"`
	Timestamp   time.Time              `json:"timestamp"`
	ChangedBy   string                 `json:"changed_by"`
	Changes     []PolicyChange         `json:"changes"`
	Snapshot    map[string]interface{} `json:"snapshot"`
	Description string                 `json:"description"`
}

// PolicyChange represents a single change in policy
type PolicyChange struct {
	Field    string      `json:"field"`
	OldValue interface{} `json:"old_value"`
	NewValue interface{} `json:"new_value"`
	Impact   string      `json:"impact"` // low, medium, high
}

// PolicyVersionStore manages policy versions
type PolicyVersionStore struct {
	mu       sync.RWMutex
	versions []PolicyVersion
	current  int
}

// Global policy version store
var globalPolicyVersionStore = &PolicyVersionStore{
	versions: []PolicyVersion{},
	current:  0,
}

// GetPolicyVersionStore returns the global store
func GetPolicyVersionStore() *PolicyVersionStore {
	return globalPolicyVersionStore
}

// SaveVersion saves a new policy version
func (pvs *PolicyVersionStore) SaveVersion(policy *PolicyEngine, changedBy, description string) PolicyVersion {
	pvs.mu.Lock()
	defer pvs.mu.Unlock()

	newVersion := pvs.current + 1

	// Create snapshot
	snapshot := map[string]interface{}{
		"environment":       policy.Environment,
		"max_risk_level":    policy.MaxRiskLevel,
		"is_privileged":     policy.IsPrivileged,
		"require_plan":      policy.RequirePlan,
		"max_tools_per_turn": policy.MaxToolsPerTurn,
		"allowed_domains":   policy.AllowedDomains,
		"blocked_paths":     policy.BlockedPaths,
	}

	// Calculate changes from previous version
	changes := []PolicyChange{}
	if len(pvs.versions) > 0 {
		prev := pvs.versions[len(pvs.versions)-1].Snapshot
		changes = pvs.calculateDiff(prev, snapshot)
	}

	version := PolicyVersion{
		Version:     newVersion,
		Timestamp:   time.Now(),
		ChangedBy:   changedBy,
		Changes:     changes,
		Snapshot:    snapshot,
		Description: description,
	}

	pvs.versions = append(pvs.versions, version)
	pvs.current = newVersion

	return version
}

// calculateDiff compares two policy snapshots
func (pvs *PolicyVersionStore) calculateDiff(old, new map[string]interface{}) []PolicyChange {
	changes := []PolicyChange{}

	for key, newVal := range new {
		oldVal, exists := old[key]
		if !exists || fmt.Sprintf("%v", oldVal) != fmt.Sprintf("%v", newVal) {
			impact := "low"
			// High impact changes
			if key == "environment" || key == "is_privileged" || key == "max_risk_level" {
				impact = "high"
			} else if key == "require_plan" || key == "max_tools_per_turn" {
				impact = "medium"
			}

			changes = append(changes, PolicyChange{
				Field:    key,
				OldValue: oldVal,
				NewValue: newVal,
				Impact:   impact,
			})
		}
	}

	return changes
}

// GetVersion returns a specific version
func (pvs *PolicyVersionStore) GetVersion(version int) *PolicyVersion {
	pvs.mu.RLock()
	defer pvs.mu.RUnlock()

	for _, v := range pvs.versions {
		if v.Version == version {
			return &v
		}
	}
	return nil
}

// GetHistory returns all versions
func (pvs *PolicyVersionStore) GetHistory() []PolicyVersion {
	pvs.mu.RLock()
	defer pvs.mu.RUnlock()
	return pvs.versions
}

// GetCurrentVersion returns current version number
func (pvs *PolicyVersionStore) GetCurrentVersion() int {
	pvs.mu.RLock()
	defer pvs.mu.RUnlock()
	return pvs.current
}

// ComparePolicies compares two versions
func (pvs *PolicyVersionStore) ComparePolicies(v1, v2 int) ([]PolicyChange, error) {
	pvs.mu.RLock()
	defer pvs.mu.RUnlock()

	var snap1, snap2 map[string]interface{}
	for _, v := range pvs.versions {
		if v.Version == v1 {
			snap1 = v.Snapshot
		}
		if v.Version == v2 {
			snap2 = v.Snapshot
		}
	}

	if snap1 == nil || snap2 == nil {
		return nil, fmt.Errorf("versão não encontrada")
	}

	return pvs.calculateDiff(snap1, snap2), nil
}


// ============================================================================
// 4. PLANNER FEEDBACK LOOP (Aprendizado)
// ============================================================================

// ExecutionFeedback represents feedback from an execution
type ExecutionFeedback struct {
	ExecutionID     string                 `json:"execution_id"`
	SessionID       string                 `json:"session_id"`
	Timestamp       time.Time              `json:"timestamp"`
	TotalSteps      int                    `json:"total_steps"`
	ExecutedSteps   int                    `json:"executed_steps"`
	BlockedSteps    int                    `json:"blocked_steps"`
	FailedSteps     int                    `json:"failed_steps"`
	BlockedTools    []string               `json:"blocked_tools"`
	FailedTools     []string               `json:"failed_tools"`
	DeniedApprovals []string               `json:"denied_approvals"`
	TimeoutTools    []string               `json:"timeout_tools"`
	TotalDuration   int64                  `json:"total_duration_ms"`
	RiskScores      map[string]int         `json:"risk_scores"`
	PolicyViolations []string              `json:"policy_violations"`
	UserFeedback    string                 `json:"user_feedback,omitempty"`
	Outcome         string                 `json:"outcome"` // success, partial, failed
}

// FeedbackStore stores execution feedback for learning
type FeedbackStore struct {
	mu       sync.RWMutex
	feedback []ExecutionFeedback
}

// Global feedback store
var globalFeedbackStore = &FeedbackStore{
	feedback: []ExecutionFeedback{},
}

// GetFeedbackStore returns the global store
func GetFeedbackStore() *FeedbackStore {
	return globalFeedbackStore
}

// RecordFeedback records execution feedback
func (fs *FeedbackStore) RecordFeedback(fb ExecutionFeedback) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	fb.Timestamp = time.Now()
	
	// Determine outcome
	if fb.FailedSteps == 0 && fb.BlockedSteps == 0 {
		fb.Outcome = "success"
	} else if fb.ExecutedSteps > 0 {
		fb.Outcome = "partial"
	} else {
		fb.Outcome = "failed"
	}

	fs.feedback = append(fs.feedback, fb)

	// Keep only last 1000 feedbacks
	if len(fs.feedback) > 1000 {
		fs.feedback = fs.feedback[len(fs.feedback)-1000:]
	}
}

// GetPlannerInsights generates insights for the planner
func (fs *FeedbackStore) GetPlannerInsights() PlannerInsights {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	insights := PlannerInsights{
		TotalExecutions:    len(fs.feedback),
		BlockedToolsFreq:   make(map[string]int),
		FailedToolsFreq:    make(map[string]int),
		TimeoutToolsFreq:   make(map[string]int),
		AvgRiskScores:      make(map[string]float64),
		CommonViolations:   make(map[string]int),
		Recommendations:    []string{},
	}

	if len(fs.feedback) == 0 {
		return insights
	}

	// Aggregate data
	successCount := 0
	riskScoreSums := make(map[string]int)
	riskScoreCounts := make(map[string]int)

	for _, fb := range fs.feedback {
		if fb.Outcome == "success" {
			successCount++
		}

		for _, tool := range fb.BlockedTools {
			insights.BlockedToolsFreq[tool]++
		}
		for _, tool := range fb.FailedTools {
			insights.FailedToolsFreq[tool]++
		}
		for _, tool := range fb.TimeoutTools {
			insights.TimeoutToolsFreq[tool]++
		}
		for _, violation := range fb.PolicyViolations {
			insights.CommonViolations[violation]++
		}
		for tool, score := range fb.RiskScores {
			riskScoreSums[tool] += score
			riskScoreCounts[tool]++
		}
	}

	// Calculate averages
	for tool, sum := range riskScoreSums {
		insights.AvgRiskScores[tool] = float64(sum) / float64(riskScoreCounts[tool])
	}

	insights.SuccessRate = float64(successCount) / float64(len(fs.feedback)) * 100

	// Generate recommendations
	for tool, count := range insights.BlockedToolsFreq {
		if count > 5 {
			insights.Recommendations = append(insights.Recommendations,
				fmt.Sprintf("Ferramenta '%s' bloqueada %d vezes - considere solicitar aprovação prévia", tool, count))
		}
	}
	for tool, count := range insights.TimeoutToolsFreq {
		if count > 3 {
			insights.Recommendations = append(insights.Recommendations,
				fmt.Sprintf("Ferramenta '%s' timeout %d vezes - considere dividir em etapas menores", tool, count))
		}
	}
	for violation, count := range insights.CommonViolations {
		if count > 5 {
			insights.Recommendations = append(insights.Recommendations,
				fmt.Sprintf("Violação '%s' ocorreu %d vezes - ajuste o plano para evitar", violation, count))
		}
	}

	return insights
}

// PlannerInsights contains aggregated insights for the planner
type PlannerInsights struct {
	TotalExecutions   int                `json:"total_executions"`
	SuccessRate       float64            `json:"success_rate"`
	BlockedToolsFreq  map[string]int     `json:"blocked_tools_freq"`
	FailedToolsFreq   map[string]int     `json:"failed_tools_freq"`
	TimeoutToolsFreq  map[string]int     `json:"timeout_tools_freq"`
	AvgRiskScores     map[string]float64 `json:"avg_risk_scores"`
	CommonViolations  map[string]int     `json:"common_violations"`
	Recommendations   []string           `json:"recommendations"`
}

// GetRecentFeedback returns recent feedback entries
func (fs *FeedbackStore) GetRecentFeedback(limit int) []ExecutionFeedback {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	if limit <= 0 || limit > len(fs.feedback) {
		limit = len(fs.feedback)
	}

	start := len(fs.feedback) - limit
	if start < 0 {
		start = 0
	}

	return fs.feedback[start:]
}

// GetFeedbackByExecution returns feedback for a specific execution
func (fs *FeedbackStore) GetFeedbackByExecution(executionID string) *ExecutionFeedback {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	for i := len(fs.feedback) - 1; i >= 0; i-- {
		if fs.feedback[i].ExecutionID == executionID {
			return &fs.feedback[i]
		}
	}
	return nil
}
