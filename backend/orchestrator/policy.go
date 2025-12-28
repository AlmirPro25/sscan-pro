package orchestrator

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// ============================================================================
// AEGIS POLICY ENGINE
// Guardrails, Approval Gates, and Context Validation
// ============================================================================

// ExecutionPlan represents the AI's explicit plan before execution
type ExecutionPlan struct {
	Intent      string   `json:"intent"`
	Plan        []string `json:"plan"`
	Reasoning   string   `json:"reasoning"`
	RiskLevel   string   `json:"risk_level"`
	EstimatedTime string `json:"estimated_time"`
	RequiresApproval bool `json:"requires_approval"`
}

// PolicyViolation represents a policy check failure
type PolicyViolation struct {
	Rule        string `json:"rule"`
	Description string `json:"description"`
	Severity    string `json:"severity"` // BLOCK, WARN, INFO
	Suggestion  string `json:"suggestion"`
}

// PolicyEngine validates and controls tool execution
type PolicyEngine struct {
	AllowedDomains    []string                    `json:"allowed_domains"`
	AllowedPaths      []string                    `json:"allowed_paths"`
	BlockedPaths      []string                    `json:"blocked_paths"`
	Environment       string                      `json:"environment"` // prod, staging, lab
	RequirePlan       bool                        `json:"require_plan"`
	MaxToolsPerTurn   int                         `json:"max_tools_per_turn"`
	MaxRiskLevel      string                      `json:"max_risk_level"` // low, medium, high, critical
	IsPrivileged      bool                        `json:"is_privileged"`  // Allows critical tools
	PendingApprovals  map[string]*PendingApproval `json:"-"`
}

// PendingApproval represents a tool awaiting human approval
type PendingApproval struct {
	ID          string                 `json:"id"`
	ToolName    string                 `json:"tool_name"`
	Arguments   map[string]interface{} `json:"arguments"`
	Reason      string                 `json:"reason"`
	RequestedAt time.Time              `json:"requested_at"`
	Status      string                 `json:"status"` // pending, approved, denied
	ApprovedBy  string                 `json:"approved_by,omitempty"`
	ApprovedAt  *time.Time             `json:"approved_at,omitempty"`
}

// NewPolicyEngine creates a new policy engine with defaults
func NewPolicyEngine() *PolicyEngine {
	return &PolicyEngine{
		AllowedDomains:   []string{}, // Empty = all allowed
		AllowedPaths:     []string{}, // Empty = all allowed
		BlockedPaths: []string{
			"C:\\Windows",
			"C:\\Program Files",
			"/etc",
			"/var",
			"/usr",
			"/root",
			"~/.ssh",
			"~/.aws",
			"~/.config",
		},
		Environment:      "lab",
		RequirePlan:      true,
		MaxToolsPerTurn:  10,
		MaxRiskLevel:     "high",      // Default: allow up to high, block critical without privilege
		IsPrivileged:     false,       // Default: not privileged
		PendingApprovals: make(map[string]*PendingApproval),
	}
}

// ValidatePlan checks if the AI provided a valid execution plan
func (p *PolicyEngine) ValidatePlan(plan *ExecutionPlan) []PolicyViolation {
	violations := []PolicyViolation{}

	if p.RequirePlan {
		if plan == nil {
			violations = append(violations, PolicyViolation{
				Rule:        "PLAN_REQUIRED",
				Description: "Plano de execução obrigatório antes de usar ferramentas",
				Severity:    "BLOCK",
				Suggestion:  "Forneça intent, plan e reasoning antes de executar",
			})
			return violations
		}

		if plan.Intent == "" {
			violations = append(violations, PolicyViolation{
				Rule:        "INTENT_MISSING",
				Description: "Intent (objetivo) não especificado",
				Severity:    "BLOCK",
				Suggestion:  "Descreva o objetivo da operação",
			})
		}

		if len(plan.Plan) == 0 {
			violations = append(violations, PolicyViolation{
				Rule:        "PLAN_EMPTY",
				Description: "Lista de ferramentas vazia",
				Severity:    "BLOCK",
				Suggestion:  "Liste as ferramentas que serão usadas",
			})
		}

		if plan.Reasoning == "" {
			violations = append(violations, PolicyViolation{
				Rule:        "REASONING_MISSING",
				Description: "Raciocínio não explicado",
				Severity:    "WARN",
				Suggestion:  "Explique por que essas ferramentas foram escolhidas",
			})
		}

		// Check for redundant tools
		toolCount := make(map[string]int)
		for _, tool := range plan.Plan {
			toolCount[tool]++
			if toolCount[tool] > 1 {
				violations = append(violations, PolicyViolation{
					Rule:        "REDUNDANT_TOOL",
					Description: fmt.Sprintf("Ferramenta '%s' aparece %d vezes no plano", tool, toolCount[tool]),
					Severity:    "WARN",
					Suggestion:  "Remova chamadas duplicadas",
				})
			}
		}

		// Check max tools
		if len(plan.Plan) > p.MaxToolsPerTurn {
			violations = append(violations, PolicyViolation{
				Rule:        "TOO_MANY_TOOLS",
				Description: fmt.Sprintf("Plano tem %d ferramentas, máximo é %d", len(plan.Plan), p.MaxToolsPerTurn),
				Severity:    "WARN",
				Suggestion:  "Divida em múltiplas etapas",
			})
		}
	}

	return violations
}

// ValidateToolCall checks if a specific tool call is allowed
func (p *PolicyEngine) ValidateToolCall(call ToolCall) []PolicyViolation {
	violations := []PolicyViolation{}
	tool := GetToolByName(call.Name)

	if tool == nil {
		violations = append(violations, PolicyViolation{
			Rule:        "UNKNOWN_TOOL",
			Description: fmt.Sprintf("Ferramenta '%s' não existe", call.Name),
			Severity:    "BLOCK",
			Suggestion:  "Use uma ferramenta válida",
		})
		return violations
	}

	// ========== RISK LEVEL ENFORCEMENT ==========
	riskOrder := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
	toolRisk := riskOrder[tool.RiskLevel]
	maxRisk := riskOrder[p.MaxRiskLevel]
	
	// Critical tools require privilege
	if tool.RiskLevel == "critical" && !p.IsPrivileged {
		violations = append(violations, PolicyViolation{
			Rule:        "CRITICAL_REQUIRES_PRIVILEGE",
			Description: fmt.Sprintf("Ferramenta '%s' é crítica e requer sessão privilegiada", call.Name),
			Severity:    "BLOCK",
			Suggestion:  "Solicite elevação de privilégio ou use ferramenta alternativa",
		})
	}
	
	// Check if tool risk exceeds max allowed
	if toolRisk > maxRisk && !p.IsPrivileged {
		violations = append(violations, PolicyViolation{
			Rule:        "RISK_LEVEL_EXCEEDED",
			Description: fmt.Sprintf("Ferramenta '%s' (risco: %s) excede o máximo permitido (%s)", call.Name, tool.RiskLevel, p.MaxRiskLevel),
			Severity:    "BLOCK",
			Suggestion:  "Use ferramenta de menor risco ou solicite aprovação",
		})
	}

	// Check approval requirement
	if tool.RequiresApproval {
		violations = append(violations, PolicyViolation{
			Rule:        "APPROVAL_REQUIRED",
			Description: fmt.Sprintf("Ferramenta '%s' requer aprovação humana (risco: %s)", call.Name, tool.RiskLevel),
			Severity:    "BLOCK",
			Suggestion:  "Solicite aprovação antes de executar",
		})
	}

	// Validate URL arguments
	if url, ok := call.Arguments["url"].(string); ok {
		if err := p.validateURL(url); err != nil {
			violations = append(violations, PolicyViolation{
				Rule:        "URL_POLICY",
				Description: err.Error(),
				Severity:    "BLOCK",
				Suggestion:  "Use uma URL permitida",
			})
		}
	}

	// Validate path arguments
	if path, ok := call.Arguments["path"].(string); ok {
		if err := p.validatePath(path); err != nil {
			violations = append(violations, PolicyViolation{
				Rule:        "PATH_POLICY",
				Description: err.Error(),
				Severity:    "BLOCK",
				Suggestion:  "Use um caminho permitido",
			})
		}
	}

	// Environment-specific checks
	if p.Environment == "prod" {
		// In production, block destructive operations
		destructiveTools := []string{"execute_javascript", "create_pull_request", "scan_authenticated"}
		for _, dt := range destructiveTools {
			if call.Name == dt {
				violations = append(violations, PolicyViolation{
					Rule:        "PROD_RESTRICTION",
					Description: fmt.Sprintf("Ferramenta '%s' bloqueada em ambiente de produção", call.Name),
					Severity:    "BLOCK",
					Suggestion:  "Execute em ambiente de lab ou staging",
				})
			}
		}
	}

	return violations
}

// validateURL checks if URL is allowed
func (p *PolicyEngine) validateURL(url string) error {
	// If no domains specified, allow all
	if len(p.AllowedDomains) == 0 {
		return nil
	}

	for _, domain := range p.AllowedDomains {
		if strings.Contains(url, domain) {
			return nil
		}
	}

	return fmt.Errorf("URL '%s' não está na lista de domínios permitidos", url)
}

// validatePath checks if path is allowed
func (p *PolicyEngine) validatePath(path string) error {
	// Normalize path
	normalizedPath := strings.ReplaceAll(path, "\\", "/")
	normalizedPath = strings.ToLower(normalizedPath)

	// Check blocked paths
	for _, blocked := range p.BlockedPaths {
		normalizedBlocked := strings.ReplaceAll(blocked, "\\", "/")
		normalizedBlocked = strings.ToLower(normalizedBlocked)
		
		if strings.HasPrefix(normalizedPath, normalizedBlocked) {
			return fmt.Errorf("caminho '%s' está bloqueado por política de segurança", path)
		}
	}

	// Check for path traversal attempts
	if strings.Contains(path, "..") {
		return fmt.Errorf("path traversal detectado em '%s'", path)
	}

	// If allowed paths specified, check whitelist
	if len(p.AllowedPaths) > 0 {
		for _, allowed := range p.AllowedPaths {
			normalizedAllowed := strings.ReplaceAll(allowed, "\\", "/")
			normalizedAllowed = strings.ToLower(normalizedAllowed)
			
			if strings.HasPrefix(normalizedPath, normalizedAllowed) {
				return nil
			}
		}
		return fmt.Errorf("caminho '%s' não está na lista de caminhos permitidos", path)
	}

	return nil
}

// RequestApproval creates a pending approval request
func (p *PolicyEngine) RequestApproval(call ToolCall, reason string) *PendingApproval {
	id := fmt.Sprintf("APR-%d", time.Now().UnixNano())
	approval := &PendingApproval{
		ID:          id,
		ToolName:    call.Name,
		Arguments:   call.Arguments,
		Reason:      reason,
		RequestedAt: time.Now(),
		Status:      "pending",
	}
	p.PendingApprovals[id] = approval
	return approval
}

// ApproveRequest approves a pending request
func (p *PolicyEngine) ApproveRequest(id, approvedBy string) error {
	approval, exists := p.PendingApprovals[id]
	if !exists {
		return fmt.Errorf("aprovação '%s' não encontrada", id)
	}
	
	now := time.Now()
	approval.Status = "approved"
	approval.ApprovedBy = approvedBy
	approval.ApprovedAt = &now
	return nil
}

// DenyRequest denies a pending request
func (p *PolicyEngine) DenyRequest(id, deniedBy string) error {
	approval, exists := p.PendingApprovals[id]
	if !exists {
		return fmt.Errorf("aprovação '%s' não encontrada", id)
	}
	
	now := time.Now()
	approval.Status = "denied"
	approval.ApprovedBy = deniedBy
	approval.ApprovedAt = &now
	return nil
}

// GetPendingApprovals returns all pending approvals
func (p *PolicyEngine) GetPendingApprovals() []*PendingApproval {
	pending := []*PendingApproval{}
	for _, approval := range p.PendingApprovals {
		if approval.Status == "pending" {
			pending = append(pending, approval)
		}
	}
	return pending
}

// SetPrivileged elevates the session to privileged mode
func (p *PolicyEngine) SetPrivileged(privileged bool) {
	p.IsPrivileged = privileged
}

// SetMaxRiskLevel sets the maximum allowed risk level
func (p *PolicyEngine) SetMaxRiskLevel(level string) error {
	validLevels := map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
	if !validLevels[level] {
		return fmt.Errorf("nível de risco inválido: %s", level)
	}
	p.MaxRiskLevel = level
	return nil
}

// SetEnvironment sets the execution environment
func (p *PolicyEngine) SetEnvironment(env string) error {
	validEnvs := map[string]bool{"lab": true, "staging": true, "prod": true}
	if !validEnvs[env] {
		return fmt.Errorf("ambiente inválido: %s", env)
	}
	p.Environment = env
	return nil
}

// GetPolicyStatus returns current policy configuration
func (p *PolicyEngine) GetPolicyStatus() map[string]interface{} {
	return map[string]interface{}{
		"environment":      p.Environment,
		"max_risk_level":   p.MaxRiskLevel,
		"is_privileged":    p.IsPrivileged,
		"require_plan":     p.RequirePlan,
		"max_tools_per_turn": p.MaxToolsPerTurn,
		"allowed_domains":  len(p.AllowedDomains),
		"blocked_paths":    len(p.BlockedPaths),
		"pending_approvals": len(p.GetPendingApprovals()),
	}
}

// IsApproved checks if a tool call has been approved
func (p *PolicyEngine) IsApproved(call ToolCall) bool {
	for _, approval := range p.PendingApprovals {
		if approval.ToolName == call.Name && approval.Status == "approved" {
			// Check if arguments match
			if matchArguments(approval.Arguments, call.Arguments) {
				return true
			}
		}
	}
	return false
}

// ExtractPlanFromMessage tries to extract execution plan from AI message
func ExtractPlanFromMessage(message string) *ExecutionPlan {
	plan := &ExecutionPlan{}

	// Try to find JSON plan in message
	jsonPattern := regexp.MustCompile(`\{[^{}]*"intent"[^{}]*\}`)
	if match := jsonPattern.FindString(message); match != "" {
		// Parse JSON (simplified)
		if strings.Contains(match, `"intent"`) {
			// Extract intent
			intentPattern := regexp.MustCompile(`"intent"\s*:\s*"([^"]+)"`)
			if intentMatch := intentPattern.FindStringSubmatch(match); len(intentMatch) > 1 {
				plan.Intent = intentMatch[1]
			}
		}
	}

	// Try to find plan markers in natural language
	if plan.Intent == "" {
		// Look for "Objetivo:", "Plano:", etc.
		lines := strings.Split(message, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(strings.ToLower(line), "objetivo:") {
				plan.Intent = strings.TrimPrefix(line, "Objetivo:")
				plan.Intent = strings.TrimPrefix(plan.Intent, "objetivo:")
				plan.Intent = strings.TrimSpace(plan.Intent)
			}
			if strings.HasPrefix(strings.ToLower(line), "raciocínio:") || strings.HasPrefix(strings.ToLower(line), "reasoning:") {
				plan.Reasoning = strings.TrimSpace(line[11:])
			}
		}
	}

	// Extract tool names from message
	allTools := GetAllTools()
	for _, tool := range allTools {
		if strings.Contains(message, tool.Name) {
			plan.Plan = append(plan.Plan, tool.Name)
		}
	}

	if plan.Intent == "" && len(plan.Plan) == 0 {
		return nil
	}

	return plan
}

func matchArguments(a, b map[string]interface{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || fmt.Sprintf("%v", v) != fmt.Sprintf("%v", bv) {
			return false
		}
	}
	return true
}
