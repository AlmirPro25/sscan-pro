package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/generative-ai-go/genai"
	"google.golang.org/api/option"
)

// ============================================================================
// AEGIS CENTRAL INTELLIGENCE ORCHESTRATOR - STRATEGIC PLANNER
// Two-Caller Architecture: Planner (AI) → Policy → Executor (System)
// The AI PLANS, the System EXECUTES
// ============================================================================

// StructuredPlan represents the AI's execution plan
type StructuredPlan struct {
	Intent      string       `json:"intent"`
	Target      string       `json:"target,omitempty"`
	RiskLevel   string       `json:"risk_level"`
	Steps       []PlanStep   `json:"steps"`
	Reasoning   string       `json:"reasoning"`
	Warnings    []string     `json:"warnings,omitempty"`
	EstimatedTime string     `json:"estimated_time"`
}

// PlanStep represents a single step in the plan
type PlanStep struct {
	Step       int                    `json:"step"`
	Tool       string                 `json:"tool"`
	Args       map[string]interface{} `json:"args"`
	Reason     string                 `json:"reason"`
	DependsOn  []int                  `json:"depends_on,omitempty"`
	RiskLevel  string                 `json:"risk_level,omitempty"`
}

// ============================================================================
// AEGIS CENTRAL INTELLIGENCE ORCHESTRATOR - PLANNER
// Uses Gemini Function Calling to plan and execute security assessments
// With Policy Engine for guardrails and approval gates
// ============================================================================

// Planner is the AI planning layer (Caller 1 - DECIDES, never executes)
type Planner struct {
	apiKey       string
	model        string
	executor     *ToolExecutor
	policy       *PolicyEngine
	metaAnalyzer *MetaAnalyzer
	memory       *SecurityMemory
}

// ChatMessage represents a message in the conversation
type ChatMessage struct {
	Role       string          `json:"role"` // user, assistant, tool, system
	Content    string          `json:"content"`
	ToolCalls  []ToolCall      `json:"tool_calls,omitempty"`
	ToolResult *ToolResult     `json:"tool_result,omitempty"`
	Thinking   string          `json:"thinking,omitempty"`
	Plan       *StructuredPlan `json:"plan,omitempty"`
	Timestamp  time.Time       `json:"timestamp"`
}

// OrchestratorSession represents a chat session
type OrchestratorSession struct {
	ID        string        `json:"id"`
	Messages  []ChatMessage `json:"messages"`
	CreatedAt time.Time     `json:"created_at"`
	UpdatedAt time.Time     `json:"updated_at"`
}

// PlannerResponse is the response from the planner
type PlannerResponse struct {
	Message          string             `json:"message"`
	ToolsCalled      []ToolResult       `json:"tools_called,omitempty"`
	Thinking         string             `json:"thinking,omitempty"`
	Plan             *StructuredPlan    `json:"plan,omitempty"`
	PolicyViolations []PolicyViolation  `json:"policy_violations,omitempty"`
	PendingApprovals []*PendingApproval `json:"pending_approvals,omitempty"`
	ExecutionSummary *ExecutionSummary  `json:"execution_summary,omitempty"`
}

// ExecutionSummary summarizes what was executed
type ExecutionSummary struct {
	TotalSteps     int      `json:"total_steps"`
	ExecutedSteps  int      `json:"executed_steps"`
	BlockedSteps   int      `json:"blocked_steps"`
	PendingSteps   int      `json:"pending_steps"`
	ToolsUsed      []string `json:"tools_used"`
	TotalDuration  int64    `json:"total_duration_ms"`
}

// NewPlanner creates a new planner
func NewPlanner(apiKey, model string) *Planner {
	if model == "" {
		model = "models/gemini-2.5-flash"
	}
	return &Planner{
		apiKey:       apiKey,
		model:        model,
		executor:     NewToolExecutor("", ""),
		policy:       NewPolicyEngine(),
		metaAnalyzer: NewMetaAnalyzer(),
		memory:       GetSecurityMemory(),
	}
}

// SetPolicy configures the policy engine
func (p *Planner) SetPolicy(policy *PolicyEngine) {
	p.policy = policy
}

// GetPolicy returns the policy engine
func (p *Planner) GetPolicy() *PolicyEngine {
	return p.policy
}

// GetMetaAnalyzer returns the meta analyzer
func (p *Planner) GetMetaAnalyzer() *MetaAnalyzer {
	return p.metaAnalyzer
}

// Chat processes a user message and returns a response
// TWO-CALLER FLOW: User → Planner (AI) → Policy → Executor → Response
func (p *Planner) Chat(session *OrchestratorSession, userMessage string) (*PlannerResponse, error) {
	ctx := context.Background()

	client, err := genai.NewClient(ctx, option.WithAPIKey(p.apiKey))
	if err != nil {
		return nil, fmt.Errorf("falha ao criar cliente Gemini: %v", err)
	}
	defer client.Close()

	// Add user message to session
	session.Messages = append(session.Messages, ChatMessage{
		Role:      "user",
		Content:   userMessage,
		Timestamp: time.Now(),
	})

	// Build the model with function calling
	model := client.GenerativeModel(p.model)
	model.SetTemperature(0.2) // Lower for more deterministic planning
	model.SetMaxOutputTokens(8192)

	// Configure tools for function calling
	model.Tools = p.buildGeminiTools()

	// Build system prompt with policy requirements and memory insights
	systemPrompt := p.buildSystemPrompt()

	// Build chat history
	chat := model.StartChat()
	chat.History = p.buildChatHistory(session, systemPrompt)

	// Initialize response
	response := &PlannerResponse{
		ToolsCalled:      []ToolResult{},
		PolicyViolations: []PolicyViolation{},
		PendingApprovals: []*PendingApproval{},
		ExecutionSummary: &ExecutionSummary{
			ToolsUsed: []string{},
		},
	}

	// Execution tracking
	thinkingLog := []string{}
	var extractedPlan *StructuredPlan
	executionStart := time.Now()

	// ========== MAIN EXECUTION LOOP ==========
	maxIterations := 15
	currentMessage := userMessage

	for i := 0; i < maxIterations; i++ {
		log.Printf("🤖 [Iteration %d] Sending to Planner: %s", i+1, truncateString(currentMessage, 100))

		resp, err := chat.SendMessage(ctx, genai.Text(currentMessage))
		if err != nil {
			return nil, fmt.Errorf("erro na chamada Gemini: %v", err)
		}

		// Process response
		hasFunctionCalls := false
		var functionResults []string

		for _, cand := range resp.Candidates {
			if cand.Content == nil {
				continue
			}

			for _, part := range cand.Content.Parts {
				// Handle text response
				if text, ok := part.(genai.Text); ok {
					textStr := string(text)
					response.Message += textStr

					// Try to extract structured plan
					if extractedPlan == nil {
						extractedPlan = p.extractStructuredPlan(textStr)
						if extractedPlan != nil {
							response.Plan = extractedPlan
							thinkingLog = append(thinkingLog, fmt.Sprintf("📋 Plano extraído: %d passos", len(extractedPlan.Steps)))
						}
					}
				}

				// Handle function call (AI wants to use a tool)
				if fc, ok := part.(genai.FunctionCall); ok {
					hasFunctionCalls = true
					log.Printf("🔧 [Function Call] %s with args: %v", fc.Name, fc.Args)

					toolCall := ToolCall{
						Name:      fc.Name,
						Arguments: convertArgs(fc.Args),
					}

					// ========== POLICY ENFORCEMENT (Caller 1 → Policy) ==========
					result := p.enforcePolicy(toolCall, extractedPlan, i, &thinkingLog, response)
					
					if result != nil {
						// Tool was executed or blocked
						if result.Success {
							response.ToolsCalled = append(response.ToolsCalled, *result)
							response.ExecutionSummary.ExecutedSteps++
							response.ExecutionSummary.ToolsUsed = append(response.ExecutionSummary.ToolsUsed, fc.Name)

							// Record in memory if it's a scan result
							p.recordToMemory(fc.Name, result)
						} else {
							response.ExecutionSummary.BlockedSteps++
						}

						// Log for audit
						p.metaAnalyzer.LogAction(AuditLog{
							SessionID: session.ID,
							Action:    "tool_execution",
							ToolName:  fc.Name,
							Arguments: toolCall.Arguments,
							Result:    fmt.Sprintf("success=%v", result.Success),
							Thinking:  strings.Join(thinkingLog, "\n"),
							Duration:  result.Duration,
							Success:   result.Success,
						})

						// Format result for next iteration
						resultJSON, _ := json.Marshal(result)
						functionResults = append(functionResults, fmt.Sprintf(
							"Resultado de %s:\n```json\n%s\n```",
							fc.Name, string(resultJSON),
						))

						// Add to session
						session.Messages = append(session.Messages, ChatMessage{
							Role:       "tool",
							Content:    string(resultJSON),
							ToolCalls:  []ToolCall{toolCall},
							ToolResult: result,
							Timestamp:  time.Now(),
						})
					} else {
						// Pending approval
						response.ExecutionSummary.PendingSteps++
						functionResults = append(functionResults, fmt.Sprintf(
							"⏳ Ferramenta '%s' aguardando aprovação humana.",
							fc.Name,
						))
					}
				}
			}
		}

		// If no function calls, we're done
		if !hasFunctionCalls {
			break
		}

		// Continue with function results
		currentMessage = strings.Join(functionResults, "\n\n")
	}

	// Finalize response
	response.Thinking = strings.Join(thinkingLog, "\n")
	response.ExecutionSummary.TotalSteps = response.ExecutionSummary.ExecutedSteps + 
		response.ExecutionSummary.BlockedSteps + response.ExecutionSummary.PendingSteps
	response.ExecutionSummary.TotalDuration = time.Since(executionStart).Milliseconds()

	// Add assistant response to session
	session.Messages = append(session.Messages, ChatMessage{
		Role:      "assistant",
		Content:   response.Message,
		Thinking:  response.Thinking,
		Plan:      response.Plan,
		Timestamp: time.Now(),
	})
	session.UpdatedAt = time.Now()

	return response, nil
}

// enforcePolicy validates and executes a tool call through the policy engine
func (p *Planner) enforcePolicy(call ToolCall, plan *StructuredPlan, iteration int, thinkingLog *[]string, response *PlannerResponse) *ToolResult {
	
	// 1. Check if plan is required but missing
	if p.policy.RequirePlan && plan == nil && iteration == 0 {
		*thinkingLog = append(*thinkingLog, "⚠️ Plano não fornecido na primeira iteração")
		response.PolicyViolations = append(response.PolicyViolations, PolicyViolation{
			Rule:        "PLAN_REQUIRED",
			Description: "Forneça um plano estruturado antes de executar ferramentas",
			Severity:    "WARN",
			Suggestion:  "Descreva: Objetivo, Ferramentas, Raciocínio",
		})
	}

	// 2. Validate tool call against policy
	violations := p.policy.ValidateToolCall(call)
	
	blocked := false
	for _, v := range violations {
		response.PolicyViolations = append(response.PolicyViolations, v)
		if v.Severity == "BLOCK" {
			blocked = true
			*thinkingLog = append(*thinkingLog, fmt.Sprintf("🚫 BLOQUEADO: %s - %s", v.Rule, v.Description))
		}
	}

	// 3. Check HITL requirement
	tool := GetToolByName(call.Name)
	if tool != nil && tool.RequiresApproval {
		if !p.policy.IsApproved(call) {
			// Create pending approval
			approval := p.policy.RequestApproval(call, fmt.Sprintf(
				"Ferramenta de alto risco: %s (Risk: %s)", 
				tool.Name, tool.RiskLevel,
			))
			response.PendingApprovals = append(response.PendingApprovals, approval)
			*thinkingLog = append(*thinkingLog, fmt.Sprintf("⏳ HITL: Aguardando aprovação para %s (ID: %s)", call.Name, approval.ID))
			return nil // Signal pending
		}
		*thinkingLog = append(*thinkingLog, fmt.Sprintf("✅ HITL: %s aprovado", call.Name))
	}

	// 4. If blocked, return error result
	if blocked {
		return &ToolResult{
			ToolName:  call.Name,
			Success:   false,
			Error:     fmt.Sprintf("Bloqueado por política: %v", violations),
			Timestamp: time.Now(),
		}
	}

	// 5. Validate arguments against registry schema
	validationErrors := ValidateToolArguments(call.Name, call.Arguments)
	if len(validationErrors) > 0 {
		*thinkingLog = append(*thinkingLog, fmt.Sprintf("❌ Schema inválido: %v", validationErrors))
		return &ToolResult{
			ToolName:  call.Name,
			Success:   false,
			Error:     fmt.Sprintf("Validação de schema falhou: %v", validationErrors),
			Timestamp: time.Now(),
		}
	}

	// 6. EXECUTE (Caller 2 - Executor)
	*thinkingLog = append(*thinkingLog, fmt.Sprintf("▶️ Executando: %s", call.Name))
	result := p.executor.Execute(call)
	
	if result.Success {
		*thinkingLog = append(*thinkingLog, fmt.Sprintf("✅ Sucesso: %s (%dms)", call.Name, result.Duration))
	} else {
		*thinkingLog = append(*thinkingLog, fmt.Sprintf("❌ Falha: %s - %s", call.Name, result.Error))
	}

	return &result
}

// recordToMemory records scan results to security memory
func (p *Planner) recordToMemory(toolName string, result *ToolResult) {
	if !result.Success {
		return
	}

	// Extract vulnerabilities from scan results and record to memory
	if resultMap, ok := result.Result.(map[string]interface{}); ok {
		// Record target
		if url, ok := resultMap["url"].(string); ok {
			score := 0
			if s, ok := resultMap["score"].(float64); ok {
				score = int(s)
			}
			vulnCount := 0
			criticalCount := 0
			if vulns, ok := resultMap["vulnerabilities"].([]interface{}); ok {
				vulnCount = len(vulns)
				for _, v := range vulns {
					if vMap, ok := v.(map[string]interface{}); ok {
						if sev, ok := vMap["severity"].(string); ok && sev == "CRITICAL" {
							criticalCount++
						}
					}
				}
			}
			p.memory.RecordTarget(url, score, vulnCount, criticalCount, []string{toolName})
		}
	}
}

// extractStructuredPlan tries to extract a structured plan from AI response
func (p *Planner) extractStructuredPlan(message string) *StructuredPlan {
	plan := &StructuredPlan{
		Steps: []PlanStep{},
	}

	// Try to find JSON plan in message
	jsonStart := strings.Index(message, "{")
	jsonEnd := strings.LastIndex(message, "}")
	if jsonStart != -1 && jsonEnd > jsonStart {
		jsonStr := message[jsonStart : jsonEnd+1]
		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(jsonStr), &parsed); err == nil {
			if intent, ok := parsed["intent"].(string); ok {
				plan.Intent = intent
			}
			if target, ok := parsed["target"].(string); ok {
				plan.Target = target
			}
			if reasoning, ok := parsed["reasoning"].(string); ok {
				plan.Reasoning = reasoning
			}
			if steps, ok := parsed["steps"].([]interface{}); ok {
				for i, s := range steps {
					if stepMap, ok := s.(map[string]interface{}); ok {
						step := PlanStep{Step: i + 1}
						if tool, ok := stepMap["tool"].(string); ok {
							step.Tool = tool
						}
						if args, ok := stepMap["args"].(map[string]interface{}); ok {
							step.Args = args
						}
						if reason, ok := stepMap["reason"].(string); ok {
							step.Reason = reason
						}
						plan.Steps = append(plan.Steps, step)
					}
				}
			}
		}
	}

	// Fallback: extract from natural language
	if plan.Intent == "" {
		lines := strings.Split(message, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			lineLower := strings.ToLower(line)
			if strings.HasPrefix(lineLower, "objetivo:") || strings.HasPrefix(lineLower, "intent:") {
				plan.Intent = strings.TrimSpace(line[9:])
			}
			if strings.HasPrefix(lineLower, "raciocínio:") || strings.HasPrefix(lineLower, "reasoning:") {
				plan.Reasoning = strings.TrimSpace(line[11:])
			}
		}
	}

	// Extract tool names mentioned
	allTools := GetAllTools()
	for _, tool := range allTools {
		if strings.Contains(message, tool.Name) {
			found := false
			for _, s := range plan.Steps {
				if s.Tool == tool.Name {
					found = true
					break
				}
			}
			if !found {
				plan.Steps = append(plan.Steps, PlanStep{
					Step: len(plan.Steps) + 1,
					Tool: tool.Name,
				})
			}
		}
	}

	// Calculate risk level
	plan.RiskLevel = "low"
	for _, step := range plan.Steps {
		tool := GetToolByName(step.Tool)
		if tool != nil {
			if tool.RiskLevel == "critical" {
				plan.RiskLevel = "critical"
				break
			} else if tool.RiskLevel == "high" && plan.RiskLevel != "critical" {
				plan.RiskLevel = "high"
			} else if tool.RiskLevel == "medium" && plan.RiskLevel == "low" {
				plan.RiskLevel = "medium"
			}
		}
	}

	if plan.Intent == "" && len(plan.Steps) == 0 {
		return nil
	}

	return plan
}

// buildSystemPrompt creates the system prompt for the orchestrator
func (p *Planner) buildSystemPrompt() string {
	toolsJSON, _ := json.MarshalIndent(GetAllTools(), "", "  ")

	// ========== MEMORY INTEGRATION ==========
	// Inject security insights into the prompt to influence planning
	insights := p.memory.GenerateInsights()
	stats := p.memory.GetStats()

	insightsSection := ""
	if len(insights) > 0 {
		insightsSection = "\n## 🧠 INSIGHTS DA MEMÓRIA DE SEGURANÇA\n\n"
		insightsSection += "Baseado em análises anteriores, considere:\n\n"
		for _, insight := range insights {
			insightsSection += fmt.Sprintf("- **%s**: %s\n  - Sugestão: %s\n",
				insight.Title, insight.Description, insight.Suggestion)
		}
		insightsSection += fmt.Sprintf("\n📊 Estatísticas: %d vulnerabilidades registradas, %d alvos analisados, %d padrões detectados\n",
			stats["total_vulnerabilities"], stats["total_targets"], stats["total_patterns"])
	}

	// Build high-risk tools list
	highRiskTools := []string{}
	for _, tool := range GetAllTools() {
		if tool.RequiresApproval {
			highRiskTools = append(highRiskTools, fmt.Sprintf("- %s (%s)", tool.Name, tool.RiskLevel))
		}
	}

	return fmt.Sprintf(`Você é o AEGIS Strategic Planner, o cérebro de um sistema de segurança autônomo.

## 🎯 SUA FUNÇÃO
Você é o PLANNER (Caller 1). Você DECIDE quais ferramentas usar, mas o EXECUTOR (Caller 2) é quem executa.
Você NUNCA executa diretamente - você planeja e o sistema executa.

## 🛠️ FERRAMENTAS DISPONÍVEIS
%s

## ⚠️ REGRA CRÍTICA: PLANO ESTRUTURADO OBRIGATÓRIO

**ANTES de chamar QUALQUER ferramenta, você DEVE fornecer um plano em JSON:**

{
  "intent": "Descrição clara do objetivo",
  "target": "URL ou sistema alvo",
  "risk_level": "low|medium|high|critical",
  "reasoning": "Por que essas ferramentas foram escolhidas",
  "steps": [
    {"step": 1, "tool": "nome_da_ferramenta", "args": {"param": "valor"}, "reason": "motivo"},
    {"step": 2, "tool": "outra_ferramenta", "args": {}, "depends_on": [1], "reason": "motivo"}
  ]
}

**Se você não fornecer o plano, a execução será bloqueada.**

## 🔒 FERRAMENTAS DE ALTO RISCO (Requerem Aprovação Humana)
%s

Quando precisar usar essas ferramentas:
1. Explique claramente o motivo
2. Aguarde aprovação humana
3. Só então a ferramenta será executada

## 🚫 RESTRIÇÕES DE SEGURANÇA
- Ambiente atual: %s
- Paths bloqueados: /etc, /var, C:\Windows, ~/.ssh, ~/.aws
- URLs devem pertencer ao projeto autorizado
- Máximo de ferramentas por turno: %d

## 📋 FLUXOS RECOMENDADOS

### Auditoria Completa de Website
1. scan_website → DAST básico
2. scan_infrastructure → Portas, SSL, Cloud
3. scan_subdomains → Enumeração
4. generate_ai_report → Relatório consolidado

### Análise de Código
1. scan_code → SAST
2. scan_dependencies → CVEs
3. scan_licenses → Compliance
4. generate_autofix → Correções

### Correlação DAST+SAST
1. Verificar projeto existente
2. correlate_dast_sast → Correlação
3. Analisar cadeias de ataque

## 📝 FORMATO DE RESPOSTA

1. **Plano JSON** (obrigatório antes de ferramentas)
2. Explicação clara do que será feito
3. Após execução: resultados principais
4. Recomendações quando aplicável

Use português brasileiro, seja técnico mas acessível.
%s
`, string(toolsJSON), strings.Join(highRiskTools, "\n"), p.policy.Environment, p.policy.MaxToolsPerTurn, insightsSection)
}

// buildGeminiTools converts our tools to Gemini function declarations
func (p *Planner) buildGeminiTools() []*genai.Tool {
	tools := GetAllTools()
	functionDeclarations := []*genai.FunctionDeclaration{}

	for _, tool := range tools {
		properties := map[string]*genai.Schema{}
		required := []string{}

		for _, param := range tool.Parameters {
			schema := &genai.Schema{
				Type:        convertToGenaiType(param.Type),
				Description: param.Description,
			}
			properties[param.Name] = schema

			if param.Required {
				required = append(required, param.Name)
			}
		}

		fd := &genai.FunctionDeclaration{
			Name:        tool.Name,
			Description: tool.Description,
			Parameters: &genai.Schema{
				Type:       genai.TypeObject,
				Properties: properties,
				Required:   required,
			},
		}
		functionDeclarations = append(functionDeclarations, fd)
	}

	return []*genai.Tool{
		{FunctionDeclarations: functionDeclarations},
	}
}

// buildChatHistory converts session messages to Gemini format
func (p *Planner) buildChatHistory(session *OrchestratorSession, systemPrompt string) []*genai.Content {
	history := []*genai.Content{}

	// Add system prompt as first user message
	history = append(history, &genai.Content{
		Parts: []genai.Part{genai.Text(systemPrompt)},
		Role:  "user",
	})
	history = append(history, &genai.Content{
		Parts: []genai.Part{genai.Text("Entendido. Sou o AEGIS Central Intelligence Orchestrator. Estou pronto para ajudar com análises de segurança. Como posso ajudar?")},
		Role:  "model",
	})

	// Add conversation history (skip last message as it will be sent)
	for i := 0; i < len(session.Messages)-1; i++ {
		msg := session.Messages[i]
		role := "user"
		if msg.Role == "assistant" || msg.Role == "model" {
			role = "model"
		}

		history = append(history, &genai.Content{
			Parts: []genai.Part{genai.Text(msg.Content)},
			Role:  role,
		})
	}

	return history
}

// Helper functions
func convertToGenaiType(t string) genai.Type {
	switch t {
	case "number":
		return genai.TypeNumber
	case "boolean":
		return genai.TypeBoolean
	case "array":
		return genai.TypeArray
	case "object":
		return genai.TypeObject
	default:
		return genai.TypeString
	}
}

func convertArgs(args map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for k, v := range args {
		result[k] = v
	}
	return result
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
