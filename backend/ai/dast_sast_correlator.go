package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/generative-ai-go/genai"
	"google.golang.org/api/option"
)

// ============================================================================
// DAST + SAST CORRELATION ENGINE
// Correlates dynamic (runtime) vulnerabilities with static (code) findings
// ============================================================================

// DASTFinding represents a vulnerability found during dynamic testing
type DASTFinding struct {
	Type        string  `json:"type"`
	Severity    string  `json:"severity"`
	URL         string  `json:"url"`
	Parameter   string  `json:"parameter"`
	Payload     string  `json:"payload"`
	Evidence    string  `json:"evidence"`
	Description string  `json:"description"`
	CWE         string  `json:"cwe"`
	CVSSScore   float64 `json:"cvss_score"`
}

// SASTFinding represents a vulnerability found in source code
type SASTFinding struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Code        string `json:"code"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
	CWE         string `json:"cwe"`
	Confidence  string `json:"confidence"`
}

// IACFinding represents an Infrastructure as Code issue
type IACFinding struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Code        string `json:"code"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
	Resource    string `json:"resource"` // docker, kubernetes, terraform
}

// CorrelatedVulnerability represents a DAST finding linked to SAST evidence
type CorrelatedVulnerability struct {
	ID              string        `json:"id"`
	Type            string        `json:"type"`
	Severity        string        `json:"severity"`
	ConfidenceLevel string        `json:"confidence_level"` // CONFIRMED, LIKELY, POSSIBLE
	DASTEvidence    *DASTFinding  `json:"dast_evidence"`
	SASTEvidence    []SASTFinding `json:"sast_evidence"`
	IACEvidence     []IACFinding  `json:"iac_evidence"`
	RootCause       string        `json:"root_cause"`
	AttackVector    string        `json:"attack_vector"`
	BusinessImpact  string        `json:"business_impact"`
	Remediation     AutoFixSuggestion `json:"remediation"`
}

// AutoFixSuggestion provides actionable fix information
type AutoFixSuggestion struct {
	Priority    int      `json:"priority"` // 1-10
	Files       []string `json:"files"`
	CodeChanges []CodeChange `json:"code_changes"`
	Commands    []string `json:"commands"`
	Description string   `json:"description"`
}

// CodeChange represents a specific code modification
type CodeChange struct {
	File        string `json:"file"`
	Line        int    `json:"line"`
	OldCode     string `json:"old_code"`
	NewCode     string `json:"new_code"`
	Explanation string `json:"explanation"`
}

// CorrelationReport is the full correlation analysis
type CorrelationReport struct {
	Target              string                    `json:"target"`
	CorrelatedVulns     []CorrelatedVulnerability `json:"correlated_vulnerabilities"`
	UnmatchedDAST       []DASTFinding             `json:"unmatched_dast"`
	UnmatchedSAST       []SASTFinding             `json:"unmatched_sast"`
	AttackChains        []AttackChain             `json:"attack_chains"`
	RiskScore           int                       `json:"risk_score"`
	ExecutiveSummary    string                    `json:"executive_summary"`
	TechnicalSummary    string                    `json:"technical_summary"`
	ComplianceImpact    ComplianceAnalysis        `json:"compliance_impact"`
	RemediationRoadmap  []RemediationStep         `json:"remediation_roadmap"`
}

// ComplianceAnalysis shows impact on compliance frameworks
type ComplianceAnalysis struct {
	LGPD     []string `json:"lgpd"`
	PCIDSS   []string `json:"pci_dss"`
	OWASP    []string `json:"owasp"`
	SOC2     []string `json:"soc2"`
	HIPAA    []string `json:"hipaa"`
}

// RemediationStep is a prioritized fix action
type RemediationStep struct {
	Priority    int      `json:"priority"`
	Timeframe   string   `json:"timeframe"` // "24h", "1 week", "2 weeks", "1 month"
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Files       []string `json:"files"`
	Effort      string   `json:"effort"` // "low", "medium", "high"
	Impact      string   `json:"impact"` // "critical", "high", "medium", "low"
}

// DASTSASTCorrelator correlates DAST and SAST findings
type DASTSASTCorrelator struct {
	apiKey string
	model  string
}

// NewDASTSASTCorrelator creates a new correlator
func NewDASTSASTCorrelator(apiKey, model string) *DASTSASTCorrelator {
	if model == "" {
		model = "models/gemini-2.5-flash"
	}
	return &DASTSASTCorrelator{
		apiKey: apiKey,
		model:  model,
	}
}

// Correlate performs DAST+SAST correlation
func (c *DASTSASTCorrelator) Correlate(
	target string,
	dastFindings []DASTFinding,
	sastFindings []SASTFinding,
	iacFindings []IACFinding,
) (*CorrelationReport, error) {
	
	report := &CorrelationReport{
		Target:          target,
		CorrelatedVulns: []CorrelatedVulnerability{},
		UnmatchedDAST:   []DASTFinding{},
		UnmatchedSAST:   []SASTFinding{},
		AttackChains:    []AttackChain{},
	}

	// Step 1: Rule-based correlation (fast, deterministic)
	correlatedDAST := make(map[int]bool)
	correlatedSAST := make(map[int]bool)

	for di, dast := range dastFindings {
		for si, sast := range sastFindings {
			if c.isCorrelated(dast, sast) {
				corr := CorrelatedVulnerability{
					ID:              fmt.Sprintf("CORR-%d-%d", di, si),
					Type:            dast.Type,
					Severity:        c.maxSeverity(dast.Severity, sast.Severity),
					ConfidenceLevel: "CONFIRMED",
					DASTEvidence:    &dast,
					SASTEvidence:    []SASTFinding{sast},
					RootCause:       fmt.Sprintf("Código vulnerável em %s:%d", sast.File, sast.Line),
					AttackVector:    fmt.Sprintf("Endpoint %s, parâmetro %s", dast.URL, dast.Parameter),
				}
				
				// Check for related IAC issues
				for _, iac := range iacFindings {
					if c.isIACRelated(dast, iac) {
						corr.IACEvidence = append(corr.IACEvidence, iac)
					}
				}
				
				report.CorrelatedVulns = append(report.CorrelatedVulns, corr)
				correlatedDAST[di] = true
				correlatedSAST[si] = true
			}
		}
	}

	// Collect unmatched findings
	for i, dast := range dastFindings {
		if !correlatedDAST[i] {
			report.UnmatchedDAST = append(report.UnmatchedDAST, dast)
		}
	}
	for i, sast := range sastFindings {
		if !correlatedSAST[i] {
			report.UnmatchedSAST = append(report.UnmatchedSAST, sast)
		}
	}

	// Step 2: AI-enhanced correlation for complex cases
	if c.apiKey != "" && (len(report.UnmatchedDAST) > 0 || len(report.UnmatchedSAST) > 0) {
		aiCorrelations, err := c.aiCorrelate(target, report.UnmatchedDAST, report.UnmatchedSAST, iacFindings)
		if err == nil && aiCorrelations != nil {
			report.CorrelatedVulns = append(report.CorrelatedVulns, aiCorrelations.CorrelatedVulns...)
			report.AttackChains = aiCorrelations.AttackChains
			report.ExecutiveSummary = aiCorrelations.ExecutiveSummary
			report.TechnicalSummary = aiCorrelations.TechnicalSummary
			report.ComplianceImpact = aiCorrelations.ComplianceImpact
			report.RemediationRoadmap = aiCorrelations.RemediationRoadmap
		}
	}

	// Calculate risk score
	report.RiskScore = c.calculateRiskScore(report)

	// Generate summaries if AI didn't
	if report.ExecutiveSummary == "" {
		report.ExecutiveSummary = c.generateExecutiveSummary(report)
	}
	if len(report.RemediationRoadmap) == 0 {
		report.RemediationRoadmap = c.generateRemediationRoadmap(report)
	}

	return report, nil
}

// isCorrelated checks if DAST and SAST findings are related
func (c *DASTSASTCorrelator) isCorrelated(dast DASTFinding, sast SASTFinding) bool {
	// Same CWE = strong correlation
	if dast.CWE != "" && sast.CWE != "" && dast.CWE == sast.CWE {
		return true
	}

	// Type-based correlation
	typeCorrelations := map[string][]string{
		"XSS":                {"XSS", "innerHTML", "document.write", "dangerouslySetInnerHTML", "eval"},
		"SQL Injection":      {"SQL Injection", "SQL", "query", "execute", "raw"},
		"Command Injection":  {"Command Injection", "exec", "system", "popen", "subprocess"},
		"Path Traversal":     {"Path Traversal", "readFile", "open", "fopen"},
		"SSRF":               {"SSRF", "fetch", "request", "http.get"},
		"Insecure Deserialization": {"Deserialization", "pickle", "unserialize", "yaml.load"},
	}

	dastType := strings.ToLower(dast.Type)
	sastType := strings.ToLower(sast.Type)

	for _, patterns := range typeCorrelations {
		dastMatch := false
		sastMatch := false
		for _, pattern := range patterns {
			if strings.Contains(dastType, strings.ToLower(pattern)) {
				dastMatch = true
			}
			if strings.Contains(sastType, strings.ToLower(pattern)) {
				sastMatch = true
			}
		}
		if dastMatch && sastMatch {
			return true
		}
	}

	// URL path to file correlation
	if dast.URL != "" && sast.File != "" {
		// Extract path from URL
		urlPath := extractURLPath(dast.URL)
		fileName := extractFileName(sast.File)
		
		// Check if URL path matches file name
		if strings.Contains(strings.ToLower(urlPath), strings.ToLower(fileName)) {
			return true
		}
	}

	return false
}

// isIACRelated checks if IAC finding is related to DAST finding
func (c *DASTSASTCorrelator) isIACRelated(dast DASTFinding, iac IACFinding) bool {
	// Port exposure correlation
	if strings.Contains(dast.Type, "Port") || strings.Contains(dast.Type, "Database") {
		if strings.Contains(iac.Type, "Port") || strings.Contains(iac.Type, "Database") {
			return true
		}
	}

	// Network/SSRF correlation
	if strings.Contains(dast.Type, "SSRF") || strings.Contains(dast.Type, "Network") {
		if strings.Contains(iac.Type, "Network") || strings.Contains(iac.Type, "Security Group") {
			return true
		}
	}

	return false
}

func (c *DASTSASTCorrelator) maxSeverity(s1, s2 string) string {
	severityOrder := map[string]int{
		"CRITICAL": 4,
		"HIGH":     3,
		"MEDIUM":   2,
		"LOW":      1,
		"INFO":     0,
	}

	if severityOrder[s1] >= severityOrder[s2] {
		return s1
	}
	return s2
}

// aiCorrelate uses AI for complex correlation
func (c *DASTSASTCorrelator) aiCorrelate(
	target string,
	dastFindings []DASTFinding,
	sastFindings []SASTFinding,
	iacFindings []IACFinding,
) (*CorrelationReport, error) {
	
	ctx := context.Background()
	client, err := genai.NewClient(ctx, option.WithAPIKey(c.apiKey))
	if err != nil {
		return nil, err
	}
	defer client.Close()

	prompt := c.buildAICorrelationPrompt(target, dastFindings, sastFindings, iacFindings)

	model := client.GenerativeModel(c.model)
	model.SetTemperature(0.2)
	model.SetMaxOutputTokens(8192)

	resp, err := model.GenerateContent(ctx, genai.Text(prompt))
	if err != nil {
		return nil, err
	}

	var responseText string
	for _, cand := range resp.Candidates {
		if cand.Content != nil {
			for _, part := range cand.Content.Parts {
				responseText += fmt.Sprintf("%v", part)
			}
		}
	}

	return c.parseAIResponse(responseText), nil
}

func (c *DASTSASTCorrelator) buildAICorrelationPrompt(
	target string,
	dastFindings []DASTFinding,
	sastFindings []SASTFinding,
	iacFindings []IACFinding,
) string {
	
	dastJSON, _ := json.MarshalIndent(dastFindings, "", "  ")
	sastJSON, _ := json.MarshalIndent(sastFindings, "", "  ")
	iacJSON, _ := json.MarshalIndent(iacFindings, "", "  ")

	return fmt.Sprintf(`Você é um Security Analyst especializado em correlação DAST+SAST.

**ALVO**: %s

## DADOS DAST (Vulnerabilidades em Runtime)
%s

## DADOS SAST (Vulnerabilidades no Código)
%s

## DADOS IAC (Problemas de Infraestrutura)
%s

## SUA TAREFA

Analise os dados e:

1. **CORRELACIONE** vulnerabilidades DAST com evidências SAST
   - Identifique qual código causa cada vulnerabilidade DAST
   - Marque confiança: CONFIRMED (mesma CWE), LIKELY (tipo similar), POSSIBLE (contexto)

2. **IDENTIFIQUE ATTACK CHAINS**
   - Sequências de vulnerabilidades que podem ser exploradas juntas
   - Ex: "SAST encontrou SQL Injection em user.go:45 → DAST confirmou em /api/users"

3. **ANALISE IMPACTO DE COMPLIANCE**
   - LGPD: Quais vulnerabilidades afetam dados pessoais?
   - PCI-DSS: Quais afetam dados de pagamento?
   - OWASP Top 10: Quais categorias são afetadas?

4. **GERE ROADMAP DE REMEDIAÇÃO**
   - Priorize por: impacto × facilidade de correção
   - Inclua arquivos específicos e linhas de código
   - Sugira código de correção quando possível

## FORMATO DE RESPOSTA (JSON)

{
  "correlated_vulnerabilities": [
    {
      "id": "CORR-1",
      "type": "SQL Injection",
      "severity": "CRITICAL",
      "confidence_level": "CONFIRMED",
      "dast_evidence": "Endpoint /api/users vulnerável",
      "sast_evidence": "user.go:45 - query sem prepared statement",
      "root_cause": "Concatenação de string em query SQL",
      "attack_vector": "Parâmetro 'id' em /api/users",
      "business_impact": "Vazamento de dados de usuários",
      "remediation": {
        "priority": 1,
        "files": ["user.go"],
        "description": "Usar prepared statements"
      }
    }
  ],
  "attack_chains": [
    {
      "name": "Data Exfiltration Chain",
      "vulnerabilities": ["SQL Injection", "Missing Rate Limit"],
      "description": "SQLi permite dump de dados, sem rate limit permite extração em massa",
      "severity": "CRITICAL"
    }
  ],
  "executive_summary": "Resumo executivo em 2-3 parágrafos...",
  "technical_summary": "Resumo técnico detalhado...",
  "compliance_impact": {
    "lgpd": ["Risco de vazamento de dados pessoais via SQLi"],
    "pci_dss": [],
    "owasp": ["A03:2021 - Injection"]
  },
  "remediation_roadmap": [
    {
      "priority": 1,
      "timeframe": "24h",
      "title": "Corrigir SQL Injection",
      "description": "Implementar prepared statements em user.go",
      "files": ["user.go"],
      "effort": "low",
      "impact": "critical"
    }
  ]
}

Responda APENAS com o JSON válido, sem markdown ou explicações adicionais.
`, target, string(dastJSON), string(sastJSON), string(iacJSON))
}

func (c *DASTSASTCorrelator) parseAIResponse(response string) *CorrelationReport {
	report := &CorrelationReport{}

	// Try to extract JSON from response
	jsonStart := strings.Index(response, "{")
	jsonEnd := strings.LastIndex(response, "}")
	
	if jsonStart >= 0 && jsonEnd > jsonStart {
		jsonStr := response[jsonStart : jsonEnd+1]
		
		var parsed struct {
			CorrelatedVulns []struct {
				ID              string `json:"id"`
				Type            string `json:"type"`
				Severity        string `json:"severity"`
				ConfidenceLevel string `json:"confidence_level"`
				DASTEvidence    string `json:"dast_evidence"`
				SASTEvidence    string `json:"sast_evidence"`
				RootCause       string `json:"root_cause"`
				AttackVector    string `json:"attack_vector"`
				BusinessImpact  string `json:"business_impact"`
				Remediation     struct {
					Priority    int      `json:"priority"`
					Files       []string `json:"files"`
					Description string   `json:"description"`
				} `json:"remediation"`
			} `json:"correlated_vulnerabilities"`
			AttackChains []struct {
				Name            string   `json:"name"`
				Vulnerabilities []string `json:"vulnerabilities"`
				Description     string   `json:"description"`
				Severity        string   `json:"severity"`
			} `json:"attack_chains"`
			ExecutiveSummary   string `json:"executive_summary"`
			TechnicalSummary   string `json:"technical_summary"`
			ComplianceImpact   struct {
				LGPD   []string `json:"lgpd"`
				PCIDSS []string `json:"pci_dss"`
				OWASP  []string `json:"owasp"`
			} `json:"compliance_impact"`
			RemediationRoadmap []struct {
				Priority    int      `json:"priority"`
				Timeframe   string   `json:"timeframe"`
				Title       string   `json:"title"`
				Description string   `json:"description"`
				Files       []string `json:"files"`
				Effort      string   `json:"effort"`
				Impact      string   `json:"impact"`
			} `json:"remediation_roadmap"`
		}

		if err := json.Unmarshal([]byte(jsonStr), &parsed); err == nil {
			// Convert parsed data to report
			for _, cv := range parsed.CorrelatedVulns {
				report.CorrelatedVulns = append(report.CorrelatedVulns, CorrelatedVulnerability{
					ID:              cv.ID,
					Type:            cv.Type,
					Severity:        cv.Severity,
					ConfidenceLevel: cv.ConfidenceLevel,
					RootCause:       cv.RootCause,
					AttackVector:    cv.AttackVector,
					BusinessImpact:  cv.BusinessImpact,
					Remediation: AutoFixSuggestion{
						Priority:    cv.Remediation.Priority,
						Files:       cv.Remediation.Files,
						Description: cv.Remediation.Description,
					},
				})
			}

			for _, ac := range parsed.AttackChains {
				report.AttackChains = append(report.AttackChains, AttackChain{
					Name:            ac.Name,
					Vulnerabilities: ac.Vulnerabilities,
					Description:     ac.Description,
					Severity:        ac.Severity,
				})
			}

			report.ExecutiveSummary = parsed.ExecutiveSummary
			report.TechnicalSummary = parsed.TechnicalSummary
			report.ComplianceImpact = ComplianceAnalysis{
				LGPD:   parsed.ComplianceImpact.LGPD,
				PCIDSS: parsed.ComplianceImpact.PCIDSS,
				OWASP:  parsed.ComplianceImpact.OWASP,
			}

			for _, rs := range parsed.RemediationRoadmap {
				report.RemediationRoadmap = append(report.RemediationRoadmap, RemediationStep{
					Priority:    rs.Priority,
					Timeframe:   rs.Timeframe,
					Title:       rs.Title,
					Description: rs.Description,
					Files:       rs.Files,
					Effort:      rs.Effort,
					Impact:      rs.Impact,
				})
			}
		}
	}

	return report
}

func (c *DASTSASTCorrelator) calculateRiskScore(report *CorrelationReport) int {
	score := 100

	// Penalize for correlated vulnerabilities (confirmed issues)
	for _, cv := range report.CorrelatedVulns {
		switch cv.Severity {
		case "CRITICAL":
			score -= 30
		case "HIGH":
			score -= 20
		case "MEDIUM":
			score -= 10
		case "LOW":
			score -= 5
		}
		
		// Extra penalty for confirmed correlations
		if cv.ConfidenceLevel == "CONFIRMED" {
			score -= 5
		}
	}

	// Penalize for attack chains
	for _, ac := range report.AttackChains {
		switch ac.Severity {
		case "CRITICAL":
			score -= 15
		case "HIGH":
			score -= 10
		}
	}

	// Penalize for unmatched findings
	score -= len(report.UnmatchedDAST) * 5
	score -= len(report.UnmatchedSAST) * 2

	if score < 0 {
		score = 0
	}

	return score
}

func (c *DASTSASTCorrelator) generateExecutiveSummary(report *CorrelationReport) string {
	criticalCount := 0
	highCount := 0
	
	for _, cv := range report.CorrelatedVulns {
		switch cv.Severity {
		case "CRITICAL":
			criticalCount++
		case "HIGH":
			highCount++
		}
	}

	summary := fmt.Sprintf("A análise de correlação DAST+SAST identificou %d vulnerabilidades confirmadas", 
		len(report.CorrelatedVulns))
	
	if criticalCount > 0 {
		summary += fmt.Sprintf(", sendo %d de severidade CRÍTICA", criticalCount)
	}
	if highCount > 0 {
		summary += fmt.Sprintf(" e %d de severidade ALTA", highCount)
	}
	summary += ". "

	if len(report.AttackChains) > 0 {
		summary += fmt.Sprintf("Foram identificadas %d cadeias de ataque potenciais que combinam múltiplas vulnerabilidades. ", 
			len(report.AttackChains))
	}

	summary += fmt.Sprintf("O score de risco calculado é %d/100. ", report.RiskScore)

	if report.RiskScore < 50 {
		summary += "Recomenda-se ação imediata para mitigar os riscos identificados."
	} else if report.RiskScore < 70 {
		summary += "Recomenda-se priorizar a correção das vulnerabilidades críticas e altas."
	} else {
		summary += "A postura de segurança está adequada, mas melhorias são recomendadas."
	}

	return summary
}

func (c *DASTSASTCorrelator) generateRemediationRoadmap(report *CorrelationReport) []RemediationStep {
	roadmap := []RemediationStep{}

	// Priority 1: Critical correlated vulnerabilities
	for _, cv := range report.CorrelatedVulns {
		if cv.Severity == "CRITICAL" {
			roadmap = append(roadmap, RemediationStep{
				Priority:    1,
				Timeframe:   "24h",
				Title:       fmt.Sprintf("Corrigir %s", cv.Type),
				Description: cv.RootCause,
				Files:       cv.Remediation.Files,
				Effort:      "medium",
				Impact:      "critical",
			})
		}
	}

	// Priority 2: High severity
	for _, cv := range report.CorrelatedVulns {
		if cv.Severity == "HIGH" {
			roadmap = append(roadmap, RemediationStep{
				Priority:    2,
				Timeframe:   "1 week",
				Title:       fmt.Sprintf("Corrigir %s", cv.Type),
				Description: cv.RootCause,
				Files:       cv.Remediation.Files,
				Effort:      "medium",
				Impact:      "high",
			})
		}
	}

	// Priority 3: Attack chains
	for _, ac := range report.AttackChains {
		roadmap = append(roadmap, RemediationStep{
			Priority:    3,
			Timeframe:   "1 week",
			Title:       fmt.Sprintf("Quebrar cadeia de ataque: %s", ac.Name),
			Description: ac.Description,
			Effort:      "high",
			Impact:      ac.Severity,
		})
	}

	return roadmap
}

// Helper functions
func extractURLPath(url string) string {
	// Remove protocol and domain
	re := regexp.MustCompile(`https?://[^/]+`)
	path := re.ReplaceAllString(url, "")
	return path
}

func extractFileName(filePath string) string {
	// Get just the filename without extension
	parts := strings.Split(filePath, "/")
	if len(parts) == 0 {
		parts = strings.Split(filePath, "\\")
	}
	fileName := parts[len(parts)-1]
	
	// Remove extension
	dotIndex := strings.LastIndex(fileName, ".")
	if dotIndex > 0 {
		fileName = fileName[:dotIndex]
	}
	
	return fileName
}
