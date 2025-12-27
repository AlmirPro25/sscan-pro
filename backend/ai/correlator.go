package ai

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/generative-ai-go/genai"
	"google.golang.org/api/option"
)

// CorrelationResult contains AI analysis of detected vulnerabilities
type CorrelationResult struct {
	AttackChains    []AttackChain
	RiskPriority    []PriorityItem
	Patterns        []Pattern
	Recommendations []string
	ContextualRisk  string
	BusinessImpact  string
}

// AttackChain represents a sequence of vulnerabilities that can be exploited together
type AttackChain struct {
	Name            string
	Vulnerabilities []string
	Description     string
	Severity        string
	Likelihood      string
}

// PriorityItem represents a prioritized vulnerability
type PriorityItem struct {
	Vulnerability string
	Priority      int // 1-10
	Reason        string
}

// Pattern represents a security pattern identified
type Pattern struct {
	Type        string // "missing_headers", "exposed_files", "misconfiguration"
	Description string
	Count       int
	Impact      string
}

// AICorrelator analyzes vulnerabilities and provides context
type AICorrelator struct {
	apiKey string
}

// NewAICorrelator creates a new AI correlator
func NewAICorrelator(apiKey string) *AICorrelator {
	return &AICorrelator{
		apiKey: apiKey,
	}
}

// Correlate analyzes detected vulnerabilities and provides insights
func (c *AICorrelator) Correlate(vulns []DetectedVulnerability, target string, score int) (*CorrelationResult, error) {
	if len(vulns) == 0 {
		return &CorrelationResult{
			ContextualRisk:  "Nenhuma vulnerabilidade detectada. Postura de segurança adequada.",
			BusinessImpact:  "Baixo risco para operações de negócio.",
			Recommendations: []string{"Manter monitoramento contínuo", "Realizar testes autenticados"},
		}, nil
	}
	
	ctx := context.Background()
	client, err := genai.NewClient(ctx, option.WithAPIKey(c.apiKey))
	if err != nil {
		return nil, err
	}
	defer client.Close()
	
	// Build prompt for AI correlation
	prompt := c.buildCorrelationPrompt(vulns, target, score)
	
	// Use gemini-1.5-flash-latest for correlation (more stable)
	model := client.GenerativeModel("gemini-1.5-flash-latest")
	model.SetTemperature(0.3) // Lower temperature for more deterministic analysis
	
	resp, err := model.GenerateContent(ctx, genai.Text(prompt))
	if err != nil {
		return nil, err
	}
	
	// Extract response
	var responseText string
	for _, cand := range resp.Candidates {
		if cand.Content != nil {
			for _, part := range cand.Content.Parts {
				responseText += fmt.Sprintf("%v", part)
			}
		}
	}
	
	// Parse AI response into structured result
	result := c.parseCorrelationResponse(responseText, vulns)
	
	return result, nil
}

func (c *AICorrelator) buildCorrelationPrompt(vulns []DetectedVulnerability, target string, score int) string {
	// Format vulnerabilities
	vulnList := ""
	for i, vuln := range vulns {
		vulnList += fmt.Sprintf(`
%d. **%s** (%s)
   - CWE: %s
   - OWASP: %s
   - CVSS: %.1f (%s)
   - Confidence: %s
   - Description: %s
`, i+1, vuln.Type, vuln.Severity, vuln.CWE, vuln.OWASP, vuln.CVSSScore, vuln.Severity, vuln.Confidence, vuln.Description)
	}
	
	// Determine if enterprise
	isEnterprise := false
	enterpriseDomains := []string{"mercadolivre", "mercadolibre", "google", "microsoft", "amazon", "facebook", "apple", "netflix"}
	for _, domain := range enterpriseDomains {
		if strings.Contains(strings.ToLower(target), domain) {
			isEnterprise = true
			break
		}
	}
	
	enterpriseContext := ""
	if isEnterprise {
		enterpriseContext = `

**CONTEXTO ENTERPRISE DETECTADO**:
Este alvo opera em escala enterprise. Considere:
- Provável presença de WAF, IDS/IPS, SIEM
- Equipe de segurança dedicada
- Bug bounty program ativo
- Frameworks modernos com proteções built-in
- Monitoramento 24/7

**AJUSTE SUA ANÁLISE**:
- Não exagere severidades de headers faltantes (WAF pode compensar)
- Reconheça que análise passiva tem limitações
- Foque em impacto real considerando defesas em profundidade
- Use tom profissional de consultor, não de atacante
`
	}
	
	return fmt.Sprintf(`
Você é um Security Analyst sênior especializado em correlação de vulnerabilidades.

**IMPORTANTE - TOM PROFISSIONAL**:
- Use linguagem de CONSULTOR DE SEGURANÇA (não de atacante)
- NÃO use termos como "hacker", "atacante", "explorar", "destruir"
- Use "adversário", "ator malicioso", "comprometer", "afetar"
- Seja REALISTA sobre severidades - não exagere
- RECONHEÇA limitações da análise passiva

**ALVO**: %s
**SCORE**: %d/100
**VULNERABILIDADES DETECTADAS**: %d
%s

%s

**SUA TAREFA**:

1. **ATTACK CHAINS**: Identifique se alguma vulnerabilidade pode ser explorada em cadeia com outra.
   Formato: "Nome da Chain | Vulnerabilidades envolvidas | Descrição | Severidade | Likelihood"
   - Se não houver chains viáveis, escreva "Nenhuma attack chain identificada"

2. **RISK PRIORITY**: Priorize as vulnerabilidades por impacto real no negócio (1-10).
   Formato: "Vulnerabilidade | Prioridade | Razão"
   - Considere contexto do alvo (enterprise vs standard)
   - Headers faltantes em sites enterprise: prioridade 5-6 (não 9-10)

3. **PATTERNS**: Identifique padrões (ex: todas relacionadas a headers de segurança).
   Formato: "Tipo | Descrição | Quantidade | Impacto"

4. **CONTEXTUAL RISK**: Avalie o risco contextual para este alvo específico (1-2 parágrafos).
   - Seja REALISTA e PROFISSIONAL
   - Considere defesas não visíveis (WAF, IDS, equipe de segurança)
   - Mencione limitações da análise passiva

5. **BUSINESS IMPACT**: Explique o impacto potencial no negócio (1-2 parágrafos).
   - Foque em impacto real, não teórico
   - Considere probabilidade de exploração
   - Seja profissional, não alarmista

6. **RECOMMENDATIONS**: Sugira ordem de correção e ações específicas (máximo 5).
   - Priorize por impacto real
   - Seja específico e acionável
   - Use tom de recomendação, não de ordem

**FORMATO DE RESPOSTA**:
Use exatamente este formato para facilitar parsing:

### ATTACK CHAINS
[Lista de chains ou "Nenhuma attack chain identificada"]

### RISK PRIORITY
[Lista de prioridades]

### PATTERNS
[Lista de padrões]

### CONTEXTUAL RISK
[1-2 parágrafos profissionais]

### BUSINESS IMPACT
[1-2 parágrafos profissionais]

### RECOMMENDATIONS
[Lista numerada de 3-5 recomendações]

**LEMBRE-SE**: 
- Você está analisando vulnerabilidades JÁ DETECTADAS. Não invente novas.
- Use tom PROFISSIONAL de consultor de segurança
- Seja REALISTA sobre severidades e impactos
- RECONHEÇA limitações da análise passiva
`, target, score, len(vulns), enterpriseContext, vulnList)
}

func (c *AICorrelator) parseCorrelationResponse(response string, vulns []DetectedVulnerability) *CorrelationResult {
	result := &CorrelationResult{
		AttackChains:    []AttackChain{},
		RiskPriority:    []PriorityItem{},
		Patterns:        []Pattern{},
		Recommendations: []string{},
	}
	
	// Split response into sections
	sections := strings.Split(response, "###")
	
	for _, section := range sections {
		section = strings.TrimSpace(section)
		
		if strings.HasPrefix(section, "ATTACK CHAINS") {
			result.AttackChains = c.parseAttackChains(section)
		} else if strings.HasPrefix(section, "RISK PRIORITY") {
			result.RiskPriority = c.parsePriority(section)
		} else if strings.HasPrefix(section, "PATTERNS") {
			result.Patterns = c.parsePatterns(section)
		} else if strings.HasPrefix(section, "CONTEXTUAL RISK") {
			result.ContextualRisk = c.extractParagraph(section)
		} else if strings.HasPrefix(section, "BUSINESS IMPACT") {
			result.BusinessImpact = c.extractParagraph(section)
		} else if strings.HasPrefix(section, "RECOMMENDATIONS") {
			result.Recommendations = c.parseRecommendations(section)
		}
	}
	
	// Fallback if parsing fails
	if result.ContextualRisk == "" {
		result.ContextualRisk = "Análise de correlação em andamento. Vulnerabilidades detectadas requerem atenção."
	}
	
	if result.BusinessImpact == "" {
		result.BusinessImpact = "Impacto potencial no negócio depende da criticidade dos sistemas afetados."
	}
	
	if len(result.Recommendations) == 0 {
		result.Recommendations = []string{
			"Corrigir vulnerabilidades CRITICAL em 24-48 horas",
			"Implementar headers de segurança faltantes",
			"Realizar auditoria completa com testes autenticados",
		}
	}
	
	return result
}

func (c *AICorrelator) parseAttackChains(section string) []AttackChain {
	chains := []AttackChain{}
	
	lines := strings.Split(section, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "ATTACK CHAINS") {
			continue
		}
		
		// Simple parsing - can be improved
		if strings.Contains(line, "|") {
			parts := strings.Split(line, "|")
			if len(parts) >= 3 {
				chain := AttackChain{
					Name:        strings.TrimSpace(parts[0]),
					Description: strings.TrimSpace(parts[2]),
				}
				if len(parts) >= 4 {
					chain.Severity = strings.TrimSpace(parts[3])
				}
				chains = append(chains, chain)
			}
		}
	}
	
	return chains
}

func (c *AICorrelator) parsePriority(section string) []PriorityItem {
	items := []PriorityItem{}
	
	lines := strings.Split(section, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "RISK PRIORITY") {
			continue
		}
		
		// Simple parsing
		if strings.Contains(line, "|") {
			parts := strings.Split(line, "|")
			if len(parts) >= 3 {
				item := PriorityItem{
					Vulnerability: strings.TrimSpace(parts[0]),
					Priority:      8, // Default
					Reason:        strings.TrimSpace(parts[2]),
				}
				items = append(items, item)
			}
		}
	}
	
	return items
}

func (c *AICorrelator) parsePatterns(section string) []Pattern {
	patterns := []Pattern{}
	
	lines := strings.Split(section, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "PATTERNS") {
			continue
		}
		
		// Simple parsing
		if strings.Contains(line, "|") {
			parts := strings.Split(line, "|")
			if len(parts) >= 3 {
				pattern := Pattern{
					Type:        strings.TrimSpace(parts[0]),
					Description: strings.TrimSpace(parts[1]),
					Count:       1,
				}
				if len(parts) >= 4 {
					pattern.Impact = strings.TrimSpace(parts[3])
				}
				patterns = append(patterns, pattern)
			}
		}
	}
	
	return patterns
}

func (c *AICorrelator) extractParagraph(section string) string {
	lines := strings.Split(section, "\n")
	paragraph := ""
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "###") {
			continue
		}
		paragraph += line + " "
	}
	
	return strings.TrimSpace(paragraph)
}

func (c *AICorrelator) parseRecommendations(section string) []string {
	recommendations := []string{}
	
	lines := strings.Split(section, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "RECOMMENDATIONS") {
			continue
		}
		
		// Remove numbering
		line = strings.TrimPrefix(line, "-")
		line = strings.TrimPrefix(line, "*")
		for i := 0; i <= 9; i++ {
			line = strings.TrimPrefix(line, fmt.Sprintf("%d.", i))
			line = strings.TrimPrefix(line, fmt.Sprintf("%d)", i))
		}
		
		line = strings.TrimSpace(line)
		if line != "" {
			recommendations = append(recommendations, line)
		}
	}
	
	return recommendations
}

// DetectedVulnerability struct (imported from scanner package)
type DetectedVulnerability struct {
	Type        string
	CWE         string
	OWASP       string
	CVSSVector  string
	CVSSScore   float64
	Severity    string
	Description string
	Confidence  string
}
