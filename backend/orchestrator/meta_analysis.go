package orchestrator

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// ============================================================================
// AEGIS META-ANALYSIS ENGINE
// Analyzes patterns across all security data to provide strategic insights
// ============================================================================

// SystemWeakness represents a recurring vulnerability pattern
type SystemWeakness struct {
	Category       string   `json:"category"`
	Occurrences    int      `json:"occurrences"`
	AffectedAreas  []string `json:"affected_areas"`
	Severity       string   `json:"severity"`
	Trend          string   `json:"trend"` // increasing, stable, decreasing
	FirstSeen      string   `json:"first_seen"`
	LastSeen       string   `json:"last_seen"`
	Recommendation string   `json:"recommendation"`
}

// CoverageGap represents an area that hasn't been tested
type CoverageGap struct {
	Area        string `json:"area"`
	LastTested  string `json:"last_tested"` // "never" or date
	Priority    string `json:"priority"`
	Reason      string `json:"reason"`
}

// SecurityTrend represents a trend over time
type SecurityTrend struct {
	Metric     string    `json:"metric"`
	Values     []float64 `json:"values"`
	Dates      []string  `json:"dates"`
	Direction  string    `json:"direction"` // up, down, stable
	Prediction string    `json:"prediction"`
}

// MetaAnalysisReport is the complete meta-analysis
type MetaAnalysisReport struct {
	GeneratedAt       time.Time         `json:"generated_at"`
	AnalysisPeriod    string            `json:"analysis_period"`
	TotalScans        int               `json:"total_scans"`
	TotalVulns        int               `json:"total_vulnerabilities"`
	TopWeaknesses     []SystemWeakness  `json:"top_weaknesses"`
	CoverageGaps      []CoverageGap     `json:"coverage_gaps"`
	SecurityTrends    []SecurityTrend   `json:"security_trends"`
	MaturityScore     int               `json:"maturity_score"`
	MaturityLevel     string            `json:"maturity_level"`
	StrategicInsights []string          `json:"strategic_insights"`
	ActionItems       []ActionItem      `json:"action_items"`
}

// ActionItem is a prioritized action
type ActionItem struct {
	Priority    int    `json:"priority"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Impact      string `json:"impact"`
	Effort      string `json:"effort"`
	Category    string `json:"category"`
}

// AuditLog represents a logged action for explainability
type AuditLog struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	SessionID   string                 `json:"session_id"`
	Action      string                 `json:"action"`
	ToolName    string                 `json:"tool_name,omitempty"`
	Arguments   map[string]interface{} `json:"arguments,omitempty"`
	Result      string                 `json:"result"`
	Thinking    string                 `json:"thinking,omitempty"`
	Duration    int64                  `json:"duration_ms"`
	Success     bool                   `json:"success"`
	UserID      string                 `json:"user_id,omitempty"`
}

// MetaAnalyzer performs meta-analysis on security data
type MetaAnalyzer struct {
	auditLogs []AuditLog
}

// NewMetaAnalyzer creates a new meta analyzer
func NewMetaAnalyzer() *MetaAnalyzer {
	return &MetaAnalyzer{
		auditLogs: []AuditLog{},
	}
}

// LogAction logs an action for audit trail
func (m *MetaAnalyzer) LogAction(log AuditLog) {
	log.ID = fmt.Sprintf("LOG-%d", time.Now().UnixNano())
	log.Timestamp = time.Now()
	m.auditLogs = append(m.auditLogs, log)
}

// AnalyzeWeaknesses analyzes vulnerability patterns
func (m *MetaAnalyzer) AnalyzeWeaknesses(vulnData []map[string]interface{}) []SystemWeakness {
	// Count vulnerabilities by category
	categoryCount := make(map[string]int)
	categoryAreas := make(map[string][]string)
	categorySeverity := make(map[string]string)

	for _, vuln := range vulnData {
		category := getString(vuln, "type", "Unknown")
		area := getString(vuln, "location", getString(vuln, "file", "Unknown"))
		severity := getString(vuln, "severity", "MEDIUM")

		categoryCount[category]++
		
		// Track affected areas
		if !contains(categoryAreas[category], area) {
			categoryAreas[category] = append(categoryAreas[category], area)
		}

		// Track highest severity
		if isHigherSeverity(severity, categorySeverity[category]) {
			categorySeverity[category] = severity
		}
	}

	// Convert to SystemWeakness list
	weaknesses := []SystemWeakness{}
	for category, count := range categoryCount {
		weakness := SystemWeakness{
			Category:      category,
			Occurrences:   count,
			AffectedAreas: categoryAreas[category],
			Severity:      categorySeverity[category],
			Trend:         "stable", // Would need historical data
			Recommendation: getRecommendation(category),
		}
		weaknesses = append(weaknesses, weakness)
	}

	// Sort by occurrences (descending)
	sort.Slice(weaknesses, func(i, j int) bool {
		return weaknesses[i].Occurrences > weaknesses[j].Occurrences
	})

	// Return top 10
	if len(weaknesses) > 10 {
		weaknesses = weaknesses[:10]
	}

	return weaknesses
}

// IdentifyCoverageGaps identifies areas that haven't been tested
func (m *MetaAnalyzer) IdentifyCoverageGaps(scannedAreas []string) []CoverageGap {
	// Define all possible security areas
	allAreas := []string{
		"DAST - Web Application",
		"DAST - API Endpoints",
		"DAST - Authentication",
		"DAST - Session Management",
		"SAST - Source Code",
		"SAST - Secrets Detection",
		"SAST - Dependency Analysis",
		"SCA - License Compliance",
		"SCA - Typosquatting",
		"IAC - Docker",
		"IAC - Kubernetes",
		"IAC - Terraform",
		"Infrastructure - Port Scanning",
		"Infrastructure - SSL/TLS",
		"Infrastructure - Cloud Config",
		"Reputation - Blacklists",
		"Reputation - Email Security",
		"Subdomains - Enumeration",
		"Subdomains - Takeover",
	}

	gaps := []CoverageGap{}
	for _, area := range allAreas {
		if !containsPartial(scannedAreas, area) {
			priority := "MEDIUM"
			reason := "Área não testada recentemente"

			// Prioritize critical areas
			if strings.Contains(area, "Authentication") || 
			   strings.Contains(area, "Secrets") ||
			   strings.Contains(area, "Takeover") {
				priority = "HIGH"
				reason = "Área crítica sem cobertura"
			}

			gaps = append(gaps, CoverageGap{
				Area:       area,
				LastTested: "never",
				Priority:   priority,
				Reason:     reason,
			})
		}
	}

	return gaps
}

// CalculateMaturityScore calculates security maturity
func (m *MetaAnalyzer) CalculateMaturityScore(data map[string]interface{}) (int, string) {
	score := 0
	maxScore := 100

	// Scoring criteria
	criteria := []struct {
		name   string
		check  func() bool
		points int
	}{
		{"DAST Coverage", func() bool { return getBool(data, "has_dast") }, 15},
		{"SAST Coverage", func() bool { return getBool(data, "has_sast") }, 15},
		{"SCA Coverage", func() bool { return getBool(data, "has_sca") }, 10},
		{"IAC Analysis", func() bool { return getBool(data, "has_iac") }, 10},
		{"Correlation Engine", func() bool { return getBool(data, "has_correlation") }, 15},
		{"Automated Fixes", func() bool { return getBool(data, "has_autofix") }, 10},
		{"CI/CD Integration", func() bool { return getBool(data, "has_cicd") }, 10},
		{"Regular Scanning", func() bool { return getBool(data, "regular_scans") }, 10},
		{"Low Critical Vulns", func() bool { return getInt(data, "critical_vulns") < 5 }, 5},
	}

	for _, c := range criteria {
		if c.check() {
			score += c.points
		}
	}

	// Determine maturity level
	level := "Initial"
	if score >= 80 {
		level = "Optimized"
	} else if score >= 60 {
		level = "Managed"
	} else if score >= 40 {
		level = "Defined"
	} else if score >= 20 {
		level = "Developing"
	}

	return min(score, maxScore), level
}

// GenerateStrategicInsights generates high-level insights
func (m *MetaAnalyzer) GenerateStrategicInsights(weaknesses []SystemWeakness, gaps []CoverageGap, maturityScore int) []string {
	insights := []string{}

	// Insight based on top weakness
	if len(weaknesses) > 0 {
		top := weaknesses[0]
		insights = append(insights, fmt.Sprintf(
			"🎯 Principal fraqueza: %s com %d ocorrências em %d áreas diferentes. Priorize correção sistemática.",
			top.Category, top.Occurrences, len(top.AffectedAreas),
		))
	}

	// Insight based on coverage gaps
	highPriorityGaps := 0
	for _, gap := range gaps {
		if gap.Priority == "HIGH" {
			highPriorityGaps++
		}
	}
	if highPriorityGaps > 0 {
		insights = append(insights, fmt.Sprintf(
			"⚠️ %d áreas críticas sem cobertura de testes. Risco de vulnerabilidades não detectadas.",
			highPriorityGaps,
		))
	}

	// Insight based on maturity
	if maturityScore < 40 {
		insights = append(insights, 
			"📈 Maturidade de segurança abaixo do ideal. Recomenda-se implementar scanning automatizado em CI/CD.",
		)
	} else if maturityScore >= 80 {
		insights = append(insights,
			"✅ Excelente maturidade de segurança. Foque em otimização e redução de falsos positivos.",
		)
	}

	// Pattern-based insights
	xssCount := 0
	sqliCount := 0
	for _, w := range weaknesses {
		if strings.Contains(strings.ToLower(w.Category), "xss") {
			xssCount += w.Occurrences
		}
		if strings.Contains(strings.ToLower(w.Category), "sql") {
			sqliCount += w.Occurrences
		}
	}

	if xssCount > 5 {
		insights = append(insights,
			"🔴 Padrão de XSS recorrente detectado. Considere implementar CSP e sanitização centralizada.",
		)
	}
	if sqliCount > 0 {
		insights = append(insights,
			"🔴 SQL Injection detectado. Migre para prepared statements/ORM em todo o código.",
		)
	}

	return insights
}

// GenerateActionItems creates prioritized action items
func (m *MetaAnalyzer) GenerateActionItems(weaknesses []SystemWeakness, gaps []CoverageGap) []ActionItem {
	items := []ActionItem{}
	priority := 1

	// Actions from weaknesses
	for i, w := range weaknesses {
		if i >= 3 {
			break // Top 3 only
		}
		items = append(items, ActionItem{
			Priority:    priority,
			Title:       fmt.Sprintf("Corrigir %s", w.Category),
			Description: fmt.Sprintf("Resolver %d ocorrências em %d áreas", w.Occurrences, len(w.AffectedAreas)),
			Impact:      w.Severity,
			Effort:      estimateEffort(w.Occurrences),
			Category:    "remediation",
		})
		priority++
	}

	// Actions from gaps
	for _, g := range gaps {
		if g.Priority == "HIGH" {
			items = append(items, ActionItem{
				Priority:    priority,
				Title:       fmt.Sprintf("Implementar testes: %s", g.Area),
				Description: g.Reason,
				Impact:      "HIGH",
				Effort:      "medium",
				Category:    "coverage",
			})
			priority++
		}
	}

	return items
}

// GetAuditLogs returns audit logs for a session
func (m *MetaAnalyzer) GetAuditLogs(sessionID string) []AuditLog {
	logs := []AuditLog{}
	for _, log := range m.auditLogs {
		if sessionID == "" || log.SessionID == sessionID {
			logs = append(logs, log)
		}
	}
	return logs
}

// Helper functions
func getString(m map[string]interface{}, key, defaultVal string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return defaultVal
}

func getBool(m map[string]interface{}, key string) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return false
}

func getInt(m map[string]interface{}, key string) int {
	if v, ok := m[key].(float64); ok {
		return int(v)
	}
	if v, ok := m[key].(int); ok {
		return v
	}
	return 0
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func containsPartial(slice []string, item string) bool {
	itemLower := strings.ToLower(item)
	for _, s := range slice {
		if strings.Contains(strings.ToLower(s), itemLower) || strings.Contains(itemLower, strings.ToLower(s)) {
			return true
		}
	}
	return false
}

func isHigherSeverity(a, b string) bool {
	order := map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
	return order[a] > order[b]
}

func getRecommendation(category string) string {
	recommendations := map[string]string{
		"XSS":               "Implementar sanitização de entrada e CSP",
		"SQL Injection":     "Usar prepared statements e ORM",
		"Command Injection": "Validar e escapar comandos do sistema",
		"Path Traversal":    "Validar e normalizar caminhos de arquivo",
		"SSRF":              "Implementar whitelist de URLs permitidas",
		"Hardcoded Secret":  "Usar variáveis de ambiente ou vault",
		"Insecure Cookie":   "Adicionar flags Secure, HttpOnly, SameSite",
	}
	
	for key, rec := range recommendations {
		if strings.Contains(strings.ToLower(category), strings.ToLower(key)) {
			return rec
		}
	}
	return "Revisar e corrigir conforme melhores práticas"
}

func estimateEffort(occurrences int) string {
	if occurrences > 20 {
		return "high"
	} else if occurrences > 5 {
		return "medium"
	}
	return "low"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
