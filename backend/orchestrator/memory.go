package orchestrator

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// AEGIS SECURITY BRAIN - Long-Term Memory
// Stores and indexes security findings for pattern detection and learning
// ============================================================================

// SecurityMemory is the long-term memory store
type SecurityMemory struct {
	mu              sync.RWMutex
	Vulnerabilities []VulnerabilityMemory `json:"vulnerabilities"`
	Targets         []TargetMemory        `json:"targets"`
	Patterns        []PatternMemory       `json:"patterns"`
	Learnings       []LearningMemory      `json:"learnings"`
}

// VulnerabilityMemory stores a vulnerability finding
type VulnerabilityMemory struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Target      string    `json:"target"`
	Location    string    `json:"location"`
	Description string    `json:"description"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Occurrences int       `json:"occurrences"`
	Status      string    `json:"status"` // open, fixed, accepted, false_positive
	Tags        []string  `json:"tags"`
}

// TargetMemory stores information about a scanned target
type TargetMemory struct {
	URL           string    `json:"url"`
	Domain        string    `json:"domain"`
	FirstScanned  time.Time `json:"first_scanned"`
	LastScanned   time.Time `json:"last_scanned"`
	ScanCount     int       `json:"scan_count"`
	AvgScore      int       `json:"avg_score"`
	BestScore     int       `json:"best_score"`
	WorstScore    int       `json:"worst_score"`
	Technologies  []string  `json:"technologies"`
	VulnCount     int       `json:"vuln_count"`
	CriticalCount int       `json:"critical_count"`
}

// PatternMemory stores detected vulnerability patterns
type PatternMemory struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	VulnTypes   []string  `json:"vuln_types"`
	Frequency   int       `json:"frequency"`
	Targets     []string  `json:"targets"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Severity    string    `json:"severity"`
	Remediation string    `json:"remediation"`
}

// LearningMemory stores system learnings
type LearningMemory struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"` // false_positive, new_pattern, optimization
	Description string    `json:"description"`
	Context     string    `json:"context"`
	CreatedAt   time.Time `json:"created_at"`
	AppliedAt   *time.Time `json:"applied_at,omitempty"`
	Impact      string    `json:"impact"`
}

// MemoryQuery represents a query to the memory
type MemoryQuery struct {
	Type       string   `json:"type"` // vulnerability, target, pattern, learning
	Filters    map[string]string `json:"filters"`
	Limit      int      `json:"limit"`
	SortBy     string   `json:"sort_by"`
	SortOrder  string   `json:"sort_order"` // asc, desc
}

// MemoryInsight represents an insight derived from memory
type MemoryInsight struct {
	Type        string `json:"type"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Confidence  float64 `json:"confidence"`
	Evidence    []string `json:"evidence"`
	Suggestion  string `json:"suggestion"`
}

// Global memory instance
var globalMemory = &SecurityMemory{
	Vulnerabilities: []VulnerabilityMemory{},
	Targets:         []TargetMemory{},
	Patterns:        []PatternMemory{},
	Learnings:       []LearningMemory{},
}

// GetSecurityMemory returns the global memory instance
func GetSecurityMemory() *SecurityMemory {
	return globalMemory
}

// RecordVulnerability adds or updates a vulnerability in memory
func (m *SecurityMemory) RecordVulnerability(vuln VulnerabilityMemory) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if vulnerability already exists
	for i, existing := range m.Vulnerabilities {
		if existing.Type == vuln.Type && existing.Target == vuln.Target && existing.Location == vuln.Location {
			// Update existing
			m.Vulnerabilities[i].LastSeen = time.Now()
			m.Vulnerabilities[i].Occurrences++
			return
		}
	}

	// Add new
	vuln.ID = fmt.Sprintf("VULN-%d", time.Now().UnixNano())
	vuln.FirstSeen = time.Now()
	vuln.LastSeen = time.Now()
	vuln.Occurrences = 1
	vuln.Status = "open"
	m.Vulnerabilities = append(m.Vulnerabilities, vuln)

	// Detect patterns
	m.detectPatterns()
}

// RecordTarget adds or updates a target in memory
func (m *SecurityMemory) RecordTarget(url string, score int, vulnCount, criticalCount int, technologies []string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	domain := extractDomain(url)

	for i, existing := range m.Targets {
		if existing.Domain == domain {
			// Update existing
			m.Targets[i].LastScanned = time.Now()
			m.Targets[i].ScanCount++
			m.Targets[i].AvgScore = (existing.AvgScore*existing.ScanCount + score) / (existing.ScanCount + 1)
			if score > existing.BestScore {
				m.Targets[i].BestScore = score
			}
			if score < existing.WorstScore {
				m.Targets[i].WorstScore = score
			}
			m.Targets[i].VulnCount += vulnCount
			m.Targets[i].CriticalCount += criticalCount
			// Merge technologies
			for _, tech := range technologies {
				if !containsString(m.Targets[i].Technologies, tech) {
					m.Targets[i].Technologies = append(m.Targets[i].Technologies, tech)
				}
			}
			return
		}
	}

	// Add new
	m.Targets = append(m.Targets, TargetMemory{
		URL:           url,
		Domain:        domain,
		FirstScanned:  time.Now(),
		LastScanned:   time.Now(),
		ScanCount:     1,
		AvgScore:      score,
		BestScore:     score,
		WorstScore:    score,
		Technologies:  technologies,
		VulnCount:     vulnCount,
		CriticalCount: criticalCount,
	})
}

// RecordLearning adds a learning to memory
func (m *SecurityMemory) RecordLearning(learningType, description, context, impact string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	learning := LearningMemory{
		ID:          fmt.Sprintf("LEARN-%d", time.Now().UnixNano()),
		Type:        learningType,
		Description: description,
		Context:     context,
		CreatedAt:   time.Now(),
		Impact:      impact,
	}
	m.Learnings = append(m.Learnings, learning)
}

// detectPatterns analyzes vulnerabilities to find patterns
func (m *SecurityMemory) detectPatterns() {
	// Group vulnerabilities by type
	typeCount := make(map[string]int)
	typeTargets := make(map[string][]string)

	for _, vuln := range m.Vulnerabilities {
		typeCount[vuln.Type]++
		if !containsString(typeTargets[vuln.Type], vuln.Target) {
			typeTargets[vuln.Type] = append(typeTargets[vuln.Type], vuln.Target)
		}
	}

	// Create patterns for recurring vulnerabilities
	for vulnType, count := range typeCount {
		if count >= 3 { // Pattern threshold
			patternExists := false
			for i, p := range m.Patterns {
				if p.Name == vulnType+" Pattern" {
					m.Patterns[i].Frequency = count
					m.Patterns[i].Targets = typeTargets[vulnType]
					m.Patterns[i].LastSeen = time.Now()
					patternExists = true
					break
				}
			}

			if !patternExists {
				m.Patterns = append(m.Patterns, PatternMemory{
					ID:          fmt.Sprintf("PAT-%d", time.Now().UnixNano()),
					Name:        vulnType + " Pattern",
					Description: fmt.Sprintf("Padrão recorrente de %s detectado em %d ocorrências", vulnType, count),
					VulnTypes:   []string{vulnType},
					Frequency:   count,
					Targets:     typeTargets[vulnType],
					FirstSeen:   time.Now(),
					LastSeen:    time.Now(),
					Severity:    getSeverityForType(vulnType),
					Remediation: getRemediationForType(vulnType),
				})
			}
		}
	}
}

// Query searches the memory
func (m *SecurityMemory) Query(q MemoryQuery) interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	switch q.Type {
	case "vulnerability":
		return m.queryVulnerabilities(q)
	case "target":
		return m.queryTargets(q)
	case "pattern":
		return m.Patterns
	case "learning":
		return m.Learnings
	default:
		return nil
	}
}

func (m *SecurityMemory) queryVulnerabilities(q MemoryQuery) []VulnerabilityMemory {
	results := []VulnerabilityMemory{}

	for _, v := range m.Vulnerabilities {
		match := true
		for key, value := range q.Filters {
			switch key {
			case "type":
				if !strings.Contains(strings.ToLower(v.Type), strings.ToLower(value)) {
					match = false
				}
			case "severity":
				if v.Severity != value {
					match = false
				}
			case "status":
				if v.Status != value {
					match = false
				}
			case "target":
				if !strings.Contains(v.Target, value) {
					match = false
				}
			}
		}
		if match {
			results = append(results, v)
		}
	}

	// Sort
	if q.SortBy == "occurrences" {
		sort.Slice(results, func(i, j int) bool {
			if q.SortOrder == "asc" {
				return results[i].Occurrences < results[j].Occurrences
			}
			return results[i].Occurrences > results[j].Occurrences
		})
	}

	// Limit
	if q.Limit > 0 && len(results) > q.Limit {
		results = results[:q.Limit]
	}

	return results
}

func (m *SecurityMemory) queryTargets(q MemoryQuery) []TargetMemory {
	results := m.Targets

	// Sort by scan count by default
	sort.Slice(results, func(i, j int) bool {
		return results[i].ScanCount > results[j].ScanCount
	})

	if q.Limit > 0 && len(results) > q.Limit {
		results = results[:q.Limit]
	}

	return results
}

// GenerateInsights analyzes memory to generate insights
func (m *SecurityMemory) GenerateInsights() []MemoryInsight {
	m.mu.RLock()
	defer m.mu.RUnlock()

	insights := []MemoryInsight{}

	// Insight: Most common vulnerability
	if len(m.Vulnerabilities) > 0 {
		typeCount := make(map[string]int)
		for _, v := range m.Vulnerabilities {
			typeCount[v.Type]++
		}
		
		maxType := ""
		maxCount := 0
		for t, c := range typeCount {
			if c > maxCount {
				maxType = t
				maxCount = c
			}
		}

		if maxCount >= 2 {
			insights = append(insights, MemoryInsight{
				Type:        "recurring_vulnerability",
				Title:       fmt.Sprintf("Vulnerabilidade Recorrente: %s", maxType),
				Description: fmt.Sprintf("%s aparece %d vezes nos scans", maxType, maxCount),
				Confidence:  float64(maxCount) / float64(len(m.Vulnerabilities)),
				Evidence:    []string{fmt.Sprintf("%d ocorrências detectadas", maxCount)},
				Suggestion:  getRemediationForType(maxType),
			})
		}
	}

	// Insight: Target with most vulnerabilities
	if len(m.Targets) > 0 {
		var worstTarget *TargetMemory
		for i := range m.Targets {
			if worstTarget == nil || m.Targets[i].CriticalCount > worstTarget.CriticalCount {
				worstTarget = &m.Targets[i]
			}
		}

		if worstTarget != nil && worstTarget.CriticalCount > 0 {
			insights = append(insights, MemoryInsight{
				Type:        "high_risk_target",
				Title:       fmt.Sprintf("Alvo de Alto Risco: %s", worstTarget.Domain),
				Description: fmt.Sprintf("%d vulnerabilidades críticas detectadas", worstTarget.CriticalCount),
				Confidence:  0.9,
				Evidence:    []string{fmt.Sprintf("Score médio: %d/100", worstTarget.AvgScore)},
				Suggestion:  "Priorize a correção das vulnerabilidades críticas neste alvo",
			})
		}
	}

	// Insight: Patterns detected
	for _, p := range m.Patterns {
		if p.Frequency >= 5 {
			insights = append(insights, MemoryInsight{
				Type:        "pattern_detected",
				Title:       p.Name,
				Description: p.Description,
				Confidence:  0.85,
				Evidence:    p.Targets,
				Suggestion:  p.Remediation,
			})
		}
	}

	// Insight: Improvement trend
	if len(m.Targets) > 0 {
		improving := 0
		for _, t := range m.Targets {
			if t.BestScore > t.WorstScore && t.ScanCount > 1 {
				improving++
			}
		}
		if improving > 0 {
			insights = append(insights, MemoryInsight{
				Type:        "positive_trend",
				Title:       "Tendência de Melhoria Detectada",
				Description: fmt.Sprintf("%d alvos mostraram melhoria no score de segurança", improving),
				Confidence:  0.8,
				Evidence:    []string{fmt.Sprintf("%d de %d alvos melhoraram", improving, len(m.Targets))},
				Suggestion:  "Continue monitorando e aplicando correções",
			})
		}
	}

	return insights
}

// GetStats returns memory statistics
func (m *SecurityMemory) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]interface{}{
		"total_vulnerabilities": len(m.Vulnerabilities),
		"total_targets":         len(m.Targets),
		"total_patterns":        len(m.Patterns),
		"total_learnings":       len(m.Learnings),
		"open_vulnerabilities":  countByStatus(m.Vulnerabilities, "open"),
		"fixed_vulnerabilities": countByStatus(m.Vulnerabilities, "fixed"),
	}
}

// Helper functions
func extractDomain(url string) string {
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	parts := strings.Split(url, "/")
	return parts[0]
}

func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func getSeverityForType(vulnType string) string {
	critical := []string{"SQL Injection", "Command Injection", "RCE", "SSRF"}
	high := []string{"XSS", "Path Traversal", "IDOR", "Authentication Bypass"}
	
	for _, c := range critical {
		if strings.Contains(strings.ToLower(vulnType), strings.ToLower(c)) {
			return "CRITICAL"
		}
	}
	for _, h := range high {
		if strings.Contains(strings.ToLower(vulnType), strings.ToLower(h)) {
			return "HIGH"
		}
	}
	return "MEDIUM"
}

func getRemediationForType(vulnType string) string {
	remediations := map[string]string{
		"xss":               "Implementar sanitização de entrada e Content Security Policy (CSP)",
		"sql":               "Usar prepared statements e ORM. Nunca concatenar input em queries",
		"command":           "Validar e escapar comandos. Usar APIs seguras ao invés de shell",
		"path":              "Validar e normalizar caminhos. Usar whitelist de diretórios",
		"ssrf":              "Implementar whitelist de URLs. Bloquear IPs internos",
		"idor":              "Implementar controle de acesso baseado em ownership",
		"authentication":    "Implementar MFA, rate limiting e políticas de senha fortes",
		"secret":            "Usar variáveis de ambiente ou vault. Nunca commitar secrets",
	}

	vulnLower := strings.ToLower(vulnType)
	for key, rem := range remediations {
		if strings.Contains(vulnLower, key) {
			return rem
		}
	}
	return "Revisar e corrigir conforme melhores práticas de segurança"
}

func countByStatus(vulns []VulnerabilityMemory, status string) int {
	count := 0
	for _, v := range vulns {
		if v.Status == status {
			count++
		}
	}
	return count
}
