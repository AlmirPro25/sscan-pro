package orchestrator

// ============================================================================
// AEGIS TOOL REGISTRY
// Centralized tool metadata with risk levels, schemas, and validation
// ============================================================================

// ToolMetadata contains extended information about a tool
type ToolMetadata struct {
	Name          string      `json:"name"`
	Description   string      `json:"description"`
	Category      string      `json:"category"`
	RiskLevel     string      `json:"risk_level"`     // low, medium, high, critical
	RequiresHITL  bool        `json:"requires_hitl"`  // Human-in-the-loop
	ImpactLevel   string      `json:"impact_level"`   // read-only, write, destructive
	ExecutionTime string      `json:"execution_time"` // fast (<1s), medium (<30s), slow (>30s)
	Schema        *ToolSchema `json:"schema"`
	Tags          []string    `json:"tags"`
}

// ToolSchema defines the expected arguments for a tool
type ToolSchema struct {
	Required   []string               `json:"required"`
	Properties map[string]PropertyDef `json:"properties"`
}

// PropertyDef defines a single property
type PropertyDef struct {
	Type        string      `json:"type"`
	Description string      `json:"description"`
	Default     interface{} `json:"default,omitempty"`
	Enum        []string    `json:"enum,omitempty"`
	MinLength   int         `json:"min_length,omitempty"`
	MaxLength   int         `json:"max_length,omitempty"`
	Pattern     string      `json:"pattern,omitempty"`
}

// ToolRegistry is the central registry of all tools with extended metadata
var ToolRegistry = map[string]ToolMetadata{
	// ============================================================================
	// SCANNING TOOLS (10)
	// ============================================================================
	"scan_website": {
		Name:          "scan_website",
		Description:   "Executa scan DAST completo em website",
		Category:      "scanning",
		RiskLevel:     "medium",
		RequiresHITL:  false,
		ImpactLevel:   "read-only",
		ExecutionTime: "slow",
		Schema: &ToolSchema{
			Required: []string{"url"},
			Properties: map[string]PropertyDef{
				"url": {Type: "string", Description: "URL do site", Pattern: "^https?://"},
			},
		},
		Tags: []string{"dast", "web", "vulnerabilities"},
	},
	"scan_code": {
		Name:          "scan_code",
		Description:   "Executa scan SAST em código-fonte",
		Category:      "scanning",
		RiskLevel:     "low",
		RequiresHITL:  false,
		ImpactLevel:   "read-only",
		ExecutionTime: "medium",
		Schema: &ToolSchema{
			Required: []string{"path"},
			Properties: map[string]PropertyDef{
				"path": {Type: "string", Description: "Caminho do diretório"},
			},
		},
		Tags: []string{"sast", "code", "static-analysis"},
	},
	"scan_dependencies": {
		Name:          "scan_dependencies",
		Description:   "Escaneia dependências em busca de CVEs",
		Category:      "scanning",
		RiskLevel:     "low",
		RequiresHITL:  false,
		ImpactLevel:   "read-only",
		ExecutionTime: "medium",
		Schema: &ToolSchema{
			Required: []string{"path"},
			Properties: map[string]PropertyDef{
				"path": {Type: "string", Description: "Caminho do projeto"},
			},
		},
		Tags: []string{"sca", "dependencies", "cve"},
	},
	"scan_infrastructure": {
		Name:          "scan_infrastructure",
		Description:   "Escaneia infraestrutura: portas, SSL, cloud",
		Category:      "scanning",
		RiskLevel:     "medium",
		RequiresHITL:  false,
		ImpactLevel:   "read-only",
		ExecutionTime: "medium",
		Schema: &ToolSchema{
			Required: []string{"url"},
			Properties: map[string]PropertyDef{
				"url": {Type: "string", Description: "URL do alvo"},
			},
		},
		Tags: []string{"infrastructure", "ports", "ssl"},
	},
	"scan_subdomains": {
		Name:          "scan_subdomains",
		Description:   "Enumera subdomínios de um domínio",
		Category:      "scanning",
		RiskLevel:     "low",
		RequiresHITL:  false,
		ImpactLevel:   "read-only",
		ExecutionTime: "medium",
		Schema: &ToolSchema{
			Required: []string{"url"},
			Properties: map[string]PropertyDef{
				"url": {Type: "string", Description: "Domínio para enumerar"},
			},
		},
		Tags: []string{"recon", "subdomains", "enumeration"},
	},
	"scan_reputation": {
		Name:          "scan_reputation",
		Description:   "Verifica reputação do domínio em blacklists",
		Category:      "scanning",
		RiskLevel:     "low",
		RequiresHITL:  false,
		ImpactLevel:   "read-only",
		ExecutionTime: "fast",
		Schema: &ToolSchema{
			Required: []string{"url"},
			Properties: map[string]PropertyDef{
				"url": {Type: "string", Description: "URL para verificar"},
			},
		},
		Tags: []string{"reputation", "blacklist", "threat-intel"},
	},
	"scan_authenticated": {
		Name:          "scan_authenticated",
		Description:   "Executa testes autenticados: login, sessão, IDOR",
		Category:      "scanning",
		RiskLevel:     "high",
		RequiresHITL:  true,
		ImpactLevel:   "write",
		ExecutionTime: "slow",
		Schema: &ToolSchema{
			Required: []string{"url", "username", "password"},
			Properties: map[string]PropertyDef{
				"url":       {Type: "string", Description: "URL do alvo"},
				"username":  {Type: "string", Description: "Usuário para login"},
				"password":  {Type: "string", Description: "Senha para login"},
				"login_url": {Type: "string", Description: "URL da página de login"},
			},
		},
		Tags: []string{"authentication", "session", "idor"},
	},
	"scan_iac": {
		Name:          "scan_iac",
		Description:   "Escaneia Infrastructure as Code",
		Category:      "scanning",
		RiskLevel:     "low",
		RequiresHITL:  false,
		ImpactLevel:   "read-only",
		ExecutionTime: "fast",
		Schema: &ToolSchema{
			Required: []string{"path"},
			Properties: map[string]PropertyDef{
				"path": {Type: "string", Description: "Caminho dos arquivos IAC"},
			},
		},
		Tags: []string{"iac", "terraform", "kubernetes", "cloudformation"},
	},
	"scan_licenses": {
		Name:          "scan_licenses",
		Description:   "Analisa licenças de dependências",
		Category:      "scanning",
		RiskLevel:     "low",
		RequiresHITL:  false,
		ImpactLevel:   "read-only",
		ExecutionTime: "fast",
		Schema: &ToolSchema{
			Required: []string{"path"},
			Properties: map[string]PropertyDef{
				"path": {Type: "string", Description: "Caminho do projeto"},
			},
		},
		Tags: []string{"license", "compliance", "legal"},
	},
	"scan_typosquatting": {
		Name:          "scan_typosquatting",
		Description:   "Detecta dependências suspeitas de typosquatting",
		Category:      "scanning",
		RiskLevel:     "low",
		RequiresHITL:  false,
		ImpactLevel:   "read-only",
		ExecutionTime: "fast",
		Schema: &ToolSchema{
			Required: []string{"path"},
			Properties: map[string]PropertyDef{
				"path": {Type: "string", Description: "Caminho do projeto"},
			},
		},
		Tags: []string{"typosquatting", "supply-chain", "malware"},
	},

	// ============================================================================
	// BROWSER TOOLS (7)
	// ============================================================================
	"navigate_to": {
		Name:          "navigate_to",
		Description:   "Navega para URL usando Playwright",
		Category:      "browser",
		RiskLevel:     "low",
		RequiresHITL:  false,
		ImpactLevel:   "read-only",
		ExecutionTime: "fast",
		Schema: &ToolSchema{
			Required: []string{"url"},
			Properties: map[string]PropertyDef{
				"url": {Type: "string", Description: "URL para navegar"},
			},
		},
		Tags: []string{"browser", "navigation"},
	},
	"take_screenshot": {
		Name:          "take_screenshot",
		Description:   "Captura screenshot da página atual",
		Category:      "browser",
		RiskLevel:     "low",
		RequiresHITL:  false,
		ImpactLevel:   "read-only",
		ExecutionTime: "fast",
		Schema: &ToolSchema{
			Required:   []string{},
			Properties: map[string]PropertyDef{
				"full_page": {Type: "boolean", Description: "Capturar página inteira", Default: true},
			},
		},
		Tags: []string{"browser", "screenshot", "visual"},
	},
	"take_contextual_screenshot": {
		Name:          "take_contextual_screenshot",
		Description:   "Captura screenshot contextual: viewport, full-page, DOM, metadata",
		Category:      "browser",
		RiskLevel:     "low",
		RequiresHITL:  false,
		ImpactLevel:   "read-only",
		ExecutionTime: "fast",
		Schema: &ToolSchema{
			Required: []string{},
			Properties: map[string]PropertyDef{
				"include_dom":     {Type: "boolean", Description: "Incluir DOM HTML", Default: true},
				"include_console": {Type: "boolean", Description: "Incluir logs do console", Default: false},
			},
		},
		Tags: []string{"browser", "screenshot", "visual", "forensic"},
	},
	"take_forensic_screenshot": {
		Name:          "take_forensic_screenshot",
		Description:   "Captura evidência forense completa: viewport, full-page, DOM, console, network, cookies, storage",
		Category:      "browser",
		RiskLevel:     "low",
		RequiresHITL:  false,
		ImpactLevel:   "read-only",
		ExecutionTime: "medium",
		Schema: &ToolSchema{
			Required: []string{},
			Properties: map[string]PropertyDef{
				"include_network": {Type: "boolean", Description: "Incluir requisições de rede", Default: true},
				"include_cookies": {Type: "boolean", Description: "Incluir cookies da sessão", Default: true},
				"include_storage": {Type: "boolean", Description: "Incluir localStorage/sessionStorage", Default: true},
			},
		},
		Tags: []string{"browser", "screenshot", "forensic", "evidence", "pentest"},
	},
	"click_element": {
		Name:          "click_element",
		Description:   "Clica em elemento na página",
		Category:      "browser",
		RiskLevel:     "medium",
		RequiresHITL:  false,
		ImpactLevel:   "write",
		ExecutionTime: "fast",
		Schema: &ToolSchema{
			Required: []string{"selector"},
			Properties: map[string]PropertyDef{
				"selector": {Type: "string", Description: "Seletor CSS do elemento"},
			},
		},
		Tags: []string{"browser", "interaction"},
	},
	"fill_input": {
		Name:          "fill_input",
		Description:   "Preenche campo de input na página",
		Category:      "browser",
		RiskLevel:     "medium",
		RequiresHITL:  false,
		ImpactLevel:   "write",
		ExecutionTime: "fast",
		Schema: &ToolSchema{
			Required: []string{"selector", "value"},
			Properties: map[string]PropertyDef{
				"selector": {Type: "string", Description: "Seletor CSS do input"},
				"value":    {Type: "string", Description: "Valor para preencher"},
			},
		},
		Tags: []string{"browser", "interaction", "form"},
	},
	"get_page_content": {
		Name:          "get_page_content",
		Description:   "Obtém conteúdo HTML da página atual",
		Category:      "browser",
		RiskLevel:     "low",
		RequiresHITL:  false,
		ImpactLevel:   "read-only",
		ExecutionTime: "fast",
		Schema: &ToolSchema{
			Required:   []string{},
			Properties: map[string]PropertyDef{},
		},
		Tags: []string{"browser", "content", "html"},
	},
	"execute_javascript": {
		Name:          "execute_javascript",
		Description:   "Executa código JavaScript na página (PERIGOSO)",
		Category:      "browser",
		RiskLevel:     "critical",
		RequiresHITL:  true,
		ImpactLevel:   "destructive",
		ExecutionTime: "fast",
		Schema: &ToolSchema{
			Required: []string{"code"},
			Properties: map[string]PropertyDef{
				"code": {Type: "string", Description: "Código JavaScript"},
			},
		},
		Tags: []string{"browser", "javascript", "dangerous"},
	},

	// ============================================================================
	// DATABASE TOOLS (4)
	// ============================================================================
	"query_scan_history": {
		Name:          "query_scan_history",
		Description:   "Consulta histórico de scans realizados",
		Category:      "database",
		RiskLevel:     "low",
		RequiresHITL:  false,
		ImpactLevel:   "read-only",
		ExecutionTime: "fast",
		Schema: &ToolSchema{
			Required: []string{},
			Properties: map[string]PropertyDef{
				"limit":      {Type: "number", Description: "Limite de resultados", Default: 50},
				"url_filter": {Type: "string", Description: "Filtrar por URL"},
			},
		},
		Tags: []string{"database", "history", "query"},
	},
	"get_scan_details": {
		Name:          "get_scan_details",
		Description:   "Obtém detalhes completos de um scan",
		Category:      "database",
		RiskLevel:     "low",
		RequiresHITL:  false,
		ImpactLevel:   "read-only",
		ExecutionTime: "fast",
		Schema: &ToolSchema{
			Required: []string{"scan_id"},
			Properties: map[string]PropertyDef{
				"scan_id": {Type: "number", Description: "ID do scan"},
			},
		},
		Tags: []string{"database", "scan", "details"},
	},
	"get_project_data": {
		Name:          "get_project_data",
		Description:   "Obtém dados de um projeto específico",
		Category:      "database",
		RiskLevel:     "low",
		RequiresHITL:  false,
		ImpactLevel:   "read-only",
		ExecutionTime: "fast",
		Schema: &ToolSchema{
			Required: []string{"project_id"},
			Properties: map[string]PropertyDef{
				"project_id": {Type: "number", Description: "ID do projeto"},
			},
		},
		Tags: []string{"database", "project"},
	},
	"list_projects": {
		Name:          "list_projects",
		Description:   "Lista todos os projetos cadastrados",
		Category:      "database",
		RiskLevel:     "low",
		RequiresHITL:  false,
		ImpactLevel:   "read-only",
		ExecutionTime: "fast",
		Schema: &ToolSchema{
			Required:   []string{},
			Properties: map[string]PropertyDef{},
		},
		Tags: []string{"database", "project", "list"},
	},

	// ============================================================================
	// ANALYSIS TOOLS (5)
	// ============================================================================
	"correlate_dast_sast": {
		Name:          "correlate_dast_sast",
		Description:   "Correlaciona vulnerabilidades DAST com evidências SAST",
		Category:      "analysis",
		RiskLevel:     "low",
		RequiresHITL:  false,
		ImpactLevel:   "read-only",
		ExecutionTime: "medium",
		Schema: &ToolSchema{
			Required: []string{"project_id"},
			Properties: map[string]PropertyDef{
				"project_id": {Type: "number", Description: "ID do projeto"},
			},
		},
		Tags: []string{"correlation", "dast", "sast"},
	},
	"analyze_attack_surface": {
		Name:          "analyze_attack_surface",
		Description:   "Analisa superfície de ataque completa",
		Category:      "analysis",
		RiskLevel:     "medium",
		RequiresHITL:  false,
		ImpactLevel:   "read-only",
		ExecutionTime: "slow",
		Schema: &ToolSchema{
			Required: []string{"url"},
			Properties: map[string]PropertyDef{
				"url": {Type: "string", Description: "URL do alvo"},
			},
		},
		Tags: []string{"attack-surface", "recon"},
	},
	"analyze_system_weaknesses": {
		Name:          "analyze_system_weaknesses",
		Description:   "Meta-análise: identifica fraquezas recorrentes",
		Category:      "analysis",
		RiskLevel:     "low",
		RequiresHITL:  false,
		ImpactLevel:   "read-only",
		ExecutionTime: "fast",
		Schema: &ToolSchema{
			Required: []string{},
			Properties: map[string]PropertyDef{
				"target": {Type: "string", Description: "Alvo específico (opcional)"},
			},
		},
		Tags: []string{"meta-analysis", "weaknesses", "patterns"},
	},
	"get_maturity_score": {
		Name:          "get_maturity_score",
		Description:   "Calcula score de maturidade de segurança",
		Category:      "analysis",
		RiskLevel:     "low",
		RequiresHITL:  false,
		ImpactLevel:   "read-only",
		ExecutionTime: "fast",
		Schema: &ToolSchema{
			Required: []string{"target"},
			Properties: map[string]PropertyDef{
				"target": {Type: "string", Description: "URL ou domínio do alvo"},
			},
		},
		Tags: []string{"maturity", "score", "assessment"},
	},
	"get_coverage_gaps": {
		Name:          "get_coverage_gaps",
		Description:   "Identifica áreas não testadas",
		Category:      "analysis",
		RiskLevel:     "low",
		RequiresHITL:  false,
		ImpactLevel:   "read-only",
		ExecutionTime: "fast",
		Schema: &ToolSchema{
			Required: []string{},
			Properties: map[string]PropertyDef{
				"target": {Type: "string", Description: "Alvo específico (opcional)"},
			},
		},
		Tags: []string{"coverage", "gaps", "testing"},
	},

	// ============================================================================
	// REPORT TOOLS (3)
	// ============================================================================
	"generate_ai_report": {
		Name:          "generate_ai_report",
		Description:   "Gera relatório detalhado com análise de IA",
		Category:      "report",
		RiskLevel:     "low",
		RequiresHITL:  false,
		ImpactLevel:   "read-only",
		ExecutionTime: "slow",
		Schema: &ToolSchema{
			Required: []string{"scan_id"},
			Properties: map[string]PropertyDef{
				"scan_id": {Type: "number", Description: "ID do scan"},
				"model":   {Type: "string", Description: "Modelo Gemini", Default: "models/gemini-2.5-flash"},
			},
		},
		Tags: []string{"report", "ai", "analysis"},
	},
	"generate_pdf": {
		Name:          "generate_pdf",
		Description:   "Gera relatório em PDF",
		Category:      "report",
		RiskLevel:     "low",
		RequiresHITL:  false,
		ImpactLevel:   "read-only",
		ExecutionTime: "medium",
		Schema: &ToolSchema{
			Required: []string{"scan_id"},
			Properties: map[string]PropertyDef{
				"scan_id": {Type: "number", Description: "ID do scan"},
			},
		},
		Tags: []string{"report", "pdf", "export"},
	},
	"compare_scans": {
		Name:          "compare_scans",
		Description:   "Compara dois scans para análise de evolução",
		Category:      "report",
		RiskLevel:     "low",
		RequiresHITL:  false,
		ImpactLevel:   "read-only",
		ExecutionTime: "fast",
		Schema: &ToolSchema{
			Required: []string{"scan_id_1", "scan_id_2"},
			Properties: map[string]PropertyDef{
				"scan_id_1": {Type: "number", Description: "ID do primeiro scan"},
				"scan_id_2": {Type: "number", Description: "ID do segundo scan"},
			},
		},
		Tags: []string{"report", "comparison", "evolution"},
	},

	// ============================================================================
	// AUTOFIX TOOLS (2)
	// ============================================================================
	"generate_autofix": {
		Name:          "generate_autofix",
		Description:   "Gera correções automáticas para vulnerabilidades",
		Category:      "autofix",
		RiskLevel:     "medium",
		RequiresHITL:  false,
		ImpactLevel:   "read-only",
		ExecutionTime: "medium",
		Schema: &ToolSchema{
			Required: []string{"scan_id"},
			Properties: map[string]PropertyDef{
				"scan_id": {Type: "number", Description: "ID do scan"},
			},
		},
		Tags: []string{"autofix", "remediation"},
	},
	"create_pull_request": {
		Name:          "create_pull_request",
		Description:   "Cria Pull Request no GitHub com correções (DESTRUTIVO)",
		Category:      "autofix",
		RiskLevel:     "critical",
		RequiresHITL:  true,
		ImpactLevel:   "destructive",
		ExecutionTime: "medium",
		Schema: &ToolSchema{
			Required: []string{"repo_url", "fixes"},
			Properties: map[string]PropertyDef{
				"repo_url":    {Type: "string", Description: "URL do repositório"},
				"fixes":       {Type: "array", Description: "Lista de correções"},
				"branch_name": {Type: "string", Description: "Nome do branch", Default: "aegis-autofix"},
			},
		},
		Tags: []string{"autofix", "github", "pr", "destructive"},
	},

	// ============================================================================
	// UTILITY TOOLS (2)
	// ============================================================================
	"get_system_status": {
		Name:          "get_system_status",
		Description:   "Verifica status dos serviços",
		Category:      "utility",
		RiskLevel:     "low",
		RequiresHITL:  false,
		ImpactLevel:   "read-only",
		ExecutionTime: "fast",
		Schema: &ToolSchema{
			Required:   []string{},
			Properties: map[string]PropertyDef{},
		},
		Tags: []string{"utility", "status", "health"},
	},
	"get_dashboard_stats": {
		Name:          "get_dashboard_stats",
		Description:   "Obtém estatísticas do dashboard",
		Category:      "utility",
		RiskLevel:     "low",
		RequiresHITL:  false,
		ImpactLevel:   "read-only",
		ExecutionTime: "fast",
		Schema: &ToolSchema{
			Required:   []string{},
			Properties: map[string]PropertyDef{},
		},
		Tags: []string{"utility", "dashboard", "stats"},
	},

	// ============================================================================
	// MEMORY TOOLS (5)
	// ============================================================================
	"remember_vulnerability": {
		Name:          "remember_vulnerability",
		Description:   "Registra vulnerabilidade na memória de longo prazo",
		Category:      "memory",
		RiskLevel:     "low",
		RequiresHITL:  false,
		ImpactLevel:   "write",
		ExecutionTime: "fast",
		Schema: &ToolSchema{
			Required: []string{"type", "severity", "target", "location"},
			Properties: map[string]PropertyDef{
				"type":        {Type: "string", Description: "Tipo da vulnerabilidade"},
				"severity":    {Type: "string", Description: "Severidade", Enum: []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}},
				"target":      {Type: "string", Description: "URL ou sistema afetado"},
				"location":    {Type: "string", Description: "Localização específica"},
				"description": {Type: "string", Description: "Descrição"},
			},
		},
		Tags: []string{"memory", "learning"},
	},
	"query_memory": {
		Name:          "query_memory",
		Description:   "Consulta memória de segurança",
		Category:      "memory",
		RiskLevel:     "low",
		RequiresHITL:  false,
		ImpactLevel:   "read-only",
		ExecutionTime: "fast",
		Schema: &ToolSchema{
			Required: []string{},
			Properties: map[string]PropertyDef{
				"type":            {Type: "string", Description: "Tipo de consulta"},
				"filter_type":     {Type: "string", Description: "Filtrar por tipo"},
				"filter_severity": {Type: "string", Description: "Filtrar por severidade"},
				"filter_target":   {Type: "string", Description: "Filtrar por alvo"},
				"limit":           {Type: "number", Description: "Limite", Default: 20},
			},
		},
		Tags: []string{"memory", "query"},
	},
	"get_security_insights": {
		Name:          "get_security_insights",
		Description:   "Gera insights baseados na memória de longo prazo",
		Category:      "memory",
		RiskLevel:     "low",
		RequiresHITL:  false,
		ImpactLevel:   "read-only",
		ExecutionTime: "fast",
		Schema: &ToolSchema{
			Required:   []string{},
			Properties: map[string]PropertyDef{},
		},
		Tags: []string{"memory", "insights", "learning"},
	},
	"get_memory_stats": {
		Name:          "get_memory_stats",
		Description:   "Obtém estatísticas da memória de segurança",
		Category:      "memory",
		RiskLevel:     "low",
		RequiresHITL:  false,
		ImpactLevel:   "read-only",
		ExecutionTime: "fast",
		Schema: &ToolSchema{
			Required:   []string{},
			Properties: map[string]PropertyDef{},
		},
		Tags: []string{"memory", "stats"},
	},
	"record_learning": {
		Name:          "record_learning",
		Description:   "Registra aprendizado do sistema",
		Category:      "memory",
		RiskLevel:     "low",
		RequiresHITL:  false,
		ImpactLevel:   "write",
		ExecutionTime: "fast",
		Schema: &ToolSchema{
			Required: []string{"learning_type", "description"},
			Properties: map[string]PropertyDef{
				"learning_type": {Type: "string", Description: "Tipo", Enum: []string{"false_positive", "new_pattern", "optimization"}},
				"description":   {Type: "string", Description: "Descrição do aprendizado"},
				"context":       {Type: "string", Description: "Contexto onde ocorreu"},
				"impact":        {Type: "string", Description: "Impacto esperado"},
			},
		},
		Tags: []string{"memory", "learning", "improvement"},
	},
}

// GetToolMetadata returns metadata for a tool
func GetToolMetadata(name string) *ToolMetadata {
	if meta, ok := ToolRegistry[name]; ok {
		return &meta
	}
	return nil
}

// GetToolsByRisk returns tools filtered by risk level
func GetToolsByRisk(riskLevel string) []ToolMetadata {
	result := []ToolMetadata{}
	for _, meta := range ToolRegistry {
		if meta.RiskLevel == riskLevel {
			result = append(result, meta)
		}
	}
	return result
}

// GetHighRiskTools returns all tools that require HITL
func GetHighRiskTools() []ToolMetadata {
	result := []ToolMetadata{}
	for _, meta := range ToolRegistry {
		if meta.RequiresHITL {
			result = append(result, meta)
		}
	}
	return result
}

// ValidateToolArguments validates arguments against schema
func ValidateToolArguments(toolName string, args map[string]interface{}) []string {
	errors := []string{}

	meta := GetToolMetadata(toolName)
	if meta == nil || meta.Schema == nil {
		return errors // No schema to validate against
	}

	// Check required fields
	for _, req := range meta.Schema.Required {
		if _, ok := args[req]; !ok {
			errors = append(errors, "campo obrigatório ausente: "+req)
		}
	}

	// Validate property types and constraints
	for name, prop := range meta.Schema.Properties {
		if val, ok := args[name]; ok {
			// Type validation
			switch prop.Type {
			case "string":
				if _, ok := val.(string); !ok {
					errors = append(errors, name+" deve ser string")
				}
			case "boolean":
				if _, ok := val.(bool); !ok {
					errors = append(errors, name+" deve ser boolean")
				}
			case "number":
				if _, ok := val.(float64); !ok {
					errors = append(errors, name+" deve ser number")
				}
			}

			// Enum validation
			if len(prop.Enum) > 0 {
				if strVal, ok := val.(string); ok {
					found := false
					for _, e := range prop.Enum {
						if e == strVal {
							found = true
							break
						}
					}
					if !found {
						errors = append(errors, name+" deve ser um de: "+joinStrings(prop.Enum))
					}
				}
			}
		}
	}

	return errors
}

func joinStrings(strs []string) string {
	result := ""
	for i, s := range strs {
		if i > 0 {
			result += ", "
		}
		result += s
	}
	return result
}
