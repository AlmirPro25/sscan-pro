package orchestrator

// ============================================================================
// AEGIS CENTRAL INTELLIGENCE ORCHESTRATOR
// Tool Definitions for Gemini Function Calling
// ============================================================================

// Tool represents a callable function by the AI
type Tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Category    string      `json:"category"`
	Parameters  []Parameter `json:"parameters"`
	Returns     string      `json:"returns"`
	RiskLevel   string      `json:"risk_level"` // low, medium, high, critical
	RequiresApproval bool  `json:"requires_approval"`
}

// Parameter defines a tool parameter
type Parameter struct {
	Name        string `json:"name"`
	Type        string `json:"type"` // string, number, boolean, array, object
	Description string `json:"description"`
	Required    bool   `json:"required"`
	Default     any    `json:"default,omitempty"`
}

// GetAllTools returns all available tools for the orchestrator
func GetAllTools() []Tool {
	return []Tool{
		// ============ SCANNING TOOLS ============
		{
			Name:        "scan_website",
			Description: "Executa um scan DAST completo em um website. Detecta XSS, SQLi, vulnerabilidades de autenticação, headers de segurança, SSL/TLS, e mapeia a estrutura do site.",
			Category:    "scanning",
			Parameters: []Parameter{
				{Name: "url", Type: "string", Description: "URL do site a ser escaneado (deve começar com http:// ou https://)", Required: true},
			},
			Returns:     "Resultado completo do scan com score, vulnerabilidades, endpoints, screenshot",
			RiskLevel:   "medium",
			RequiresApproval: false,
		},
		{
			Name:        "scan_code",
			Description: "Executa um scan SAST em um diretório de código-fonte. Detecta secrets hardcoded, SQL injection, XSS, command injection, e outros padrões vulneráveis.",
			Category:    "scanning",
			Parameters: []Parameter{
				{Name: "path", Type: "string", Description: "Caminho do diretório a ser escaneado", Required: true},
			},
			Returns:     "Lista de vulnerabilidades com arquivo, linha, código e remediação",
			RiskLevel:   "low",
			RequiresApproval: false,
		},
		{
			Name:        "scan_dependencies",
			Description: "Escaneia dependências do projeto em busca de CVEs conhecidas. Suporta npm, Go, Python (pip), PHP (composer).",
			Category:    "scanning",
			Parameters: []Parameter{
				{Name: "path", Type: "string", Description: "Caminho do diretório do projeto", Required: true},
			},
			Returns:     "Lista de dependências vulneráveis com CVE, severidade e versão corrigida",
			RiskLevel:   "low",
			RequiresApproval: false,
		},
		{
			Name:        "scan_infrastructure",
			Description: "Escaneia infraestrutura: portas abertas, detecção de cloud provider, análise SSL, detecção de WAF.",
			Category:    "scanning",
			Parameters: []Parameter{
				{Name: "url", Type: "string", Description: "URL do alvo", Required: true},
			},
			Returns:     "Informações de infraestrutura, portas, SSL, cloud providers",
			RiskLevel:   "medium",
			RequiresApproval: false,
		},
		{
			Name:        "scan_subdomains",
			Description: "Enumera subdomínios e detecta riscos de subdomain takeover.",
			Category:    "scanning",
			Parameters: []Parameter{
				{Name: "url", Type: "string", Description: "URL do domínio principal", Required: true},
			},
			Returns:     "Lista de subdomínios encontrados e riscos de takeover",
			RiskLevel:   "medium",
			RequiresApproval: false,
		},
		{
			Name:        "scan_reputation",
			Description: "Verifica reputação do IP/domínio em blacklists e analisa segurança de email (SPF, DMARC).",
			Category:    "scanning",
			Parameters: []Parameter{
				{Name: "url", Type: "string", Description: "URL do alvo", Required: true},
			},
			Returns:     "Status em blacklists, geolocalização IP, configuração de email",
			RiskLevel:   "low",
			RequiresApproval: false,
		},
		{
			Name:        "scan_authenticated",
			Description: "Executa testes de segurança autenticados: login, sessão, IDOR.",
			Category:    "scanning",
			Parameters: []Parameter{
				{Name: "url", Type: "string", Description: "URL do alvo", Required: true},
				{Name: "username", Type: "string", Description: "Usuário para login", Required: true},
				{Name: "password", Type: "string", Description: "Senha para login", Required: true},
				{Name: "login_url", Type: "string", Description: "URL da página de login (opcional)", Required: false},
			},
			Returns:     "Vulnerabilidades de sessão, IDOR, páginas acessíveis",
			RiskLevel:   "high",
			RequiresApproval: true,
		},
		{
			Name:        "scan_iac",
			Description: "Analisa arquivos de Infrastructure as Code: Dockerfile, docker-compose, Kubernetes, Terraform.",
			Category:    "scanning",
			Parameters: []Parameter{
				{Name: "path", Type: "string", Description: "Caminho do diretório", Required: true},
			},
			Returns:     "Problemas de configuração em arquivos IAC",
			RiskLevel:   "low",
			RequiresApproval: false,
		},
		{
			Name:        "scan_licenses",
			Description: "Analisa licenças de dependências e detecta licenças problemáticas (GPL, AGPL).",
			Category:    "scanning",
			Parameters: []Parameter{
				{Name: "path", Type: "string", Description: "Caminho do diretório do projeto", Required: true},
			},
			Returns:     "Lista de pacotes com licenças problemáticas",
			RiskLevel:   "low",
			RequiresApproval: false,
		},
		{
			Name:        "scan_typosquatting",
			Description: "Detecta possíveis pacotes de typosquatting nas dependências.",
			Category:    "scanning",
			Parameters: []Parameter{
				{Name: "path", Type: "string", Description: "Caminho do diretório do projeto", Required: true},
			},
			Returns:     "Pacotes suspeitos similares a pacotes populares",
			RiskLevel:   "low",
			RequiresApproval: false,
		},

		// ============ BROWSER/PLAYWRIGHT TOOLS ============
		{
			Name:        "navigate_to",
			Description: "Navega para uma URL específica usando Playwright. Permite interação visual com o site.",
			Category:    "browser",
			Parameters: []Parameter{
				{Name: "url", Type: "string", Description: "URL para navegar", Required: true},
			},
			Returns:     "Status da navegação e screenshot da página",
			RiskLevel:   "low",
			RequiresApproval: false,
		},
		{
			Name:        "take_screenshot",
			Description: "Captura screenshot da página atual. Pode ser full-page ou apenas viewport.",
			Category:    "browser",
			Parameters: []Parameter{
				{Name: "full_page", Type: "boolean", Description: "Se true, captura a página inteira (scroll)", Required: false, Default: true},
			},
			Returns:     "Screenshot em base64",
			RiskLevel:   "low",
			RequiresApproval: false,
		},
		{
			Name:        "take_contextual_screenshot",
			Description: "Captura screenshot contextual completo: viewport, full-page, DOM snapshot, URL e timestamp. Ideal para análise visual com IA.",
			Category:    "browser",
			Parameters: []Parameter{
				{Name: "include_dom", Type: "boolean", Description: "Incluir snapshot do DOM HTML", Required: false, Default: true},
				{Name: "include_console", Type: "boolean", Description: "Incluir logs do console", Required: false, Default: false},
			},
			Returns:     "Objeto com viewport, full_page, dom, url, timestamp, console_logs",
			RiskLevel:   "low",
			RequiresApproval: false,
		},
		{
			Name:        "click_element",
			Description: "Clica em um elemento da página usando seletor CSS ou texto.",
			Category:    "browser",
			Parameters: []Parameter{
				{Name: "selector", Type: "string", Description: "Seletor CSS do elemento (ex: #btn-login, .submit-button)", Required: false},
				{Name: "text", Type: "string", Description: "Texto do elemento para clicar (ex: 'Login', 'Submit')", Required: false},
			},
			Returns:     "Status do clique e screenshot após ação",
			RiskLevel:   "medium",
			RequiresApproval: false,
		},
		{
			Name:        "fill_input",
			Description: "Preenche um campo de input na página.",
			Category:    "browser",
			Parameters: []Parameter{
				{Name: "selector", Type: "string", Description: "Seletor CSS do input", Required: true},
				{Name: "value", Type: "string", Description: "Valor a ser preenchido", Required: true},
			},
			Returns:     "Status do preenchimento",
			RiskLevel:   "medium",
			RequiresApproval: false,
		},
		{
			Name:        "get_page_content",
			Description: "Obtém o conteúdo HTML da página atual.",
			Category:    "browser",
			Parameters:  []Parameter{},
			Returns:     "HTML da página",
			RiskLevel:   "low",
			RequiresApproval: false,
		},
		{
			Name:        "execute_javascript",
			Description: "Executa código JavaScript na página atual.",
			Category:    "browser",
			Parameters: []Parameter{
				{Name: "code", Type: "string", Description: "Código JavaScript a executar", Required: true},
			},
			Returns:     "Resultado da execução",
			RiskLevel:   "high",
			RequiresApproval: true,
		},

		// ============ DATABASE TOOLS ============
		{
			Name:        "query_scan_history",
			Description: "Consulta histórico de scans no banco de dados.",
			Category:    "database",
			Parameters: []Parameter{
				{Name: "target", Type: "string", Description: "Filtrar por URL alvo (opcional)", Required: false},
				{Name: "limit", Type: "number", Description: "Número máximo de resultados", Required: false, Default: 20},
			},
			Returns:     "Lista de scans com ID, target, score, data",
			RiskLevel:   "low",
			RequiresApproval: false,
		},
		{
			Name:        "get_scan_details",
			Description: "Obtém detalhes completos de um scan específico.",
			Category:    "database",
			Parameters: []Parameter{
				{Name: "scan_id", Type: "number", Description: "ID do scan", Required: true},
			},
			Returns:     "Dados completos do scan incluindo vulnerabilidades e endpoints",
			RiskLevel:   "low",
			RequiresApproval: false,
		},
		{
			Name:        "get_project_data",
			Description: "Obtém dados de um projeto (SAST + DAST combinados).",
			Category:    "database",
			Parameters: []Parameter{
				{Name: "project_id", Type: "number", Description: "ID do projeto", Required: true},
			},
			Returns:     "Dados do projeto com scans SAST e DAST vinculados",
			RiskLevel:   "low",
			RequiresApproval: false,
		},
		{
			Name:        "list_projects",
			Description: "Lista todos os projetos cadastrados.",
			Category:    "database",
			Parameters:  []Parameter{},
			Returns:     "Lista de projetos com nome, path, URL",
			RiskLevel:   "low",
			RequiresApproval: false,
		},

		// ============ CORRELATION TOOLS ============
		{
			Name:        "correlate_dast_sast",
			Description: "Executa correlação entre vulnerabilidades DAST e SAST de um projeto.",
			Category:    "analysis",
			Parameters: []Parameter{
				{Name: "project_id", Type: "number", Description: "ID do projeto para correlacionar", Required: true},
			},
			Returns:     "Relatório de correlação com vulnerabilidades confirmadas e cadeias de ataque",
			RiskLevel:   "low",
			RequiresApproval: false,
		},
		{
			Name:        "analyze_attack_surface",
			Description: "Analisa a superfície de ataque completa de um alvo.",
			Category:    "analysis",
			Parameters: []Parameter{
				{Name: "url", Type: "string", Description: "URL do alvo", Required: true},
			},
			Returns:     "Mapa de superfície de ataque com endpoints, tecnologias, vetores",
			RiskLevel:   "medium",
			RequiresApproval: false,
		},

		// ============ REPORT TOOLS ============
		{
			Name:        "generate_ai_report",
			Description: "Gera relatório de segurança usando IA para um scan específico.",
			Category:    "report",
			Parameters: []Parameter{
				{Name: "scan_id", Type: "number", Description: "ID do scan", Required: true},
				{Name: "model", Type: "string", Description: "Modelo Gemini a usar", Required: false, Default: "models/gemini-2.5-flash"},
			},
			Returns:     "Relatório em Markdown com análise detalhada",
			RiskLevel:   "low",
			RequiresApproval: false,
		},
		{
			Name:        "generate_pdf",
			Description: "Gera relatório PDF de um scan.",
			Category:    "report",
			Parameters: []Parameter{
				{Name: "scan_id", Type: "number", Description: "ID do scan", Required: true},
			},
			Returns:     "URL para download do PDF",
			RiskLevel:   "low",
			RequiresApproval: false,
		},
		{
			Name:        "compare_scans",
			Description: "Compara dois scans para identificar mudanças.",
			Category:    "report",
			Parameters: []Parameter{
				{Name: "scan_id_1", Type: "number", Description: "ID do primeiro scan", Required: true},
				{Name: "scan_id_2", Type: "number", Description: "ID do segundo scan", Required: true},
			},
			Returns:     "Diferenças entre os scans (score, endpoints, vulnerabilidades)",
			RiskLevel:   "low",
			RequiresApproval: false,
		},

		// ============ AUTOFIX TOOLS ============
		{
			Name:        "generate_autofix",
			Description: "Gera sugestões de correção automática para vulnerabilidades.",
			Category:    "autofix",
			Parameters: []Parameter{
				{Name: "scan_id", Type: "number", Description: "ID do scan SAST", Required: true},
			},
			Returns:     "Lista de correções sugeridas com código",
			RiskLevel:   "low",
			RequiresApproval: false,
		},
		{
			Name:        "create_pull_request",
			Description: "Cria um Pull Request no GitHub com as correções.",
			Category:    "autofix",
			Parameters: []Parameter{
				{Name: "repo_url", Type: "string", Description: "URL do repositório GitHub", Required: true},
				{Name: "fixes", Type: "array", Description: "Lista de correções a aplicar", Required: true},
				{Name: "branch_name", Type: "string", Description: "Nome do branch", Required: false, Default: "aegis-autofix"},
			},
			Returns:     "URL do Pull Request criado",
			RiskLevel:   "high",
			RequiresApproval: true,
		},

		// ============ UTILITY TOOLS ============
		{
			Name:        "get_system_status",
			Description: "Verifica status dos serviços do sistema (backend, worker, frontend).",
			Category:    "utility",
			Parameters:  []Parameter{},
			Returns:     "Status de cada serviço",
			RiskLevel:   "low",
			RequiresApproval: false,
		},
		{
			Name:        "get_dashboard_stats",
			Description: "Obtém estatísticas do dashboard (total scans, score médio, etc).",
			Category:    "utility",
			Parameters:  []Parameter{},
			Returns:     "Estatísticas agregadas",
			RiskLevel:   "low",
			RequiresApproval: false,
		},

		// ============ META-ANALYSIS TOOLS ============
		{
			Name:        "analyze_system_weaknesses",
			Description: "Analisa padrões de vulnerabilidades recorrentes no sistema. Identifica onde o sistema mais falha e quais áreas nunca foram testadas.",
			Category:    "analysis",
			Parameters: []Parameter{
				{Name: "project_id", Type: "number", Description: "ID do projeto (opcional, analisa todos se não especificado)", Required: false},
			},
			Returns:     "Relatório de fraquezas sistêmicas, gaps de cobertura, score de maturidade",
			RiskLevel:   "low",
			RequiresApproval: false,
		},
		{
			Name:        "get_security_maturity",
			Description: "Calcula o score de maturidade de segurança do sistema baseado em cobertura de testes, vulnerabilidades e práticas.",
			Category:    "analysis",
			Parameters:  []Parameter{},
			Returns:     "Score de maturidade (0-100), nível (Initial/Developing/Defined/Managed/Optimized), recomendações",
			RiskLevel:   "low",
			RequiresApproval: false,
		},
		{
			Name:        "get_audit_logs",
			Description: "Obtém logs de auditoria das ações executadas pelo orchestrator.",
			Category:    "utility",
			Parameters: []Parameter{
				{Name: "session_id", Type: "string", Description: "ID da sessão (opcional)", Required: false},
				{Name: "limit", Type: "number", Description: "Número máximo de logs", Required: false, Default: 50},
			},
			Returns:     "Lista de ações executadas com timestamp, ferramenta, resultado",
			RiskLevel:   "low",
			RequiresApproval: false,
		},
		{
			Name:        "get_pending_approvals",
			Description: "Lista solicitações de aprovação pendentes para ferramentas de alto risco.",
			Category:    "utility",
			Parameters:  []Parameter{},
			Returns:     "Lista de aprovações pendentes com ID, ferramenta, motivo",
			RiskLevel:   "low",
			RequiresApproval: false,
		},

		// ============ MEMORY/BRAIN TOOLS ============
		{
			Name:        "remember_vulnerability",
			Description: "Registra uma vulnerabilidade na memória de longo prazo para detecção de padrões.",
			Category:    "memory",
			Parameters: []Parameter{
				{Name: "type", Type: "string", Description: "Tipo da vulnerabilidade (XSS, SQLi, etc)", Required: true},
				{Name: "severity", Type: "string", Description: "Severidade (CRITICAL, HIGH, MEDIUM, LOW)", Required: true},
				{Name: "target", Type: "string", Description: "URL ou sistema afetado", Required: true},
				{Name: "location", Type: "string", Description: "Localização específica (endpoint, arquivo:linha)", Required: true},
				{Name: "description", Type: "string", Description: "Descrição da vulnerabilidade", Required: false},
			},
			Returns:     "Confirmação do registro",
			RiskLevel:   "low",
			RequiresApproval: false,
		},
		{
			Name:        "query_memory",
			Description: "Consulta a memória de segurança para encontrar vulnerabilidades, alvos ou padrões.",
			Category:    "memory",
			Parameters: []Parameter{
				{Name: "type", Type: "string", Description: "Tipo de consulta: vulnerability, target, pattern, learning", Required: true},
				{Name: "filter_type", Type: "string", Description: "Filtrar por tipo de vulnerabilidade", Required: false},
				{Name: "filter_severity", Type: "string", Description: "Filtrar por severidade", Required: false},
				{Name: "filter_target", Type: "string", Description: "Filtrar por alvo", Required: false},
				{Name: "limit", Type: "number", Description: "Número máximo de resultados", Required: false, Default: 20},
			},
			Returns:     "Resultados da consulta",
			RiskLevel:   "low",
			RequiresApproval: false,
		},
		{
			Name:        "get_security_insights",
			Description: "Gera insights de segurança baseados na memória de longo prazo. Identifica padrões, tendências e recomendações.",
			Category:    "memory",
			Parameters:  []Parameter{},
			Returns:     "Lista de insights com título, descrição, confiança e sugestões",
			RiskLevel:   "low",
			RequiresApproval: false,
		},
		{
			Name:        "get_memory_stats",
			Description: "Retorna estatísticas da memória de segurança.",
			Category:    "memory",
			Parameters:  []Parameter{},
			Returns:     "Estatísticas: total de vulnerabilidades, alvos, padrões, learnings",
			RiskLevel:   "low",
			RequiresApproval: false,
		},
	}
}

// GetToolsByCategory returns tools filtered by category
func GetToolsByCategory(category string) []Tool {
	allTools := GetAllTools()
	filtered := []Tool{}
	for _, tool := range allTools {
		if tool.Category == category {
			filtered = append(filtered, tool)
		}
	}
	return filtered
}

// GetToolByName returns a specific tool by name
func GetToolByName(name string) *Tool {
	for _, tool := range GetAllTools() {
		if tool.Name == name {
			return &tool
		}
	}
	return nil
}

// ConvertToGeminiFunctionDeclarations converts tools to Gemini function calling format
func ConvertToGeminiFunctionDeclarations() []map[string]interface{} {
	tools := GetAllTools()
	declarations := []map[string]interface{}{}

	for _, tool := range tools {
		properties := map[string]interface{}{}
		required := []string{}

		for _, param := range tool.Parameters {
			paramDef := map[string]interface{}{
				"type":        convertType(param.Type),
				"description": param.Description,
			}
			properties[param.Name] = paramDef

			if param.Required {
				required = append(required, param.Name)
			}
		}

		declaration := map[string]interface{}{
			"name":        tool.Name,
			"description": tool.Description,
			"parameters": map[string]interface{}{
				"type":       "object",
				"properties": properties,
				"required":   required,
			},
		}

		declarations = append(declarations, declaration)
	}

	return declarations
}

func convertType(t string) string {
	switch t {
	case "number":
		return "number"
	case "boolean":
		return "boolean"
	case "array":
		return "array"
	case "object":
		return "object"
	default:
		return "string"
	}
}
