package scanner

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// CodeVulnerability represents a vulnerability found in source code
type CodeVulnerability struct {
	Type        string   `json:"type"`
	Severity    string   `json:"severity"`
	CWE         string   `json:"cwe"`
	OWASP       string   `json:"owasp"`
	File        string   `json:"file"`
	Line        int      `json:"line"`
	Code        string   `json:"code"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation"`
	Confidence  string   `json:"confidence"`
}

// CodeScanResult represents the result of a local code scan
type CodeScanResult struct {
	Path            string              `json:"path"`
	FilesScanned    int                 `json:"files_scanned"`
	LinesScanned    int                 `json:"lines_scanned"`
	Vulnerabilities []CodeVulnerability `json:"vulnerabilities"`
	Score           int                 `json:"score"`
	Summary         CodeScanSummary     `json:"summary"`
}

type CodeScanSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// SecretPattern defines a pattern for detecting secrets
type SecretPattern struct {
	Name        string
	Pattern     *regexp.Regexp
	Severity    string
	CWE         string
	Description string
	Remediation string
}

// VulnPattern defines a pattern for detecting code vulnerabilities
type VulnPattern struct {
	Name        string
	Pattern     *regexp.Regexp
	FileTypes   []string
	Severity    string
	CWE         string
	OWASP       string
	Description string
	Remediation string
}

// CodeScanner scans local code for vulnerabilities
type CodeScanner struct {
	secretPatterns []SecretPattern
	vulnPatterns   []VulnPattern
	ignoreDirs     []string
	ignoreFiles    []string
}

// NewCodeScanner creates a new code scanner with default patterns
func NewCodeScanner() *CodeScanner {
	return &CodeScanner{
		secretPatterns: getSecretPatterns(),
		vulnPatterns:   getVulnPatterns(),
		ignoreDirs:     []string{"node_modules", ".git", "vendor", "__pycache__", ".venv", "venv", "dist", "build", ".next", ".nuxt"},
		ignoreFiles:    []string{".min.js", ".min.css", ".map", ".lock"},
	}
}

func getSecretPatterns() []SecretPattern {
	return []SecretPattern{
		{
			Name:        "AWS Access Key",
			Pattern:     regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
			Severity:    "CRITICAL",
			CWE:         "CWE-798",
			Description: "AWS Access Key ID hardcoded no código",
			Remediation: "Usar variáveis de ambiente ou AWS Secrets Manager",
		},
		{
			Name:        "AWS Secret Key",
			Pattern:     regexp.MustCompile(`(?i)(aws_secret|aws_secret_key|secret_access_key)\s*[=:]\s*['"][A-Za-z0-9/+=]{40}['"]`),
			Severity:    "CRITICAL",
			CWE:         "CWE-798",
			Description: "AWS Secret Access Key hardcoded no código",
			Remediation: "Usar variáveis de ambiente ou AWS Secrets Manager",
		},
		{
			Name:        "Generic API Key",
			Pattern:     regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[=:]\s*['"][A-Za-z0-9_\-]{20,}['"]`),
			Severity:    "HIGH",
			CWE:         "CWE-798",
			Description: "API Key hardcoded no código",
			Remediation: "Usar variáveis de ambiente para armazenar API keys",
		},
		{
			Name:        "Private Key",
			Pattern:     regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
			Severity:    "CRITICAL",
			CWE:         "CWE-321",
			Description: "Chave privada exposta no código",
			Remediation: "Remover chave privada e usar gerenciador de secrets",
		},
		{
			Name:        "Database Connection String",
			Pattern:     regexp.MustCompile(`(?i)(mongodb|postgres|mysql|redis|amqp):\/\/[^\s'"]+:[^\s'"]+@[^\s'"]+`),
			Severity:    "CRITICAL",
			CWE:         "CWE-798",
			Description: "String de conexão com credenciais hardcoded",
			Remediation: "Usar variáveis de ambiente para connection strings",
		},
		{
			Name:        "JWT Secret",
			Pattern:     regexp.MustCompile(`(?i)(jwt[_-]?secret|jwt[_-]?key)\s*[=:]\s*['"][^'"]{10,}['"]`),
			Severity:    "CRITICAL",
			CWE:         "CWE-798",
			Description: "JWT Secret hardcoded no código",
			Remediation: "Usar variáveis de ambiente para JWT secrets",
		},
		{
			Name:        "Password in Code",
			Pattern:     regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[=:]\s*['"][^'"]{4,}['"]`),
			Severity:    "HIGH",
			CWE:         "CWE-798",
			Description: "Senha hardcoded no código",
			Remediation: "Usar variáveis de ambiente ou vault para senhas",
		},
		{
			Name:        "GitHub Token",
			Pattern:     regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`),
			Severity:    "CRITICAL",
			CWE:         "CWE-798",
			Description: "GitHub Personal Access Token exposto",
			Remediation: "Revogar token e usar GitHub Secrets",
		},
		{
			Name:        "Slack Token",
			Pattern:     regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`),
			Severity:    "HIGH",
			CWE:         "CWE-798",
			Description: "Slack Token exposto no código",
			Remediation: "Revogar token e usar variáveis de ambiente",
		},
		{
			Name:        "Google API Key",
			Pattern:     regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
			Severity:    "HIGH",
			CWE:         "CWE-798",
			Description: "Google API Key exposta no código",
			Remediation: "Restringir API key e usar variáveis de ambiente",
		},
	}
}


func getVulnPatterns() []VulnPattern {
	return []VulnPattern{
		// SQL Injection
		{
			Name:        "SQL Injection",
			Pattern:     regexp.MustCompile(`(?i)(execute|query|raw)\s*\(\s*['"]?\s*SELECT.*\+|fmt\.Sprintf\s*\(\s*['"]SELECT`),
			FileTypes:   []string{".go", ".py", ".js", ".ts", ".php", ".java", ".rb"},
			Severity:    "CRITICAL",
			CWE:         "CWE-89",
			OWASP:       "A03:2021 - Injection",
			Description: "Possível SQL Injection por concatenação de strings",
			Remediation: "Usar prepared statements ou ORM com parâmetros",
		},
		{
			Name:        "SQL Injection (Python)",
			Pattern:     regexp.MustCompile(`(?i)cursor\.(execute|executemany)\s*\(\s*['"].*%s|f['"]SELECT.*\{`),
			FileTypes:   []string{".py"},
			Severity:    "CRITICAL",
			CWE:         "CWE-89",
			OWASP:       "A03:2021 - Injection",
			Description: "SQL Injection via string formatting em Python",
			Remediation: "Usar parâmetros: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
		},
		// XSS
		{
			Name:        "XSS (innerHTML)",
			Pattern:     regexp.MustCompile(`\.innerHTML\s*=`),
			FileTypes:   []string{".js", ".ts", ".jsx", ".tsx"},
			Severity:    "HIGH",
			CWE:         "CWE-79",
			OWASP:       "A03:2021 - Injection",
			Description: "Uso de innerHTML pode permitir XSS",
			Remediation: "Usar textContent ou sanitizar input com DOMPurify",
		},
		{
			Name:        "XSS (document.write)",
			Pattern:     regexp.MustCompile(`document\.write\s*\(`),
			FileTypes:   []string{".js", ".ts", ".html"},
			Severity:    "HIGH",
			CWE:         "CWE-79",
			OWASP:       "A03:2021 - Injection",
			Description: "document.write pode permitir XSS",
			Remediation: "Usar métodos DOM seguros como createElement",
		},
		{
			Name:        "XSS (dangerouslySetInnerHTML)",
			Pattern:     regexp.MustCompile(`dangerouslySetInnerHTML`),
			FileTypes:   []string{".jsx", ".tsx", ".js", ".ts"},
			Severity:    "MEDIUM",
			CWE:         "CWE-79",
			OWASP:       "A03:2021 - Injection",
			Description: "dangerouslySetInnerHTML pode permitir XSS se não sanitizado",
			Remediation: "Sanitizar conteúdo com DOMPurify antes de usar",
		},
		// Command Injection
		{
			Name:        "Command Injection",
			Pattern:     regexp.MustCompile(`(?i)(exec|system|popen|subprocess\.call|os\.system|child_process\.exec)\s*\([^)]*\+`),
			FileTypes:   []string{".py", ".js", ".ts", ".php", ".rb", ".go"},
			Severity:    "CRITICAL",
			CWE:         "CWE-78",
			OWASP:       "A03:2021 - Injection",
			Description: "Possível Command Injection por concatenação",
			Remediation: "Usar arrays de argumentos e evitar shell=True",
		},
		// Path Traversal
		{
			Name:        "Path Traversal",
			Pattern:     regexp.MustCompile(`(?i)(readFile|readFileSync|open|fopen)\s*\([^)]*\+`),
			FileTypes:   []string{".js", ".ts", ".py", ".php", ".go"},
			Severity:    "HIGH",
			CWE:         "CWE-22",
			OWASP:       "A01:2021 - Broken Access Control",
			Description: "Possível Path Traversal por concatenação de path",
			Remediation: "Validar e sanitizar paths, usar path.join com validação",
		},
		// Insecure Deserialization
		{
			Name:        "Insecure Deserialization (Python)",
			Pattern:     regexp.MustCompile(`pickle\.loads?\s*\(`),
			FileTypes:   []string{".py"},
			Severity:    "HIGH",
			CWE:         "CWE-502",
			OWASP:       "A08:2021 - Software and Data Integrity Failures",
			Description: "pickle.load pode executar código arbitrário",
			Remediation: "Usar JSON ou validar origem dos dados",
		},
		{
			Name:        "Insecure Deserialization (Node)",
			Pattern:     regexp.MustCompile(`(?i)(serialize|unserialize|node-serialize)`),
			FileTypes:   []string{".js", ".ts"},
			Severity:    "HIGH",
			CWE:         "CWE-502",
			OWASP:       "A08:2021 - Software and Data Integrity Failures",
			Description: "Deserialização insegura pode executar código",
			Remediation: "Usar JSON.parse com validação de schema",
		},
		// Weak Crypto
		{
			Name:        "Weak Hash (MD5)",
			Pattern:     regexp.MustCompile(`(?i)(md5|MD5)\s*\(`),
			FileTypes:   []string{".py", ".js", ".ts", ".php", ".go", ".java"},
			Severity:    "MEDIUM",
			CWE:         "CWE-328",
			OWASP:       "A02:2021 - Cryptographic Failures",
			Description: "MD5 é considerado criptograficamente fraco",
			Remediation: "Usar SHA-256 ou bcrypt para senhas",
		},
		{
			Name:        "Weak Hash (SHA1)",
			Pattern:     regexp.MustCompile(`(?i)(sha1|SHA1)\s*\(`),
			FileTypes:   []string{".py", ".js", ".ts", ".php", ".go", ".java"},
			Severity:    "LOW",
			CWE:         "CWE-328",
			OWASP:       "A02:2021 - Cryptographic Failures",
			Description: "SHA1 é considerado fraco para segurança",
			Remediation: "Usar SHA-256 ou superior",
		},
		// Hardcoded IPs
		{
			Name:        "Hardcoded IP Address",
			Pattern:     regexp.MustCompile(`['"](\d{1,3}\.){3}\d{1,3}['"]`),
			FileTypes:   []string{".py", ".js", ".ts", ".go", ".java", ".php"},
			Severity:    "LOW",
			CWE:         "CWE-547",
			OWASP:       "A05:2021 - Security Misconfiguration",
			Description: "IP hardcoded pode dificultar manutenção",
			Remediation: "Usar variáveis de ambiente ou configuração",
		},
		// Eval
		{
			Name:        "Dangerous eval()",
			Pattern:     regexp.MustCompile(`(?i)\beval\s*\(`),
			FileTypes:   []string{".js", ".ts", ".py", ".php"},
			Severity:    "HIGH",
			CWE:         "CWE-95",
			OWASP:       "A03:2021 - Injection",
			Description: "eval() pode executar código arbitrário",
			Remediation: "Evitar eval, usar alternativas seguras",
		},
		// CORS Misconfiguration
		{
			Name:        "CORS Allow All",
			Pattern:     regexp.MustCompile(`(?i)(Access-Control-Allow-Origin|cors).*['"]\*['"]`),
			FileTypes:   []string{".js", ".ts", ".py", ".go", ".java", ".php"},
			Severity:    "MEDIUM",
			CWE:         "CWE-942",
			OWASP:       "A05:2021 - Security Misconfiguration",
			Description: "CORS configurado para aceitar qualquer origem",
			Remediation: "Restringir origens permitidas",
		},
		// Debug Mode
		{
			Name:        "Debug Mode Enabled",
			Pattern:     regexp.MustCompile(`(?i)(DEBUG|debug)\s*[=:]\s*(true|True|1|['"]true['"])`),
			FileTypes:   []string{".py", ".js", ".ts", ".env", ".json", ".yaml", ".yml"},
			Severity:    "MEDIUM",
			CWE:         "CWE-489",
			OWASP:       "A05:2021 - Security Misconfiguration",
			Description: "Debug mode habilitado pode expor informações",
			Remediation: "Desabilitar debug em produção",
		},
	}
}


// ScanDirectory scans a directory for vulnerabilities
func (cs *CodeScanner) ScanDirectory(dirPath string) (*CodeScanResult, error) {
	result := &CodeScanResult{
		Path:            dirPath,
		Vulnerabilities: []CodeVulnerability{},
	}

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip files we can't access
		}

		// Skip ignored directories
		if info.IsDir() {
			for _, ignoreDir := range cs.ignoreDirs {
				if info.Name() == ignoreDir {
					return filepath.SkipDir
				}
			}
			return nil
		}

		// Skip ignored files
		for _, ignoreFile := range cs.ignoreFiles {
			if strings.HasSuffix(path, ignoreFile) {
				return nil
			}
		}

		// Only scan code files
		ext := strings.ToLower(filepath.Ext(path))
		if !cs.isCodeFile(ext) {
			return nil
		}

		// Scan file
		vulns, lines, err := cs.scanFile(path, ext)
		if err != nil {
			return nil // Skip files we can't read
		}

		result.FilesScanned++
		result.LinesScanned += lines
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)

		return nil
	})

	if err != nil {
		return nil, err
	}

	// Calculate summary
	for _, v := range result.Vulnerabilities {
		switch v.Severity {
		case "CRITICAL":
			result.Summary.Critical++
		case "HIGH":
			result.Summary.High++
		case "MEDIUM":
			result.Summary.Medium++
		case "LOW":
			result.Summary.Low++
		default:
			result.Summary.Info++
		}
	}

	// Calculate score (100 - penalties)
	result.Score = cs.calculateScore(result.Summary)

	return result, nil
}

func (cs *CodeScanner) isCodeFile(ext string) bool {
	codeExtensions := []string{
		".go", ".py", ".js", ".ts", ".jsx", ".tsx",
		".java", ".php", ".rb", ".rs", ".c", ".cpp",
		".cs", ".swift", ".kt", ".scala", ".sh",
		".yaml", ".yml", ".json", ".xml", ".env",
		".html", ".vue", ".svelte",
	}

	for _, e := range codeExtensions {
		if ext == e {
			return true
		}
	}
	return false
}

func (cs *CodeScanner) scanFile(filePath string, ext string) ([]CodeVulnerability, int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()

	var vulns []CodeVulnerability
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Check secret patterns
		for _, pattern := range cs.secretPatterns {
			if pattern.Pattern.MatchString(line) {
				// Skip if it's a comment or example
				if cs.isCommentOrExample(line) {
					continue
				}

				vulns = append(vulns, CodeVulnerability{
					Type:        pattern.Name,
					Severity:    pattern.Severity,
					CWE:         pattern.CWE,
					OWASP:       "A07:2021 - Identification and Authentication Failures",
					File:        filePath,
					Line:        lineNum,
					Code:        cs.maskSensitive(line),
					Description: pattern.Description,
					Remediation: pattern.Remediation,
					Confidence:  "high",
				})
			}
		}

		// Check vulnerability patterns
		for _, pattern := range cs.vulnPatterns {
			// Check if file type matches
			if !cs.matchesFileType(ext, pattern.FileTypes) {
				continue
			}

			if pattern.Pattern.MatchString(line) {
				// Skip if it's a comment
				if cs.isCommentOrExample(line) {
					continue
				}

				vulns = append(vulns, CodeVulnerability{
					Type:        pattern.Name,
					Severity:    pattern.Severity,
					CWE:         pattern.CWE,
					OWASP:       pattern.OWASP,
					File:        filePath,
					Line:        lineNum,
					Code:        cs.truncateLine(line),
					Description: pattern.Description,
					Remediation: pattern.Remediation,
					Confidence:  "medium",
				})
			}
		}
	}

	return vulns, lineNum, scanner.Err()
}

func (cs *CodeScanner) matchesFileType(ext string, fileTypes []string) bool {
	for _, ft := range fileTypes {
		if ext == ft {
			return true
		}
	}
	return false
}

func (cs *CodeScanner) isCommentOrExample(line string) bool {
	trimmed := strings.TrimSpace(line)
	
	// Common comment patterns
	commentPrefixes := []string{"//", "#", "/*", "*", "<!--", "'''", `"""`}
	for _, prefix := range commentPrefixes {
		if strings.HasPrefix(trimmed, prefix) {
			return true
		}
	}

	// Example/test indicators
	exampleIndicators := []string{"example", "sample", "test", "mock", "fake", "dummy", "placeholder"}
	lowerLine := strings.ToLower(line)
	for _, indicator := range exampleIndicators {
		if strings.Contains(lowerLine, indicator) {
			return true
		}
	}

	return false
}

func (cs *CodeScanner) maskSensitive(line string) string {
	// Mask potential secrets in the output
	masked := line
	
	// Mask anything that looks like a key/token
	keyPattern := regexp.MustCompile(`['"][A-Za-z0-9_\-/+=]{20,}['"]`)
	masked = keyPattern.ReplaceAllString(masked, `"***MASKED***"`)
	
	// Mask passwords
	pwdPattern := regexp.MustCompile(`(?i)(password|passwd|pwd|secret)\s*[=:]\s*['"][^'"]+['"]`)
	masked = pwdPattern.ReplaceAllString(masked, `$1 = "***MASKED***"`)

	return cs.truncateLine(masked)
}

func (cs *CodeScanner) truncateLine(line string) string {
	if len(line) > 200 {
		return line[:200] + "..."
	}
	return line
}

func (cs *CodeScanner) calculateScore(summary CodeScanSummary) int {
	score := 100

	// Penalties
	score -= summary.Critical * 25
	score -= summary.High * 15
	score -= summary.Medium * 5
	score -= summary.Low * 2

	if score < 0 {
		score = 0
	}

	return score
}
