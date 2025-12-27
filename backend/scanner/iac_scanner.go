package scanner

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// IACVulnerability represents a vulnerability in Infrastructure as Code
type IACVulnerability struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Code        string `json:"code"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
	CWE         string `json:"cwe"`
	Resource    string `json:"resource"` // docker, kubernetes, terraform, etc
}

// IACScanResult represents the result of IAC scanning
type IACScanResult struct {
	FilesScanned    int                `json:"files_scanned"`
	Vulnerabilities []IACVulnerability `json:"vulnerabilities"`
	Summary         IACSummary         `json:"summary"`
	Resources       IACResources       `json:"resources"`
}

type IACSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

type IACResources struct {
	Dockerfiles       int `json:"dockerfiles"`
	DockerComposeFiles int `json:"docker_compose_files"`
	KubernetesFiles   int `json:"kubernetes_files"`
	TerraformFiles    int `json:"terraform_files"`
	CloudFormation    int `json:"cloudformation_files"`
}

// IACPattern defines a pattern for detecting IAC vulnerabilities
type IACPattern struct {
	Name        string
	Pattern     *regexp.Regexp
	FileTypes   []string
	Severity    string
	CWE         string
	Description string
	Remediation string
	Resource    string
}

// IACScanner scans Infrastructure as Code files
type IACScanner struct {
	patterns   []IACPattern
	ignoreDirs []string
}

// NewIACScanner creates a new IAC scanner
func NewIACScanner() *IACScanner {
	return &IACScanner{
		patterns:   getIACPatterns(),
		ignoreDirs: []string{"node_modules", ".git", "vendor", "__pycache__", ".terraform"},
	}
}

func getIACPatterns() []IACPattern {
	return []IACPattern{
		// ============ DOCKERFILE PATTERNS ============
		{
			Name:        "Docker: Running as Root",
			Pattern:     regexp.MustCompile(`(?i)^USER\s+root\s*$`),
			FileTypes:   []string{"Dockerfile", "dockerfile", ".dockerfile"},
			Severity:    "HIGH",
			CWE:         "CWE-250",
			Description: "Container rodando como root aumenta superfície de ataque",
			Remediation: "Adicione 'USER nonroot' ou crie usuário não-privilegiado",
			Resource:    "docker",
		},
		{
			Name:        "Docker: No USER Instruction",
			Pattern:     regexp.MustCompile(`^FROM\s+`),
			FileTypes:   []string{"Dockerfile", "dockerfile", ".dockerfile"},
			Severity:    "MEDIUM",
			CWE:         "CWE-250",
			Description: "Dockerfile sem instrução USER roda como root por padrão",
			Remediation: "Adicione 'USER <username>' após instalar dependências",
			Resource:    "docker",
		},
		{
			Name:        "Docker: Latest Tag",
			Pattern:     regexp.MustCompile(`(?i)^FROM\s+\S+:latest`),
			FileTypes:   []string{"Dockerfile", "dockerfile", ".dockerfile"},
			Severity:    "MEDIUM",
			CWE:         "CWE-1104",
			Description: "Uso de tag 'latest' pode causar builds não reproduzíveis",
			Remediation: "Use tags específicas de versão (ex: node:18.19.0-alpine)",
			Resource:    "docker",
		},
		{
			Name:        "Docker: ADD Instead of COPY",
			Pattern:     regexp.MustCompile(`(?i)^ADD\s+(?!https?://)`),
			FileTypes:   []string{"Dockerfile", "dockerfile", ".dockerfile"},
			Severity:    "LOW",
			CWE:         "CWE-829",
			Description: "ADD tem comportamento imprevisível, COPY é mais seguro",
			Remediation: "Use COPY ao invés de ADD para arquivos locais",
			Resource:    "docker",
		},
		{
			Name:        "Docker: Exposed Secrets in ENV",
			Pattern:     regexp.MustCompile(`(?i)^ENV\s+.*(PASSWORD|SECRET|KEY|TOKEN|CREDENTIAL)\s*=`),
			FileTypes:   []string{"Dockerfile", "dockerfile", ".dockerfile"},
			Severity:    "CRITICAL",
			CWE:         "CWE-798",
			Description: "Secrets hardcoded em ENV ficam visíveis na imagem",
			Remediation: "Use Docker secrets ou variáveis em runtime",
			Resource:    "docker",
		},
		{
			Name:        "Docker: Privileged Port",
			Pattern:     regexp.MustCompile(`(?i)^EXPOSE\s+(2[0-2]|[0-9]|[1-9][0-9]|1[0-9]{2}|10[0-2][0-3])\s*$`),
			FileTypes:   []string{"Dockerfile", "dockerfile", ".dockerfile"},
			Severity:    "MEDIUM",
			CWE:         "CWE-269",
			Description: "Portas privilegiadas (<1024) requerem root",
			Remediation: "Use portas não-privilegiadas (>1024)",
			Resource:    "docker",
		},
		{
			Name:        "Docker: HEALTHCHECK Missing",
			Pattern:     regexp.MustCompile(`^FROM\s+`),
			FileTypes:   []string{"Dockerfile", "dockerfile", ".dockerfile"},
			Severity:    "LOW",
			CWE:         "CWE-693",
			Description: "Sem HEALTHCHECK, orquestradores não detectam falhas",
			Remediation: "Adicione HEALTHCHECK CMD para monitoramento",
			Resource:    "docker",
		},

		// ============ DOCKER-COMPOSE PATTERNS ============
		{
			Name:        "Compose: Privileged Container",
			Pattern:     regexp.MustCompile(`(?i)privileged:\s*true`),
			FileTypes:   []string{"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"},
			Severity:    "CRITICAL",
			CWE:         "CWE-250",
			Description: "Container privilegiado tem acesso total ao host",
			Remediation: "Remova 'privileged: true' e use capabilities específicas",
			Resource:    "docker-compose",
		},
		{
			Name:        "Compose: Host Network Mode",
			Pattern:     regexp.MustCompile(`(?i)network_mode:\s*["']?host["']?`),
			FileTypes:   []string{"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"},
			Severity:    "HIGH",
			CWE:         "CWE-668",
			Description: "network_mode: host expõe todas as portas do container",
			Remediation: "Use redes bridge isoladas",
			Resource:    "docker-compose",
		},
		{
			Name:        "Compose: Exposed Database Port",
			Pattern:     regexp.MustCompile(`(?i)ports:\s*\n\s*-\s*["']?(3306|5432|27017|6379|9200|1433)["']?`),
			FileTypes:   []string{"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"},
			Severity:    "HIGH",
			CWE:         "CWE-668",
			Description: "Porta de banco de dados exposta publicamente",
			Remediation: "Use '127.0.0.1:PORT:PORT' ou remova exposição externa",
			Resource:    "docker-compose",
		},
		{
			Name:        "Compose: Hardcoded Password",
			Pattern:     regexp.MustCompile(`(?i)(MYSQL_ROOT_PASSWORD|POSTGRES_PASSWORD|MONGO_INITDB_ROOT_PASSWORD|REDIS_PASSWORD):\s*["']?[^$\s]+["']?`),
			FileTypes:   []string{"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"},
			Severity:    "CRITICAL",
			CWE:         "CWE-798",
			Description: "Senha de banco de dados hardcoded no compose",
			Remediation: "Use variáveis de ambiente ou Docker secrets",
			Resource:    "docker-compose",
		},
		{
			Name:        "Compose: No Resource Limits",
			Pattern:     regexp.MustCompile(`(?i)services:\s*\n\s+\w+:`),
			FileTypes:   []string{"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"},
			Severity:    "MEDIUM",
			CWE:         "CWE-770",
			Description: "Sem limites de recursos, container pode consumir todo o host",
			Remediation: "Adicione 'deploy.resources.limits' para CPU e memória",
			Resource:    "docker-compose",
		},
		{
			Name:        "Compose: Volume Mount Root",
			Pattern:     regexp.MustCompile(`(?i)volumes:\s*\n\s*-\s*["']?/["']?:`),
			FileTypes:   []string{"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"},
			Severity:    "CRITICAL",
			CWE:         "CWE-552",
			Description: "Montagem do diretório raiz do host no container",
			Remediation: "Monte apenas diretórios específicos necessários",
			Resource:    "docker-compose",
		},

		// ============ KUBERNETES PATTERNS ============
		{
			Name:        "K8s: Privileged Container",
			Pattern:     regexp.MustCompile(`(?i)privileged:\s*true`),
			FileTypes:   []string{".yaml", ".yml"},
			Severity:    "CRITICAL",
			CWE:         "CWE-250",
			Description: "Pod privilegiado pode escapar do container",
			Remediation: "Remova 'privileged: true' do securityContext",
			Resource:    "kubernetes",
		},
		{
			Name:        "K8s: Run as Root",
			Pattern:     regexp.MustCompile(`(?i)runAsUser:\s*0`),
			FileTypes:   []string{".yaml", ".yml"},
			Severity:    "HIGH",
			CWE:         "CWE-250",
			Description: "Container rodando como root (UID 0)",
			Remediation: "Use 'runAsUser: 1000' ou superior",
			Resource:    "kubernetes",
		},
		{
			Name:        "K8s: Allow Privilege Escalation",
			Pattern:     regexp.MustCompile(`(?i)allowPrivilegeEscalation:\s*true`),
			FileTypes:   []string{".yaml", ".yml"},
			Severity:    "HIGH",
			CWE:         "CWE-269",
			Description: "Permite escalação de privilégios no container",
			Remediation: "Defina 'allowPrivilegeEscalation: false'",
			Resource:    "kubernetes",
		},
		{
			Name:        "K8s: Host PID Namespace",
			Pattern:     regexp.MustCompile(`(?i)hostPID:\s*true`),
			FileTypes:   []string{".yaml", ".yml"},
			Severity:    "HIGH",
			CWE:         "CWE-668",
			Description: "Compartilha namespace PID com o host",
			Remediation: "Remova 'hostPID: true'",
			Resource:    "kubernetes",
		},
		{
			Name:        "K8s: Host Network",
			Pattern:     regexp.MustCompile(`(?i)hostNetwork:\s*true`),
			FileTypes:   []string{".yaml", ".yml"},
			Severity:    "HIGH",
			CWE:         "CWE-668",
			Description: "Pod usa rede do host, expondo serviços",
			Remediation: "Remova 'hostNetwork: true'",
			Resource:    "kubernetes",
		},
		{
			Name:        "K8s: Secret in Env",
			Pattern:     regexp.MustCompile(`(?i)env:\s*\n\s*-\s*name:.*\n\s*value:\s*["']?[A-Za-z0-9+/=]{20,}["']?`),
			FileTypes:   []string{".yaml", ".yml"},
			Severity:    "HIGH",
			CWE:         "CWE-798",
			Description: "Secret hardcoded em variável de ambiente",
			Remediation: "Use secretKeyRef para referenciar Secrets",
			Resource:    "kubernetes",
		},
		{
			Name:        "K8s: No Resource Limits",
			Pattern:     regexp.MustCompile(`(?i)containers:\s*\n\s*-\s*name:`),
			FileTypes:   []string{".yaml", ".yml"},
			Severity:    "MEDIUM",
			CWE:         "CWE-770",
			Description: "Container sem limites de recursos definidos",
			Remediation: "Adicione 'resources.limits' para CPU e memória",
			Resource:    "kubernetes",
		},
		{
			Name:        "K8s: Default Service Account",
			Pattern:     regexp.MustCompile(`(?i)serviceAccountName:\s*["']?default["']?`),
			FileTypes:   []string{".yaml", ".yml"},
			Severity:    "MEDIUM",
			CWE:         "CWE-269",
			Description: "Uso da service account padrão",
			Remediation: "Crie service account específica com permissões mínimas",
			Resource:    "kubernetes",
		},

		// ============ TERRAFORM PATTERNS ============
		{
			Name:        "Terraform: Public S3 Bucket",
			Pattern:     regexp.MustCompile(`(?i)acl\s*=\s*["']public-read["']`),
			FileTypes:   []string{".tf"},
			Severity:    "CRITICAL",
			CWE:         "CWE-732",
			Description: "S3 bucket configurado como público",
			Remediation: "Use 'acl = \"private\"' e configure bucket policies",
			Resource:    "terraform",
		},
		{
			Name:        "Terraform: Unencrypted S3",
			Pattern:     regexp.MustCompile(`(?i)resource\s*["']aws_s3_bucket["']`),
			FileTypes:   []string{".tf"},
			Severity:    "MEDIUM",
			CWE:         "CWE-311",
			Description: "S3 bucket pode estar sem criptografia",
			Remediation: "Adicione aws_s3_bucket_server_side_encryption_configuration",
			Resource:    "terraform",
		},
		{
			Name:        "Terraform: Open Security Group",
			Pattern:     regexp.MustCompile(`(?i)cidr_blocks\s*=\s*\[\s*["']0\.0\.0\.0/0["']\s*\]`),
			FileTypes:   []string{".tf"},
			Severity:    "HIGH",
			CWE:         "CWE-284",
			Description: "Security group aberto para toda internet",
			Remediation: "Restrinja CIDR blocks para IPs específicos",
			Resource:    "terraform",
		},
		{
			Name:        "Terraform: Hardcoded Secret",
			Pattern:     regexp.MustCompile(`(?i)(password|secret|key|token)\s*=\s*["'][^${"']+["']`),
			FileTypes:   []string{".tf"},
			Severity:    "CRITICAL",
			CWE:         "CWE-798",
			Description: "Secret hardcoded em arquivo Terraform",
			Remediation: "Use variáveis ou AWS Secrets Manager",
			Resource:    "terraform",
		},
		{
			Name:        "Terraform: Unencrypted RDS",
			Pattern:     regexp.MustCompile(`(?i)storage_encrypted\s*=\s*false`),
			FileTypes:   []string{".tf"},
			Severity:    "HIGH",
			CWE:         "CWE-311",
			Description: "RDS sem criptografia de storage",
			Remediation: "Defina 'storage_encrypted = true'",
			Resource:    "terraform",
		},
		{
			Name:        "Terraform: Public RDS",
			Pattern:     regexp.MustCompile(`(?i)publicly_accessible\s*=\s*true`),
			FileTypes:   []string{".tf"},
			Severity:    "CRITICAL",
			CWE:         "CWE-668",
			Description: "RDS acessível publicamente",
			Remediation: "Defina 'publicly_accessible = false'",
			Resource:    "terraform",
		},
	}
}

// ScanDirectory scans a directory for IAC vulnerabilities
func (is *IACScanner) ScanDirectory(dirPath string) (*IACScanResult, error) {
	result := &IACScanResult{
		Vulnerabilities: []IACVulnerability{},
	}

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		// Skip ignored directories
		if info.IsDir() {
			for _, ignoreDir := range is.ignoreDirs {
				if info.Name() == ignoreDir {
					return filepath.SkipDir
				}
			}
			return nil
		}

		// Check if it's an IAC file
		fileName := info.Name()
		if is.isIACFile(fileName) {
			vulns, resource := is.scanFile(path, fileName)
			result.FilesScanned++
			result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
			is.updateResources(&result.Resources, resource)
		}

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
		}
	}

	// Post-process: Check for missing patterns (like no USER in Dockerfile)
	is.checkMissingPatterns(dirPath, result)

	return result, nil
}

func (is *IACScanner) isIACFile(fileName string) bool {
	iacFiles := []string{
		"Dockerfile", "dockerfile",
		"docker-compose.yml", "docker-compose.yaml",
		"compose.yml", "compose.yaml",
		".tf", ".tfvars",
		"deployment.yaml", "deployment.yml",
		"service.yaml", "service.yml",
		"pod.yaml", "pod.yml",
		"configmap.yaml", "configmap.yml",
		"secret.yaml", "secret.yml",
		"ingress.yaml", "ingress.yml",
	}

	for _, iac := range iacFiles {
		if strings.HasSuffix(fileName, iac) || fileName == iac {
			return true
		}
	}

	// Check for Kubernetes files by content pattern
	if strings.HasSuffix(fileName, ".yaml") || strings.HasSuffix(fileName, ".yml") {
		return true // Will be filtered by pattern matching
	}

	return false
}

func (is *IACScanner) scanFile(filePath, fileName string) ([]IACVulnerability, string) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, ""
	}
	defer file.Close()

	var vulns []IACVulnerability
	var resource string
	scanner := bufio.NewScanner(file)
	lineNum := 0

	// Determine resource type
	if strings.Contains(fileName, "Dockerfile") || strings.HasSuffix(fileName, ".dockerfile") {
		resource = "docker"
	} else if strings.Contains(fileName, "compose") {
		resource = "docker-compose"
	} else if strings.HasSuffix(fileName, ".tf") {
		resource = "terraform"
	}

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for _, pattern := range is.patterns {
			// Check if pattern applies to this file type
			if !is.matchesFileType(fileName, pattern.FileTypes) {
				continue
			}

			if pattern.Pattern.MatchString(line) {
				// For Kubernetes, verify it's actually a K8s file
				if pattern.Resource == "kubernetes" && resource == "" {
					// Check if file contains K8s markers
					if !is.isKubernetesFile(filePath) {
						continue
					}
					resource = "kubernetes"
				}

				vulns = append(vulns, IACVulnerability{
					Type:        pattern.Name,
					Severity:    pattern.Severity,
					File:        filePath,
					Line:        lineNum,
					Code:        is.truncateLine(line),
					Description: pattern.Description,
					Remediation: pattern.Remediation,
					CWE:         pattern.CWE,
					Resource:    pattern.Resource,
				})
			}
		}
	}

	return vulns, resource
}

func (is *IACScanner) matchesFileType(fileName string, fileTypes []string) bool {
	for _, ft := range fileTypes {
		if strings.HasSuffix(fileName, ft) || fileName == ft {
			return true
		}
	}
	return false
}

func (is *IACScanner) isKubernetesFile(filePath string) bool {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return false
	}

	content := string(data)
	k8sMarkers := []string{
		"apiVersion:",
		"kind: Deployment",
		"kind: Service",
		"kind: Pod",
		"kind: ConfigMap",
		"kind: Secret",
		"kind: Ingress",
		"kind: StatefulSet",
		"kind: DaemonSet",
	}

	for _, marker := range k8sMarkers {
		if strings.Contains(content, marker) {
			return true
		}
	}

	return false
}

func (is *IACScanner) checkMissingPatterns(dirPath string, result *IACScanResult) {
	// Check Dockerfiles for missing USER instruction
	filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		if strings.Contains(info.Name(), "Dockerfile") {
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}

			content := string(data)
			hasFrom := strings.Contains(content, "FROM ")
			hasUser := regexp.MustCompile(`(?i)^USER\s+`).MatchString(content)

			if hasFrom && !hasUser {
				result.Vulnerabilities = append(result.Vulnerabilities, IACVulnerability{
					Type:        "Docker: No USER Instruction",
					Severity:    "MEDIUM",
					File:        path,
					Line:        0,
					Code:        "(arquivo inteiro)",
					Description: "Dockerfile sem instrução USER roda como root por padrão",
					Remediation: "Adicione 'USER <username>' após instalar dependências",
					CWE:         "CWE-250",
					Resource:    "docker",
				})
				result.Summary.Medium++
			}

			// Check for HEALTHCHECK
			hasHealthcheck := strings.Contains(content, "HEALTHCHECK")
			if hasFrom && !hasHealthcheck {
				result.Vulnerabilities = append(result.Vulnerabilities, IACVulnerability{
					Type:        "Docker: No HEALTHCHECK",
					Severity:    "LOW",
					File:        path,
					Line:        0,
					Code:        "(arquivo inteiro)",
					Description: "Dockerfile sem HEALTHCHECK dificulta monitoramento",
					Remediation: "Adicione 'HEALTHCHECK CMD curl -f http://localhost/ || exit 1'",
					CWE:         "CWE-693",
					Resource:    "docker",
				})
				result.Summary.Low++
			}
		}

		return nil
	})
}

func (is *IACScanner) updateResources(resources *IACResources, resource string) {
	switch resource {
	case "docker":
		resources.Dockerfiles++
	case "docker-compose":
		resources.DockerComposeFiles++
	case "kubernetes":
		resources.KubernetesFiles++
	case "terraform":
		resources.TerraformFiles++
	}
}

func (is *IACScanner) truncateLine(line string) string {
	line = strings.TrimSpace(line)
	if len(line) > 150 {
		return line[:150] + "..."
	}
	return line
}
