package autofix

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/generative-ai-go/genai"
	"google.golang.org/api/option"
)

// AutoFix represents a generated fix for a vulnerability
type AutoFix struct {
	VulnType    string
	Stack       string
	Language    string
	Framework   string
	FilePath    string
	LineNumber  int
	Patch       string
	Description string
	TestCommand string
	Confidence  string // high, medium, low
}

// StackInfo contains detected stack information
type StackInfo struct {
	WebServer  string // nginx, apache, caddy
	Backend    string // express, spring, django, laravel
	Frontend   string // react, vue, angular
	Language   string // javascript, java, python, php, go
	Framework  string // specific framework version
}

// AutoFixGenerator generates automatic fixes for vulnerabilities
type AutoFixGenerator struct {
	apiKey string
}

// NewAutoFixGenerator creates a new auto-fix generator
func NewAutoFixGenerator(apiKey string) *AutoFixGenerator {
	return &AutoFixGenerator{
		apiKey: apiKey,
	}
}

// GenerateAutoFix generates a fix for a specific vulnerability
func (g *AutoFixGenerator) GenerateAutoFix(vulnType string, stack StackInfo, codeContext string) (*AutoFix, error) {
	// Try deterministic fix first (faster, more reliable)
	if fix := g.getDeterministicFix(vulnType, stack); fix != nil {
		return fix, nil
	}
	
	// Fallback to AI-generated fix for complex cases
	return g.generateAIFix(vulnType, stack, codeContext)
}

// getDeterministicFix returns a pre-defined fix for common vulnerabilities
func (g *AutoFixGenerator) getDeterministicFix(vulnType string, stack StackInfo) *AutoFix {
	switch vulnType {
	case "HSTS Missing":
		return g.fixHSTSMissing(stack)
	case "CSP Missing":
		return g.fixCSPMissing(stack)
	case "X-Frame-Options Missing":
		return g.fixXFrameOptions(stack)
	case "X-Content-Type-Options Missing":
		return g.fixXContentTypeOptions(stack)
	default:
		return nil
	}
}

func (g *AutoFixGenerator) fixHSTSMissing(stack StackInfo) *AutoFix {
	fix := &AutoFix{
		VulnType:   "HSTS Missing",
		Stack:      stack.WebServer,
		Confidence: "high",
	}
	
	switch stack.WebServer {
	case "nginx":
		fix.FilePath = "/etc/nginx/sites-available/default"
		fix.Patch = `# Add inside server block (HTTPS only)
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;`
		fix.Description = "Adiciona header HSTS no Nginx"
		fix.TestCommand = `curl -I https://seu-site.com | grep Strict-Transport-Security`
		
	case "apache":
		fix.FilePath = "/etc/apache2/sites-available/000-default-ssl.conf"
		fix.Patch = `# Add inside <VirtualHost *:443>
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"`
		fix.Description = "Adiciona header HSTS no Apache"
		fix.TestCommand = `curl -I https://seu-site.com | grep Strict-Transport-Security`
		
	case "express", "node":
		fix.FilePath = "app.js"
		fix.Language = "javascript"
		fix.Patch = `// Install: npm install helmet
const helmet = require('helmet');

app.use(helmet.hsts({
  maxAge: 31536000,
  includeSubDomains: true,
  preload: true
}));`
		fix.Description = "Adiciona HSTS usando Helmet.js"
		fix.TestCommand = `npm install helmet && npm start`
		
	case "spring", "java":
		fix.FilePath = "src/main/java/config/SecurityConfig.java"
		fix.Language = "java"
		fix.Patch = `@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.headers()
            .httpStrictTransportSecurity()
            .maxAgeInSeconds(31536000)
            .includeSubDomains(true)
            .preload(true);
    }
}`
		fix.Description = "Adiciona HSTS no Spring Security"
		fix.TestCommand = `mvn spring-boot:run`
		
	case "django", "python":
		fix.FilePath = "settings.py"
		fix.Language = "python"
		fix.Patch = `# Add to settings.py
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True`
		fix.Description = "Adiciona HSTS no Django"
		fix.TestCommand = `python manage.py runserver`
		
	default:
		fix.Patch = `# Generic HSTS header
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
		fix.Description = "Header HSTS genérico"
		fix.Confidence = "medium"
	}
	
	return fix
}

func (g *AutoFixGenerator) fixCSPMissing(stack StackInfo) *AutoFix {
	fix := &AutoFix{
		VulnType:   "CSP Missing",
		Stack:      stack.WebServer,
		Confidence: "high",
	}
	
	switch stack.WebServer {
	case "nginx":
		fix.FilePath = "/etc/nginx/sites-available/default"
		fix.Patch = `# Add inside server block
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" always;`
		fix.Description = "Adiciona CSP básico no Nginx"
		fix.TestCommand = `curl -I https://seu-site.com | grep Content-Security-Policy`
		
	case "apache":
		fix.FilePath = "/etc/apache2/sites-available/000-default.conf"
		fix.Patch = `# Add inside <VirtualHost>
Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"`
		fix.Description = "Adiciona CSP básico no Apache"
		fix.TestCommand = `curl -I https://seu-site.com | grep Content-Security-Policy`
		
	case "express", "node":
		fix.FilePath = "app.js"
		fix.Language = "javascript"
		fix.Patch = `// Install: npm install helmet
const helmet = require('helmet');

app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "data:", "https:"],
  }
}));`
		fix.Description = "Adiciona CSP usando Helmet.js"
		fix.TestCommand = `npm install helmet && npm start`
		
	case "spring", "java":
		fix.FilePath = "src/main/java/config/SecurityConfig.java"
		fix.Language = "java"
		fix.Patch = `@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.headers()
            .contentSecurityPolicy("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'");
    }
}`
		fix.Description = "Adiciona CSP no Spring Security"
		fix.TestCommand = `mvn spring-boot:run`
		
	default:
		fix.Patch = `# Generic CSP header
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';`
		fix.Description = "Header CSP genérico"
		fix.Confidence = "medium"
	}
	
	return fix
}

func (g *AutoFixGenerator) fixXFrameOptions(stack StackInfo) *AutoFix {
	fix := &AutoFix{
		VulnType:   "X-Frame-Options Missing",
		Stack:      stack.WebServer,
		Confidence: "high",
	}
	
	switch stack.WebServer {
	case "nginx":
		fix.FilePath = "/etc/nginx/sites-available/default"
		fix.Patch = `# Add inside server block
add_header X-Frame-Options "SAMEORIGIN" always;`
		fix.Description = "Adiciona X-Frame-Options no Nginx"
		fix.TestCommand = `curl -I https://seu-site.com | grep X-Frame-Options`
		
	case "apache":
		fix.FilePath = "/etc/apache2/sites-available/000-default.conf"
		fix.Patch = `# Add inside <VirtualHost>
Header always set X-Frame-Options "SAMEORIGIN"`
		fix.Description = "Adiciona X-Frame-Options no Apache"
		fix.TestCommand = `curl -I https://seu-site.com | grep X-Frame-Options`
		
	case "express", "node":
		fix.FilePath = "app.js"
		fix.Language = "javascript"
		fix.Patch = `// Install: npm install helmet
const helmet = require('helmet');

app.use(helmet.frameguard({ action: 'sameorigin' }));`
		fix.Description = "Adiciona X-Frame-Options usando Helmet.js"
		fix.TestCommand = `npm install helmet && npm start`
		
	default:
		fix.Patch = `# Generic X-Frame-Options header
X-Frame-Options: SAMEORIGIN`
		fix.Description = "Header X-Frame-Options genérico"
		fix.Confidence = "medium"
	}
	
	return fix
}

func (g *AutoFixGenerator) fixXContentTypeOptions(stack StackInfo) *AutoFix {
	fix := &AutoFix{
		VulnType:   "X-Content-Type-Options Missing",
		Stack:      stack.WebServer,
		Confidence: "high",
	}
	
	switch stack.WebServer {
	case "nginx":
		fix.FilePath = "/etc/nginx/sites-available/default"
		fix.Patch = `# Add inside server block
add_header X-Content-Type-Options "nosniff" always;`
		fix.Description = "Adiciona X-Content-Type-Options no Nginx"
		fix.TestCommand = `curl -I https://seu-site.com | grep X-Content-Type-Options`
		
	case "apache":
		fix.FilePath = "/etc/apache2/sites-available/000-default.conf"
		fix.Patch = `# Add inside <VirtualHost>
Header always set X-Content-Type-Options "nosniff"`
		fix.Description = "Adiciona X-Content-Type-Options no Apache"
		fix.TestCommand = `curl -I https://seu-site.com | grep X-Content-Type-Options`
		
	case "express", "node":
		fix.FilePath = "app.js"
		fix.Language = "javascript"
		fix.Patch = `// Install: npm install helmet
const helmet = require('helmet');

app.use(helmet.noSniff());`
		fix.Description = "Adiciona X-Content-Type-Options usando Helmet.js"
		fix.TestCommand = `npm install helmet && npm start`
		
	default:
		fix.Patch = `# Generic X-Content-Type-Options header
X-Content-Type-Options: nosniff`
		fix.Description = "Header X-Content-Type-Options genérico"
		fix.Confidence = "medium"
	}
	
	return fix
}

// generateAIFix uses AI to generate a fix for complex vulnerabilities
func (g *AutoFixGenerator) generateAIFix(vulnType string, stack StackInfo, codeContext string) (*AutoFix, error) {
	ctx := context.Background()
	client, err := genai.NewClient(ctx, option.WithAPIKey(g.apiKey))
	if err != nil {
		return nil, err
	}
	defer client.Close()
	
	prompt := g.buildAIFixPrompt(vulnType, stack, codeContext)
	
	model := client.GenerativeModel("gemini-1.5-flash-latest")
	model.SetTemperature(0.2) // Low temperature for deterministic output
	
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
	
	return g.parseAIFixResponse(responseText, vulnType, stack)
}

func (g *AutoFixGenerator) buildAIFixPrompt(vulnType string, stack StackInfo, codeContext string) string {
	return fmt.Sprintf(`
Você é um Security Engineer especializado em correção de vulnerabilidades.

**TAREFA**: Gerar patch de código para corrigir a vulnerabilidade.

**Vulnerabilidade**: %s
**Stack**: %s
**Backend**: %s
**Language**: %s

**Contexto do Código**:
%s

**INSTRUÇÕES**:
1. Gere código COPIÁVEL e FUNCIONAL
2. Use best practices da stack detectada
3. Inclua comentários explicativos
4. Forneça comando de teste
5. Seja específico para a stack (não genérico)

**FORMATO DE RESPOSTA**:
### FILE: [caminho do arquivo]
### PATCH:
[código aqui]

### DESCRIPTION:
[descrição breve]

### TEST:
[comando de teste]

**IMPORTANTE**: Código deve ser production-ready, não exemplo didático.
`, vulnType, stack.WebServer, stack.Backend, stack.Language, codeContext)
}

func (g *AutoFixGenerator) parseAIFixResponse(response string, vulnType string, stack StackInfo) (*AutoFix, error) {
	fix := &AutoFix{
		VulnType:   vulnType,
		Stack:      stack.WebServer,
		Language:   stack.Language,
		Confidence: "medium",
	}
	
	// Simple parsing - extract sections
	lines := strings.Split(response, "\n")
	currentSection := ""
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		if strings.HasPrefix(line, "### FILE:") {
			fix.FilePath = strings.TrimSpace(strings.TrimPrefix(line, "### FILE:"))
		} else if strings.HasPrefix(line, "### PATCH:") {
			currentSection = "patch"
		} else if strings.HasPrefix(line, "### DESCRIPTION:") {
			currentSection = "description"
		} else if strings.HasPrefix(line, "### TEST:") {
			currentSection = "test"
		} else if line != "" && !strings.HasPrefix(line, "###") {
			switch currentSection {
			case "patch":
				fix.Patch += line + "\n"
			case "description":
				fix.Description += line + " "
			case "test":
				fix.TestCommand += line + " "
			}
		}
	}
	
	fix.Patch = strings.TrimSpace(fix.Patch)
	fix.Description = strings.TrimSpace(fix.Description)
	fix.TestCommand = strings.TrimSpace(fix.TestCommand)
	
	return fix, nil
}

// DetectStack detects the technology stack from scan metadata
func DetectStack(metadata map[string]interface{}) StackInfo {
	stack := StackInfo{}
	
	// Detect from tech field
	if tech, ok := metadata["tech"].(map[string]interface{}); ok {
		if server, ok := tech["server"].(string); ok {
			stack.WebServer = strings.ToLower(server)
		}
		if framework, ok := tech["framework"].(string); ok {
			stack.Framework = framework
			
			// Infer backend from framework
			if strings.Contains(strings.ToLower(framework), "express") {
				stack.Backend = "express"
				stack.Language = "javascript"
			} else if strings.Contains(strings.ToLower(framework), "spring") {
				stack.Backend = "spring"
				stack.Language = "java"
			} else if strings.Contains(strings.ToLower(framework), "django") {
				stack.Backend = "django"
				stack.Language = "python"
			} else if strings.Contains(strings.ToLower(framework), "laravel") {
				stack.Backend = "laravel"
				stack.Language = "php"
			}
		}
	}
	
	// Detect from schema (technologies detected)
	if schema, ok := metadata["schema"].([]interface{}); ok {
		for _, tech := range schema {
			techStr := strings.ToLower(fmt.Sprintf("%v", tech))
			
			if strings.Contains(techStr, "nginx") {
				stack.WebServer = "nginx"
			} else if strings.Contains(techStr, "apache") {
				stack.WebServer = "apache"
			} else if strings.Contains(techStr, "express") {
				stack.Backend = "express"
				stack.Language = "javascript"
			} else if strings.Contains(techStr, "react") {
				stack.Frontend = "react"
			} else if strings.Contains(techStr, "vue") {
				stack.Frontend = "vue"
			} else if strings.Contains(techStr, "angular") {
				stack.Frontend = "angular"
			}
		}
	}
	
	// Default to nginx if no web server detected
	if stack.WebServer == "" {
		stack.WebServer = "nginx"
	}
	
	return stack
}
