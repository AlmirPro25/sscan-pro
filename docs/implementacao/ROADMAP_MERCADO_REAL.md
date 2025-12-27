# 🚀 ROADMAP: AEGISSCAN ENTERPRISE - NÍVEL MERCADO REAL

**Data**: 27 de Dezembro de 2025  
**Versão Atual**: 4.0 (MVP Funcional)  
**Objetivo**: Evolução para produto comercial enterprise

---

## 📊 STATUS ATUAL

### ✅ O Que Já Temos (MVP v4.0)
- Sistema completo rodando localmente
- Backend Go robusto com rate limiting
- Worker Node.js com Playwright
- Frontend responsivo
- AI Reports com Gemini (qualidade 10/10)
- Chat interativo contextual
- PDF export
- Dashboard com estatísticas
- Banco SQLite com persistência
- Relatórios com 9 seções obrigatórias (Compliance, Roadmap, Methodology, Disclaimer)

### 🎯 Score Atual: MVP Funcional (Prova de Conceito)

---

## 🎯 ROADMAP: 6 FASES PARA MERCADO REAL

---

## 1️⃣ FASE 1: AUTENTICAÇÃO E AUTORIZAÇÃO ENTERPRISE

**Objetivo**: Transformar de ferramenta local para SaaS multi-tenant

### 1.1 Autenticação JWT
```go
// backend/auth/jwt.go
type JWTClaims struct {
    UserID       string   `json:"user_id"`
    Email        string   `json:"email"`
    Role         string   `json:"role"` // admin, analyst, viewer
    Permissions  []string `json:"permissions"`
    TenantID     string   `json:"tenant_id"` // Multi-tenant
    jwt.StandardClaims
}

func GenerateToken(user User) (string, error) {
    claims := JWTClaims{
        UserID:   user.ID,
        Email:    user.Email,
        Role:     user.Role,
        TenantID: user.TenantID,
        StandardClaims: jwt.StandardClaims{
            ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
            Issuer:    "aegis-enterprise",
        },
    }
    
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString([]byte(os.Getenv("JWT_SECRET")))
}
```

### 1.2 RBAC (Role-Based Access Control)
```go
// backend/auth/rbac.go
type Permission string

const (
    PermissionScanCreate    Permission = "scan:create"
    PermissionScanRead      Permission = "scan:read"
    PermissionScanDelete    Permission = "scan:delete"
    PermissionReportGenerate Permission = "report:generate"
    PermissionReportExport   Permission = "report:export"
    PermissionUserManage     Permission = "user:manage"
    PermissionAPIKeyManage   Permission = "apikey:manage"
)

type Role struct {
    Name        string
    Permissions []Permission
}

var Roles = map[string]Role{
    "admin": {
        Name: "Administrator",
        Permissions: []Permission{
            PermissionScanCreate,
            PermissionScanRead,
            PermissionScanDelete,
            PermissionReportGenerate,
            PermissionReportExport,
            PermissionUserManage,
            PermissionAPIKeyManage,
        },
    },
    "analyst": {
        Name: "Security Analyst",
        Permissions: []Permission{
            PermissionScanCreate,
            PermissionScanRead,
            PermissionReportGenerate,
            PermissionReportExport,
        },
    },
    "viewer": {
        Name: "Viewer",
        Permissions: []Permission{
            PermissionScanRead,
        },
    },
}

func HasPermission(user User, permission Permission) bool {
    role := Roles[user.Role]
    for _, p := range role.Permissions {
        if p == permission {
            return true
        }
    }
    return false
}
```

### 1.3 API Keys para Integração
```go
// backend/models/apikey.go
type APIKey struct {
    ID          uint      `gorm:"primaryKey"`
    Key         string    `gorm:"uniqueIndex"` // SHA256 hash
    Name        string    // "CI/CD Pipeline", "Monitoring System"
    UserID      uint
    TenantID    string
    Permissions []string  `gorm:"type:json"`
    LastUsedAt  *time.Time
    ExpiresAt   *time.Time
    CreatedAt   time.Time
}

// Middleware
func APIKeyMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        apiKey := c.GetHeader("X-API-Key")
        if apiKey == "" {
            c.JSON(401, gin.H{"error": "API key required"})
            c.Abort()
            return
        }
        
        // Validate and load user context
        key, err := ValidateAPIKey(apiKey)
        if err != nil {
            c.JSON(401, gin.H{"error": "Invalid API key"})
            c.Abort()
            return
        }
        
        c.Set("user_id", key.UserID)
        c.Set("tenant_id", key.TenantID)
        c.Next()
    }
}
```

### 1.4 Multi-Tenancy
```go
// backend/models/tenant.go
type Tenant struct {
    ID          string    `gorm:"primaryKey"` // UUID
    Name        string
    Plan        string    // free, pro, enterprise
    MaxScans    int       // Quota
    MaxUsers    int
    Features    []string  `gorm:"type:json"` // ["ai_reports", "pdf_export", "api_access"]
    CreatedAt   time.Time
}

// Middleware
func TenantMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        tenantID := c.GetString("tenant_id")
        
        // Check quota
        tenant, _ := GetTenant(tenantID)
        scanCount := GetScanCount(tenantID, time.Now().Month())
        
        if scanCount >= tenant.MaxScans {
            c.JSON(429, gin.H{"error": "Quota exceeded"})
            c.Abort()
            return
        }
        
        c.Next()
    }
}
```

**Prazo**: 2 semanas  
**Impacto**: Transforma em SaaS multi-tenant

---

## 2️⃣ FASE 2: SCAN MODES E CONFIGURAÇÃO AVANÇADA

**Objetivo**: Permitir diferentes níveis de agressividade e customização

### 2.1 Scan Modes
```go
// backend/models/scan.go
type ScanMode string

const (
    ScanModePassive    ScanMode = "passive"    // Apenas headers, robots.txt
    ScanModeSafe       ScanMode = "safe"       // + file probing (common files)
    ScanModeAggressive ScanMode = "aggressive" // + fuzzing, brute force
)

type ScanConfig struct {
    Mode            ScanMode
    MaxDepth        int           // Site map depth
    MaxRequests     int           // Rate limiting
    Timeout         time.Duration
    FollowRedirects bool
    CheckSSL        bool
    ProbeFiles      []string      // Custom file list
    CustomHeaders   map[string]string
    UserAgent       string
    Proxy           string        // HTTP proxy
}

type ScanRequest struct {
    URL    string     `json:"url"`
    Config ScanConfig `json:"config"`
}
```

### 2.2 Worker com Modos
```javascript
// backend/worker/scanner.js
class Scanner {
    constructor(config) {
        this.mode = config.mode || 'safe';
        this.maxDepth = config.maxDepth || 2;
        this.maxRequests = config.maxRequests || 100;
    }
    
    async scan(url) {
        switch(this.mode) {
            case 'passive':
                return await this.passiveScan(url);
            case 'safe':
                return await this.safeScan(url);
            case 'aggressive':
                return await this.aggressiveScan(url);
        }
    }
    
    async passiveScan(url) {
        // Apenas headers, robots.txt, DNS
        return {
            headers: await this.getHeaders(url),
            robots: await this.getRobots(url),
            dns: await this.getDNS(url),
            ssl: await this.getSSL(url),
        };
    }
    
    async safeScan(url) {
        // Passive + common files (top 100)
        const passive = await this.passiveScan(url);
        const files = await this.probeCommonFiles(url, COMMON_FILES_TOP_100);
        
        return { ...passive, exposedFiles: files };
    }
    
    async aggressiveScan(url) {
        // Safe + fuzzing + brute force
        const safe = await this.safeScan(url);
        const fuzzing = await this.fuzzParameters(url);
        const bruteforce = await this.bruteforceDirectories(url);
        
        return { ...safe, fuzzing, bruteforce };
    }
}
```

### 2.3 Profiles Pré-Configurados
```go
// backend/profiles/profiles.go
var ScanProfiles = map[string]ScanConfig{
    "quick": {
        Mode:        ScanModePassive,
        MaxDepth:    1,
        MaxRequests: 10,
        Timeout:     30 * time.Second,
    },
    "standard": {
        Mode:        ScanModeSafe,
        MaxDepth:    2,
        MaxRequests: 100,
        Timeout:     120 * time.Second,
    },
    "deep": {
        Mode:        ScanModeAggressive,
        MaxDepth:    5,
        MaxRequests: 1000,
        Timeout:     600 * time.Second,
    },
    "compliance": {
        Mode:        ScanModeSafe,
        MaxDepth:    3,
        MaxRequests: 200,
        CheckSSL:    true,
        // Focus on compliance checks (LGPD, PCI-DSS)
    },
}
```

**Prazo**: 1 semana  
**Impacto**: Flexibilidade para diferentes casos de uso

---

## 3️⃣ FASE 3: CVSS SCORING E CLASSIFICAÇÃO PROFISSIONAL

**Objetivo**: Scoring padronizado e reconhecido pela indústria

### 3.1 CVSS Calculator
```go
// backend/cvss/calculator.go
type CVSSVector struct {
    // Base Metrics
    AttackVector       string // N (Network), A (Adjacent), L (Local), P (Physical)
    AttackComplexity   string // L (Low), H (High)
    PrivilegesRequired string // N (None), L (Low), H (High)
    UserInteraction    string // N (None), R (Required)
    Scope              string // U (Unchanged), C (Changed)
    Confidentiality    string // N (None), L (Low), H (High)
    Integrity          string // N (None), L (Low), H (High)
    Availability       string // N (None), L (Low), H (High)
}

func (v CVSSVector) CalculateScore() float64 {
    // CVSS v3.1 formula
    impact := calculateImpact(v)
    exploitability := calculateExploitability(v)
    
    if impact <= 0 {
        return 0.0
    }
    
    if v.Scope == "U" {
        return roundUp(min(impact+exploitability, 10.0))
    }
    
    return roundUp(min(1.08*(impact+exploitability), 10.0))
}

func (v CVSSVector) GetSeverity() string {
    score := v.CalculateScore()
    
    switch {
    case score == 0.0:
        return "NONE"
    case score < 4.0:
        return "LOW"
    case score < 7.0:
        return "MEDIUM"
    case score < 9.0:
        return "HIGH"
    default:
        return "CRITICAL"
    }
}
```

### 3.2 Vulnerability com CVSS
```go
// backend/models/vulnerability.go
type Vulnerability struct {
    ID          uint      `gorm:"primaryKey"`
    ScanID      uint
    Type        string    // "HSTS Missing", "XSS", "SQLi"
    CWE         string    // "CWE-200"
    OWASP       string    // "A05:2021"
    CVSSVector  string    // "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    CVSSScore   float64   // 7.5
    Severity    string    // "HIGH"
    Description string
    Evidence    string    `gorm:"type:text"` // JSON with proof
    Remediation string    `gorm:"type:text"`
    Status      string    // "open", "fixed", "false_positive"
    CreatedAt   time.Time
}

// Auto-calculate CVSS
func (v *Vulnerability) BeforeSave(tx *gorm.DB) error {
    if v.CVSSVector != "" {
        vector := ParseCVSSVector(v.CVSSVector)
        v.CVSSScore = vector.CalculateScore()
        v.Severity = vector.GetSeverity()
    }
    return nil
}
```

### 3.3 Vulnerability Database
```go
// backend/vulndb/database.go
type VulnTemplate struct {
    Type        string
    CWE         string
    OWASP       string
    CVSSVector  string
    Description string
    Remediation string
}

var VulnDB = map[string]VulnTemplate{
    "hsts_missing": {
        Type:       "HSTS Missing",
        CWE:        "CWE-319",
        OWASP:      "A05:2021",
        CVSSVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
        Description: "Strict-Transport-Security header ausente permite ataques de downgrade",
        Remediation: "Implementar header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "xss_reflected": {
        Type:       "Reflected XSS",
        CWE:        "CWE-79",
        OWASP:      "A03:2021",
        CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        Description: "Cross-Site Scripting permite execução de código JavaScript no navegador da vítima",
        Remediation: "Sanitizar inputs com htmlspecialchars() ou equivalente",
    },
    // ... mais templates
}
```

**Prazo**: 1 semana  
**Impacto**: Scoring profissional reconhecido pela indústria

---

## 4️⃣ FASE 4: EVIDENCE OBJECTS E PROVA FORENSE

**Objetivo**: Evidências irrefutáveis para cada vulnerabilidade

### 4.1 Evidence Structure
```go
// backend/models/evidence.go
type Evidence struct {
    ID              uint      `gorm:"primaryKey"`
    VulnerabilityID uint
    Type            string    // "http_response", "screenshot", "html_source"
    
    // HTTP Evidence
    Request         string    `gorm:"type:text"` // Raw HTTP request
    Response        string    `gorm:"type:text"` // Raw HTTP response
    StatusCode      int
    Headers         string    `gorm:"type:json"`
    Body            string    `gorm:"type:text"`
    
    // Visual Evidence
    Screenshot      string    // Base64 or S3 URL
    ScreenshotPath  string    // File path
    
    // Source Code Evidence
    HTMLSource      string    `gorm:"type:text"`
    JSSource        string    `gorm:"type:text"`
    
    // Metadata
    Timestamp       time.Time
    UserAgent       string
    IPAddress       string
    
    CreatedAt       time.Time
}
```

### 4.2 Evidence Collector
```javascript
// backend/worker/evidence.js
class EvidenceCollector {
    async collectHTTPEvidence(url, response) {
        return {
            type: 'http_response',
            request: {
                method: 'GET',
                url: url,
                headers: response.request().headers(),
            },
            response: {
                status: response.status(),
                headers: response.headers(),
                body: await response.text(),
                timing: response.timing(),
            },
            timestamp: new Date().toISOString(),
        };
    }
    
    async collectScreenshotEvidence(page, selector = null) {
        const screenshot = await page.screenshot({
            fullPage: true,
            type: 'png',
        });
        
        return {
            type: 'screenshot',
            data: screenshot.toString('base64'),
            viewport: await page.viewportSize(),
            timestamp: new Date().toISOString(),
        };
    }
    
    async collectSourceEvidence(page) {
        return {
            type: 'html_source',
            html: await page.content(),
            scripts: await page.evaluate(() => {
                return Array.from(document.scripts).map(s => ({
                    src: s.src,
                    inline: s.innerHTML,
                }));
            }),
            timestamp: new Date().toISOString(),
        };
    }
}
```

### 4.3 Evidence Storage (S3/MinIO)
```go
// backend/storage/s3.go
type EvidenceStorage interface {
    Store(evidence Evidence) (string, error)
    Retrieve(id string) (Evidence, error)
    Delete(id string) error
}

type S3Storage struct {
    client *s3.Client
    bucket string
}

func (s *S3Storage) Store(evidence Evidence) (string, error) {
    key := fmt.Sprintf("evidence/%d/%s", evidence.VulnerabilityID, uuid.New())
    
    // Compress large evidence
    compressed := compress(evidence)
    
    _, err := s.client.PutObject(context.Background(), &s3.PutObjectInput{
        Bucket: aws.String(s.bucket),
        Key:    aws.String(key),
        Body:   bytes.NewReader(compressed),
    })
    
    return key, err
}
```

**Prazo**: 2 semanas  
**Impacto**: Evidências forenses para compliance e auditoria

---

## 5️⃣ FASE 5: FILA DISTRIBUÍDA E ESCALABILIDADE

**Objetivo**: Processar milhares de scans simultaneamente

### 5.1 Redis Queue
```go
// backend/queue/redis.go
type ScanJob struct {
    ID       string
    URL      string
    Config   ScanConfig
    TenantID string
    UserID   string
    Priority int // 1-10
    Status   string // "pending", "processing", "completed", "failed"
}

type RedisQueue struct {
    client *redis.Client
}

func (q *RedisQueue) Enqueue(job ScanJob) error {
    data, _ := json.Marshal(job)
    
    // Add to priority queue
    return q.client.ZAdd(context.Background(), "scan_queue", &redis.Z{
        Score:  float64(job.Priority),
        Member: data,
    }).Err()
}

func (q *RedisQueue) Dequeue() (*ScanJob, error) {
    // Pop highest priority job
    result, err := q.client.ZPopMax(context.Background(), "scan_queue").Result()
    if err != nil {
        return nil, err
    }
    
    var job ScanJob
    json.Unmarshal([]byte(result[0].Member.(string)), &job)
    
    return &job, nil
}
```

### 5.2 Worker Pool
```go
// backend/worker/pool.go
type WorkerPool struct {
    workers   int
    queue     *RedisQueue
    wg        sync.WaitGroup
}

func (p *WorkerPool) Start() {
    for i := 0; i < p.workers; i++ {
        p.wg.Add(1)
        go p.worker(i)
    }
}

func (p *WorkerPool) worker(id int) {
    defer p.wg.Done()
    
    for {
        job, err := p.queue.Dequeue()
        if err != nil {
            time.Sleep(1 * time.Second)
            continue
        }
        
        log.Printf("Worker %d processing job %s", id, job.ID)
        
        // Process scan
        result, err := ProcessScan(job)
        if err != nil {
            job.Status = "failed"
        } else {
            job.Status = "completed"
            SaveScanResult(result)
        }
        
        UpdateJobStatus(job)
    }
}
```

### 5.3 Horizontal Scaling
```yaml
# docker-compose.yml
version: '3.8'

services:
  backend:
    image: aegis-backend:latest
    deploy:
      replicas: 3
    environment:
      - REDIS_URL=redis://redis:6379
      - DATABASE_URL=postgresql://postgres:5432/aegis
    depends_on:
      - redis
      - postgres
  
  worker:
    image: aegis-worker:latest
    deploy:
      replicas: 10
    environment:
      - REDIS_URL=redis://redis:6379
    depends_on:
      - redis
  
  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data
  
  postgres:
    image: postgres:15-alpine
    volumes:
      - postgres_data:/var/lib/postgresql/data
```

**Prazo**: 2 semanas  
**Impacto**: Escalabilidade para milhares de scans/hora

---

## 6️⃣ FASE 6: IA COMO CORRELATOR (NÃO DETECTOR)

**Objetivo**: IA analisa e correlaciona, não detecta vulnerabilidades

### 6.1 Arquitetura Correta
```
┌─────────────────┐
│  Scanner Engine │ ← Detecta vulnerabilidades (regras determinísticas)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Vulnerability DB│ ← Armazena findings com evidências
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  AI Correlator  │ ← Analisa contexto, correlaciona, prioriza
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Report Engine  │ ← Gera relatório profissional
└─────────────────┘
```

### 6.2 Scanner Determinístico
```go
// backend/scanner/detector.go
type VulnerabilityDetector interface {
    Detect(target Target) []Vulnerability
}

type HSTSDetector struct{}

func (d *HSTSDetector) Detect(target Target) []Vulnerability {
    vulns := []Vulnerability{}
    
    // Deterministic check
    if !target.Headers.Has("Strict-Transport-Security") {
        vulns = append(vulns, Vulnerability{
            Type:       "HSTS Missing",
            CWE:        "CWE-319",
            CVSSVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
            Evidence: Evidence{
                Type:       "http_response",
                Headers:    target.Headers,
                StatusCode: target.StatusCode,
            },
        })
    }
    
    return vulns
}

// Mais detectores: XSSDetector, SQLiDetector, CSPDetector, etc
```

### 6.3 AI Correlator
```go
// backend/ai/correlator.go
type AICorrelator struct {
    client *genai.Client
}

func (c *AICorrelator) Correlate(vulns []Vulnerability, target Target) CorrelationResult {
    // IA NÃO detecta, apenas correlaciona e contextualiza
    prompt := fmt.Sprintf(`
Você é um Security Analyst sênior.

Foram detectadas %d vulnerabilidades no alvo %s:
%s

Sua tarefa é:
1. Correlacionar vulnerabilidades (quais podem ser exploradas em cadeia?)
2. Priorizar por impacto real no negócio
3. Sugerir ordem de correção
4. Identificar padrões (ex: todas relacionadas a headers)

NÃO invente novas vulnerabilidades. Apenas analise as detectadas.
`, len(vulns), target.URL, formatVulns(vulns))
    
    response := c.client.GenerateContent(prompt)
    
    return CorrelationResult{
        AttackChains:    extractAttackChains(response),
        Priority:        extractPriority(response),
        Patterns:        extractPatterns(response),
        Recommendations: extractRecommendations(response),
    }
}
```

### 6.4 Report com Correlação
```go
// backend/report/generator.go
func GenerateReport(scan Scan, vulns []Vulnerability, correlation CorrelationResult) Report {
    return Report{
        ExecutiveSummary: generateExecutiveSummary(scan, vulns, correlation),
        
        // Vulnerabilidades detectadas (determinístico)
        Vulnerabilities: vulns,
        
        // Análise da IA (correlação)
        AttackChains:    correlation.AttackChains,
        RiskPriority:    correlation.Priority,
        Patterns:        correlation.Patterns,
        
        // Compliance (determinístico)
        Compliance:      calculateCompliance(vulns),
        
        // Roadmap (baseado em CVSS + correlação)
        Roadmap:         generateRoadmap(vulns, correlation),
    }
}
```

**Prazo**: 1 semana  
**Impacto**: IA confiável e auditável (não alucina vulnerabilidades)

---

## 📊 RESUMO DO ROADMAP

| Fase | Objetivo | Prazo | Impacto |
|------|----------|-------|---------|
| 1️⃣ Auth | SaaS multi-tenant | 2 semanas | Comercialização |
| 2️⃣ Scan Modes | Flexibilidade | 1 semana | Casos de uso |
| 3️⃣ CVSS | Scoring profissional | 1 semana | Credibilidade |
| 4️⃣ Evidence | Prova forense | 2 semanas | Compliance |
| 5️⃣ Queue | Escalabilidade | 2 semanas | Performance |
| 6️⃣ AI Correlator | IA confiável | 1 semana | Qualidade |

**Total**: 9 semanas (2 meses)

---

## 🎯 RESULTADO FINAL

### Antes (MVP v4.0)
- Ferramenta local
- Scan único
- Relatórios 10/10
- SQLite

### Depois (Enterprise v5.0)
- ✅ SaaS multi-tenant
- ✅ API REST + API Keys
- ✅ RBAC completo
- ✅ Scan modes (passive/safe/aggressive)
- ✅ CVSS scoring
- ✅ Evidence objects
- ✅ Fila distribuída (Redis)
- ✅ Horizontal scaling
- ✅ IA como correlator
- ✅ PostgreSQL
- ✅ S3/MinIO storage

---

## 💰 MODELO DE NEGÓCIO

### Planos
1. **Free**: 10 scans/mês, passive mode, 1 usuário
2. **Pro** ($99/mês): 100 scans/mês, safe mode, 5 usuários, API access
3. **Enterprise** ($499/mês): Unlimited scans, aggressive mode, unlimited users, dedicated support

### Diferenciais
- ✅ Relatórios com compliance (LGPD, PCI-DSS)
- ✅ CVSS scoring profissional
- ✅ Evidence objects para auditoria
- ✅ IA que não alucina (correlator, não detector)
- ✅ API para integração CI/CD

---

## 📚 TECNOLOGIAS ADICIONAIS

### Backend
- PostgreSQL (substituir SQLite)
- Redis (queue + cache)
- MinIO/S3 (evidence storage)
- JWT (autenticação)

### Infraestrutura
- Docker + Kubernetes
- Nginx (reverse proxy)
- Prometheus + Grafana (monitoring)
- ELK Stack (logs)

### Frontend
- React/Vue (substituir vanilla JS)
- TypeScript
- Tailwind CSS
- Chart.js (dashboards)

---

**Status**: ROADMAP APROVADO  
**Próximo Passo**: Escolher fase para implementar  
**Recomendação**: Começar pela Fase 1 (Auth) para viabilizar comercialização
