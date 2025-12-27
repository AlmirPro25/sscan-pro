# 🚀 Plano de Ação: 14 Dias para MVP Comercial

## 🎯 Objetivo
Transformar o AegisScan em um produto comercialmente viável em 14 dias.

---

## 📅 Dia 1-3: Segurança Core

### Dia 1: Autenticação (Backend)
**Tempo**: 8 horas

**Tarefas:**
```go
// 1. Criar model User
type User struct {
    ID        uint   `gorm:"primaryKey"`
    Email     string `gorm:"unique"`
    Password  string // bcrypt
    Plan      string // free, pro, business
    ScanLimit int
    CreatedAt time.Time
}

// 2. Endpoints de auth
POST /api/v1/auth/register
POST /api/v1/auth/login
POST /api/v1/auth/refresh
GET  /api/v1/auth/me

// 3. JWT middleware
func authMiddleware() gin.HandlerFunc {
    // Validate JWT token
}

// 4. Proteger rotas
v1.Use(authMiddleware())
v1.POST("/scan", handleScan)
```

**Checklist:**
- [ ] Model User criado
- [ ] Bcrypt para passwords
- [ ] JWT generation
- [ ] JWT validation
- [ ] Refresh tokens
- [ ] Middleware aplicado

---

### Dia 2: Autenticação (Frontend)
**Tempo**: 8 horas

**Tarefas:**
```javascript
// 1. Telas de auth
- Login screen
- Register screen
- Forgot password screen

// 2. Auth state management
class AuthManager {
    async login(email, password) {
        const res = await fetch('/api/v1/auth/login', {
            method: 'POST',
            body: JSON.stringify({ email, password })
        });
        const { token } = await res.json();
        localStorage.setItem('token', token);
    }
    
    async register(email, password) { }
    logout() { }
    isAuthenticated() { }
}

// 3. Protected routes
if (!auth.isAuthenticated()) {
    showLoginScreen();
}

// 4. Token refresh
setInterval(() => auth.refreshToken(), 15 * 60 * 1000);
```

**Checklist:**
- [ ] Login UI
- [ ] Register UI
- [ ] Auth state management
- [ ] Token storage
- [ ] Auto-refresh
- [ ] Logout flow

---

### Dia 3: Rate Limiting & Validação
**Tempo**: 8 horas

**Tarefas:**
```go
// 1. Rate limiting
import "github.com/ulule/limiter/v3"

rate := limiter.Rate{
    Period: 1 * time.Minute,
    Limit:  10,
}

// 2. Validação de URL
func validateURL(url string) error {
    parsed, err := url.Parse(url)
    if err != nil {
        return errors.New("invalid URL")
    }
    
    // Block internal IPs (SSRF)
    if isInternalIP(parsed.Hostname()) {
        return errors.New("internal IPs not allowed")
    }
    
    return nil
}

// 3. Scan limits por plano
func checkScanLimit(userID uint) error {
    var user User
    db.First(&user, userID)
    
    count := countScansThisMonth(userID)
    if count >= user.ScanLimit {
        return errors.New("scan limit reached")
    }
    
    return nil
}
```

**Checklist:**
- [ ] Rate limiting implementado
- [ ] Validação de URL
- [ ] SSRF protection
- [ ] Scan limits por plano
- [ ] Error messages claros

---

## 📅 Dia 4-5: Banco de Dados

### Dia 4: Migração PostgreSQL
**Tempo**: 6 horas

**Tarefas:**
```go
// 1. Trocar driver
import "gorm.io/driver/postgres"

dsn := os.Getenv("DATABASE_URL")
db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})

// 2. Atualizar docker-compose.yml
services:
  db:
    image: postgres:15-alpine
    environment:
      POSTGRES_PASSWORD: ${DB_PASSWORD}
      POSTGRES_DB: aegis
    volumes:
      - postgres_data:/var/lib/postgresql/data

// 3. Migrations
db.AutoMigrate(&User{}, &ScanResult{}, &AIReport{}, &ChatMessage{})

// 4. Índices
db.Exec("CREATE INDEX idx_scans_user_id ON scan_results(user_id)")
db.Exec("CREATE INDEX idx_scans_created_at ON scan_results(created_at)")
```

**Checklist:**
- [ ] PostgreSQL no docker-compose
- [ ] Driver atualizado
- [ ] Migrations rodadas
- [ ] Índices criados
- [ ] Connection pooling
- [ ] Teste de conexão

---

### Dia 5: Logs & Monitoring
**Tempo**: 6 horas

**Tarefas:**
```go
// 1. Logger estruturado
import "go.uber.org/zap"

logger, _ := zap.NewProduction()
defer logger.Sync()

logger.Info("scan started",
    zap.String("url", url),
    zap.Int("user_id", userID),
)

// 2. Health checks
v1.GET("/health", func(c *gin.Context) {
    workerHealth := checkWorker()
    dbHealth := db.DB()
    
    c.JSON(200, gin.H{
        "status": "ok",
        "worker": workerHealth,
        "database": dbHealth != nil,
    })
})

// 3. Error tracking (Sentry)
import "github.com/getsentry/sentry-go"

sentry.Init(sentry.ClientOptions{
    Dsn: os.Getenv("SENTRY_DSN"),
})
```

**Checklist:**
- [ ] Zap logger configurado
- [ ] Health check endpoint
- [ ] Sentry configurado (opcional)
- [ ] Logs estruturados
- [ ] Error tracking

---

## 📅 Dia 6-8: Monetização

### Dia 6: Stripe Setup
**Tempo**: 8 horas

**Tarefas:**
```go
// 1. Criar conta Stripe
// 2. Criar produtos
- Free (R$ 0, 3 scans)
- Pro (R$ 97, 20 scans)
- Business (R$ 297, 100 scans)

// 3. Backend integration
import "github.com/stripe/stripe-go/v74"

stripe.Key = os.Getenv("STRIPE_SECRET_KEY")

func createCheckoutSession(userID uint, priceID string) {
    params := &stripe.CheckoutSessionParams{
        Customer: stripe.String(userID),
        LineItems: []*stripe.CheckoutSessionLineItemParams{
            {Price: stripe.String(priceID), Quantity: stripe.Int64(1)},
        },
        Mode: stripe.String("subscription"),
        SuccessURL: stripe.String("https://aegis.com/success"),
        CancelURL: stripe.String("https://aegis.com/cancel"),
    }
    stripe.CheckoutSession.New(params)
}
```

**Checklist:**
- [ ] Conta Stripe criada
- [ ] Produtos criados
- [ ] API keys configuradas
- [ ] Checkout session endpoint
- [ ] Success/cancel URLs

---

### Dia 7: Stripe Webhooks
**Tempo**: 8 horas

**Tarefas:**
```go
// 1. Webhook endpoint
POST /api/v1/stripe/webhook

func handleStripeWebhook(c *gin.Context) {
    payload, _ := ioutil.ReadAll(c.Request.Body)
    event, _ := webhook.ConstructEvent(payload, sig, webhookSecret)
    
    switch event.Type {
    case "checkout.session.completed":
        // Ativar assinatura
        updateUserPlan(customerID, "pro")
        
    case "invoice.payment_failed":
        // Suspender conta
        suspendUser(customerID)
        
    case "customer.subscription.deleted":
        // Cancelar assinatura
        updateUserPlan(customerID, "free")
    }
}

// 2. Atualizar user plan
func updateUserPlan(userID uint, plan string) {
    limits := map[string]int{
        "free": 3,
        "pro": 20,
        "business": 100,
    }
    
    db.Model(&User{}).Where("id = ?", userID).Updates(map[string]interface{}{
        "plan": plan,
        "scan_limit": limits[plan],
    })
}
```

**Checklist:**
- [ ] Webhook endpoint criado
- [ ] Webhook secret configurado
- [ ] Event handlers
- [ ] User plan updates
- [ ] Email notifications

---

### Dia 8: Frontend Billing
**Tempo**: 8 horas

**Tarefas:**
```javascript
// 1. Pricing page
<div class="pricing-cards">
    <div class="plan free">
        <h3>Free</h3>
        <p>R$ 0/mês</p>
        <ul>
            <li>3 scans/mês</li>
            <li>Relatórios básicos</li>
        </ul>
        <button>Começar Grátis</button>
    </div>
    
    <div class="plan pro">
        <h3>Pro</h3>
        <p>R$ 97/mês</p>
        <ul>
            <li>20 scans/mês</li>
            <li>Relatórios AI</li>
            <li>Chat com IA</li>
        </ul>
        <button onclick="checkout('pro')">Assinar</button>
    </div>
</div>

// 2. Checkout flow
async function checkout(plan) {
    const res = await fetch('/api/v1/stripe/checkout', {
        method: 'POST',
        body: JSON.stringify({ plan })
    });
    const { url } = await res.json();
    window.location.href = url;
}

// 3. Billing dashboard
- Current plan
- Usage (scans this month)
- Upgrade/downgrade
- Cancel subscription
```

**Checklist:**
- [ ] Pricing page
- [ ] Checkout flow
- [ ] Billing dashboard
- [ ] Usage tracking
- [ ] Upgrade/downgrade

---

## 📅 Dia 9-11: Landing Page

### Dia 9: Design & Copy
**Tempo**: 8 horas

**Estrutura:**
```html
<!-- Hero Section -->
<section class="hero">
    <h1>Auditoria de Segurança Web com IA</h1>
    <p>Descubra vulnerabilidades antes dos hackers</p>
    <button>Começar Grátis</button>
</section>

<!-- Features -->
<section class="features">
    <div>🔍 Deep Scanning</div>
    <div>🤖 Análise com IA</div>
    <div>🛡️ Red Team Ops</div>
</section>

<!-- Pricing -->
<section class="pricing">
    <!-- Cards de preço -->
</section>

<!-- Social Proof -->
<section class="testimonials">
    <!-- Depoimentos -->
</section>

<!-- CTA -->
<section class="cta">
    <h2>Pronto para proteger seu site?</h2>
    <button>Começar Agora</button>
</section>
```

**Checklist:**
- [ ] Hero section
- [ ] Features showcase
- [ ] Pricing section
- [ ] Testimonials (mock)
- [ ] CTA buttons
- [ ] Responsive design

---

### Dia 10: Implementação
**Tempo**: 8 horas

**Tarefas:**
- [ ] HTML/CSS da landing
- [ ] Animações suaves
- [ ] Forms de contato
- [ ] SEO básico (meta tags)
- [ ] Google Analytics
- [ ] Favicon e logo

---

### Dia 11: Email & Onboarding
**Tempo**: 8 horas

**Tarefas:**
```javascript
// 1. SendGrid setup
const sgMail = require('@sendgrid/mail');
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// 2. Welcome email
const msg = {
    to: user.email,
    from: 'hello@aegisscan.com',
    subject: 'Bem-vindo ao AegisScan!',
    html: welcomeTemplate,
};
sgMail.send(msg);

// 3. Email templates
- Welcome email
- Email verification
- Password reset
- Scan completed
- Vulnerability alert
```

**Checklist:**
- [ ] SendGrid configurado
- [ ] Welcome email
- [ ] Email verification
- [ ] Password reset
- [ ] Templates profissionais

---

## 📅 Dia 12-14: Deploy & Testes

### Dia 12: Deploy Staging
**Tempo**: 8 horas

**Tarefas:**
```bash
# 1. Servidor (DigitalOcean/AWS)
- Ubuntu 22.04
- 2GB RAM
- 50GB SSD

# 2. Docker setup
docker-compose -f docker-compose.prod.yml up -d

# 3. Nginx reverse proxy
server {
    listen 80;
    server_name staging.aegisscan.com;
    
    location / {
        proxy_pass http://localhost:8080;
    }
}

# 4. SSL (Let's Encrypt)
certbot --nginx -d staging.aegisscan.com

# 5. Environment variables
DATABASE_URL=postgres://...
STRIPE_SECRET_KEY=sk_test_...
SENDGRID_API_KEY=SG...
```

**Checklist:**
- [ ] Servidor provisionado
- [ ] Docker instalado
- [ ] Nginx configurado
- [ ] SSL certificate
- [ ] Environment vars
- [ ] Deploy automático (GitHub Actions)

---

### Dia 13: Testes Completos
**Tempo**: 8 horas

**Checklist:**
- [ ] Signup flow
- [ ] Login flow
- [ ] Scan completo
- [ ] Relatório AI
- [ ] Chat com IA
- [ ] Checkout Stripe
- [ ] Webhook Stripe
- [ ] Email notifications
- [ ] Rate limiting
- [ ] Scan limits
- [ ] Health checks
- [ ] Backup restore

---

### Dia 14: Launch Preparation
**Tempo**: 8 horas

**Tarefas:**
- [ ] Smoke tests em produção
- [ ] Monitoring ativo (Sentry, UptimeRobot)
- [ ] Backup configurado
- [ ] Documentação atualizada
- [ ] Anúncio preparado (LinkedIn, Reddit)
- [ ] Email para beta users
- [ ] Product Hunt draft (opcional)

---

## 🎯 Resultado Esperado (Dia 14)

### Sistema Completo
✅ Autenticação funcional  
✅ Rate limiting ativo  
✅ PostgreSQL em produção  
✅ Stripe integrado  
✅ Landing page live  
✅ Email notifications  
✅ Deploy automático  
✅ Monitoring ativo  

### Pronto Para
✅ Primeiros clientes pagantes  
✅ Marketing orgânico  
✅ Feedback loop  
✅ Iteração rápida  

---

## 📊 Métricas de Sucesso (30 dias)

- [ ] 50+ signups
- [ ] 5+ paying customers
- [ ] R$ 500+ MRR
- [ ] 99% uptime
- [ ] < 5 bugs críticos
- [ ] 10+ testimonials

---

## 🚨 Riscos & Mitigação

### Risco 1: Atraso no desenvolvimento
**Mitigação**: Cortar features não-essenciais

### Risco 2: Bugs em produção
**Mitigação**: Testes extensivos + monitoring

### Risco 3: Sem clientes
**Mitigação**: Marketing agressivo + beta gratuito

### Risco 4: Custos altos
**Mitigação**: Começar pequeno + escalar conforme demanda

---

## ✅ Daily Checklist

Todos os dias:
- [ ] Commit code
- [ ] Update progress
- [ ] Test features
- [ ] Document changes
- [ ] Review security

---

**Status**: 🟢 READY TO START  
**Próximo Passo**: Dia 1 - Autenticação Backend  
**Deadline**: 14 dias a partir de hoje  
**Objetivo**: MVP Comercial Funcional 🚀
