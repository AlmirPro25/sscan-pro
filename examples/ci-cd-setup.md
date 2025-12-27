# Exemplos de Setup CI/CD - AegisScan

## Cenário 1: Startup SaaS

**Stack**: React + Node.js + PostgreSQL  
**Deploy**: Vercel (frontend) + Railway (backend)  
**Objetivo**: Bloquear deploy se vulnerabilidades HIGH+

### GitHub Actions
```yaml
name: Deploy with Security Check

on:
  push:
    branches: [ main ]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Security Scan
        run: |
          # Install CLI
          cd cli && go build -o aegis aegis.go && cd ..
          
          # Scan staging
          ./cli/aegis scan https://staging.meuapp.com \
            --fail-on high \
            --output security-report.md
        env:
          GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
      
      - name: Upload Report
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: security-report.md
  
  deploy:
    needs: security
    runs-on: ubuntu-latest
    steps:
      - name: Deploy to Production
        run: vercel --prod
```

**Resultado**: Deploy só acontece se scan passar.

---

## Cenário 2: E-commerce Enterprise

**Stack**: Java Spring Boot + React + MySQL  
**Deploy**: Kubernetes (AWS EKS)  
**Objetivo**: Scan em staging antes de produção

### GitLab CI
```yaml
stages:
  - build
  - test
  - security
  - deploy-staging
  - security-staging
  - deploy-production

security-staging:
  stage: security-staging
  image: golang:1.21
  script:
    - cd cli && go build -o aegis aegis.go
    - |
      ./aegis scan https://staging.loja.com \
        --fail-on high \
        --output report-staging.md
  artifacts:
    paths:
      - report-staging.md
  only:
    - main

deploy-production:
  stage: deploy-production
  needs: 
    - security-staging
  script:
    - kubectl apply -f k8s/production/
  only:
    - main
```

**Resultado**: Produção só recebe deploy se staging passar no scan.

---

## Cenário 3: Fintech (Compliance Rigoroso)

**Stack**: Python Django + PostgreSQL  
**Deploy**: AWS ECS  
**Objetivo**: Zero tolerância para CRITICAL, relatório obrigatório

### Jenkins
```groovy
pipeline {
    agent any
    
    environment {
        GEMINI_API_KEY = credentials('gemini-api-key')
    }
    
    stages {
        stage('Build') {
            steps {
                sh 'docker build -t myapp:${BUILD_NUMBER} .'
            }
        }
        
        stage('Security Scan - CRITICAL Check') {
            steps {
                sh '''
                    cd cli && go build -o aegis aegis.go
                    ./aegis scan https://staging.fintech.com \
                        --fail-on critical \
                        --output report-critical.md
                '''
            }
        }
        
        stage('Security Scan - Full Report') {
            steps {
                sh '''
                    ./cli/aegis scan https://staging.fintech.com \
                        --output report-full.md
                '''
            }
        }
        
        stage('Compliance Check') {
            steps {
                script {
                    def report = readFile('report-full.md')
                    
                    // Verificar se menciona compliance
                    if (!report.contains('LGPD') || !report.contains('PCI-DSS')) {
                        error('Compliance section missing in report')
                    }
                }
            }
        }
        
        stage('Deploy to Production') {
            when {
                branch 'main'
            }
            steps {
                sh 'aws ecs update-service --cluster prod --service myapp'
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'report-*.md'
            
            emailext(
                subject: "Security Report: ${env.JOB_NAME} - ${env.BUILD_NUMBER}",
                body: readFile('report-full.md'),
                to: 'security@fintech.com,compliance@fintech.com'
            )
        }
        
        failure {
            slackSend(
                color: 'danger',
                message: "Security scan failed: ${env.JOB_NAME} - ${env.BUILD_NUMBER}"
            )
        }
    }
}
```

**Resultado**: 
- CRITICAL bloqueia deploy
- Relatório completo enviado para security + compliance
- Slack notifica falhas

---

## Cenário 4: Agência Digital (Multi-cliente)

**Stack**: WordPress + PHP  
**Deploy**: cPanel / Shared Hosting  
**Objetivo**: Scan de múltiplos sites de clientes

### Script Bash
```bash
#!/bin/bash
# scan-all-clients.sh

CLIENTS=(
    "https://cliente1.com"
    "https://cliente2.com"
    "https://cliente3.com"
)

FAIL_COUNT=0

for CLIENT in "${CLIENTS[@]}"; do
    echo "Scanning $CLIENT..."
    
    ./cli/aegis scan "$CLIENT" \
        --fail-on high \
        --output "report-$(echo $CLIENT | sed 's/https:\/\///g' | sed 's/\.com//g').md"
    
    if [ $? -ne 0 ]; then
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo "❌ $CLIENT failed security check"
    else
        echo "✅ $CLIENT passed security check"
    fi
done

echo ""
echo "Summary: $FAIL_COUNT / ${#CLIENTS[@]} clients failed"

if [ $FAIL_COUNT -gt 0 ]; then
    exit 1
fi
```

**Cron Job**:
```bash
# Scan diário às 2am
0 2 * * * /home/user/aegis/scan-all-clients.sh >> /var/log/aegis-scan.log 2>&1
```

**Resultado**: Scan automático de todos os clientes, relatórios individuais.

---

## Cenário 5: Microservices (10+ serviços)

**Stack**: Go + Node.js + Python  
**Deploy**: Kubernetes  
**Objetivo**: Scan paralelo de todos os serviços

### GitHub Actions (Matrix Strategy)
```yaml
name: Microservices Security Scan

on:
  push:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        service:
          - name: api-gateway
            url: https://api.empresa.com
            fail-on: high
          - name: auth-service
            url: https://auth.empresa.com
            fail-on: critical
          - name: payment-service
            url: https://payment.empresa.com
            fail-on: high
          - name: notification-service
            url: https://notification.empresa.com
            fail-on: medium
          - name: analytics-service
            url: https://analytics.empresa.com
            fail-on: medium
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Scan ${{ matrix.service.name }}
        run: |
          cd cli && go build -o aegis aegis.go
          ./aegis scan ${{ matrix.service.url }} \
            --fail-on ${{ matrix.service.fail-on }} \
            --output report-${{ matrix.service.name }}.md
        env:
          GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
      
      - name: Upload Report
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: security-reports
          path: report-*.md
```

**Resultado**: Scan paralelo de 5 serviços, fail conditions individuais.

---

## Cenário 6: Mobile Backend (API)

**Stack**: Node.js Express + MongoDB  
**Deploy**: Heroku  
**Objetivo**: Scan antes de release para app stores

### GitLab CI
```yaml
stages:
  - test
  - security
  - deploy
  - release

security-api:
  stage: security
  image: golang:1.21
  script:
    - cd cli && go build -o aegis aegis.go
    - |
      ./aegis scan https://api-staging.meuapp.com \
        --fail-on high \
        --output api-security-report.md
  artifacts:
    paths:
      - api-security-report.md
  only:
    - release/*

deploy-production:
  stage: deploy
  needs:
    - security-api
  script:
    - git push heroku main
  only:
    - release/*

notify-release:
  stage: release
  needs:
    - deploy-production
  script:
    - |
      curl -X POST https://slack.com/api/chat.postMessage \
        -H "Authorization: Bearer $SLACK_TOKEN" \
        -d "channel=#releases" \
        -d "text=API v${CI_COMMIT_TAG} deployed. Security report: ${CI_JOB_URL}/artifacts"
  only:
    - tags
```

**Resultado**: Release só acontece se API passar no scan.

---

## Cenário 7: Open Source Project

**Stack**: Qualquer  
**Deploy**: GitHub Pages / Netlify  
**Objetivo**: Scan em PRs, não bloquear contribuições

### GitHub Actions
```yaml
name: Security Check (Non-blocking)

on:
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    continue-on-error: true  # Não bloqueia PR
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Security Scan
        run: |
          cd cli && go build -o aegis aegis.go
          ./aegis scan https://preview-${{ github.event.number }}.netlify.app \
            --output security-report.md
        env:
          GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
      
      - name: Comment PR
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const report = fs.readFileSync('security-report.md', 'utf8');
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `## 🛡️ Security Scan Results\n\n${report.substring(0, 3000)}\n\n_This is informational only and does not block the PR._`
            });
```

**Resultado**: Scan informativo em PRs, não bloqueia merge.

---

## Dicas por Tipo de Projeto

### Startup (MVP)
- `--fail-on critical` (não bloqueia muito)
- Scan apenas em main
- Relatório simples

### Scale-up (Crescimento)
- `--fail-on high`
- Scan em staging + production
- Notificações Slack

### Enterprise (Maduro)
- `--fail-on medium` (rigoroso)
- Scan em todos os ambientes
- Compliance obrigatório
- Relatórios para múltiplos stakeholders

### Agência (Multi-cliente)
- Scan paralelo de clientes
- Relatórios individuais
- Cron jobs diários

### Open Source
- Scan não-bloqueante
- Comentários em PRs
- Educação da comunidade

---

**Criado por**: Kiro AI  
**Data**: 2024-12-27
