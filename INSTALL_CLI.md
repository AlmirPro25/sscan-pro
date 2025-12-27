# Instalação Rápida - AegisScan CLI

## 🚀 Opção 1: Build Local (Recomendado)

### Windows
```powershell
cd cli
go build -o aegis.exe aegis.go
move aegis.exe C:\Windows\System32\

# Testar
aegis scan https://example.com
```

### Linux/Mac
```bash
cd cli
go build -o aegis aegis.go
chmod +x aegis
sudo mv aegis /usr/local/bin/

# Testar
aegis scan https://example.com
```

---

## 🐳 Opção 2: Docker

```bash
# Build
docker build -t aegis-cli:latest -f cli/Dockerfile cli/

# Usar
docker run --rm aegis-cli:latest scan https://example.com
```

---

## ⚙️ Configuração

### 1. API Key (Obrigatório)
```bash
# Opção 1: Environment variable
export GEMINI_API_KEY=sua_chave_aqui

# Opção 2: Flag
aegis scan https://site.com --api-key sua_chave_aqui
```

### 2. Backend (Obrigatório)
```bash
# Terminal 1: Backend
cd backend
./aegis-backend-v4.2.exe

# Terminal 2: Worker
cd backend/worker
node server.js

# Terminal 3: CLI
aegis scan https://site.com
```

---

## ✅ Teste Rápido

```bash
# Scan básico
aegis scan http://testphp.vulnweb.com

# Com fail condition
aegis scan http://testphp.vulnweb.com --fail-on high

# Com output
aegis scan http://testphp.vulnweb.com --output report.md
```

---

## 🔧 Troubleshooting

### "aegis: command not found"
```bash
# Verificar se está no PATH
which aegis  # Linux/Mac
where aegis  # Windows

# Adicionar ao PATH se necessário
export PATH=$PATH:/caminho/para/cli
```

### "connection refused"
```bash
# Verificar se backend está rodando
curl http://localhost:8080/api/v1/health

# Iniciar backend se necessário
cd backend && ./aegis-backend-v4.2.exe
```

### "API key not configured"
```bash
# Verificar variável de ambiente
echo $GEMINI_API_KEY  # Linux/Mac
echo %GEMINI_API_KEY%  # Windows

# Configurar se necessário
export GEMINI_API_KEY=sua_chave_aqui
```

---

## 📚 Próximos Passos

1. ✅ CLI instalado
2. ⏳ Integrar com CI/CD → Ver [CLI_CICD_INTEGRATION.md](docs/CLI_CICD_INTEGRATION.md)
3. ⏳ Configurar fail conditions
4. ⏳ Automatizar scans

---

**Tempo de instalação**: 2-5 minutos  
**Dificuldade**: Fácil
