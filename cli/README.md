# AegisScan CLI

Security scanner for CI/CD pipelines.

## Quick Start

```bash
# Build
go build -o aegis aegis.go

# Scan
./aegis scan https://meusite.com --fail-on high

# Output
./aegis scan https://meusite.com --output report.md
```

## CI/CD Integration

### GitHub Actions
```yaml
- name: Security Scan
  run: aegis scan ${{ secrets.TARGET_URL }} --fail-on high
  env:
    GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
```

### GitLab CI
```yaml
security:
  script:
    - aegis scan ${TARGET_URL} --fail-on high
```

### Jenkins
```groovy
sh 'aegis scan ${TARGET_URL} --fail-on high'
```

## Options

```
--api string        API URL (default "http://localhost:8080")
--fail-on string    Fail on severity: critical, high, medium, low (default "high")
--output string     Output file path
--json              Output as JSON
--timeout int       Timeout in seconds (default 300)
--api-key string    Gemini API key
--model string      AI model (default "gemini-3-flash-preview")
```

## Exit Codes

- `0`: Success (no vulnerabilities or below threshold)
- `1`: Failure (vulnerabilities found at or above threshold)

## Documentation

See [CLI_CICD_INTEGRATION.md](../docs/CLI_CICD_INTEGRATION.md) for full documentation.
