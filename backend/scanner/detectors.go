package scanner

import (
	"encoding/json"
	"strings"
)

// VulnerabilityDetector interface for deterministic detection
type VulnerabilityDetector interface {
	Detect(target *Target) []DetectedVulnerability
	Name() string
}

// Target represents the scan target with collected data
type Target struct {
	URL         string
	Headers     map[string]string
	StatusCode  int
	Body        string
	Metadata    map[string]interface{}
	ExposedFiles []ExposedFile
}

// DetectedVulnerability represents a confirmed vulnerability
type DetectedVulnerability struct {
	Type        string
	CWE         string
	OWASP       string
	CVSSVector  string
	CVSSScore   float64
	Severity    string
	Description string
	Evidence    Evidence
	Remediation string
	Confidence  string // "confirmed", "likely", "possible"
}

// Evidence contains proof of vulnerability
type Evidence struct {
	Type       string                 // "http_header", "file_exposure", "response_analysis"
	Data       map[string]interface{} // Flexible evidence data
	Timestamp  string
}

// ExposedFile represents a publicly accessible sensitive file
type ExposedFile struct {
	Path       string
	StatusCode int
	Size       int
	Type       string // ".env", ".git", "backup"
}

// ============================================================================
// DETECTOR 1: HSTS Missing
// ============================================================================

type HSTSDetector struct{}

func (d *HSTSDetector) Name() string {
	return "HSTS Detector"
}

func (d *HSTSDetector) Detect(target *Target) []DetectedVulnerability {
	vulns := []DetectedVulnerability{}
	
	// Check if HSTS header is present
	hstsHeader := ""
	for key, value := range target.Headers {
		if strings.ToLower(key) == "strict-transport-security" {
			hstsHeader = value
			break
		}
	}
	
	if hstsHeader == "" {
		vulns = append(vulns, DetectedVulnerability{
			Type:        "HSTS Missing",
			CWE:         "CWE-319",
			OWASP:       "A05:2021 - Security Misconfiguration",
			CVSSVector:  "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
			CVSSScore:   5.3,
			Severity:    "MEDIUM",
			Description: "Strict-Transport-Security header ausente permite ataques de downgrade HTTPS",
			Evidence: Evidence{
				Type: "http_header",
				Data: map[string]interface{}{
					"header":      "Strict-Transport-Security",
					"status":      "missing",
					"url":         target.URL,
					"status_code": target.StatusCode,
				},
			},
			Remediation: "Implementar header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
			Confidence:  "confirmed",
		})
	}
	
	return vulns
}

// ============================================================================
// DETECTOR 2: CSP Missing
// ============================================================================

type CSPDetector struct{}

func (d *CSPDetector) Name() string {
	return "CSP Detector"
}

func (d *CSPDetector) Detect(target *Target) []DetectedVulnerability {
	vulns := []DetectedVulnerability{}
	
	// Check if CSP header is present
	cspHeader := ""
	for key, value := range target.Headers {
		lowerKey := strings.ToLower(key)
		if lowerKey == "content-security-policy" || lowerKey == "content-security-policy-report-only" {
			cspHeader = value
			break
		}
	}
	
	if cspHeader == "" {
		vulns = append(vulns, DetectedVulnerability{
			Type:        "CSP Missing",
			CWE:         "CWE-1021",
			OWASP:       "A05:2021 - Security Misconfiguration",
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
			CVSSScore:   6.1,
			Severity:    "MEDIUM",
			Description: "Content Security Policy ausente permite execução de scripts maliciosos (XSS)",
			Evidence: Evidence{
				Type: "http_header",
				Data: map[string]interface{}{
					"header":      "Content-Security-Policy",
					"status":      "missing",
					"url":         target.URL,
					"status_code": target.StatusCode,
				},
			},
			Remediation: "Implementar CSP: Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'",
			Confidence:  "confirmed",
		})
	}
	
	return vulns
}

// ============================================================================
// DETECTOR 3: X-Frame-Options Missing
// ============================================================================

type XFrameOptionsDetector struct{}

func (d *XFrameOptionsDetector) Name() string {
	return "X-Frame-Options Detector"
}

func (d *XFrameOptionsDetector) Detect(target *Target) []DetectedVulnerability {
	vulns := []DetectedVulnerability{}
	
	// Check if X-Frame-Options header is present
	xFrameHeader := ""
	for key, value := range target.Headers {
		if strings.ToLower(key) == "x-frame-options" {
			xFrameHeader = value
			break
		}
	}
	
	if xFrameHeader == "" {
		vulns = append(vulns, DetectedVulnerability{
			Type:        "X-Frame-Options Missing",
			CWE:         "CWE-1021",
			OWASP:       "A05:2021 - Security Misconfiguration",
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
			CVSSScore:   5.4,
			Severity:    "MEDIUM",
			Description: "X-Frame-Options ausente permite ataques de Clickjacking",
			Evidence: Evidence{
				Type: "http_header",
				Data: map[string]interface{}{
					"header":      "X-Frame-Options",
					"status":      "missing",
					"url":         target.URL,
					"status_code": target.StatusCode,
				},
			},
			Remediation: "Implementar header: X-Frame-Options: SAMEORIGIN ou DENY",
			Confidence:  "confirmed",
		})
	}
	
	return vulns
}

// ============================================================================
// DETECTOR 4: X-Content-Type-Options Missing
// ============================================================================

type XContentTypeOptionsDetector struct{}

func (d *XContentTypeOptionsDetector) Name() string {
	return "X-Content-Type-Options Detector"
}

func (d *XContentTypeOptionsDetector) Detect(target *Target) []DetectedVulnerability {
	vulns := []DetectedVulnerability{}
	
	// Check if X-Content-Type-Options header is present
	xContentHeader := ""
	for key, value := range target.Headers {
		if strings.ToLower(key) == "x-content-type-options" {
			xContentHeader = value
			break
		}
	}
	
	if xContentHeader == "" {
		vulns = append(vulns, DetectedVulnerability{
			Type:        "X-Content-Type-Options Missing",
			CWE:         "CWE-16",
			OWASP:       "A05:2021 - Security Misconfiguration",
			CVSSVector:  "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
			CVSSScore:   3.1,
			Severity:    "LOW",
			Description: "X-Content-Type-Options ausente permite MIME sniffing attacks",
			Evidence: Evidence{
				Type: "http_header",
				Data: map[string]interface{}{
					"header":      "X-Content-Type-Options",
					"status":      "missing",
					"url":         target.URL,
					"status_code": target.StatusCode,
				},
			},
			Remediation: "Implementar header: X-Content-Type-Options: nosniff",
			Confidence:  "confirmed",
		})
	}
	
	return vulns
}

// ============================================================================
// DETECTOR 5: Exposed Sensitive Files
// ============================================================================

type ExposedFilesDetector struct{}

func (d *ExposedFilesDetector) Name() string {
	return "Exposed Files Detector"
}

func (d *ExposedFilesDetector) Detect(target *Target) []DetectedVulnerability {
	vulns := []DetectedVulnerability{}
	
	// Check for exposed files in metadata
	if len(target.ExposedFiles) == 0 {
		return vulns
	}
	
	// Categorize by severity
	criticalFiles := []ExposedFile{}
	highFiles := []ExposedFile{}
	mediumFiles := []ExposedFile{}
	
	for _, file := range target.ExposedFiles {
		if file.StatusCode == 200 {
			switch file.Type {
			case ".env", "id_rsa", ".git/HEAD", ".git/config":
				criticalFiles = append(criticalFiles, file)
			case "backup.zip", ".sql", "database.sql":
				highFiles = append(highFiles, file)
			case "debug.log", ".log", "config.json":
				mediumFiles = append(mediumFiles, file)
			}
		}
	}
	
	// Create vulnerability for critical files
	if len(criticalFiles) > 0 {
		fileList := []string{}
		for _, f := range criticalFiles {
			fileList = append(fileList, f.Path)
		}
		
		vulns = append(vulns, DetectedVulnerability{
			Type:        "Exposed Sensitive Files",
			CWE:         "CWE-200",
			OWASP:       "A01:2021 - Broken Access Control",
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			CVSSScore:   7.5,
			Severity:    "CRITICAL",
			Description: "Arquivos sensíveis expostos publicamente contendo credenciais ou código-fonte",
			Evidence: Evidence{
				Type: "file_exposure",
				Data: map[string]interface{}{
					"files":       fileList,
					"count":       len(criticalFiles),
					"status_code": 200,
				},
			},
			Remediation: "Remover arquivos sensíveis do web root e configurar .htaccess/.gitignore",
			Confidence:  "confirmed",
		})
	}
	
	// Create vulnerability for high severity files
	if len(highFiles) > 0 {
		fileList := []string{}
		for _, f := range highFiles {
			fileList = append(fileList, f.Path)
		}
		
		vulns = append(vulns, DetectedVulnerability{
			Type:        "Exposed Backup Files",
			CWE:         "CWE-530",
			OWASP:       "A05:2021 - Security Misconfiguration",
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			CVSSScore:   7.5,
			Severity:    "HIGH",
			Description: "Arquivos de backup expostos publicamente",
			Evidence: Evidence{
				Type: "file_exposure",
				Data: map[string]interface{}{
					"files":       fileList,
					"count":       len(highFiles),
					"status_code": 200,
				},
			},
			Remediation: "Remover arquivos de backup do web root",
			Confidence:  "confirmed",
		})
	}
	
	return vulns
}

// ============================================================================
// SCANNER ENGINE - Runs all detectors
// ============================================================================

type ScannerEngine struct {
	detectors []VulnerabilityDetector
}

func NewScannerEngine() *ScannerEngine {
	return &ScannerEngine{
		detectors: []VulnerabilityDetector{
			&HSTSDetector{},
			&CSPDetector{},
			&XFrameOptionsDetector{},
			&XContentTypeOptionsDetector{},
			&ExposedFilesDetector{},
		},
	}
}

func (s *ScannerEngine) Scan(target *Target) []DetectedVulnerability {
	allVulns := []DetectedVulnerability{}
	
	for _, detector := range s.detectors {
		vulns := detector.Detect(target)
		allVulns = append(allVulns, vulns...)
	}
	
	return allVulns
}

// ============================================================================
// HELPER: Parse scan result to Target
// ============================================================================

func ParseScanResult(scanResult map[string]interface{}) *Target {
	target := &Target{
		Headers:  make(map[string]string),
		Metadata: scanResult,
	}
	
	// Extract URL
	if url, ok := scanResult["url"].(string); ok {
		target.URL = url
	}
	
	// Extract headers from security_audit
	if sa, ok := scanResult["security_audit"].(map[string]interface{}); ok {
		if headers, ok := sa["headers"].(map[string]interface{}); ok {
			for key, value := range headers {
				if strValue, ok := value.(string); ok {
					target.Headers[key] = strValue
				}
			}
		}
		
		// Extract exposed files
		if exposedFiles, ok := sa["exposed_files"].([]interface{}); ok {
			for _, file := range exposedFiles {
				if fileMap, ok := file.(map[string]interface{}); ok {
					exposedFile := ExposedFile{}
					
					if path, ok := fileMap["path"].(string); ok {
						exposedFile.Path = path
					}
					if status, ok := fileMap["status"].(float64); ok {
						exposedFile.StatusCode = int(status)
					}
					if fileType, ok := fileMap["type"].(string); ok {
						exposedFile.Type = fileType
					}
					
					target.ExposedFiles = append(target.ExposedFiles, exposedFile)
				}
			}
		}
	}
	
	return target
}

// ============================================================================
// HELPER: Convert to JSON
// ============================================================================

func (v DetectedVulnerability) ToJSON() string {
	data, _ := json.MarshalIndent(v, "", "  ")
	return string(data)
}
