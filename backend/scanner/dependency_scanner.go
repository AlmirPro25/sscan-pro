package scanner

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// DependencyVulnerability represents a vulnerability in a dependency
type DependencyVulnerability struct {
	Package     string `json:"package"`
	Version     string `json:"version"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	CVE         string `json:"cve"`
	CWE         string `json:"cwe"`
	CVSS        float64 `json:"cvss"`
	FixVersion  string `json:"fix_version"`
	URL         string `json:"url"`
	Ecosystem   string `json:"ecosystem"` // npm, go, pip, etc
}

// DependencyScanResult represents the result of dependency scanning
type DependencyScanResult struct {
	Ecosystem       string                    `json:"ecosystem"`
	TotalDeps       int                       `json:"total_deps"`
	Vulnerabilities []DependencyVulnerability `json:"vulnerabilities"`
	Summary         DependencySummary         `json:"summary"`
}

type DependencySummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// DependencyScanner scans project dependencies for vulnerabilities
type DependencyScanner struct{}

// NewDependencyScanner creates a new dependency scanner
func NewDependencyScanner() *DependencyScanner {
	return &DependencyScanner{}
}

// ScanDirectory scans a directory for dependency files and vulnerabilities
func (ds *DependencyScanner) ScanDirectory(dirPath string) ([]DependencyScanResult, error) {
	var results []DependencyScanResult

	// Check for package.json (npm/node)
	if _, err := os.Stat(filepath.Join(dirPath, "package.json")); err == nil {
		npmResult := ds.scanNpm(dirPath)
		if npmResult != nil {
			results = append(results, *npmResult)
		}
	}

	// Check for package-lock.json (more accurate)
	if _, err := os.Stat(filepath.Join(dirPath, "package-lock.json")); err == nil {
		npmAuditResult := ds.runNpmAudit(dirPath)
		if npmAuditResult != nil {
			// Merge with existing npm result or add new
			merged := false
			for i, r := range results {
				if r.Ecosystem == "npm" {
					results[i].Vulnerabilities = append(results[i].Vulnerabilities, npmAuditResult.Vulnerabilities...)
					results[i].Summary.Critical += npmAuditResult.Summary.Critical
					results[i].Summary.High += npmAuditResult.Summary.High
					results[i].Summary.Medium += npmAuditResult.Summary.Medium
					results[i].Summary.Low += npmAuditResult.Summary.Low
					merged = true
					break
				}
			}
			if !merged {
				results = append(results, *npmAuditResult)
			}
		}
	}

	// Check for go.mod (Go)
	if _, err := os.Stat(filepath.Join(dirPath, "go.mod")); err == nil {
		goResult := ds.scanGo(dirPath)
		if goResult != nil {
			results = append(results, *goResult)
		}
	}

	// Check for requirements.txt (Python)
	if _, err := os.Stat(filepath.Join(dirPath, "requirements.txt")); err == nil {
		pipResult := ds.scanPip(dirPath)
		if pipResult != nil {
			results = append(results, *pipResult)
		}
	}

	// Check for Pipfile (Python)
	if _, err := os.Stat(filepath.Join(dirPath, "Pipfile")); err == nil {
		pipfileResult := ds.scanPipfile(dirPath)
		if pipfileResult != nil {
			results = append(results, *pipfileResult)
		}
	}

	// Check for composer.json (PHP)
	if _, err := os.Stat(filepath.Join(dirPath, "composer.json")); err == nil {
		composerResult := ds.scanComposer(dirPath)
		if composerResult != nil {
			results = append(results, *composerResult)
		}
	}

	// Check for Gemfile (Ruby)
	if _, err := os.Stat(filepath.Join(dirPath, "Gemfile")); err == nil {
		gemResult := ds.scanGem(dirPath)
		if gemResult != nil {
			results = append(results, *gemResult)
		}
	}

	return results, nil
}

// scanNpm scans package.json for known vulnerable packages
func (ds *DependencyScanner) scanNpm(dirPath string) *DependencyScanResult {
	packagePath := filepath.Join(dirPath, "package.json")
	data, err := os.ReadFile(packagePath)
	if err != nil {
		return nil
	}

	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}

	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}

	result := &DependencyScanResult{
		Ecosystem: "npm",
		TotalDeps: len(pkg.Dependencies) + len(pkg.DevDependencies),
	}

	// Check against known vulnerable packages
	knownVulnerable := getKnownVulnerableNpmPackages()

	allDeps := make(map[string]string)
	for k, v := range pkg.Dependencies {
		allDeps[k] = v
	}
	for k, v := range pkg.DevDependencies {
		allDeps[k] = v
	}

	for pkgName, version := range allDeps {
		if vuln, ok := knownVulnerable[pkgName]; ok {
			if isVersionVulnerable(version, vuln.FixVersion) {
				vuln.Version = version
				result.Vulnerabilities = append(result.Vulnerabilities, vuln)
				ds.updateSummary(&result.Summary, vuln.Severity)
			}
		}
	}

	return result
}

// runNpmAudit runs npm audit and parses results
func (ds *DependencyScanner) runNpmAudit(dirPath string) *DependencyScanResult {
	cmd := exec.Command("npm", "audit", "--json")
	cmd.Dir = dirPath
	output, err := cmd.Output()
	if err != nil {
		// npm audit returns non-zero if vulnerabilities found, that's ok
		if exitErr, ok := err.(*exec.ExitError); ok {
			output = exitErr.Stderr
			if len(output) == 0 {
				output, _ = cmd.Output()
			}
		}
	}

	if len(output) == 0 {
		return nil
	}

	var auditResult struct {
		Vulnerabilities map[string]struct {
			Name     string `json:"name"`
			Severity string `json:"severity"`
			Via      []interface{} `json:"via"`
			Effects  []string `json:"effects"`
			Range    string `json:"range"`
			FixAvailable interface{} `json:"fixAvailable"`
		} `json:"vulnerabilities"`
		Metadata struct {
			Vulnerabilities struct {
				Critical int `json:"critical"`
				High     int `json:"high"`
				Moderate int `json:"moderate"`
				Low      int `json:"low"`
			} `json:"vulnerabilities"`
			Dependencies int `json:"dependencies"`
		} `json:"metadata"`
	}

	if err := json.Unmarshal(output, &auditResult); err != nil {
		return nil
	}

	result := &DependencyScanResult{
		Ecosystem: "npm",
		TotalDeps: auditResult.Metadata.Dependencies,
		Summary: DependencySummary{
			Critical: auditResult.Metadata.Vulnerabilities.Critical,
			High:     auditResult.Metadata.Vulnerabilities.High,
			Medium:   auditResult.Metadata.Vulnerabilities.Moderate,
			Low:      auditResult.Metadata.Vulnerabilities.Low,
		},
	}

	for name, vuln := range auditResult.Vulnerabilities {
		severity := strings.ToUpper(vuln.Severity)
		if severity == "MODERATE" {
			severity = "MEDIUM"
		}

		depVuln := DependencyVulnerability{
			Package:   name,
			Version:   vuln.Range,
			Severity:  severity,
			Title:     "Vulnerability in " + name,
			Ecosystem: "npm",
		}

		// Extract CVE from via if available
		for _, v := range vuln.Via {
			if viaMap, ok := v.(map[string]interface{}); ok {
				if title, ok := viaMap["title"].(string); ok {
					depVuln.Title = title
				}
				if url, ok := viaMap["url"].(string); ok {
					depVuln.URL = url
				}
				if cve, ok := viaMap["cve"].([]interface{}); ok && len(cve) > 0 {
					if cveStr, ok := cve[0].(string); ok {
						depVuln.CVE = cveStr
					}
				}
			}
		}

		result.Vulnerabilities = append(result.Vulnerabilities, depVuln)
	}

	return result
}

// scanGo scans go.mod for dependencies
func (ds *DependencyScanner) scanGo(dirPath string) *DependencyScanResult {
	modPath := filepath.Join(dirPath, "go.mod")
	data, err := os.ReadFile(modPath)
	if err != nil {
		return nil
	}

	result := &DependencyScanResult{
		Ecosystem: "go",
	}

	// Parse go.mod
	lines := strings.Split(string(data), "\n")
	inRequire := false
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		if strings.HasPrefix(line, "require (") {
			inRequire = true
			continue
		}
		if line == ")" {
			inRequire = false
			continue
		}
		if strings.HasPrefix(line, "require ") {
			// Single line require
			parts := strings.Fields(strings.TrimPrefix(line, "require "))
			if len(parts) >= 2 {
				result.TotalDeps++
				ds.checkGoVulnerability(result, parts[0], parts[1])
			}
			continue
		}
		if inRequire && line != "" && !strings.HasPrefix(line, "//") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				result.TotalDeps++
				ds.checkGoVulnerability(result, parts[0], parts[1])
			}
		}
	}

	return result
}

func (ds *DependencyScanner) checkGoVulnerability(result *DependencyScanResult, pkg, version string) {
	knownVulnerable := getKnownVulnerableGoPackages()
	
	if vuln, ok := knownVulnerable[pkg]; ok {
		vuln.Version = version
		result.Vulnerabilities = append(result.Vulnerabilities, vuln)
		ds.updateSummary(&result.Summary, vuln.Severity)
	}
}

// scanPip scans requirements.txt
func (ds *DependencyScanner) scanPip(dirPath string) *DependencyScanResult {
	reqPath := filepath.Join(dirPath, "requirements.txt")
	data, err := os.ReadFile(reqPath)
	if err != nil {
		return nil
	}

	result := &DependencyScanResult{
		Ecosystem: "pip",
	}

	knownVulnerable := getKnownVulnerablePipPackages()
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse package==version or package>=version
		var pkgName, version string
		if strings.Contains(line, "==") {
			parts := strings.Split(line, "==")
			pkgName = strings.TrimSpace(parts[0])
			if len(parts) > 1 {
				version = strings.TrimSpace(parts[1])
			}
		} else if strings.Contains(line, ">=") {
			parts := strings.Split(line, ">=")
			pkgName = strings.TrimSpace(parts[0])
			if len(parts) > 1 {
				version = ">=" + strings.TrimSpace(parts[1])
			}
		} else {
			pkgName = line
		}

		result.TotalDeps++

		if vuln, ok := knownVulnerable[strings.ToLower(pkgName)]; ok {
			vuln.Version = version
			result.Vulnerabilities = append(result.Vulnerabilities, vuln)
			ds.updateSummary(&result.Summary, vuln.Severity)
		}
	}

	return result
}

func (ds *DependencyScanner) scanPipfile(dirPath string) *DependencyScanResult {
	// Similar to scanPip but for Pipfile format
	return nil
}

func (ds *DependencyScanner) scanComposer(dirPath string) *DependencyScanResult {
	composerPath := filepath.Join(dirPath, "composer.json")
	data, err := os.ReadFile(composerPath)
	if err != nil {
		return nil
	}

	var composer struct {
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}

	if err := json.Unmarshal(data, &composer); err != nil {
		return nil
	}

	result := &DependencyScanResult{
		Ecosystem: "composer",
		TotalDeps: len(composer.Require) + len(composer.RequireDev),
	}

	// Check known vulnerable PHP packages
	knownVulnerable := getKnownVulnerableComposerPackages()

	for pkg, version := range composer.Require {
		if vuln, ok := knownVulnerable[pkg]; ok {
			vuln.Version = version
			result.Vulnerabilities = append(result.Vulnerabilities, vuln)
			ds.updateSummary(&result.Summary, vuln.Severity)
		}
	}

	return result
}

func (ds *DependencyScanner) scanGem(dirPath string) *DependencyScanResult {
	// Ruby Gemfile scanning
	return nil
}

func (ds *DependencyScanner) updateSummary(summary *DependencySummary, severity string) {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		summary.Critical++
	case "HIGH":
		summary.High++
	case "MEDIUM", "MODERATE":
		summary.Medium++
	case "LOW":
		summary.Low++
	}
}

func isVersionVulnerable(currentVersion, fixVersion string) bool {
	// Simplified version comparison
	// In production, use proper semver comparison
	if fixVersion == "" {
		return true
	}
	// Remove ^ or ~ prefixes
	currentVersion = strings.TrimLeft(currentVersion, "^~>=<")
	return currentVersion < fixVersion
}
