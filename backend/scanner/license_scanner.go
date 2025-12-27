package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// LicenseRisk represents the risk level of a license
type LicenseRisk struct {
	License     string `json:"license"`
	Risk        string `json:"risk"` // HIGH, MEDIUM, LOW, SAFE
	Type        string `json:"type"` // copyleft, permissive, proprietary, unknown
	Description string `json:"description"`
	Viral       bool   `json:"viral"` // If true, requires derivative works to use same license
}

// LicenseVulnerability represents a license issue found
type LicenseVulnerability struct {
	Package     string `json:"package"`
	Version     string `json:"version"`
	License     string `json:"license"`
	Risk        string `json:"risk"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Viral       bool   `json:"viral"`
	Ecosystem   string `json:"ecosystem"`
}

// LicenseScanResult represents the result of license scanning
type LicenseScanResult struct {
	TotalPackages   int                    `json:"total_packages"`
	Vulnerabilities []LicenseVulnerability `json:"vulnerabilities"`
	Summary         LicenseSummary         `json:"summary"`
	LicenseBreakdown map[string]int        `json:"license_breakdown"`
}

type LicenseSummary struct {
	HighRisk   int `json:"high_risk"`
	MediumRisk int `json:"medium_risk"`
	LowRisk    int `json:"low_risk"`
	Safe       int `json:"safe"`
	Unknown    int `json:"unknown"`
}

// LicenseScanner scans for license compliance issues
type LicenseScanner struct {
	licenseDB map[string]LicenseRisk
}

// NewLicenseScanner creates a new license scanner
func NewLicenseScanner() *LicenseScanner {
	return &LicenseScanner{
		licenseDB: getLicenseDatabase(),
	}
}

func getLicenseDatabase() map[string]LicenseRisk {
	return map[string]LicenseRisk{
		// HIGH RISK - Copyleft/Viral licenses
		"GPL-3.0": {
			License:     "GPL-3.0",
			Risk:        "HIGH",
			Type:        "copyleft",
			Description: "Licença viral - código derivado deve ser GPL. Incompatível com projetos proprietários.",
			Viral:       true,
		},
		"GPL-2.0": {
			License:     "GPL-2.0",
			Risk:        "HIGH",
			Type:        "copyleft",
			Description: "Licença viral - código derivado deve ser GPL-2.0.",
			Viral:       true,
		},
		"AGPL-3.0": {
			License:     "AGPL-3.0",
			Risk:        "HIGH",
			Type:        "copyleft",
			Description: "Licença viral extrema - mesmo uso em rede requer abertura do código.",
			Viral:       true,
		},
		"LGPL-3.0": {
			License:     "LGPL-3.0",
			Risk:        "MEDIUM",
			Type:        "copyleft",
			Description: "Copyleft fraco - modificações na biblioteca devem ser abertas.",
			Viral:       true,
		},
		"LGPL-2.1": {
			License:     "LGPL-2.1",
			Risk:        "MEDIUM",
			Type:        "copyleft",
			Description: "Copyleft fraco - modificações na biblioteca devem ser abertas.",
			Viral:       true,
		},
		"MPL-2.0": {
			License:     "MPL-2.0",
			Risk:        "MEDIUM",
			Type:        "copyleft",
			Description: "Copyleft por arquivo - modificações em arquivos MPL devem ser abertas.",
			Viral:       true,
		},
		"CC-BY-NC": {
			License:     "CC-BY-NC",
			Risk:        "HIGH",
			Type:        "restrictive",
			Description: "Proíbe uso comercial - incompatível com projetos comerciais.",
			Viral:       false,
		},
		"CC-BY-NC-SA": {
			License:     "CC-BY-NC-SA",
			Risk:        "HIGH",
			Type:        "restrictive",
			Description: "Proíbe uso comercial e é viral.",
			Viral:       true,
		},
		"SSPL": {
			License:     "SSPL",
			Risk:        "HIGH",
			Type:        "copyleft",
			Description: "Server Side Public License - extremamente restritiva para SaaS.",
			Viral:       true,
		},
		"BSL-1.1": {
			License:     "BSL-1.1",
			Risk:        "MEDIUM",
			Type:        "source-available",
			Description: "Business Source License - restrições de uso comercial por período.",
			Viral:       false,
		},
		// SAFE - Permissive licenses
		"MIT": {
			License:     "MIT",
			Risk:        "SAFE",
			Type:        "permissive",
			Description: "Licença permissiva - uso livre com atribuição.",
			Viral:       false,
		},
		"Apache-2.0": {
			License:     "Apache-2.0",
			Risk:        "SAFE",
			Type:        "permissive",
			Description: "Licença permissiva com proteção de patentes.",
			Viral:       false,
		},
		"BSD-2-Clause": {
			License:     "BSD-2-Clause",
			Risk:        "SAFE",
			Type:        "permissive",
			Description: "Licença permissiva simplificada.",
			Viral:       false,
		},
		"BSD-3-Clause": {
			License:     "BSD-3-Clause",
			Risk:        "SAFE",
			Type:        "permissive",
			Description: "Licença permissiva com cláusula de não-endosso.",
			Viral:       false,
		},
		"ISC": {
			License:     "ISC",
			Risk:        "SAFE",
			Type:        "permissive",
			Description: "Licença permissiva similar ao MIT.",
			Viral:       false,
		},
		"Unlicense": {
			License:     "Unlicense",
			Risk:        "SAFE",
			Type:        "public-domain",
			Description: "Domínio público - sem restrições.",
			Viral:       false,
		},
		"CC0-1.0": {
			License:     "CC0-1.0",
			Risk:        "SAFE",
			Type:        "public-domain",
			Description: "Creative Commons Zero - domínio público.",
			Viral:       false,
		},
		"0BSD": {
			License:     "0BSD",
			Risk:        "SAFE",
			Type:        "permissive",
			Description: "Zero-Clause BSD - máxima permissividade.",
			Viral:       false,
		},
		"WTFPL": {
			License:     "WTFPL",
			Risk:        "SAFE",
			Type:        "permissive",
			Description: "Do What The F*** You Want - sem restrições.",
			Viral:       false,
		},
	}
}

// ScanDirectory scans a directory for license issues
func (ls *LicenseScanner) ScanDirectory(dirPath string) (*LicenseScanResult, error) {
	result := &LicenseScanResult{
		Vulnerabilities:  []LicenseVulnerability{},
		LicenseBreakdown: make(map[string]int),
	}

	// Scan npm packages
	if _, err := os.Stat(filepath.Join(dirPath, "package.json")); err == nil {
		ls.scanNpmLicenses(dirPath, result)
	}

	// Scan Go modules
	if _, err := os.Stat(filepath.Join(dirPath, "go.mod")); err == nil {
		ls.scanGoLicenses(dirPath, result)
	}

	// Scan Python packages
	if _, err := os.Stat(filepath.Join(dirPath, "requirements.txt")); err == nil {
		ls.scanPipLicenses(dirPath, result)
	}

	// Scan composer packages
	if _, err := os.Stat(filepath.Join(dirPath, "composer.json")); err == nil {
		ls.scanComposerLicenses(dirPath, result)
	}

	return result, nil
}

func (ls *LicenseScanner) scanNpmLicenses(dirPath string, result *LicenseScanResult) {
	// Try to read package-lock.json for more accurate info
	lockPath := filepath.Join(dirPath, "package-lock.json")
	data, err := os.ReadFile(lockPath)
	if err != nil {
		// Fallback to package.json
		pkgPath := filepath.Join(dirPath, "package.json")
		data, err = os.ReadFile(pkgPath)
		if err != nil {
			return
		}
	}

	var pkg struct {
		Dependencies map[string]interface{} `json:"dependencies"`
		Packages     map[string]struct {
			License string `json:"license"`
			Version string `json:"version"`
		} `json:"packages"`
	}

	if err := json.Unmarshal(data, &pkg); err != nil {
		return
	}

	// Process packages from lock file
	for name, info := range pkg.Packages {
		if name == "" || strings.HasPrefix(name, "node_modules/") == false {
			continue
		}
		pkgName := strings.TrimPrefix(name, "node_modules/")
		result.TotalPackages++
		
		license := strings.ToUpper(info.License)
		result.LicenseBreakdown[info.License]++

		if risk, ok := ls.licenseDB[ls.normalizeLicense(info.License)]; ok {
			if risk.Risk == "HIGH" || risk.Risk == "MEDIUM" {
				result.Vulnerabilities = append(result.Vulnerabilities, LicenseVulnerability{
					Package:     pkgName,
					Version:     info.Version,
					License:     info.License,
					Risk:        risk.Risk,
					Type:        risk.Type,
					Description: risk.Description,
					Viral:       risk.Viral,
					Ecosystem:   "npm",
				})
				ls.updateSummary(&result.Summary, risk.Risk)
			} else {
				result.Summary.Safe++
			}
		} else if license != "" {
			result.Summary.Unknown++
		}
	}
}

func (ls *LicenseScanner) scanGoLicenses(dirPath string, result *LicenseScanResult) {
	// Go doesn't store license info in go.mod, would need to check each module
	// For now, we'll check go.sum for known problematic packages
	sumPath := filepath.Join(dirPath, "go.sum")
	data, err := os.ReadFile(sumPath)
	if err != nil {
		return
	}

	// Known GPL Go packages
	gplPackages := map[string]string{
		"github.com/jteeuwen/go-bindata": "CC0-1.0",
		"github.com/mattn/go-sqlite3":    "MIT",
	}

	lines := strings.Split(string(data), "\n")
	seen := make(map[string]bool)
	
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		pkg := parts[0]
		if seen[pkg] {
			continue
		}
		seen[pkg] = true
		result.TotalPackages++

		if license, ok := gplPackages[pkg]; ok {
			if risk, ok := ls.licenseDB[ls.normalizeLicense(license)]; ok {
				if risk.Risk == "HIGH" || risk.Risk == "MEDIUM" {
					result.Vulnerabilities = append(result.Vulnerabilities, LicenseVulnerability{
						Package:     pkg,
						License:     license,
						Risk:        risk.Risk,
						Type:        risk.Type,
						Description: risk.Description,
						Viral:       risk.Viral,
						Ecosystem:   "go",
					})
					ls.updateSummary(&result.Summary, risk.Risk)
				}
			}
		}
	}
}

func (ls *LicenseScanner) scanPipLicenses(dirPath string, result *LicenseScanResult) {
	// Python packages don't include license in requirements.txt
	// Would need pip show or metadata files
	reqPath := filepath.Join(dirPath, "requirements.txt")
	data, err := os.ReadFile(reqPath)
	if err != nil {
		return
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		result.TotalPackages++
	}
}

func (ls *LicenseScanner) scanComposerLicenses(dirPath string, result *LicenseScanResult) {
	lockPath := filepath.Join(dirPath, "composer.lock")
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return
	}

	var lock struct {
		Packages []struct {
			Name    string   `json:"name"`
			Version string   `json:"version"`
			License []string `json:"license"`
		} `json:"packages"`
	}

	if err := json.Unmarshal(data, &lock); err != nil {
		return
	}

	for _, pkg := range lock.Packages {
		result.TotalPackages++
		
		for _, license := range pkg.License {
			result.LicenseBreakdown[license]++
			
			if risk, ok := ls.licenseDB[ls.normalizeLicense(license)]; ok {
				if risk.Risk == "HIGH" || risk.Risk == "MEDIUM" {
					result.Vulnerabilities = append(result.Vulnerabilities, LicenseVulnerability{
						Package:     pkg.Name,
						Version:     pkg.Version,
						License:     license,
						Risk:        risk.Risk,
						Type:        risk.Type,
						Description: risk.Description,
						Viral:       risk.Viral,
						Ecosystem:   "composer",
					})
					ls.updateSummary(&result.Summary, risk.Risk)
				} else {
					result.Summary.Safe++
				}
			}
		}
	}
}

func (ls *LicenseScanner) normalizeLicense(license string) string {
	// Normalize common license variations
	license = strings.ToUpper(strings.TrimSpace(license))
	
	normalizations := map[string]string{
		"MIT LICENSE":     "MIT",
		"APACHE 2.0":      "Apache-2.0",
		"APACHE-2":        "Apache-2.0",
		"APACHE2":         "Apache-2.0",
		"BSD":             "BSD-3-Clause",
		"BSD-2":           "BSD-2-Clause",
		"BSD-3":           "BSD-3-Clause",
		"GPL":             "GPL-3.0",
		"GPL3":            "GPL-3.0",
		"GPL-3":           "GPL-3.0",
		"GPL2":            "GPL-2.0",
		"GPL-2":           "GPL-2.0",
		"LGPL":            "LGPL-3.0",
		"LGPL3":           "LGPL-3.0",
		"LGPL-3":          "LGPL-3.0",
		"AGPL":            "AGPL-3.0",
		"AGPL3":           "AGPL-3.0",
		"AGPL-3":          "AGPL-3.0",
		"MPL":             "MPL-2.0",
		"MPL2":            "MPL-2.0",
		"MPL-2":           "MPL-2.0",
		"UNLICENSED":      "UNLICENSE",
		"PUBLIC DOMAIN":   "Unlicense",
	}

	if normalized, ok := normalizations[license]; ok {
		return normalized
	}
	
	// Try direct match
	for key := range ls.licenseDB {
		if strings.EqualFold(license, key) {
			return key
		}
	}
	
	return license
}

func (ls *LicenseScanner) updateSummary(summary *LicenseSummary, risk string) {
	switch risk {
	case "HIGH":
		summary.HighRisk++
	case "MEDIUM":
		summary.MediumRisk++
	case "LOW":
		summary.LowRisk++
	case "SAFE":
		summary.Safe++
	default:
		summary.Unknown++
	}
}
