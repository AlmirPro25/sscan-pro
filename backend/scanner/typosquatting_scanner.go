package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// TyposquattingVulnerability represents a potential typosquatting attack
type TyposquattingVulnerability struct {
	Package       string  `json:"package"`
	SimilarTo     string  `json:"similar_to"`
	Similarity    float64 `json:"similarity"`
	Risk          string  `json:"risk"`
	Description   string  `json:"description"`
	Ecosystem     string  `json:"ecosystem"`
	Recommendation string `json:"recommendation"`
}

// TyposquattingScanResult represents the result of typosquatting scan
type TyposquattingScanResult struct {
	TotalPackages   int                          `json:"total_packages"`
	Vulnerabilities []TyposquattingVulnerability `json:"vulnerabilities"`
	Summary         TyposquattingSummary         `json:"summary"`
}

type TyposquattingSummary struct {
	HighRisk   int `json:"high_risk"`
	MediumRisk int `json:"medium_risk"`
	LowRisk    int `json:"low_risk"`
}

// TyposquattingScanner detects potential typosquatting attacks
type TyposquattingScanner struct {
	popularPackages map[string][]string // ecosystem -> popular packages
}

// NewTyposquattingScanner creates a new typosquatting scanner
func NewTyposquattingScanner() *TyposquattingScanner {
	return &TyposquattingScanner{
		popularPackages: getPopularPackages(),
	}
}

func getPopularPackages() map[string][]string {
	return map[string][]string{
		"npm": {
			"lodash", "express", "react", "axios", "moment", "request",
			"chalk", "commander", "debug", "async", "bluebird", "underscore",
			"uuid", "mkdirp", "glob", "minimist", "yargs", "inquirer",
			"webpack", "babel", "eslint", "prettier", "jest", "mocha",
			"typescript", "jquery", "vue", "angular", "next", "nuxt",
			"socket.io", "mongoose", "sequelize", "prisma", "graphql",
			"dotenv", "cors", "body-parser", "cookie-parser", "helmet",
			"jsonwebtoken", "bcrypt", "passport", "nodemailer", "multer",
			"aws-sdk", "firebase", "stripe", "twilio", "sendgrid",
			"lodash.merge", "lodash.get", "lodash.set", "lodash.clonedeep",
			"cross-env", "rimraf", "concurrently", "nodemon", "pm2",
			"colors", "chalk", "ora", "boxen", "figlet", "gradient-string",
		},
		"pip": {
			"requests", "numpy", "pandas", "django", "flask", "tensorflow",
			"pytorch", "scikit-learn", "matplotlib", "pillow", "beautifulsoup4",
			"selenium", "scrapy", "celery", "redis", "sqlalchemy", "psycopg2",
			"boto3", "paramiko", "cryptography", "pyyaml", "jinja2", "click",
			"pytest", "black", "flake8", "mypy", "pylint", "coverage",
			"fastapi", "uvicorn", "gunicorn", "aiohttp", "httpx", "pydantic",
		},
		"go": {
			"github.com/gin-gonic/gin",
			"github.com/gorilla/mux",
			"github.com/labstack/echo",
			"github.com/gofiber/fiber",
			"gorm.io/gorm",
			"github.com/go-redis/redis",
			"github.com/stretchr/testify",
			"go.uber.org/zap",
			"github.com/spf13/cobra",
			"github.com/spf13/viper",
		},
		"composer": {
			"laravel/framework",
			"symfony/symfony",
			"guzzlehttp/guzzle",
			"monolog/monolog",
			"phpunit/phpunit",
			"doctrine/orm",
			"twig/twig",
			"vlucas/phpdotenv",
		},
	}
}

// ScanDirectory scans for potential typosquatting
func (ts *TyposquattingScanner) ScanDirectory(dirPath string) (*TyposquattingScanResult, error) {
	result := &TyposquattingScanResult{
		Vulnerabilities: []TyposquattingVulnerability{},
	}

	// Scan npm
	if _, err := os.Stat(filepath.Join(dirPath, "package.json")); err == nil {
		ts.scanNpmTyposquatting(dirPath, result)
	}

	// Scan pip
	if _, err := os.Stat(filepath.Join(dirPath, "requirements.txt")); err == nil {
		ts.scanPipTyposquatting(dirPath, result)
	}

	// Scan Go
	if _, err := os.Stat(filepath.Join(dirPath, "go.mod")); err == nil {
		ts.scanGoTyposquatting(dirPath, result)
	}

	// Scan composer
	if _, err := os.Stat(filepath.Join(dirPath, "composer.json")); err == nil {
		ts.scanComposerTyposquatting(dirPath, result)
	}

	return result, nil
}

func (ts *TyposquattingScanner) scanNpmTyposquatting(dirPath string, result *TyposquattingScanResult) {
	pkgPath := filepath.Join(dirPath, "package.json")
	data, err := os.ReadFile(pkgPath)
	if err != nil {
		return
	}

	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}

	if err := json.Unmarshal(data, &pkg); err != nil {
		return
	}

	allDeps := make([]string, 0)
	for name := range pkg.Dependencies {
		allDeps = append(allDeps, name)
	}
	for name := range pkg.DevDependencies {
		allDeps = append(allDeps, name)
	}

	result.TotalPackages += len(allDeps)
	ts.checkTyposquatting(allDeps, "npm", result)
}

func (ts *TyposquattingScanner) scanPipTyposquatting(dirPath string, result *TyposquattingScanResult) {
	reqPath := filepath.Join(dirPath, "requirements.txt")
	data, err := os.ReadFile(reqPath)
	if err != nil {
		return
	}

	var packages []string
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Extract package name
		name := strings.Split(line, "==")[0]
		name = strings.Split(name, ">=")[0]
		name = strings.Split(name, "<=")[0]
		name = strings.Split(name, "[")[0]
		packages = append(packages, strings.TrimSpace(name))
	}

	result.TotalPackages += len(packages)
	ts.checkTyposquatting(packages, "pip", result)
}

func (ts *TyposquattingScanner) scanGoTyposquatting(dirPath string, result *TyposquattingScanResult) {
	modPath := filepath.Join(dirPath, "go.mod")
	data, err := os.ReadFile(modPath)
	if err != nil {
		return
	}

	var packages []string
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
		if inRequire && line != "" && !strings.HasPrefix(line, "//") {
			parts := strings.Fields(line)
			if len(parts) >= 1 {
				packages = append(packages, parts[0])
			}
		}
	}

	result.TotalPackages += len(packages)
	ts.checkTyposquatting(packages, "go", result)
}

func (ts *TyposquattingScanner) scanComposerTyposquatting(dirPath string, result *TyposquattingScanResult) {
	composerPath := filepath.Join(dirPath, "composer.json")
	data, err := os.ReadFile(composerPath)
	if err != nil {
		return
	}

	var composer struct {
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}

	if err := json.Unmarshal(data, &composer); err != nil {
		return
	}

	var packages []string
	for name := range composer.Require {
		packages = append(packages, name)
	}
	for name := range composer.RequireDev {
		packages = append(packages, name)
	}

	result.TotalPackages += len(packages)
	ts.checkTyposquatting(packages, "composer", result)
}

func (ts *TyposquattingScanner) checkTyposquatting(packages []string, ecosystem string, result *TyposquattingScanResult) {
	popular := ts.popularPackages[ecosystem]
	if popular == nil {
		return
	}

	for _, pkg := range packages {
		pkgLower := strings.ToLower(pkg)
		
		// Skip if it's an exact match with a popular package
		isPopular := false
		for _, pop := range popular {
			if strings.EqualFold(pkg, pop) {
				isPopular = true
				break
			}
		}
		if isPopular {
			continue
		}

		// Check similarity with popular packages
		for _, pop := range popular {
			popLower := strings.ToLower(pop)
			similarity := ts.calculateSimilarity(pkgLower, popLower)
			
			// High similarity but not exact match = potential typosquatting
			if similarity >= 0.85 && similarity < 1.0 {
				risk := "MEDIUM"
				if similarity >= 0.95 {
					risk = "HIGH"
				}

				vuln := TyposquattingVulnerability{
					Package:       pkg,
					SimilarTo:     pop,
					Similarity:    similarity,
					Risk:          risk,
					Description:   ts.getTyposquattingDescription(pkg, pop),
					Ecosystem:     ecosystem,
					Recommendation: "Verifique se você realmente quis instalar '" + pkg + "' e não '" + pop + "'",
				}

				result.Vulnerabilities = append(result.Vulnerabilities, vuln)
				ts.updateSummary(&result.Summary, risk)
			}
		}
	}

	// Sort by similarity (highest first)
	sort.Slice(result.Vulnerabilities, func(i, j int) bool {
		return result.Vulnerabilities[i].Similarity > result.Vulnerabilities[j].Similarity
	})
}

// calculateSimilarity uses Levenshtein distance to calculate similarity
func (ts *TyposquattingScanner) calculateSimilarity(s1, s2 string) float64 {
	if s1 == s2 {
		return 1.0
	}

	// Also check for common typosquatting patterns
	if ts.isCommonTyposquatPattern(s1, s2) {
		return 0.95
	}

	distance := ts.levenshteinDistance(s1, s2)
	maxLen := max(len(s1), len(s2))
	if maxLen == 0 {
		return 1.0
	}

	return 1.0 - float64(distance)/float64(maxLen)
}

func (ts *TyposquattingScanner) levenshteinDistance(s1, s2 string) int {
	if len(s1) == 0 {
		return len(s2)
	}
	if len(s2) == 0 {
		return len(s1)
	}

	matrix := make([][]int, len(s1)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(s2)+1)
		matrix[i][0] = i
	}
	for j := range matrix[0] {
		matrix[0][j] = j
	}

	for i := 1; i <= len(s1); i++ {
		for j := 1; j <= len(s2); j++ {
			cost := 1
			if s1[i-1] == s2[j-1] {
				cost = 0
			}
			matrix[i][j] = min(
				matrix[i-1][j]+1,
				min(matrix[i][j-1]+1, matrix[i-1][j-1]+cost),
			)
		}
	}

	return matrix[len(s1)][len(s2)]
}

func (ts *TyposquattingScanner) isCommonTyposquatPattern(pkg, popular string) bool {
	// Common typosquatting patterns
	patterns := []struct {
		check func(string, string) bool
		name  string
	}{
		// Character swap (axois vs axios)
		{func(p, pop string) bool {
			if len(p) != len(pop) {
				return false
			}
			diffs := 0
			for i := 0; i < len(p)-1; i++ {
				if p[i] != pop[i] {
					// Check if it's a swap
					if i+1 < len(p) && p[i] == pop[i+1] && p[i+1] == pop[i] {
						return true
					}
					diffs++
				}
			}
			return diffs == 2
		}, "swap"},
		
		// Missing character (lodas vs lodash)
		{func(p, pop string) bool {
			return len(pop)-len(p) == 1 && strings.Contains(pop, p[:len(p)-1])
		}, "missing"},
		
		// Extra character (lodashs vs lodash)
		{func(p, pop string) bool {
			return len(p)-len(pop) == 1 && strings.Contains(p, pop)
		}, "extra"},
		
		// Hyphen/underscore confusion (lodash_merge vs lodash-merge)
		{func(p, pop string) bool {
			p1 := strings.ReplaceAll(p, "-", "_")
			p2 := strings.ReplaceAll(pop, "-", "_")
			return p1 == p2 && p != pop
		}, "separator"},
		
		// Number substitution (l0dash vs lodash)
		{func(p, pop string) bool {
			p1 := strings.ReplaceAll(p, "0", "o")
			p1 = strings.ReplaceAll(p1, "1", "l")
			p1 = strings.ReplaceAll(p1, "3", "e")
			return p1 == pop && p != pop
		}, "number"},
	}

	for _, pattern := range patterns {
		if pattern.check(pkg, popular) {
			return true
		}
	}

	return false
}

func (ts *TyposquattingScanner) getTyposquattingDescription(pkg, popular string) string {
	pkgLower := strings.ToLower(pkg)
	popLower := strings.ToLower(popular)

	// Detect the type of typosquatting
	if len(pkgLower) == len(popLower) {
		// Check for character swap
		swaps := 0
		for i := 0; i < len(pkgLower); i++ {
			if pkgLower[i] != popLower[i] {
				swaps++
			}
		}
		if swaps == 2 {
			return "Possível typosquatting por troca de caracteres. '" + pkg + "' é muito similar a '" + popular + "'."
		}
		return "Possível typosquatting por substituição de caracteres."
	}

	if len(pkgLower) < len(popLower) {
		return "Possível typosquatting por omissão de caractere. Você quis dizer '" + popular + "'?"
	}

	if len(pkgLower) > len(popLower) {
		return "Possível typosquatting por adição de caractere. Você quis dizer '" + popular + "'?"
	}

	return "Pacote com nome muito similar ao popular '" + popular + "'. Verifique se é o pacote correto."
}

func (ts *TyposquattingScanner) updateSummary(summary *TyposquattingSummary, risk string) {
	switch risk {
	case "HIGH":
		summary.HighRisk++
	case "MEDIUM":
		summary.MediumRisk++
	case "LOW":
		summary.LowRisk++
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
