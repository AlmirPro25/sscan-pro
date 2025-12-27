package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	apiURL      string
	failOn      string
	outputFile  string
	jsonOutput  bool
	timeout     int
	apiKey      string
	model       string
)

type ScanResult struct {
	ID        uint      `json:"id"`
	Target    string    `json:"target"`
	Score     int       `json:"score"`
	CreatedAt time.Time `json:"created_at"`
}

type AIReport struct {
	ID      uint   `json:"id"`
	Content string `json:"content"`
}

type Vulnerability struct {
	Type     string
	Severity string
	CVSS     float64
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "aegis",
		Short: "AegisScan CLI - Security Scanner for CI/CD",
		Long:  `AegisScan CLI integrates security scanning into your CI/CD pipeline.`,
	}

	scanCmd := &cobra.Command{
		Use:   "scan [url]",
		Short: "Scan a target URL",
		Args:  cobra.ExactArgs(1),
		Run:   runScan,
	}

	scanCmd.Flags().StringVar(&apiURL, "api", "http://localhost:8080", "AegisScan API URL")
	scanCmd.Flags().StringVar(&failOn, "fail-on", "high", "Fail on severity: critical, high, medium, low")
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path")
	scanCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output as JSON")
	scanCmd.Flags().IntVar(&timeout, "timeout", 300, "Scan timeout in seconds")
	scanCmd.Flags().StringVar(&apiKey, "api-key", "", "Gemini API key (or use GEMINI_API_KEY env)")
	scanCmd.Flags().StringVar(&model, "model", "gemini-3-flash-preview", "AI model to use")

	// Auto-fix command
	autofixCmd := &cobra.Command{
		Use:   "autofix [scan-id]",
		Short: "Generate auto-fixes for vulnerabilities",
		Args:  cobra.ExactArgs(1),
		Run:   runAutoFix,
	}
	
	autofixCmd.Flags().StringVar(&apiURL, "api", "http://localhost:8080", "AegisScan API URL")
	autofixCmd.Flags().StringVar(&apiKey, "api-key", "", "Gemini API key")
	autofixCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output as JSON")
	
	// Create PR command
	createPRCmd := &cobra.Command{
		Use:   "create-pr [scan-id] [vuln-type]",
		Short: "Create GitHub PR with auto-fix",
		Args:  cobra.ExactArgs(2),
		Run:   runCreatePR,
	}
	
	createPRCmd.Flags().StringVar(&apiURL, "api", "http://localhost:8080", "AegisScan API URL")
	createPRCmd.Flags().StringVar(&apiKey, "api-key", "", "Gemini API key")
	createPRCmd.Flags().String("github-token", "", "GitHub personal access token (required)")
	createPRCmd.Flags().String("owner", "", "GitHub repository owner (required)")
	createPRCmd.Flags().String("repo", "", "GitHub repository name (required)")
	createPRCmd.MarkFlagRequired("github-token")
	createPRCmd.MarkFlagRequired("owner")
	createPRCmd.MarkFlagRequired("repo")

	// Local scan command
	scanLocalCmd := &cobra.Command{
		Use:   "scan-local [path]",
		Short: "Scan local code directory for vulnerabilities",
		Args:  cobra.ExactArgs(1),
		Run:   runLocalScan,
	}
	
	scanLocalCmd.Flags().StringVar(&apiURL, "api", "http://localhost:8080", "AegisScan API URL")
	scanLocalCmd.Flags().StringVar(&failOn, "fail-on", "high", "Fail on severity: critical, high, medium, low")
	scanLocalCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path")
	scanLocalCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output as JSON")
	scanLocalCmd.Flags().StringVar(&apiKey, "api-key", "", "Gemini API key")
	scanLocalCmd.Flags().BoolP("ai-report", "a", false, "Generate AI analysis report")

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(autofixCmd)
	rootCmd.AddCommand(createPRCmd)
	rootCmd.AddCommand(scanLocalCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) {
	targetURL := args[0]

	// Colors
	green := color.New(color.FgGreen, color.Bold)
	red := color.New(color.FgRed, color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)

	cyan.Printf("🛡️  AegisScan CLI v4.2\n\n")
	fmt.Printf("Target: %s\n", targetURL)
	fmt.Printf("API: %s\n", apiURL)
	fmt.Printf("Fail on: %s\n\n", failOn)

	// Step 1: Trigger scan
	cyan.Println("⏳ Starting scan...")
	scanResult, err := triggerScan(targetURL)
	if err != nil {
		red.Printf("❌ Scan failed: %v\n", err)
		os.Exit(1)
	}
	green.Printf("✅ Scan completed (ID: %d, Score: %d/100)\n\n", scanResult.ID, scanResult.Score)

	// Step 2: Generate AI report
	cyan.Println("⏳ Generating AI report...")
	report, err := generateReport(scanResult.ID)
	if err != nil {
		red.Printf("❌ Report generation failed: %v\n", err)
		os.Exit(1)
	}
	green.Println("✅ Report generated\n")

	// Step 3: Parse vulnerabilities
	vulns := parseVulnerabilities(report.Content)
	
	// Step 4: Display results
	displayResults(scanResult, vulns)

	// Step 5: Save output if requested
	if outputFile != "" {
		if err := saveOutput(outputFile, scanResult, report, vulns); err != nil {
			red.Printf("❌ Failed to save output: %v\n", err)
		} else {
			green.Printf("✅ Report saved to %s\n", outputFile)
		}
	}

	// Step 6: Check fail conditions
	exitCode := checkFailConditions(vulns, failOn)
	if exitCode != 0 {
		red.Printf("\n❌ Build failed: Found vulnerabilities at or above '%s' severity\n", failOn)
		os.Exit(exitCode)
	}

	green.Println("\n✅ Security check passed")
}

func triggerScan(targetURL string) (*ScanResult, error) {
	payload := map[string]string{"url": targetURL}
	body, _ := json.Marshal(payload)

	resp, err := http.Post(apiURL+"/api/v1/scan", "application/json", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error: %s", string(bodyBytes))
	}

	var result ScanResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func generateReport(scanID uint) (*AIReport, error) {
	key := apiKey
	if key == "" {
		key = os.Getenv("GEMINI_API_KEY")
	}

	payload := map[string]interface{}{
		"scan_id": scanID,
		"model":   model,
		"api_key": key,
	}
	body, _ := json.Marshal(payload)

	resp, err := http.Post(apiURL+"/api/v1/ai/report", "application/json", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error: %s", string(bodyBytes))
	}

	var report AIReport
	if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
		return nil, err
	}

	return &report, nil
}

func parseVulnerabilities(content string) []Vulnerability {
	vulns := []Vulnerability{}

	// Simple parsing - look for severity markers
	if contains(content, "CRITICAL") {
		vulns = append(vulns, Vulnerability{Type: "Various", Severity: "CRITICAL", CVSS: 9.0})
	}
	if contains(content, "HIGH") {
		vulns = append(vulns, Vulnerability{Type: "Various", Severity: "HIGH", CVSS: 7.5})
	}
	if contains(content, "MEDIUM") {
		vulns = append(vulns, Vulnerability{Type: "Various", Severity: "MEDIUM", CVSS: 5.3})
	}

	return vulns
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && findSubstring(s, substr)
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func displayResults(scan *ScanResult, vulns []Vulnerability) {
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	green := color.New(color.FgGreen, color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)

	cyan.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	cyan.Println("                 SECURITY SCAN RESULTS")
	cyan.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("\nTarget: %s\n", scan.Target)
	fmt.Printf("Score: %d/100\n", scan.Score)
	fmt.Printf("Scan ID: %d\n", scan.ID)
	fmt.Printf("Date: %s\n\n", scan.CreatedAt.Format("2006-01-02 15:04:05"))

	if len(vulns) == 0 {
		green.Println("✅ No vulnerabilities detected")
		return
	}

	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0

	for _, vuln := range vulns {
		switch vuln.Severity {
		case "CRITICAL":
			criticalCount++
		case "HIGH":
			highCount++
		case "MEDIUM":
			mediumCount++
		case "LOW":
			lowCount++
		}
	}

	fmt.Println("Vulnerabilities Found:")
	if criticalCount > 0 {
		red.Printf("  🔴 CRITICAL: %d\n", criticalCount)
	}
	if highCount > 0 {
		red.Printf("  🟠 HIGH: %d\n", highCount)
	}
	if mediumCount > 0 {
		yellow.Printf("  🟡 MEDIUM: %d\n", mediumCount)
	}
	if lowCount > 0 {
		green.Printf("  🟢 LOW: %d\n", lowCount)
	}

	cyan.Println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
}

func saveOutput(filename string, scan *ScanResult, report *AIReport, vulns []Vulnerability) error {
	if jsonOutput {
		data := map[string]interface{}{
			"scan":            scan,
			"vulnerabilities": vulns,
			"report":          report.Content,
		}
		file, err := os.Create(filename)
		if err != nil {
			return err
		}
		defer file.Close()

		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		return encoder.Encode(data)
	}

	// Markdown output
	return os.WriteFile(filename, []byte(report.Content), 0644)
}

func checkFailConditions(vulns []Vulnerability, failOn string) int {
	severityLevels := map[string]int{
		"critical": 4,
		"high":     3,
		"medium":   2,
		"low":      1,
	}

	threshold := severityLevels[failOn]

	for _, vuln := range vulns {
		vulnLevel := severityLevels[vuln.Severity]
		if vulnLevel >= threshold {
			return 1
		}
	}

	return 0
}


func runAutoFix(cmd *cobra.Command, args []string) {
	scanIDStr := args[0]
	scanID, err := strconv.Atoi(scanIDStr)
	if err != nil {
		fmt.Printf("❌ Invalid scan ID: %s\n", scanIDStr)
		os.Exit(1)
	}

	green := color.New(color.FgGreen, color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)

	cyan.Printf("🔧 AegisScan Auto-Fix Generator\n\n")
	fmt.Printf("Scan ID: %s\n", scanID)
	fmt.Printf("API: %s\n\n", apiURL)

	cyan.Println("⏳ Generating auto-fixes...")

	key := apiKey
	if key == "" {
		key = os.Getenv("GEMINI_API_KEY")
	}

	payload := map[string]interface{}{
		"scan_id": scanID,
		"api_key": key,
	}
	body, _ := json.Marshal(payload)

	resp, err := http.Post(apiURL+"/api/v1/autofix/generate", "application/json", bytes.NewBuffer(body))
	if err != nil {
		fmt.Printf("❌ Failed to generate fixes: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		fmt.Printf("❌ API error: %s\n", string(bodyBytes))
		os.Exit(1)
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	green.Printf("✅ Generated %v fixes\n\n", result["fixes_generated"])

	// Display fixes
	if fixes, ok := result["fixes"].([]interface{}); ok {
		for i, fixData := range fixes {
			fix := fixData.(map[string]interface{})
			
			cyan.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
			cyan.Printf("Fix #%d: %s\n", i+1, fix["VulnType"])
			cyan.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
			
			fmt.Printf("Stack: %s\n", fix["Stack"])
			fmt.Printf("File: %s\n", fix["FilePath"])
			fmt.Printf("Confidence: %s\n\n", fix["Confidence"])
			
			yellow.Println("Description:")
			fmt.Printf("%s\n\n", fix["Description"])
			
			yellow.Println("Patch:")
			fmt.Printf("```%s\n%s\n```\n\n", fix["Language"], fix["Patch"])
			
			if testCmd, ok := fix["TestCommand"].(string); ok && testCmd != "" {
				yellow.Println("Test Command:")
				fmt.Printf("```bash\n%s\n```\n\n", testCmd)
			}
		}
	}

	green.Println("✅ Auto-fix generation complete")
	fmt.Println("\nNext steps:")
	fmt.Println("1. Review the patches above")
	fmt.Println("2. Apply manually or use 'aegis create-pr' to automate")
}

func runCreatePR(cmd *cobra.Command, args []string) {
	scanID := args[0]
	vulnType := args[1]

	githubToken, _ := cmd.Flags().GetString("github-token")
	owner, _ := cmd.Flags().GetString("owner")
	repo, _ := cmd.Flags().GetString("repo")

	green := color.New(color.FgGreen, color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)
	red := color.New(color.FgRed, color.Bold)

	cyan.Printf("🚀 AegisScan PR Creator\n\n")
	fmt.Printf("Scan ID: %s\n", scanID)
	fmt.Printf("Vulnerability: %s\n", vulnType)
	fmt.Printf("Repository: %s/%s\n\n", owner, repo)

	cyan.Println("⏳ Creating pull request...")

	key := apiKey
	if key == "" {
		key = os.Getenv("GEMINI_API_KEY")
	}

	payload := map[string]interface{}{
		"scan_id":      scanID,
		"vuln_type":    vulnType,
		"github_token": githubToken,
		"owner":        owner,
		"repo":         repo,
		"api_key":      key,
	}
	body, _ := json.Marshal(payload)

	resp, err := http.Post(apiURL+"/api/v1/autofix/create-pr", "application/json", bytes.NewBuffer(body))
	if err != nil {
		red.Printf("❌ Failed to create PR: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		red.Printf("❌ API error: %s\n", string(bodyBytes))
		os.Exit(1)
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	green.Printf("✅ Pull request created successfully!\n\n")
	cyan.Printf("PR URL: %s\n", result["pr_url"])
	
	fmt.Println("\nNext steps:")
	fmt.Println("1. Review the PR on GitHub")
	fmt.Println("2. Run tests to ensure nothing breaks")
	fmt.Println("3. Merge when ready")
}


// ============================================================================
// LOCAL SCAN COMMAND
// ============================================================================

type LocalScanResult struct {
	ID              uint                `json:"id"`
	Path            string              `json:"path"`
	FilesScanned    int                 `json:"files_scanned"`
	LinesScanned    int                 `json:"lines_scanned"`
	Score           int                 `json:"score"`
	Vulnerabilities []CodeVulnerability `json:"vulnerabilities"`
	Summary         CodeScanSummary     `json:"summary"`
	CreatedAt       time.Time           `json:"created_at"`
}

type CodeVulnerability struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	CWE         string `json:"cwe"`
	OWASP       string `json:"owasp"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Code        string `json:"code"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
	Confidence  string `json:"confidence"`
}

type CodeScanSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

func runLocalScan(cmd *cobra.Command, args []string) {
	targetPath := args[0]
	generateAI, _ := cmd.Flags().GetBool("ai-report")

	// Colors
	green := color.New(color.FgGreen, color.Bold)
	red := color.New(color.FgRed, color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)

	cyan.Printf("🛡️  AegisScan CLI v6.0 - Local Code Scanner\n\n")
	fmt.Printf("Path: %s\n", targetPath)
	fmt.Printf("API: %s\n", apiURL)
	fmt.Printf("Fail on: %s\n\n", failOn)

	// Step 1: Trigger local scan
	cyan.Println("⏳ Scanning local code...")
	result, err := triggerLocalScan(targetPath)
	if err != nil {
		red.Printf("❌ Scan failed: %v\n", err)
		os.Exit(1)
	}
	green.Printf("✅ Scan completed (ID: %d, Score: %d/100)\n", result.ID, result.Score)
	fmt.Printf("   Files: %d | Lines: %d\n\n", result.FilesScanned, result.LinesScanned)

	// Step 2: Display results
	displayLocalResults(result)

	// Step 3: Generate AI report if requested
	if generateAI {
		cyan.Println("\n⏳ Generating AI analysis...")
		report, err := generateLocalAIReport(result.ID)
		if err != nil {
			yellow.Printf("⚠️ AI report failed: %v\n", err)
		} else {
			green.Println("✅ AI report generated\n")
			fmt.Println(report.Content)
		}
	}

	// Step 4: Save output if requested
	if outputFile != "" {
		if err := saveLocalOutput(outputFile, result); err != nil {
			red.Printf("❌ Failed to save output: %v\n", err)
		} else {
			green.Printf("✅ Report saved to %s\n", outputFile)
		}
	}

	// Step 5: Check fail conditions
	exitCode := checkLocalFailConditions(result.Summary, failOn)
	if exitCode != 0 {
		red.Printf("\n❌ Build failed: Found vulnerabilities at or above '%s' severity\n", failOn)
		os.Exit(exitCode)
	}

	green.Println("\n✅ Security check passed")
}

func triggerLocalScan(path string) (*LocalScanResult, error) {
	payload := map[string]string{"path": path}
	body, _ := json.Marshal(payload)

	resp, err := http.Post(apiURL+"/api/v1/scan-local", "application/json", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error: %s", string(bodyBytes))
	}

	var result LocalScanResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func generateLocalAIReport(scanID uint) (*AIReport, error) {
	key := apiKey
	if key == "" {
		key = os.Getenv("GEMINI_API_KEY")
	}

	payload := map[string]interface{}{
		"scan_id": scanID,
		"api_key": key,
	}
	body, _ := json.Marshal(payload)

	resp, err := http.Post(apiURL+"/api/v1/scan-local/ai-report", "application/json", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error: %s", string(bodyBytes))
	}

	var report AIReport
	if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
		return nil, err
	}

	return &report, nil
}

func displayLocalResults(result *LocalScanResult) {
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	green := color.New(color.FgGreen, color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)

	cyan.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	cyan.Println("              LOCAL CODE SCAN RESULTS")
	cyan.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("\nPath: %s\n", result.Path)
	fmt.Printf("Score: %d/100\n", result.Score)
	fmt.Printf("Files Scanned: %d\n", result.FilesScanned)
	fmt.Printf("Lines Scanned: %d\n\n", result.LinesScanned)

	if len(result.Vulnerabilities) == 0 {
		green.Println("✅ No vulnerabilities detected")
		return
	}

	fmt.Println("Vulnerabilities Found:")
	if result.Summary.Critical > 0 {
		red.Printf("  🔴 CRITICAL: %d\n", result.Summary.Critical)
	}
	if result.Summary.High > 0 {
		red.Printf("  🟠 HIGH: %d\n", result.Summary.High)
	}
	if result.Summary.Medium > 0 {
		yellow.Printf("  🟡 MEDIUM: %d\n", result.Summary.Medium)
	}
	if result.Summary.Low > 0 {
		green.Printf("  🟢 LOW: %d\n", result.Summary.Low)
	}

	// Show top 5 vulnerabilities
	cyan.Println("\n📋 Top Findings:")
	count := 0
	for _, vuln := range result.Vulnerabilities {
		if count >= 5 {
			break
		}
		
		severityColor := yellow
		if vuln.Severity == "CRITICAL" || vuln.Severity == "HIGH" {
			severityColor = red
		}
		
		severityColor.Printf("  [%s] ", vuln.Severity)
		fmt.Printf("%s\n", vuln.Type)
		fmt.Printf("    File: %s:%d\n", vuln.File, vuln.Line)
		fmt.Printf("    %s\n\n", vuln.Description)
		count++
	}

	if len(result.Vulnerabilities) > 5 {
		fmt.Printf("  ... and %d more\n", len(result.Vulnerabilities)-5)
	}

	cyan.Println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
}

func saveLocalOutput(filename string, result *LocalScanResult) error {
	if jsonOutput {
		file, err := os.Create(filename)
		if err != nil {
			return err
		}
		defer file.Close()

		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	}

	// Markdown output
	content := fmt.Sprintf(`# AegisScan Local Code Analysis

## Summary
- **Path**: %s
- **Score**: %d/100
- **Files Scanned**: %d
- **Lines Scanned**: %d

## Vulnerabilities

| Severity | Type | File | Line | Description |
|----------|------|------|------|-------------|
`, result.Path, result.Score, result.FilesScanned, result.LinesScanned)

	for _, v := range result.Vulnerabilities {
		content += fmt.Sprintf("| %s | %s | %s | %d | %s |\n",
			v.Severity, v.Type, v.File, v.Line, v.Description)
	}

	return os.WriteFile(filename, []byte(content), 0644)
}

func checkLocalFailConditions(summary CodeScanSummary, failOn string) int {
	severityLevels := map[string]int{
		"critical": 4,
		"high":     3,
		"medium":   2,
		"low":      1,
	}

	threshold := severityLevels[failOn]

	if threshold >= 4 && summary.Critical > 0 {
		return 1
	}
	if threshold >= 3 && summary.High > 0 {
		return 1
	}
	if threshold >= 2 && summary.Medium > 0 {
		return 1
	}
	if threshold >= 1 && summary.Low > 0 {
		return 1
	}

	return 0
}
