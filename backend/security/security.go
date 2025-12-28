package security

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// ============================================================================
// AEGIS SECURITY HARDENING MODULE v8.5
// CORS, Input Validation, API Key Protection, DoS Prevention
// ============================================================================

// ============================================================================
// 1. CORS CONFIGURATION (Secure)
// ============================================================================

// AllowedOrigins returns the list of allowed origins for CORS
func GetAllowedOrigins() []string {
	// Check environment for custom origins
	customOrigins := os.Getenv("AEGIS_ALLOWED_ORIGINS")
	if customOrigins != "" {
		return strings.Split(customOrigins, ",")
	}

	// Default safe origins
	env := os.Getenv("AEGIS_ENV")
	switch env {
	case "production":
		return []string{
			"https://app.aegis.ai",
			"https://aegis.ai",
		}
	case "staging":
		return []string{
			"https://staging.aegis.ai",
			"http://localhost:3000",
		}
	default: // development
		return []string{
			"http://localhost:3000",
			"http://localhost:5173",
			"http://127.0.0.1:3000",
			"http://127.0.0.1:5173",
		}
	}
}

// ValidateOrigin checks if origin is allowed (for dynamic CORS)
func ValidateOrigin(origin string) bool {
	allowed := GetAllowedOrigins()
	for _, o := range allowed {
		if o == origin {
			return true
		}
	}
	return false
}

// ============================================================================
// 2. INPUT VALIDATION
// ============================================================================

// ValidateScanID validates and parses a scan ID parameter
func ValidateScanID(scanID string) (uint64, error) {
	if scanID == "" {
		return 0, fmt.Errorf("scan_id is required")
	}

	// Must be numeric
	id, err := strconv.ParseUint(scanID, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid scan_id: must be a positive integer")
	}

	// Reasonable bounds
	if id == 0 || id > 999999999 {
		return 0, fmt.Errorf("invalid scan_id: out of range")
	}

	return id, nil
}

// ValidateURL validates a URL input
func ValidateURL(url string) error {
	if url == "" {
		return fmt.Errorf("url is required")
	}

	// Length check
	if len(url) > 2048 {
		return fmt.Errorf("url too long (max 2048 chars)")
	}

	// Must start with http:// or https://
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return fmt.Errorf("url must start with http:// or https://")
	}

	// Basic URL pattern
	urlPattern := regexp.MustCompile(`^https?://[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+`)
	if !urlPattern.MatchString(url) {
		return fmt.Errorf("invalid url format")
	}

	return nil
}

// ValidateProjectID validates a project ID
func ValidateProjectID(projectID string) (uint64, error) {
	return ValidateScanID(projectID) // Same validation
}

// ValidateSessionID validates a session ID (UUID format)
func ValidateSessionID(sessionID string) error {
	if sessionID == "" {
		return fmt.Errorf("session_id is required")
	}

	// UUID pattern
	uuidPattern := regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
	if !uuidPattern.MatchString(sessionID) {
		return fmt.Errorf("invalid session_id format")
	}

	return nil
}

// ValidateTokenID validates an approval token ID
func ValidateTokenID(tokenID string) error {
	if tokenID == "" {
		return fmt.Errorf("token_id is required")
	}

	// Token pattern: tok_<hex>
	tokenPattern := regexp.MustCompile(`^tok_[a-f0-9]{16}$`)
	if !tokenPattern.MatchString(tokenID) {
		return fmt.Errorf("invalid token_id format")
	}

	return nil
}

// ============================================================================
// 3. API KEY PROTECTION
// ============================================================================

// APIKeyConfig holds API key configuration
type APIKeyConfig struct {
	// Never accept API keys from frontend in production
	AllowFrontendKey bool
	// Hash keys before logging
	HashKeysInLogs bool
}

var apiKeyConfig = APIKeyConfig{
	AllowFrontendKey: os.Getenv("AEGIS_ENV") != "production",
	HashKeysInLogs:   true,
}

// GetAPIKey safely retrieves API key (never from frontend in production)
func GetAPIKey(frontendKey string) (string, error) {
	// In production, NEVER accept frontend keys
	if os.Getenv("AEGIS_ENV") == "production" && frontendKey != "" {
		return "", fmt.Errorf("API keys from frontend not allowed in production")
	}

	// Try frontend key in dev/staging
	if frontendKey != "" && apiKeyConfig.AllowFrontendKey {
		return frontendKey, nil
	}

	// Use environment variable
	envKey := os.Getenv("GEMINI_API_KEY")
	if envKey == "" {
		return "", fmt.Errorf("GEMINI_API_KEY not configured")
	}

	return envKey, nil
}

// HashAPIKey creates a safe hash for logging
func HashAPIKey(key string) string {
	if len(key) < 10 {
		return "***"
	}
	hash := sha256.Sum256([]byte(key))
	return key[:4] + "..." + hex.EncodeToString(hash[:4])
}

// LogAPIKeyUsage logs API key usage safely
func LogAPIKeyUsage(key, operation string) string {
	if apiKeyConfig.HashKeysInLogs {
		return fmt.Sprintf("API Key %s used for %s", HashAPIKey(key), operation)
	}
	return fmt.Sprintf("API Key used for %s", operation)
}

// ============================================================================
// 4. DoS PREVENTION
// ============================================================================

// ContentLimits defines size limits for various content types
var ContentLimits = struct {
	MaxReportContent   int
	MaxPromptLength    int
	MaxImageSize       int
	MaxPDFLines        int
	MaxChatMessage     int
	MaxURLLength       int
	MaxPathLength      int
}{
	MaxReportContent:   100000,  // 100KB
	MaxPromptLength:    50000,   // 50KB
	MaxImageSize:       4194304, // 4MB
	MaxPDFLines:        500,
	MaxChatMessage:     10000,   // 10KB
	MaxURLLength:       2048,
	MaxPathLength:      1024,
}

// TruncateContent safely truncates content to prevent DoS
func TruncateContent(content string, maxLen int) string {
	if len(content) <= maxLen {
		return content
	}
	return content[:maxLen] + "\n\n[TRUNCATED - Content exceeded limit]"
}

// ValidateContentSize checks if content is within limits
func ValidateContentSize(content string, maxLen int, fieldName string) error {
	if len(content) > maxLen {
		return fmt.Errorf("%s exceeds maximum size (%d > %d)", fieldName, len(content), maxLen)
	}
	return nil
}

// ============================================================================
// 5. REQUEST VALIDATION MIDDLEWARE
// ============================================================================

// RequestValidator middleware for common validations
func RequestValidator() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Validate Content-Length
		if c.Request.ContentLength > 10*1024*1024 { // 10MB max
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{
				"error": "Request body too large (max 10MB)",
			})
			c.Abort()
			return
		}

		// Validate Content-Type for POST/PUT
		if c.Request.Method == "POST" || c.Request.Method == "PUT" {
			contentType := c.GetHeader("Content-Type")
			if contentType != "" && !strings.Contains(contentType, "application/json") {
				c.JSON(http.StatusUnsupportedMediaType, gin.H{
					"error": "Content-Type must be application/json",
				})
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

// ============================================================================
// 6. SECURE HEADERS MIDDLEWARE
// ============================================================================

// SecureHeaders adds security headers to responses
func SecureHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Prevent clickjacking
		c.Header("X-Frame-Options", "DENY")
		// Prevent MIME sniffing
		c.Header("X-Content-Type-Options", "nosniff")
		// XSS protection
		c.Header("X-XSS-Protection", "1; mode=block")
		// Referrer policy
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		// Content Security Policy (API)
		c.Header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")

		c.Next()
	}
}

// ============================================================================
// 7. AUDIT LOGGING
// ============================================================================

// AuditEntry represents an audit log entry
type AuditEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	IP          string    `json:"ip"`
	Method      string    `json:"method"`
	Path        string    `json:"path"`
	StatusCode  int       `json:"status_code"`
	Duration    int64     `json:"duration_ms"`
	UserAgent   string    `json:"user_agent"`
	RequestID   string    `json:"request_id"`
	Error       string    `json:"error,omitempty"`
}

// AuditLogger stores audit logs
type AuditLogger struct {
	mu      sync.RWMutex
	entries []AuditEntry
	maxSize int
}

var globalAuditLogger = &AuditLogger{
	entries: []AuditEntry{},
	maxSize: 10000,
}

// GetAuditLogger returns the global audit logger
func GetAuditLogger() *AuditLogger {
	return globalAuditLogger
}

// Log adds an audit entry
func (al *AuditLogger) Log(entry AuditEntry) {
	al.mu.Lock()
	defer al.mu.Unlock()

	al.entries = append(al.entries, entry)

	// Keep only last maxSize entries
	if len(al.entries) > al.maxSize {
		al.entries = al.entries[len(al.entries)-al.maxSize:]
	}
}

// GetRecent returns recent audit entries
func (al *AuditLogger) GetRecent(limit int) []AuditEntry {
	al.mu.RLock()
	defer al.mu.RUnlock()

	if limit <= 0 || limit > len(al.entries) {
		limit = len(al.entries)
	}

	start := len(al.entries) - limit
	if start < 0 {
		start = 0
	}

	return al.entries[start:]
}

// AuditMiddleware logs all requests
func AuditMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		requestID := fmt.Sprintf("%d", time.Now().UnixNano())
		c.Set("request_id", requestID)

		c.Next()

		entry := AuditEntry{
			Timestamp:  time.Now(),
			IP:         c.ClientIP(),
			Method:     c.Request.Method,
			Path:       c.Request.URL.Path,
			StatusCode: c.Writer.Status(),
			Duration:   time.Since(start).Milliseconds(),
			UserAgent:  c.GetHeader("User-Agent"),
			RequestID:  requestID,
		}

		// Capture error if any
		if len(c.Errors) > 0 {
			entry.Error = c.Errors.String()
		}

		globalAuditLogger.Log(entry)
	}
}

// ============================================================================
// 8. PATH TRAVERSAL PROTECTION
// ============================================================================

// ValidatePath checks for path traversal attacks
func ValidatePath(path string) error {
	if path == "" {
		return fmt.Errorf("path is required")
	}

	// Length check
	if len(path) > ContentLimits.MaxPathLength {
		return fmt.Errorf("path too long")
	}

	// Check for traversal patterns
	dangerousPatterns := []string{
		"..",
		"..\\",
		"../",
		"%2e%2e",
		"%252e%252e",
		"....//",
		"....\\\\",
	}

	lowerPath := strings.ToLower(path)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(lowerPath, pattern) {
			return fmt.Errorf("path traversal detected")
		}
	}

	// Check for sensitive paths
	sensitivePaths := []string{
		"/etc/",
		"/var/",
		"/usr/",
		"/root/",
		"c:\\windows",
		"c:\\program files",
		".ssh",
		".aws",
		".config",
		".env",
	}

	for _, sensitive := range sensitivePaths {
		if strings.Contains(lowerPath, sensitive) {
			return fmt.Errorf("access to sensitive path denied")
		}
	}

	return nil
}
