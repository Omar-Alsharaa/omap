package recon

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// VulnScanner handles vulnerability scanning
type VulnScanner struct {
	client       *http.Client
	vulnDB       map[string]VulnSignature
	results      map[string]*VulnScanResult
	mutex        sync.RWMutex
	userAgent    string
	timeout      time.Duration
	maxRedirects int
	threads      int
}

// VulnScanResult contains vulnerability scan results
type VulnScanResult struct {
	Target          string            `json:"target"`
	Vulnerabilities []Vulnerability   `json:"vulnerabilities"`
	SecurityIssues  []SecurityIssue   `json:"securityIssues"`
	Misconfigs      []Misconfiguration `json:"misconfigurations"`
	ExposedFiles    []ExposedFile     `json:"exposedFiles"`
	WeakCiphers     []WeakCipher      `json:"weakCiphers"`
	Headers         map[string]string `json:"headers"`
	RiskScore       int               `json:"riskScore"`
	SeverityCount   SeverityCount     `json:"severityCount"`
	Timestamp       time.Time         `json:"timestamp"`
	ScanDuration    time.Duration     `json:"scanDuration"`
	Errors          []string          `json:"errors,omitempty"`
}

// Vulnerability represents a detected vulnerability
type Vulnerability struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	CVSS        float64   `json:"cvss,omitempty"`
	CVE         string    `json:"cve,omitempty"`
	CWE         string    `json:"cwe,omitempty"`
	Category    string    `json:"category"`
	Evidence    string    `json:"evidence"`
	URL         string    `json:"url"`
	Method      string    `json:"method"`
	Payload     string    `json:"payload,omitempty"`
	Response    string    `json:"response,omitempty"`
	Remediation string    `json:"remediation"`
	References  []string  `json:"references,omitempty"`
	Confidence  int       `json:"confidence"`
	Timestamp   time.Time `json:"timestamp"`
}

// SecurityIssue represents a security configuration issue
type SecurityIssue struct {
	Type        string   `json:"type"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Evidence    string   `json:"evidence"`
	Impact      string   `json:"impact"`
	Solution    string   `json:"solution"`
	References  []string `json:"references,omitempty"`
}

// Misconfiguration represents a server misconfiguration
type Misconfiguration struct {
	Type        string `json:"type"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Evidence    string `json:"evidence"`
	Risk        string `json:"risk"`
	Fix         string `json:"fix"`
}

// ExposedFile represents an exposed sensitive file
type ExposedFile struct {
	Path        string `json:"path"`
	URL         string `json:"url"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Size        int64  `json:"size"`
	StatusCode  int    `json:"statusCode"`
	ContentType string `json:"contentType"`
	Risk        string `json:"risk"`
}

// WeakCipher represents a weak SSL/TLS cipher
type WeakCipher struct {
	Cipher      string   `json:"cipher"`
	Protocol    string   `json:"protocol"`
	KeySize     int      `json:"keySize"`
	Severity    string   `json:"severity"`
	Weaknesses  []string `json:"weaknesses"`
	Description string   `json:"description"`
}

// SeverityCount tracks vulnerability counts by severity
type SeverityCount struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// VulnSignature defines how to detect a vulnerability
type VulnSignature struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Severity    string            `json:"severity"`
	CVSS        float64           `json:"cvss"`
	CVE         string            `json:"cve"`
	CWE         string            `json:"cwe"`
	Category    string            `json:"category"`
	Method      string            `json:"method"`
	Path        string            `json:"path"`
	Headers     map[string]string `json:"headers"`
	Payload     string            `json:"payload"`
	Matches     []string          `json:"matches"`
	Negative    []string          `json:"negative"`
	StatusCodes []int             `json:"statusCodes"`
	Remediation string            `json:"remediation"`
	References  []string          `json:"references"`
}

// VulnScanConfig holds configuration for vulnerability scanning
type VulnScanConfig struct {
	UserAgent       string        `json:"userAgent"`
	Timeout         time.Duration `json:"timeout"`
	MaxRedirects    int           `json:"maxRedirects"`
	Threads         int           `json:"threads"`
	FollowRedirects bool          `json:"followRedirects"`
	VerifySSL       bool          `json:"verifySSL"`
	ScanSSL         bool          `json:"scanSSL"`
	ScanHeaders     bool          `json:"scanHeaders"`
	ScanFiles       bool          `json:"scanFiles"`
	ScanInjection   bool          `json:"scanInjection"`
	CustomPayloads  []string      `json:"customPayloads"`
	CustomHeaders   map[string]string `json:"customHeaders"`
	ExcludePaths    []string      `json:"excludePaths"`
}

// NewVulnScanner creates a new vulnerability scanner
func NewVulnScanner(config VulnScanConfig) *VulnScanner {
	userAgent := config.UserAgent
	if userAgent == "" {
		userAgent = "OMAP/1.0 (Vulnerability Scanner)"
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}

	maxRedirects := config.MaxRedirects
	if maxRedirects == 0 {
		maxRedirects = 3
	}

	threads := config.Threads
	if threads == 0 {
		threads = 10
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: !config.VerifySSL,
			},
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 20,
			IdleConnTimeout:     30 * time.Second,
		},
	}

	if !config.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	scanner := &VulnScanner{
		client:       client,
		vulnDB:       make(map[string]VulnSignature),
		results:      make(map[string]*VulnScanResult),
		userAgent:    userAgent,
		timeout:      timeout,
		maxRedirects: maxRedirects,
		threads:      threads,
	}

	// Load built-in vulnerability signatures
	scanner.loadBuiltinSignatures()

	return scanner
}

// ScanTarget performs a comprehensive vulnerability scan on a target
func (vs *VulnScanner) ScanTarget(target string, config VulnScanConfig) (*VulnScanResult, error) {
	start := time.Now()

	result := &VulnScanResult{
		Target:          target,
		Vulnerabilities: make([]Vulnerability, 0),
		SecurityIssues:  make([]SecurityIssue, 0),
		Misconfigs:      make([]Misconfiguration, 0),
		ExposedFiles:    make([]ExposedFile, 0),
		WeakCiphers:     make([]WeakCipher, 0),
		Headers:         make(map[string]string),
		Timestamp:       time.Now(),
		Errors:          make([]string, 0),
	}

	// Perform initial request to get headers
	resp, err := vs.makeRequest("GET", target, nil, config.CustomHeaders)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Initial request failed: %v", err))
	} else {
		defer resp.Body.Close()
		// Extract headers
		for key, values := range resp.Header {
			if len(values) > 0 {
				result.Headers[key] = values[0]
			}
		}
	}

	// Scan for security headers
	if config.ScanHeaders {
		vs.scanSecurityHeaders(result)
	}

	// Scan for SSL/TLS issues
	if config.ScanSSL {
		vs.scanSSLIssues(result, target)
	}

	// Scan for exposed files
	if config.ScanFiles {
		vs.scanExposedFiles(result, target, config)
	}

	// Scan for injection vulnerabilities
	if config.ScanInjection {
		vs.scanInjectionVulns(result, target, config)
	}

	// Scan for misconfigurations
	vs.scanMisconfigurations(result, target, config)

	// Calculate risk score and severity counts
	vs.calculateRiskScore(result)
	vs.countSeverities(result)

	// Sort vulnerabilities by severity and CVSS
	vs.sortVulnerabilities(result)

	result.ScanDuration = time.Since(start)

	// Store result
	vs.mutex.Lock()
	vs.results[target] = result
	vs.mutex.Unlock()

	return result, nil
}

// loadBuiltinSignatures loads built-in vulnerability signatures
func (vs *VulnScanner) loadBuiltinSignatures() {
	// SQL Injection
	vs.vulnDB["sql-injection-error"] = VulnSignature{
		ID:          "sql-injection-error",
		Name:        "SQL Injection (Error-based)",
		Description: "SQL injection vulnerability detected through error messages",
		Severity:    "High",
		CVSS:        8.5,
		CWE:         "CWE-89",
		Category:    "Injection",
		Method:      "GET",
		Payload:     "'",
		Matches: []string{
			"SQL syntax.*MySQL",
			"Warning.*mysql_.*",
			"valid MySQL result",
			"PostgreSQL.*ERROR",
			"Warning.*pg_.*",
			"valid PostgreSQL result",
			"Microsoft OLE DB Provider for ODBC Drivers",
			"Microsoft JET Database Engine",
			"ORA-[0-9][0-9][0-9][0-9]",
			"Oracle error",
			"SQLite.*error",
		},
		Remediation: "Use parameterized queries and input validation",
		References:  []string{"https://owasp.org/www-community/attacks/SQL_Injection"},
	}

	// XSS
	vs.vulnDB["xss-reflected"] = VulnSignature{
		ID:          "xss-reflected",
		Name:        "Cross-Site Scripting (Reflected)",
		Description: "Reflected XSS vulnerability detected",
		Severity:    "Medium",
		CVSS:        6.1,
		CWE:         "CWE-79",
		Category:    "XSS",
		Method:      "GET",
		Payload:     "<script>alert('XSS')</script>",
		Matches:     []string{`<script>alert\('XSS'\)</script>`},
		Remediation: "Implement proper input validation and output encoding",
		References:  []string{"https://owasp.org/www-community/attacks/xss/"},
	}

	// Directory Traversal
	vs.vulnDB["directory-traversal"] = VulnSignature{
		ID:          "directory-traversal",
		Name:        "Directory Traversal",
		Description: "Directory traversal vulnerability detected",
		Severity:    "High",
		CVSS:        7.5,
		CWE:         "CWE-22",
		Category:    "Path Traversal",
		Method:      "GET",
		Payload:     "../../../etc/passwd",
		Matches: []string{
			"root:.*:0:0:",
			"daemon:.*:1:1:",
			"bin:.*:2:2:",
			"\\[boot loader\\]",
			"\\[operating systems\\]",
		},
		Remediation: "Implement proper input validation and use whitelisting",
		References:  []string{"https://owasp.org/www-community/attacks/Path_Traversal"},
	}

	// Command Injection
	vs.vulnDB["command-injection"] = VulnSignature{
		ID:          "command-injection",
		Name:        "Command Injection",
		Description: "Command injection vulnerability detected",
		Severity:    "Critical",
		CVSS:        9.8,
		CWE:         "CWE-78",
		Category:    "Injection",
		Method:      "GET",
		Payload:     "; id",
		Matches: []string{
			"uid=[0-9]+.*gid=[0-9]+",
			"root:.*:0:0:",
			"SYSTEM\\\\.*\\\\.*",
		},
		Remediation: "Avoid system calls with user input, use safe APIs",
		References:  []string{"https://owasp.org/www-community/attacks/Command_Injection"},
	}

	// LDAP Injection
	vs.vulnDB["ldap-injection"] = VulnSignature{
		ID:          "ldap-injection",
		Name:        "LDAP Injection",
		Description: "LDAP injection vulnerability detected",
		Severity:    "Medium",
		CVSS:        6.5,
		CWE:         "CWE-90",
		Category:    "Injection",
		Method:      "GET",
		Payload:     "*)(uid=*))(|(uid=*",
		Matches: []string{
			"javax.naming.NameNotFoundException",
			"LDAPException",
			"com.sun.jndi.ldap",
		},
		Remediation: "Use parameterized LDAP queries and input validation",
		References:  []string{"https://owasp.org/www-community/attacks/LDAP_Injection"},
	}
}

// scanSecurityHeaders scans for missing or weak security headers
func (vs *VulnScanner) scanSecurityHeaders(result *VulnScanResult) {
	headers := result.Headers

	// Check for missing security headers
	securityHeaders := map[string]string{
		"X-Frame-Options":           "Clickjacking protection",
		"X-Content-Type-Options":    "MIME type sniffing protection",
		"X-XSS-Protection":          "XSS protection",
		"Strict-Transport-Security": "HTTPS enforcement",
		"Content-Security-Policy":   "Content injection protection",
		"Referrer-Policy":           "Referrer information control",
	}

	for header, description := range securityHeaders {
		if _, exists := headers[header]; !exists {
			result.SecurityIssues = append(result.SecurityIssues, SecurityIssue{
				Type:        "Missing Security Header",
				Title:       fmt.Sprintf("Missing %s Header", header),
				Description: fmt.Sprintf("The %s header is missing, which provides %s", header, description),
				Severity:    "Medium",
				Evidence:    fmt.Sprintf("Header '%s' not found in response", header),
				Impact:      "Reduced security posture",
				Solution:    fmt.Sprintf("Add the %s header to all responses", header),
			})
		}
	}

	// Check for weak security header values
	if xss, exists := headers["X-XSS-Protection"]; exists && xss == "0" {
		result.SecurityIssues = append(result.SecurityIssues, SecurityIssue{
			Type:        "Weak Security Header",
			Title:       "X-XSS-Protection Disabled",
			Description: "XSS protection is explicitly disabled",
			Severity:    "Medium",
			Evidence:    "X-XSS-Protection: 0",
			Impact:      "Increased XSS vulnerability",
			Solution:    "Set X-XSS-Protection to '1; mode=block'",
		})
	}

	// Check for information disclosure headers
	infoHeaders := []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"}
	for _, header := range infoHeaders {
		if value, exists := headers[header]; exists {
			result.SecurityIssues = append(result.SecurityIssues, SecurityIssue{
				Type:        "Information Disclosure",
				Title:       fmt.Sprintf("%s Header Disclosure", header),
				Description: "Server information is disclosed in HTTP headers",
				Severity:    "Low",
				Evidence:    fmt.Sprintf("%s: %s", header, value),
				Impact:      "Information leakage for attackers",
				Solution:    fmt.Sprintf("Remove or obfuscate the %s header", header),
			})
		}
	}
}

// scanSSLIssues scans for SSL/TLS configuration issues
func (vs *VulnScanner) scanSSLIssues(result *VulnScanResult, target string) {
	// This would require more advanced SSL/TLS testing
	// For now, we'll check basic SSL configuration
	resp, err := vs.makeRequest("GET", target, nil, nil)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.TLS != nil {
		// Check for weak TLS versions
		if resp.TLS.Version < tls.VersionTLS12 {
			result.WeakCiphers = append(result.WeakCiphers, WeakCipher{
				Cipher:      "N/A",
				Protocol:    vs.getTLSVersion(resp.TLS.Version),
				Severity:    "High",
				Weaknesses:  []string{"Outdated TLS version"},
				Description: "Server supports outdated TLS version",
			})
		}

		// Check certificate validity
		if len(resp.TLS.PeerCertificates) > 0 {
			cert := resp.TLS.PeerCertificates[0]
			if time.Now().After(cert.NotAfter) {
				result.SecurityIssues = append(result.SecurityIssues, SecurityIssue{
					Type:        "SSL Certificate",
					Title:       "Expired SSL Certificate",
					Description: "The SSL certificate has expired",
					Severity:    "High",
					Evidence:    fmt.Sprintf("Certificate expired on %s", cert.NotAfter.Format("2006-01-02")),
					Impact:      "Users will receive security warnings",
					Solution:    "Renew the SSL certificate",
				})
			}

			// Check for self-signed certificate
			if cert.Subject.String() == cert.Issuer.String() {
				result.SecurityIssues = append(result.SecurityIssues, SecurityIssue{
					Type:        "SSL Certificate",
					Title:       "Self-Signed Certificate",
					Description: "The SSL certificate is self-signed",
					Severity:    "Medium",
					Evidence:    "Subject equals Issuer",
					Impact:      "Users will receive security warnings",
					Solution:    "Use a certificate from a trusted CA",
				})
			}
		}
	}
}

// scanExposedFiles scans for exposed sensitive files
func (vs *VulnScanner) scanExposedFiles(result *VulnScanResult, target string, config VulnScanConfig) {
	sensitiveFiles := []string{
		".env",
		".git/config",
		".svn/entries",
		"web.config",
		"wp-config.php",
		"config.php",
		"database.yml",
		"settings.py",
		"application.properties",
		"robots.txt",
		"sitemap.xml",
		"crossdomain.xml",
		"clientaccesspolicy.xml",
		"phpinfo.php",
		"info.php",
		"test.php",
		"backup.sql",
		"dump.sql",
		"admin/",
		"administrator/",
		"phpmyadmin/",
		"adminer.php",
	}

	for _, file := range sensitiveFiles {
		fileURL := strings.TrimSuffix(target, "/") + "/" + file
		resp, err := vs.makeRequest("GET", fileURL, nil, config.CustomHeaders)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			body, _ := io.ReadAll(resp.Body)
			contentType := resp.Header.Get("Content-Type")

			severity := "Medium"
			risk := "Information disclosure"

			// Determine severity based on file type
			if strings.Contains(file, "config") || strings.Contains(file, ".env") {
				severity = "High"
				risk = "Configuration and credentials exposure"
			} else if strings.Contains(file, "admin") {
				severity = "High"
				risk = "Administrative interface exposure"
			} else if strings.Contains(file, ".git") || strings.Contains(file, ".svn") {
				severity = "High"
				risk = "Source code exposure"
			}

			result.ExposedFiles = append(result.ExposedFiles, ExposedFile{
				Path:        file,
				URL:         fileURL,
				Type:        vs.getFileType(file),
				Description: fmt.Sprintf("Sensitive file '%s' is publicly accessible", file),
				Severity:    severity,
				Size:        int64(len(body)),
				StatusCode:  resp.StatusCode,
				ContentType: contentType,
				Risk:        risk,
			})
		}
	}
}

// scanInjectionVulns scans for injection vulnerabilities
func (vs *VulnScanner) scanInjectionVulns(result *VulnScanResult, target string, config VulnScanConfig) {
	// Test for SQL injection
	vs.testSQLInjection(result, target, config)

	// Test for XSS
	vs.testXSS(result, target, config)

	// Test for command injection
	vs.testCommandInjection(result, target, config)

	// Test for LDAP injection
	vs.testLDAPInjection(result, target, config)
}

// testSQLInjection tests for SQL injection vulnerabilities
func (vs *VulnScanner) testSQLInjection(result *VulnScanResult, target string, config VulnScanConfig) {
	payloads := []string{"'", `"'`, "1' OR '1'='1", `1" OR "1"="1`, "'; DROP TABLE users; --"}

	for _, payload := range payloads {
		testURL := target + "?id=" + payload
		resp, err := vs.makeRequest("GET", testURL, nil, config.CustomHeaders)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)

		// Check for SQL error patterns
		if sig, exists := vs.vulnDB["sql-injection-error"]; exists {
			for _, pattern := range sig.Matches {
				if matched, _ := regexp.MatchString(pattern, bodyStr); matched {
					result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
						ID:          sig.ID,
						Name:        sig.Name,
						Description: sig.Description,
						Severity:    sig.Severity,
						CVSS:        sig.CVSS,
						CWE:         sig.CWE,
						Category:    sig.Category,
						Evidence:    pattern,
						URL:         testURL,
						Method:      "GET",
						Payload:     payload,
						Response:    vs.truncateString(bodyStr, 500),
						Remediation: sig.Remediation,
						References:  sig.References,
						Confidence:  85,
						Timestamp:   time.Now(),
					})
					break
				}
			}
		}
	}
}

// testXSS tests for XSS vulnerabilities
func (vs *VulnScanner) testXSS(result *VulnScanResult, target string, config VulnScanConfig) {
	payloads := []string{
		"<script>alert('XSS')</script>",
		"<img src=x onerror=alert('XSS')>",
		"javascript:alert('XSS')",
		"<svg onload=alert('XSS')>",
	}

	for _, payload := range payloads {
		testURL := target + "?q=" + payload
		resp, err := vs.makeRequest("GET", testURL, nil, config.CustomHeaders)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)

		// Check if payload is reflected
		if strings.Contains(bodyStr, payload) {
			if sig, exists := vs.vulnDB["xss-reflected"]; exists {
				result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
					ID:          sig.ID,
					Name:        sig.Name,
					Description: sig.Description,
					Severity:    sig.Severity,
					CVSS:        sig.CVSS,
					CWE:         sig.CWE,
					Category:    sig.Category,
					Evidence:    "Payload reflected in response",
					URL:         testURL,
					Method:      "GET",
					Payload:     payload,
					Response:    vs.truncateString(bodyStr, 500),
					Remediation: sig.Remediation,
					References:  sig.References,
					Confidence:  80,
					Timestamp:   time.Now(),
				})
				break
			}
		}
	}
}

// testCommandInjection tests for command injection vulnerabilities
func (vs *VulnScanner) testCommandInjection(result *VulnScanResult, target string, config VulnScanConfig) {
	payloads := []string{"; id", "| id", "&& id", "; whoami", "| whoami"}

	for _, payload := range payloads {
		testURL := target + "?cmd=" + payload
		resp, err := vs.makeRequest("GET", testURL, nil, config.CustomHeaders)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)

		// Check for command execution patterns
		if sig, exists := vs.vulnDB["command-injection"]; exists {
			for _, pattern := range sig.Matches {
				if matched, _ := regexp.MatchString(pattern, bodyStr); matched {
					result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
						ID:          sig.ID,
						Name:        sig.Name,
						Description: sig.Description,
						Severity:    sig.Severity,
						CVSS:        sig.CVSS,
						CWE:         sig.CWE,
						Category:    sig.Category,
						Evidence:    pattern,
						URL:         testURL,
						Method:      "GET",
						Payload:     payload,
						Response:    vs.truncateString(bodyStr, 500),
						Remediation: sig.Remediation,
						References:  sig.References,
						Confidence:  90,
						Timestamp:   time.Now(),
					})
					break
				}
			}
		}
	}
}

// testLDAPInjection tests for LDAP injection vulnerabilities
func (vs *VulnScanner) testLDAPInjection(result *VulnScanResult, target string, config VulnScanConfig) {
	payloads := []string{"*)(uid=*))(|(uid=*", "*)(|(mail=*))", "*))%00"}

	for _, payload := range payloads {
		testURL := target + "?user=" + payload
		resp, err := vs.makeRequest("GET", testURL, nil, config.CustomHeaders)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)

		// Check for LDAP error patterns
		if sig, exists := vs.vulnDB["ldap-injection"]; exists {
			for _, pattern := range sig.Matches {
				if matched, _ := regexp.MatchString(pattern, bodyStr); matched {
					result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
						ID:          sig.ID,
						Name:        sig.Name,
						Description: sig.Description,
						Severity:    sig.Severity,
						CVSS:        sig.CVSS,
						CWE:         sig.CWE,
						Category:    sig.Category,
						Evidence:    pattern,
						URL:         testURL,
						Method:      "GET",
						Payload:     payload,
						Response:    vs.truncateString(bodyStr, 500),
						Remediation: sig.Remediation,
						References:  sig.References,
						Confidence:  75,
						Timestamp:   time.Now(),
					})
					break
				}
			}
		}
	}
}

// scanMisconfigurations scans for common misconfigurations
func (vs *VulnScanner) scanMisconfigurations(result *VulnScanResult, target string, config VulnScanConfig) {
	// Check for directory listing
	resp, err := vs.makeRequest("GET", target, nil, config.CustomHeaders)
	if err == nil {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)

		if strings.Contains(bodyStr, "Index of /") || strings.Contains(bodyStr, "Directory Listing") {
			result.Misconfigs = append(result.Misconfigs, Misconfiguration{
				Type:        "Directory Listing",
				Title:       "Directory Listing Enabled",
				Description: "Server allows directory browsing",
				Severity:    "Medium",
				Evidence:    "Directory listing detected in response",
				Risk:        "Information disclosure",
				Fix:         "Disable directory listing in web server configuration",
			})
		}
	}

	// Check for HTTP methods
	resp, err = vs.makeRequest("OPTIONS", target, nil, config.CustomHeaders)
	if err == nil {
		defer resp.Body.Close()
		if allow := resp.Header.Get("Allow"); allow != "" {
			dangerousMethods := []string{"PUT", "DELETE", "TRACE", "CONNECT"}
			for _, method := range dangerousMethods {
				if strings.Contains(strings.ToUpper(allow), method) {
					result.Misconfigs = append(result.Misconfigs, Misconfiguration{
						Type:        "HTTP Methods",
						Title:       fmt.Sprintf("Dangerous HTTP Method: %s", method),
						Description: fmt.Sprintf("Server allows %s method", method),
						Severity:    "Medium",
						Evidence:    fmt.Sprintf("Allow: %s", allow),
						Risk:        "Potential for unauthorized actions",
						Fix:         fmt.Sprintf("Disable %s method if not required", method),
					})
				}
			}
		}
	}
}

// Helper functions
func (vs *VulnScanner) makeRequest(method, url string, body io.Reader, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", vs.userAgent)
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	return vs.client.Do(req)
}

func (vs *VulnScanner) getTLSVersion(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "Unknown"
	}
}

func (vs *VulnScanner) getFileType(filename string) string {
	if strings.Contains(filename, "config") {
		return "Configuration"
	} else if strings.Contains(filename, "admin") {
		return "Administrative"
	} else if strings.Contains(filename, ".git") || strings.Contains(filename, ".svn") {
		return "Version Control"
	} else if strings.HasSuffix(filename, ".php") {
		return "PHP Script"
	} else if strings.HasSuffix(filename, ".sql") {
		return "Database"
	}
	return "Other"
}

func (vs *VulnScanner) truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func (vs *VulnScanner) calculateRiskScore(result *VulnScanResult) {
	score := 0
	for _, vuln := range result.Vulnerabilities {
		switch vuln.Severity {
		case "Critical":
			score += 100
		case "High":
			score += 50
		case "Medium":
			score += 25
		case "Low":
			score += 10
		case "Info":
			score += 5
		}
	}

	for _, issue := range result.SecurityIssues {
		switch issue.Severity {
		case "High":
			score += 30
		case "Medium":
			score += 15
		case "Low":
			score += 5
		}
	}

	for _, misc := range result.Misconfigs {
		switch misc.Severity {
		case "High":
			score += 20
		case "Medium":
			score += 10
		case "Low":
			score += 5
		}
	}

	result.RiskScore = score
}

func (vs *VulnScanner) countSeverities(result *VulnScanResult) {
	for _, vuln := range result.Vulnerabilities {
		switch vuln.Severity {
		case "Critical":
			result.SeverityCount.Critical++
		case "High":
			result.SeverityCount.High++
		case "Medium":
			result.SeverityCount.Medium++
		case "Low":
			result.SeverityCount.Low++
		case "Info":
			result.SeverityCount.Info++
		}
	}
}

func (vs *VulnScanner) sortVulnerabilities(result *VulnScanResult) {
	sort.Slice(result.Vulnerabilities, func(i, j int) bool {
		severityOrder := map[string]int{
			"Critical": 5,
			"High":     4,
			"Medium":   3,
			"Low":      2,
			"Info":     1,
		}

		iSev := severityOrder[result.Vulnerabilities[i].Severity]
		jSev := severityOrder[result.Vulnerabilities[j].Severity]

		if iSev != jSev {
			return iSev > jSev
		}

		return result.Vulnerabilities[i].CVSS > result.Vulnerabilities[j].CVSS
	})
}

// LoadVulnSignatures loads vulnerability signatures from JSON
func (vs *VulnScanner) LoadVulnSignatures(data []byte) error {
	var signatures map[string]VulnSignature
	if err := json.Unmarshal(data, &signatures); err != nil {
		return err
	}

	vs.mutex.Lock()
	for id, sig := range signatures {
		vs.vulnDB[id] = sig
	}
	vs.mutex.Unlock()

	return nil
}

// GetResult returns the vulnerability scan result for a target
func (vs *VulnScanner) GetResult(target string) *VulnScanResult {
	vs.mutex.RLock()
	defer vs.mutex.RUnlock()
	return vs.results[target]
}

// GetAllResults returns all vulnerability scan results
func (vs *VulnScanner) GetAllResults() map[string]*VulnScanResult {
	vs.mutex.RLock()
	defer vs.mutex.RUnlock()

	results := make(map[string]*VulnScanResult)
	for k, v := range vs.results {
		results[k] = v
	}
	return results
}

// Clear clears all vulnerability scan results
func (vs *VulnScanner) Clear() {
	vs.mutex.Lock()
	defer vs.mutex.Unlock()
	vs.results = make(map[string]*VulnScanResult)
}