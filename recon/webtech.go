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

// WebTechDetector handles web technology detection
type WebTechDetector struct {
	client      *http.Client
	signatures  map[string]TechSignature
	results     map[string]*WebTechResult
	mutex       sync.RWMutex
	userAgent   string
	timeout     time.Duration
	maxRedirects int
}

// WebTechResult contains detected web technologies
type WebTechResult struct {
	URL          string              `json:"url"`
	StatusCode   int                 `json:"statusCode"`
	Title        string              `json:"title,omitempty"`
	Server       string              `json:"server,omitempty"`
	Technologies []DetectedTech      `json:"technologies"`
	Headers      map[string]string   `json:"headers"`
	Cookies      []CookieInfo        `json:"cookies,omitempty"`
	SSL          *SSLInfo            `json:"ssl,omitempty"`
	Security     *SecurityHeaders    `json:"security,omitempty"`
	Performance  *PerformanceMetrics `json:"performance,omitempty"`
	Timestamp    time.Time           `json:"timestamp"`
	Errors       []string            `json:"errors,omitempty"`
}

// DetectedTech represents a detected technology
type DetectedTech struct {
	Name        string   `json:"name"`
	Version     string   `json:"version,omitempty"`
	Category    string   `json:"category"`
	Confidence  int      `json:"confidence"`
	Source      string   `json:"source"`
	Description string   `json:"description,omitempty"`
	Website     string   `json:"website,omitempty"`
	CPE         string   `json:"cpe,omitempty"`
	Icon        string   `json:"icon,omitempty"`
}

// TechSignature defines how to detect a technology
type TechSignature struct {
	Name        string            `json:"name"`
	Category    string            `json:"category"`
	Description string            `json:"description"`
	Website     string            `json:"website"`
	Icon        string            `json:"icon"`
	Headers     map[string]string `json:"headers"`
	HTML        []string          `json:"html"`
	Script      []string          `json:"script"`
	Meta        map[string]string `json:"meta"`
	Cookies     []string          `json:"cookies"`
	URL         []string          `json:"url"`
	Implies     []string          `json:"implies"`
	Excludes    []string          `json:"excludes"`
	CPE         string            `json:"cpe"`
}

// CookieInfo represents cookie information
type CookieInfo struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain,omitempty"`
	Path     string `json:"path,omitempty"`
	Secure   bool   `json:"secure"`
	HttpOnly bool   `json:"httpOnly"`
	SameSite string `json:"sameSite,omitempty"`
}

// SSLInfo contains SSL/TLS information
type SSLInfo struct {
	Enabled       bool      `json:"enabled"`
	Version       string    `json:"version,omitempty"`
	Cipher        string    `json:"cipher,omitempty"`
	Certificate   *CertInfo `json:"certificate,omitempty"`
	HSTS          bool      `json:"hsts"`
	HSTSMaxAge    int       `json:"hstsMaxAge,omitempty"`
	Validation    string    `json:"validation,omitempty"`
	Vulnerable    []string  `json:"vulnerable,omitempty"`
}

// CertInfo contains certificate information
type CertInfo struct {
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer"`
	NotBefore     time.Time `json:"notBefore"`
	NotAfter      time.Time `json:"notAfter"`
	SerialNumber  string    `json:"serialNumber"`
	Signature     string    `json:"signature"`
	SANs          []string  `json:"sans,omitempty"`
	SelfSigned    bool      `json:"selfSigned"`
	Expired       bool      `json:"expired"`
	DaysUntilExp  int       `json:"daysUntilExpiry"`
}

// SecurityHeaders contains security header analysis
type SecurityHeaders struct {
	CSP                    string `json:"csp,omitempty"`
	XFrameOptions          string `json:"xFrameOptions,omitempty"`
	XContentTypeOptions    string `json:"xContentTypeOptions,omitempty"`
	XXSSProtection         string `json:"xXSSProtection,omitempty"`
	ReferrerPolicy         string `json:"referrerPolicy,omitempty"`
	PermissionsPolicy      string `json:"permissionsPolicy,omitempty"`
	ExpectCT               string `json:"expectCT,omitempty"`
	SecurityScore          int    `json:"securityScore"`
	MissingHeaders         []string `json:"missingHeaders,omitempty"`
	VulnerableHeaders      []string `json:"vulnerableHeaders,omitempty"`
}

// PerformanceMetrics contains performance information
type PerformanceMetrics struct {
	ResponseTime   time.Duration `json:"responseTime"`
	ContentLength  int64         `json:"contentLength"`
	Compression    string        `json:"compression,omitempty"`
	CacheControl   string        `json:"cacheControl,omitempty"`
	ETag           string        `json:"etag,omitempty"`
	LastModified   string        `json:"lastModified,omitempty"`
}

// WebTechConfig holds configuration for web technology detection
type WebTechConfig struct {
	UserAgent     string        `json:"userAgent"`
	Timeout       time.Duration `json:"timeout"`
	MaxRedirects  int           `json:"maxRedirects"`
	FollowRedirects bool        `json:"followRedirects"`
	VerifySSL     bool          `json:"verifySSL"`
	AnalyzeSSL    bool          `json:"analyzeSSL"`
	AnalyzeSecurity bool        `json:"analyzeSecurity"`
	AnalyzePerformance bool     `json:"analyzePerformance"`
	CustomHeaders map[string]string `json:"customHeaders"`
}

// NewWebTechDetector creates a new web technology detector
func NewWebTechDetector(config WebTechConfig) *WebTechDetector {
	userAgent := config.UserAgent
	if userAgent == "" {
		userAgent = "OMAP/1.0 (Web Technology Scanner)"
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	maxRedirects := config.MaxRedirects
	if maxRedirects == 0 {
		maxRedirects = 5
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// #nosec G402 - InsecureSkipVerify is configurable via VerifySSL setting
				InsecureSkipVerify: !config.VerifySSL,
			},
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     30 * time.Second,
		},
	}

	if !config.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	detector := &WebTechDetector{
		client:       client,
		signatures:   make(map[string]TechSignature),
		results:      make(map[string]*WebTechResult),
		userAgent:    userAgent,
		timeout:      timeout,
		maxRedirects: maxRedirects,
	}

	// Load built-in signatures
	detector.loadBuiltinSignatures()

	return detector
}

// DetectTechnologies analyzes a URL for web technologies
func (wtd *WebTechDetector) DetectTechnologies(url string, config WebTechConfig) (*WebTechResult, error) {
	start := time.Now()

	result := &WebTechResult{
		URL:          url,
		Technologies: make([]DetectedTech, 0),
		Headers:      make(map[string]string),
		Cookies:      make([]CookieInfo, 0),
		Timestamp:    time.Now(),
		Errors:       make([]string, 0),
	}

	// Create request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// Set headers
	req.Header.Set("User-Agent", wtd.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Connection", "keep-alive")

	// Add custom headers
	for key, value := range config.CustomHeaders {
		req.Header.Set(key, value)
	}

	// Make request
	resp, err := wtd.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode

	// Extract headers
	for key, values := range resp.Header {
		if len(values) > 0 {
			result.Headers[key] = values[0]
		}
	}

	// Extract server header
	if server := resp.Header.Get("Server"); server != "" {
		result.Server = server
	}

	// Extract cookies
	for _, cookie := range resp.Cookies() {
		result.Cookies = append(result.Cookies, CookieInfo{
			Name:     cookie.Name,
			Value:    cookie.Value,
		})
		cookieInfo := CookieInfo{
			Name:     cookie.Name,
			Value:    cookie.Value,
			Domain:   cookie.Domain,
			Path:     cookie.Path,
			Secure:   cookie.Secure,
			HttpOnly: cookie.HttpOnly,
			SameSite: fmt.Sprintf("%v", cookie.SameSite),
		}
		result.Cookies = append(result.Cookies, cookieInfo)
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to read response body: %v", err))
		body = []byte{}
	}

	bodyStr := string(body)

	// Extract title
	if title := wtd.extractTitle(bodyStr); title != "" {
		result.Title = title
	}

	// Analyze SSL/TLS
	if config.AnalyzeSSL && resp.TLS != nil {
		result.SSL = wtd.analyzeSSL(resp, result.Headers)
	}

	// Analyze security headers
	if config.AnalyzeSecurity {
		result.Security = wtd.analyzeSecurityHeaders(result.Headers)
	}

	// Analyze performance
	if config.AnalyzePerformance {
		result.Performance = wtd.analyzePerformance(resp, body, time.Since(start))
	}

	// Detect technologies
	wtd.detectFromHeaders(result)
	wtd.detectFromHTML(result, bodyStr)
	wtd.detectFromCookies(result)
	wtd.detectFromURL(result)

	// Apply implications and exclusions
	wtd.applyImplications(result)
	wtd.applyExclusions(result)

	// Sort technologies by confidence
	sort.Slice(result.Technologies, func(i, j int) bool {
		return result.Technologies[i].Confidence > result.Technologies[j].Confidence
	})

	// Store result
	wtd.mutex.Lock()
	wtd.results[url] = result
	wtd.mutex.Unlock()

	return result, nil
}

// loadBuiltinSignatures loads built-in technology signatures
func (wtd *WebTechDetector) loadBuiltinSignatures() {
	// Web Servers
	wtd.signatures["Apache"] = TechSignature{
		Name:        "Apache",
		Category:    "Web Server",
		Description: "Apache HTTP Server",
		Website:     "https://httpd.apache.org/",
		Headers:     map[string]string{"Server": "(?i)apache"},
		CPE:         "cpe:2.3:a:apache:http_server",
	}

	wtd.signatures["Nginx"] = TechSignature{
		Name:        "Nginx",
		Category:    "Web Server",
		Description: "Nginx HTTP Server",
		Website:     "https://nginx.org/",
		Headers:     map[string]string{"Server": "(?i)nginx"},
		CPE:         "cpe:2.3:a:nginx:nginx",
	}

	wtd.signatures["IIS"] = TechSignature{
		Name:        "Microsoft IIS",
		Category:    "Web Server",
		Description: "Microsoft Internet Information Services",
		Website:     "https://www.iis.net/",
		Headers:     map[string]string{"Server": "(?i)microsoft-iis"},
		CPE:         "cpe:2.3:a:microsoft:internet_information_services",
	}

	// Content Management Systems
	wtd.signatures["WordPress"] = TechSignature{
		Name:        "WordPress",
		Category:    "CMS",
		Description: "WordPress Content Management System",
		Website:     "https://wordpress.org/",
		HTML:        []string{`/wp-content/`, `wp-includes`, `<meta name="generator" content="WordPress`},
		CPE:         "cpe:2.3:a:wordpress:wordpress",
	}

	wtd.signatures["Drupal"] = TechSignature{
		Name:        "Drupal",
		Category:    "CMS",
		Description: "Drupal Content Management System",
		Website:     "https://drupal.org/",
		HTML:        []string{`Drupal.settings`, `/sites/default/files/`, `<meta name="Generator" content="Drupal`},
		Headers:     map[string]string{"X-Drupal-Cache": "", "X-Generator": "(?i)drupal"},
		CPE:         "cpe:2.3:a:drupal:drupal",
	}

	wtd.signatures["Joomla"] = TechSignature{
		Name:        "Joomla",
		Category:    "CMS",
		Description: "Joomla Content Management System",
		Website:     "https://www.joomla.org/",
		HTML:        []string{`/media/system/js/`, `Joomla.JText`, `<meta name="generator" content="Joomla`},
		CPE:         "cpe:2.3:a:joomla:joomla",
	}

	// JavaScript Frameworks
	wtd.signatures["jQuery"] = TechSignature{
		Name:        "jQuery",
		Category:    "JavaScript Library",
		Description: "jQuery JavaScript Library",
		Website:     "https://jquery.com/",
		Script:      []string{`jquery`, `jQuery`},
		HTML:        []string{`jquery.min.js`, `jquery.js`},
	}

	wtd.signatures["React"] = TechSignature{
		Name:        "React",
		Category:    "JavaScript Framework",
		Description: "React JavaScript Library",
		Website:     "https://reactjs.org/",
		HTML:        []string{`react.min.js`, `react.js`, `data-reactroot`},
		Script:      []string{`React.version`, `ReactDOM`},
	}

	wtd.signatures["Angular"] = TechSignature{
		Name:        "Angular",
		Category:    "JavaScript Framework",
		Description: "Angular JavaScript Framework",
		Website:     "https://angular.io/",
		HTML:        []string{`ng-app`, `ng-controller`, `angular.min.js`},
		Script:      []string{`angular.version`},
	}

	wtd.signatures["Vue.js"] = TechSignature{
		Name:        "Vue.js",
		Category:    "JavaScript Framework",
		Description: "Vue.js JavaScript Framework",
		Website:     "https://vuejs.org/",
		HTML:        []string{`vue.min.js`, `vue.js`, `v-if`, `v-for`},
		Script:      []string{`Vue.version`},
	}

	// E-commerce
	wtd.signatures["Shopify"] = TechSignature{
		Name:        "Shopify",
		Category:    "E-commerce",
		Description: "Shopify E-commerce Platform",
		Website:     "https://www.shopify.com/",
		HTML:        []string{`Shopify.shop`, `shopify_pay`, `/assets/shopify_pay`},
		Headers:     map[string]string{"X-ShopId": ""},
	}

	wtd.signatures["WooCommerce"] = TechSignature{
		Name:        "WooCommerce",
		Category:    "E-commerce",
		Description: "WooCommerce WordPress Plugin",
		Website:     "https://woocommerce.com/",
		HTML:        []string{`woocommerce`, `/wc-ajax/`, `wc_add_to_cart_params`},
		Implies:     []string{"WordPress"},
	}

	// Analytics
	wtd.signatures["Google Analytics"] = TechSignature{
		Name:        "Google Analytics",
		Category:    "Analytics",
		Description: "Google Analytics",
		Website:     "https://analytics.google.com/",
		HTML:        []string{`google-analytics.com/analytics.js`, `gtag`, `ga('create'`},
		Script:      []string{`GoogleAnalyticsObject`},
	}

	// CDNs
	wtd.signatures["Cloudflare"] = TechSignature{
		Name:        "Cloudflare",
		Category:    "CDN",
		Description: "Cloudflare CDN",
		Website:     "https://www.cloudflare.com/",
		Headers:     map[string]string{"CF-Ray": "", "Server": "cloudflare"},
	}

	// Programming Languages
	wtd.signatures["PHP"] = TechSignature{
		Name:        "PHP",
		Category:    "Programming Language",
		Description: "PHP Programming Language",
		Website:     "https://www.php.net/",
		Headers:     map[string]string{"X-Powered-By": "(?i)php"},
		Cookies:     []string{"PHPSESSID"},
		URL:         []string{`\.php$`, `\.php\?`},
	}

	wtd.signatures["ASP.NET"] = TechSignature{
		Name:        "ASP.NET",
		Category:    "Web Framework",
		Description: "Microsoft ASP.NET Framework",
		Website:     "https://dotnet.microsoft.com/apps/aspnet",
		Headers:     map[string]string{"X-AspNet-Version": "", "X-Powered-By": `(?i)asp\.net`},
		Cookies:     []string{"ASP.NET_SessionId"},
		HTML:        []string{`__VIEWSTATE`, `__EVENTVALIDATION`},
	}
}

// detectFromHeaders detects technologies from HTTP headers
func (wtd *WebTechDetector) detectFromHeaders(result *WebTechResult) {
	for _, sig := range wtd.signatures {
		for headerName, pattern := range sig.Headers {
			if headerValue, exists := result.Headers[headerName]; exists {
				if pattern == "" || wtd.matchPattern(headerValue, pattern) {
					confidence := 90
					if pattern == "" {
						confidence = 70
					}
					wtd.addDetection(result, sig, confidence, "headers", headerValue)
				}
			}
		}
	}
}

// detectFromHTML detects technologies from HTML content
func (wtd *WebTechDetector) detectFromHTML(result *WebTechResult, html string) {
	for _, sig := range wtd.signatures {
		for _, pattern := range sig.HTML {
			if wtd.matchPattern(html, pattern) {
				wtd.addDetection(result, sig, 80, "html", pattern)
			}
		}
		for _, pattern := range sig.Script {
			if wtd.matchPattern(html, pattern) {
				wtd.addDetection(result, sig, 85, "script", pattern)
			}
		}
	}
}

// detectFromCookies detects technologies from cookies
func (wtd *WebTechDetector) detectFromCookies(result *WebTechResult) {
	for _, sig := range wtd.signatures {
		for _, cookiePattern := range sig.Cookies {
			for _, cookie := range result.Cookies {
				if wtd.matchPattern(cookie.Name, cookiePattern) {
					wtd.addDetection(result, sig, 75, "cookies", cookie.Name)
				}
			}
		}
	}
}

// detectFromURL detects technologies from URL patterns
func (wtd *WebTechDetector) detectFromURL(result *WebTechResult) {
	for _, sig := range wtd.signatures {
		for _, pattern := range sig.URL {
			if wtd.matchPattern(result.URL, pattern) {
				wtd.addDetection(result, sig, 60, "url", pattern)
			}
		}
	}
}

// addDetection adds a detected technology to the result
func (wtd *WebTechDetector) addDetection(result *WebTechResult, sig TechSignature, confidence int, source, evidence string) {
	// Check if already detected
	for i, tech := range result.Technologies {
		if tech.Name == sig.Name {
			// Update confidence if higher
			if confidence > tech.Confidence {
				result.Technologies[i].Confidence = confidence
				result.Technologies[i].Source = source
			}
			return
		}
	}

	// Add new detection
	result.Technologies = append(result.Technologies, DetectedTech{
		Name:        sig.Name,
		Category:    sig.Category,
		Confidence:  confidence,
		Source:      source,
		Description: sig.Description,
		Website:     sig.Website,
		CPE:         sig.CPE,
		Icon:        sig.Icon,
	})
}

// applyImplications applies technology implications
func (wtd *WebTechDetector) applyImplications(result *WebTechResult) {
	for _, tech := range result.Technologies {
		if sig, exists := wtd.signatures[tech.Name]; exists {
			for _, implied := range sig.Implies {
				if impliedSig, impliedExists := wtd.signatures[implied]; impliedExists {
					wtd.addDetection(result, impliedSig, 50, "implication", tech.Name)
				}
			}
		}
	}
}

// applyExclusions removes excluded technologies
func (wtd *WebTechDetector) applyExclusions(result *WebTechResult) {
	for _, tech := range result.Technologies {
		if sig, exists := wtd.signatures[tech.Name]; exists {
			for _, excluded := range sig.Excludes {
				for i := len(result.Technologies) - 1; i >= 0; i-- {
					if result.Technologies[i].Name == excluded {
						result.Technologies = append(result.Technologies[:i], result.Technologies[i+1:]...)
					}
				}
			}
		}
	}
}

// matchPattern matches a string against a pattern (regex or simple string)
func (wtd *WebTechDetector) matchPattern(text, pattern string) bool {
	if pattern == "" {
		return true
	}

	// Try regex match first
	if matched, err := regexp.MatchString(pattern, text); err == nil {
		return matched
	}

	// Fallback to simple string contains
	return strings.Contains(strings.ToLower(text), strings.ToLower(pattern))
}

// extractTitle extracts the page title from HTML
func (wtd *WebTechDetector) extractTitle(html string) string {
	re := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
	matches := re.FindStringSubmatch(html)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

// analyzeSSL analyzes SSL/TLS configuration
func (wtd *WebTechDetector) analyzeSSL(resp *http.Response, headers map[string]string) *SSLInfo {
	if resp.TLS == nil {
		return &SSLInfo{Enabled: false}
	}

	ssl := &SSLInfo{
		Enabled: true,
		Version: wtd.getTLSVersion(resp.TLS.Version),
		Cipher:  wtd.getCipherSuite(resp.TLS.CipherSuite),
	}

	// Check HSTS
	if hsts := headers["Strict-Transport-Security"]; hsts != "" {
		ssl.HSTS = true
		// Parse max-age if present
		if re := regexp.MustCompile(`max-age=(\d+)`); re.MatchString(hsts) {
			matches := re.FindStringSubmatch(hsts)
			if len(matches) > 1 {
				ssl.HSTSMaxAge = wtd.parseInt(matches[1])
			}
		}
	}

	// Analyze certificate
	if len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]
		ssl.Certificate = &CertInfo{
			Subject:      cert.Subject.String(),
			Issuer:       cert.Issuer.String(),
			NotBefore:    cert.NotBefore,
			NotAfter:     cert.NotAfter,
			SerialNumber: cert.SerialNumber.String(),
			Signature:    cert.SignatureAlgorithm.String(),
			SANs:         cert.DNSNames,
			SelfSigned:   cert.Subject.String() == cert.Issuer.String(),
			Expired:      time.Now().After(cert.NotAfter),
			DaysUntilExp: int(time.Until(cert.NotAfter).Hours() / 24),
		}
	}

	return ssl
}

// analyzeSecurityHeaders analyzes security headers
func (wtd *WebTechDetector) analyzeSecurityHeaders(headers map[string]string) *SecurityHeaders {
	security := &SecurityHeaders{
		MissingHeaders:    make([]string, 0),
		VulnerableHeaders: make([]string, 0),
	}

	// Check for security headers
	if csp := headers["Content-Security-Policy"]; csp != "" {
		security.CSP = csp
		security.SecurityScore += 20
	} else {
		security.MissingHeaders = append(security.MissingHeaders, "Content-Security-Policy")
	}

	if xframe := headers["X-Frame-Options"]; xframe != "" {
		security.XFrameOptions = xframe
		security.SecurityScore += 15
	} else {
		security.MissingHeaders = append(security.MissingHeaders, "X-Frame-Options")
	}

	if xcontent := headers["X-Content-Type-Options"]; xcontent != "" {
		security.XContentTypeOptions = xcontent
		security.SecurityScore += 10
	} else {
		security.MissingHeaders = append(security.MissingHeaders, "X-Content-Type-Options")
	}

	if xxss := headers["X-XSS-Protection"]; xxss != "" {
		security.XXSSProtection = xxss
		if xxss == "0" {
			security.VulnerableHeaders = append(security.VulnerableHeaders, "X-XSS-Protection disabled")
		} else {
			security.SecurityScore += 10
		}
	} else {
		security.MissingHeaders = append(security.MissingHeaders, "X-XSS-Protection")
	}

	if referrer := headers["Referrer-Policy"]; referrer != "" {
		security.ReferrerPolicy = referrer
		security.SecurityScore += 10
	}

	if permissions := headers["Permissions-Policy"]; permissions != "" {
		security.PermissionsPolicy = permissions
		security.SecurityScore += 10
	}

	if expectCT := headers["Expect-CT"]; expectCT != "" {
		security.ExpectCT = expectCT
		security.SecurityScore += 5
	}

	return security
}

// analyzePerformance analyzes performance metrics
func (wtd *WebTechDetector) analyzePerformance(resp *http.Response, body []byte, responseTime time.Duration) *PerformanceMetrics {
	perf := &PerformanceMetrics{
		ResponseTime:  responseTime,
		ContentLength: int64(len(body)),
	}

	if encoding := resp.Header.Get("Content-Encoding"); encoding != "" {
		perf.Compression = encoding
	}

	if cache := resp.Header.Get("Cache-Control"); cache != "" {
		perf.CacheControl = cache
	}

	if etag := resp.Header.Get("ETag"); etag != "" {
		perf.ETag = etag
	}

	if lastMod := resp.Header.Get("Last-Modified"); lastMod != "" {
		perf.LastModified = lastMod
	}

	return perf
}

// Helper functions
func (wtd *WebTechDetector) getTLSVersion(version uint16) string {
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

func (wtd *WebTechDetector) getCipherSuite(suite uint16) string {
	// This would map cipher suite IDs to names
	// Simplified for brevity
	return fmt.Sprintf("0x%04X", suite)
}

func (wtd *WebTechDetector) parseInt(s string) int {
	var result int
	if _, err := fmt.Sscanf(s, "%d", &result); err != nil {
		return 0
	}
	return result
}

// LoadSignatures loads technology signatures from JSON
func (wtd *WebTechDetector) LoadSignatures(data []byte) error {
	var signatures map[string]TechSignature
	if err := json.Unmarshal(data, &signatures); err != nil {
		return err
	}

	wtd.mutex.Lock()
	for name, sig := range signatures {
		wtd.signatures[name] = sig
	}
	wtd.mutex.Unlock()

	return nil
}

// GetResult returns the web technology detection result for a URL
func (wtd *WebTechDetector) GetResult(url string) *WebTechResult {
	wtd.mutex.RLock()
	defer wtd.mutex.RUnlock()
	return wtd.results[url]
}

// GetAllResults returns all web technology detection results
func (wtd *WebTechDetector) GetAllResults() map[string]*WebTechResult {
	wtd.mutex.RLock()
	defer wtd.mutex.RUnlock()

	results := make(map[string]*WebTechResult)
	for k, v := range wtd.results {
		results[k] = v
	}
	return results
}

// Clear clears all web technology detection results
func (wtd *WebTechDetector) Clear() {
	wtd.mutex.Lock()
	defer wtd.mutex.Unlock()
	wtd.results = make(map[string]*WebTechResult)
}