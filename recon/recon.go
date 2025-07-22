package recon

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// ReconEngine coordinates all reconnaissance modules
type ReconEngine struct {
	subdomainEnum   *SubdomainEnumerator
	dnsAnalyzer     *DNSAnalyzer
	webTechDetector *WebTechDetector
	vulnScanner     *VulnScanner
	results         map[string]*ReconResult
	mutex           sync.RWMutex
	config          ReconConfig
}

// ReconResult contains comprehensive reconnaissance results
type ReconResult struct {
	Target     string            `json:"target"`
	Domain     string            `json:"domain"`
	Subdomains []SubdomainResult `json:"subdomains,omitempty"`
	DNSRecords map[string][]struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"dnsRecords,omitempty"`
	WebTechnologies map[string]*WebTechResult  `json:"webTechnologies,omitempty"`
	Vulnerabilities map[string]*VulnScanResult `json:"vulnerabilities,omitempty"`
	Assets          []AssetInfo                `json:"assets"`
	RiskAssessment  *RiskAssessment            `json:"riskAssessment"`
	Timestamp       time.Time                  `json:"timestamp"`
	ScanDuration    time.Duration              `json:"scanDuration"`
	ModulesExecuted []string                   `json:"modulesExecuted"`
	Errors          []string                   `json:"errors,omitempty"`
	Statistics      *ReconStatistics           `json:"statistics"`
}

// AssetInfo represents a discovered asset
type AssetInfo struct {
	Type       string            `json:"type"`
	URL        string            `json:"url"`
	IP         string            `json:"ip,omitempty"`
	Port       int               `json:"port,omitempty"`
	Service    string            `json:"service,omitempty"`
	Technology string            `json:"technology,omitempty"`
	Status     string            `json:"status"`
	Title      string            `json:"title,omitempty"`
	Server     string            `json:"server,omitempty"`
	SSL        bool              `json:"ssl"`
	Headers    map[string]string `json:"headers,omitempty"`
	RiskLevel  string            `json:"riskLevel"`
	VulnCount  int               `json:"vulnCount"`
	LastSeen   time.Time         `json:"lastSeen"`
}

// RiskAssessment provides overall risk analysis
type RiskAssessment struct {
	OverallRisk     string               `json:"overallRisk"`
	RiskScore       int                  `json:"riskScore"`
	CriticalIssues  []string             `json:"criticalIssues"`
	HighRiskAssets  []string             `json:"highRiskAssets"`
	ExposedServices []string             `json:"exposedServices"`
	VulnSummary     VulnerabilitySummary `json:"vulnerabilitySummary"`
	Recommendations []string             `json:"recommendations"`
	Compliance      *ComplianceStatus    `json:"compliance,omitempty"`
}

// VulnerabilitySummary summarizes vulnerability findings
type VulnerabilitySummary struct {
	Total       int            `json:"total"`
	BySeverity  map[string]int `json:"bySeverity"`
	ByCategory  map[string]int `json:"byCategory"`
	TopVulns    []string       `json:"topVulnerabilities"`
	CVSSAverage float64        `json:"cvssAverage"`
	Trending    []TrendingVuln `json:"trending,omitempty"`
}

// TrendingVuln represents trending vulnerability information
type TrendingVuln struct {
	Name        string    `json:"name"`
	CVE         string    `json:"cve"`
	Severity    string    `json:"severity"`
	CVSS        float64   `json:"cvss"`
	Description string    `json:"description"`
	FirstSeen   time.Time `json:"firstSeen"`
	Count       int       `json:"count"`
}

// ComplianceStatus tracks compliance with security standards
type ComplianceStatus struct {
	OWASPTop10      map[string]bool `json:"owaspTop10"`
	PCIDSS          bool            `json:"pciDss"`
	HIPAA           bool            `json:"hipaa"`
	GDPR            bool            `json:"gdpr"`
	SOX             bool            `json:"sox"`
	ISO27001        bool            `json:"iso27001"`
	NIST            bool            `json:"nist"`
	Score           int             `json:"score"`
	Recommendations []string        `json:"recommendations"`
}

// ReconStatistics provides scan statistics
type ReconStatistics struct {
	SubdomainsFound      int           `json:"subdomainsFound"`
	DNSRecordsFound      int           `json:"dnsRecordsFound"`
	WebAssetsFound       int           `json:"webAssetsFound"`
	VulnerabilitiesFound int           `json:"vulnerabilitiesFound"`
	TechnologiesFound    int           `json:"technologiesFound"`
	ExposedFilesFound    int           `json:"exposedFilesFound"`
	SSLIssuesFound       int           `json:"sslIssuesFound"`
	TotalRequests        int           `json:"totalRequests"`
	FailedRequests       int           `json:"failedRequests"`
	AverageResponseTime  time.Duration `json:"averageResponseTime"`
	DataProcessed        int64         `json:"dataProcessed"`
}

// ReconConfig holds configuration for reconnaissance
type ReconConfig struct {
	// General settings
	Threads         int           `json:"threads"`
	Timeout         time.Duration `json:"timeout"`
	UserAgent       string        `json:"userAgent"`
	MaxDepth        int           `json:"maxDepth"`
	FollowRedirects bool          `json:"followRedirects"`
	VerifySSL       bool          `json:"verifySSL"`

	// Module enablement
	EnableSubdomainEnum    bool `json:"enableSubdomainEnum"`
	EnableDNSAnalysis      bool `json:"enableDNSAnalysis"`
	EnableWebTechDetection bool `json:"enableWebTechDetection"`
	EnableVulnScanning     bool `json:"enableVulnScanning"`

	// Subdomain enumeration
	SubdomainWordlists []string `json:"subdomainWordlists"`
	SubdomainSources   []string `json:"subdomainSources"`
	MaxSubdomains      int      `json:"maxSubdomains"`

	// DNS analysis
	DNSServers     []string `json:"dnsServers"`
	DNSRecordTypes []string `json:"dnsRecordTypes"`
	EnableDNSSEC   bool     `json:"enableDNSSEC"`

	// Web technology detection
	CustomSignatures   []byte            `json:"customSignatures,omitempty"`
	AnalyzeSSL         bool              `json:"analyzeSSL"`
	AnalyzeSecurity    bool              `json:"analyzeSecurity"`
	AnalyzePerformance bool              `json:"analyzePerformance"`
	CustomHeaders      map[string]string `json:"customHeaders"`

	// Vulnerability scanning
	VulnSignatures []byte   `json:"vulnSignatures,omitempty"`
	ScanSSL        bool     `json:"scanSSL"`
	ScanHeaders    bool     `json:"scanHeaders"`
	ScanFiles      bool     `json:"scanFiles"`
	ScanInjection  bool     `json:"scanInjection"`
	CustomPayloads []string `json:"customPayloads"`
	ExcludePaths   []string `json:"excludePaths"`

	// Output settings
	OutputFormat   string `json:"outputFormat"`
	OutputFile     string `json:"outputFile"`
	Verbose        bool   `json:"verbose"`
	Quiet          bool   `json:"quiet"`
	IncludeRawData bool   `json:"includeRawData"`
}

// NewReconEngine creates a new reconnaissance engine
func NewReconEngine(config ReconConfig) *ReconEngine {
	// Set default values
	if config.Threads == 0 {
		config.Threads = 20
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.UserAgent == "" {
		config.UserAgent = "OMAP/1.0 (Advanced Reconnaissance Engine)"
	}
	if config.MaxDepth == 0 {
		config.MaxDepth = 3
	}
	if config.MaxSubdomains == 0 {
		config.MaxSubdomains = 1000
	}

	// Initialize modules
	var subdomainEnum *SubdomainEnumerator
	var dnsAnalyzer *DNSAnalyzer
	var webTechDetector *WebTechDetector
	var vulnScanner *VulnScanner

	if config.EnableSubdomainEnum {
		subdomainConfig := SubdomainConfig{
			Wordlists:     config.SubdomainWordlists,
			Sources:       config.SubdomainSources,
			MaxSubdomains: config.MaxSubdomains,
			Threads:       config.Threads,
			Timeout:       config.Timeout,
		}
		subdomainEnum = NewSubdomainEnumerator(subdomainConfig)
	}

	if config.EnableDNSAnalysis {
		dnsConfig := DNSConfig{
			Servers:      config.DNSServers,
			RecordTypes:  config.DNSRecordTypes,
			Timeout:      config.Timeout,
			Threads:      config.Threads,
			EnableDNSSEC: config.EnableDNSSEC,
		}
		dnsAnalyzer = NewDNSAnalyzer(dnsConfig)
		// Store dnsConfig for later use
	}

	if config.EnableWebTechDetection {
		webTechConfig := WebTechConfig{
			UserAgent:          config.UserAgent,
			Timeout:            config.Timeout,
			FollowRedirects:    config.FollowRedirects,
			VerifySSL:          config.VerifySSL,
			AnalyzeSSL:         config.AnalyzeSSL,
			AnalyzeSecurity:    config.AnalyzeSecurity,
			AnalyzePerformance: config.AnalyzePerformance,
			CustomHeaders:      config.CustomHeaders,
		}
		webTechDetector = NewWebTechDetector(webTechConfig)

		// Load custom signatures if provided
		if len(config.CustomSignatures) > 0 {
			if err := webTechDetector.LoadSignatures(config.CustomSignatures); err != nil {
				log.Printf("Warning: Failed to load custom signatures: %v", err)
			}
		}
	}

	if config.EnableVulnScanning {
		vulnConfig := VulnScanConfig{
			UserAgent:       config.UserAgent,
			Timeout:         config.Timeout,
			Threads:         config.Threads,
			FollowRedirects: config.FollowRedirects,
			VerifySSL:       config.VerifySSL,
			ScanSSL:         config.ScanSSL,
			ScanHeaders:     config.ScanHeaders,
			ScanFiles:       config.ScanFiles,
			ScanInjection:   config.ScanInjection,
			CustomPayloads:  config.CustomPayloads,
			CustomHeaders:   config.CustomHeaders,
			ExcludePaths:    config.ExcludePaths,
		}
		vulnScanner = NewVulnScanner(vulnConfig)

		// Load custom vulnerability signatures if provided
		if len(config.VulnSignatures) > 0 {
			if err := vulnScanner.LoadVulnSignatures(config.VulnSignatures); err != nil {
				log.Printf("Warning: Failed to load vulnerability signatures: %v", err)
			}
		}
	}

	return &ReconEngine{
		subdomainEnum:   subdomainEnum,
		dnsAnalyzer:     dnsAnalyzer,
		webTechDetector: webTechDetector,
		vulnScanner:     vulnScanner,
		results:         make(map[string]*ReconResult),
		config:          config,
	}
}

// RunReconnaissance performs comprehensive reconnaissance on a target
func (re *ReconEngine) RunReconnaissance(target string) (*ReconResult, error) {
	start := time.Now()

	// Parse target to extract domain
	domain := re.extractDomain(target)
	if domain == "" {
		return nil, fmt.Errorf("invalid target: %s", target)
	}

	result := &ReconResult{
		Target:     target,
		Domain:     domain,
		Subdomains: make([]SubdomainResult, 0),
		DNSRecords: make(map[string][]struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		}),
		WebTechnologies: make(map[string]*WebTechResult),
		Vulnerabilities: make(map[string]*VulnScanResult),
		Assets:          make([]AssetInfo, 0),
		Timestamp:       time.Now(),
		ModulesExecuted: make([]string, 0),
		Errors:          make([]string, 0),
		Statistics:      &ReconStatistics{},
	}

	// Phase 1: Subdomain Enumeration
	if re.config.EnableSubdomainEnum && re.subdomainEnum != nil {
		if !re.config.Quiet {
			fmt.Printf("[*] Starting subdomain enumeration for %s\n", domain)
		}
		subdomains, err := re.subdomainEnum.EnumerateSubdomains(domain, SubdomainConfig{
			Wordlists:     re.config.SubdomainWordlists,
			Sources:       re.config.SubdomainSources,
			MaxSubdomains: re.config.MaxSubdomains,
			Threads:       re.config.Threads,
			Timeout:       re.config.Timeout,
		})
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Subdomain enumeration failed: %v", err))
		} else {
			result.Subdomains = subdomains
			result.Statistics.SubdomainsFound = len(subdomains)
			result.ModulesExecuted = append(result.ModulesExecuted, "subdomain_enumeration")
			if re.config.Verbose {
				fmt.Printf("[+] Found %d subdomains\n", len(subdomains))
			}
		}
	}

	// Phase 2: DNS Analysis
	if re.config.EnableDNSAnalysis && re.dnsAnalyzer != nil {
		if !re.config.Quiet {
			fmt.Printf("[*] Starting DNS analysis for %s\n", domain)
		}

		// Analyze main domain
		dnsConfig := DNSConfig{
			Servers:      re.config.DNSServers,
			RecordTypes:  re.config.DNSRecordTypes,
			Timeout:      re.config.Timeout,
			Threads:      re.config.Threads,
			EnableDNSSEC: re.config.EnableDNSSEC,
		}
		dnsResult, err := re.dnsAnalyzer.AnalyzeDomain(domain, dnsConfig)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("DNS analysis failed for %s: %v", domain, err))
		} else {
			// Convert Records map to structured format
			var records []struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			}
			for recordType, values := range dnsResult.Records {
				for _, value := range values {
					records = append(records, struct {
						Type  string `json:"type"`
						Value string `json:"value"`
					}{
						Type:  recordType,
						Value: value,
					})
				}
			}
			result.DNSRecords[domain] = records
			result.Statistics.DNSRecordsFound += len(records)
		}

		// Analyze subdomains
		for _, subdomain := range result.Subdomains {
			if subdomain.Status == "active" {
				dnsConfig := DNSConfig{
					Servers:      re.config.DNSServers,
					RecordTypes:  re.config.DNSRecordTypes,
					Timeout:      re.config.Timeout,
					Threads:      re.config.Threads,
					EnableDNSSEC: re.config.EnableDNSSEC,
				}
				dnsResult, err := re.dnsAnalyzer.AnalyzeDomain(subdomain.Subdomain, dnsConfig)
				if err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("DNS analysis failed for %s: %v", subdomain.Subdomain, err))
				} else {
					// Convert Records map to structured format
					var records []struct {
						Type  string `json:"type"`
						Value string `json:"value"`
					}
					for recordType, values := range dnsResult.Records {
						for _, value := range values {
							records = append(records, struct {
								Type  string `json:"type"`
								Value string `json:"value"`
							}{
								Type:  recordType,
								Value: value,
							})
						}
					}
					result.DNSRecords[subdomain.Subdomain] = records
					result.Statistics.DNSRecordsFound += len(records)
				}
			}
		}

		result.ModulesExecuted = append(result.ModulesExecuted, "dns_analysis")
		if re.config.Verbose {
			fmt.Printf("[+] Found %d DNS records\n", result.Statistics.DNSRecordsFound)
		}
	}

	// Phase 3: Web Technology Detection
	if re.config.EnableWebTechDetection && re.webTechDetector != nil {
		if !re.config.Quiet {
			fmt.Printf("[*] Starting web technology detection\n")
		}

		// Collect web assets
		webAssets := re.collectWebAssets(result)
		for _, asset := range webAssets {
			webTechConfig := WebTechConfig{
				UserAgent:          re.config.UserAgent,
				Timeout:            re.config.Timeout,
				FollowRedirects:    re.config.FollowRedirects,
				VerifySSL:          re.config.VerifySSL,
				AnalyzeSSL:         re.config.AnalyzeSSL,
				AnalyzeSecurity:    re.config.AnalyzeSecurity,
				AnalyzePerformance: re.config.AnalyzePerformance,
				CustomHeaders:      re.config.CustomHeaders,
			}

			webTechResult, err := re.webTechDetector.DetectTechnologies(asset, webTechConfig)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("Web tech detection failed for %s: %v", asset, err))
			} else {
				result.WebTechnologies[asset] = webTechResult
				result.Statistics.TechnologiesFound += len(webTechResult.Technologies)
				result.Statistics.WebAssetsFound++
			}
		}

		result.ModulesExecuted = append(result.ModulesExecuted, "web_technology_detection")
		if re.config.Verbose {
			fmt.Printf("[+] Analyzed %d web assets, found %d technologies\n", result.Statistics.WebAssetsFound, result.Statistics.TechnologiesFound)
		}
	}

	// Phase 4: Vulnerability Scanning
	if re.config.EnableVulnScanning && re.vulnScanner != nil {
		if !re.config.Quiet {
			fmt.Printf("[*] Starting vulnerability scanning\n")
		}

		// Scan web assets for vulnerabilities
		webAssets := re.collectWebAssets(result)
		for _, asset := range webAssets {
			vulnConfig := VulnScanConfig{
				UserAgent:       re.config.UserAgent,
				Timeout:         re.config.Timeout,
				Threads:         re.config.Threads,
				FollowRedirects: re.config.FollowRedirects,
				VerifySSL:       re.config.VerifySSL,
				ScanSSL:         re.config.ScanSSL,
				ScanHeaders:     re.config.ScanHeaders,
				ScanFiles:       re.config.ScanFiles,
				ScanInjection:   re.config.ScanInjection,
				CustomPayloads:  re.config.CustomPayloads,
				CustomHeaders:   re.config.CustomHeaders,
				ExcludePaths:    re.config.ExcludePaths,
			}

			vulnResult, err := re.vulnScanner.ScanTarget(asset, vulnConfig)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("Vulnerability scan failed for %s: %v", asset, err))
			} else {
				result.Vulnerabilities[asset] = vulnResult
				result.Statistics.VulnerabilitiesFound += len(vulnResult.Vulnerabilities)
				result.Statistics.ExposedFilesFound += len(vulnResult.ExposedFiles)
				result.Statistics.SSLIssuesFound += len(vulnResult.WeakCiphers)
			}
		}

		result.ModulesExecuted = append(result.ModulesExecuted, "vulnerability_scanning")
		if re.config.Verbose {
			fmt.Printf("[+] Found %d vulnerabilities across %d assets\n", result.Statistics.VulnerabilitiesFound, len(webAssets))
		}
	}

	// Phase 5: Asset Discovery and Consolidation
	result.Assets = re.consolidateAssets(result)

	// Phase 6: Risk Assessment
	result.RiskAssessment = re.performRiskAssessment(result)

	result.ScanDuration = time.Since(start)

	// Store result
	re.mutex.Lock()
	re.results[target] = result
	re.mutex.Unlock()

	if !re.config.Quiet {
		fmt.Printf("[+] Reconnaissance completed in %v\n", result.ScanDuration)
		fmt.Printf("[+] Found %d assets, %d vulnerabilities, %d technologies\n",
			len(result.Assets), result.Statistics.VulnerabilitiesFound, result.Statistics.TechnologiesFound)
	}

	return result, nil
}

// extractDomain extracts the domain from a target URL or hostname
func (re *ReconEngine) extractDomain(target string) string {
	// Remove protocol if present
	if strings.HasPrefix(target, "http://") {
		target = strings.TrimPrefix(target, "http://")
	} else if strings.HasPrefix(target, "https://") {
		target = strings.TrimPrefix(target, "https://")
	}

	// Parse as URL to handle complex cases
	if !strings.Contains(target, "://") {
		target = "http://" + target
	}

	parsedURL, err := url.Parse(target)
	if err != nil {
		// Fallback: extract domain manually
		parts := strings.Split(target, "/")
		if len(parts) > 0 {
			hostPart := parts[0]
			if strings.Contains(hostPart, ":") {
				return strings.Split(hostPart, ":")[0]
			}
			return hostPart
		}
		return ""
	}

	return parsedURL.Hostname()
}

// collectWebAssets collects web assets from reconnaissance results
func (re *ReconEngine) collectWebAssets(result *ReconResult) []string {
	assets := make([]string, 0)
	assetSet := make(map[string]bool)

	// Add main domain
	for _, protocol := range []string{"http", "https"} {
		asset := fmt.Sprintf("%s://%s", protocol, result.Domain)
		if !assetSet[asset] {
			assets = append(assets, asset)
			assetSet[asset] = true
		}
	}

	// Add subdomains
	for _, subdomain := range result.Subdomains {
		if subdomain.Status == "active" {
			for _, protocol := range []string{"http", "https"} {
				asset := fmt.Sprintf("%s://%s", protocol, subdomain.Subdomain)
				if !assetSet[asset] {
					assets = append(assets, asset)
					assetSet[asset] = true
				}
			}
		}
	}

	// Add assets from DNS records (A records)
	for domain, records := range result.DNSRecords {
		for _, record := range records {
			if record.Type == "A" && record.Value != "" {
				for _, protocol := range []string{"http", "https"} {
					asset := fmt.Sprintf("%s://%s", protocol, domain)
					if !assetSet[asset] {
						assets = append(assets, asset)
						assetSet[asset] = true
					}
				}
			}
		}
	}

	return assets
}

// consolidateAssets consolidates all discovered assets
func (re *ReconEngine) consolidateAssets(result *ReconResult) []AssetInfo {
	assets := make([]AssetInfo, 0)
	assetMap := make(map[string]*AssetInfo)

	// Process web technologies
	for assetURL, webTech := range result.WebTechnologies {
		parsedURL, _ := url.Parse(assetURL)
		hostname := parsedURL.Hostname()

		asset := &AssetInfo{
			Type:      "web",
			URL:       assetURL,
			Status:    fmt.Sprintf("%d", webTech.StatusCode),
			Title:     webTech.Title,
			Server:    webTech.Server,
			SSL:       strings.HasPrefix(assetURL, "https"),
			Headers:   webTech.Headers,
			RiskLevel: "Low",
			LastSeen:  time.Now(),
		}

		// Extract IP from DNS records
		if dnsRecords, exists := result.DNSRecords[hostname]; exists {
			for _, record := range dnsRecords {
				if record.Type == "A" {
					asset.IP = record.Value
					break
				}
			}
		}

		// Extract port from URL
		if parsedURL.Port() != "" {
			if _, err := fmt.Sscanf(parsedURL.Port(), "%d", &asset.Port); err != nil {
				// Default to standard ports on parse error
				if asset.SSL {
					asset.Port = 443
				} else {
					asset.Port = 80
				}
			}
		} else {
			if asset.SSL {
				asset.Port = 443
			} else {
				asset.Port = 80
			}
		}

		// Determine primary technology
		if len(webTech.Technologies) > 0 {
			asset.Technology = webTech.Technologies[0].Name
		}

		assetMap[assetURL] = asset
	}

	// Process vulnerabilities and update risk levels
	for assetURL, vulnResult := range result.Vulnerabilities {
		if asset, exists := assetMap[assetURL]; exists {
			asset.VulnCount = len(vulnResult.Vulnerabilities)

			// Determine risk level based on vulnerabilities
			if vulnResult.SeverityCount.Critical > 0 {
				asset.RiskLevel = "Critical"
			} else if vulnResult.SeverityCount.High > 0 {
				asset.RiskLevel = "High"
			} else if vulnResult.SeverityCount.Medium > 0 {
				asset.RiskLevel = "Medium"
			} else if vulnResult.SeverityCount.Low > 0 {
				asset.RiskLevel = "Low"
			}
		}
	}

	// Convert map to slice
	for _, asset := range assetMap {
		assets = append(assets, *asset)
	}

	// Sort assets by risk level
	sort.Slice(assets, func(i, j int) bool {
		riskOrder := map[string]int{
			"Critical": 4,
			"High":     3,
			"Medium":   2,
			"Low":      1,
		}
		return riskOrder[assets[i].RiskLevel] > riskOrder[assets[j].RiskLevel]
	})

	return assets
}

// performRiskAssessment performs comprehensive risk assessment
func (re *ReconEngine) performRiskAssessment(result *ReconResult) *RiskAssessment {
	riskAssessment := &RiskAssessment{
		CriticalIssues:  make([]string, 0),
		HighRiskAssets:  make([]string, 0),
		ExposedServices: make([]string, 0),
		Recommendations: make([]string, 0),
		VulnSummary: VulnerabilitySummary{
			BySeverity: make(map[string]int),
			ByCategory: make(map[string]int),
			TopVulns:   make([]string, 0),
		},
	}

	// Analyze vulnerabilities
	totalVulns := 0
	totalCVSS := 0.0
	vulnCount := 0

	for assetURL, vulnResult := range result.Vulnerabilities {
		totalVulns += len(vulnResult.Vulnerabilities)

		for _, vuln := range vulnResult.Vulnerabilities {
			riskAssessment.VulnSummary.BySeverity[vuln.Severity]++
			riskAssessment.VulnSummary.ByCategory[vuln.Category]++

			if vuln.CVSS > 0 {
				totalCVSS += vuln.CVSS
				vulnCount++
			}

			// Track critical issues
			if vuln.Severity == "Critical" {
				riskAssessment.CriticalIssues = append(riskAssessment.CriticalIssues,
					fmt.Sprintf("%s: %s", assetURL, vuln.Name))
			}
		}

		// Track high-risk assets
		if vulnResult.SeverityCount.Critical > 0 || vulnResult.SeverityCount.High > 0 {
			riskAssessment.HighRiskAssets = append(riskAssessment.HighRiskAssets, assetURL)
		}

		// Track exposed files as services
		for _, exposedFile := range vulnResult.ExposedFiles {
			if exposedFile.Severity == "High" {
				riskAssessment.ExposedServices = append(riskAssessment.ExposedServices,
					fmt.Sprintf("%s: %s", assetURL, exposedFile.Path))
			}
		}
	}

	riskAssessment.VulnSummary.Total = totalVulns
	if vulnCount > 0 {
		riskAssessment.VulnSummary.CVSSAverage = totalCVSS / float64(vulnCount)
	}

	// Calculate overall risk score
	riskScore := 0
	for severity, count := range riskAssessment.VulnSummary.BySeverity {
		switch severity {
		case "Critical":
			riskScore += count * 100
		case "High":
			riskScore += count * 50
		case "Medium":
			riskScore += count * 25
		case "Low":
			riskScore += count * 10
		case "Info":
			riskScore += count * 5
		}
	}

	riskAssessment.RiskScore = riskScore

	// Determine overall risk level
	if riskScore >= 500 {
		riskAssessment.OverallRisk = "Critical"
	} else if riskScore >= 200 {
		riskAssessment.OverallRisk = "High"
	} else if riskScore >= 50 {
		riskAssessment.OverallRisk = "Medium"
	} else if riskScore > 0 {
		riskAssessment.OverallRisk = "Low"
	} else {
		riskAssessment.OverallRisk = "Minimal"
	}

	// Generate recommendations
	re.generateRecommendations(riskAssessment, result)

	return riskAssessment
}

// generateRecommendations generates security recommendations
func (re *ReconEngine) generateRecommendations(riskAssessment *RiskAssessment, result *ReconResult) {
	// Critical vulnerabilities
	if riskAssessment.VulnSummary.BySeverity["Critical"] > 0 {
		riskAssessment.Recommendations = append(riskAssessment.Recommendations,
			"Immediately patch all critical vulnerabilities")
	}

	// High vulnerabilities
	if riskAssessment.VulnSummary.BySeverity["High"] > 0 {
		riskAssessment.Recommendations = append(riskAssessment.Recommendations,
			"Address high-severity vulnerabilities within 30 days")
	}

	// Exposed services
	if len(riskAssessment.ExposedServices) > 0 {
		riskAssessment.Recommendations = append(riskAssessment.Recommendations,
			"Secure or remove exposed sensitive files and services")
	}

	// SSL/TLS issues
	for _, vulnResult := range result.Vulnerabilities {
		if len(vulnResult.WeakCiphers) > 0 {
			riskAssessment.Recommendations = append(riskAssessment.Recommendations,
				"Update SSL/TLS configuration to use strong ciphers")
			break
		}
	}

	// Security headers
	for _, vulnResult := range result.Vulnerabilities {
		if len(vulnResult.SecurityIssues) > 0 {
			riskAssessment.Recommendations = append(riskAssessment.Recommendations,
				"Implement proper security headers (CSP, HSTS, etc.)")
			break
		}
	}

	// General recommendations
	if len(result.Subdomains) > 10 {
		riskAssessment.Recommendations = append(riskAssessment.Recommendations,
			"Review and minimize exposed subdomains")
	}

	riskAssessment.Recommendations = append(riskAssessment.Recommendations,
		"Implement regular security scanning and monitoring",
		"Establish incident response procedures",
		"Conduct regular security awareness training")
}

// ExportResults exports reconnaissance results in various formats
func (re *ReconEngine) ExportResults(target, format, filename string) error {
	re.mutex.RLock()
	result, exists := re.results[target]
	re.mutex.RUnlock()

	if !exists {
		return fmt.Errorf("no results found for target: %s", target)
	}

	switch strings.ToLower(format) {
	case "json":
		return re.exportJSON(result, filename)
	case "html":
		return re.exportHTML(result, filename)
	case "csv":
		return re.exportCSV(result, filename)
	case "xml":
		return re.exportXML(result, filename)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

// exportJSON exports results as JSON
func (re *ReconEngine) exportJSON(result *ReconResult, filename string) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}

	// This would write to file - placeholder for actual implementation
	fmt.Printf("JSON export would write %d bytes to %s\n", len(data), filename)
	return nil
}

// exportHTML exports results as HTML report
func (re *ReconEngine) exportHTML(result *ReconResult, filename string) error {
	// This would generate an HTML report - placeholder for actual implementation
	fmt.Printf("HTML export would generate report for %s to %s\n", result.Target, filename)
	return nil
}

// exportCSV exports results as CSV
func (re *ReconEngine) exportCSV(result *ReconResult, filename string) error {
	// This would generate a CSV report - placeholder for actual implementation
	fmt.Printf("CSV export would generate report for %s to %s\n", result.Target, filename)
	return nil
}

// exportXML exports results as XML
func (re *ReconEngine) exportXML(result *ReconResult, filename string) error {
	// This would generate an XML report - placeholder for actual implementation
	fmt.Printf("XML export would generate report for %s to %s\n", result.Target, filename)
	return nil
}

// GetResult returns the reconnaissance result for a target
func (re *ReconEngine) GetResult(target string) *ReconResult {
	re.mutex.RLock()
	defer re.mutex.RUnlock()
	return re.results[target]
}

// GetAllResults returns all reconnaissance results
func (re *ReconEngine) GetAllResults() map[string]*ReconResult {
	re.mutex.RLock()
	defer re.mutex.RUnlock()

	results := make(map[string]*ReconResult)
	for k, v := range re.results {
		results[k] = v
	}
	return results
}

// Clear clears all reconnaissance results
func (re *ReconEngine) Clear() {
	re.mutex.Lock()
	defer re.mutex.Unlock()
	re.results = make(map[string]*ReconResult)

	// Clear individual module results
	if re.subdomainEnum != nil {
		re.subdomainEnum.Clear()
	}
	if re.dnsAnalyzer != nil {
		re.dnsAnalyzer.Clear()
	}
	if re.webTechDetector != nil {
		re.webTechDetector.Clear()
	}
	if re.vulnScanner != nil {
		re.vulnScanner = nil
	}
}
