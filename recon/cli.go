package recon

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ReconCLI handles command-line interface for reconnaissance
type ReconCLI struct {
	engine *ReconEngine
	config ReconConfig
}

// NewReconCLI creates a new reconnaissance CLI
func NewReconCLI() *ReconCLI {
	return &ReconCLI{
		config: getDefaultReconConfig(),
	}
}

// getDefaultReconConfig returns default reconnaissance configuration
func getDefaultReconConfig() ReconConfig {
	return ReconConfig{
		// General settings
		Threads:         20,
		Timeout:         30 * time.Second,
		UserAgent:       "OMAP/1.0 (Advanced Reconnaissance Engine)",
		MaxDepth:        3,
		FollowRedirects: true,
		VerifySSL:       false,

		// Module enablement
		EnableSubdomainEnum:    true,
		EnableDNSAnalysis:      true,
		EnableWebTechDetection: true,
		EnableVulnScanning:     true,

		// Subdomain enumeration
		SubdomainWordlists: []string{
			"common.txt",
			"subdomains-top1million-5000.txt",
		},
		SubdomainSources: []string{
			"crt.sh",
			"virustotal",
			"securitytrails",
		},
		MaxSubdomains: 1000,

		// DNS analysis
		DNSServers: []string{
			"8.8.8.8",
			"1.1.1.1",
			"208.67.222.222",
		},
		DNSRecordTypes: []string{
			"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA",
		},
		EnableDNSSEC: false,

		// Web technology detection
		AnalyzeSSL:         true,
		AnalyzeSecurity:    true,
		AnalyzePerformance: true,
		CustomHeaders:      make(map[string]string),

		// Vulnerability scanning
		ScanSSL:       true,
		ScanHeaders:   true,
		ScanFiles:     true,
		ScanInjection: false, // Disabled by default for safety
		CustomPayloads: []string{},
		ExcludePaths: []string{
			"/logout",
			"/admin/delete",
			"/api/delete",
		},

		// Output settings
		OutputFormat:   "json",
		OutputFile:     "",
		Verbose:        false,
		Quiet:          false,
		IncludeRawData: false,
	}
}

// ParseReconFlags parses reconnaissance-specific command line flags
func (cli *ReconCLI) ParseReconFlags(args []string) error {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		
		switch {
		// General settings
		case arg == "--recon-threads" && i+1 < len(args):
			fmt.Sscanf(args[i+1], "%d", &cli.config.Threads)
			i++
		case arg == "--recon-timeout" && i+1 < len(args):
			var seconds int
			fmt.Sscanf(args[i+1], "%d", &seconds)
			cli.config.Timeout = time.Duration(seconds) * time.Second
			i++
		case arg == "--recon-user-agent" && i+1 < len(args):
			cli.config.UserAgent = args[i+1]
			i++
		case arg == "--recon-max-depth" && i+1 < len(args):
			fmt.Sscanf(args[i+1], "%d", &cli.config.MaxDepth)
			i++
		case arg == "--recon-no-redirects":
			cli.config.FollowRedirects = false
		case arg == "--recon-verify-ssl":
			cli.config.VerifySSL = true

		// Module enablement
		case arg == "--recon-no-subdomains":
			cli.config.EnableSubdomainEnum = false
		case arg == "--recon-no-dns":
			cli.config.EnableDNSAnalysis = false
		case arg == "--recon-no-webtech":
			cli.config.EnableWebTechDetection = false
		case arg == "--recon-no-vulns":
			cli.config.EnableVulnScanning = false
		case arg == "--recon-only-subdomains":
			cli.config.EnableSubdomainEnum = true
			cli.config.EnableDNSAnalysis = false
			cli.config.EnableWebTechDetection = false
			cli.config.EnableVulnScanning = false
		case arg == "--recon-only-dns":
			cli.config.EnableSubdomainEnum = false
			cli.config.EnableDNSAnalysis = true
			cli.config.EnableWebTechDetection = false
			cli.config.EnableVulnScanning = false
		case arg == "--recon-only-webtech":
			cli.config.EnableSubdomainEnum = false
			cli.config.EnableDNSAnalysis = false
			cli.config.EnableWebTechDetection = true
			cli.config.EnableVulnScanning = false
		case arg == "--recon-only-vulns":
			cli.config.EnableSubdomainEnum = false
			cli.config.EnableDNSAnalysis = false
			cli.config.EnableWebTechDetection = false
			cli.config.EnableVulnScanning = true

		// Subdomain enumeration
		case arg == "--recon-subdomain-wordlist" && i+1 < len(args):
			cli.config.SubdomainWordlists = strings.Split(args[i+1], ",")
			i++
		case arg == "--recon-subdomain-sources" && i+1 < len(args):
			cli.config.SubdomainSources = strings.Split(args[i+1], ",")
			i++
		case arg == "--recon-max-subdomains" && i+1 < len(args):
			fmt.Sscanf(args[i+1], "%d", &cli.config.MaxSubdomains)
			i++

		// DNS analysis
		case arg == "--recon-dns-servers" && i+1 < len(args):
			cli.config.DNSServers = strings.Split(args[i+1], ",")
			i++
		case arg == "--recon-dns-types" && i+1 < len(args):
			cli.config.DNSRecordTypes = strings.Split(args[i+1], ",")
			i++
		case arg == "--recon-enable-dnssec":
			cli.config.EnableDNSSEC = true

		// Web technology detection
		case arg == "--recon-no-ssl-analysis":
			cli.config.AnalyzeSSL = false
		case arg == "--recon-no-security-analysis":
			cli.config.AnalyzeSecurity = false
		case arg == "--recon-no-performance-analysis":
			cli.config.AnalyzePerformance = false
		case arg == "--recon-custom-header" && i+1 < len(args):
			headerParts := strings.SplitN(args[i+1], ":", 2)
			if len(headerParts) == 2 {
				if cli.config.CustomHeaders == nil {
					cli.config.CustomHeaders = make(map[string]string)
				}
				cli.config.CustomHeaders[strings.TrimSpace(headerParts[0])] = strings.TrimSpace(headerParts[1])
			}
			i++

		// Vulnerability scanning
		case arg == "--recon-no-ssl-scan":
			cli.config.ScanSSL = false
		case arg == "--recon-no-header-scan":
			cli.config.ScanHeaders = false
		case arg == "--recon-no-file-scan":
			cli.config.ScanFiles = false
		case arg == "--recon-enable-injection-scan":
			cli.config.ScanInjection = true
		case arg == "--recon-custom-payload" && i+1 < len(args):
			cli.config.CustomPayloads = append(cli.config.CustomPayloads, args[i+1])
			i++
		case arg == "--recon-exclude-path" && i+1 < len(args):
			cli.config.ExcludePaths = append(cli.config.ExcludePaths, args[i+1])
			i++

		// Output settings
		case arg == "--recon-output-format" && i+1 < len(args):
			cli.config.OutputFormat = args[i+1]
			i++
		case arg == "--recon-output-file" && i+1 < len(args):
			cli.config.OutputFile = args[i+1]
			i++
		case arg == "--recon-verbose":
			cli.config.Verbose = true
		case arg == "--recon-quiet":
			cli.config.Quiet = true
		case arg == "--recon-include-raw":
			cli.config.IncludeRawData = true
		}
	}

	return nil
}

// RunReconnaissance executes reconnaissance on the specified target
func (cli *ReconCLI) RunReconnaissance(target string) error {
	// Initialize the reconnaissance engine
	cli.engine = NewReconEngine(cli.config)

	if !cli.config.Quiet {
		fmt.Printf("\n[*] Starting Advanced Reconnaissance on %s\n", target)
		fmt.Printf("[*] Configuration:\n")
		fmt.Printf("    Threads: %d\n", cli.config.Threads)
		fmt.Printf("    Timeout: %v\n", cli.config.Timeout)
		fmt.Printf("    Modules: ")
		
		modules := []string{}
		if cli.config.EnableSubdomainEnum {
			modules = append(modules, "Subdomains")
		}
		if cli.config.EnableDNSAnalysis {
			modules = append(modules, "DNS")
		}
		if cli.config.EnableWebTechDetection {
			modules = append(modules, "WebTech")
		}
		if cli.config.EnableVulnScanning {
			modules = append(modules, "Vulnerabilities")
		}
		fmt.Printf("%s\n\n", strings.Join(modules, ", "))
	}

	// Run reconnaissance
	result, err := cli.engine.RunReconnaissance(target)
	if err != nil {
		return fmt.Errorf("reconnaissance failed: %v", err)
	}

	// Display results
	if !cli.config.Quiet {
		cli.displayResults(result)
	}

	// Export results if output file specified
	if cli.config.OutputFile != "" {
		if err := cli.exportResults(result); err != nil {
			fmt.Printf("[!] Failed to export results: %v\n", err)
		} else if !cli.config.Quiet {
			fmt.Printf("[+] Results exported to %s\n", cli.config.OutputFile)
		}
	}

	return nil
}

// displayResults displays reconnaissance results in a formatted manner
func (cli *ReconCLI) displayResults(result *ReconResult) {
	fmt.Printf("\n" + strings.Repeat("=", 80) + "\n")
	fmt.Printf("RECONNAISSANCE RESULTS FOR %s\n", strings.ToUpper(result.Target))
	fmt.Printf(strings.Repeat("=", 80) + "\n\n")

	// Summary
	fmt.Printf("📊 SUMMARY\n")
	fmt.Printf(strings.Repeat("-", 40) + "\n")
	fmt.Printf("Target Domain:      %s\n", result.Domain)
	fmt.Printf("Scan Duration:      %v\n", result.ScanDuration)
	fmt.Printf("Modules Executed:   %s\n", strings.Join(result.ModulesExecuted, ", "))
	fmt.Printf("Overall Risk:       %s\n", result.RiskAssessment.OverallRisk)
	fmt.Printf("Risk Score:         %d\n", result.RiskAssessment.RiskScore)
	fmt.Printf("\n")

	// Statistics
	fmt.Printf("📈 STATISTICS\n")
	fmt.Printf(strings.Repeat("-", 40) + "\n")
	fmt.Printf("Subdomains Found:      %d\n", result.Statistics.SubdomainsFound)
	fmt.Printf("DNS Records Found:     %d\n", result.Statistics.DNSRecordsFound)
	fmt.Printf("Web Assets Found:      %d\n", result.Statistics.WebAssetsFound)
	fmt.Printf("Technologies Found:    %d\n", result.Statistics.TechnologiesFound)
	fmt.Printf("Vulnerabilities Found: %d\n", result.Statistics.VulnerabilitiesFound)
	fmt.Printf("Exposed Files Found:   %d\n", result.Statistics.ExposedFilesFound)
	fmt.Printf("SSL Issues Found:      %d\n", result.Statistics.SSLIssuesFound)
	fmt.Printf("\n")

	// Subdomains
	if len(result.Subdomains) > 0 {
		fmt.Printf("🌐 SUBDOMAINS (%d found)\n", len(result.Subdomains))
		fmt.Printf(strings.Repeat("-", 40) + "\n")
		for i, subdomain := range result.Subdomains {
			if i >= 10 && !cli.config.Verbose {
				fmt.Printf("... and %d more (use --recon-verbose to see all)\n", len(result.Subdomains)-10)
				break
			}
			status := "❌"
			if subdomain.Status == "active" {
				status = "✅"
			}
			fmt.Printf("%s %s\n", status, subdomain.Subdomain)
			if cli.config.Verbose && len(subdomain.IPs) > 0 {
				fmt.Printf("    IPs: %s\n", strings.Join(subdomain.IPs, ", "))
			}
		}
		fmt.Printf("\n")
	}

	// Assets
	if len(result.Assets) > 0 {
		fmt.Printf("🎯 ASSETS (%d found)\n", len(result.Assets))
		fmt.Printf(strings.Repeat("-", 40) + "\n")
		for i, asset := range result.Assets {
			if i >= 10 && !cli.config.Verbose {
				fmt.Printf("... and %d more (use --recon-verbose to see all)\n", len(result.Assets)-10)
				break
			}
			riskIcon := cli.getRiskIcon(asset.RiskLevel)
			sslIcon := "🔓"
			if asset.SSL {
				sslIcon = "🔒"
			}
			fmt.Printf("%s %s %s", riskIcon, sslIcon, asset.URL)
			if asset.Title != "" {
				fmt.Printf(" - %s", asset.Title)
			}
			fmt.Printf("\n")
			if cli.config.Verbose {
				if asset.IP != "" {
					fmt.Printf("    IP: %s:%d\n", asset.IP, asset.Port)
				}
				if asset.Technology != "" {
					fmt.Printf("    Technology: %s\n", asset.Technology)
				}
				if asset.VulnCount > 0 {
					fmt.Printf("    Vulnerabilities: %d\n", asset.VulnCount)
				}
			}
		}
		fmt.Printf("\n")
	}

	// Vulnerabilities Summary
	if result.Statistics.VulnerabilitiesFound > 0 {
		fmt.Printf("🚨 VULNERABILITIES SUMMARY\n")
		fmt.Printf(strings.Repeat("-", 40) + "\n")
		fmt.Printf("Total: %d\n", result.RiskAssessment.VulnSummary.Total)
		if result.RiskAssessment.VulnSummary.CVSSAverage > 0 {
			fmt.Printf("Average CVSS: %.1f\n", result.RiskAssessment.VulnSummary.CVSSAverage)
		}
		fmt.Printf("By Severity:\n")
		for severity, count := range result.RiskAssessment.VulnSummary.BySeverity {
			if count > 0 {
				icon := cli.getSeverityIcon(severity)
				fmt.Printf("  %s %s: %d\n", icon, severity, count)
			}
		}
		fmt.Printf("\n")
	}

	// Critical Issues
	if len(result.RiskAssessment.CriticalIssues) > 0 {
		fmt.Printf("🔥 CRITICAL ISSUES\n")
		fmt.Printf(strings.Repeat("-", 40) + "\n")
		for i, issue := range result.RiskAssessment.CriticalIssues {
			if i >= 5 && !cli.config.Verbose {
				fmt.Printf("... and %d more (use --recon-verbose to see all)\n", len(result.RiskAssessment.CriticalIssues)-5)
				break
			}
			fmt.Printf("❗ %s\n", issue)
		}
		fmt.Printf("\n")
	}

	// Recommendations
	if len(result.RiskAssessment.Recommendations) > 0 {
		fmt.Printf("💡 RECOMMENDATIONS\n")
		fmt.Printf(strings.Repeat("-", 40) + "\n")
		for i, rec := range result.RiskAssessment.Recommendations {
			if i >= 5 && !cli.config.Verbose {
				fmt.Printf("... and %d more (use --recon-verbose to see all)\n", len(result.RiskAssessment.Recommendations)-5)
				break
			}
			fmt.Printf("💡 %s\n", rec)
		}
		fmt.Printf("\n")
	}

	// Errors
	if len(result.Errors) > 0 {
		fmt.Printf("⚠️  ERRORS\n")
		fmt.Printf(strings.Repeat("-", 40) + "\n")
		for _, err := range result.Errors {
			fmt.Printf("⚠️  %s\n", err)
		}
		fmt.Printf("\n")
	}

	fmt.Printf(strings.Repeat("=", 80) + "\n")
}

// getRiskIcon returns an icon for the risk level
func (cli *ReconCLI) getRiskIcon(riskLevel string) string {
	switch strings.ToLower(riskLevel) {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🟢"
	default:
		return "⚪"
	}
}

// getSeverityIcon returns an icon for the severity level
func (cli *ReconCLI) getSeverityIcon(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🟢"
	case "info":
		return "🔵"
	default:
		return "⚪"
	}
}

// exportResults exports reconnaissance results to file
func (cli *ReconCLI) exportResults(result *ReconResult) error {
	// Ensure output directory exists
	outputDir := filepath.Dir(cli.config.OutputFile)
	if outputDir != "." && outputDir != "" {
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %v", err)
		}
	}

	// Determine format from file extension if not specified
	format := cli.config.OutputFormat
	if format == "" {
		ext := strings.ToLower(filepath.Ext(cli.config.OutputFile))
		switch ext {
		case ".json":
			format = "json"
		case ".html":
			format = "html"
		case ".csv":
			format = "csv"
		case ".xml":
			format = "xml"
		default:
			format = "json" // Default to JSON
		}
	}

	return cli.engine.ExportResults(result.Target, format, cli.config.OutputFile)
}

// PrintReconHelp prints help information for reconnaissance options
func (cli *ReconCLI) PrintReconHelp() {
	fmt.Printf(`
Advanced Reconnaissance Options:

`)
	fmt.Printf(`General Settings:
`)
	fmt.Printf(`  --recon-threads <n>           Number of concurrent threads (default: 20)
`)
	fmt.Printf(`  --recon-timeout <seconds>     Request timeout in seconds (default: 30)
`)
	fmt.Printf(`  --recon-user-agent <string>   Custom User-Agent string
`)
	fmt.Printf(`  --recon-max-depth <n>         Maximum crawling depth (default: 3)
`)
	fmt.Printf(`  --recon-no-redirects          Don't follow HTTP redirects
`)
	fmt.Printf(`  --recon-verify-ssl            Verify SSL certificates
`)
	fmt.Printf(`\n`)

	fmt.Printf(`Module Control:
`)
	fmt.Printf(`  --recon-no-subdomains         Disable subdomain enumeration
`)
	fmt.Printf(`  --recon-no-dns                Disable DNS analysis
`)
	fmt.Printf(`  --recon-no-webtech            Disable web technology detection
`)
	fmt.Printf(`  --recon-no-vulns              Disable vulnerability scanning
`)
	fmt.Printf(`  --recon-only-subdomains       Only run subdomain enumeration
`)
	fmt.Printf(`  --recon-only-dns              Only run DNS analysis
`)
	fmt.Printf(`  --recon-only-webtech          Only run web technology detection
`)
	fmt.Printf(`  --recon-only-vulns            Only run vulnerability scanning
`)
	fmt.Printf(`\n`)

	fmt.Printf(`Subdomain Enumeration:
`)
	fmt.Printf(`  --recon-subdomain-wordlist <files>  Comma-separated wordlist files
`)
	fmt.Printf(`  --recon-subdomain-sources <sources> Comma-separated sources (crt.sh,virustotal,etc)
`)
	fmt.Printf(`  --recon-max-subdomains <n>          Maximum subdomains to find (default: 1000)
`)
	fmt.Printf(`\n`)

	fmt.Printf(`DNS Analysis:
`)
	fmt.Printf(`  --recon-dns-servers <servers>       Comma-separated DNS servers
`)
	fmt.Printf(`  --recon-dns-types <types>           Comma-separated record types (A,AAAA,CNAME,etc)
`)
	fmt.Printf(`  --recon-enable-dnssec               Enable DNSSEC analysis
`)
	fmt.Printf(`\n`)

	fmt.Printf(`Web Technology Detection:
`)
	fmt.Printf(`  --recon-no-ssl-analysis             Disable SSL/TLS analysis
`)
	fmt.Printf(`  --recon-no-security-analysis        Disable security header analysis
`)
	fmt.Printf(`  --recon-no-performance-analysis     Disable performance analysis
`)
	fmt.Printf(`  --recon-custom-header <name:value>  Add custom HTTP header
`)
	fmt.Printf(`\n`)

	fmt.Printf(`Vulnerability Scanning:
`)
	fmt.Printf(`  --recon-no-ssl-scan                 Disable SSL vulnerability scanning
`)
	fmt.Printf(`  --recon-no-header-scan              Disable security header scanning
`)
	fmt.Printf(`  --recon-no-file-scan                Disable exposed file scanning
`)
	fmt.Printf(`  --recon-enable-injection-scan       Enable injection vulnerability scanning
`)
	fmt.Printf(`  --recon-custom-payload <payload>    Add custom vulnerability payload
`)
	fmt.Printf(`  --recon-exclude-path <path>         Exclude path from scanning
`)
	fmt.Printf(`\n`)

	fmt.Printf(`Output Options:
`)
	fmt.Printf(`  --recon-output-format <format>      Output format (json,html,csv,xml)
`)
	fmt.Printf(`  --recon-output-file <file>          Output file path
`)
	fmt.Printf(`  --recon-verbose                     Verbose output
`)
	fmt.Printf(`  --recon-quiet                       Quiet mode (minimal output)
`)
	fmt.Printf(`  --recon-include-raw                 Include raw data in output
`)
	fmt.Printf(`\n`)

	fmt.Printf(`Examples:
`)
	fmt.Printf(`  omap --recon example.com
`)
	fmt.Printf(`  omap --recon --recon-only-subdomains --recon-verbose example.com
`)
	fmt.Printf(`  omap --recon --recon-output-file results.json example.com
`)
	fmt.Printf(`  omap --recon --recon-no-vulns --recon-threads 50 example.com
`)
	fmt.Printf(`\n`)
}

// ValidateReconConfig validates the reconnaissance configuration
func (cli *ReconCLI) ValidateReconConfig() error {
	// Validate threads
	if cli.config.Threads < 1 || cli.config.Threads > 100 {
		return fmt.Errorf("threads must be between 1 and 100")
	}

	// Validate timeout
	if cli.config.Timeout < time.Second || cli.config.Timeout > 5*time.Minute {
		return fmt.Errorf("timeout must be between 1 second and 5 minutes")
	}

	// Validate max depth
	if cli.config.MaxDepth < 1 || cli.config.MaxDepth > 10 {
		return fmt.Errorf("max depth must be between 1 and 10")
	}

	// Validate max subdomains
	if cli.config.MaxSubdomains < 1 || cli.config.MaxSubdomains > 10000 {
		return fmt.Errorf("max subdomains must be between 1 and 10000")
	}

	// Validate output format
	validFormats := []string{"json", "html", "csv", "xml"}
	formatValid := false
	for _, format := range validFormats {
		if strings.ToLower(cli.config.OutputFormat) == format {
			formatValid = true
			break
		}
	}
	if !formatValid {
		return fmt.Errorf("output format must be one of: %s", strings.Join(validFormats, ", "))
	}

	// Validate that at least one module is enabled
	if !cli.config.EnableSubdomainEnum && !cli.config.EnableDNSAnalysis && 
	   !cli.config.EnableWebTechDetection && !cli.config.EnableVulnScanning {
		return fmt.Errorf("at least one reconnaissance module must be enabled")
	}

	// Validate wordlist files exist
	for _, wordlist := range cli.config.SubdomainWordlists {
		if wordlist != "" {
			if _, err := os.Stat(wordlist); os.IsNotExist(err) {
				fmt.Printf("[!] Warning: Wordlist file not found: %s\n", wordlist)
			}
		}
	}

	return nil
}

// GetReconConfig returns the current reconnaissance configuration
func (cli *ReconCLI) GetReconConfig() ReconConfig {
	return cli.config
}

// SetReconConfig sets the reconnaissance configuration
func (cli *ReconCLI) SetReconConfig(config ReconConfig) {
	cli.config = config
}