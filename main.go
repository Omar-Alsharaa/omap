package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"omap/fingerprint"
	"omap/network"
	"omap/plugins"
	"omap/recon"
	"omap/scanner"
)

// ScanOptions holds all scanning configuration
type ScanOptions struct {
	Targets         string
	Ports           string
	Workers         int
	Timeout         time.Duration
	RateLimit       time.Duration
	ConnectOnly     bool
	EnablePlugins   bool
	PluginDir       string
	OSDetection     bool
	ServiceDetection bool
	Verbose         bool
	OutputFormat    string
	OutputFile      string
	// Reconnaissance options
	EnableRecon     bool
	ReconMode       string
}

// HostResult represents scan results for a single host
type HostResult struct {
	Host            string
	Hostname        string
	Ports           []scanner.ScanResult
	OSFingerprint   fingerprint.OSFingerprint
	PluginResults   []plugins.PluginResult
	ScanDuration    time.Duration
}

func main() {
	opts := parseFlags()
	
	if opts.Targets == "" {
		fmt.Println("Error: Target is required")
		printUsage()
		os.Exit(1)
	}
	
	// Handle reconnaissance mode
	if opts.EnableRecon {
		runReconnaissance(opts)
		return
	}
	
	// Parse targets
	parser := network.NewTargetParser()
	targets, err := parser.ParseTargets(opts.Targets)
	if err != nil {
		fmt.Printf("Error parsing targets: %v\n", err)
		os.Exit(1)
	}
	
	// Parse ports
	ports, err := parsePorts(opts.Ports)
	if err != nil {
		fmt.Printf("Error parsing ports: %v\n", err)
		os.Exit(1)
	}
	
	fmt.Printf("OMAP - Advanced Network Scanner\n")
	fmt.Printf("================================\n\n")
	fmt.Printf("Targets: %d\n", len(targets))
	fmt.Printf("Ports: %d\n", len(ports))
	fmt.Printf("Workers: %d\n", opts.Workers)
	fmt.Printf("Timeout: %v\n", opts.Timeout)
	if opts.RateLimit > 0 {
		fmt.Printf("Rate Limit: %v\n", opts.RateLimit)
	}
	fmt.Printf("\nStarting scan...\n\n")
	
	// Initialize components
	var pluginManager *plugins.PluginManager
	var osDetector *fingerprint.OSDetector
	var serviceDetector *fingerprint.ServiceDetector
	
	if opts.EnablePlugins {
		pluginManager = plugins.NewPluginManager(opts.PluginDir)
		if err := pluginManager.LoadPlugins(); err != nil {
			fmt.Printf("Warning: Failed to load plugins: %v\n", err)
		} else {
			pluginCount := len(pluginManager.GetPlugins())
			fmt.Printf("Loaded %d plugins\n", pluginCount)
		}
	}
	
	if opts.OSDetection {
		osDetector = fingerprint.NewOSDetector(opts.Timeout)
	}
	
	if opts.ServiceDetection {
		serviceDetector = fingerprint.NewServiceDetector()
	}
	
	// Scan all targets
	var allResults []HostResult
	overallStart := time.Now()
	
	for i, target := range targets {
		if opts.Verbose {
			fmt.Printf("[%d/%d] Scanning %s...\n", i+1, len(targets), target.IP.String())
		}
		
		result := scanTarget(target, ports, opts, pluginManager, osDetector, serviceDetector)
		allResults = append(allResults, result)
	}
	
	overallDuration := time.Since(overallStart)
	
	// Print results
	printScanResults(allResults, overallDuration, opts)
}

func parseFlags() *ScanOptions {
	opts := &ScanOptions{}
	
	flag.StringVar(&opts.Targets, "t", "", "Target specification (IP, hostname, CIDR, or range)")
	flag.StringVar(&opts.Targets, "target", "", "Target specification (IP, hostname, CIDR, or range)")
	flag.StringVar(&opts.Ports, "p", "1-1000", "Port specification (e.g., 22,80,443 or 1-1000)")
	flag.StringVar(&opts.Ports, "ports", "1-1000", "Port specification (e.g., 22,80,443 or 1-1000)")
	flag.IntVar(&opts.Workers, "w", 100, "Number of concurrent workers")
	flag.IntVar(&opts.Workers, "workers", 100, "Number of concurrent workers")
	flag.DurationVar(&opts.Timeout, "timeout", 3*time.Second, "Connection timeout")
	flag.DurationVar(&opts.RateLimit, "rate-limit", 0, "Rate limit between connections")
	flag.BoolVar(&opts.ConnectOnly, "connect-only", false, "Skip banner grabbing (faster)")
	flag.BoolVar(&opts.EnablePlugins, "plugins", false, "Enable plugin system")
	flag.StringVar(&opts.PluginDir, "plugin-dir", "./plugins/examples", "Plugin directory")
	flag.BoolVar(&opts.OSDetection, "os", false, "Enable OS detection")
	flag.BoolVar(&opts.ServiceDetection, "sV", false, "Enable service version detection")
	flag.BoolVar(&opts.Verbose, "v", false, "Verbose output")
	flag.StringVar(&opts.OutputFormat, "oF", "text", "Output format (text, json, xml)")
	flag.StringVar(&opts.OutputFile, "oN", "", "Output file")
	// Reconnaissance flags
	flag.BoolVar(&opts.EnableRecon, "recon", false, "Enable advanced reconnaissance mode")
	flag.StringVar(&opts.ReconMode, "recon-mode", "full", "Reconnaissance mode (full, subdomains, dns, webtech, vulns)")
	
	flag.Usage = printUsage
	flag.Parse()
	
	// Handle positional arguments for backward compatibility
	args := flag.Args()
	if len(args) > 0 && opts.Targets == "" {
		opts.Targets = args[0]
	}
	if len(args) > 1 {
		if startPort, err := strconv.Atoi(args[1]); err == nil {
			if len(args) > 2 {
				if endPort, err := strconv.Atoi(args[2]); err == nil {
					opts.Ports = fmt.Sprintf("%d-%d", startPort, endPort)
				}
			} else {
				opts.Ports = strconv.Itoa(startPort)
			}
		}
	}
	if len(args) > 3 {
		if workers, err := strconv.Atoi(args[3]); err == nil {
			opts.Workers = workers
		}
	}
	
	return opts
}

func parsePorts(portSpec string) ([]int, error) {
	// Handle preset port lists
	commonPortSets := network.GetCommonPortSets()
	presets := map[string][]int{
		"top-100":  commonPortSets["top-100"],
		"top-1000": commonPortSets["top-1000"],
		"common":   commonPortSets["common"],
		"web":      commonPortSets["web"],
		"database": commonPortSets["database"],
	}
	
	if preset, exists := presets[portSpec]; exists {
		return preset, nil
	}
	
	// Parse custom port specification
	return network.ParsePortRange(portSpec)
}

func scanTarget(target network.Target, ports []int, opts *ScanOptions, 
	pluginManager *plugins.PluginManager, osDetector *fingerprint.OSDetector, 
	serviceDetector *fingerprint.ServiceDetector) HostResult {
	
	start := time.Now()
	result := HostResult{
		Host:     target.IP.String(),
		Hostname: target.Hostname,
	}
	
	// Configure scanner
	config := scanner.ScanConfig{
		Workers:     opts.Workers,
		Timeout:     opts.Timeout,
		RateLimit:   opts.RateLimit,
		ConnectOnly: opts.ConnectOnly,
		Retries:     2,
		BannerTimeout: 2 * time.Second,
	}
	
	// Create and run scanner
	scn := scanner.NewAsyncScanner(&config)
	result.Ports = scn.ScanPorts(target.IP.String(), ports)
	
	// OS Detection
	if osDetector != nil && len(result.Ports) > 0 {
		result.OSFingerprint = osDetector.DetectOS(target.IP.String(), result.Ports)
	}
	
	// Enhanced service detection
	if serviceDetector != nil {
		for i := range result.Ports {
			if result.Ports[i].Open && result.Ports[i].Banner != "" {
				serviceFP := serviceDetector.DetectService(result.Ports[i].Port, result.Ports[i].Banner)
				result.Ports[i].Service = serviceFP.Service
				result.Ports[i].Version = serviceFP.Version
			}
		}
	}
	
	// Plugin execution
	if pluginManager != nil {
		for _, port := range result.Ports {
			if port.Open {
				context := plugins.ScanContext{
					Host:    target.IP.String(),
					Port:    port.Port,
					Service: port.Service,
					Banner:  port.Banner,
					Timeout: opts.Timeout,
				}
				
				pluginResults := pluginManager.ExecutePluginsForTarget(context)
				result.PluginResults = append(result.PluginResults, pluginResults...)
			}
		}
	}
	
	result.ScanDuration = time.Since(start)
	return result
}

func printScanResults(results []HostResult, overallDuration time.Duration, opts *ScanOptions) {
	totalHosts := len(results)
	totalOpenPorts := 0
	
	for _, result := range results {
		for _, port := range result.Ports {
			if port.Open {
				totalOpenPorts++
			}
		}
	}
	
	fmt.Printf("\n" + strings.Repeat("=", 60) + "\n")
	fmt.Printf("SCAN RESULTS\n")
	fmt.Printf(strings.Repeat("=", 60) + "\n\n")
	
	for _, result := range results {
		printHostResult(result, opts)
	}
	
	// Summary
	fmt.Printf("\n" + strings.Repeat("-", 60) + "\n")
	fmt.Printf("SCAN SUMMARY\n")
	fmt.Printf(strings.Repeat("-", 60) + "\n")
	fmt.Printf("Hosts scanned: %d\n", totalHosts)
	fmt.Printf("Total open ports: %d\n", totalOpenPorts)
	fmt.Printf("Scan duration: %.2f seconds\n", overallDuration.Seconds())
	fmt.Printf("Average time per host: %.2f seconds\n", overallDuration.Seconds()/float64(totalHosts))
}

func printHostResult(result HostResult, opts *ScanOptions) {
	openPorts := make([]scanner.ScanResult, 0)
	for _, port := range result.Ports {
		if port.Open {
			openPorts = append(openPorts, port)
		}
	}
	
	if len(openPorts) == 0 && !opts.Verbose {
		return // Skip hosts with no open ports unless verbose
	}
	
	fmt.Printf("Host: %s", result.Host)
	if result.Hostname != "" && result.Hostname != result.Host {
		fmt.Printf(" (%s)", result.Hostname)
	}
	fmt.Printf(" - Scan time: %.2fs\n", result.ScanDuration.Seconds())
	
	// OS Detection results
	if result.OSFingerprint.OS != "" {
		fmt.Printf("OS: %s", result.OSFingerprint.OS)
		if result.OSFingerprint.Version != "" {
			fmt.Printf(" %s", result.OSFingerprint.Version)
		}
		if result.OSFingerprint.Confidence > 0 {
			fmt.Printf(" (Confidence: %.1f%%)", result.OSFingerprint.Confidence*100)
		}
		fmt.Println()
	}
	
	if len(openPorts) == 0 {
		fmt.Println("No open ports found.")
	} else {
		fmt.Printf("\nOpen ports (%d):\n", len(openPorts))
		fmt.Println("PORT\tSTATE\tSERVICE\t\tVERSION\t\tBANNER")
		fmt.Println(strings.Repeat("-", 80))
		
		for _, port := range openPorts {
			service := port.Service
			if service == "" {
				service = "unknown"
			}
			
			version := port.Version
			if version == "" {
				version = "-"
			}
			
			banner := port.Banner
			if len(banner) > 30 {
				banner = banner[:27] + "..."
			}
			if banner == "" {
				banner = "-"
			}
			
			fmt.Printf("%d\topen\t%-15s\t%-15s\t%s\n", 
				port.Port, service, version, banner)
		}
	}
	
	// Plugin results
	if len(result.PluginResults) > 0 {
		fmt.Printf("\nPlugin Results:\n")
		for _, pluginResult := range result.PluginResults {
			fmt.Printf("  [%s] %s\n", pluginResult.PluginName, pluginResult.Summary)
			if opts.Verbose && len(pluginResult.Details) > 0 {
				for key, value := range pluginResult.Details {
					fmt.Printf("    %s: %v\n", key, value)
				}
			}
			if pluginResult.Severity != "" {
				fmt.Printf("    Severity: %s\n", pluginResult.Severity)
			}
		}
	}
	
	fmt.Println()
}

// runReconnaissance handles reconnaissance mode
func runReconnaissance(opts *ScanOptions) {
	// Create reconnaissance CLI
	reconCLI := recon.NewReconCLI()
	
	// Parse reconnaissance-specific flags from os.Args
	if err := reconCLI.ParseReconFlags(os.Args); err != nil {
		fmt.Printf("Error parsing reconnaissance flags: %v\n", err)
		os.Exit(1)
	}
	
	// Configure reconnaissance based on mode
	config := reconCLI.GetReconConfig()
	switch opts.ReconMode {
	case "subdomains":
		config.EnableSubdomainEnum = true
		config.EnableDNSAnalysis = false
		config.EnableWebTechDetection = false
		config.EnableVulnScanning = false
	case "dns":
		config.EnableSubdomainEnum = false
		config.EnableDNSAnalysis = true
		config.EnableWebTechDetection = false
		config.EnableVulnScanning = false
	case "webtech":
		config.EnableSubdomainEnum = false
		config.EnableDNSAnalysis = false
		config.EnableWebTechDetection = true
		config.EnableVulnScanning = false
	case "vulns":
		config.EnableSubdomainEnum = false
		config.EnableDNSAnalysis = false
		config.EnableWebTechDetection = false
		config.EnableVulnScanning = true
	case "full":
		// All modules enabled by default
	default:
		fmt.Printf("Unknown reconnaissance mode: %s\n", opts.ReconMode)
		fmt.Printf("Available modes: full, subdomains, dns, webtech, vulns\n")
		os.Exit(1)
	}
	
	// Apply general options
	if opts.Verbose {
		config.Verbose = true
	}
	if opts.OutputFile != "" {
		config.OutputFile = opts.OutputFile
		config.OutputFormat = opts.OutputFormat
	}
	if opts.Timeout > 0 {
		config.Timeout = opts.Timeout
	}
	if opts.Workers > 0 {
		config.Threads = opts.Workers
	}
	
	reconCLI.SetReconConfig(config)
	
	// Validate configuration
	if err := reconCLI.ValidateReconConfig(); err != nil {
		fmt.Printf("Configuration error: %v\n", err)
		os.Exit(1)
	}
	
	// Run reconnaissance
	if err := reconCLI.RunReconnaissance(opts.Targets); err != nil {
		fmt.Printf("Reconnaissance failed: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf(`OMAP - Advanced Network Scanner

Usage:
  omap -t <targets> [options]
  omap <target> [start_port] [end_port] [workers]  # Legacy format

Targets:
  Single IP:     192.168.1.1
  Hostname:      example.com
  CIDR:          192.168.1.0/24
  Range:         192.168.1.1-192.168.1.10
  Multiple:      192.168.1.1,192.168.1.5,10.0.0.0/24

Port Specifications:
  Single:        22
  Multiple:      22,80,443
  Range:         1-1000
  Mixed:         22,80-90,443
  Preset:        top-100, common, web, database

Reconnaissance Modes:
  --recon                       Enable advanced reconnaissance
  --recon-mode <mode>          Reconnaissance mode:
    full                        All reconnaissance modules (default)
    subdomains                  Subdomain enumeration only
    dns                         DNS analysis only
    webtech                     Web technology detection only
    vulns                       Vulnerability scanning only

Options:
`)
	flag.PrintDefaults()
	fmt.Printf(`
Examples:
  omap -t 192.168.1.1 -p 1-1000
  omap -t 192.168.1.0/24 -p top-100 --os --sV
  omap -t example.com -p 80,443 --plugins
  omap --recon -t example.com
  omap --recon --recon-mode subdomains -t example.com
  omap --recon --recon-verbose --recon-output-file results.json -t example.com
  omap 192.168.1.1 1 1000 200

For detailed reconnaissance options, use: omap --recon --help
`)
	
	// Show reconnaissance help if in recon mode
	for _, arg := range os.Args {
		if arg == "--recon" {
			reconCLI := recon.NewReconCLI()
			reconCLI.PrintReconHelp()
			break
		}
	}
}