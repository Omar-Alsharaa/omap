package scanner

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// ScanResult represents the result of scanning a single port
type ScanResult struct {
	Host    string
	Port    int
	Open    bool
	Banner  string
	Service string
	Latency time.Duration
	Error   error
}

// ScanConfig holds configuration for the scanner
type ScanConfig struct {
	Timeout       time.Duration
	Workers       int
	RateLimit     time.Duration // Delay between connections
	Retries       int
	BannerTimeout time.Duration
	ConnectOnly   bool // Skip banner grabbing if true
}

// DefaultScanConfig returns a default configuration
func DefaultScanConfig() *ScanConfig {
	return &ScanConfig{
		Timeout:       3 * time.Second,
		Workers:       100,
		RateLimit:     0, // No rate limiting by default
		Retries:       1,
		BannerTimeout: 2 * time.Second,
		ConnectOnly:   false,
	}
}

// AsyncScanner provides advanced scanning capabilities
type AsyncScanner struct {
	config *ScanConfig
	ctx    context.Context
	cancel context.CancelFunc
}

// NewAsyncScanner creates a new async scanner with the given configuration
func NewAsyncScanner(config *ScanConfig) *AsyncScanner {
	if config == nil {
		config = DefaultScanConfig()
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	return &AsyncScanner{
		config: config,
		ctx:    ctx,
		cancel: cancel,
	}
}

// ScanPort scans a single port on the target host
func (s *AsyncScanner) ScanPort(host string, port int) ScanResult {
	start := time.Now()
	result := ScanResult{
		Host: host,
		Port: port,
		Open: false,
	}
	
	// Create connection with timeout
	address := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{
		Timeout: s.config.Timeout,
	}
	
	conn, err := dialer.DialContext(s.ctx, "tcp", address)
	if err != nil {
		result.Error = err
		result.Latency = time.Since(start)
		return result
	}
	
	defer conn.Close()
	result.Open = true
	result.Latency = time.Since(start)
	
	// Skip banner grabbing if connect-only mode
	if s.config.ConnectOnly {
		return result
	}
	
	// Grab banner with timeout
	if banner := s.grabBannerWithTimeout(conn); banner != "" {
		result.Banner = banner
		result.Service = s.identifyService(port, banner)
	} else {
		result.Service = s.identifyServiceByPort(port)
	}
	
	return result
}

// grabBannerWithTimeout attempts to grab a banner with a specific timeout
func (s *AsyncScanner) grabBannerWithTimeout(conn net.Conn) string {
	// Set deadline for banner grabbing
	deadline := time.Now().Add(s.config.BannerTimeout)
	conn.SetReadDeadline(deadline)
	
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}
	
	banner := strings.TrimSpace(string(buffer[:n]))
	return banner
}

// ScanPorts scans multiple ports on a single host
func (s *AsyncScanner) ScanPorts(host string, ports []int) []ScanResult {
	var results []ScanResult
	var mutex sync.Mutex
	var wg sync.WaitGroup
	
	// Create semaphore for worker pool
	semaphore := make(chan struct{}, s.config.Workers)
	
	// Rate limiting channel
	var rateLimiter <-chan time.Time
	if s.config.RateLimit > 0 {
		ticker := time.NewTicker(s.config.RateLimit)
		defer ticker.Stop()
		rateLimiter = ticker.C
	}
	
	for _, port := range ports {
		// Check if context is cancelled
		select {
		case <-s.ctx.Done():
			return results
		default:
		}
		
		// Rate limiting
		if rateLimiter != nil {
			<-rateLimiter
		}
		
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			
			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			
			result := s.scanPortWithRetry(host, p)
			
			mutex.Lock()
			results = append(results, result)
			mutex.Unlock()
		}(port)
	}
	
	wg.Wait()
	
	// Sort results by port number
	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})
	
	return results
}

// scanPortWithRetry scans a port with retry logic
func (s *AsyncScanner) scanPortWithRetry(host string, port int) ScanResult {
	var lastResult ScanResult
	
	for attempt := 0; attempt <= s.config.Retries; attempt++ {
		result := s.ScanPort(host, port)
		
		// If successful or no retries left, return result
		if result.Open || attempt == s.config.Retries {
			return result
		}
		
		lastResult = result
		
		// Small delay between retries
		time.Sleep(100 * time.Millisecond)
	}
	
	return lastResult
}

// identifyService identifies service based on port and banner
func (s *AsyncScanner) identifyService(port int, banner string) string {
	service := s.identifyServiceByPort(port)
	
	// Enhance with banner analysis
	if banner != "" {
		banner = strings.ToLower(banner)
		if strings.Contains(banner, "ssh") {
			return "SSH"
		} else if strings.Contains(banner, "http") {
			return "HTTP"
		} else if strings.Contains(banner, "ftp") {
			return "FTP"
		} else if strings.Contains(banner, "smtp") {
			return "SMTP"
		} else if strings.Contains(banner, "pop3") {
			return "POP3"
		} else if strings.Contains(banner, "imap") {
			return "IMAP"
		}
	}
	
	return service
}

// identifyServiceByPort identifies service based on port number only
func (s *AsyncScanner) identifyServiceByPort(port int) string {
	serviceMap := map[int]string{
		21:   "FTP",
		22:   "SSH",
		23:   "Telnet",
		25:   "SMTP",
		53:   "DNS",
		80:   "HTTP",
		110:  "POP3",
		135:  "RPC",
		139:  "NetBIOS",
		143:  "IMAP",
		443:  "HTTPS",
		445:  "SMB",
		993:  "IMAPS",
		995:  "POP3S",
		1433: "MSSQL",
		3306: "MySQL",
		3389: "RDP",
		5432: "PostgreSQL",
		6379: "Redis",
		27017: "MongoDB",
	}
	
	if service, exists := serviceMap[port]; exists {
		return service
	}
	return "Unknown"
}

// Cancel stops all ongoing scans
func (s *AsyncScanner) Cancel() {
	s.cancel()
}

// GetOpenPorts filters and returns only open ports from scan results
func GetOpenPorts(results []ScanResult) []ScanResult {
	var openPorts []ScanResult
	for _, result := range results {
		if result.Open {
			openPorts = append(openPorts, result)
		}
	}
	return openPorts
}

// GeneratePortRange generates a slice of ports from start to end
func GeneratePortRange(start, end int) []int {
	if start > end {
		start, end = end, start
	}
	
	ports := make([]int, end-start+1)
	for i := range ports {
		ports[i] = start + i
	}
	return ports
}

// CommonPorts returns a list of commonly scanned ports
func CommonPorts() []int {
	return []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
		1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017,
	}
}