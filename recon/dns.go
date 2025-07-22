package recon

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// DNSAnalyzer handles comprehensive DNS analysis
type DNSAnalyzer struct {
	resolvers []string
	timeout   time.Duration
	results   map[string]*DNSResult
	mutex     sync.RWMutex
}

// DNSResult contains comprehensive DNS information
type DNSResult struct {
	Domain       string            `json:"domain"`
	ARecords     []string          `json:"aRecords"`
	AAAARecords  []string          `json:"aaaaRecords"`
	CNAME        string            `json:"cname,omitempty"`
	MXRecords    []MXRecord        `json:"mxRecords"`
	NSRecords    []string          `json:"nsRecords"`
	TXTRecords   []string          `json:"txtRecords"`
	SOARecord    *SOARecord        `json:"soaRecord,omitempty"`
	PTRRecords   []string          `json:"ptrRecords,omitempty"`
	SRVRecords   []SRVRecord       `json:"srvRecords,omitempty"`
	DNSSEC       *DNSSECInfo       `json:"dnssec,omitempty"`
	ZoneTransfer *ZoneTransferInfo `json:"zoneTransfer,omitempty"`
	Timestamp    time.Time         `json:"timestamp"`
	ResponseTime time.Duration     `json:"responseTime"`
	Errors       []string          `json:"errors,omitempty"`
}

// MXRecord represents a mail exchange record
type MXRecord struct {
	Priority int    `json:"priority"`
	Host     string `json:"host"`
}

// SOARecord represents a start of authority record
type SOARecord struct {
	PrimaryNS   string `json:"primaryNS"`
	AdminEmail  string `json:"adminEmail"`
	Serial      uint32 `json:"serial"`
	Refresh     uint32 `json:"refresh"`
	Retry       uint32 `json:"retry"`
	Expire      uint32 `json:"expire"`
	MinimumTTL  uint32 `json:"minimumTTL"`
}

// SRVRecord represents a service record
type SRVRecord struct {
	Service  string `json:"service"`
	Protocol string `json:"protocol"`
	Priority uint16 `json:"priority"`
	Weight   uint16 `json:"weight"`
	Port     uint16 `json:"port"`
	Target   string `json:"target"`
}

// DNSSECInfo contains DNSSEC validation information
type DNSSECInfo struct {
	Enabled    bool     `json:"enabled"`
	Validated  bool     `json:"validated"`
	Algorithms []string `json:"algorithms,omitempty"`
	KeyTags    []uint16 `json:"keyTags,omitempty"`
	Errors     []string `json:"errors,omitempty"`
}

// ZoneTransferInfo contains zone transfer attempt results
type ZoneTransferInfo struct {
	Attempted   bool     `json:"attempted"`
	Successful  bool     `json:"successful"`
	NameServers []string `json:"nameServers"`
	Records     []string `json:"records,omitempty"`
	Errors      []string `json:"errors,omitempty"`
}

// DNSConfig holds configuration for DNS analysis
type DNSConfig struct {
	Servers         []string      `json:"servers"`
	RecordTypes     []string      `json:"recordTypes"`
	Threads         int           `json:"threads"`
	EnableDNSSEC    bool          `json:"enableDNSSEC"`
	Resolvers       []string      `json:"resolvers"`
	Timeout         time.Duration `json:"timeout"`
	CheckDNSSEC     bool          `json:"checkDNSSEC"`
	AttemptZoneXfer bool          `json:"attemptZoneTransfer"`
	CheckReverse    bool          `json:"checkReverse"`
	CheckSRV        bool          `json:"checkSRV"`
	Verbose         bool          `json:"verbose"`
}

// NewDNSAnalyzer creates a new DNS analyzer
func NewDNSAnalyzer(config DNSConfig) *DNSAnalyzer {
	resolvers := config.Resolvers
	if len(resolvers) == 0 {
		resolvers = []string{
			"8.8.8.8:53",
			"8.8.4.4:53",
			"1.1.1.1:53",
			"1.0.0.1:53",
			"208.67.222.222:53",
			"208.67.220.220:53",
			"9.9.9.9:53",
			"149.112.112.112:53",
		}
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	return &DNSAnalyzer{
		resolvers: resolvers,
		timeout:   timeout,
		results:   make(map[string]*DNSResult),
	}
}

// AnalyzeDomain performs comprehensive DNS analysis
func (da *DNSAnalyzer) AnalyzeDomain(domain string, config DNSConfig) (*DNSResult, error) {
	start := time.Now()

	result := &DNSResult{
		Domain:    domain,
		Timestamp: time.Now(),
		Errors:    make([]string, 0),
	}

	var wg sync.WaitGroup
	errorChan := make(chan string, 10)

	// Basic DNS lookups
	wg.Add(1)
	go func() {
		defer wg.Done()
		da.performBasicLookups(domain, result, errorChan)
	}()

	// MX record lookup
	wg.Add(1)
	go func() {
		defer wg.Done()
		da.lookupMXRecords(domain, result, errorChan)
	}()

	// NS record lookup
	wg.Add(1)
	go func() {
		defer wg.Done()
		da.lookupNSRecords(domain, result, errorChan)
	}()

	// TXT record lookup
	wg.Add(1)
	go func() {
		defer wg.Done()
		da.lookupTXTRecords(domain, result, errorChan)
	}()

	// SOA record lookup
	wg.Add(1)
	go func() {
		defer wg.Done()
		da.lookupSOARecord(domain, result, errorChan)
	}()

	// SRV record lookup
	if config.CheckSRV {
		wg.Add(1)
		go func() {
			defer wg.Done()
			da.lookupSRVRecords(domain, result, errorChan)
		}()
	}

	// DNSSEC check
	if config.CheckDNSSEC {
		wg.Add(1)
		go func() {
			defer wg.Done()
			da.checkDNSSEC(domain, result, errorChan)
		}()
	}

	// Zone transfer attempt
	if config.AttemptZoneXfer {
		wg.Add(1)
		go func() {
			defer wg.Done()
			da.attemptZoneTransfer(domain, result, errorChan)
		}()
	}

	// Reverse DNS lookup
	if config.CheckReverse {
		wg.Add(1)
		go func() {
			defer wg.Done()
			da.performReverseLookups(result, errorChan)
		}()
	}

	// Wait for all lookups to complete
	go func() {
		wg.Wait()
		close(errorChan)
	}()

	// Collect errors
	for err := range errorChan {
		result.Errors = append(result.Errors, err)
	}

	result.ResponseTime = time.Since(start)

	// Store result
	da.mutex.Lock()
	da.results[domain] = result
	da.mutex.Unlock()

	return result, nil
}

// performBasicLookups performs A, AAAA, and CNAME lookups
func (da *DNSAnalyzer) performBasicLookups(domain string, result *DNSResult, errorChan chan<- string) {
	for _, resolver := range da.resolvers {
		ctx, cancel := context.WithTimeout(context.Background(), da.timeout)
		defer cancel()

		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: da.timeout}
				return d.DialContext(ctx, network, resolver)
			},
		}

		// A records
		if ips, err := r.LookupIPAddr(ctx, domain); err == nil {
			for _, ip := range ips {
				if ip.IP.To4() != nil {
					result.ARecords = append(result.ARecords, ip.IP.String())
				} else {
					result.AAAARecords = append(result.AAAARecords, ip.IP.String())
				}
			}
			break // Success, no need to try other resolvers
		} else if len(da.resolvers) == 1 {
			errorChan <- fmt.Sprintf("A/AAAA lookup failed: %v", err)
		}

		// CNAME record
		if cname, err := r.LookupCNAME(ctx, domain); err == nil {
			if cname != domain+"." {
				result.CNAME = strings.TrimSuffix(cname, ".")
			}
			break
		}
	}

	// Remove duplicates
	result.ARecords = removeDuplicates(result.ARecords)
	result.AAAARecords = removeDuplicates(result.AAAARecords)
}

// lookupMXRecords performs MX record lookup
func (da *DNSAnalyzer) lookupMXRecords(domain string, result *DNSResult, errorChan chan<- string) {
	for _, resolver := range da.resolvers {
		ctx, cancel := context.WithTimeout(context.Background(), da.timeout)
		defer cancel()

		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: da.timeout}
				return d.DialContext(ctx, network, resolver)
			},
		}

		if mxRecords, err := r.LookupMX(ctx, domain); err == nil {
			for _, mx := range mxRecords {
				result.MXRecords = append(result.MXRecords, MXRecord{
					Priority: int(mx.Pref),
					Host:     strings.TrimSuffix(mx.Host, "."),
				})
			}
			// Sort by priority
			sort.Slice(result.MXRecords, func(i, j int) bool {
				return result.MXRecords[i].Priority < result.MXRecords[j].Priority
			})
			break
		} else if len(da.resolvers) == 1 {
			errorChan <- fmt.Sprintf("MX lookup failed: %v", err)
		}
	}
}

// lookupNSRecords performs NS record lookup
func (da *DNSAnalyzer) lookupNSRecords(domain string, result *DNSResult, errorChan chan<- string) {
	for _, resolver := range da.resolvers {
		ctx, cancel := context.WithTimeout(context.Background(), da.timeout)
		defer cancel()

		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: da.timeout}
				return d.DialContext(ctx, network, resolver)
			},
		}

		if nsRecords, err := r.LookupNS(ctx, domain); err == nil {
			for _, ns := range nsRecords {
				result.NSRecords = append(result.NSRecords, strings.TrimSuffix(ns.Host, "."))
			}
			result.NSRecords = removeDuplicates(result.NSRecords)
			sort.Strings(result.NSRecords)
			break
		} else if len(da.resolvers) == 1 {
			errorChan <- fmt.Sprintf("NS lookup failed: %v", err)
		}
	}
}

// lookupTXTRecords performs TXT record lookup
func (da *DNSAnalyzer) lookupTXTRecords(domain string, result *DNSResult, errorChan chan<- string) {
	for _, resolver := range da.resolvers {
		ctx, cancel := context.WithTimeout(context.Background(), da.timeout)
		defer cancel()

		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: da.timeout}
				return d.DialContext(ctx, network, resolver)
			},
		}

		if txtRecords, err := r.LookupTXT(ctx, domain); err == nil {
			result.TXTRecords = txtRecords
			sort.Strings(result.TXTRecords)
			break
		} else if len(da.resolvers) == 1 {
			errorChan <- fmt.Sprintf("TXT lookup failed: %v", err)
		}
	}
}

// lookupSOARecord performs SOA record lookup
func (da *DNSAnalyzer) lookupSOARecord(domain string, result *DNSResult, errorChan chan<- string) {
	// SOA lookup is more complex and would require a DNS library
	// This is a simplified placeholder
	errorChan <- "SOA lookup not implemented (requires DNS library)"
}

// lookupSRVRecords performs SRV record lookup for common services
func (da *DNSAnalyzer) lookupSRVRecords(domain string, result *DNSResult, errorChan chan<- string) {
	commonServices := []string{
		"_http._tcp",
		"_https._tcp",
		"_ftp._tcp",
		"_ssh._tcp",
		"_smtp._tcp",
		"_pop3._tcp",
		"_imap._tcp",
		"_ldap._tcp",
		"_sip._tcp",
		"_sip._udp",
		"_xmpp-server._tcp",
		"_xmpp-client._tcp",
		"_caldav._tcp",
		"_carddav._tcp",
		"_autodiscover._tcp",
	}

	for _, service := range commonServices {
		serviceDomain := service + "." + domain
		for _, resolver := range da.resolvers {
			ctx, cancel := context.WithTimeout(context.Background(), da.timeout)

			r := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{Timeout: da.timeout}
					return d.DialContext(ctx, network, resolver)
				},
			}

			// Perform SRV lookup for the service
			_, err := r.LookupSRV(ctx, "", "", serviceDomain)
			if err == nil {
				// Service found - could add to results here
			}
			cancel()
			break
		}
	}
}

// checkDNSSEC performs DNSSEC validation
func (da *DNSAnalyzer) checkDNSSEC(domain string, result *DNSResult, errorChan chan<- string) {
	// DNSSEC validation requires specialized DNS libraries
	// This is a placeholder implementation
	result.DNSSEC = &DNSSECInfo{
		Enabled:   false,
		Validated: false,
		Errors:    []string{"DNSSEC validation not implemented (requires DNS library)"},
	}
}

// attemptZoneTransfer attempts DNS zone transfer
func (da *DNSAnalyzer) attemptZoneTransfer(domain string, result *DNSResult, errorChan chan<- string) {
	zoneInfo := &ZoneTransferInfo{
		Attempted:   true,
		Successful:  false,
		NameServers: result.NSRecords,
		Errors:      make([]string, 0),
	}

	// Zone transfer requires specialized DNS libraries for AXFR requests
	// This is a placeholder implementation
	for _, ns := range result.NSRecords {
		zoneInfo.Errors = append(zoneInfo.Errors, 
			fmt.Sprintf("Zone transfer attempt to %s not implemented (requires DNS library)", ns))
	}

	result.ZoneTransfer = zoneInfo
}

// performReverseLookups performs reverse DNS lookups for discovered IPs
func (da *DNSAnalyzer) performReverseLookups(result *DNSResult, errorChan chan<- string) {
	allIPs := append(result.ARecords, result.AAAARecords...)

	for _, ip := range allIPs {
		for _, resolver := range da.resolvers {
			ctx, cancel := context.WithTimeout(context.Background(), da.timeout)
			defer cancel()

			r := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{Timeout: da.timeout}
					return d.DialContext(ctx, network, resolver)
				},
			}

			if names, err := r.LookupAddr(ctx, ip); err == nil {
				for _, name := range names {
					result.PTRRecords = append(result.PTRRecords, strings.TrimSuffix(name, "."))
				}
				break
			}
		}
	}

	result.PTRRecords = removeDuplicates(result.PTRRecords)
	sort.Strings(result.PTRRecords)
}

// GetResult returns the DNS analysis result for a domain
func (da *DNSAnalyzer) GetResult(domain string) *DNSResult {
	da.mutex.RLock()
	defer da.mutex.RUnlock()
	return da.results[domain]
}

// GetAllResults returns all DNS analysis results
func (da *DNSAnalyzer) GetAllResults() map[string]*DNSResult {
	da.mutex.RLock()
	defer da.mutex.RUnlock()

	results := make(map[string]*DNSResult)
	for k, v := range da.results {
		results[k] = v
	}
	return results
}

// Clear clears all DNS analysis results
func (da *DNSAnalyzer) Clear() {
	da.mutex.Lock()
	defer da.mutex.Unlock()
	da.results = make(map[string]*DNSResult)
}

// removeDuplicates removes duplicate strings from a slice
func removeDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	result := []string{}

	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}

	return result
}

// AnalyzeDomainBatch performs DNS analysis on multiple domains
func (da *DNSAnalyzer) AnalyzeDomainBatch(domains []string, config DNSConfig) (map[string]*DNSResult, error) {
	results := make(map[string]*DNSResult)
	var wg sync.WaitGroup
	var mutex sync.Mutex

	for _, domain := range domains {
		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			if result, err := da.AnalyzeDomain(d, config); err == nil {
				mutex.Lock()
				results[d] = result
				mutex.Unlock()
			}
		}(domain)
	}

	wg.Wait()
	return results, nil
}