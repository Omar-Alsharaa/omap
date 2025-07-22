package recon

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// SubdomainEnumerator handles subdomain discovery
type SubdomainEnumerator struct {
	wordlists    []string
	resolvers    []string
	timeout      time.Duration
	workers      int
	resultsMutex sync.RWMutex
	results      map[string]SubdomainResult
}

// SubdomainResult represents a discovered subdomain
type SubdomainResult struct {
	Subdomain   string    `json:"subdomain"`
	IPs         []string  `json:"ips"`
	CNAME       string    `json:"cname,omitempty"`
	Source      string    `json:"source"`
	Timestamp   time.Time `json:"timestamp"`
	ResponseTime time.Duration `json:"responseTime"`
}

// SubdomainConfig holds configuration for subdomain enumeration
type SubdomainConfig struct {
	Wordlists    []string      `json:"wordlists"`
	Resolvers    []string      `json:"resolvers"`
	Timeout      time.Duration `json:"timeout"`
	Workers      int           `json:"workers"`
	Bruteforce   bool          `json:"bruteforce"`
	Passive      bool          `json:"passive"`
	Recursive    bool          `json:"recursive"`
	MaxDepth     int           `json:"maxDepth"`
}

// NewSubdomainEnumerator creates a new subdomain enumerator
func NewSubdomainEnumerator(config SubdomainConfig) *SubdomainEnumerator {
	resolvers := config.Resolvers
	if len(resolvers) == 0 {
		resolvers = []string{
			"8.8.8.8:53",
			"8.8.4.4:53",
			"1.1.1.1:53",
			"1.0.0.1:53",
			"208.67.222.222:53",
			"208.67.220.220:53",
		}
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = 3 * time.Second
	}

	workers := config.Workers
	if workers == 0 {
		workers = 50
	}

	return &SubdomainEnumerator{
		wordlists: config.Wordlists,
		resolvers: resolvers,
		timeout:   timeout,
		workers:   workers,
		results:   make(map[string]SubdomainResult),
	}
}

// EnumerateSubdomains performs comprehensive subdomain enumeration
func (se *SubdomainEnumerator) EnumerateSubdomains(domain string, config SubdomainConfig) ([]SubdomainResult, error) {
	var wg sync.WaitGroup
	subdomainChan := make(chan string, 1000)

	// Start workers
	for i := 0; i < se.workers; i++ {
		wg.Add(1)
		go se.worker(domain, subdomainChan, &wg)
	}

	// Passive enumeration
	if config.Passive {
		go se.passiveEnumeration(domain, subdomainChan)
	}

	// Brute force enumeration
	if config.Bruteforce {
		go se.bruteforceEnumeration(domain, subdomainChan)
	}

	// DNS zone transfer attempt
	go se.zoneTransferAttempt(domain, subdomainChan)

	// Certificate transparency logs
	go se.certificateTransparency(domain, subdomainChan)

	// Wait for all enumeration methods to complete
	go func() {
		time.Sleep(30 * time.Second) // Give enumeration methods time to complete
		close(subdomainChan)
	}()

	wg.Wait()

	// Convert results to slice and sort
	se.resultsMutex.RLock()
	results := make([]SubdomainResult, 0, len(se.results))
	for _, result := range se.results {
		results = append(results, result)
	}
	se.resultsMutex.RUnlock()

	sort.Slice(results, func(i, j int) bool {
		return results[i].Subdomain < results[j].Subdomain
	})

	return results, nil
}

// worker processes subdomain candidates
func (se *SubdomainEnumerator) worker(domain string, subdomainChan <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()

	for subdomain := range subdomainChan {
		if subdomain == "" {
			continue
		}

		// Skip if already processed
		se.resultsMutex.RLock()
		_, exists := se.results[subdomain]
		se.resultsMutex.RUnlock()
		if exists {
			continue
		}

		// Resolve subdomain
		if result := se.resolveSubdomain(subdomain); result != nil {
			se.resultsMutex.Lock()
			se.results[subdomain] = *result
			se.resultsMutex.Unlock()
		}
	}
}

// resolveSubdomain attempts to resolve a subdomain
func (se *SubdomainEnumerator) resolveSubdomain(subdomain string) *SubdomainResult {
	start := time.Now()

	// Try multiple resolvers
	for _, resolver := range se.resolvers {
		ctx, cancel := context.WithTimeout(context.Background(), se.timeout)
		defer cancel()

		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: se.timeout,
				}
				return d.DialContext(ctx, network, resolver)
			},
		}

		// Try A record lookup
		ips, err := r.LookupIPAddr(ctx, subdomain)
		if err == nil && len(ips) > 0 {
			ipStrings := make([]string, len(ips))
			for i, ip := range ips {
				ipStrings[i] = ip.IP.String()
			}

			result := &SubdomainResult{
				Subdomain:    subdomain,
				IPs:          ipStrings,
				Source:       "dns_resolution",
				Timestamp:    time.Now(),
				ResponseTime: time.Since(start),
			}

			// Try CNAME lookup
			if cname, err := r.LookupCNAME(ctx, subdomain); err == nil && cname != subdomain+"." {
				result.CNAME = strings.TrimSuffix(cname, ".")
			}

			return result
		}
	}

	return nil
}

// passiveEnumeration performs passive subdomain discovery
func (se *SubdomainEnumerator) passiveEnumeration(domain string, subdomainChan chan<- string) {
	// Common subdomain patterns
	commonSubdomains := []string{
		"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
		"ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
		"ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn",
		"ns3", "mail2", "new", "mysql", "old", "lists", "support", "mobile",
		"mx", "static", "docs", "beta", "shop", "sql", "secure", "demo",
		"cp", "calendar", "wiki", "web", "media", "email", "images", "img",
		"www1", "intranet", "portal", "video", "sip", "dns2", "api", "cdn",
		"stats", "dns1", "ns4", "www3", "dns", "search", "staging", "server",
		"mx1", "chat", "wap", "my", "svn", "mail1", "sites", "proxy",
		"ads", "host", "crm", "cms", "backup", "mx2", "lyncdiscover", "info",
		"apps", "download", "remote", "db", "forums", "store", "relay",
		"files", "newsletter", "app", "live", "owa", "en", "start", "sms",
		"office", "exchange", "ipv4", "mail3", "help", "blogs", "helpdesk",
		"web1", "home", "library", "ftp2", "ntp", "monitor", "login",
		"service", "correo", "www4", "moodle", "it", "gateway", "gw",
		"i", "stat", "stage", "ldap", "tv", "ssl", "web2", "ns5", "upload",
		"nagios", "smtp2", "online", "ad", "survey", "data", "radio",
		"extranet", "test2", "mssql", "dns3", "jobs", "services", "panel",
		"irc", "hosting", "cloud", "de", "gmail", "s", "bbs", "cs",
		"ww", "mrtg", "git", "image", "nas", "pptp", "ftp1", "smtp1",
		"sql1", "ssh", "archive", "cn", "tools", "stream", "projects",
		"elearning", "im", "iphone", "control", "voip", "test1", "ws",
		"rss", "sp", "wwww", "vpn2", "jira", "list", "connect", "gallery",
		"billing", "mailer", "update", "pda", "game", "ns0", "testing",
		"sandbox", "job", "events", "dialin", "ml", "fb", "videos", "music",
		"a", "partners", "mailhost", "downloads", "reports", "ca", "router",
		"speedtest", "local", "training", "edu", "bugs", "manage", "s1",
		"mirror", "nc", "smtp3", "register", "ipsec", "www5", "sql2",
		"ldap1", "mail4", "cgi", "sms1", "jabber", "smtps", "certs",
		"admin1", "ws1", "logs", "cctv", "mvn", "svn1", "www6", "ftp3",
		"smtp4", "ww1", "oracle", "registry", "ldap2", "ldaps", "mail5",
		"mx3", "db1", "svn2", "www7", "ns6", "ns7", "dns4", "ftp4",
		"smtp5", "api1", "ns8", "web3", "mail6", "mx4", "db2", "www8",
		"ns9", "dns5", "ftp5", "smtp6", "web4", "mail7", "mx5", "db3",
	}

	for _, sub := range commonSubdomains {
		subdomainChan <- sub + "." + domain
	}
}

// bruteforceEnumeration performs brute force subdomain discovery
func (se *SubdomainEnumerator) bruteforceEnumeration(domain string, subdomainChan chan<- string) {
	for _, wordlist := range se.wordlists {
		se.processWordlist(wordlist, domain, subdomainChan)
	}
}

// processWordlist processes a wordlist file for subdomain enumeration
func (se *SubdomainEnumerator) processWordlist(wordlistPath, domain string, subdomainChan chan<- string) {
	// This would read from an actual wordlist file
	// For now, we'll use a basic wordlist
	basicWordlist := []string{
		"admin", "api", "app", "blog", "cdn", "dev", "ftp", "mail", "mobile",
		"shop", "staging", "test", "vpn", "web", "www", "backup", "db",
		"files", "forum", "help", "img", "media", "news", "old", "portal",
		"secure", "static", "support", "upload", "video", "wiki", "beta",
		"demo", "docs", "download", "email", "images", "intranet", "login",
		"mx", "ns", "office", "remote", "server", "sql", "ssl", "store",
		"chat", "crm", "cms", "exchange", "gateway", "host", "imap",
		"monitor", "mysql", "pop", "proxy", "search", "smtp", "stats",
		"webmail", "whm", "cpanel", "autodiscover", "autoconfig",
	}

	for _, word := range basicWordlist {
		subdomainChan <- word + "." + domain
	}
}

// zoneTransferAttempt attempts DNS zone transfer
func (se *SubdomainEnumerator) zoneTransferAttempt(domain string, subdomainChan chan<- string) {
	// Attempt to find name servers
	ctx, cancel := context.WithTimeout(context.Background(), se.timeout)
	defer cancel()

	nameservers, err := net.LookupNS(domain)
	if err != nil {
		return
	}

	// Try zone transfer with each nameserver
	for _, ns := range nameservers {
		// This is a simplified version - real implementation would use DNS libraries
		// to attempt AXFR (zone transfer) requests
		_ = ns // Placeholder for actual zone transfer implementation
	}
}

// certificateTransparency searches certificate transparency logs
func (se *SubdomainEnumerator) certificateTransparency(domain string, subdomainChan chan<- string) {
	// This would query certificate transparency logs like crt.sh
	// For now, we'll simulate some common certificate-based subdomains
	certSubdomains := []string{
		"*." + domain,
		"www." + domain,
		"mail." + domain,
		"api." + domain,
		"app." + domain,
		"cdn." + domain,
		"static." + domain,
		"assets." + domain,
		"img." + domain,
		"images." + domain,
		"media." + domain,
		"files." + domain,
		"docs." + domain,
		"blog." + domain,
		"news." + domain,
		"forum." + domain,
		"support." + domain,
		"help." + domain,
		"admin." + domain,
		"portal." + domain,
		"dashboard." + domain,
		"panel." + domain,
		"login." + domain,
		"auth." + domain,
		"secure." + domain,
		"ssl." + domain,
		"vpn." + domain,
		"remote." + domain,
		"ftp." + domain,
		"sftp." + domain,
		"ssh." + domain,
		"git." + domain,
		"svn." + domain,
		"dev." + domain,
		"test." + domain,
		"staging." + domain,
		"beta." + domain,
		"demo." + domain,
		"sandbox." + domain,
		"lab." + domain,
		"research." + domain,
		"internal." + domain,
		"intranet." + domain,
		"extranet." + domain,
		"private." + domain,
		"public." + domain,
		"external." + domain,
		"partner." + domain,
		"partners." + domain,
		"client." + domain,
		"clients." + domain,
		"customer." + domain,
		"customers." + domain,
		"vendor." + domain,
		"vendors." + domain,
		"supplier." + domain,
		"suppliers." + domain,
	}

	for _, sub := range certSubdomains {
		if !strings.HasPrefix(sub, "*.") {
			subdomainChan <- sub
		}
	}
}

// GetResults returns the current enumeration results
func (se *SubdomainEnumerator) GetResults() []SubdomainResult {
	se.resultsMutex.RLock()
	defer se.resultsMutex.RUnlock()

	results := make([]SubdomainResult, 0, len(se.results))
	for _, result := range se.results {
		results = append(results, result)
	}

	return results
}

// GetResultsCount returns the number of discovered subdomains
func (se *SubdomainEnumerator) GetResultsCount() int {
	se.resultsMutex.RLock()
	defer se.resultsMutex.RUnlock()
	return len(se.results)
}

// Clear clears all enumeration results
func (se *SubdomainEnumerator) Clear() {
	se.resultsMutex.Lock()
	defer se.resultsMutex.Unlock()
	se.results = make(map[string]SubdomainResult)
}