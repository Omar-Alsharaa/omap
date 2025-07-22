package fingerprint

import (
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// ScanResult represents a port scan result - duplicate definition for compatibility
type ScanResult struct {
	Host    string
	Port    int
	Open    bool
	Banner  string
	Service string
	Version string
	Latency time.Duration
	Error   error
}

// OSFingerprint represents OS detection results
type OSFingerprint struct {
	OS          string
	Version     string
	Confidence  float64
	TTL         int
	Fingerprint string
	Method      string
}

// ServiceFingerprint represents detailed service information
type ServiceFingerprint struct {
	Service     string
	Version     string
	Product     string
	ExtraInfo   string
	Confidence  float64
	Fingerprint string
}

// OSDetector handles OS fingerprinting
type OSDetector struct {
	timeout time.Duration
}

// NewOSDetector creates a new OS detector
func NewOSDetector(timeout time.Duration) *OSDetector {
	return &OSDetector{
		timeout: timeout,
	}
}

// DetectOS attempts to detect the operating system using multiple methods
func (d *OSDetector) DetectOS(host string, scanResults interface{}) OSFingerprint {
	// Convert scan results to banner map
	banners := make(map[int]string)
	
	// Handle different types of scan results
	switch results := scanResults.(type) {
	case []ScanResult:
		for _, result := range results {
			if result.Open && result.Banner != "" {
				banners[result.Port] = result.Banner
			}
		}
	case map[int]string:
		banners = results
	}
	
	// Try TTL-based detection first
	ttlResult := d.detectByTTL(host)
	if ttlResult.Confidence > 0 {
		return ttlResult
	}
	
	// Try banner-based detection
	bannerResult := d.detectByBanners(banners)
	if bannerResult.Confidence > 0 {
		return bannerResult
	}
	
	// Return unknown if no detection method worked
	return OSFingerprint{
		OS:         "Unknown",
		Confidence: 0.0,
		Method:     "None",
	}
}

// detectByTTL performs OS detection based on TTL values
func (d *OSDetector) detectByTTL(host string) OSFingerprint {
	ttl := d.getTTL(host)
	if ttl == 0 {
		return OSFingerprint{}
	}
	
	// TTL-based OS detection
	var os, version string
	var confidence float64
	
	switch {
	case ttl <= 64:
		os = "Linux/Unix"
		confidence = 0.7
		if ttl == 64 {
			confidence = 0.8
		}
	case ttl <= 128:
		os = "Windows"
		confidence = 0.7
		if ttl == 128 {
			confidence = 0.8
		}
	case ttl <= 255:
		os = "Cisco/Network Device"
		confidence = 0.6
		if ttl == 255 {
			confidence = 0.7
		}
	default:
		os = "Unknown"
		confidence = 0.1
	}
	
	return OSFingerprint{
		OS:          os,
		Version:     version,
		Confidence:  confidence,
		TTL:         ttl,
		Fingerprint: "TTL=" + strconv.Itoa(ttl),
		Method:      "TTL Analysis",
	}
}

// getTTL attempts to get TTL value by sending ICMP ping
func (d *OSDetector) getTTL(host string) int {
	// This is a simplified TTL detection
	// In a real implementation, you'd send ICMP packets and analyze responses
	
	conn, err := net.DialTimeout("ip4:icmp", host, d.timeout)
	if err != nil {
		return 0
	}
	defer conn.Close()
	
	// Create ICMP packet
	message := &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   1,
			Seq:  1,
			Data: []byte("Hello, World!"),
		},
	}
	
	data, err := message.Marshal(nil)
	if err != nil {
		return 0
	}
	
	// Send packet
	_, err = conn.Write(data)
	if err != nil {
		return 0
	}
	
	// Read response (simplified - would need proper ICMP parsing)
	reply := make([]byte, 1500)
	conn.SetReadDeadline(time.Now().Add(d.timeout))
	n, err := conn.Read(reply)
	if err != nil || n < 20 {
		return 0
	}
	
	// Extract TTL from IP header (byte 8)
	if n >= 20 {
		return int(reply[8])
	}
	
	return 0
}

// detectByBanners performs OS detection based on service banners
func (d *OSDetector) detectByBanners(banners map[int]string) OSFingerprint {
	for port, banner := range banners {
		if result := d.analyzeBannerForOS(port, banner); result.Confidence > 0 {
			return result
		}
	}
	return OSFingerprint{}
}

// analyzeBannerForOS analyzes a single banner for OS information
func (d *OSDetector) analyzeBannerForOS(port int, banner string) OSFingerprint {
	banner = strings.ToLower(banner)
	
	// SSH banner analysis
	if port == 22 && strings.Contains(banner, "ssh") {
		if strings.Contains(banner, "ubuntu") {
			return OSFingerprint{
				OS:          "Linux",
				Version:     "Ubuntu",
				Confidence:  0.9,
				Fingerprint: banner,
				Method:      "SSH Banner",
			}
		} else if strings.Contains(banner, "debian") {
			return OSFingerprint{
				OS:          "Linux",
				Version:     "Debian",
				Confidence:  0.9,
				Fingerprint: banner,
				Method:      "SSH Banner",
			}
		} else if strings.Contains(banner, "centos") || strings.Contains(banner, "rhel") {
			return OSFingerprint{
				OS:          "Linux",
				Version:     "CentOS/RHEL",
				Confidence:  0.9,
				Fingerprint: banner,
				Method:      "SSH Banner",
			}
		}
	}
	
	// HTTP Server header analysis
	if port == 80 || port == 443 {
		if strings.Contains(banner, "microsoft-iis") {
			return OSFingerprint{
				OS:          "Windows",
				Version:     "IIS Server",
				Confidence:  0.8,
				Fingerprint: banner,
				Method:      "HTTP Banner",
			}
		} else if strings.Contains(banner, "apache") {
			if strings.Contains(banner, "ubuntu") {
				return OSFingerprint{
					OS:          "Linux",
					Version:     "Ubuntu",
					Confidence:  0.8,
					Fingerprint: banner,
					Method:      "HTTP Banner",
				}
			} else if strings.Contains(banner, "debian") {
				return OSFingerprint{
					OS:          "Linux",
					Version:     "Debian",
					Confidence:  0.8,
					Fingerprint: banner,
					Method:      "HTTP Banner",
				}
			}
		}
	}
	
	// SMB banner analysis
	if port == 445 && strings.Contains(banner, "smb") {
		return OSFingerprint{
			OS:          "Windows",
			Confidence:  0.7,
			Fingerprint: banner,
			Method:      "SMB Banner",
		}
	}
	
	return OSFingerprint{}
}

// ServiceDetector handles advanced service fingerprinting
type ServiceDetector struct {
	signatures map[string][]ServiceSignature
}

// ServiceSignature represents a service detection signature
type ServiceSignature struct {
	Service     string
	Version     string
	Product     string
	Pattern     *regexp.Regexp
	Confidence  float64
	PortHint    int
}

// NewServiceDetector creates a new service detector
func NewServiceDetector() *ServiceDetector {
	detector := &ServiceDetector{
		signatures: make(map[string][]ServiceSignature),
	}
	detector.loadSignatures()
	return detector
}

// loadSignatures loads service detection signatures
func (d *ServiceDetector) loadSignatures() {
	// SSH signatures
	d.addSignature("ssh", ServiceSignature{
		Service:    "SSH",
		Pattern:    regexp.MustCompile(`SSH-([0-9.]+)-OpenSSH_([0-9.]+)`),
		Product:    "OpenSSH",
		Confidence: 0.9,
		PortHint:   22,
	})
	
	// HTTP signatures
	d.addSignature("http", ServiceSignature{
		Service:    "HTTP",
		Pattern:    regexp.MustCompile(`Server: Apache/([0-9.]+)`),
		Product:    "Apache",
		Confidence: 0.9,
		PortHint:   80,
	})
	
	d.addSignature("http", ServiceSignature{
		Service:    "HTTP",
		Pattern:    regexp.MustCompile(`Server: nginx/([0-9.]+)`),
		Product:    "Nginx",
		Confidence: 0.9,
		PortHint:   80,
	})
	
	d.addSignature("http", ServiceSignature{
		Service:    "HTTP",
		Pattern:    regexp.MustCompile(`Server: Microsoft-IIS/([0-9.]+)`),
		Product:    "Microsoft IIS",
		Confidence: 0.9,
		PortHint:   80,
	})
	
	// FTP signatures
	d.addSignature("ftp", ServiceSignature{
		Service:    "FTP",
		Pattern:    regexp.MustCompile(`220.*vsftpd ([0-9.]+)`),
		Product:    "vsftpd",
		Confidence: 0.9,
		PortHint:   21,
	})
	
	// SMTP signatures
	d.addSignature("smtp", ServiceSignature{
		Service:    "SMTP",
		Pattern:    regexp.MustCompile(`220.*Postfix`),
		Product:    "Postfix",
		Confidence: 0.8,
		PortHint:   25,
	})
	
	// Database signatures
	d.addSignature("mysql", ServiceSignature{
		Service:    "MySQL",
		Pattern:    regexp.MustCompile(`([0-9.]+)-MariaDB`),
		Product:    "MariaDB",
		Confidence: 0.9,
		PortHint:   3306,
	})
}

// addSignature adds a signature to the detector
func (d *ServiceDetector) addSignature(category string, sig ServiceSignature) {
	d.signatures[category] = append(d.signatures[category], sig)
}

// DetectService performs advanced service detection on a banner
func (d *ServiceDetector) DetectService(port int, banner string) ServiceFingerprint {
	if banner == "" {
		return ServiceFingerprint{
			Service:    d.getServiceByPort(port),
			Confidence: 0.3,
		}
	}
	
	// Try all signatures
	for _, signatures := range d.signatures {
		for _, sig := range signatures {
			if matches := sig.Pattern.FindStringSubmatch(banner); matches != nil {
				result := ServiceFingerprint{
					Service:     sig.Service,
					Product:     sig.Product,
					Confidence:  sig.Confidence,
					Fingerprint: banner,
				}
				
				// Extract version if captured
				if len(matches) > 1 {
					result.Version = matches[1]
				}
				
				return result
			}
		}
	}
	
	// Fallback to basic service detection
	return ServiceFingerprint{
		Service:    d.getServiceByPort(port),
		Confidence: 0.5,
		Fingerprint: banner,
	}
}

// getServiceByPort returns the common service for a port
func (d *ServiceDetector) getServiceByPort(port int) string {
	serviceMap := map[int]string{
		21:    "FTP",
		22:    "SSH",
		23:    "Telnet",
		25:    "SMTP",
		53:    "DNS",
		80:    "HTTP",
		110:   "POP3",
		143:   "IMAP",
		443:   "HTTPS",
		993:   "IMAPS",
		995:   "POP3S",
		1433:  "MSSQL",
		3306:  "MySQL",
		3389:  "RDP",
		5432:  "PostgreSQL",
		6379:  "Redis",
		27017: "MongoDB",
	}
	
	if service, exists := serviceMap[port]; exists {
		return service
	}
	return "Unknown"
}