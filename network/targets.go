package network

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// Target represents a scan target
type Target struct {
	IP       net.IP
	Hostname string
	Ports    []int
}

// TargetGroup represents a group of targets for organized scanning
type TargetGroup struct {
	Name    string
	Targets []Target
}

// TargetParser handles parsing of various target formats
type TargetParser struct{}

// NewTargetParser creates a new target parser
func NewTargetParser() *TargetParser {
	return &TargetParser{}
}

// ParseTargets parses various target formats and returns a list of targets
func (p *TargetParser) ParseTargets(input string) ([]Target, error) {
	var targets []Target
	
	// Split by comma for multiple targets
	parts := strings.Split(input, ",")
	
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		
		// Determine target type and parse accordingly
		if strings.Contains(part, "/") {
			// CIDR notation
			cidrTargets, err := p.parseCIDR(part)
			if err != nil {
				return nil, fmt.Errorf("error parsing CIDR %s: %v", part, err)
			}
			targets = append(targets, cidrTargets...)
		} else if strings.Contains(part, "-") {
			// IP range (e.g., 192.168.1.1-192.168.1.10)
			rangeTargets, err := p.parseIPRange(part)
			if err != nil {
				return nil, fmt.Errorf("error parsing IP range %s: %v", part, err)
			}
			targets = append(targets, rangeTargets...)
		} else {
			// Single IP or hostname
			target, err := p.parseSingleTarget(part)
			if err != nil {
				return nil, fmt.Errorf("error parsing target %s: %v", part, err)
			}
			targets = append(targets, target)
		}
	}
	
	return targets, nil
}

// parseCIDR parses CIDR notation (e.g., 192.168.1.0/24)
func (p *TargetParser) parseCIDR(cidr string) ([]Target, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	
	var targets []Target
	
	// Generate all IPs in the subnet
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); p.incrementIP(ip) {
		// Skip network and broadcast addresses for /24 and smaller
		ones, bits := ipnet.Mask.Size()
		if ones >= 24 {
			// Skip network address (first) and broadcast address (last)
			if ip.Equal(ipnet.IP) || ip.Equal(p.getBroadcastIP(ipnet)) {
				continue
			}
		}
		
		// Create a copy of the IP
		ipCopy := make(net.IP, len(ip))
		copy(ipCopy, ip)
		
		targets = append(targets, Target{
			IP: ipCopy,
		})
		
		// Prevent infinite loop for large subnets
		if bits < 16 && len(targets) > 65536 {
			return nil, fmt.Errorf("subnet too large, would generate more than 65536 targets")
		}
	}
	
	return targets, nil
}

// parseIPRange parses IP ranges (e.g., 192.168.1.1-192.168.1.10)
func (p *TargetParser) parseIPRange(ipRange string) ([]Target, error) {
	parts := strings.Split(ipRange, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid IP range format")
	}
	
	startIP := net.ParseIP(strings.TrimSpace(parts[0]))
	endIP := net.ParseIP(strings.TrimSpace(parts[1]))
	
	if startIP == nil || endIP == nil {
		return nil, fmt.Errorf("invalid IP addresses in range")
	}
	
	// Convert to IPv4 if possible
	if startIP.To4() != nil {
		startIP = startIP.To4()
	}
	if endIP.To4() != nil {
		endIP = endIP.To4()
	}
	
	var targets []Target
	currentIP := make(net.IP, len(startIP))
	copy(currentIP, startIP)
	
	for {
		// Add current IP to targets
		ipCopy := make(net.IP, len(currentIP))
		copy(ipCopy, currentIP)
		targets = append(targets, Target{IP: ipCopy})
		
		// Check if we've reached the end IP
		if currentIP.Equal(endIP) {
			break
		}
		
		// Increment IP
		p.incrementIP(currentIP)
		
		// Safety check to prevent infinite loops
		if len(targets) > 65536 {
			return nil, fmt.Errorf("IP range too large, would generate more than 65536 targets")
		}
	}
	
	return targets, nil
}

// parseSingleTarget parses a single IP address or hostname
func (p *TargetParser) parseSingleTarget(target string) (Target, error) {
	// Try to parse as IP first
	ip := net.ParseIP(target)
	if ip != nil {
		return Target{IP: ip}, nil
	}
	
	// Try to resolve as hostname
	ips, err := net.LookupIP(target)
	if err != nil {
		return Target{}, fmt.Errorf("could not resolve hostname %s: %v", target, err)
	}
	
	if len(ips) == 0 {
		return Target{}, fmt.Errorf("no IP addresses found for hostname %s", target)
	}
	
	// Use the first IP address
	return Target{
		IP:       ips[0],
		Hostname: target,
	}, nil
}

// incrementIP increments an IP address by 1
func (p *TargetParser) incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}

// getBroadcastIP calculates the broadcast IP for a network
func (p *TargetParser) getBroadcastIP(ipnet *net.IPNet) net.IP {
	ip := make(net.IP, len(ipnet.IP))
	copy(ip, ipnet.IP)
	
	for i := 0; i < len(ip); i++ {
		ip[i] |= ^ipnet.Mask[i]
	}
	
	return ip
}

// ParsePortRange parses port ranges and lists
func ParsePortRange(portStr string) ([]int, error) {
	var ports []int
	
	// Split by comma for multiple port specifications
	parts := strings.Split(portStr, ",")
	
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		
		if strings.Contains(part, "-") {
			// Port range (e.g., 80-90)
			rangePorts, err := parsePortRangeSegment(part)
			if err != nil {
				return nil, err
			}
			ports = append(ports, rangePorts...)
		} else {
			// Single port
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port number: %s", part)
			}
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("port number out of range: %d", port)
			}
			ports = append(ports, port)
		}
	}
	
	// Remove duplicates and sort
	ports = removeDuplicatePorts(ports)
	sort.Ints(ports)
	
	return ports, nil
}

// parsePortRangeSegment parses a single port range (e.g., "80-90")
func parsePortRangeSegment(rangeStr string) ([]int, error) {
	parts := strings.Split(rangeStr, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid port range format: %s", rangeStr)
	}
	
	startPort, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return nil, fmt.Errorf("invalid start port: %s", parts[0])
	}
	
	endPort, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return nil, fmt.Errorf("invalid end port: %s", parts[1])
	}
	
	if startPort < 1 || startPort > 65535 || endPort < 1 || endPort > 65535 {
		return nil, fmt.Errorf("port numbers out of range: %d-%d", startPort, endPort)
	}
	
	if startPort > endPort {
		startPort, endPort = endPort, startPort
	}
	
	var ports []int
	for port := startPort; port <= endPort; port++ {
		ports = append(ports, port)
	}
	
	return ports, nil
}

// removeDuplicatePorts removes duplicate ports from a slice
func removeDuplicatePorts(ports []int) []int {
	keys := make(map[int]bool)
	var result []int
	
	for _, port := range ports {
		if !keys[port] {
			keys[port] = true
			result = append(result, port)
		}
	}
	
	return result
}

// GetCommonPortSets returns predefined port sets
func GetCommonPortSets() map[string][]int {
	return map[string][]int{
		"top-100": {
			7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
			113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445,
			465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990,
			993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723,
			1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389,
			3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631,
			5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080,
			8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154,
			49155, 49156, 49157,
		},
		"top-1000": generateTopPorts(1000),
		"common": {
			21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993,
			995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017,
		},
		"web": {80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9080, 9443},
		"database": {1433, 1521, 3306, 5432, 6379, 27017, 27018, 27019},
		"mail": {25, 110, 143, 465, 587, 993, 995},
	}
}

// generateTopPorts generates a list of the most common ports
func generateTopPorts(count int) []int {
	// This would typically be loaded from a comprehensive port database
	// For now, return a basic set
	basePorts := []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
		1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017,
	}
	
	// Extend with additional common ports
	for i := 1; i <= 1024 && len(basePorts) < count; i++ {
		found := false
		for _, existing := range basePorts {
			if existing == i {
				found = true
				break
			}
		}
		if !found {
			basePorts = append(basePorts, i)
		}
	}
	
	return basePorts[:min(count, len(basePorts))]
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ValidateTarget validates if a target string is in a supported format
func ValidateTarget(target string) error {
	parser := NewTargetParser()
	_, err := parser.ParseTargets(target)
	return err
}

// GetTargetCount estimates the number of targets that would be generated
func GetTargetCount(target string) (int, error) {
	parser := NewTargetParser()
	targets, err := parser.ParseTargets(target)
	if err != nil {
		return 0, err
	}
	return len(targets), nil
}