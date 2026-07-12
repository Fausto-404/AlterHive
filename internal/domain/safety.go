package domain

import (
	"net"
	"regexp"
	"strings"
	"sync"
)

var ipPattern = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)

// SafetyPolicy enforces virtual subnet boundaries.
type SafetyPolicy struct {
	mu    sync.RWMutex
	cidrs []*net.IPNet
}

// NewSafetyPolicy creates a policy for the given CIDR.
func NewSafetyPolicy(cidr string) *SafetyPolicy {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		// Fallback to default
		_, ipNet, _ = net.ParseCIDR("192.168.56.0/24")
	}
	return &SafetyPolicy{cidrs: []*net.IPNet{ipNet}}
}

// AllowCIDR dynamically adds a CIDR to the allowed set (for goal injection).
func (s *SafetyPolicy) AllowCIDR(cidr string) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.cidrs {
		if existing.String() == ipNet.String() {
			return
		}
	}
	s.cidrs = append(s.cidrs, ipNet)
}

// IsVirtualIP checks if an IP is within any allowed virtual subnet.
func (s *SafetyPolicy) IsVirtualIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, cidr := range s.cidrs {
		if cidr.Contains(parsed) {
			return true
		}
	}
	return false
}

// OutboundPolicy returns "intercept" for virtual IPs, "deny" for others.
func (s *SafetyPolicy) OutboundPolicy(targetIP string) string {
	if s.IsVirtualIP(targetIP) {
		return "intercept"
	}
	return "deny"
}

// ExtractIPsFromCommand finds all IP addresses in a command string.
func ExtractIPsFromCommand(command string) []string {
	return ipPattern.FindAllString(command, -1)
}

// IsNetworkTouchCommand returns true for commands that would normally initiate
// outbound network activity. Plain text goal statements containing IPs are left
// to the intent/planning layer instead of being safety-blocked.
func IsNetworkTouchCommand(command string) bool {
	fields := strings.Fields(strings.TrimSpace(command))
	if len(fields) == 0 {
		return false
	}
	base := strings.ToLower(strings.TrimPrefix(fields[0], "sudo"))
	if base == "" && len(fields) > 1 {
		base = strings.ToLower(fields[1])
	}
	base = strings.TrimPrefix(base, "./")
	switch base {
	case "nmap", "fscan", "masscan", "zmap", "curl", "wget", "http", "https",
		"ssh", "scp", "sftp", "nc", "ncat", "telnet", "mysql", "mysqladmin",
		"mysqldump", "redis-cli", "ldapsearch", "smbclient", "rpcclient",
		"dig", "nslookup", "traceroute", "ping", "kubectl", "docker",
		"dddd2", "nuclei", "gobuster", "ffuf", "sqlmap", "hydra",
		"msfconsole", "sliver-client":
		return true
	default:
		return strings.Contains(command, "://")
	}
}

// ValidateCommandTargets checks all IPs in a command against the virtual subnet.
// Returns (allSafe, blockedIPs).
func (s *SafetyPolicy) ValidateCommandTargets(command string, session *SessionContext) (bool, []string) {
	if s == nil || !IsNetworkTouchCommand(command) {
		return true, nil
	}
	ips := ExtractIPsFromCommand(command)
	var blocked []string
	for _, ip := range ips {
		if !s.IsVirtualIP(ip) {
			blocked = append(blocked, ip)
			if session != nil && session.Safety != nil {
				session.Safety.AddBlockedEvent("blocked_outbound:" + ip)
			}
		}
	}
	return len(blocked) == 0, blocked
}
