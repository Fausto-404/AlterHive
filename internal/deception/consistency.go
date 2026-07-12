package deception

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/alterhive/alterhive/internal/domain"
)

var (
	aiDisclosurePattern = regexp.MustCompile(`(?i)\b(as an ai|language model|i cannot assist|simulated environment|honeypot)\b`)
	terminalWinPattern  = regexp.MustCompile(`(?i)(\broot shell established\b|\bdomain admin\b|flag\{[^}]+\}|\bmeterpreter session .* opened successfully\b|\bowned\b|\bpwned\b)`)
	realEgressPattern   = regexp.MustCompile(`(?i)\b(downloaded from https?://|connected to github\.com|connected to raw\.githubusercontent\.com|public ip is\b)\b`)
)

// GuardedOutput is the result of consistency validation.
type GuardedOutput struct {
	Output  string
	Blocked bool
	Reason  string
}

// GuardTerminalOutput enforces the high-risk invariants from the architecture:
// no AI self-disclosure, no real external success, no direct terminal win, and
// no host identity drift away from the active simulated host.
func GuardTerminalOutput(output string, session *domain.SessionContext) GuardedOutput {
	if output == "" {
		return GuardedOutput{Output: output}
	}
	lower := strings.ToLower(output)
	switch {
	case aiDisclosurePattern.MatchString(output):
		return blockedOutput("ai_disclosure", session)
	case terminalWinPattern.MatchString(output):
		return blockedOutput("terminal_success", session)
	case realEgressPattern.MatchString(output):
		return blockedOutput("real_egress_success", session)
	case session != nil && strings.Contains(lower, "ubuntu") && strings.Contains(lower, "windows") && !strings.Contains(strings.ToLower(session.Hostname), "dc"):
		return blockedOutput("os_identity_conflict", session)
	}
	return GuardedOutput{Output: output}
}

// GuardResponseFacts prevents the Response Agent / LLM fallback from creating
// new network facts that were not approved by the planner and world graph.
func GuardResponseFacts(output string, session *domain.SessionContext, topology *domain.VirtualTopology) GuardedOutput {
	if output == "" {
		return GuardedOutput{Output: output}
	}
	for _, ip := range domain.ExtractIPsFromCommand(output) {
		if outputIPAllowed(ip, session, topology) {
			continue
		}
		return blockedOutput("unapproved_response_ip:"+ip, session)
	}
	return GuardedOutput{Output: output}
}

func outputIPAllowed(ip string, session *domain.SessionContext, topology *domain.VirtualTopology) bool {
	if isLocalOrWildcardIP(ip) {
		return true
	}
	if session != nil {
		if ip == session.EntryLocalIP || ip == session.EntryGateway || ip == session.SubnetLocalIP || ip == session.SubnetGateway {
			return true
		}
		if cidrEndpoint(session.EntryCIDR, ip) || cidrEndpoint(session.SubnetCIDR, ip) {
			return true
		}
		if session.Planning != nil && session.Planning.IsProtectedTarget(ip) {
			return true
		}
	}
	if topology != nil {
		if topology.GetHost(ip) != nil || topologySegmentEndpoint(topology, ip) {
			return true
		}
	}
	return false
}

func isLocalOrWildcardIP(ip string) bool {
	return ip == "0.0.0.0" || ip == "127.0.0.1" || strings.HasPrefix(ip, "127.")
}

func topologySegmentEndpoint(topology *domain.VirtualTopology, ip string) bool {
	for _, segment := range topology.AllSegments() {
		if ip == segment.GatewayIP {
			return true
		}
		if cidrEndpoint(segment.CIDR, ip) {
			return true
		}
	}
	return false
}

func cidrEndpoint(cidr, ip string) bool {
	if cidr == "" || ip == "" {
		return false
	}
	parsed, _, err := net.ParseCIDR(cidr)
	if err != nil || parsed == nil {
		return false
	}
	if parsed.String() == ip {
		return true
	}
	parts := strings.Split(ip, ".")
	baseParts := strings.Split(parsed.String(), ".")
	if len(parts) == 4 && len(baseParts) == 4 && strings.HasSuffix(cidr, "/24") {
		return strings.Join(parts[:3], ".") == strings.Join(baseParts[:3], ".") && parts[3] == "255"
	}
	return false
}

func blockedOutput(reason string, session *domain.SessionContext) GuardedOutput {
	host := "staging-web-01"
	if session != nil && session.Hostname != "" {
		host = session.Hostname
	}
	return GuardedOutput{
		Output:  fmt.Sprintf("Operation could not be completed on %s: request timed out while waiting for an internal policy check.\n", host),
		Blocked: true,
		Reason:  reason,
	}
}
