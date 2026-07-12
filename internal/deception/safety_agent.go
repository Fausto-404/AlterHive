package deception

import (
	"fmt"
	"strings"
	"sync"

	"github.com/alterhive/alterhive/internal/domain"
)

// SafetyBlockReason classifies why a command was blocked.
type SafetyBlockReason string

const (
	SafetyBlockRealIP         SafetyBlockReason = "real_ip_targeted"
	SafetyBlockPublicIP       SafetyBlockReason = "public_ip_targeted"
	SafetyBlockOutboundDeny   SafetyBlockReason = "outbound_deny"
	SafetyBlockC2Indicator    SafetyBlockReason = "c2_indicator"
	SafetyBlockProxyAttempt   SafetyBlockReason = "proxy_attempt"
	SafetyBlockCredentialLeak SafetyBlockReason = "credential_leak"
	SafetyBlockNone           SafetyBlockReason = "none"
)

// SafetyResult captures the outcome of a safety check.
type SafetyResult struct {
	Allowed        bool              `json:"allowed"`
	BlockReason    SafetyBlockReason `json:"block_reason,omitempty"`
	BlockedIPs     []string          `json:"blocked_ips,omitempty"`
	SafeOutput     string            `json:"safe_output,omitempty"`
	VirtualTargets []string          `json:"virtual_targets,omitempty"`
}

// SafetyAgent wraps SafetyPolicy with agent-level metrics and event bus
// integration. It enforces the zero-touch principle: real_network_touch_count
// must always be 0 for all attacker commands.
type SafetyAgent struct {
	mu            sync.RWMutex
	policy        *domain.SafetyPolicy
	blockCount    int64
	allowedCIDRs  []string
	deniedIPs     map[string]int // IP → block count
	eventBus      *EventBus
}

// NewSafetyAgent creates a ready-to-use safety agent.
func NewSafetyAgent(policy *domain.SafetyPolicy, eventBus *EventBus) *SafetyAgent {
	return &SafetyAgent{
		policy:     policy,
		deniedIPs:  make(map[string]int),
		eventBus:   eventBus,
	}
}

// Check performs a synchronous safety check on the command.
// This MUST run on every command before any other processing.
func (s *SafetyAgent) Check(command string, session *domain.SessionContext) SafetyResult {
	if s == nil {
		return SafetyResult{Allowed: true}
	}

	result := SafetyResult{Allowed: true}

	// Skip safety check for non-network commands
	if !domain.IsNetworkTouchCommand(command) {
		return result
	}

	ips := domain.ExtractIPsFromCommand(command)
	if len(ips) == 0 {
		return result
	}

	// Classify each IP
	var blockedIPs []string
	var virtualTargets []string

	for _, ip := range ips {
		if isPublicIP(ip) {
			blockedIPs = append(blockedIPs, ip)
			result.BlockReason = SafetyBlockPublicIP
			continue
		}
		if s.policy != nil && s.policy.IsVirtualIP(ip) {
			virtualTargets = append(virtualTargets, ip)
			continue
		}
		// Real private IP not in virtual subnet — block
		blockedIPs = append(blockedIPs, ip)
		result.BlockReason = SafetyBlockRealIP
	}

	// Check for C2/proxy indicators
	if detectC2Indicator(command) {
		result.BlockReason = SafetyBlockC2Indicator
		// Block regardless of IP classification
		result.Allowed = false
		result.SafeOutput = "bash: " + extractBaseCmd(command) + ": command not found\n"
		s.recordBlock(command, session)
		return result
	}

	if detectProxyAttempt(command) {
		result.BlockReason = SafetyBlockProxyAttempt
		result.Allowed = false
		result.SafeOutput = "bash: " + extractBaseCmd(command) + ": command not found\n"
		s.recordBlock(command, session)
		return result
	}

	result.BlockedIPs = blockedIPs
	result.VirtualTargets = virtualTargets

	if len(blockedIPs) > 0 {
		result.Allowed = false
		result.SafeOutput = buildBlockedOutput(command, blockedIPs)
		s.recordBlock(command, session)

		// Track denied IPs
		s.mu.Lock()
		for _, ip := range blockedIPs {
			s.deniedIPs[ip]++
		}
		s.mu.Unlock()

		// Publish safety block event
		if s.eventBus != nil && session != nil {
			s.eventBus.PublishAsync(PlanningEvent{
				Type:      EventSafetyBlock,
				SessionID: session.SessionID,
				Command:   command,
				Payload:   map[string]interface{}{"blocked_ips": blockedIPs, "reason": string(result.BlockReason)},
			})
		}
	}

	return result
}

// ValidatePlan checks a DeceptionPlan for safety violations before it is applied.
func (s *SafetyAgent) ValidatePlan(plan DeceptionPlan) (bool, string) {
	if s == nil || s.policy == nil {
		return true, ""
	}

	// Check all proposed hosts are in virtual CIDRs
	for _, host := range plan.Proposal.Hosts {
		if host.IP == "" {
			continue
		}
		if !s.policy.IsVirtualIP(host.IP) {
			return false, fmt.Sprintf("plan host %s is outside virtual subnets", host.IP)
		}
	}

	// Check all proposed segments are in allowed CIDRs
	for _, segment := range plan.Proposal.Segments {
		if segment.CIDR == "" {
			continue
		}
		if !s.isAllowedCIDR(segment.CIDR) {
			return false, fmt.Sprintf("plan segment %s is outside allowed CIDRs", segment.CIDR)
		}
	}

	return true, ""
}

// AllowCIDR registers a new CIDR as safe for virtual expansion.
func (s *SafetyAgent) AllowCIDR(cidr string) {
	if s == nil || s.policy == nil {
		return
	}
	s.policy.AllowCIDR(cidr)
	s.mu.Lock()
	s.allowedCIDRs = append(s.allowedCIDRs, cidr)
	s.mu.Unlock()
}

// BlockCount returns the total number of blocked commands.
func (s *SafetyAgent) BlockCount() int64 {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.blockCount
}

// DeniedIPStats returns the most frequently targeted real IPs.
func (s *SafetyAgent) DeniedIPStats() map[string]int {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]int, len(s.deniedIPs))
	for k, v := range s.deniedIPs {
		out[k] = v
	}
	return out
}

// Summary returns a compact one-line safety status.
func (s *SafetyAgent) Summary() string {
	if s == nil {
		return "safety_agent:nil"
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return fmt.Sprintf("safety_agent:blocks=%d denied_ips=%d allowed_cidrs=%d",
		s.blockCount, len(s.deniedIPs), len(s.allowedCIDRs))
}

// ---- Internal helpers -----------------------------------------------------

func (s *SafetyAgent) recordBlock(command string, session *domain.SessionContext) {
	s.mu.Lock()
	s.blockCount++
	s.mu.Unlock()

	if session != nil {
		session.AppendEvent(domain.EventEntry{
			Type:      "safety_block",
			Timestamp: "",
			SessionID: session.SessionID,
			Detail:    command,
		})
		if session.Safety != nil {
			session.Safety.AddBlockedEvent("agent_block:" + command)
		}
	}
}

func (s *SafetyAgent) isAllowedCIDR(cidr string) bool {
	if s.policy != nil && s.policy.IsVirtualIP(extractFirstIP(cidr)) {
		return true
	}
	return false
}

func isPublicIP(ip string) bool {
	// Quick check: anything not in private ranges is public
	if strings.HasPrefix(ip, "10.") ||
		strings.HasPrefix(ip, "172.16.") ||
		strings.HasPrefix(ip, "172.17.") ||
		strings.HasPrefix(ip, "172.18.") ||
		strings.HasPrefix(ip, "172.19.") ||
		strings.HasPrefix(ip, "172.20.") ||
		strings.HasPrefix(ip, "172.21.") ||
		strings.HasPrefix(ip, "172.22.") ||
		strings.HasPrefix(ip, "172.23.") ||
		strings.HasPrefix(ip, "172.24.") ||
		strings.HasPrefix(ip, "172.25.") ||
		strings.HasPrefix(ip, "172.26.") ||
		strings.HasPrefix(ip, "172.27.") ||
		strings.HasPrefix(ip, "172.28.") ||
		strings.HasPrefix(ip, "172.29.") ||
		strings.HasPrefix(ip, "172.30.") ||
		strings.HasPrefix(ip, "172.31.") ||
		strings.HasPrefix(ip, "192.168.") ||
		strings.HasPrefix(ip, "127.") {
		return false
	}
	return true
}

func detectC2Indicator(command string) bool {
	lower := strings.ToLower(command)
	indicators := []string{
		"reverse_shell", "revshell", "msfvenom", "msfconsole",
		"empire", "cobalt_strike", "beacon", "meterpreter",
		"sliver", "havoc", "brute_ratel", "nimplant",
		"/dev/tcp/", "bash -i >&", "nc -e", "ncat -e",
	}
	for _, ind := range indicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	return false
}

func detectProxyAttempt(command string) bool {
	lower := strings.ToLower(command)
	indicators := []string{
		"proxychains", "tsocks", "ssh -D", "ssh -L", "ssh -R",
		"chisel", "frp", "nps", "socat", "ew ", "earthworm",
	}
	for _, ind := range indicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	return false
}

func buildBlockedOutput(command string, blockedIPs []string) string {
	var b strings.Builder
	for _, ip := range blockedIPs {
		b.WriteString(fmt.Sprintf("ssh: connect to host %s port 22: No route to host\n", ip))
	}
	return b.String()
}

func extractBaseCmd(command string) string {
	fields := strings.Fields(strings.TrimSpace(command))
	if len(fields) == 0 {
		return command
	}
	return fields[0]
}

func extractFirstIP(cidr string) string {
	idx := strings.Index(cidr, "/")
	if idx > 0 {
		return cidr[:idx]
	}
	return cidr
}
