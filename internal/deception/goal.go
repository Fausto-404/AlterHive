package deception

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/alterhive/alterhive/internal/domain"
)

var (
	goalCIDRPattern = regexp.MustCompile(`\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}|172\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}|192\.168\.\d{1,3}\.\d{1,3}/\d{1,2})\b`)
	goalIPPattern   = regexp.MustCompile(`\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`)
)

// GoalTarget represents a parsed attack target.
type GoalTarget struct {
	TargetIP string
	CIDR     string
	Theme    string
	Raw      string
}

// ParseGoal extracts a target IP or CIDR from command text.
// Returns nil if no private IP/CIDR is found.
func ParseGoal(text string) *GoalTarget {
	themeHint := themeForText(text)
	// Try CIDR first
	if m := goalCIDRPattern.FindString(text); m != "" {
		theme := themeForCIDR(m)
		if themeHint != "" {
			theme = themeHint
		}
		return &GoalTarget{CIDR: m, Theme: theme, Raw: m}
	}
	// Try bare IP
	if m := goalIPPattern.FindString(text); m != "" {
		cidr := ipToCIDR(m)
		theme := themeForCIDR(cidr)
		if themeHint != "" {
			theme = themeHint
		}
		return &GoalTarget{TargetIP: m, CIDR: cidr, Theme: theme, Raw: m}
	}
	return nil
}

// InjectGoalTopology creates a gated goal lead and an intermediate shadow path.
// Returns true if new topology was injected.
func InjectGoalTopology(session *domain.SessionContext, topology *domain.VirtualTopology, safety *domain.SafetyPolicy, goal *GoalTarget) bool {
	if goal == nil || goal.CIDR == "" {
		return false
	}
	if topology == nil || session == nil || safety == nil {
		return false
	}

	pivotIP := DefaultPivotIP(topology, session)
	if goal.TargetIP != "" && session.Planning != nil {
		session.Planning.AddProtectedTarget(goal.TargetIP)
	}

	// Allow the requested CIDR and all multi-hop chain CIDRs so scans
	// fail as filtered virtual traffic rather than leaking real-network behavior.
	safety.AllowCIDR(goal.CIDR)
	multiHopCIDRs := chainedCIDRs(goal.CIDR, goal.Theme)
	for _, cidr := range multiHopCIDRs {
		safety.AllowCIDR(cidr)
	}

	added := topology.AppendSegment(domain.NetworkSegment{
		CIDR:           goal.CIDR,
		Name:           fmt.Sprintf("goal-lead-%s", goal.Theme),
		Zone:           "goal",
		GatewayIP:      hostIPFromCIDR(goal.CIDR, 1),
		Shadow:         true,
		OwnerSessionID: session.SessionID,
	})

	// Goal assets must never be directly reachable from the entry host. The goal
	// segment is visible as a lead, but real access is gated behind jump01 PPF.
	topology.AppendEdge(domain.NetworkEdge{
		From:           pivotIP,
		To:             goal.CIDR,
		Type:           "pivot",
		Via:            pivotIP,
		RequiredState:  PivotGateStates(),
		Status:         "locked",
		OwnerSessionID: session.SessionID,
	})

	// Exact target IPs are terminal objectives. Do not create them here; the
	// topology planner/LLM will produce an intermediate path or fallback chain.
	if goal.TargetIP == "" {
		defaultIP := hostIPFromCIDR(goal.CIDR, 50)
		if topology.GetHostForSession(defaultIP, session.SessionID) == nil {
			host := domain.VirtualHost{
				IP:             defaultIP,
				Hostname:       hostnameForGoal(defaultIP, goal.Theme),
				Role:           roleForTheme(goal.Theme),
				OS:             "Ubuntu 22.04",
				Services:       servicesForTheme(goal.Theme),
				VisibleAfter:   []string{"subnet_scan"},
				SegmentCIDR:    goal.CIDR,
				ReachableVia:   pivotIP,
				RequiredState:  TargetGateStates(),
				Shadow:         true,
				Theme:          goal.Theme,
				CompromiseMode: "partial",
				OwnerSessionID: session.SessionID,
			}
			topology.AppendHost(host)
			addGoalShadowHost(session, host, goal.Raw)
			added = true
		}
	}

	// Create multi-hop shadow chain to provide intermediate lateral movement
	// steps before the attacker reaches the goal segment.
	multiHopPlan := PlanFromDecision(ExpansionDecision{
		Triggered: true,
		CIDR:      goal.CIDR,
		TargetIP:  goal.TargetIP,
		Theme:     goal.Theme,
		PivotIP:   pivotIP,
		Reason:    fmt.Sprintf("goal:%s", goal.Raw),
	})
	// Filter out hosts at protected target IPs (terminal objectives).
	filteredHosts := make([]domain.VirtualHost, 0, len(multiHopPlan.Hosts))
	for _, host := range multiHopPlan.Hosts {
		if goal.TargetIP != "" && host.IP == goal.TargetIP {
			continue
		}
		filteredHosts = append(filteredHosts, host)
	}
	multiHopPlan.Hosts = filteredHosts
	// Merge multi-hop segments, edges, and hosts into the topology.
	for _, segment := range multiHopPlan.Segments {
		segment.OwnerSessionID = session.SessionID
		topology.AppendSegment(segment)
	}
	for _, edge := range multiHopPlan.Edges {
		edge.OwnerSessionID = session.SessionID
		topology.AppendEdge(edge)
	}
	for _, host := range multiHopPlan.Hosts {
		host.OwnerSessionID = session.SessionID
		if topology.GetHostForSession(host.IP, session.SessionID) != nil {
			continue
		}
		topology.AppendHost(host)
		added = true
		session.AddShadowHost(map[string]string{
			"ip":             host.IP,
			"hostname":       host.Hostname,
			"role":           host.Role,
			"segment_cidr":   host.SegmentCIDR,
			"reachable_via":  host.ReachableVia,
			"theme":          host.Theme,
			"status":         "locked",
			"required_state": strings.Join(host.RequiredState, ","),
			"triggered_by":   fmt.Sprintf("goal_chain:%s", goal.Raw),
		})
	}

	if added && session.Planning != nil {
		session.Planning.SetGoal(fmt.Sprintf("%s:%s:%s", goal.Theme, goal.CIDR, goal.TargetIP), "goal_trace")
		session.Planning.BumpExposedFactVersion("goal_trace:" + goal.Raw)
	}
	return added
}

func addGoalShadowHost(session *domain.SessionContext, host domain.VirtualHost, trigger string) {
	session.AddShadowHost(map[string]string{
		"ip":             host.IP,
		"hostname":       host.Hostname,
		"role":           host.Role,
		"segment_cidr":   host.SegmentCIDR,
		"reachable_via":  host.ReachableVia,
		"theme":          host.Theme,
		"status":         "locked",
		"required_state": strings.Join(host.RequiredState, ","),
		"triggered_by":   "goal:" + trigger,
	})
}

func ipToCIDR(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	return parts[0] + "." + parts[1] + "." + parts[2] + ".0/24"
}

func hostIPFromCIDR(cidr string, lastOctet int) string {
	base := strings.Split(cidr, "/")[0]
	parts := strings.Split(base, ".")
	if len(parts) != 4 {
		return base
	}
	parts[3] = fmt.Sprintf("%d", lastOctet)
	return strings.Join(parts, ".")
}

func themeForCIDR(cidr string) string {
	base := strings.Split(cidr, "/")[0]
	parts := strings.Split(base, ".")
	if len(parts) != 4 {
		return "network"
	}
	// Use the third octet to pick a theme deterministically
	var octet int
	fmt.Sscanf(parts[2], "%d", &octet)
	themes := []string{"network", "finance", "cloud", "domain", "flag"}
	return themes[octet%len(themes)]
}

func themeForText(text string) string {
	lower := strings.ToLower(text)
	switch {
	case strings.Contains(lower, "flag"), strings.Contains(lower, "proof"), strings.Contains(lower, "root.txt"), strings.Contains(lower, "user.txt"):
		return "flag"
	case strings.Contains(lower, "finance"), strings.Contains(lower, "payroll"), strings.Contains(lower, "billing"), strings.Contains(lower, "财务"):
		return "finance"
	case strings.Contains(lower, "kubectl"), strings.Contains(lower, "k8s"), strings.Contains(lower, "kube"), strings.Contains(lower, "jenkins"), strings.Contains(lower, "gitlab"):
		return "cloud"
	case strings.Contains(lower, "ldap"), strings.Contains(lower, "kerberos"), strings.Contains(lower, "smb"), strings.Contains(lower, "domain"), strings.Contains(lower, "域控"):
		return "domain"
	default:
		return ""
	}
}

func diversionCIDRForGoal(goal *GoalTarget) string {
	if goal == nil || goal.TargetIP == "" {
		return goal.CIDR
	}
	parts := strings.Split(goal.TargetIP, ".")
	if len(parts) != 4 {
		return DefaultCIDRForTheme(goal.Theme)
	}
	switch goal.Theme {
	case "flag":
		return "172.20." + parts[2] + ".0/24"
	case "finance":
		return "10.42." + parts[2] + ".0/24"
	case "cloud":
		return "10.88." + parts[2] + ".0/24"
	case "domain":
		return "10.9." + parts[2] + ".0/24"
	default:
		return "10.1." + parts[2] + ".0/24"
	}
}

func hostnameForGoal(ip string, theme string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return "srv-01"
	}

	var octet int
	fmt.Sscanf(parts[3], "%d", &octet)

	// Generate realistic hostnames based on theme - no suffix needed, names are complete
	switch theme {
	case "finance":
		hostnames := []string{"fin-app01", "acc-web01", "fin-api01", "fin-db02", "acc-srv01"}
		return hostnames[octet%len(hostnames)]
	case "cloud":
		hostnames := []string{"k8s-node01", "kube-apisrv", "etcd-01", "cloud-api01", "ingress-01"}
		return hostnames[octet%len(hostnames)]
	case "domain":
		hostnames := []string{"dc-child01", "ldap-srv01", "ad-replica01", "dns-sec01", "ca-srv01"}
		return hostnames[octet%len(hostnames)]
	case "flag":
		hostnames := []string{"web-prod01", "app-srv01", "ctf-srv01", "flag-box01", "target-01"}
		return hostnames[octet%len(hostnames)]
	default:
		hostnames := []string{"srv-prod01", "web-app01", "app-srv01", "node-01", "host-01"}
		return hostnames[octet%len(hostnames)]
	}
}

func roleForTheme(theme string) string {
	switch theme {
	case "finance":
		return "finance_app"
	case "cloud":
		return "cloud_api"
	case "domain":
		return "domain_ctrl"
	case "flag":
		return "flag_server"
	default:
		return "app"
	}
}

func servicesForTheme(theme string) []domain.VirtualService {
	switch theme {
	case "finance":
		return []domain.VirtualService{
			{Port: 22, Protocol: "ssh", NmapName: "ssh", FailureMode: "auth_denied"},
			{Port: 443, Protocol: "https", NmapName: "ssl/http", Banner: "nginx", FailureMode: "redirect_login"},
			{Port: 3306, Protocol: "mysql", NmapName: "mysql", FailureMode: "auth_denied"},
		}
	case "cloud":
		return []domain.VirtualService{
			{Port: 22, Protocol: "ssh", NmapName: "ssh", FailureMode: "auth_denied"},
			{Port: 6443, Protocol: "https", NmapName: "https", FailureMode: "auth_required"},
		}
	case "domain":
		return []domain.VirtualService{
			{Port: 53, Protocol: "dns", NmapName: "domain", FailureMode: "refused"},
			{Port: 389, Protocol: "ldap", NmapName: "ldap", FailureMode: "stronger_auth_required"},
			{Port: 445, Protocol: "smb", NmapName: "microsoft-ds", FailureMode: "access_denied"},
		}
	case "flag":
		return []domain.VirtualService{
			{Port: 22, Protocol: "ssh", NmapName: "ssh", FailureMode: "auth_denied"},
			{Port: 80, Protocol: "http", NmapName: "http", Banner: "nginx", FailureMode: "redirect_login"},
		}
	default:
		return []domain.VirtualService{
			{Port: 22, Protocol: "ssh", NmapName: "ssh", FailureMode: "auth_denied"},
			{Port: 80, Protocol: "http", NmapName: "http", Banner: "nginx", FailureMode: "redirect_login"},
		}
	}
}
