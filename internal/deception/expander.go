package deception

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/alterhive/alterhive/internal/domain"
)

var requestedCIDRPattern = regexp.MustCompile(`\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])|192\.168)\.\d{1,3}\.\d{1,3}/24\b`)
var requestedPrivateIPPattern = regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`)

// ExpansionDecision describes an intent-driven topology growth request.
type ExpansionDecision struct {
	Triggered bool   `json:"triggered"`
	CIDR      string `json:"cidr"`
	TargetIP  string `json:"target_ip"`
	Theme     string `json:"theme"`
	PivotIP   string `json:"pivot_ip"`
	Reason    string `json:"reason"`
}

// DetectExpansionIntent converts attacker behavior into graph growth. This is
// deterministic so the topology can expand before slower LLM advice returns.
func DetectExpansionIntent(command string, profile AgentProfile) ExpansionDecision {
	lower := strings.ToLower(command)
	cidr := requestedCIDRPattern.FindString(lower)
	targetIP := ""
	if cidr == "" {
		targetIP = requestedPrivateIPPattern.FindString(lower)
		if targetIP != "" {
			cidr = cidrForHostIP(targetIP)
		}
	}
	theme := detectTheme(lower, profile)

	if cidr == "" && theme == "" {
		return ExpansionDecision{}
	}
	if theme == "" {
		theme = "network"
	}
	if cidr == "" {
		cidr = DefaultCIDRForTheme(theme)
	}

	return ExpansionDecision{
		Triggered: true,
		CIDR:      cidr,
		TargetIP:  targetIP,
		Theme:     theme,
		PivotIP:   "",
		Reason:    expansionReason(cidr, theme, profile),
	}
}

// ExpandShadowTopology appends a locked segment, pivot edge, and themed hosts.
func ExpandShadowTopology(session *domain.SessionContext, topology *domain.VirtualTopology, decision ExpansionDecision) []domain.VirtualHost {
	if session == nil || topology == nil || !decision.Triggered || decision.CIDR == "" {
		return nil
	}
	if decision.PivotIP == "" {
		decision.PivotIP = DefaultPivotIP(topology, session)
	}
	theme := decision.Theme
	if theme == "" {
		theme = "network"
	}

	topology.AppendSegment(domain.NetworkSegment{
		CIDR:           decision.CIDR,
		Name:           fmt.Sprintf("%s-shadow", theme),
		Zone:           "shadow",
		GatewayIP:      hostIP(decision.CIDR, 1),
		Shadow:         true,
		VisibleAfter:   []string{"subnet_scan"},
		OwnerSessionID: session.SessionID,
	})
	topology.AppendEdge(domain.NetworkEdge{
		From:           decision.PivotIP,
		To:             decision.CIDR,
		Type:           "pivot",
		Via:            decision.PivotIP,
		RequiredState:  PivotGateStates(),
		Status:         "locked",
		OwnerSessionID: session.SessionID,
	})

	var added []domain.VirtualHost
	for _, host := range themedHosts(decision.CIDR, theme, decision.PivotIP) {
		host.OwnerSessionID = session.SessionID
		if topology.GetHostForSession(host.IP, session.SessionID) != nil {
			continue
		}
		topology.AppendHost(host)
		added = append(added, host)
		session.AddShadowHost(map[string]string{
			"ip":             host.IP,
			"hostname":       host.Hostname,
			"role":           host.Role,
			"segment_cidr":   host.SegmentCIDR,
			"reachable_via":  host.ReachableVia,
			"theme":          host.Theme,
			"status":         "locked",
			"required_state": strings.Join(host.RequiredState, ","),
			"triggered_by":   decision.Reason,
		})
	}
	return added
}

// DefaultPivotIP chooses the currently configured pivot instead of relying on
// the original 192.168.56.10 template.
func DefaultPivotIP(topology *domain.VirtualTopology, session *domain.SessionContext) string {
	if topology != nil {
		for _, host := range topology.AllHosts() {
			if host.Role == "jumpbox" || strings.EqualFold(host.Hostname, "jump01") {
				return host.IP
			}
		}
	}
	if session != nil && session.SubnetGateway != "" {
		return session.SubnetGateway
	}
	return "192.168.56.10"
}

func detectTheme(command string, profile AgentProfile) string {
	switch {
	case strings.Contains(command, "finance"), strings.Contains(command, "payroll"), strings.Contains(command, "billing"), strings.Contains(command, "accounting"), strings.Contains(command, "财务"):
		return "finance"
	case strings.Contains(command, "flag"), strings.Contains(command, "proof"), strings.Contains(command, "root.txt"), strings.Contains(command, "user.txt"):
		return "flag"
	case strings.Contains(command, "kubectl"), strings.Contains(command, "k8s"), strings.Contains(command, "kube"), strings.Contains(command, "jenkins"), strings.Contains(command, "gitlab"), strings.Contains(command, "registry"):
		return "cloud"
	case strings.Contains(command, "ldap"), strings.Contains(command, "kerberos"), strings.Contains(command, "smb"), strings.Contains(command, "dc"), strings.Contains(command, "domain"):
		return "domain"
	case profile.PrimaryStyle == "cloud_native":
		return "cloud"
	case profile.PrimaryStyle == "domain_mapper":
		return "domain"
	case profile.PrimaryStyle == "network_mapper":
		return "network"
	default:
		return ""
	}
}

// DefaultCIDRForTheme returns the default CIDR for a given theme.
func DefaultCIDRForTheme(theme string) string {
	switch theme {
	case "finance":
		return "10.42.18.0/24"
	case "flag":
		return "172.20.7.0/24"
	case "cloud":
		return "10.88.12.0/24"
	case "domain":
		return "10.9.30.0/24"
	default:
		return "10.1.5.0/24"
	}
}

func expansionReason(cidr, theme string, profile AgentProfile) string {
	if profile.PrimaryStyle != "" && profile.PrimaryStyle != "general_recon" {
		return fmt.Sprintf("%s:%s:%s", profile.PrimaryStyle, theme, cidr)
	}
	return fmt.Sprintf("%s:%s", theme, cidr)
}

func themedHosts(cidr, theme, pivotIP string) []domain.VirtualHost {
	switch theme {
	case "finance":
		return []domain.VirtualHost{
			shadowHost(cidr, 10, "finance-web-01", "finance_app", "Ubuntu 22.04", pivotIP, theme, services("https", "http")),
			shadowHost(cidr, 20, "finance-db-01", "finance_db", "CentOS 7", pivotIP, theme, services("mysql", "ssh")),
			shadowHost(cidr, 30, "backup-nas-01", "backup", "TrueNAS", pivotIP, theme, services("smb")),
		}
	case "flag":
		return []domain.VirtualHost{
			shadowHost(cidr, 11, "dev-wiki-01", "flag_hint_wiki", "Ubuntu 20.04", pivotIP, theme, services("http")),
			shadowHost(cidr, 21, "artifact-store-01", "flag_hint_artifacts", "Debian 11", pivotIP, theme, services("http-alt")),
			shadowHost(cidr, 31, "old-runner-01", "flag_hint_runner", "Ubuntu 18.04", pivotIP, theme, services("ssh")),
		}
	case "cloud":
		return []domain.VirtualHost{
			shadowHost(cidr, 10, "gitlab-runner-01", "runner", "Ubuntu 22.04", pivotIP, theme, services("ssh")),
			shadowHost(cidr, 20, "k8s-master-01", "k8s_api", "Ubuntu 22.04", pivotIP, theme, services("k8s")),
			shadowHost(cidr, 30, "registry-01", "registry", "Alpine Linux", pivotIP, theme, services("registry")),
		}
	case "domain":
		return []domain.VirtualHost{
			shadowHost(cidr, 50, "child-dc-01", "child_dc", "Windows Server 2019", pivotIP, theme, services("ad")),
			shadowHost(cidr, 60, "fs-archive-01", "file_share", "Windows Server 2016", pivotIP, theme, services("smb")),
		}
	default:
		return []domain.VirtualHost{
			shadowHost(cidr, 10, "app-node-01", "app", "Ubuntu 22.04", pivotIP, theme, services("http", "ssh")),
			shadowHost(cidr, 20, "db-node-01", "database", "CentOS 7", pivotIP, theme, services("mysql")),
		}
	}
}

func shadowHost(cidr string, lastOctet int, hostname, role, osName, pivotIP, theme string, svcs []domain.VirtualService) domain.VirtualHost {
	return domain.VirtualHost{
		IP:             hostIP(cidr, lastOctet),
		Hostname:       hostname,
		Role:           role,
		OS:             osName,
		CanaryID:       domain.DeploySeed,
		Services:       svcs,
		VisibleAfter:   []string{"subnet_scan"},
		SegmentCIDR:    cidr,
		ReachableVia:   pivotIP,
		RequiredState:  gateStatesForTheme(theme, role),
		Shadow:         true,
		Theme:          theme,
		CompromiseMode: "partial",
		Password:       shadowPassword(hostname, lastOctet),
	}
}

func gateStatesForTheme(theme, role string) []string {
	switch {
	case strings.Contains(role, "target"):
		return TargetGateStates()
	case theme == "flag":
		return []string{GateJump01LowPrivShell, GateExploitPartial}
	case theme == "finance":
		return []string{GateJump01LowPrivShell, GateCredentialValidated}
	case theme == "cloud":
		return []string{GateJump01LowPrivShell, GateServiceAuthLimited}
	case theme == "domain":
		return []string{GateJump01LowPrivShell, GateServiceAuthLimited}
	default:
		return PivotGateStates()
	}
}

func hostIP(cidr string, lastOctet int) string {
	base := strings.Split(cidr, "/")[0]
	parts := strings.Split(base, ".")
	if len(parts) != 4 {
		return base
	}
	parts[3] = fmt.Sprintf("%d", lastOctet)
	return strings.Join(parts, ".")
}

func cidrForHostIP(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	parts[3] = "0"
	return strings.Join(parts, ".") + "/24"
}

// chainedCIDRs generates 2-3 sequential /24 CIDRs for multi-hop chains
// derived from the original CIDR's third octet.
func chainedCIDRs(baseCIDR, theme string) []string {
	parts := strings.Split(strings.Split(baseCIDR, "/")[0], ".")
	third, err := strconv.Atoi(parts[2])
	if err != nil || third < 0 || third > 255 {
		return []string{baseCIDR}
	}
	prefix := parts[0] + "." + parts[1]

	switch theme {
	case "flag":
		return []string{
			fmt.Sprintf("172.20.%d.0/24", third),
			fmt.Sprintf("172.20.%d.0/24", wrapOctet(third+1)),
			fmt.Sprintf("172.20.%d.0/24", wrapOctet(third+2)),
		}
	case "finance":
		return []string{
			fmt.Sprintf("10.42.%d.0/24", third),
			fmt.Sprintf("10.42.%d.0/24", wrapOctet(third+1)),
		}
	case "cloud":
		return []string{
			fmt.Sprintf("10.88.%d.0/24", third),
			fmt.Sprintf("10.88.%d.0/24", wrapOctet(third+1)),
		}
	case "domain":
		return []string{
			fmt.Sprintf("10.9.%d.0/24", third),
			fmt.Sprintf("10.9.%d.0/24", wrapOctet(third+1)),
		}
	default:
		return []string{
			fmt.Sprintf("%s.%d.0/24", prefix, third),
			fmt.Sprintf("%s.%d.0/24", prefix, wrapOctet(third+1)),
		}
	}
}

func wrapOctet(v int) int {
	if v > 255 {
		return v - 256
	}
	if v < 0 {
		return v + 256
	}
	return v
}

// themedHopHosts returns hosts for a specific hop in the multi-hop chain.
// Each hop gets a distinct set of hosts with the correct reachableVia.
func themedHopHosts(cidr, theme, reachableVia string) []domain.VirtualHost {
	switch theme {
	case "flag":
		return []domain.VirtualHost{
			shadowHost(cidr, 10, "web-proxy-01", "web_proxy", "Ubuntu 22.04", reachableVia, theme, services("http", "ssh")),
			shadowHost(cidr, 20, "artifact-store-01", "flag_hint_artifacts", "Debian 11", reachableVia, theme, services("http-alt", "ssh")),
			shadowHost(cidr, 30, "old-runner-01", "flag_hint_runner", "Ubuntu 18.04", reachableVia, theme, services("ssh")),
		}
	case "finance":
		return []domain.VirtualHost{
			shadowHost(cidr, 10, "finance-web-01", "finance_app", "Ubuntu 22.04", reachableVia, theme, services("https", "http")),
			shadowHost(cidr, 20, "finance-db-01", "finance_db", "CentOS 7", reachableVia, theme, services("mysql", "ssh")),
			shadowHost(cidr, 30, "backup-nas-01", "backup", "TrueNAS", reachableVia, theme, services("smb")),
		}
	case "cloud":
		return []domain.VirtualHost{
			shadowHost(cidr, 10, "gitlab-runner-01", "runner", "Ubuntu 22.04", reachableVia, theme, services("ssh")),
			shadowHost(cidr, 20, "k8s-master-01", "k8s_api", "Ubuntu 22.04", reachableVia, theme, services("k8s")),
			shadowHost(cidr, 30, "registry-01", "registry", "Alpine Linux", reachableVia, theme, services("registry")),
		}
	case "domain":
		return []domain.VirtualHost{
			shadowHost(cidr, 50, "child-dc-01", "child_dc", "Windows Server 2019", reachableVia, theme, services("ad")),
			shadowHost(cidr, 60, "fs-archive-01", "file_share", "Windows Server 2016", reachableVia, theme, services("smb")),
		}
	default:
		return []domain.VirtualHost{
			shadowHost(cidr, 10, "app-node-01", "app", "Ubuntu 22.04", reachableVia, theme, services("http", "ssh")),
			shadowHost(cidr, 20, "db-node-01", "database", "CentOS 7", reachableVia, theme, services("mysql")),
		}
	}
}

func services(names ...string) []domain.VirtualService {
	var out []domain.VirtualService
	for _, name := range names {
		switch name {
		case "ssh":
			out = append(out, domain.VirtualService{Port: 22, Protocol: "ssh", NmapName: "ssh", FailureMode: "auth_denied"})
		case "http":
			out = append(out, domain.VirtualService{Port: 80, Protocol: "http", NmapName: "http", Banner: "nginx", FailureMode: "redirect_login"})
		case "http-alt":
			out = append(out, domain.VirtualService{Port: 8080, Protocol: "http", NmapName: "http-proxy", Banner: "Jetty", FailureMode: "redirect_login"})
		case "https":
			out = append(out, domain.VirtualService{Port: 443, Protocol: "https", NmapName: "ssl/http", Banner: "nginx", FailureMode: "redirect_login"})
		case "mysql":
			out = append(out, domain.VirtualService{Port: 3306, Protocol: "mysql", NmapName: "mysql", FailureMode: "auth_denied"})
		case "smb":
			out = append(out, domain.VirtualService{Port: 445, Protocol: "smb", NmapName: "microsoft-ds", FailureMode: "access_denied"})
		case "k8s":
			out = append(out, domain.VirtualService{Port: 6443, Protocol: "https", NmapName: "https", FailureMode: "auth_required"})
			out = append(out, domain.VirtualService{Port: 10250, Protocol: "https", NmapName: "https", FailureMode: "auth_required"})
		case "registry":
			out = append(out, domain.VirtualService{Port: 5000, Protocol: "http", NmapName: "http", Banner: "Docker Registry", FailureMode: "auth_required"})
		case "ad":
			out = append(out, domain.VirtualService{Port: 53, Protocol: "dns", NmapName: "domain", FailureMode: "refused"})
			out = append(out, domain.VirtualService{Port: 88, Protocol: "kerberos", NmapName: "kerberos-sec", FailureMode: "auth_required"})
			out = append(out, domain.VirtualService{Port: 389, Protocol: "ldap", NmapName: "ldap", FailureMode: "stronger_auth_required"})
			out = append(out, domain.VirtualService{Port: 445, Protocol: "smb", NmapName: "microsoft-ds", FailureMode: "access_denied"})
		}
	}
	return out
}

// shadowPassword generates a per-host password using domain.DerivePassword.
func shadowPassword(hostname string, lastOctet int) string {
	return domain.DerivePassword(hostname)
}
