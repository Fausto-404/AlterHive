package responders

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/alterhive/alterhive/internal/domain"
)

var (
	reCIDR = regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+`)
	reIP   = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)
	rePort = regexp.MustCompile(`-p\s*(\d+)`)
	reNcIP = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\d+)\b`)
)

// HandleNetworkCommand processes externally initiated scan/probe commands.
func HandleNetworkCommand(cmd string, session *domain.SessionContext, topology *domain.VirtualTopology) (string, []string) {
	var evidenceHits []string
	cmdLower := strings.ToLower(strings.TrimSpace(cmd))

	// nmap
	if strings.HasPrefix(cmdLower, "nmap") {
		evidenceHits = append(evidenceHits, "subnet_scan")
		hosts := scopedHosts(cmd, session, topology)

		// CIDR range scan
		if cidrMatch := reCIDR.FindString(cmd); cidrMatch != "" {
			return buildNmapScan(hosts, session, cidrMatch), evidenceHits
		}

		// Single IP target
		if ipMatch := reIP.FindString(cmd); ipMatch != "" {
			host := topology.GetHost(ipMatch)
			if host != nil {
				return buildSingleHostScan(host, session), evidenceHits
			}
			if host == nil && topology.IsVirtualIP(ipMatch) {
				return fmt.Sprintf("Starting Nmap 7.93 ( https://nmap.org )\nNmap scan report for %s\nHost is up (0.0042s latency).\nAll 1000 scanned ports on %s are filtered\n", ipMatch, ipMatch), evidenceHits
			}
			return "Starting Nmap 7.93 ( https://nmap.org )\nNote: Host seems down. If it is really up, but blocking our ping probes, try -Pn\nNmap done: 1 IP address (0 hosts up) scanned in 2.01 seconds\n", evidenceHits
		}

		// Default: full subnet scan
		return buildNmapScan(hosts, session, ""), evidenceHits
	}

	// fscan
	if strings.HasPrefix(cmdLower, "fscan") {
		evidenceHits = append(evidenceHits, "subnet_scan", "service_enum")
		return buildFscanOutput(scopedHosts(cmd, session, topology), session), evidenceHits
	}

	// nc / ncat
	if strings.HasPrefix(cmdLower, "nc ") || strings.HasPrefix(cmdLower, "ncat ") {
		evidenceHits = append(evidenceHits, "lateral_probe")

		if match := reNcIP.FindStringSubmatch(cmd); len(match) > 2 {
			targetIP := match[1]
			port := match[2]
			host := topology.GetHost(targetIP)
			if host != nil {
				return buildNcOutput(host, port, session), evidenceHits
			}
			return fmt.Sprintf("nc: connect to %s port %s (tcp) failed: Connection refused\n", targetIP, port), evidenceHits
		}

		if ipMatch := reIP.FindString(cmd); ipMatch != "" {
			return fmt.Sprintf("Connection to %s port [tcp] succeeded!\n", ipMatch), evidenceHits
		}
	}

	if strings.HasPrefix(cmdLower, "dddd2") {
		evidenceHits = append(evidenceHits, "subnet_scan", "service_enum", "vuln_probe")
		return buildDddd2Output(scopedHosts(cmd, session, topology), session), evidenceHits
	}

	if strings.HasPrefix(cmdLower, "nuclei") {
		evidenceHits = append(evidenceHits, "http_probe", "vuln_probe")
		return buildNucleiOutput(cmd, scopedHosts(cmd, session, topology), session), evidenceHits
	}

	if strings.HasPrefix(cmdLower, "gobuster") || strings.HasPrefix(cmdLower, "ffuf") {
		evidenceHits = append(evidenceHits, "http_probe", "web_enum")
		return buildWebFuzzOutput(cmdLower, scopedHosts(cmd, session, topology), session), evidenceHits
	}

	if strings.HasPrefix(cmdLower, "sqlmap") {
		evidenceHits = append(evidenceHits, "db_probe", "vuln_probe")
		return buildSQLMapOutput(cmdLower, scopedHosts(cmd, session, topology), session), evidenceHits
	}

	return "", evidenceHits
}

type scanHost struct {
	host    domain.VirtualHost
	visible bool
}

func scopedHosts(cmd string, session *domain.SessionContext, topology *domain.VirtualTopology) []scanHost {
	visible := topology.GetHostsForSession(session)
	visibleMap := map[string]bool{}
	for _, host := range visible {
		visibleMap[host.IP] = true
	}

	var selected []domain.VirtualHost
	if cidrMatch := reCIDR.FindString(cmd); cidrMatch != "" {
		selected = hostsInCIDR(topology.AllHosts(), cidrMatch)
	} else if ipMatch := reIP.FindString(cmd); ipMatch != "" {
		if host := topology.GetHost(ipMatch); host != nil {
			selected = []domain.VirtualHost{*host}
		}
	} else {
		selected = topology.AllHosts()
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].IP < selected[j].IP })
	out := make([]scanHost, 0, len(selected))
	for _, host := range selected {
		out = append(out, scanHost{host: host, visible: visibleMap[host.IP]})
	}
	return out
}

func hostsInCIDR(hosts []domain.VirtualHost, cidr string) []domain.VirtualHost {
	prefix := strings.TrimSuffix(cidr, "/24")
	parts := strings.Split(prefix, ".")
	if len(parts) != 4 {
		return nil
	}
	base := strings.Join(parts[:3], ".") + "."
	var out []domain.VirtualHost
	for _, host := range hosts {
		if strings.HasPrefix(host.IP, base) {
			out = append(out, host)
		}
	}
	return out
}

func buildFscanOutput(hosts []scanHost, session *domain.SessionContext) string {
	var lines []string
	lines = append(lines, "   ___                              _")
	lines = append(lines, "  / _ \\     ___  ___ _ __ __ _  ___| | __")
	lines = append(lines, " / /_)/____/ __|/ __| '__/ _` |/ __| |/ /")
	lines = append(lines, "/ ___/_____|__ \\ (__| | | (_| | (__|   <")
	lines = append(lines, "\\/         |___/\\___|_|  \\__,_|\\___|_|\\_\\")
	lines = append(lines, "[*] fscan version: 1.8.4")
	lines = append(lines, "[*] start infoscan")
	for _, item := range hosts {
		host := item.host
		lines = append(lines, fmt.Sprintf("[*] alive %s", host.IP))
		for _, svc := range host.Services {
			name := svc.NmapName
			if name == "" {
				name = svc.Protocol
			}
			if !item.visible {
				lines = append(lines, fmt.Sprintf("[-] %s %s:%d filtered", strings.ToUpper(name), host.IP, svc.Port))
				continue
			}
			switch svc.Protocol {
			case "http", "https", "http-proxy":
				scheme := "http"
				if svc.Protocol == "https" {
					scheme = "https"
				}
				lines = append(lines, fmt.Sprintf("[+] WebTitle: %s://%s:%d code:200 title:%s", scheme, host.IP, svc.Port, host.Hostname))
			case "ssh":
				lines = append(lines, fmt.Sprintf("[+] SSH %s:%d OpenSSH_8.9p1 Ubuntu", host.IP, svc.Port))
			case "mysql":
				lines = append(lines, fmt.Sprintf("[+] Mysql %s:%d open", host.IP, svc.Port))
			case "redis":
				lines = append(lines, fmt.Sprintf("[+] Redis %s:%d unauthorized or auth required", host.IP, svc.Port))
			case "ldap", "smb", "kerberos", "dns":
				lines = append(lines, fmt.Sprintf("[+] %s %s:%d open", strings.ToUpper(name), host.IP, svc.Port))
			default:
				lines = append(lines, fmt.Sprintf("[+] %s %s:%d open", name, host.IP, svc.Port))
			}
		}
	}
	lines = append(lines, "[*] scan finished")
	return strings.Join(lines, "\n") + "\n"
}

func hostInList(host *domain.VirtualHost, list []domain.VirtualHost) bool {
	for _, h := range list {
		if h.IP == host.IP {
			return true
		}
	}
	return false
}

func buildNmapScan(hosts []scanHost, session *domain.SessionContext, target string) string {
	if len(hosts) == 0 {
		if target == "" && session != nil && session.SubnetCIDR != "" {
			target = session.SubnetCIDR
		}
		if target == "" {
			target = "target range"
		}
		return fmt.Sprintf("Starting Nmap 7.93 ( https://nmap.org )\nNote: No active hosts found in %s. If hosts are behind a firewall, try -Pn or scan from a pivoted position.\nNmap done: 256 IP addresses (0 hosts up) scanned in 12.34 seconds\n", target)
	}

	var lines []string
	lines = append(lines, "Starting Nmap 7.93 ( https://nmap.org )")
	lines = append(lines, "")

	for _, item := range hosts {
		host := item.host
		lines = append(lines, fmt.Sprintf("Nmap scan report for %s", host.IP))
		lines = append(lines, "Host is up (0.0042s latency).")
		lines = append(lines, "")
		lines = append(lines, "PORT     STATE SERVICE     VERSION")

		for _, svc := range host.Services {
			svcName := svc.NmapName
			if svcName == "" {
				svcName = svc.Protocol
			}
			version := svc.Banner
			if persona := servicePersonaSummary(session, host.IP, svc.Protocol); persona != "" {
				version = persona
			}
			state := "open"
			if !item.visible {
				state = "filtered"
			}
			lines = append(lines, fmt.Sprintf("%-8s %-5s %-11s %s", fmt.Sprintf("%d/tcp", svc.Port), state, svcName, version))
		}
		lines = append(lines, "")
	}

	lines = append(lines, "Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .")
	lines = append(lines, fmt.Sprintf("Nmap done: 256 IP addresses (%d hosts up) scanned in 12.34 seconds", len(hosts)))

	return strings.Join(lines, "\n") + "\n"
}

func buildSingleHostScan(host *domain.VirtualHost, session *domain.SessionContext) string {
	visible := hostInList(host, sessionVisibleHosts(session, host))
	var lines []string
	lines = append(lines, "Starting Nmap 7.93 ( https://nmap.org )")
	lines = append(lines, fmt.Sprintf("Nmap scan report for %s", host.IP))
	lines = append(lines, "Host is up (0.0042s latency).")
	lines = append(lines, "")
	lines = append(lines, "PORT     STATE SERVICE     VERSION")

	for _, svc := range host.Services {
		svcName := svc.NmapName
		if svcName == "" {
			svcName = svc.Protocol
		}
		version := svc.Banner
		if persona := servicePersonaSummary(session, host.IP, svc.Protocol); persona != "" {
			version = persona
		}
		state := "open"
		if !visible {
			state = "filtered"
		}
		lines = append(lines, fmt.Sprintf("%-8s %-5s %-11s %s", fmt.Sprintf("%d/tcp", svc.Port), state, svcName, version))
	}

	lines = append(lines, "")
	lines = append(lines, "Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .")
	lines = append(lines, "Nmap done: 1 IP address (1 host up) scanned in 3.21 seconds")
	return strings.Join(lines, "\n") + "\n"
}

func servicePersonaSummary(session *domain.SessionContext, hostIP, protocol string) string {
	if session == nil || hostIP == "" || protocol == "" {
		return ""
	}
	if session.Planning != nil {
		if fact, ok := session.Planning.GetServicePersona(hostIP, protocol); ok {
			return compactVersionString(fact.Summary)
		}
	}
	if session.Memory == nil {
		return ""
	}
	if fact, ok := session.Memory.GetInvariant("service." + hostIP + "." + protocol); ok {
		return compactVersionString(fact.Value)
	}
	return ""
}

func compactVersionString(value string) string {
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.TrimSpace(value)
	if len(value) > 80 {
		value = value[:77] + "..."
	}
	return value
}

func sessionVisibleHosts(session *domain.SessionContext, host *domain.VirtualHost) []domain.VirtualHost {
	if host == nil {
		return nil
	}
	allMet := true
	for _, state := range host.RequiredState {
		if !session.HasAccessState(state) {
			allMet = false
			break
		}
	}
	if allMet {
		return []domain.VirtualHost{*host}
	}
	return nil
}

func buildNcOutput(host *domain.VirtualHost, port string, session *domain.SessionContext) string {
	if !hostInList(host, sessionVisibleHosts(session, host)) {
		return fmt.Sprintf("nc: connect to %s port %s (tcp) timed out: Operation now in progress\n", host.IP, port)
	}
	for _, svc := range host.Services {
		if fmt.Sprintf("%d", svc.Port) == port {
			switch svc.FailureMode {
			case "refused":
				return fmt.Sprintf("Connection to %s %s port [tcp/*] refused!\n", host.IP, port)
			default:
				return fmt.Sprintf("Connection to %s %s port [tcp/*] succeeded!\n", host.IP, port)
			}
		}
	}
	return fmt.Sprintf("nc: connect to %s port %s (tcp) failed: Connection refused\n", host.IP, port)
}

func buildDddd2Output(hosts []scanHost, session *domain.SessionContext) string {
	var lines []string
	lines = append(lines, "[*] dddd2 v0.5.9 started")
	for _, item := range hosts {
		host := item.host
		if !item.visible {
			lines = append(lines, fmt.Sprintf("[-] %s host alive but all probes filtered", host.IP))
			continue
		}
		lines = append(lines, fmt.Sprintf("[+] %s %s os:%s", host.IP, host.Hostname, host.OS))
		for _, svc := range host.Services {
			product := serviceProduct(host, svc)
			lines = append(lines, fmt.Sprintf("[+] %s:%d %s fingerprint:%s", host.IP, svc.Port, svc.Protocol, product))
			if isLikelyVulnHint(host, svc) {
				lines = append(lines, fmt.Sprintf("[?] %s:%d possible weak config, poc check requires auth or pivot context", host.IP, svc.Port))
			}
		}
	}
	lines = append(lines, "[*] scan done")
	return strings.Join(lines, "\n") + "\n"
}

func buildNucleiOutput(cmd string, hosts []scanHost, session *domain.SessionContext) string {
	var lines []string
	for _, item := range hosts {
		host := item.host
		if !item.visible {
			continue
		}
		for _, svc := range host.Services {
			if svc.Protocol != "http" && svc.Protocol != "https" {
				continue
			}
			scheme := "http"
			if svc.Protocol == "https" {
				scheme = "https"
			}
			url := fmt.Sprintf("%s://%s:%d", scheme, host.IP, svc.Port)
			lines = append(lines, fmt.Sprintf("[exposed-panel] [http] [info] %s [%s]", url, host.Hostname))
			if isLikelyVulnHint(host, svc) {
				lines = append(lines, fmt.Sprintf("[legacy-config-disclosure] [http] [medium] %s [requires-auth]", url))
			}
		}
	}
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

func buildWebFuzzOutput(cmdLower string, hosts []scanHost, session *domain.SessionContext) string {
	host := firstVisibleWebHost(hosts)
	if host == nil {
		return "Error: context deadline exceeded while connecting to target\n"
	}
	if strings.HasPrefix(cmdLower, "ffuf") {
		return `admin                   [Status: 302, Size: 178, Words: 12, Lines: 5]
backup                  [Status: 403, Size: 153, Words: 9, Lines: 4]
api                     [Status: 200, Size: 421, Words: 31, Lines: 8]
server-status           [Status: 403, Size: 274, Words: 20, Lines: 7]
`
	}
	return `/admin               (Status: 302) [Size: 178]
/api                 (Status: 200) [Size: 421]
/backup              (Status: 403) [Size: 153]
/server-status       (Status: 403) [Size: 274]
`
}

func buildSQLMapOutput(cmdLower string, hosts []scanHost, session *domain.SessionContext) string {
	if strings.Contains(cmdLower, "--dbs") {
		return `available databases [2]:
[*] information_schema
[*] fin_readonly_` + domain.DeploySeed + `
`
	}
	if strings.Contains(cmdLower, "--tables") {
		return `Database: fin_readonly_" + domain.DeploySeed + "
[4 tables]
+--------------+
| accounts     |
| audit_log    |
| transactions |
| users        |
+--------------+
`
	}
	if strings.Contains(cmdLower, "--dump") {
		return `sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: boolean-based blind
---
[WARNING] reflective value(s) found and filtering out
[INFO] fetching entries for table 'users' in database 'fin_readonly_` + domain.DeploySeed + `'
[ERROR] unable to dump full table: current DB user has SELECT on limited columns only
`
	}
	return `[INFO] testing connection to the target URL
[INFO] checking if the target is protected by some kind of WAF/IPS
[INFO] testing if GET parameter 'id' is dynamic
[INFO] heuristic (basic) test shows that GET parameter 'id' might be injectable
[WARNING] the back-end DBMS is MySQL but current user appears restricted
`
}

func firstVisibleWebHost(hosts []scanHost) *domain.VirtualHost {
	for _, item := range hosts {
		if !item.visible {
			continue
		}
		for _, svc := range item.host.Services {
			if svc.Protocol == "http" || svc.Protocol == "https" {
				host := item.host
				return &host
			}
		}
	}
	return nil
}

func serviceProduct(host domain.VirtualHost, svc domain.VirtualService) string {
	if svc.Banner != "" {
		return svc.Banner
	}
	switch svc.Protocol {
	case "ssh":
		return "OpenSSH_8.4p1 Debian"
	case "mysql":
		return "MySQL 5.7.38"
	case "redis":
		return "Redis 6.2.7"
	case "smb":
		return "Windows Server 2019 microsoft-ds"
	case "ldap":
		return "Microsoft Active Directory LDAP"
	default:
		if svc.NmapName != "" {
			return svc.NmapName
		}
		return svc.Protocol + " service " + strconv.Itoa(svc.Port)
	}
}

func isLikelyVulnHint(host domain.VirtualHost, svc domain.VirtualService) bool {
	return strings.Contains(host.Role, "app") ||
		strings.Contains(host.Role, "runner") ||
		strings.Contains(host.Role, "finance") ||
		svc.Protocol == "http" ||
		svc.Protocol == "https" ||
		svc.Protocol == "mysql"
}
