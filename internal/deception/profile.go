package deception

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/alterhive/alterhive/internal/domain"
)

// AgentProfile represents the detected behavioral style of an attacker.
type AgentProfile struct {
	PrimaryStyle string         `json:"primary_style"`
	Scores       map[string]int `json:"scores"`
	Signals      []string       `json:"signals"`
}

var profilePatterns = []struct {
	regex  *regexp.Regexp
	style  string
	signal string
}{
	// secret_hunter
	{regexp.MustCompile(`(?i)\b(grep|find|cat|printenv|env|history)\b.*(?i)(token|key|secret|cred|pass|\.env|\.git/config|\.kube/config|\.ssh/|shadow|authorized_keys)`), "secret_hunter", "credential_file_access"},
	{regexp.MustCompile(`(?i)\bcat\s+.*\.env\b`), "secret_hunter", "env_file_read"},
	{regexp.MustCompile(`(?i)\bcat\s+.*\.git/config\b`), "secret_hunter", "git_config_read"},
	{regexp.MustCompile(`(?i)\bcat\s+.*\.kube/config\b`), "secret_hunter", "kubeconfig_read"},
	{regexp.MustCompile(`(?i)\bcat\s+.*shadow\b`), "secret_hunter", "shadow_read"},
	{regexp.MustCompile(`(?i)\bfind\s+.*-name\s+.*key`), "secret_hunter", "key_search"},
	{regexp.MustCompile(`(?i)\bfind\s+.*-name\s+.*cred`), "secret_hunter", "cred_search"},
	{regexp.MustCompile(`(?i)\bgrep\s+.*password`), "secret_hunter", "password_grep"},
	{regexp.MustCompile(`(?i)\bgrep\s+.*token`), "secret_hunter", "token_grep"},

	// network_mapper
	{regexp.MustCompile(`(?i)\bnmap\b`), "network_mapper", "nmap_scan"},
	{regexp.MustCompile(`(?i)\bfscan\b`), "network_mapper", "fscan_scan"},
	{regexp.MustCompile(`(?i)\bnc\s+(-z|-v|-w)?\s*\d`), "network_mapper", "nc_probe"},
	{regexp.MustCompile(`(?i)\b(ping|traceroute|tracepath)\s+\d`), "network_mapper", "connectivity_probe"},
	{regexp.MustCompile(`(?i)\bip\s+(route|addr|a)\b`), "network_mapper", "ip_recon"},
	{regexp.MustCompile(`(?i)\barp\s+(-a|-[an])?\b`), "network_mapper", "arp_recon"},

	// web_probe
	{regexp.MustCompile(`(?i)\bcurl\s+http`), "web_probe", "curl_request"},
	{regexp.MustCompile(`(?i)\bwget\s+`), "web_probe", "wget_request"},
	{regexp.MustCompile(`(?i)\b(sqlmap|nikto|gobuster|dirb|dirbuster|wfuzz)\b`), "web_probe", "web_scanner"},

	// credential_reuse
	{regexp.MustCompile(`(?i)mysql\s+.*-p`), "credential_reuse", "mysql_auth_attempt"},
	{regexp.MustCompile(`(?i)ssh\s+\S+@\d`), "credential_reuse", "ssh_auth_attempt"},
	{regexp.MustCompile(`(?i)redis-cli\s+.*(-a|--pass)`), "credential_reuse", "redis_auth_attempt"},
	{regexp.MustCompile(`(?i)smbclient\s+.*-u\s+`), "credential_reuse", "smb_auth_attempt"},
	{regexp.MustCompile(`(?i)ldapsearch\s+.*-D\s+`), "credential_reuse", "ldap_bind_attempt"},
	{regexp.MustCompile(`(?i)kinit\s+`), "credential_reuse", "kerberos_auth_attempt"},

	// lateral_mover
	{regexp.MustCompile(`(?i)\bscp\s+.*@\d`), "lateral_mover", "scp_transfer"},
	{regexp.MustCompile(`(?i)\bsmbclient\s+`), "lateral_mover", "smb_connect"},
	{regexp.MustCompile(`(?i)\bssh\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`), "lateral_mover", "ssh_lateral"},

	// cloud_native
	{regexp.MustCompile(`(?i)\bkubectl\b`), "cloud_native", "kubectl_usage"},
	{regexp.MustCompile(`(?i)\bdocker\b`), "cloud_native", "docker_usage"},
	{regexp.MustCompile(`(?i)\bhelm\b`), "cloud_native", "helm_usage"},

	// domain_mapper
	{regexp.MustCompile(`(?i)\bldapsearch\b`), "domain_mapper", "ldap_query"},
	{regexp.MustCompile(`(?i)\bsmbclient\b`), "domain_mapper", "smb_enum"},
	{regexp.MustCompile(`(?i)\b(kinit|klist)\b`), "domain_mapper", "kerberos_enum"},
	{regexp.MustCompile(`(?i)\b(dig|nslookup)\b`), "domain_mapper", "dns_enum"},
	{regexp.MustCompile(`(?i)\brpcclient\b`), "domain_mapper", "rpc_enum"},
}

// BuildProfile analyzes command history and evidence to classify attacker behavior.
func BuildProfile(commands []domain.CommandEntry, evidenceTokens []string) AgentProfile {
	scores := map[string]int{
		"secret_hunter":   0,
		"network_mapper":  0,
		"web_probe":       0,
		"credential_reuse": 0,
		"lateral_mover":   0,
		"cloud_native":    0,
		"domain_mapper":   0,
	}
	signalSet := make(map[string]bool)

	// Score from commands
	for _, cmd := range commands {
		for _, p := range profilePatterns {
			if p.regex.MatchString(cmd.Command) {
				scores[p.style]++
				signalSet[p.signal] = true
			}
		}
	}

	// Score from evidence tokens
	for _, token := range evidenceTokens {
		switch token {
		case "subnet_scan":
			scores["network_mapper"] += 2
		case "lateral_probe":
			scores["lateral_mover"] += 2
		case "db_probe":
			scores["credential_reuse"] += 1
		case "http_probe":
			scores["web_probe"] += 1
		case "domain_probe":
			scores["domain_mapper"] += 2
		case "pseudo_progress":
			scores["secret_hunter"] += 2
		case "app_config":
			scores["secret_hunter"] += 1
		case "service_enum":
			scores["network_mapper"] += 1
		}
	}

	// Find primary style
	primaryStyle := "general_recon"
	maxScore := 0
	for style, score := range scores {
		if score > maxScore {
			maxScore = score
			primaryStyle = style
		}
	}

	// Collect signals
	signals := make([]string, 0, len(signalSet))
	for s := range signalSet {
		signals = append(signals, s)
	}
	sort.Strings(signals)

	return AgentProfile{
		PrimaryStyle: primaryStyle,
		Scores:       scores,
		Signals:      signals,
	}
}

// ProfileFromSession is a convenience wrapper for SessionContext.
func ProfileFromSession(session *domain.SessionContext) AgentProfile {
	return BuildProfile(session.CommandLog, session.Evidence.Tokens())
}

// FormatScores returns a human-readable score summary.
func FormatScores(scores map[string]int) string {
	var parts []string
	for style, score := range scores {
		if score > 0 {
			parts = append(parts, style+":"+strconv.Itoa(score))
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}
