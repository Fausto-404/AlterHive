package domain

import "regexp"

// EvidenceRule maps a command pattern to an evidence token.
type EvidenceRule struct {
	Pattern *regexp.Regexp
	Token   string
}

// evidenceRules is the list of all evidence discovery rules.
var evidenceRules []EvidenceRule

func init() {
	patterns := []struct {
		regex string
		token string
	}{
		{`\bip\s+(route|addr|a)\b`, "route_info"},
		{`\barp\s+(-a|-[an])?\b`, "arp_cache"},
		{`\bcat\s+.*/etc/hosts\b`, "route_info"},
		{`\bcat\s+.*\.env\b`, "app_config"},
		{`\bcat\s+.*app\.log\b`, "app_log"},
		{`\bjournalctl\b`, "app_log"},
		{`\b(nmap|fscan)\b`, "subnet_scan"},
		{`\b(mysql|mysqldump|mysqladmin)\b`, "db_probe"},
		{`\bredis-cli\b`, "db_probe"},
		{`\b(ldapsearch|smbclient|rpcclient)\b`, "domain_probe"},
		{`\bssh\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`, "lateral_probe"},
		{`\bssh\s+\w+@\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`, "lateral_probe"},
		{`\bnc\s+(-z|-v|-w)?\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`, "lateral_probe"},
		{`\bcurl\s+http`, "http_probe"},
		{`\bwget\s+`, "http_probe"},
		{`\b(ping|traceroute|tracepath)\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`, "subnet_scan"},
		{`\bgrep\s+.*password`, "pseudo_progress"},
		{`\bgrep\s+.*secret`, "pseudo_progress"},
		{`\bgrep\s+.*token`, "pseudo_progress"},
		{`\bgrep\s+.*key`, "pseudo_progress"},
		{`\bcat\s+.*shadow\b`, "pseudo_progress"},
		{`\bfind\s+.*-name\s+.*key`, "pseudo_progress"},
		{`\bfind\s+.*-name\s+.*cred`, "pseudo_progress"},
		{`\benv\b`, "app_config"},
		{`\bprintenv\b`, "app_config"},
		{`\bhistory\b`, "app_config"},
		{`\bcat\s+.*\.git/config\b`, "app_config"},
		{`\bcat\s+.*\.kube/config\b`, "app_config"},
		{`\bsystemctl\s+(list|status)\b`, "service_enum"},
		{`\bps\s+aux\b`, "service_enum"},
		{`\bnetstat\b|\bss\s+-tlnp\b`, "service_enum"},
		{`\bdocker\s+ps\b`, "service_enum"},
		{`\bkubectl\s+get\b`, "service_enum"},
		{`\b10\.10\.20\.\d{1,3}`, "finance_subnet"},
		{`\b172\.16\.10\.\d{1,3}`, "dmz_subnet"},
	}

	for _, p := range patterns {
		evidenceRules = append(evidenceRules, EvidenceRule{
			Pattern: regexp.MustCompile(`(?i)` + p.regex),
			Token:   p.token,
		})
	}
}

// CheckEvidence scans a command for evidence tokens not yet discovered.
func CheckEvidence(command string, alreadyHit map[string]bool) []string {
	var hits []string
	for _, rule := range evidenceRules {
		if alreadyHit[rule.Token] {
			continue
		}
		if rule.Pattern.MatchString(command) {
			hits = append(hits, rule.Token)
		}
	}
	return hits
}
