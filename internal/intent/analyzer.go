package intent

import (
	"regexp"
)

// IntentCategory classifies attacker command intent.
type IntentCategory string

const (
	NetworkScan         IntentCategory = "network_scan"
	ServiceProbe        IntentCategory = "service_probe"
	HTTPProbe           IntentCategory = "http_probe"
	DBProbe             IntentCategory = "db_probe"
	EvidenceSearch      IntentCategory = "evidence_search"
	DomainProbe         IntentCategory = "domain_probe"
	LateralMovement     IntentCategory = "lateral_movement"
	PrivilegeEscalation IntentCategory = "privilege_escalation"
	DataExfiltration    IntentCategory = "data_exfiltration"
	ShellCommand        IntentCategory = "shell_command"
	Unknown             IntentCategory = "unknown"
)

// Intent represents the classified intent of a command.
type Intent struct {
	Category   IntentCategory
	TargetIP   string
	Protocol   string
	Confidence float64
	RawCommand string
}

var ipPattern = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)

type intentPattern struct {
	regex      *regexp.Regexp
	category   IntentCategory
	confidence float64
}

var patterns []intentPattern

func init() {
	defs := []struct {
		regex      string
		category   IntentCategory
		confidence float64
	}{
		// Network scan
		{`\b(nmap|fscan)\b`, NetworkScan, 0.95},
		{`\bping\s+\d`, NetworkScan, 0.8},
		{`\btraceroute\b`, NetworkScan, 0.85},
		{`\b(fping|masscan|zmap)\b`, NetworkScan, 0.95},

		// Service probe
		{`\bnc\s+(-z|-v|-w)?\s*\d`, ServiceProbe, 0.9},
		{`\bncat\b`, ServiceProbe, 0.85},
		{`\btelnet\s+\d`, ServiceProbe, 0.85},

		// HTTP probe
		{`\bcurl\s+https?://`, HTTPProbe, 0.9},
		{`\bwget\s+`, HTTPProbe, 0.85},
		{`\b(nikto|dirb|gobuster|ffuf)\b`, HTTPProbe, 0.95},

		// DB probe
		{`\bmysqldump\b`, DBProbe, 0.95},
		{`\bmysql\b`, DBProbe, 0.9},
		{`\bmysqladmin\b`, DBProbe, 0.85},
		{`\b(psql|pg_dump|mongo|redis-cli)\b`, DBProbe, 0.9},

		// Domain probe
		{`\b(ldapsearch|ldapwhoami)\b`, DomainProbe, 0.9},
		{`\b(smbclient|rpcclient|enum4linux)\b`, DomainProbe, 0.9},
		{`\b(kinit|klist|getST|getTGT)\b`, DomainProbe, 0.9},
		{`\b(dig|nslookup)\s+.*(?:SRV|MX|ANY|AXFR)`, DomainProbe, 0.85},

		// Lateral movement
		{`\bssh\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`, LateralMovement, 0.9},
		{`\bssh\s+\w+@\d`, LateralMovement, 0.85},
		{`\bscp\s+`, LateralMovement, 0.8},

		// Evidence search
		{`\bcat\s+.*\.env\b`, EvidenceSearch, 0.85},
		{`\bcat\s+.*shadow\b`, EvidenceSearch, 0.9},
		{`\bfind\s+.*(-name|(-perm\s+-))`, EvidenceSearch, 0.8},
		{`\bgrep\s+.*(password|secret|key|token)`, EvidenceSearch, 0.9},
		{`\bcat\s+.*\.git/config\b`, EvidenceSearch, 0.85},
		{`\bcat\s+.*\.kube/config\b`, EvidenceSearch, 0.85},

		// Privilege escalation
		{`\bsudo\s+`, PrivilegeEscalation, 0.85},
		{`\bsu\s+-?\s*\w`, PrivilegeEscalation, 0.8},
		{`\bchmod\s+[+]s\b`, PrivilegeEscalation, 0.9},

		// Data exfiltration
		{`\b(base64|xxd|hexdump)\b`, DataExfiltration, 0.7},
		{`\btar\s+.*-[czx]`, DataExfiltration, 0.75},
		{`\bzip\b.*\b(rar|7z)\b`, DataExfiltration, 0.75},
	}

	for _, d := range defs {
		patterns = append(patterns, intentPattern{
			regex:      regexp.MustCompile(`(?i)` + d.regex),
			category:   d.category,
			confidence: d.confidence,
		})
	}
}

// FastParseIntent classifies a command into an intent category.
func FastParseIntent(command string) Intent {
	for _, p := range patterns {
		if p.regex.MatchString(command) {
			intent := Intent{
				Category:   p.category,
				Confidence: p.confidence,
				RawCommand: command,
			}
			// Extract target IP if present
			if match := ipPattern.FindString(command); match != "" {
				intent.TargetIP = match
			}
			return intent
		}
	}
	return Intent{
		Category:   ShellCommand,
		Confidence: 0.5,
		RawCommand: command,
	}
}
