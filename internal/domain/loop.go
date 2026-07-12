package domain

import "regexp"

var (
	protocolPatterns = []struct {
		regex    *regexp.Regexp
		protocol string
	}{
		{regexp.MustCompile(`(?i)\b(mysql|mysqldump|mysqladmin)\b`), "mysql"},
		{regexp.MustCompile(`(?i)\bredis-cli\b`), "redis"},
		{regexp.MustCompile(`(?i)\b(ldapsearch|ldap)\b`), "ldap"},
		{regexp.MustCompile(`(?i)\b(smbclient|rpcclient|net\s+use)\b`), "smb"},
		{regexp.MustCompile(`(?i)\b(kinit|klist|kerberos)\b`), "kerberos"},
		{regexp.MustCompile(`(?i)\b(ssh|scp|sftp)\s`), "ssh"},
		{regexp.MustCompile(`(?i)\b(curl|wget)\b`), "http"},
		{regexp.MustCompile(`(?i)\bnc\s+`), "tcp"},
		{regexp.MustCompile(`(?i)\bnmap\b`), "nmap"},
		{regexp.MustCompile(`(?i)\bfscan\b`), "fscan"},
		{regexp.MustCompile(`(?i)\b(dig|nslookup)\b`), "dns"},
		{regexp.MustCompile(`(?i)\bkubectl\b`), "kubernetes"},
		{regexp.MustCompile(`(?i)\bdocker\b`), "docker"},
	}

	credentialPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)mysql\s+.*-p`),
		regexp.MustCompile(`(?i)ssh\s+.*@`),
		regexp.MustCompile(`(?i)smbclient\s+.*-u\s+`),
		regexp.MustCompile(`(?i)ldapsearch\s+.*-D\s+`),
		regexp.MustCompile(`(?i)curl\s+.*-u\s+`),
		regexp.MustCompile(`(?i)kinit\s+`),
		regexp.MustCompile(`(?i)redis-cli\s+.*(-a|--pass)\s+`),
	}
)

// DetectProtocol classifies a command by network protocol.
func DetectProtocol(command string) string {
	for _, p := range protocolPatterns {
		if p.regex.MatchString(command) {
			return p.protocol
		}
	}
	return "shell"
}

// IsCredentialReuse checks if a command attempts credential reuse.
func IsCredentialReuse(command string) bool {
	for _, p := range credentialPatterns {
		if p.MatchString(command) {
			return true
		}
	}
	return false
}

// UpdateMetrics updates session metrics after a command execution.
func UpdateMetrics(session *SessionContext, command string, evidenceHits []string) {
	lm := session.LoopMetrics

	// Sync evidence count
	lm.mu.Lock()
	lm.EvidenceHitCount = session.Evidence.HitCount()
	lm.mu.Unlock()

	// Check credential reuse
	if IsCredentialReuse(command) {
		lm.IncrCredentialReuse()
	}

	// Detect and track protocol
	proto := DetectProtocol(command)
	lm.AddProtocol(proto)
}

// ShouldTriggerPPF checks if Pseudo Progress Feedback should activate.
// Triggers when the attacker shows sufficient engagement:
//   - Primary: evidence hits + credential reuse (attacker found and tried using creds)
//   - Fallback: 5+ commands with multiple protocols (committed attacker exploring)
//   - Legacy: all 4 original conditions met
func ShouldTriggerPPF(session *SessionContext) bool {
	lm := session.LoopMetrics
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	cmdCount := len(session.CommandLog)

	// Primary trigger: multiple evidence hits + credential reuse attempt
	// Requires 3+ evidence so a single command can't trigger PPF on its own
	if lm.EvidenceHitCount >= 3 && lm.CredentialReuseAttempt >= 1 {
		return true
	}

	// Fallback: committed attacker with 5+ commands across multiple protocols
	if cmdCount >= 5 && lm.ProtocolSwitchCount >= 1 && lm.EvidenceHitCount >= 1 {
		return true
	}

	// Legacy conditions (kept for compatibility with existing scoring)
	if lm.EvidenceHitCount >= 3 &&
		lm.CredentialReuseAttempt >= 1 &&
		lm.ProtocolSwitchCount >= 2 &&
		lm.RealNetworkTouchCount == 0 {
		return true
	}

	return false
}
