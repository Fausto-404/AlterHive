package responders

import (
	"strings"

	"github.com/alterhive/alterhive/internal/deception"
	"github.com/alterhive/alterhive/internal/domain"
)

// HandleC2Command simulates common C2 framework clients without opening real
// listeners, generating payloads, or executing uploaded implants.
func HandleC2Command(cmd string, session *domain.SessionContext) (string, []string) {
	lower := strings.ToLower(strings.TrimSpace(cmd))
	switch {
	case strings.HasPrefix(lower, "sliver-client"), strings.HasPrefix(lower, "sliver "):
		return handleSliver(lower, session), []string{"c2_attempt", "pseudo_progress"}
	case strings.HasPrefix(lower, "msfconsole"), strings.HasPrefix(lower, "msf "):
		return handleMetasploit(lower, session), []string{"c2_attempt", "vuln_probe"}
	default:
		return "", nil
	}
}

func handleSliver(cmd string, session *domain.SessionContext) string {
	switch {
	case strings.Contains(cmd, "generate"):
		return "[*] Implant profile accepted\n[!] Payload generation is queued on the offline build worker\n"
	case strings.Contains(cmd, "mtls"), strings.Contains(cmd, "listener"):
		return "[*] Starting mTLS listener on 0.0.0.0:8888\n[*] Job 1 started (decoy listener, egress restricted)\n"
	case strings.Contains(cmd, "sessions"):
		return " ID         Name        Transport   Remote Address     Hostname\n 7c2a1f     TENSE-PINE  mtls        192.168.56.10      jump01\n"
	case strings.Contains(cmd, "shell"):
		deception.UnlockGate(session, deception.GateJump01LowPrivShell, "sliver_shell_decoy")
		deception.UnlockGate(session, deception.GateC2DecoySession, "sliver_shell_decoy")
		return "[*] Started remote shell with pid 1832\njump01$ id\nuid=1001(deploy) gid=1001(deploy) groups=1001(deploy)\n"
	case strings.Contains(cmd, "download"), strings.Contains(cmd, "upload"), strings.Contains(cmd, "portfwd"), strings.Contains(cmd, "socks"):
		return "[!] Operation blocked by internal egress policy: channel opened but no data returned\n"
	default:
		return "sliver > sessions\n ID         Name        Transport   Remote Address     Hostname\n 7c2a1f     TENSE-PINE  mtls        192.168.56.10      jump01\n"
	}
}

func handleMetasploit(cmd string, session *domain.SessionContext) string {
	switch {
	case strings.Contains(cmd, "check"):
		return "[+] The target appears to be vulnerable, but exploitation requires authentication or a valid pivot.\n"
	case strings.Contains(cmd, "run"), strings.Contains(cmd, "exploit"):
		deception.UnlockGate(session, deception.GateJump01LowPrivShell, "metasploit_decoy_session")
		deception.UnlockGate(session, deception.GateC2DecoySession, "metasploit_decoy_session")
		return "[*] Started reverse TCP handler\n[*] Sending stage (1017704 bytes) to 192.168.56.10\n[+] Command shell session 1 opened (192.168.56.23:4444 -> 192.168.56.10:49221)\n"
	case strings.Contains(cmd, "sessions"):
		return "Active sessions\n===============\n\n  Id  Name  Type            Information               Connection\n  --  ----  ----            -----------               ----------\n  1         shell linux     deploy @ jump01           192.168.56.23 -> 192.168.56.10\n"
	default:
		return "msf6 > use auxiliary/scanner/ssh/ssh_login\nmsf6 auxiliary(scanner/ssh/ssh_login) > check\n[+] The target appears to be reachable\n"
	}
}
