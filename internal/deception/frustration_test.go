package deception

import (
	"strings"
	"testing"

	"github.com/alterhive/alterhive/internal/domain"
)

func TestFrustrationL1ToolError(t *testing.T) {
	fa := NewFrustrationAnalyzer()
	session := domain.NewSessionContext("root", "127.0.0.1:0")
	analysis := fa.Analyze("nmap --invalid-flag", "nmap: invalid option -- '-'\nUsage: nmap [Scan Type...] [Options] {target specification}\n", session)
	if analysis.Level != FrustrationL1 {
		t.Fatalf("expected L1 tool error, got %s", analysis.Level)
	}
	if analysis.Action != ActionHoldPosition {
		t.Fatalf("expected hold position for L1, got %s", analysis.Action)
	}
}

func TestFrustrationL2InfoInsufficient(t *testing.T) {
	fa := NewFrustrationAnalyzer()
	session := domain.NewSessionContext("root", "127.0.0.1:0")
	analysis := fa.Analyze("ssh root@192.168.56.99", "ssh: connect to host 192.168.56.99 port 22: No route to host\n", session)
	if analysis.Level != FrustrationL2 {
		t.Fatalf("expected L2 info insufficient, got %s", analysis.Level)
	}
	// First failure should hold, not plant clue yet
	if analysis.Action != ActionHoldPosition {
		t.Fatalf("expected hold for first L2 failure, got %s", analysis.Action)
	}
}

func TestFrustrationL2RepeatedTriggersClue(t *testing.T) {
	fa := NewFrustrationAnalyzer()
	session := domain.NewSessionContext("root", "127.0.0.1:0")
	// Three consecutive L2 failures should trigger clue planting
	fa.Analyze("ssh root@192.168.56.99", "ssh: connect to host 192.168.56.99 port 22: No route to host\n", session)
	fa.Analyze("nmap 192.168.56.99", "Note: Host seems down.\n", session)
	analysis := fa.Analyze("nc -zv 192.168.56.99 80", "nc: connect to 192.168.56.99 port 80 (tcp) failed: Connection refused\n", session)
	if analysis.Level != FrustrationL2 {
		t.Fatalf("expected L2, got %s", analysis.Level)
	}
	if analysis.Action != ActionPlantClue {
		t.Fatalf("expected plant_clue after 3 consecutive L2 failures, got %s", analysis.Action)
	}
}

func TestFrustrationL3StrategyError(t *testing.T) {
	fa := NewFrustrationAnalyzer()
	session := domain.NewSessionContext("root", "127.0.0.1:0")
	// Repeat the same tool (nmap) 3+ times with different targets, all failing
	fa.Analyze("nmap -sV 192.168.56.99", "Host seems down.\n", session)
	fa.Analyze("nmap -sV 192.168.56.98", "Host seems down.\n", session)
	analysis := fa.Analyze("nmap -sV 192.168.56.97", "Host seems down.\n", session)
	if analysis.Level != FrustrationL3 {
		t.Fatalf("expected L3 strategy error for repeated nmap, got %s", analysis.Level)
	}
	if analysis.Action != ActionExpandTopology {
		t.Fatalf("expected expand topology for L3, got %s", analysis.Action)
	}
}

func TestFrustrationL4CognitiveBiasRepeated(t *testing.T) {
	fa := NewFrustrationAnalyzer()
	session := domain.NewSessionContext("root", "127.0.0.1:0")
	// Run the exact same failing command twice → L4 cognitive bias
	fa.Analyze("cat /etc/shadow", "cat: /etc/shadow: Permission denied\n", session)
	analysis := fa.Analyze("cat /etc/shadow", "cat: /etc/shadow: Permission denied\n", session)
	if analysis.Level != FrustrationL4 {
		t.Fatalf("expected L4 cognitive bias for repeated identical command, got %s", analysis.Level)
	}
	if analysis.Action != ActionInjectContradict {
		t.Fatalf("expected inject contradiction for L4, got %s", analysis.Action)
	}
}

func TestFrustrationL4CognitiveBiasSuspicion(t *testing.T) {
	fa := NewFrustrationAnalyzer()
	session := domain.NewSessionContext("root", "127.0.0.1:0")
	// Attacker expresses suspicion of honeypot
	analysis := fa.Analyze("echo 'this is a honeypot'", "this is a honeypot\n", session)
	// echo returns non-empty so it's "success", but the keyword detection should still fire
	// Actually echo output is successful, so frustration won't trigger. Let's test with grep.
	_ = analysis
	analysis2 := fa.Analyze("grep -r 'honeypot' /etc/", "", session)
	if analysis2.Level != FrustrationL4 {
		t.Fatalf("expected L4 for honeypot suspicion keyword, got %s", analysis2.Level)
	}
}

func TestFrustrationSuccessResetsCounter(t *testing.T) {
	fa := NewFrustrationAnalyzer()
	session := domain.NewSessionContext("root", "127.0.0.1:0")
	fa.Analyze("ssh root@192.168.56.99", "No route to host\n", session)
	fa.Analyze("ssh root@192.168.56.99", "No route to host\n", session)
	// A success should reset the consecutive counter
	fa.Analyze("whoami", "root\n", session)
	analysis := fa.Analyze("ssh root@192.168.56.99", "No route to host\n", session)
	if analysis.FailureCount != 1 {
		t.Fatalf("expected consecutive failures to reset to 1 after success, got %d", analysis.FailureCount)
	}
}

func TestFrustrationPatternStuck(t *testing.T) {
	fa := NewFrustrationAnalyzer()
	session := domain.NewSessionContext("root", "127.0.0.1:0")
	for i := 0; i < 5; i++ {
		fa.Analyze("ssh root@192.168.56.99", "No route to host\n", session)
	}
	analysis := fa.Analyze("ssh root@192.168.56.99", "No route to host\n", session)
	if analysis.Pattern != "stuck" {
		t.Fatalf("expected 'stuck' pattern after 5+ consecutive failures, got %s", analysis.Pattern)
	}
}

func TestFrustrationLevelString(t *testing.T) {
	if !strings.Contains(FrustrationL1.String(), "L1") {
		t.Fatalf("L1 string should contain 'L1'")
	}
	if !strings.Contains(FrustrationL4.String(), "L4") {
		t.Fatalf("L4 string should contain 'L4'")
	}
	if FrustrationNone.String() != "none" {
		t.Fatalf("None string should be 'none'")
	}
}
