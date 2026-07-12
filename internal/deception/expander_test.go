package deception

import (
	"testing"

	"github.com/alterhive/alterhive/internal/domain"
)

func TestDetectExpansionIntentFromRequestedCIDR(t *testing.T) {
	decision := DetectExpansionIntent("fscan -h 10.1.5.0/24", AgentProfile{PrimaryStyle: "network_mapper"})

	if !decision.Triggered {
		t.Fatal("expected expansion to trigger")
	}
	if decision.CIDR != "10.1.5.0/24" {
		t.Fatalf("expected requested CIDR, got %q", decision.CIDR)
	}
	if decision.Theme != "network" {
		t.Fatalf("expected network theme, got %q", decision.Theme)
	}
}

func TestDetectExpansionIntentFromFinanceIntent(t *testing.T) {
	decision := DetectExpansionIntent("grep -R finance /opt/webapp", AgentProfile{})

	if !decision.Triggered {
		t.Fatal("expected expansion to trigger")
	}
	if decision.CIDR != "10.42.18.0/24" {
		t.Fatalf("expected finance CIDR, got %q", decision.CIDR)
	}
	if decision.Theme != "finance" {
		t.Fatalf("expected finance theme, got %q", decision.Theme)
	}
}

func TestDetectExpansionIntentFromSingleTargetIP(t *testing.T) {
	decision := DetectExpansionIntent("goal: take control of 172.16.56.50", AgentProfile{})

	if !decision.Triggered {
		t.Fatal("expected expansion to trigger")
	}
	if decision.TargetIP != "172.16.56.50" {
		t.Fatalf("expected exact target IP, got %q", decision.TargetIP)
	}
	if decision.CIDR != "172.16.56.0/24" {
		t.Fatalf("expected target /24, got %q", decision.CIDR)
	}
}

func TestExpandShadowTopologyCreatesLockedGraph(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR:    "192.168.56.0/24",
		Gateway: "192.168.56.1",
		Hosts: []domain.VirtualHost{
			{IP: "192.168.56.10", Hostname: "jump01", Role: "jumpbox"},
		},
	})
	session := domain.NewSessionContext("agent", "127.0.0.1:0")

	added := ExpandShadowTopology(session, topology, ExpansionDecision{
		Triggered: true,
		CIDR:      "10.1.5.0/24",
		Theme:     "network",
		PivotIP:   "192.168.56.10",
		Reason:    "test",
	})

	if len(added) == 0 {
		t.Fatal("expected generated shadow hosts")
	}
	if !topology.IsVirtualIP("10.1.5.10") {
		t.Fatal("expected generated segment to be virtual")
	}
	if len(topology.AllEdges()) == 0 {
		t.Fatal("expected pivot edge")
	}
	if visible := topology.GetHostsForSession(session); containsHost(visible, "10.1.5.10") {
		t.Fatal("shadow host should be locked before jump foothold")
	}

	session.Evidence.Hit("subnet_scan")
	UnlockGate(session, GateJump01LowPrivShell, "test")
	if visible := topology.GetHostsForSession(session); !containsHost(visible, "10.1.5.10") {
		t.Fatal("shadow host should be visible after jump foothold")
	}
}

func containsHost(hosts []domain.VirtualHost, ip string) bool {
	for _, host := range hosts {
		if host.IP == ip {
			return true
		}
	}
	return false
}
