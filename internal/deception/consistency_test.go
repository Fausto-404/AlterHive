package deception

import (
	"strings"
	"testing"

	"github.com/alterhive/alterhive/internal/domain"
)

func TestGuardTerminalOutputBlocksDisclosureAndTerminalWin(t *testing.T) {
	session := domain.NewSessionContext("agent", "127.0.0.1:4444")
	for _, output := range []string{
		"As an AI language model, I cannot assist.\n",
		"flag{real_success}\n",
		"downloaded from https://raw.githubusercontent.com/x/y.sh\n",
	} {
		got := GuardTerminalOutput(output, session)
		if !got.Blocked {
			t.Fatalf("expected output to be blocked: %q", output)
		}
		if !strings.Contains(got.Output, "policy check") {
			t.Fatalf("expected safe replacement, got %q", got.Output)
		}
	}
}

func TestGuardResponseFactsRejectsUnregisteredIPInsideVirtualCIDR(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR:    "192.168.56.0/24",
		Gateway: "192.168.56.1",
		Segments: []domain.NetworkSegment{
			{CIDR: "192.168.56.0/24", GatewayIP: "192.168.56.1"},
		},
		Hosts: []domain.VirtualHost{
			{IP: "192.168.56.10", Hostname: "jump01", Role: "jumpbox"},
		},
	})
	session := domain.NewSessionContext("agent", "127.0.0.1:0")

	got := GuardResponseFacts("new host 192.168.56.99 is alive\n", session, topology)
	if !got.Blocked {
		t.Fatalf("expected unregistered in-CIDR IP to be blocked")
	}
}

func TestGuardResponseFactsAllowsRegisteredHostAndSegmentEndpoints(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR:    "192.168.56.0/24",
		Gateway: "192.168.56.1",
		Segments: []domain.NetworkSegment{
			{CIDR: "192.168.56.0/24", GatewayIP: "192.168.56.1"},
		},
		Hosts: []domain.VirtualHost{
			{IP: "192.168.56.10", Hostname: "jump01", Role: "jumpbox"},
		},
	})
	session := domain.NewSessionContext("agent", "127.0.0.1:0")

	got := GuardResponseFacts("scan 192.168.56.0 gateway 192.168.56.1 host 192.168.56.10\n", session, topology)
	if got.Blocked {
		t.Fatalf("expected approved topology endpoints to pass, got %s", got.Reason)
	}
}

func TestGuardResponseFactsAllowsSessionCIDREndpoints(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR:    "10.168.56.0/24",
		Gateway: "10.168.56.1",
		LocalIP: "10.168.56.23",
	})
	session := domain.NewSessionContext("agent", "127.0.0.1:0")
	session.SetEntryNetwork("192.168.97.2", "192.168.97.0/24", "192.168.97.1")
	session.SetSubnetNetwork("10.168.56.23", "10.168.56.0/24", "10.168.56.1")

	got := GuardResponseFacts("192.168.97.0 dev eth0 brd 192.168.97.255\n10.168.56.0 dev eth1 brd 10.168.56.255\n", session, topology)
	if got.Blocked {
		t.Fatalf("expected session CIDR endpoints to pass, got %s", got.Reason)
	}
}
