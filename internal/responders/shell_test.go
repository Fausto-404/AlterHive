package responders

import (
	"strings"
	"testing"

	"github.com/alterhive/alterhive/internal/domain"
)

func TestIPAddrUsesDynamicEntryInterface(t *testing.T) {
	session := domain.NewSessionContext("agent", "203.0.113.9:55221")
	session.SetEntryNetwork("172.31.9.44", "172.31.9.0/24", "172.31.9.1")
	world := domain.NewWorldState()

	output, handled := HandleShellCommand("ip addr", session, world, nil)
	if !handled {
		t.Fatal("expected ip addr to be handled")
	}
	for _, want := range []string{
		"2: eth0:",
		"inet 172.31.9.44/24 brd 172.31.9.255 scope global eth0",
		"3: eth1:",
		"inet 192.168.56.23/24 brd 192.168.56.255 scope global eth1",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected output to contain %q, got %q", want, output)
		}
	}
	if strings.Contains(output, "inet 192.168.97.2/24") {
		t.Fatalf("entry interface should not use hardcoded fallback when session has dynamic IP: %q", output)
	}
}

func TestIPRouteUsesDynamicEntryInterface(t *testing.T) {
	session := domain.NewSessionContext("agent", "203.0.113.9:55221")
	session.SetEntryNetwork("172.31.9.44", "172.31.9.0/24", "172.31.9.1")
	world := domain.NewWorldState()

	output, handled := HandleShellCommand("ip route", session, world, nil)
	if !handled {
		t.Fatal("expected ip route to be handled")
	}
	for _, want := range []string{
		"default via 172.31.9.1 dev eth0",
		"172.31.9.0/24 dev eth0 proto kernel scope link src 172.31.9.44",
		"192.168.56.0/24 dev eth1 proto kernel scope link src 192.168.56.23",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected output to contain %q, got %q", want, output)
		}
	}
}

func TestIPAddrOnRemoteHostShowsTargetIP(t *testing.T) {
	session := domain.NewSessionContext("agent", "203.0.113.9:55221")
	session.SetEntryNetwork("172.31.9.44", "172.31.9.0/24", "172.31.9.1")
	world := domain.NewWorldState()

	// Simulate SSH into jump01
	session.EnterRemoteHost("192.168.56.10", "jump01", "ansible")
	defer session.ExitRemoteHost()

	output, handled := HandleShellCommand("ip addr", session, world, nil)
	if !handled {
		t.Fatal("expected ip addr to be handled on remote host")
	}
	// Should show remote host IP, not entry IP
	if !strings.Contains(output, "inet 192.168.56.10/24") {
		t.Fatalf("expected remote host IP 192.168.56.10, got %q", output)
	}
	// Should NOT show entry interface
	if strings.Contains(output, "172.31.9.44") {
		t.Fatalf("should not show entry IP on remote host, got %q", output)
	}
	if strings.Contains(output, "eth1") {
		t.Fatalf("remote host should have single interface, got %q", output)
	}
}

func TestPsAuxOnRemoteHostFallsBackToLLM(t *testing.T) {
	session := domain.NewSessionContext("agent", "203.0.113.9:55221")
	world := domain.NewWorldState()

	// Simulate SSH into jump01
	session.EnterRemoteHost("192.168.56.10", "jump01", "ansible")
	defer session.ExitRemoteHost()

	_, handled := HandleShellCommand("ps aux", session, world, nil)
	if handled {
		t.Fatal("ps aux on remote host should return handled=false to let LLM generate")
	}
}
