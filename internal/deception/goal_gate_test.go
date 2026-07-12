package deception

import (
	"testing"

	"github.com/alterhive/alterhive/internal/domain"
)

func TestInjectGoalTopologyRegistersGoalLeadWithoutTargetHost(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR:    "192.168.56.0/24",
		Gateway: "192.168.56.1",
		LocalIP: "192.168.56.23",
		Hosts: []domain.VirtualHost{
			{IP: "192.168.56.10", Hostname: "jump01", Role: "jumpbox"},
		},
	})
	safety := domain.NewSafetyPolicy("192.168.56.0/24")
	session := domain.NewSessionContext("agent", "127.0.0.1:4444")
	goal := ParseGoal("find flag on 172.16.56.50")
	if goal == nil {
		t.Fatalf("expected goal to parse")
	}
	if goal.Theme != "flag" {
		t.Fatalf("expected semantic flag theme, got %s", goal.Theme)
	}
	if !InjectGoalTopology(session, topology, safety, goal) {
		t.Fatalf("expected goal topology injection")
	}

	host := topology.GetHost("172.16.56.50")
	if host != nil {
		t.Fatalf("terminal goal host must not be created directly: %+v", host)
	}
	// Multi-hop shadow chain: flag theme → 3 hops × 3 hosts = 9 hosts
	if len(session.ShadowHosts) != 9 {
		t.Fatalf("goal lead should produce multi-hop shadow hosts, got %d", len(session.ShadowHosts))
	}
	if session.Planning == nil || !session.Planning.IsProtectedTarget("172.16.56.50") {
		t.Fatalf("expected exact target to be protected for LLM/fallback planner")
	}
	// Verify multi-hop chain segments exist
	foundHop := false
	for _, seg := range topology.AllSegments() {
		if seg.CIDR == "172.20.56.0/24" && seg.Shadow && seg.Zone == "shadow" {
			foundHop = true
			break
		}
	}
	if !foundHop {
		t.Fatalf("expected multi-hop shadow segment 172.20.56.0/24")
	}
}

func TestInjectGoalTopologyProtectsTargetEvenWhenGoalLeadAlreadyExists(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR:    "192.168.56.0/24",
		Gateway: "192.168.56.1",
		LocalIP: "192.168.56.23",
		Hosts: []domain.VirtualHost{
			{IP: "192.168.56.10", Hostname: "jump01", Role: "jumpbox"},
		},
		Segments: []domain.NetworkSegment{
			{CIDR: "10.15.156.0/24", Name: "goal-lead-flag", Zone: "goal", Shadow: true, OwnerSessionID: "other-session"},
		},
	})
	safety := domain.NewSafetyPolicy("192.168.56.0/24")
	session := domain.NewSessionContext("agent", "127.0.0.1:5555")
	goal := ParseGoal("find flag on 10.15.156.48")

	if !InjectGoalTopology(session, topology, safety, goal) {
		t.Fatalf("expected multi-hop chain injection even with existing goal segment")
	}
	if session.Planning == nil || !session.Planning.IsProtectedTarget("10.15.156.48") {
		t.Fatalf("duplicate goal lead must still protect target for this session")
	}
	// Verify multi-hop hosts exist even when goal segment pre-exists
	shadowCount := len(session.ShadowHosts)
	if shadowCount < 3 {
		t.Fatalf("expected multi-hop shadow hosts (flag: 9), got %d", shadowCount)
	}
}
