package session

import (
	"strings"
	"testing"

	"github.com/alterhive/alterhive/internal/deception"
	"github.com/alterhive/alterhive/internal/domain"
	"github.com/alterhive/alterhive/internal/tracer"
)

type noopTracer struct{}

func (noopTracer) TraceEvent(tracer.Event) {}

func TestDeleteSessionRemovesSessionWorldAndReuseIndex(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{CIDR: "192.168.56.0/24"})
	manager := NewManager(topology, domain.NewSafetyPolicy("192.168.56.0/24"), noopTracer{}, "staging-web-01", nil)

	first := manager.GetOrCreateSession("root", "203.0.113.10:51000")
	if first == nil {
		t.Fatal("expected session to be created")
	}
	if !manager.DeleteSession(first.SessionID) {
		t.Fatal("expected delete to return true")
	}
	if manager.GetSession(first.SessionID) != nil {
		t.Fatal("expected deleted session lookup to return nil")
	}
	if manager.DeleteSession(first.SessionID) {
		t.Fatal("expected deleting the same session twice to return false")
	}

	second := manager.GetOrCreateSession("root", "203.0.113.10:52000")
	if second == nil {
		t.Fatal("expected new session to be created")
	}
	if second.SessionID == first.SessionID {
		t.Fatal("expected reuse index to be removed so a new session is created")
	}
}

func TestDeleteSessionRemovesOwnedShadowTopology(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR:    "192.168.56.0/24",
		Gateway: "192.168.56.1",
		Hosts: []domain.VirtualHost{
			{IP: "192.168.56.10", Hostname: "jump01", Role: "jumpbox"},
		},
	})
	manager := NewManager(topology, domain.NewSafetyPolicy("192.168.56.0/24"), noopTracer{}, "staging-web-01", nil)
	session := manager.CreateSession("sim-agent", "127.0.0.1:0")

	topology.AppendSegment(domain.NetworkSegment{CIDR: "10.15.156.0/24", Shadow: true, OwnerSessionID: session.SessionID})
	topology.AppendEdge(domain.NetworkEdge{From: "192.168.56.10", To: "10.15.156.0/24", Type: "pivot", OwnerSessionID: session.SessionID})
	topology.AppendHost(domain.VirtualHost{IP: "10.15.156.48", Hostname: "flag-box01", SegmentCIDR: "10.15.156.0/24", Shadow: true, OwnerSessionID: session.SessionID})

	if topology.GetHost("10.15.156.48") == nil {
		t.Fatal("expected shadow host before deletion")
	}
	if !manager.DeleteSession(session.SessionID) {
		t.Fatal("expected session delete to succeed")
	}
	if topology.GetHost("10.15.156.48") != nil {
		t.Fatal("expected owned shadow host to be removed")
	}
	for _, segment := range topology.AllSegments() {
		if segment.CIDR == "10.15.156.0/24" {
			t.Fatal("expected owned shadow segment to be removed")
		}
	}
	for _, edge := range topology.AllEdges() {
		if edge.To == "10.15.156.0/24" {
			t.Fatal("expected owned shadow edge to be removed")
		}
	}
}

func TestCreateSessionAppliesConfiguredTopologyNetwork(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR:      "10.168.56.0/24",
		Gateway:   "10.168.56.1",
		LocalIP:   "10.168.56.23",
		DNSSuffix: "lab.local",
		Hosts: []domain.VirtualHost{
			{IP: "10.168.56.10", Hostname: "jump01", Role: "jumpbox"},
		},
	})
	manager := NewManager(topology, domain.NewSafetyPolicy("10.168.56.0/24"), noopTracer{}, "staging-web-01", nil)
	session := manager.CreateSession("root", "127.0.0.1:12345")

	if session.SubnetCIDR != "10.168.56.0/24" || session.SubnetLocalIP != "10.168.56.23" || session.SubnetGateway != "10.168.56.1" {
		t.Fatalf("expected configured subnet state, got cidr=%s local=%s gw=%s", session.SubnetCIDR, session.SubnetLocalIP, session.SubnetGateway)
	}
	if session.DNSSuffix != "lab.local" {
		t.Fatalf("expected configured dns suffix, got %s", session.DNSSuffix)
	}
	if session.Planning == nil || session.Planning.WorldVersion == 0 {
		t.Fatalf("expected planning world version to record topology rebase")
	}
}

func TestRepeatedPlanningIntentDoesNotDuplicateShadowHosts(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR:    "192.168.56.0/24",
		Gateway: "192.168.56.1",
		LocalIP: "192.168.56.23",
		Hosts: []domain.VirtualHost{
			{IP: "192.168.56.10", Hostname: "jump01", Role: "jumpbox"},
		},
	})
	manager := NewManager(topology, domain.NewSafetyPolicy("192.168.56.0/24"), noopTracer{}, "staging-web-01", nil)
	session := manager.CreateSession("sim-agent", "127.0.0.1:0")

	manager.PlanTopology(session, "fscan -h 10.1.5.0/24")
	firstCount := len(session.ShadowHosts)
	manager.PlanTopology(session, "fscan -h 10.1.5.0/24")
	secondCount := len(session.ShadowHosts)

	if firstCount == 0 {
		t.Fatal("expected first planning pass to add shadow hosts")
	}
	if secondCount != firstCount {
		t.Fatalf("expected plan cache to avoid duplicate shadow hosts: first=%d second=%d", firstCount, secondCount)
	}
	if session.Planning == nil || session.Planning.PlanCacheHits == 0 {
		t.Fatalf("expected repeated intent to record a plan cache hit")
	}
}

func TestGoalLeadPreventsFollowupScanFromCreatingExactTargetHost(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR:    "192.168.56.0/24",
		Gateway: "192.168.56.1",
		LocalIP: "192.168.56.23",
		Hosts: []domain.VirtualHost{
			{IP: "192.168.56.10", Hostname: "jump01", Role: "jumpbox"},
		},
	})
	manager := NewManager(topology, domain.NewSafetyPolicy("192.168.56.0/24"), noopTracer{}, "staging-web-01", nil)
	session := manager.CreateSession("sim-agent", "127.0.0.1:0")

	goal := deception.ParseGoal("find flag file on 10.15.156.48")
	if goal == nil {
		t.Fatal("expected goal")
	}
	if !deception.InjectGoalTopology(session, topology, manager.SafetyRef(), goal) {
		t.Fatal("expected goal topology injection")
	}
	manager.PlanTopology(session, "nmap -sV 10.15.156.48")

	if host := topology.GetHost("10.15.156.48"); host != nil {
		t.Fatalf("follow-up scan must not create exact terminal target: %+v", host)
	}
}

func TestSafetyAgentBlocksRealNetworkWithoutCountingTouch(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR:    "192.168.56.0/24",
		Gateway: "192.168.56.1",
		LocalIP: "192.168.56.23",
	})
	manager := NewManager(topology, domain.NewSafetyPolicy("192.168.56.0/24"), noopTracer{}, "staging-web-01", nil)
	session := manager.CreateSession("sim-agent", "127.0.0.1:0")
	session.Planning.SetActivePlanMetadata("plan-real-target", "", "recon", []string{"safety_block"}, 20, true, 0)

	got := manager.ExecuteCommand(session.SessionID, "nmap -sV 8.8.8.8")
	if !strings.Contains(got, "0 hosts up") {
		t.Fatalf("expected virtual no-route scan failure, got %q", got)
	}
	if session.Safety.SafetyBlockCount != 1 {
		t.Fatalf("expected one safety block, got %d", session.Safety.SafetyBlockCount)
	}
	if session.Safety.RealNetworkTouchCount != 0 || session.LoopMetrics.RealNetworkTouchCount != 0 {
		t.Fatalf("safety block must not count as real touch, safety=%d loop=%d", session.Safety.RealNetworkTouchCount, session.LoopMetrics.RealNetworkTouchCount)
	}
	if session.Planning.ActivePlanID != "" {
		t.Fatalf("expected active plan invalidated on safety block, got %q", session.Planning.ActivePlanID)
	}
	if len(session.CommandLog) != 1 || session.CommandLog[0].Intent != "safety_block" {
		t.Fatalf("expected safety block command log, got %#v", session.CommandLog)
	}
}

func TestSafetyAgentDoesNotBlockGoalStatementWithIP(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR:    "192.168.56.0/24",
		Gateway: "192.168.56.1",
		LocalIP: "192.168.56.23",
		Hosts: []domain.VirtualHost{
			{IP: "192.168.56.10", Hostname: "jump01", Role: "jumpbox"},
		},
	})
	manager := NewManager(topology, domain.NewSafetyPolicy("192.168.56.0/24"), noopTracer{}, "staging-web-01", nil)
	session := manager.CreateSession("sim-agent", "127.0.0.1:0")

	manager.ExecuteCommand(session.SessionID, "find flag file on 10.15.156.48")
	if session.Safety.SafetyBlockCount != 0 {
		t.Fatalf("goal statement should not be safety-blocked, got %d", session.Safety.SafetyBlockCount)
	}
	foundGoalLead := false
	for _, segment := range topology.AllSegments() {
		if segment.Shadow && segment.Zone == "goal" && segment.OwnerSessionID == session.SessionID {
			foundGoalLead = true
			break
		}
	}
	if !foundGoalLead {
		t.Fatal("expected goal statement to reach planner/goal injection path")
	}
}
