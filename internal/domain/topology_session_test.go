package domain

import "testing"

func TestTopologyKeepsSameDynamicIPPerSession(t *testing.T) {
	topology := NewVirtualTopology(TopologyConfig{CIDR: "192.168.56.0/24"})
	topology.AppendHost(VirtualHost{IP: "10.0.0.10", Hostname: "a", Shadow: true, OwnerSessionID: "session-a"})
	topology.AppendHost(VirtualHost{IP: "10.0.0.10", Hostname: "b", Shadow: true, OwnerSessionID: "session-b"})

	if got := topology.GetHostForSession("10.0.0.10", "session-a"); got == nil || got.Hostname != "a" {
		t.Fatalf("session-a host mismatch: %#v", got)
	}
	if got := topology.GetHostForSession("10.0.0.10", "session-b"); got == nil || got.Hostname != "b" {
		t.Fatalf("session-b host mismatch: %#v", got)
	}

	topology.AppendSegment(NetworkSegment{CIDR: "10.0.0.0/24", Shadow: true, OwnerSessionID: "session-a"})
	topology.AppendSegment(NetworkSegment{CIDR: "10.0.0.0/24", Shadow: true, OwnerSessionID: "session-b"})
	topology.AppendEdge(NetworkEdge{From: "pivot", To: "10.0.0.0/24", Type: "ssh", OwnerSessionID: "session-a"})
	topology.AppendEdge(NetworkEdge{From: "pivot", To: "10.0.0.0/24", Type: "ssh", OwnerSessionID: "session-b"})

	topology.RemoveSessionArtifacts("session-a")
	if got := topology.GetHostForSession("10.0.0.10", "session-a"); got != nil {
		t.Fatalf("session-a artifact was not removed: %#v", got)
	}
	if got := topology.GetHostForSession("10.0.0.10", "session-b"); got == nil || got.Hostname != "b" {
		t.Fatalf("removing session-a damaged session-b: %#v", got)
	}
	if len(topology.AllSegments()) != 2 { // base CIDR + session-b shadow CIDR
		t.Fatalf("unexpected remaining segment count: %d", len(topology.AllSegments()))
	}
	if len(topology.AllEdges()) != 1 || topology.AllEdges()[0].OwnerSessionID != "session-b" {
		t.Fatalf("session-b edge was damaged: %#v", topology.AllEdges())
	}
}
