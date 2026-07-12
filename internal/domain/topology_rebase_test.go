package domain

import "testing"

func TestRebasePrimaryCIDRPreservesHostOffsets(t *testing.T) {
	config := TopologyConfig{
		CIDR:    "192.168.56.0/24",
		Gateway: "192.168.56.1",
		LocalIP: "192.168.56.23",
		Segments: []NetworkSegment{
			{CIDR: "192.168.56.0/24", GatewayIP: "192.168.56.1"},
			{CIDR: "10.10.20.0/24", GatewayIP: "10.10.20.1", Shadow: true},
		},
		Hosts: []VirtualHost{
			{IP: "192.168.56.23", Hostname: "staging-web-01", SegmentCIDR: "192.168.56.0/24"},
			{IP: "192.168.56.10", Hostname: "jump01", SegmentCIDR: "192.168.56.0/24"},
			{IP: "10.10.20.10", Hostname: "fin-app-01", SegmentCIDR: "10.10.20.0/24", ReachableVia: "192.168.56.10"},
		},
		Edges: []NetworkEdge{
			{From: "staging-web-01", To: "192.168.56.0/24", Type: "dual_nic", Via: "192.168.56.23"},
			{From: "192.168.56.23", To: "192.168.56.10", Type: "ssh", Via: "192.168.56.23"},
			{From: "192.168.56.10", To: "10.10.20.0/24", Type: "pivot", Via: "192.168.56.10"},
		},
	}

	got, err := RebasePrimaryCIDR(config, "192.168.6.0/24")
	if err != nil {
		t.Fatalf("rebase failed: %v", err)
	}

	if got.CIDR != "192.168.6.0/24" || got.Gateway != "192.168.6.1" || got.LocalIP != "192.168.6.23" {
		t.Fatalf("entry subnet not rebased: %#v", got)
	}
	if got.Hosts[0].IP != "192.168.6.23" || got.Hosts[0].SegmentCIDR != "192.168.6.0/24" {
		t.Fatalf("entry host not rebased: %#v", got.Hosts[0])
	}
	if got.Hosts[1].IP != "192.168.6.10" || got.Hosts[2].IP != "10.10.20.10" || got.Hosts[2].ReachableVia != "192.168.6.10" {
		t.Fatalf("host rebase mismatch: %#v", got.Hosts)
	}
	if got.Edges[1].From != "192.168.6.23" || got.Edges[1].To != "192.168.6.10" || got.Edges[2].From != "192.168.6.10" {
		t.Fatalf("edges not rebased: %#v", got.Edges)
	}
}
