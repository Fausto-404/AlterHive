package deception

import (
	"context"
	"strings"
	"testing"

	"github.com/alterhive/alterhive/internal/domain"
	"github.com/alterhive/alterhive/internal/llm"
)

type fakePlannerLLM struct {
	active    bool
	content   string
	responses []string
	requests  int
}

func (f *fakePlannerLLM) IsActive() bool { return f.active }

func (f *fakePlannerLLM) Complete(context.Context, llm.CompletionRequest) (*llm.CompletionResponse, error) {
	f.requests++
	if len(f.responses) > 0 {
		content := f.responses[0]
		f.responses = f.responses[1:]
		return &llm.CompletionResponse{Content: content}, nil
	}
	return &llm.CompletionResponse{Content: f.content}, nil
}

func TestPlannerMergesValidatedLLMPlan(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR:    "192.168.56.0/24",
		Gateway: "192.168.56.1",
		Hosts: []domain.VirtualHost{
			{IP: "192.168.56.10", Hostname: "jump01", Role: "jumpbox"},
		},
	})
	session := domain.NewSessionContext("agent", "127.0.0.1:0")
	planner := NewTopologyPlanner(topology, nil)

	added := planner.MergePlan(session, TopologyPlan{
		Reason: "unit-test",
		Segments: []domain.NetworkSegment{
			{CIDR: "10.77.8.0/24", Name: "finance-shadow", Zone: "shadow", GatewayIP: "10.77.8.1", Shadow: true},
		},
		Edges: []domain.NetworkEdge{
			{From: "192.168.56.10", To: "10.77.8.0/24", Type: "pivot", Via: "192.168.56.10", RequiredState: []string{Jump01FootholdState()}, Status: "locked"},
		},
		Hosts: []domain.VirtualHost{
			{
				IP:             "10.77.8.10",
				Hostname:       "finance-web-01",
				Role:           "finance_app",
				OS:             "Ubuntu 22.04",
				SegmentCIDR:    "10.77.8.0/24",
				ReachableVia:   "192.168.56.10",
				RequiredState:  []string{Jump01FootholdState()},
				Shadow:         true,
				Theme:          "finance",
				CompromiseMode: "partial",
				Services:       []domain.VirtualService{{Port: 443, Protocol: "https"}},
			},
		},
	})

	if len(added) != 1 {
		t.Fatalf("expected one generated host, got %d", len(added))
	}
	if !topology.IsVirtualIP("10.77.8.10") {
		t.Fatal("expected generated private segment to be virtual")
	}
}

func TestPlanDecisionPrefersLLMPlanWhenAvailable(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR:    "10.168.56.0/24",
		Gateway: "10.168.56.1",
		LocalIP: "10.168.56.23",
		Hosts: []domain.VirtualHost{
			{IP: "10.168.56.10", Hostname: "jump01", Role: "jumpbox"},
		},
	})
	session := domain.NewSessionContext("agent", "127.0.0.1:0")
	session.Planning.AddProtectedTarget("10.15.156.48")
	llmClient := &fakePlannerLLM{active: true, content: `{
		"reason":"llm_flag_trace",
		"segments":[{"cidr":"10.250.156.0/24","name":"llm-flag-trace","zone":"shadow","gateway_ip":"10.250.156.1","shadow":true,"visible_after":["subnet_scan"]}],
		"edges":[{"from":"10.168.56.10","to":"10.250.156.0/24","type":"pivot","via":"10.168.56.10","required_state":["gate_jump01_lowpriv_shell"],"status":"locked"}],
		"hosts":[{"ip":"10.250.156.10","hostname":"llm-artifact-hop","role":"flag_hint_artifacts","os":"Ubuntu 22.04","segment_cidr":"10.250.156.0/24","reachable_via":"10.168.56.10","required_state":["gate_jump01_lowpriv_shell","gate_exploit_partial"],"shadow":true,"theme":"flag","compromise_mode":"partial","visible_after":["subnet_scan"],"services":[{"port":8080,"protocol":"http","nmap_name":"http-proxy","banner":"Jetty","failure_mode":"redirect_login"}]}]
	}`}
	planner := NewTopologyPlanner(topology, llmClient)

	added := planner.PlanDecision(session, "find flag file on 10.15.156.48", AgentProfile{PrimaryStyle: "flag_hunter"}, ExpansionDecision{
		Triggered: true,
		CIDR:      "10.15.156.0/24",
		TargetIP:  "10.15.156.48",
		Theme:     "flag",
		PivotIP:   "10.168.56.10",
		Reason:    "unit_flag_goal",
	}, true)

	// Fast path: deterministic plan is always applied immediately.
	// Flag theme → 3 hops × 3 hosts = 9 hosts in chained 172.20.156-158.0/24.
	if len(added) != 9 {
		t.Fatalf("expected 9 deterministic hosts (3 hops × 3), got %d: %+v", len(added), added)
	}
	// LLM is now async — the sync call is never made.
	if llmClient.requests != 0 {
		t.Fatalf("expected zero sync LLM calls (async only), got %d", llmClient.requests)
	}
	if topology.GetHost("10.15.156.48") != nil {
		t.Fatalf("protected terminal target must not be created")
	}
	// Verify deterministic diversion CIDR was used.
	foundDiversion := false
	for _, host := range added {
		if strings.HasPrefix(host.IP, "172.20.156.") {
			foundDiversion = true
			break
		}
	}
	if !foundDiversion {
		t.Fatalf("expected deterministic hosts in diversion CIDR 172.20.156.0/24, got %+v", added)
	}
}

func TestPlanDecisionAcceptsDeceptionPlanWorldPatchProposal(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR:    "10.168.56.0/24",
		Gateway: "10.168.56.1",
		LocalIP: "10.168.56.23",
		Hosts: []domain.VirtualHost{
			{IP: "10.168.56.10", Hostname: "jump01", Role: "jumpbox"},
		},
	})
	session := domain.NewSessionContext("agent", "127.0.0.1:0")
	llmClient := &fakePlannerLLM{active: true, content: `{
		"plan_id":"plan_finance_shadow_001",
		"attacker_goal_hypothesis":"finance database path",
		"defender_objective":"route attacker through shadow finance branch without terminal DB compromise",
		"phase":"service_validation",
		"shadow_path":["entry","10.168.56.10","10.66.7.0/24","finance-report-01"],
		"pseudo_progress_policy":"credential_valid_scope_limited",
		"failure_points":["readonly_database","second_pivot_required"],
		"invalidators":["goal_shift","plan_ttl"],
		"cache_policy":{"plan_ttl_commands":12,"response_cacheable":true},
		"world_patch_proposal":{
			"reason":"proposal_finance_shadow",
			"phase":"service_validation",
			"segments":[{"cidr":"10.66.7.0/24","name":"finance-shadow","zone":"shadow","gateway_ip":"10.66.7.1","shadow":true,"visible_after":["subnet_scan"]}],
			"edges":[{"from":"10.168.56.10","to":"10.66.7.0/24","type":"pivot","via":"10.168.56.10","required_state":["gate_jump01_lowpriv_shell"],"status":"locked"}],
			"hosts":[{"ip":"10.66.7.10","hostname":"finance-report-01","role":"finance_app","os":"Ubuntu 22.04","segment_cidr":"10.66.7.0/24","reachable_via":"10.168.56.10","required_state":["gate_jump01_lowpriv_shell","gate_credential_validated"],"shadow":true,"theme":"finance","compromise_mode":"partial","visible_after":["subnet_scan"],"services":[{"port":443,"protocol":"https","nmap_name":"ssl/http","banner":"nginx","failure_mode":"redirect_login"}]}]
		}
	}`}
	planner := NewTopologyPlanner(topology, llmClient)

	added := planner.PlanDecision(session, "operator note says locate the finance crown jewel database", AgentProfile{PrimaryStyle: "secret_hunter"}, ExpansionDecision{
		Triggered: true,
		CIDR:      "10.66.7.0/24",
		Theme:     "finance",
		PivotIP:   "10.168.56.10",
		Reason:    "unit_finance_goal",
	}, true)

	// Fast path: deterministic plan is always applied immediately.
	// Finance theme → 2 hops × 3 hosts = 6 hosts.
	if len(added) != 6 {
		t.Fatalf("expected 6 deterministic finance hosts (2 hops × 3), got %d: %+v", len(added), added)
	}
	// LLM is async — no sync calls.
	if llmClient.requests != 0 {
		t.Fatalf("expected zero sync LLM calls (async only), got %d", llmClient.requests)
	}
	// Deterministic plan sets phase and TTL via MergePlan.
	if session.Planning.CurrentPhase != "service_validation" {
		t.Fatalf("expected deterministic phase service_validation, got %q", session.Planning.CurrentPhase)
	}
	if session.Planning.ActivePlanTTLCommands != 20 {
		t.Fatalf("expected deterministic TTL 20, got %d", session.Planning.ActivePlanTTLCommands)
	}
}

func TestPlanDecisionRepairsMalformedLLMPlan(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR:    "10.168.56.0/24",
		Gateway: "10.168.56.1",
		LocalIP: "10.168.56.23",
		Hosts: []domain.VirtualHost{
			{IP: "10.168.56.10", Hostname: "jump01", Role: "jumpbox"},
		},
	})
	session := domain.NewSessionContext("agent", "127.0.0.1:0")
	session.Planning.AddProtectedTarget("10.15.156.48")
	llmClient := &fakePlannerLLM{active: true, responses: []string{
		`plan = { reason: "bad-json"`,
		`{
			"reason":"repaired_flag_trace",
			"segments":[{"cidr":"10.251.156.0/24","name":"repaired-flag-trace","zone":"shadow","gateway_ip":"10.251.156.1","shadow":true,"visible_after":["subnet_scan"]}],
			"edges":[{"from":"10.168.56.10","to":"10.251.156.0/24","type":"pivot","via":"10.168.56.10","required_state":["gate_jump01_lowpriv_shell"],"status":"locked"}],
			"hosts":[{"ip":"10.251.156.10","hostname":"repair-artifact-hop","role":"flag_hint_artifacts","os":"Ubuntu 22.04","segment_cidr":"10.251.156.0/24","reachable_via":"10.168.56.10","required_state":["gate_jump01_lowpriv_shell","gate_exploit_partial"],"shadow":true,"theme":"flag","compromise_mode":"partial","visible_after":["subnet_scan"],"services":[{"port":8080,"protocol":"http","nmap_name":"http-proxy","banner":"Jetty","failure_mode":"redirect_login"}]}]
		}`,
	}}
	planner := NewTopologyPlanner(topology, llmClient)

	added := planner.PlanDecision(session, "find flag file on 10.15.156.48", AgentProfile{PrimaryStyle: "flag_hunter"}, ExpansionDecision{
		Triggered: true,
		CIDR:      "10.15.156.0/24",
		TargetIP:  "10.15.156.48",
		Theme:     "flag",
		PivotIP:   "10.168.56.10",
		Reason:    "unit_flag_goal",
	}, true)

	// Fast path: deterministic plan is always applied immediately.
	// Flag theme → 3 hops × 3 hosts = 9 hosts.
	if len(added) != 9 {
		t.Fatalf("expected 9 deterministic hosts (3 hops × 3), got %d: %+v", len(added), added)
	}
	// LLM is async — no sync calls, no repair calls.
	if llmClient.requests != 0 {
		t.Fatalf("expected zero sync LLM calls (async only), got %d", llmClient.requests)
	}
}

func TestPlanDecisionRepairsRejectedLLMPlan(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR:    "10.168.56.0/24",
		Gateway: "10.168.56.1",
		LocalIP: "10.168.56.23",
		Segments: []domain.NetworkSegment{
			{CIDR: "10.15.156.0/24", Name: "goal-lead-flag", Zone: "goal", Shadow: true},
		},
		Hosts: []domain.VirtualHost{
			{IP: "10.168.56.10", Hostname: "jump01", Role: "jumpbox"},
		},
	})
	session := domain.NewSessionContext("agent", "127.0.0.1:0")
	session.Planning.AddProtectedTarget("10.15.156.48")
	llmClient := &fakePlannerLLM{active: true, responses: []string{
		`{
			"reason":"bad_goal_segment_plan",
			"segments":[],
			"edges":[{"from":"10.168.56.10","to":"10.15.156.0/24","type":"pivot","via":"10.168.56.10","required_state":["gate_jump01_lowpriv_shell"],"status":"locked"}],
			"hosts":[{"ip":"10.15.156.10","hostname":"bad-hop","role":"artifact_store","os":"Ubuntu 22.04","segment_cidr":"10.15.156.0/24","reachable_via":"10.168.56.10","required_state":["gate_jump01_lowpriv_shell","gate_exploit_partial"],"shadow":true,"theme":"flag","compromise_mode":"partial","visible_after":["subnet_scan"],"services":[{"port":8080,"protocol":"http"}]}]
		}`,
		`{
			"reason":"repaired_rejected_plan",
			"segments":[{"cidr":"10.252.156.0/24","name":"repaired-shadow","zone":"shadow","gateway_ip":"10.252.156.1","shadow":true,"visible_after":["subnet_scan"]}],
			"edges":[{"from":"10.168.56.10","to":"10.252.156.0/24","type":"pivot","via":"10.168.56.10","required_state":["gate_jump01_lowpriv_shell"],"status":"locked"}],
			"hosts":[{"ip":"10.252.156.10","hostname":"repaired-artifact-hop","role":"flag_hint_artifacts","os":"Ubuntu 22.04","segment_cidr":"10.252.156.0/24","reachable_via":"10.168.56.10","required_state":["gate_jump01_lowpriv_shell","gate_exploit_partial"],"shadow":true,"theme":"flag","compromise_mode":"partial","visible_after":["subnet_scan"],"services":[{"port":8080,"protocol":"http"}]}]
		}`,
	}}
	planner := NewTopologyPlanner(topology, llmClient)

	added := planner.PlanDecision(session, "find flag file on 10.15.156.48", AgentProfile{PrimaryStyle: "flag_hunter"}, ExpansionDecision{
		Triggered: true,
		CIDR:      "10.15.156.0/24",
		TargetIP:  "10.15.156.48",
		Theme:     "flag",
		PivotIP:   "10.168.56.10",
		Reason:    "unit_flag_goal",
	}, true)

	// Fast path: deterministic plan is always applied immediately.
	// The deterministic plan creates hosts in diversion CIDRs (172.20.156-158.0/24),
	// not in the goal-lead segment 10.15.156.0/24, so MergePlan should succeed.
	// Flag theme → 3 hops × 3 hosts = 9 hosts.
	if len(added) != 9 {
		t.Fatalf("expected 9 deterministic hosts (3 hops × 3), got %d: %+v", len(added), added)
	}
	// LLM is async — no sync calls, no repair calls.
	if llmClient.requests != 0 {
		t.Fatalf("expected zero sync LLM calls (async only), got %d", llmClient.requests)
	}
	// Host must not be placed in the goal-lead segment.
	if topology.GetHost("10.15.156.10") != nil {
		t.Fatalf("host in goal-lead segment must not be committed")
	}
}

func TestPlanFromDecisionIncludesExactTargetHost(t *testing.T) {
	plan := PlanFromDecision(ExpansionDecision{
		Triggered: true,
		CIDR:      "172.16.56.0/24",
		TargetIP:  "172.16.56.50",
		Theme:     "domain",
		PivotIP:   "192.168.56.10",
		Reason:    "target-ip",
	})

	if !hostListContains(plan.Hosts, "172.16.56.50") {
		t.Fatalf("expected exact target host in plan, got %#v", plan.Hosts)
	}
	if plan.Hosts[0].ReachableVia != "192.168.56.10" {
		t.Fatalf("expected target host to be behind jump01, got %q", plan.Hosts[0].ReachableVia)
	}
}

func TestPlannerRejectsDirectSuccessPlan(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR: "192.168.56.0/24",
		Hosts: []domain.VirtualHost{
			{IP: "192.168.56.10", Hostname: "jump01", Role: "jumpbox"},
		},
	})
	err := ValidateTopologyPlan(TopologyPlan{
		Segments: []domain.NetworkSegment{
			{CIDR: "10.77.9.0/24", Name: "flag-shadow", Zone: "shadow", GatewayIP: "10.77.9.1", Shadow: true},
		},
		Edges: []domain.NetworkEdge{
			{From: "192.168.56.10", To: "10.77.9.0/24", Type: "pivot", Via: "192.168.56.10", RequiredState: []string{Jump01FootholdState()}, Status: "locked"},
		},
		Hosts: []domain.VirtualHost{
			{
				IP:             "10.77.9.10",
				Hostname:       "flag-box",
				Role:           "flag",
				SegmentCIDR:    "10.77.9.0/24",
				ReachableVia:   "192.168.56.10",
				RequiredState:  []string{Jump01FootholdState()},
				Shadow:         true,
				CompromiseMode: "success",
				Services:       []domain.VirtualService{{Port: 22, Protocol: "ssh"}},
			},
		},
	}, topology)
	if err == nil || !strings.Contains(err.Error(), "terminal success") {
		t.Fatalf("expected terminal success rejection, got %v", err)
	}
}

func TestPlannerAllowsKnownNonJumpPivot(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR: "192.168.56.0/24",
		Hosts: []domain.VirtualHost{
			{IP: "192.168.56.10", Hostname: "jump01", Role: "jumpbox"},
			{IP: "192.168.56.50", Hostname: "dc01", Role: "dc"},
		},
	})
	err := ValidateTopologyPlan(TopologyPlan{
		Segments: []domain.NetworkSegment{
			{CIDR: "172.16.70.0/24", Name: "dmz-shadow", Zone: "shadow", GatewayIP: "172.16.70.1", Shadow: true},
		},
		Edges: []domain.NetworkEdge{
			{From: "192.168.56.50", To: "172.16.70.0/24", Type: "pivot", Via: "192.168.56.50", RequiredState: []string{"gate_dc01_foothold"}, Status: "locked"},
		},
		Hosts: []domain.VirtualHost{
			{
				IP:             "172.16.70.10",
				Hostname:       "dmz-web-01",
				Role:           "webserver",
				SegmentCIDR:    "172.16.70.0/24",
				ReachableVia:   "192.168.56.50",
				RequiredState:  []string{"gate_dc01_foothold"},
				Shadow:         true,
				CompromiseMode: "partial",
				Services:       []domain.VirtualService{{Port: 443, Protocol: "https"}},
			},
		},
	}, topology)
	if err != nil {
		t.Fatalf("expected dc01 pivot plan to pass, got %v", err)
	}
}

func hasEventType(events []domain.EventEntry, want string) bool {
	for _, event := range events {
		if event.Type == want {
			return true
		}
	}
	return false
}
