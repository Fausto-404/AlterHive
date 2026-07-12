package deception

import (
	"testing"

	"github.com/alterhive/alterhive/internal/domain"
)

func TestIntentRouterAgentUsesLLMForNaturalLanguageGoal(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR:    "192.168.56.0/24",
		Gateway: "192.168.56.1",
		LocalIP: "192.168.56.23",
		Hosts: []domain.VirtualHost{
			{IP: "192.168.56.10", Hostname: "jump01", Role: "jumpbox"},
		},
	})
	llmClient := &fakePlannerLLM{active: true, content: `{
		"intent_type":"finance_hunt",
		"target_subnet":"10.66.7.0/24",
		"target_service":"mysql",
		"target_goal":"finance crown jewel database",
		"confidence":0.91,
		"is_new_discovery":true,
		"should_plan":true,
		"should_schedule_llm":true,
		"decision":{"triggered":true,"cidr":"10.66.7.0/24","theme":"finance","reason":"llm inferred finance target"}
	}`}
	router := NewIntentRouterAgent(topology, llmClient)
	session := domain.NewSessionContext("agent", "127.0.0.1:0")
	event := NewCommandEvent(session, "operator note says locate the finance crown jewel database", AgentProfile{})

	got := router.Route(event, session)
	if got.Source != "llm_intent_router" {
		t.Fatalf("expected LLM intent source, got %#v", got)
	}
	if got.IntentType != "finance_hunt" || got.TargetSubnet != "10.66.7.0/24" || !got.ShouldPlan {
		t.Fatalf("expected structured finance planning intent, got %#v", got)
	}
	if !got.Decision.Triggered || got.Decision.PivotIP != "192.168.56.10" {
		t.Fatalf("expected sanitized expansion decision with default pivot, got %#v", got.Decision)
	}
	if llmClient.requests != 1 {
		t.Fatalf("expected one LLM request, got %d", llmClient.requests)
	}
}

func TestIntentRouterAgentRejectsPublicLLMTarget(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{CIDR: "192.168.56.0/24"})
	llmClient := &fakePlannerLLM{active: true, content: `{
		"intent_type":"host_probe",
		"target_ip":"8.8.8.8",
		"target_subnet":"8.8.8.0/24",
		"confidence":0.96,
		"is_new_discovery":true,
		"should_plan":true,
		"decision":{"triggered":true,"cidr":"8.8.8.0/24","target_ip":"8.8.8.8","theme":"network"}
	}`}
	router := NewIntentRouterAgent(topology, llmClient)
	session := domain.NewSessionContext("agent", "127.0.0.1:0")
	event := NewCommandEvent(session, "operator asked about the external dns resolver target", AgentProfile{})

	got := router.Route(event, session)
	if got.TargetIP != "" || got.TargetSubnet != "" || got.ShouldPlan {
		t.Fatalf("public LLM target must not become a planning intent, got %#v", got)
	}
}

func TestIntentRouterAgentCachesLLMIntent(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{CIDR: "192.168.56.0/24"})
	llmClient := &fakePlannerLLM{active: true, content: `{
		"intent_type":"domain_hunt",
		"target_subnet":"10.77.8.0/24",
		"target_goal":"domain controller path",
		"confidence":0.9,
		"is_new_discovery":true,
		"should_plan":true,
		"decision":{"triggered":true,"cidr":"10.77.8.0/24","theme":"domain"}
	}`}
	router := NewIntentRouterAgent(topology, llmClient)
	session := domain.NewSessionContext("agent", "127.0.0.1:0")
	event := NewCommandEvent(session, "find the domain controller path from this foothold", AgentProfile{})

	first := router.Route(event, session)
	second := router.Route(event, session)
	if first.TargetSubnet != "10.77.8.0/24" || second.TargetSubnet != "10.77.8.0/24" {
		t.Fatalf("expected cached subnet on repeated route, first=%#v second=%#v", first, second)
	}
	if llmClient.requests != 1 {
		t.Fatalf("expected cached intent to avoid second LLM call, got %d calls", llmClient.requests)
	}
	if second.Source != "intent_cache" {
		t.Fatalf("expected second route to come from cache, got %#v", second)
	}
}
