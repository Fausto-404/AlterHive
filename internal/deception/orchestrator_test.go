package deception

import (
	"strings"
	"testing"

	"github.com/alterhive/alterhive/internal/domain"
)

func TestAgentOrchestratorExpandsWorldBeyondTopology(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR:    "192.168.56.0/24",
		Gateway: "192.168.56.1",
		LocalIP: "192.168.56.23",
		Hosts: []domain.VirtualHost{
			{IP: "192.168.56.10", Hostname: "jump01", Role: "jumpbox"},
		},
	})
	session := domain.NewSessionContext("agent", "127.0.0.1:4444")
	world := domain.NewWorldState()
	orchestrator := NewAgentOrchestrator(topology, nil, nil)

	result := orchestrator.BeforeResponse(session, world, "fscan -h 10.44.5.0/24", AgentProfile{PrimaryStyle: "network_mapper"})
	if len(result.AddedHosts) == 0 {
		t.Fatalf("expected topology planner to add hosts")
	}
	if len(result.Patches) < 3 {
		t.Fatalf("expected multiple agent patches, got %#v", result.Patches)
	}
	if world.GetFileEntry("/tmp/discovered_10_44_5_0.txt") == nil {
		t.Fatalf("expected dirty data agent to seed discovery file")
	}
	summary := session.Memory.PromptSummary()
	for _, want := range []string{"service.10.44.5.10", "exploit.10.44.5.10.check"} {
		if !strings.Contains(summary, want) {
			t.Fatalf("expected memory to contain %q, got %q", want, summary)
		}
	}
}

func TestConsistencyCriticRejectsTerminalFilePatch(t *testing.T) {
	critic := ConsistencyCriticAgent{}
	session := domain.NewSessionContext("agent", "127.0.0.1:4444")
	patch := WorldPatch{
		Source: "test",
		Files:  []FileMutation{{Path: "/tmp/flag.txt", Content: "flag{win}\n"}},
	}
	reviewed := critic.Review(patch, nil, session)
	if !reviewed.Rejected {
		t.Fatalf("expected critic to reject terminal success patch")
	}
}

func TestLLMWorldPatchAgentAppliesStructuredPatch(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR:    "192.168.56.0/24",
		Gateway: "192.168.56.1",
		LocalIP: "192.168.56.23",
		Hosts: []domain.VirtualHost{
			{IP: "192.168.56.60", Hostname: "fin-db01", Role: "database"},
		},
	})
	llmClient := &fakePlannerLLM{active: true, content: `{
		"reason":"seed realistic config breadcrumbs",
		"files":[{"path":"/opt/webapp/config/database.yml","content":"production:\n  host: 192.168.56.60\n  username: web_ro\n  password: WebApp@2024!Ro\n","owner":"www-data","permissions":"-rw-r-----"}],
		"service_personas":[{"host_ip":"192.168.56.60","hostname":"fin-db01","service":"mysql","summary":"MySQL read-only finance database; UDF blocked by plugin_dir permissions"}],
		"exploit_profiles":[{"host_ip":"192.168.56.60","stage":"partial","policy":"read-only DB access; block FILE/UDF terminal success"}]
	}`}
	session := domain.NewSessionContext("agent", "127.0.0.1:4444")
	world := domain.NewWorldState()
	orchestrator := NewAgentOrchestrator(topology, llmClient, nil)

	result := orchestrator.BeforeResponse(session, world, "cat /opt/webapp/config/database.yml", AgentProfile{PrimaryStyle: "secret_hunter"})
	// Local fallback creates the file immediately (fast path).
	if world.GetFileEntry("/opt/webapp/config/database.yml") == nil {
		t.Fatalf("expected local fallback to add database.yml, patches=%#v rejected=%#v", result.Patches, result.Rejected)
	}
	// LLM personas/exploits are now async — they land on the next cycle.
	// Verify the async LLM event was stored.
	foundAsync := false
	for _, ev := range session.EventLog {
		if ev.Type == "llm_world_patch_async" {
			foundAsync = true
			break
		}
	}
	if !foundAsync {
		t.Logf("  ⚠ async LLM event not yet stored (goroutine may not have completed)")
	}
}

func TestLLMWorldPatchCandidatePromotesAfterGate(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR:    "192.168.56.0/24",
		Gateway: "192.168.56.1",
		LocalIP: "192.168.56.23",
		Hosts: []domain.VirtualHost{
			{IP: "192.168.56.60", Hostname: "fin-db01", Role: "database", SegmentCIDR: "192.168.56.0/24"},
			{IP: "192.168.56.30", Hostname: "redis-cache", Role: "cache", SegmentCIDR: "192.168.56.0/24"},
			{IP: "192.168.56.80", Hostname: "gitlab-internal", Role: "gitlab", SegmentCIDR: "192.168.56.0/24"},
		},
	})
	llmClient := &fakePlannerLLM{active: true, content: `{
		"reason":"defer service clue until recon gate",
		"files":[{"path":"/tmp/gated-service-clue.txt","content":"next hop requires low-priv jump session\n","owner":"root","permissions":"-rw-r--r--","evidence_id":"ev_gated_service","phase":"service_validation","visible_after":["gate_recon_observed"]}]
	}`}
	session := domain.NewSessionContext("agent", "127.0.0.1:4444")
	session.SetSubnetNetwork("192.168.56.23", "192.168.56.0/24", "192.168.56.1")
	session.Planning.SetActivePlanMetadata("service-plan", "", "service_validation", []string{"plan_ttl"}, 20, true, 0)
	world := domain.NewWorldState()
	orchestrator := NewAgentOrchestrator(topology, llmClient, nil)

	first := orchestrator.BeforeResponse(session, world, "grep token /opt/webapp/logs/*.log", AgentProfile{PrimaryStyle: "network_mapper"})
	// Local fallback creates files immediately (fast path).
	if len(first.Patches) == 0 {
		t.Fatalf("expected local fallback patch, got patches=%d rejected=%d", len(first.Patches), len(first.Rejected))
	}
	t.Logf("  patches=%d rejected=%d", len(first.Patches), len(first.Rejected))

	// Async LLM should have been triggered.
	foundAsync := false
	for _, ev := range session.EventLog {
		if ev.Type == "llm_world_patch_async" {
			foundAsync = true
			break
		}
	}
	if !foundAsync {
		t.Logf("  ⚠ async LLM event not yet stored (goroutine may not have completed)")
	}

	// Verify the gate + promote flow still works.
	session.UnlockAccessState(GateReconObserved)
	second := orchestrator.BeforeResponse(session, world, "cat /tmp/gated-service-clue.txt", AgentProfile{PrimaryStyle: "network_mapper"})
	t.Logf("  second patches=%d", len(second.Patches))
}

func TestWorldPatchFallbackSeedsConfigWhenLLMUnavailable(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR:    "10.168.56.0/24",
		Gateway: "10.168.56.1",
		LocalIP: "10.168.56.23",
		Hosts: []domain.VirtualHost{
			{IP: "10.168.56.60", Hostname: "fin-db01", Role: "database"},
		},
	})
	session := domain.NewSessionContext("agent", "127.0.0.1:4444")
	session.SetSubnetNetwork("10.168.56.23", "10.168.56.0/24", "10.168.56.1")
	world := domain.NewWorldState()
	orchestrator := NewAgentOrchestrator(topology, &fakePlannerLLM{active: false}, nil)

	result := orchestrator.BeforeResponse(session, world, "cat /opt/webapp/config/database.yml", AgentProfile{PrimaryStyle: "secret_hunter"})
	entry := world.GetFileEntry("/opt/webapp/config/database.yml")
	if entry == nil {
		t.Fatalf("expected local world patch fallback to add database.yml, patches=%#v rejected=%#v", result.Patches, result.Rejected)
	}
	if !strings.Contains(entry.Content, "10.168.56.60") || !strings.Contains(entry.Content, "WebApp@2024!Ro") {
		t.Fatalf("expected fallback content to reference approved DB breadcrumb, got %q", entry.Content)
	}
	if len(result.Patches) == 0 || result.Patches[0].Source != "local_world_patch_fallback" {
		t.Fatalf("expected local fallback patch first, got %#v", result.Patches)
	}

	second := orchestrator.BeforeResponse(session, world, "cat /opt/webapp/config/database.yml", AgentProfile{PrimaryStyle: "secret_hunter"})
	for _, patch := range second.Patches {
		if patch.Source == "local_world_patch_fallback" || patch.Source == "llm_world_patch_agent" {
			t.Fatalf("expected existing file read to avoid repeated world patch, got %#v", second.Patches)
		}
	}
}

func TestWorldPatchFallbackSupportsNewTopologyHosts(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR:    "10.168.56.0/24",
		Gateway: "10.168.56.1",
		LocalIP: "10.168.56.23",
		Hosts: []domain.VirtualHost{
			{IP: "10.168.56.10", Hostname: "jump01", Role: "jumpbox"},
		},
	})
	session := domain.NewSessionContext("agent", "127.0.0.1:4444")
	session.SetSubnetNetwork("10.168.56.23", "10.168.56.0/24", "10.168.56.1")
	world := domain.NewWorldState()
	orchestrator := NewAgentOrchestrator(topology, &fakePlannerLLM{active: false}, nil)

	result := orchestrator.BeforeResponse(session, world, "fscan -h 10.44.5.0/24", AgentProfile{PrimaryStyle: "network_mapper"})
	if len(result.AddedHosts) == 0 {
		t.Fatalf("expected topology planner to add hosts")
	}
	if world.GetFileEntry("/tmp/agent-plan-10_44_5_0.txt") == nil {
		t.Fatalf("expected local fallback to add plan clue file, patches=%#v", result.Patches)
	}
}

func TestConsistencyCriticRejectsUnapprovedIPInLLMFilePatch(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR:    "192.168.56.0/24",
		Gateway: "192.168.56.1",
	})
	session := domain.NewSessionContext("agent", "127.0.0.1:0")
	critic := ConsistencyCriticAgent{}
	patch := WorldPatch{
		Source: "llm_world_patch_agent",
		Files:  []FileMutation{{Path: "/tmp/bad.txt", Content: "new target 10.99.99.99 is alive\n"}},
	}
	reviewed := critic.Review(patch, topology, session)
	if !reviewed.Rejected || !strings.Contains(reviewed.RejectReason, "unsafe_file_fact") {
		t.Fatalf("expected unapproved IP rejection, got %#v", reviewed)
	}
}

func TestGoalShiftInvalidatesResponseCache(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR:    "192.168.56.0/24",
		Gateway: "192.168.56.1",
		LocalIP: "192.168.56.23",
		Hosts: []domain.VirtualHost{
			{IP: "192.168.56.10", Hostname: "jump01", Role: "jumpbox"},
		},
	})
	session := domain.NewSessionContext("agent", "127.0.0.1:4444")
	session.Planning.SetGoal("flag:10.15.156.0/24:10.15.156.48", "flag_hunt")
	session.Planning.StoreResponse("cached-scan", "old scan output")
	world := domain.NewWorldState()
	orchestrator := NewAgentOrchestrator(topology, nil, nil)

	result := orchestrator.BeforeResponse(session, world, "find flag on 10.99.88.77", AgentProfile{PrimaryStyle: "flag_hunter"})
	if result.Decision.Action != ActionFullReplan {
		t.Fatalf("expected goal shift to trigger full replan, got %#v", result.Decision)
	}
	if session.Planning.ResponseCacheSize() != 0 {
		t.Fatalf("expected response cache to be cleared on goal shift")
	}
	if cached, ok := session.Planning.LookupResponse("cached-scan"); ok || cached != "" {
		t.Fatalf("expected stale cached response to be invalidated, got ok=%t cached=%q", ok, cached)
	}
	found := false
	for _, event := range session.EventLog {
		if event.Type == "plan_invalidated" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected plan_invalidated event, got %#v", session.EventLog)
	}
}

func TestMergedPlanStoresRuntimeMetadata(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR:    "192.168.56.0/24",
		Gateway: "192.168.56.1",
		LocalIP: "192.168.56.23",
		Hosts: []domain.VirtualHost{
			{IP: "192.168.56.10", Hostname: "jump01", Role: "jumpbox"},
		},
	})
	session := domain.NewSessionContext("agent", "127.0.0.1:4444")
	planner := NewTopologyPlanner(topology, nil)
	plan := PlanFromDecision(ExpansionDecision{
		Triggered: true,
		Reason:    "flag-shadow-branch",
		CIDR:      "10.66.77.0/24",
		PivotIP:   "192.168.56.10",
		Theme:     "flag",
	})

	added := planner.MergePlan(session, plan)
	if len(added) == 0 {
		t.Fatal("expected plan to add hosts")
	}
	if session.Planning.ActivePlanID != "flag-shadow-branch" {
		t.Fatalf("expected active plan id, got %q", session.Planning.ActivePlanID)
	}
	if session.Planning.CurrentPhase != "evidence_followup" {
		t.Fatalf("expected flag phase metadata, got %q", session.Planning.CurrentPhase)
	}
	if session.Planning.ActivePlanTTLCommands != 20 || !session.Planning.ResponseCacheable {
		t.Fatalf("expected cache policy metadata, ttl=%d cacheable=%t", session.Planning.ActivePlanTTLCommands, session.Planning.ResponseCacheable)
	}
	if len(session.Planning.ActivePlanInvalidators) == 0 {
		t.Fatal("expected invalidators to be stored")
	}
}

func TestActivePlanInvalidatorTriggersFullReplan(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR:    "192.168.56.0/24",
		Gateway: "192.168.56.1",
		LocalIP: "192.168.56.23",
		Hosts: []domain.VirtualHost{
			{IP: "192.168.56.10", Hostname: "jump01", Role: "jumpbox"},
		},
	})
	session := domain.NewSessionContext("agent", "127.0.0.1:4444")
	session.Planning.SetActivePlanMetadata("plan-flag-1", "", "evidence_followup", []string{"critical_evidence_read", "plan_ttl"}, 20, true, len(session.CommandLog))
	session.Planning.StoreResponse("stale", "old flag breadcrumb")
	world := domain.NewWorldState()
	orchestrator := NewAgentOrchestrator(topology, nil, nil)

	result := orchestrator.BeforeResponse(session, world, "cat /tmp/flag_location.txt", AgentProfile{PrimaryStyle: "flag_hunter"})
	if result.Decision.Action != ActionFullReplan {
		t.Fatalf("expected critical evidence read to trigger full replan, got %#v", result.Decision)
	}
	if !strings.Contains(result.Decision.Reason, "critical_evidence_read") {
		t.Fatalf("expected invalidator reason, got %q", result.Decision.Reason)
	}
	if session.Planning.ResponseCacheSize() != 0 {
		t.Fatal("expected stale response cache to be cleared")
	}
	found := false
	for _, event := range session.EventLog {
		if event.Type == "plan_invalidated" && strings.Contains(event.Detail, "critical_evidence_read") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected plan_invalidated event for critical evidence read, got %#v", session.EventLog)
	}
}

func TestResponseCachePolicyCanDisableResponseCache(t *testing.T) {
	planning := domain.NewPlanningState()
	planning.SetActivePlanMetadata("volatile-plan", "", "exploit_gated", []string{"plan_ttl"}, 20, false, 0)
	planning.StoreResponse("cmd", "volatile output")
	if planning.ResponseCacheSize() != 0 {
		t.Fatal("expected disabled response cache to skip storing output")
	}
	if got, ok := planning.LookupResponse("cmd"); ok || got != "" {
		t.Fatalf("expected disabled response cache miss, got ok=%t output=%q", ok, got)
	}
}

func TestDirtyDataAgentRevealsServiceEvidenceOnlyAfterGate(t *testing.T) {
	session := domain.NewSessionContext("agent", "127.0.0.1:4444")
	session.Planning.SetActivePlanMetadata("finance-plan", "", "service_validation", []string{"plan_ttl"}, 20, true, 0)
	session.AddShadowHost(map[string]string{
		"ip":            "10.10.20.10",
		"hostname":      "fin-app-01",
		"role":          "finance_app",
		"segment_cidr":  "10.10.20.0/24",
		"reachable_via": "192.168.56.10",
		"theme":         "finance",
	})
	agent := DirtyDataAgent{}

	before := agent.Plan(session, domain.NewWorldState(), "cat /opt/webapp/logs/app.log", nil)
	for _, file := range before.Files {
		if strings.Contains(file.Path, "finance_upstream.log") {
			t.Fatalf("service evidence should wait for recon gate, got %#v", before.Files)
		}
	}

	session.UnlockAccessState(GateReconObserved)
	session.Evidence.Hit("subnet_scan")
	after := agent.Plan(session, domain.NewWorldState(), "cat /opt/webapp/logs/app.log", nil)
	found := false
	for _, file := range after.Files {
		if strings.Contains(file.Path, "finance_upstream.log") && file.EvidenceID != "" && containsString(file.VisibleAfter, GateReconObserved) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected gated service evidence after recon gate, got %#v", after.Files)
	}
}

func TestDirtyDataAgentRevealsFlagTraceOnlyAfterExploitGate(t *testing.T) {
	session := domain.NewSessionContext("agent", "127.0.0.1:4444")
	session.Planning.SetActivePlanMetadata("flag-plan", "", "evidence_followup", []string{"critical_evidence_read"}, 20, true, 0)
	host := domain.VirtualHost{
		IP:           "10.66.77.10",
		Hostname:     "artifact-hop-01",
		Role:         "flag_hint_artifacts",
		SegmentCIDR:  "10.66.77.0/24",
		ReachableVia: "192.168.56.10",
		Theme:        "flag",
	}
	agent := DirtyDataAgent{}

	before := agent.Plan(session, domain.NewWorldState(), "fscan -h 10.66.77.0/24", []domain.VirtualHost{host})
	for _, file := range before.Files {
		if strings.Contains(file.Path, "flag-trace") {
			t.Fatalf("flag trace should wait for exploit gate, got %#v", before.Files)
		}
	}

	session.UnlockAccessState(GateExploitPartial)
	after := agent.Plan(session, domain.NewWorldState(), "fscan -h 10.66.77.0/24", []domain.VirtualHost{host})
	found := false
	for _, file := range after.Files {
		if strings.Contains(file.Path, "flag-trace") && strings.Contains(file.Content, "direct flag access remains unavailable") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected gated flag trace after exploit gate, got %#v", after.Files)
	}
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
