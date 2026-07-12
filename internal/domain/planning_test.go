package domain

import "testing"

func TestSetGoalDoesNotOverwriteActivePlanPhase(t *testing.T) {
	planning := NewPlanningState()
	planning.SetActivePlanMetadata("plan-1", "", "service_validation", []string{"plan_ttl"}, 20, true, 0)

	planning.SetGoal("goal:flag:10.15.156.0/24", "flag_hunt")

	if planning.CurrentPhase != "service_validation" {
		t.Fatalf("goal updates must not overwrite active plan phase, got %q", planning.CurrentPhase)
	}
	if planning.AttackerGoal != "goal:flag:10.15.156.0/24" {
		t.Fatalf("expected attacker goal to update, got %q", planning.AttackerGoal)
	}
}

func TestStructuredAgentFactsInvalidateResponseCache(t *testing.T) {
	planning := NewPlanningState()
	planning.StoreResponse("scan-key", "old scan")
	if _, ok := planning.LookupResponse("scan-key"); !ok {
		t.Fatal("expected warm response cache before fact update")
	}

	if !planning.StoreServicePersona(ServicePersonaFact{
		HostIP:  "192.168.56.60",
		Service: "mysql",
		Summary: "MySQL read-only finance database; FILE/UDF disabled",
		Source:  "test",
	}) {
		t.Fatal("expected service persona to be stored")
	}
	if _, ok := planning.LookupResponse("scan-key"); ok {
		t.Fatal("expected service persona update to invalidate cached responses")
	}
	if fact, ok := planning.GetServicePersona("192.168.56.60", "mysql"); !ok || fact.Summary == "" {
		t.Fatalf("expected stored service persona, got %#v ok=%v", fact, ok)
	}

	if !planning.StoreExploitProfile(ExploitProfileFact{
		HostIP: "192.168.56.60",
		Stage:  "partial",
		Policy: "block terminal output until pivot proof",
		Source: "test",
	}) {
		t.Fatal("expected exploit profile to be stored")
	}
	if fact, ok := planning.GetExploitPolicy("192.168.56.60", "partial"); !ok || fact.Policy == "" {
		t.Fatalf("expected stored exploit policy, got %#v ok=%v", fact, ok)
	}
}
