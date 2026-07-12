package deception

import (
	"fmt"
	"time"

	"github.com/alterhive/alterhive/internal/domain"
)

type CommandEvent struct {
	SessionID  string
	Command    string
	User       string
	CWD        string
	Hostname   string
	OccurredAt time.Time
	Profile    AgentProfile
}

type RuntimeAction string

const (
	ActionFastResponse RuntimeAction = "fast_response"
	ActionPatchPlan    RuntimeAction = "patch_plan"
	ActionFullReplan   RuntimeAction = "full_replan"
	ActionSafetyBlock  RuntimeAction = "safety_block"
)

type RuntimeDecision struct {
	Action         RuntimeAction
	Intent         IntentResult
	SelectedPlanID string
	CacheKey       string
	Events         []string
	Reason         string
}

func NewCommandEvent(session *domain.SessionContext, command string, profile AgentProfile) CommandEvent {
	event := CommandEvent{
		Command:    command,
		OccurredAt: time.Now().UTC(),
		Profile:    profile,
	}
	if session != nil {
		event.SessionID = session.SessionID
		event.User = session.User
		event.CWD = session.CWD
		event.Hostname = session.Hostname
	}
	return event
}

func BuildRuntimeDecision(event CommandEvent, intent IntentResult, session *domain.SessionContext) RuntimeDecision {
	action := ActionFastResponse
	reason := "cache_or_registered_fact"
	if intent.IsPlanBreaking || intent.IsGoalShift {
		action = ActionFullReplan
		reason = "plan_break_or_goal_shift"
	} else if intent.ShouldPlan || intent.ShouldScheduleLLM {
		action = ActionPatchPlan
		reason = "planning_event"
	}

	planID := ""
	if session != nil && session.Planning != nil {
		planID = session.Planning.ActivePlanID
		if invalid, invalidReason := session.Planning.EvaluateActivePlan(event.Command, len(session.CommandLog)+1, session.IsNestedSSH()); invalid {
			action = ActionFullReplan
			reason = "active_plan_invalidated:" + invalidReason
		}
	}
	return RuntimeDecision{
		Action:         action,
		Intent:         intent,
		SelectedPlanID: planID,
		CacheKey:       fmt.Sprintf("%s|%s|%s|%s", event.SessionID, event.CWD, event.User, intent.PlanKey()),
		Events:         intent.Events,
		Reason:         reason,
	}
}
