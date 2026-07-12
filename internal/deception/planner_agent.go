package deception

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/alterhive/alterhive/internal/domain"
	"github.com/alterhive/alterhive/internal/llm"
)

// DeceptionPlannerAgent is the strategic LLM deception planner. It produces
// DeceptionPlan (strategy) that the World Builder translates into concrete
// WorldPatchProposal mutations. It is separated from the topology mutation
// logic (TopologyPlanner.MergePlan) so the plan can be validated by consistency
// and safety agents before any world mutation.
type DeceptionPlannerAgent struct {
	llm      CompletionClient
	topology *domain.VirtualTopology
}

// NewDeceptionPlannerAgent creates a ready-to-use deception planner.
func NewDeceptionPlannerAgent(llmClient CompletionClient, topology *domain.VirtualTopology) *DeceptionPlannerAgent {
	return &DeceptionPlannerAgent{
		llm:      llmClient,
		topology: topology,
	}
}

// IsActive returns true when the LLM client is available.
func (p *DeceptionPlannerAgent) IsActive() bool {
	return p != nil && !completionClientInactive(p.llm)
}

// Plan generates a strategic DeceptionPlan via LLM for the given session and
// intent. This is the COLD PATH — it is called asynchronously when the event
// bus signals a replanning event, not on every command.
func (p *DeceptionPlannerAgent) Plan(ctx context.Context, session *domain.SessionContext, intent IntentResult, event PlanningEvent) (DeceptionPlan, error) {
	if p == nil || !p.IsActive() {
		return DeceptionPlan{}, fmt.Errorf("planner agent not active")
	}
	if session == nil {
		return DeceptionPlan{}, fmt.Errorf("session required")
	}

	// Build a composite profile from session state
	profile := ProfileFromSession(session)

	req := llm.CompletionRequest{
		MaxTokens:      1600,
		Temperature:    0.1,
		ResponseFormat: "json_object",
		Messages: []llm.Message{
			{Role: "system", Content: buildPlannerSystemPrompt()},
			{Role: "user", Content: buildPlannerUserPrompt(session, p.topology, buildPlannerCommand(intent, event), profile)},
		},
	}

	resp, err := p.llm.Complete(ctx, req)
	if err != nil {
		return DeceptionPlan{}, fmt.Errorf("llm planner: %w", err)
	}
	if strings.TrimSpace(resp.Content) == "" {
		return DeceptionPlan{}, fmt.Errorf("empty LLM planner response")
	}

	plan, err := parseDeceptionPlanContent(resp.Content)
	if err != nil {
		return DeceptionPlan{}, fmt.Errorf("parse deception plan: %w", err)
	}

	plan = p.enrichPlan(plan, intent, event, session)
	return plan, nil
}

// PlanAsync schedules LLM planning in the background and calls the callback
// when complete. This is the primary integration point for the Cold Path.
func (p *DeceptionPlannerAgent) PlanAsync(session *domain.SessionContext, intent IntentResult, event PlanningEvent, callback func(DeceptionPlan, error)) {
	if p == nil || !p.IsActive() {
		if callback != nil {
			callback(DeceptionPlan{}, fmt.Errorf("planner not active"))
		}
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		plan, err := p.Plan(ctx, session, intent, event)
		if callback != nil {
			callback(plan, err)
		}

		if err != nil && session != nil {
			session.AppendEvent(domain.EventEntry{
				Type:      "deception_planner_failed",
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				SessionID: session.SessionID,
				Detail:    err.Error(),
			})
		} else if session != nil {
			session.AppendEvent(domain.EventEntry{
				Type:      "deception_plan_generated",
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				SessionID: session.SessionID,
				Detail:    deceptionPlanSummary(plan),
			})
		}
	}()
}

// RepairPlan sends a rejected plan back to the LLM with feedback for revision.
func (p *DeceptionPlannerAgent) RepairPlan(ctx context.Context, session *domain.SessionContext, plan DeceptionPlan, feedback string, intent IntentResult, event PlanningEvent) (DeceptionPlan, error) {
	if p == nil || !p.IsActive() {
		return DeceptionPlan{}, fmt.Errorf("planner agent not active")
	}

	profile := ProfileFromSession(session)
	payload := map[string]interface{}{
		"feedback":       feedback,
		"rejected_plan":  plan,
		"original_input": buildPlannerUserPrompt(session, p.topology, buildPlannerCommand(intent, event), profile),
	}
	b, _ := json.Marshal(payload)

	req := llm.CompletionRequest{
		MaxTokens:      1600,
		Temperature:    0.1,
		ResponseFormat: "json_object",
		Messages: []llm.Message{
			{Role: "system", Content: buildPlannerSystemPrompt()},
			{Role: "user", Content: string(b)},
		},
	}

	resp, err := p.llm.Complete(ctx, req)
	if err != nil {
		return DeceptionPlan{}, fmt.Errorf("repair planner: %w", err)
	}
	if strings.TrimSpace(resp.Content) == "" {
		return DeceptionPlan{}, fmt.Errorf("empty repair response")
	}

	repaired, err := parseDeceptionPlanContent(resp.Content)
	if err != nil {
		return DeceptionPlan{}, err
	}
	if repaired.PlanID == "" {
		repaired.PlanID = "llm_repair:" + plan.PlanID
	}
	return p.enrichPlan(repaired, intent, event, session), nil
}

// enrichPlan fills in defaults and derives metadata from intent/event/session.
func (p *DeceptionPlannerAgent) enrichPlan(plan DeceptionPlan, intent IntentResult, event PlanningEvent, session *domain.SessionContext) DeceptionPlan {
	if plan.PlanID == "" {
		plan.PlanID = fmt.Sprintf("llm_plan_%s_%d", event.SessionID, time.Now().Unix())
	}
	if plan.Phase == "" && session != nil && session.Planning != nil {
		plan.Phase = session.Planning.CurrentPhase
	}
	if plan.Phase == "" {
		plan.Phase = "recon"
	}
	if plan.AttackerGoalHypothesis == "" && intent.TargetGoal != "" {
		plan.AttackerGoalHypothesis = intent.TargetGoal
	}
	if plan.AttackerGoalHypothesis == "" && intent.Decision.Theme != "" {
		plan.AttackerGoalHypothesis = intent.Decision.Theme
	}
	if len(plan.ShadowPath) == 0 && intent.TargetSubnet != "" {
		plan.ShadowPath = []string{intent.TargetSubnet}
	}
	if len(plan.Invalidators) == 0 {
		plan.Invalidators = defaultPlanInvalidators(intent.Decision.Theme)
	}
	if plan.CachePolicy.PlanTTLCommands == 0 {
		plan.CachePolicy.PlanTTLCommands = 20
		plan.CachePolicy.ResponseCacheable = true
	}

	// Fill proposal defaults from intent
	if plan.Proposal.Reason == "" {
		plan.Proposal.Reason = fmt.Sprintf("llm_plan:%s:%s", intent.IntentType, intent.PlanKey())
	}
	if plan.Proposal.Phase == "" {
		plan.Proposal.Phase = plan.Phase
	}

	return plan
}

// buildPlannerCommand synthesizes a command-like string from intent + event
// for the planner prompt, so the LLM has context even in the cold path.
func buildPlannerCommand(intent IntentResult, event PlanningEvent) string {
	var parts []string
	if event.Command != "" {
		parts = append(parts, event.Command)
	}
	if intent.TargetGoal != "" {
		parts = append(parts, "goal:"+intent.TargetGoal)
	}
	if intent.TargetSubnet != "" {
		parts = append(parts, "subnet:"+intent.TargetSubnet)
	}
	if intent.TargetIP != "" {
		parts = append(parts, "ip:"+intent.TargetIP)
	}
	if intent.TargetService != "" {
		parts = append(parts, "service:"+intent.TargetService)
	}
	if len(parts) == 0 {
		return string(event.Type)
	}
	return strings.Join(parts, " ")
}
