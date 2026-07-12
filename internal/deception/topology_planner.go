package deception

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/alterhive/alterhive/internal/domain"
	"github.com/alterhive/alterhive/internal/llm"
)

// CompletionClient is the LLM surface used by the topology planner.
type CompletionClient interface {
	IsActive() bool
	Complete(context.Context, llm.CompletionRequest) (*llm.CompletionResponse, error)
}

// TopologyPlan is the structured graph mutation accepted from rules or LLM.
type TopologyPlan struct {
	Reason       string                  `json:"reason"`
	Phase        string                  `json:"phase,omitempty"`
	Segments     []domain.NetworkSegment `json:"segments"`
	Edges        []domain.NetworkEdge    `json:"edges"`
	Hosts        []domain.VirtualHost    `json:"hosts"`
	Breadcrumbs  []PlanBreadcrumb        `json:"breadcrumbs"`
	Invalidators []string                `json:"invalidators,omitempty"`
	CachePolicy  PlanCachePolicy         `json:"cache_policy,omitempty"`
}

// WorldPatchProposal is the concrete graph mutation proposed by the World
// Builder layer. It is deliberately separate from DeceptionPlan so the planner
// can describe strategy without directly committing runtime facts.
type WorldPatchProposal struct {
	Reason       string                  `json:"reason"`
	Phase        string                  `json:"phase,omitempty"`
	Segments     []domain.NetworkSegment `json:"segments,omitempty"`
	Edges        []domain.NetworkEdge    `json:"edges,omitempty"`
	Hosts        []domain.VirtualHost    `json:"hosts,omitempty"`
	Breadcrumbs  []PlanBreadcrumb        `json:"breadcrumbs,omitempty"`
	Invalidators []string                `json:"invalidators,omitempty"`
	CachePolicy  PlanCachePolicy         `json:"cache_policy,omitempty"`
}

// DeceptionPlan is the strategic output of the planner agent. Only the nested
// proposal may mutate the world after consistency/safety validation.
type DeceptionPlan struct {
	PlanID                 string             `json:"plan_id,omitempty"`
	AttackerGoalHypothesis string             `json:"attacker_goal_hypothesis,omitempty"`
	DefenderObjective      string             `json:"defender_objective,omitempty"`
	Phase                  string             `json:"phase,omitempty"`
	ShadowPath             []string           `json:"shadow_path,omitempty"`
	PseudoProgressPolicy   string             `json:"pseudo_progress_policy,omitempty"`
	FailurePoints          []string           `json:"failure_points,omitempty"`
	ExposableFacts         []string           `json:"exposable_facts,omitempty"`
	HiddenFacts            []string           `json:"hidden_facts,omitempty"`
	TriggerConditions      []string           `json:"trigger_conditions,omitempty"`
	Invalidators           []string           `json:"invalidators,omitempty"`
	CachePolicy            PlanCachePolicy    `json:"cache_policy,omitempty"`
	Proposal               WorldPatchProposal `json:"world_patch_proposal,omitempty"`
	LegacyPlan             TopologyPlan       `json:"-"`
}

type PlanCachePolicy struct {
	PlanTTLCommands   int  `json:"plan_ttl_commands,omitempty"`
	ResponseCacheable bool `json:"response_cacheable"`
}

// PlanBreadcrumb records deferred evidence/file hints for future world mutators.
type PlanBreadcrumb struct {
	Path         string   `json:"path"`
	ContentHint  string   `json:"content_hint"`
	VisibleAfter []string `json:"visible_after"`
}

// TopologyPlanner runs a fast deterministic planner and an optional async LLM planner.
type TopologyPlanner struct {
	llm      CompletionClient
	topology *domain.VirtualTopology
	mu       sync.Mutex
	inflight map[string]bool
}

// NewTopologyPlanner creates an agentic planner for topology graph mutations.
func NewTopologyPlanner(topology *domain.VirtualTopology, llmClient CompletionClient) *TopologyPlanner {
	return &TopologyPlanner{
		llm:      llmClient,
		topology: topology,
		inflight: make(map[string]bool),
	}
}

// Plan applies the rule path immediately and schedules the LLM path in background.
func (p *TopologyPlanner) Plan(session *domain.SessionContext, command string, profile AgentProfile) []domain.VirtualHost {
	if p == nil || session == nil || p.topology == nil {
		return nil
	}

	decision := DetectExpansionIntent(command, profile)
	if decision.Triggered && decision.PivotIP == "" {
		decision.PivotIP = DefaultPivotIP(p.topology, session)
	}
	return p.PlanDecision(session, command, profile, decision, session.HasAccessState(Jump01FootholdState()) || shouldAskLLMPlanner(command, profile))
}

// PlanDecision applies an already-routed expansion decision and optionally
// schedules the LLM planner for a richer follow-up graph mutation.
// The deterministic plan is always applied immediately (fast path). LLM
// enrichment is always scheduled asynchronously and lands on the next cycle.
func (p *TopologyPlanner) PlanDecision(session *domain.SessionContext, command string, profile AgentProfile, decision ExpansionDecision, scheduleLLM bool) []domain.VirtualHost {
	if p == nil || session == nil || p.topology == nil {
		return nil
	}

	var added []domain.VirtualHost
	if decision.Triggered {
		if decision.PivotIP == "" {
			decision.PivotIP = DefaultPivotIP(p.topology, session)
		}
		if decision.TargetIP != "" && decision.Theme == "flag" {
			decision.CIDR = diversionCIDRForGoal(&GoalTarget{TargetIP: decision.TargetIP, CIDR: decision.CIDR, Theme: decision.Theme})
		}

		// Fast path: always apply the deterministic plan immediately.
		plan := PlanFromDecision(decision)
		added = p.MergePlan(session, plan)

		// Async path: schedule LLM enrichment in the background.
		if scheduleLLM && !completionClientInactive(p.llm) {
			if session.Planning != nil {
				session.Planning.RecordLLMPlanningCall()
			}
			p.scheduleLLMPlan(session, command, profile)
		}
	}

	if !decision.Triggered && scheduleLLM {
		if session.Planning != nil {
			session.Planning.RecordLLMPlanningCall()
		}
		p.scheduleLLMPlan(session, command, profile)
	}
	return added
}

// PlanFromDecision converts the deterministic fast path into the same schema as LLM plans.
func PlanFromDecision(decision ExpansionDecision) TopologyPlan {
	if !decision.Triggered {
		return TopologyPlan{}
	}
	if decision.PivotIP == "" {
		decision.PivotIP = "192.168.56.10"
	}
	theme := decision.Theme
	if theme == "" {
		theme = "network"
	}

	// Multi-hop: generate chained CIDRs, segments, and edges
	cidrs := chainedCIDRs(decision.CIDR, theme)

	// Build segments
	segments := make([]domain.NetworkSegment, 0, len(cidrs))
	for i, cidr := range cidrs {
		segments = append(segments, domain.NetworkSegment{
			CIDR:         cidr,
			Name:         fmt.Sprintf("%s-hop%d", theme, i+1),
			Zone:         "shadow",
			GatewayIP:    hostIP(cidr, 1),
			Shadow:       true,
			VisibleAfter: []string{"subnet_scan"},
		})
	}

	// Build chained edges: pivot → cidr[0], host_on_cidr[0] → cidr[1], ...
	edges := make([]domain.NetworkEdge, 0, len(cidrs))
	prevPivot := decision.PivotIP
	for _, cidr := range cidrs {
		edges = append(edges, domain.NetworkEdge{
			From:          prevPivot,
			To:            cidr,
			Type:          "pivot",
			Via:           prevPivot,
			RequiredState: PivotGateStates(),
			Status:        "locked",
		})
		// Next hop's pivot is the first host on the current segment
		prevPivot = hostIP(cidr, 10)
	}

	// Distribute hosts across hops with correct reachableVia
	hosts := make([]domain.VirtualHost, 0)
	for i, cidr := range cidrs {
		var reachableVia string
		if i == 0 {
			reachableVia = decision.PivotIP
		} else {
			reachableVia = hostIP(cidrs[i-1], 10) // first host of previous segment
		}
		hopHosts := themedHopHosts(cidr, theme, reachableVia)
		hosts = append(hosts, hopHosts...)
	}

	// If there's an exact target IP and it's not already included, prepend it on the last hop
	if decision.TargetIP != "" && theme != "flag" && !hostListContains(hosts, decision.TargetIP) {
		lastCIDR := cidrs[len(cidrs)-1]
		lastReachable := decision.PivotIP
		if len(cidrs) > 1 {
			lastReachable = hostIP(cidrs[len(cidrs)-2], 10)
		}
		hosts = append(hosts, targetShadowHost(decision.TargetIP, lastCIDR, theme, lastReachable))
	}

	return TopologyPlan{
		Reason:       decision.Reason,
		Phase:        phaseForTheme(theme),
		Segments:     segments,
		Edges:        edges,
		Hosts:        hosts,
		Invalidators: defaultPlanInvalidators(theme),
		CachePolicy:  PlanCachePolicy{PlanTTLCommands: 20, ResponseCacheable: true},
	}
}

// MergePlan validates and merges graph mutations into the runtime topology.
func (p *TopologyPlanner) MergePlan(session *domain.SessionContext, plan TopologyPlan) []domain.VirtualHost {
	if p == nil || p.topology == nil || session == nil {
		return nil
	}
	plan = sanitizePlan(plan)
	filtered, err := filterProtectedTargets(plan, session)
	if err != nil {
		session.AppendEvent(domain.EventEntry{
			Type:      "topology_plan_rejected",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			SessionID: session.SessionID,
			Detail:    err.Error(),
		})
		return nil
	}
	plan = filtered
	if err := ValidateTopologyPlan(plan, p.topology); err != nil {
		session.AppendEvent(domain.EventEntry{
			Type:      "topology_plan_rejected",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			SessionID: session.SessionID,
			Detail:    err.Error(),
		})
		return nil
	}

	for _, segment := range plan.Segments {
		segment.OwnerSessionID = session.SessionID
		p.topology.AppendSegment(segment)
	}
	for _, edge := range plan.Edges {
		edge.OwnerSessionID = session.SessionID
		p.topology.AppendEdge(edge)
	}

	var added []domain.VirtualHost
	for _, host := range plan.Hosts {
		host.OwnerSessionID = session.SessionID
		if p.topology.GetHostForSession(host.IP, session.SessionID) != nil {
			continue
		}
		p.topology.AppendHost(host)
		added = append(added, host)
		session.AddShadowHost(map[string]string{
			"ip":             host.IP,
			"hostname":       host.Hostname,
			"role":           host.Role,
			"segment_cidr":   host.SegmentCIDR,
			"reachable_via":  host.ReachableVia,
			"theme":          host.Theme,
			"status":         "locked",
			"required_state": strings.Join(host.RequiredState, ","),
			"triggered_by":   plan.Reason,
		})
	}
	if len(added) > 0 {
		if session.Planning != nil {
			session.Planning.BumpExposedFactVersion("topology_plan:" + plan.Reason)
			session.Planning.SetActivePlanMetadata(plan.Reason, "", plan.Phase, plan.Invalidators, plan.CachePolicy.PlanTTLCommands, plan.CachePolicy.ResponseCacheable, len(session.CommandLog))
		}
		session.AppendEvent(domain.EventEntry{
			Type:      "topology_expanded",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			SessionID: session.SessionID,
			Detail:    plan.Reason,
		})
	}
	return added
}

func (p *TopologyPlanner) MergeDeceptionPlan(session *domain.SessionContext, plan DeceptionPlan) []domain.VirtualHost {
	if p == nil || session == nil {
		return nil
	}
	topologyPlan := plan.ToTopologyPlan()
	if topologyPlan.Reason == "" {
		topologyPlan.Reason = plan.PlanID
	}
	if topologyPlan.Phase == "" {
		topologyPlan.Phase = plan.Phase
	}
	if len(topologyPlan.Invalidators) == 0 {
		topologyPlan.Invalidators = append([]string{}, plan.Invalidators...)
	}
	if topologyPlan.CachePolicy.PlanTTLCommands == 0 && plan.CachePolicy.PlanTTLCommands > 0 {
		topologyPlan.CachePolicy = plan.CachePolicy
	}
	if session.Planning != nil {
		session.AppendEvent(domain.EventEntry{
			Type:      "deception_plan_proposed",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			SessionID: session.SessionID,
			Detail:    deceptionPlanSummary(plan),
		})
	}
	added := p.MergePlan(session, topologyPlan)
	if len(added) > 0 {
		session.AppendEvent(domain.EventEntry{
			Type:      "world_patch_proposal_applied",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			SessionID: session.SessionID,
			Detail:    topologyPlan.Reason,
		})
	}
	return added
}

func (p DeceptionPlan) ToTopologyPlan() TopologyPlan {
	if !isEmptyTopologyPlan(p.LegacyPlan) {
		return p.LegacyPlan
	}
	return TopologyPlan{
		Reason:       firstNonEmpty(p.Proposal.Reason, p.PlanID, p.AttackerGoalHypothesis),
		Phase:        firstNonEmpty(p.Proposal.Phase, p.Phase),
		Segments:     append([]domain.NetworkSegment{}, p.Proposal.Segments...),
		Edges:        append([]domain.NetworkEdge{}, p.Proposal.Edges...),
		Hosts:        append([]domain.VirtualHost{}, p.Proposal.Hosts...),
		Breadcrumbs:  append([]PlanBreadcrumb{}, p.Proposal.Breadcrumbs...),
		Invalidators: append([]string{}, firstStringSlice(p.Proposal.Invalidators, p.Invalidators)...),
		CachePolicy:  firstCachePolicy(p.Proposal.CachePolicy, p.CachePolicy),
	}
}

func isEmptyTopologyPlan(plan TopologyPlan) bool {
	return plan.Reason == "" &&
		plan.Phase == "" &&
		len(plan.Segments) == 0 &&
		len(plan.Edges) == 0 &&
		len(plan.Hosts) == 0 &&
		len(plan.Breadcrumbs) == 0
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func firstStringSlice(values ...[]string) []string {
	for _, value := range values {
		if len(value) > 0 {
			return value
		}
	}
	return nil
}

func firstCachePolicy(values ...PlanCachePolicy) PlanCachePolicy {
	for _, value := range values {
		if value.PlanTTLCommands > 0 || value.ResponseCacheable {
			return value
		}
	}
	return PlanCachePolicy{}
}

func deceptionPlanSummary(plan DeceptionPlan) string {
	parts := []string{}
	if plan.PlanID != "" {
		parts = append(parts, "plan="+plan.PlanID)
	}
	if plan.Phase != "" {
		parts = append(parts, "phase="+plan.Phase)
	}
	if plan.AttackerGoalHypothesis != "" {
		parts = append(parts, "goal="+plan.AttackerGoalHypothesis)
	}
	if plan.PseudoProgressPolicy != "" {
		parts = append(parts, "ppf="+plan.PseudoProgressPolicy)
	}
	if len(plan.Proposal.Hosts) > 0 || len(plan.LegacyPlan.Hosts) > 0 {
		parts = append(parts, fmt.Sprintf("hosts=%d", len(plan.ToTopologyPlan().Hosts)))
	}
	if len(parts) == 0 {
		return "empty_deception_plan"
	}
	return strings.Join(parts, " ")
}

func rejectProtectedTargets(plan TopologyPlan, session *domain.SessionContext) error {
	if session == nil || session.Planning == nil {
		return nil
	}
	for _, host := range plan.Hosts {
		if session.Planning.IsProtectedTarget(host.IP) {
			return fmt.Errorf("plan attempted to create protected terminal target %s", host.IP)
		}
	}
	return nil
}

// filterProtectedTargets removes hosts at protected target IPs from the plan.
// If the majority of hosts are protected targets, the entire plan is rejected
// as a safety measure against LLM-generated direct-success paths.
func filterProtectedTargets(plan TopologyPlan, session *domain.SessionContext) (TopologyPlan, error) {
	if session == nil || session.Planning == nil {
		return plan, nil
	}
	if len(plan.Hosts) == 0 {
		return plan, nil
	}
	protectedCount := 0
	filtered := make([]domain.VirtualHost, 0, len(plan.Hosts))
	for _, host := range plan.Hosts {
		if session.Planning.IsProtectedTarget(host.IP) {
			protectedCount++
			continue
		}
		filtered = append(filtered, host)
	}
	// If the majority of hosts are at protected targets, the plan is suspicious
	if protectedCount > 0 && protectedCount >= len(plan.Hosts) {
		return plan, fmt.Errorf("plan targets protected terminals (%d/%d hosts)", protectedCount, len(plan.Hosts))
	}
	plan.Hosts = filtered
	return plan, nil
}

func (p *TopologyPlanner) scheduleLLMPlan(session *domain.SessionContext, command string, profile AgentProfile) {
	if completionClientInactive(p.llm) {
		return
	}
	key := session.SessionID + ":" + command
	p.mu.Lock()
	if p.inflight[key] {
		p.mu.Unlock()
		return
	}
	p.inflight[key] = true
	p.mu.Unlock()

	go func() {
		defer func() {
			p.mu.Lock()
			delete(p.inflight, key)
			p.mu.Unlock()
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		plan, err := p.llmPlan(ctx, session, command, profile)
		if err != nil {
			session.AppendEvent(domain.EventEntry{
				Type:      "topology_plan_failed",
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				SessionID: session.SessionID,
				Detail:    err.Error(),
			})
			return
		}
		p.MergeDeceptionPlan(session, plan)
	}()
}

func completionClientInactive(client CompletionClient) bool {
	if client == nil {
		return true
	}
	value := reflect.ValueOf(client)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return true
		}
	}
	return !client.IsActive()
}

func (p *TopologyPlanner) llmPlan(ctx context.Context, session *domain.SessionContext, command string, profile AgentProfile) (DeceptionPlan, error) {
	req := llm.CompletionRequest{
		MaxTokens:      1600,
		Temperature:    0.1,
		ResponseFormat: "json_object",
		Messages: []llm.Message{
			{Role: "system", Content: buildPlannerSystemPrompt()},
			{Role: "user", Content: buildPlannerUserPrompt(session, p.topology, command, profile)},
		},
	}
	resp, err := p.llm.Complete(ctx, req)
	if err != nil {
		return DeceptionPlan{}, err
	}
	if strings.TrimSpace(resp.Content) == "" {
		return DeceptionPlan{}, fmt.Errorf("empty LLM planner response")
	}
	plan, err := parseDeceptionPlanContent(resp.Content)
	if err != nil {
		repaired, repairErr := p.repairPlanJSON(ctx, resp.Content)
		if repairErr != nil {
			return DeceptionPlan{}, fmt.Errorf("parse deception plan: %w; repair failed: %v", err, repairErr)
		}
		plan, err = parseDeceptionPlanContent(repaired)
		if err != nil {
			return DeceptionPlan{}, fmt.Errorf("parse repaired deception plan: %w", err)
		}
	}
	if plan.PlanID == "" {
		plan.PlanID = "llm_planner:" + command
	}
	return plan, nil
}

func (p *TopologyPlanner) repairRejectedPlan(ctx context.Context, session *domain.SessionContext, command string, profile AgentProfile, plan DeceptionPlan, feedback string) (DeceptionPlan, error) {
	payload := map[string]interface{}{
		"feedback":       feedback,
		"rejected_plan":  plan,
		"original_input": buildPlannerUserPrompt(session, p.topology, command, profile),
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
		return DeceptionPlan{}, err
	}
	if strings.TrimSpace(resp.Content) == "" {
		return DeceptionPlan{}, fmt.Errorf("empty rejected-plan repair response")
	}
	repaired, err := parseDeceptionPlanContent(resp.Content)
	if err != nil {
		return DeceptionPlan{}, err
	}
	if repaired.PlanID == "" {
		repaired.PlanID = "llm_repair:" + command
	}
	return repaired, nil
}

func (p *TopologyPlanner) repairPlanJSON(ctx context.Context, raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("empty raw planner response")
	}
	req := llm.CompletionRequest{
		MaxTokens:      1200,
		Temperature:    0,
		ResponseFormat: "json_object",
		Messages: []llm.Message{
			{Role: "system", Content: "Repair this AlterHive TopologyPlan into one valid JSON object only. Do not add markdown or commentary. Preserve fields and intent; do not create protected targets."},
			{Role: "user", Content: raw},
		},
	}
	resp, err := p.llm.Complete(ctx, req)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(resp.Content) == "" {
		return "", fmt.Errorf("empty repair response")
	}
	return resp.Content, nil
}

func parseTopologyPlanContent(content string, plan *TopologyPlan) error {
	if plan == nil {
		return fmt.Errorf("nil plan")
	}
	candidates := []string{
		strings.TrimSpace(content),
		extractJSONObject(content),
		extractBalancedJSONObject(content),
	}
	var lastErr error
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if err := json.Unmarshal([]byte(candidate), plan); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("empty planner response")
	}
	return lastErr
}

func parseDeceptionPlanContent(content string) (DeceptionPlan, error) {
	candidates := []string{
		strings.TrimSpace(content),
		extractJSONObject(content),
		extractBalancedJSONObject(content),
	}
	var lastErr error
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		plan, err := parseDeceptionPlanJSON(candidate)
		if err == nil {
			return plan, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("empty planner response")
	}
	return DeceptionPlan{}, lastErr
}

func parseDeceptionPlanJSON(candidate string) (DeceptionPlan, error) {
	var envelope struct {
		DeceptionPlan      *DeceptionPlan      `json:"deception_plan"`
		WorldPatchProposal *WorldPatchProposal `json:"world_patch_proposal"`
	}
	_ = json.Unmarshal([]byte(candidate), &envelope)
	if envelope.DeceptionPlan != nil {
		plan := *envelope.DeceptionPlan
		if envelope.WorldPatchProposal != nil && isEmptyWorldPatchProposal(plan.Proposal) {
			plan.Proposal = *envelope.WorldPatchProposal
		}
		if !isEmptyDeceptionPlan(plan) {
			return plan, nil
		}
	}

	var plan DeceptionPlan
	if err := json.Unmarshal([]byte(candidate), &plan); err == nil && !isEmptyDeceptionPlan(plan) {
		return plan, nil
	}

	var legacy TopologyPlan
	if err := parseTopologyPlanContent(candidate, &legacy); err != nil {
		return DeceptionPlan{}, err
	}
	if isEmptyTopologyPlan(legacy) {
		return DeceptionPlan{}, fmt.Errorf("empty deception plan")
	}
	return DeceptionPlan{
		PlanID:               legacy.Reason,
		Phase:                legacy.Phase,
		Invalidators:         append([]string{}, legacy.Invalidators...),
		CachePolicy:          legacy.CachePolicy,
		PseudoProgressPolicy: "legacy_topology_plan",
		LegacyPlan:           legacy,
	}, nil
}

func isEmptyDeceptionPlan(plan DeceptionPlan) bool {
	return plan.PlanID == "" &&
		plan.AttackerGoalHypothesis == "" &&
		plan.DefenderObjective == "" &&
		len(plan.ShadowPath) == 0 &&
		plan.PseudoProgressPolicy == "" &&
		isEmptyWorldPatchProposal(plan.Proposal) &&
		isEmptyTopologyPlan(plan.LegacyPlan)
}

func isEmptyWorldPatchProposal(proposal WorldPatchProposal) bool {
	return proposal.Reason == "" &&
		proposal.Phase == "" &&
		len(proposal.Segments) == 0 &&
		len(proposal.Edges) == 0 &&
		len(proposal.Hosts) == 0 &&
		len(proposal.Breadcrumbs) == 0
}

func buildPlannerSystemPrompt() string {
	return `You are AlterHive Deception Planner Agent. Return JSON only.
Goal: expand a simulated internal network graph to keep a penetration-testing agent engaged, without letting it directly win.
Schema:
{
  "plan_id": "stable short id",
  "attacker_goal_hypothesis": "what the attacker appears to want",
  "defender_objective": "route attacker into shadow path and never expose real target",
  "phase": "recon|pivot_discovery|service_validation|exploit_gated|evidence_followup",
  "shadow_path": ["entry", "existing-pivot-ip", "new-shadow-cidr", "new-shadow-host"],
  "pseudo_progress_policy": "slow_success_then_gate|partial_discovery_then_acl|credential_valid_scope_limited",
  "failure_points": ["credential_valid_but_scope_limited", "target_requires_second_pivot"],
  "invalidators": ["goal_shift","nested_shell","critical_evidence_read","plan_ttl"],
  "cache_policy": {"plan_ttl_commands": 20, "response_cacheable": true},
  "world_patch_proposal": {
    "reason": "short concrete mutation reason",
    "phase": "same phase",
    "segments": [{"cidr":"10.x.y.0/24","name":"finance-shadow","zone":"shadow","gateway_ip":"10.x.y.1","shadow":true,"visible_after":["subnet_scan"]}],
    "edges": [{"from":"<existing pivot IP>","to":"10.x.y.0/24","type":"pivot","via":"<same existing pivot IP>","required_state":["gate_jump01_lowpriv_shell"],"status":"locked"}],
    "hosts": [{"ip":"10.x.y.10","hostname":"finance-web-01","role":"finance_app","os":"Ubuntu 22.04","segment_cidr":"10.x.y.0/24","reachable_via":"<same existing pivot IP>","required_state":["gate_jump01_lowpriv_shell","gate_credential_validated"],"shadow":true,"theme":"finance","compromise_mode":"partial","visible_after":["subnet_scan"],"services":[{"port":443,"protocol":"https","nmap_name":"ssl/http","banner":"nginx","failure_mode":"redirect_login"}]}],
    "breadcrumbs": [{"path":"/opt/webapp/logs/app.log","content_hint":"mentions finance-web-01","visible_after":["app_config"]}]
  }
}
Rules:
- Use private RFC1918 CIDRs only, /24 only.
- Do not create public IPs, localhost, metadata IPs, or real external targets.
- Never create any host whose IP appears in protected_targets. Those are terminal attacker goals; create intermediate pivot/trace assets instead.
- The planner describes strategy in top-level fields; only world_patch_proposal contains concrete graph mutation facts.
- Every new shadow segment must have a concrete upstream pivot host in edges[].from/via. Prefer the host the attacker is actually trying to pivot through.
- The upstream pivot must be one of the existing_hosts IPs from the user payload. Do not invent or copy example IPs.
- Every new shadow segment and host must require at least one gate_* state matching that upstream pivot, for example gate_jump01_lowpriv_shell or gate_dc01_foothold.
- Add a second gate when appropriate: finance requires gate_credential_validated, cloud/domain requires gate_service_auth_limited, flag/target requires gate_exploit_partial or gate_target_partial_reachability.
- If the command, profile, or protected target indicates flag/proof/root.txt/user.txt hunting, the new plan theme must be flag and roles should look like artifact store, CI runner, backup index, wiki, or deploy trace. Do not create finance assets unless finance/payroll/billing is explicitly requested.
- Never create a direct flag/root/admin success host. Use partial, locked, ambiguous breadcrumbs.
- Prefer 2-4 hosts, 1 segment, 1 pivot edge per plan.
- Output only valid JSON, no markdown.`
}

func buildPlannerUserPrompt(session *domain.SessionContext, topology *domain.VirtualTopology, command string, profile AgentProfile) string {
	protectedTargets := []string{}
	if session.Planning != nil {
		protectedTargets = session.Planning.ProtectedTargetList()
	}
	payload := map[string]interface{}{
		"command":           command,
		"profile":           profile,
		"session_id":        session.SessionID,
		"cwd":               session.CWD,
		"user":              session.User,
		"evidence":          session.Evidence.Tokens(),
		"access_states":     session.AccessStateList(),
		"memory":            plannerMemorySummary(session),
		"existing_segments": topology.AllSegments(),
		"existing_edges":    topology.AllEdges(),
		"existing_hosts":    topology.AllHosts(),
		"entry_host":        session.Hostname,
		"entry_internal_ip": session.SubnetLocalIP,
		"protected_targets": protectedTargets,
	}
	b, _ := json.Marshal(payload)
	return string(b)
}

func plannerMemorySummary(session *domain.SessionContext) string {
	if session == nil || session.Memory == nil {
		return ""
	}
	return session.Memory.PromptSummary()
}

// ValidateTopologyPlan rejects unsafe or too-easy LLM graph mutations.
func ValidateTopologyPlan(plan TopologyPlan, topology *domain.VirtualTopology) error {
	if len(plan.Segments) == 0 && len(plan.Hosts) == 0 && len(plan.Edges) == 0 {
		return fmt.Errorf("empty plan")
	}
	segmentSet := make(map[string]bool)
	segmentZone := make(map[string]string)
	for _, segment := range topology.AllSegments() {
		segmentSet[segment.CIDR] = true
		segmentZone[segment.CIDR] = segment.Zone
	}
	for _, segment := range plan.Segments {
		if err := validateCIDR(segment.CIDR); err != nil {
			return err
		}
		segmentSet[segment.CIDR] = true
		segmentZone[segment.CIDR] = segment.Zone
		if !segment.Shadow {
			return fmt.Errorf("planned segment %s must be shadow", segment.CIDR)
		}
	}
	for _, edge := range plan.Edges {
		if edge.Type == "" || edge.To == "" {
			return fmt.Errorf("edge missing type/to")
		}
		if edge.From == "" {
			return fmt.Errorf("edge to %s missing upstream pivot", edge.To)
		}
		if !hasGateState(edge.RequiredState) {
			return fmt.Errorf("edge to %s must require at least one gate state", edge.To)
		}
		if !knownPivotHost(topology, edge.From) && !planContainsHost(plan, edge.From) {
			return fmt.Errorf("edge from %s is not an existing or planned pivot host", edge.From)
		}
		if edge.Via != "" && edge.Via != edge.From {
			return fmt.Errorf("edge via %s must match upstream pivot %s", edge.Via, edge.From)
		}
	}
	for _, host := range plan.Hosts {
		if host.IP == "" || host.Hostname == "" || host.Role == "" {
			return fmt.Errorf("host missing identity fields")
		}
		if !segmentSet[host.SegmentCIDR] {
			return fmt.Errorf("host %s segment %s missing", host.IP, host.SegmentCIDR)
		}
		if segmentZone[host.SegmentCIDR] == "goal" {
			return fmt.Errorf("host %s cannot be placed in goal-lead segment %s", host.IP, host.SegmentCIDR)
		}
		if !ipInCIDR(host.IP, host.SegmentCIDR) {
			return fmt.Errorf("host %s outside segment %s", host.IP, host.SegmentCIDR)
		}
		if !host.Shadow {
			return fmt.Errorf("host %s must be shadow", host.IP)
		}
		if host.ReachableVia == "" {
			return fmt.Errorf("host %s missing reachable_via", host.IP)
		}
		if !knownPivotHost(topology, host.ReachableVia) && !planContainsHost(plan, host.ReachableVia) {
			return fmt.Errorf("host %s reachable_via %s is not an existing or planned pivot host", host.IP, host.ReachableVia)
		}
		if !hasGateState(host.RequiredState) {
			return fmt.Errorf("host %s must require at least one gate state", host.IP)
		}
		if host.CompromiseMode == "success" || host.CompromiseMode == "owned" {
			return fmt.Errorf("host %s grants terminal success", host.IP)
		}
		for _, svc := range host.Services {
			if svc.Port <= 0 || svc.Port > 65535 || svc.Protocol == "" {
				return fmt.Errorf("host %s has invalid service", host.IP)
			}
		}
	}
	return nil
}

func sanitizePlan(plan TopologyPlan) TopologyPlan {
	theme := planTheme(plan)
	cachePolicyOmitted := plan.CachePolicy.PlanTTLCommands == 0 && !plan.CachePolicy.ResponseCacheable
	if plan.Phase == "" {
		plan.Phase = phaseForTheme(theme)
	}
	if len(plan.Invalidators) == 0 {
		plan.Invalidators = defaultPlanInvalidators(theme)
	}
	if plan.CachePolicy.PlanTTLCommands <= 0 {
		plan.CachePolicy.PlanTTLCommands = 20
	}
	if cachePolicyOmitted {
		plan.CachePolicy.ResponseCacheable = true
	}
	defaultPivot := "192.168.56.10"
	if len(plan.Edges) > 0 {
		if plan.Edges[0].From != "" {
			defaultPivot = plan.Edges[0].From
		} else if plan.Edges[0].Via != "" {
			defaultPivot = plan.Edges[0].Via
		}
	}
	pivotBySegment := make(map[string]string)
	for i := range plan.Segments {
		if plan.Segments[i].Zone == "" {
			plan.Segments[i].Zone = "shadow"
		}
		plan.Segments[i].Shadow = true
	}
	for i := range plan.Edges {
		if plan.Edges[i].From == "" {
			plan.Edges[i].From = defaultPivot
		}
		if plan.Edges[i].Via == "" {
			plan.Edges[i].Via = plan.Edges[i].From
		}
		if plan.Edges[i].Status == "" {
			plan.Edges[i].Status = "locked"
		}
		if !hasGateState(plan.Edges[i].RequiredState) {
			plan.Edges[i].RequiredState = append(plan.Edges[i].RequiredState, GateJump01LowPrivShell)
		}
		pivotBySegment[plan.Edges[i].To] = plan.Edges[i].From
	}
	for i := range plan.Hosts {
		plan.Hosts[i].Shadow = true
		if plan.Hosts[i].ReachableVia == "" {
			plan.Hosts[i].ReachableVia = pivotBySegment[plan.Hosts[i].SegmentCIDR]
			if plan.Hosts[i].ReachableVia == "" {
				plan.Hosts[i].ReachableVia = defaultPivot
			}
		}
		if plan.Hosts[i].CompromiseMode == "" {
			plan.Hosts[i].CompromiseMode = "partial"
		}
		if !hasGateState(plan.Hosts[i].RequiredState) {
			plan.Hosts[i].RequiredState = append(plan.Hosts[i].RequiredState, GateJump01LowPrivShell)
		}
		if len(plan.Hosts[i].VisibleAfter) == 0 {
			plan.Hosts[i].VisibleAfter = []string{"subnet_scan"}
		}
	}
	return plan
}

func planTheme(plan TopologyPlan) string {
	for _, host := range plan.Hosts {
		if host.Theme != "" {
			return host.Theme
		}
		if strings.Contains(strings.ToLower(host.Role), "flag") {
			return "flag"
		}
	}
	name := strings.ToLower(plan.Reason)
	switch {
	case strings.Contains(name, "flag"), strings.Contains(name, "proof"):
		return "flag"
	case strings.Contains(name, "finance"), strings.Contains(name, "财务"):
		return "finance"
	case strings.Contains(name, "domain"), strings.Contains(name, "ldap"), strings.Contains(name, "smb"):
		return "domain"
	case strings.Contains(name, "cloud"), strings.Contains(name, "k8s"), strings.Contains(name, "kubectl"):
		return "cloud"
	default:
		return "network"
	}
}

func phaseForTheme(theme string) string {
	switch theme {
	case "flag":
		return "evidence_followup"
	case "finance", "cloud", "domain":
		return "service_validation"
	default:
		return "pivot_discovery"
	}
}

func defaultPlanInvalidators(theme string) []string {
	base := []string{"goal_shift", "plan_ttl", "nested_shell", "safety_block", "consistency_reject"}
	if theme == "flag" {
		return append(base, "critical_evidence_read")
	}
	return append(base, "critical_evidence_read")
}

func shouldAskLLMPlanner(command string, profile AgentProfile) bool {
	lower := strings.ToLower(command)
	if requestedCIDRPattern.MatchString(lower) {
		return true
	}
	for _, marker := range []string{"finance", "财务", "flag", "proof", "kubectl", "gitlab", "jenkins", "ldap", "smb", "domain", "10.", "172."} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return profile.PrimaryStyle == "cloud_native" || profile.PrimaryStyle == "domain_mapper" || profile.PrimaryStyle == "network_mapper"
}

func validateCIDR(cidr string) error {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid cidr %s", cidr)
	}
	ones, bits := network.Mask.Size()
	if bits != 32 || ones != 24 {
		return fmt.Errorf("cidr %s must be IPv4 /24", cidr)
	}
	if !isPrivateIPv4(ip) {
		return fmt.Errorf("cidr %s must be private", cidr)
	}
	return nil
}

func isPrivateIPv4(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	return ip4[0] == 10 ||
		(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
		(ip4[0] == 192 && ip4[1] == 168)
}

func ipInCIDR(ip, cidr string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	_, network, err := net.ParseCIDR(cidr)
	return err == nil && network.Contains(parsed)
}

func extractJSONObject(text string) string {
	text = strings.TrimSpace(text)
	if strings.HasPrefix(text, "{") && strings.HasSuffix(text, "}") {
		return text
	}
	re := regexp.MustCompile(`(?s)\{.*\}`)
	if match := re.FindString(text); match != "" {
		return match
	}
	return text
}

func extractBalancedJSONObject(text string) string {
	start := strings.Index(text, "{")
	if start < 0 {
		return ""
	}
	depth := 0
	inString := false
	escaped := false
	for i := start; i < len(text); i++ {
		ch := text[i]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' && inString {
			escaped = true
			continue
		}
		if ch == '"' {
			inString = !inString
			continue
		}
		if inString {
			continue
		}
		switch ch {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return text[start : i+1]
			}
		}
	}
	return ""
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func hasGateState(items []string) bool {
	for _, item := range items {
		if strings.HasPrefix(item, "gate_") || item == Jump01FootholdState() {
			return true
		}
	}
	return false
}

func knownPivotHost(topology *domain.VirtualTopology, ip string) bool {
	return topology != nil && topology.GetHost(ip) != nil
}

func hostListContains(hosts []domain.VirtualHost, ip string) bool {
	for _, host := range hosts {
		if host.IP == ip {
			return true
		}
	}
	return false
}

// planContainsHost checks whether a host with the given IP is included in the plan.
// Used to allow intermediate pivot hosts that are being created in the same plan.
func planContainsHost(plan TopologyPlan, ip string) bool {
	for _, host := range plan.Hosts {
		if host.IP == ip {
			return true
		}
	}
	return false
}

func targetShadowHost(ip, cidr, theme, pivotIP string) domain.VirtualHost {
	if theme == "" {
		theme = "target"
	}
	return domain.VirtualHost{
		IP:             ip,
		Hostname:       hostnameForTarget(ip, theme),
		Role:           theme + "_target",
		OS:             "Linux",
		CanaryID:       domain.DeploySeed,
		Services:       services("ssh", "https"),
		VisibleAfter:   []string{"subnet_scan"},
		SegmentCIDR:    cidr,
		ReachableVia:   pivotIP,
		RequiredState:  TargetGateStates(),
		Shadow:         true,
		Theme:          theme,
		CompromiseMode: "partial",
	}
}

func hostnameForTarget(ip, theme string) string {
	parts := strings.Split(ip, ".")
	last := "target"
	if len(parts) == 4 {
		last = parts[3]
	}
	return fmt.Sprintf("%s-target-%s", theme, last)
}
