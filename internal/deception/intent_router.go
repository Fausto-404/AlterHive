package deception

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/alterhive/alterhive/internal/domain"
	"github.com/alterhive/alterhive/internal/llm"
)

var whitespacePattern = regexp.MustCompile(`\s+`)

// IntentResult is the fast-path interpretation used to decide whether the
// slower planner/LLM path is worth invoking.
type IntentResult struct {
	IntentType        string            `json:"intent_type"`
	TargetIP          string            `json:"target_ip,omitempty"`
	TargetPort        string            `json:"target_port,omitempty"`
	TargetService     string            `json:"target_service,omitempty"`
	TargetSubnet      string            `json:"target_subnet,omitempty"`
	TargetFile        string            `json:"target_file,omitempty"`
	TargetGoal        string            `json:"target_goal,omitempty"`
	Confidence        float64           `json:"confidence"`
	IsGoalShift       bool              `json:"is_goal_shift,omitempty"`
	IsNewDiscovery    bool              `json:"is_new_discovery,omitempty"`
	IsPlanFollowing   bool              `json:"is_plan_following,omitempty"`
	IsPlanBreaking    bool              `json:"is_plan_breaking,omitempty"`
	ShouldPlan        bool              `json:"should_plan,omitempty"`
	ShouldScheduleLLM bool              `json:"should_schedule_llm,omitempty"`
	Events            []string          `json:"events,omitempty"`
	Decision          ExpansionDecision `json:"decision,omitempty"`
	Source            string            `json:"source,omitempty"`
}

func (r IntentResult) PlanKey() string {
	if r.TargetGoal != "" {
		return "goal:" + r.TargetGoal
	}
	if r.TargetSubnet != "" {
		return "subnet:" + r.TargetSubnet + ":" + r.Decision.Theme
	}
	if r.TargetIP != "" {
		return "host:" + r.TargetIP + ":" + r.Decision.Theme
	}
	return "intent:" + r.IntentType + ":" + r.Decision.Theme
}

// IntentRouterAgent combines a deterministic fast path with an optional LLM
// parser for ambiguous or natural-language attacker goals.
type IntentRouterAgent struct {
	llm      CompletionClient
	topology *domain.VirtualTopology
	mu       sync.Mutex
	cache    map[string]IntentResult
}

func NewIntentRouterAgent(topology *domain.VirtualTopology, llmClient CompletionClient) *IntentRouterAgent {
	return &IntentRouterAgent{
		llm:      llmClient,
		topology: topology,
		cache:    make(map[string]IntentResult),
	}
}

func (r *IntentRouterAgent) Route(event CommandEvent, session *domain.SessionContext) IntentResult {
	if r == nil {
		return RouteIntent(event.Command, session, nil, event.Profile)
	}
	fast := RouteIntent(event.Command, session, r.topology, event.Profile)
	fast.Source = "rule_fast_path"
	if !r.shouldAskLLM(event.Command, fast) {
		return fast
	}

	cacheKey := r.cacheKey(event, session)
	if cached, ok := r.lookup(cacheKey); ok {
		cached.Source = "intent_cache"
		return mergeIntentResults(fast, cached, session, r.topology)
	}

	// Fire async LLM call to enrich future routing decisions.
	// Return the rule-based fast-path result immediately so the
	// terminal stays responsive.
	go r.routeAsync(cacheKey, event, session, fast)

	return fast
}

func (r *IntentRouterAgent) routeAsync(cacheKey string, event CommandEvent, session *domain.SessionContext, fast IntentResult) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	llmIntent, err := r.routeWithLLM(ctx, event, session, fast)
	if err != nil {
		if session != nil {
			session.AppendEvent(domain.EventEntry{
				Type:      "intent_router_llm_failed",
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				SessionID: session.SessionID,
				Detail:    err.Error(),
			})
		}
		return
	}
	r.store(cacheKey, llmIntent)
}

func (r *IntentRouterAgent) shouldAskLLM(command string, fast IntentResult) bool {
	if completionClientInactive(r.llm) {
		return false
	}
	lower := strings.ToLower(strings.TrimSpace(command))
	if lower == "" {
		return false
	}
	if fast.Confidence < 0.75 {
		return true
	}
	if looksLikeNaturalLanguageGoal(lower) && (fast.TargetSubnet == "" || fast.TargetGoal == "") {
		return true
	}
	if fast.ShouldScheduleLLM && fast.TargetSubnet == "" && fast.TargetIP == "" {
		return true
	}
	return false
}

func (r *IntentRouterAgent) routeWithLLM(ctx context.Context, event CommandEvent, session *domain.SessionContext, fast IntentResult) (IntentResult, error) {
	req := llm.CompletionRequest{
		MaxTokens:      700,
		Temperature:    0.0,
		ResponseFormat: "json_object",
		Messages: []llm.Message{
			{Role: "system", Content: buildIntentRouterSystemPrompt()},
			{Role: "user", Content: buildIntentRouterUserPrompt(event, session, fast, r.topology)},
		},
	}
	resp, err := r.llm.Complete(ctx, req)
	if err != nil {
		return IntentResult{}, err
	}
	if strings.TrimSpace(resp.Content) == "" {
		return IntentResult{}, fmt.Errorf("empty LLM intent response")
	}
	var result IntentResult
	if err := json.Unmarshal([]byte(resp.Content), &result); err != nil {
		return IntentResult{}, fmt.Errorf("parse LLM intent: %w", err)
	}
	result.Source = "llm_intent_router"
	return sanitizeLLMIntent(result)
}

func (r *IntentRouterAgent) cacheKey(event CommandEvent, session *domain.SessionContext) string {
	goal := ""
	planID := ""
	if session != nil && session.Planning != nil {
		goal = session.Planning.AttackerGoal
		planID = session.Planning.ActivePlanID
	}
	return event.SessionID + "|" + planID + "|" + goal + "|" + normalizedCommand(event.Command)
}

func (r *IntentRouterAgent) lookup(key string) (IntentResult, bool) {
	if key == "" {
		return IntentResult{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	result, ok := r.cache[key]
	return result, ok
}

func (r *IntentRouterAgent) store(key string, result IntentResult) {
	if key == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.cache) > 128 {
		r.cache = make(map[string]IntentResult)
	}
	r.cache[key] = result
}

// RouteIntent keeps deterministic, latency-sensitive decisions out of the LLM
// path. The planner can still ask LLM for richer graph design after this.
func RouteIntent(command string, session *domain.SessionContext, topology *domain.VirtualTopology, profile AgentProfile) IntentResult {
	lower := strings.ToLower(strings.TrimSpace(command))
	result := IntentResult{IntentType: "general", Confidence: 0.35}
	if lower == "" {
		return result
	}

	if cidr := requestedCIDRPattern.FindString(lower); cidr != "" {
		result.TargetSubnet = cidr
		result.IntentType = "subnet_recon"
		result.IsNewDiscovery = true
		result.ShouldPlan = true
		result.Confidence = 0.92
	}
	if ip := requestedPrivateIPPattern.FindString(lower); ip != "" {
		result.TargetIP = ip
		if result.TargetSubnet == "" {
			result.TargetSubnet = cidrForHostIP(ip)
		}
		result.IntentType = "host_probe"
		result.IsNewDiscovery = true
		result.ShouldPlan = true
		result.Confidence = 0.88
	}
	if file := targetFile(lower); file != "" {
		result.TargetFile = file
		result.IntentType = "file_hunt"
		result.Confidence = 0.82
	}
	if service := targetService(lower); service != "" {
		result.TargetService = service
		result.IntentType = service + "_probe"
		result.Confidence = 0.8
	}

	theme := detectTheme(lower, profile)
	if theme != "" {
		result.TargetGoal = theme
		result.ShouldScheduleLLM = true
		if result.TargetSubnet == "" {
			result.TargetSubnet = DefaultCIDRForTheme(theme)
		}
		if result.IntentType == "general" {
			result.IntentType = theme + "_hunt"
		}
	}

	decision := DetectExpansionIntent(command, profile)
	if decision.Triggered {
		decision.PivotIP = DefaultPivotIP(topology, session)
		result.Decision = decision
		result.ShouldPlan = true
		result.ShouldScheduleLLM = true
		if result.TargetSubnet == "" {
			result.TargetSubnet = decision.CIDR
		}
		if result.TargetIP == "" {
			result.TargetIP = decision.TargetIP
		}
	}

	if result.TargetGoal != "" && session != nil && session.Planning != nil {
		goalSig := fmt.Sprintf("%s:%s:%s", result.TargetGoal, result.TargetSubnet, result.TargetIP)
		if session.Planning.AttackerGoal != "" && session.Planning.AttackerGoal != goalSig {
			result.IsGoalShift = true
			result.ShouldPlan = true
		}
	}
	if topology != nil {
		if result.TargetIP != "" && topology.GetHost(result.TargetIP) != nil {
			result.IsPlanFollowing = true
			result.ShouldPlan = false
		}
		if result.TargetSubnet != "" && topologyHasGoalLeadSegment(topology, result.TargetSubnet) && result.TargetGoal == "" {
			result.IsPlanFollowing = true
			result.ShouldPlan = false
			result.ShouldScheduleLLM = false
		}
		if result.TargetSubnet != "" && topologyHasBaseSegment(topology, result.TargetSubnet) && result.TargetGoal == "" {
			result.IsPlanFollowing = true
			result.ShouldPlan = false
		}
	}
	if strings.Contains(lower, "permission denied") || strings.Contains(lower, "try harder") || strings.Contains(lower, "no route") {
		result.IsPlanBreaking = true
		result.ShouldScheduleLLM = true
	}
	if result.ShouldPlan {
		result.Events = append(result.Events, "plan:"+result.PlanKey())
	}
	return result
}

func sanitizeLLMIntent(result IntentResult) (IntentResult, error) {
	result.IntentType = strings.TrimSpace(result.IntentType)
	if result.IntentType == "" {
		result.IntentType = "general"
	}
	if result.Confidence <= 0 || result.Confidence > 1 {
		result.Confidence = 0.65
	}
	result.TargetIP = strings.TrimSpace(result.TargetIP)
	result.TargetSubnet = strings.TrimSpace(result.TargetSubnet)
	result.TargetGoal = strings.TrimSpace(result.TargetGoal)
	result.TargetFile = strings.TrimSpace(result.TargetFile)
	result.TargetService = strings.TrimSpace(result.TargetService)
	result.TargetPort = strings.TrimSpace(result.TargetPort)

	if result.TargetIP != "" && !requestedPrivateIPPattern.MatchString(result.TargetIP) {
		result.TargetIP = ""
	}
	if result.TargetSubnet != "" {
		if _, _, err := net.ParseCIDR(result.TargetSubnet); err != nil || !requestedCIDRPattern.MatchString(result.TargetSubnet) {
			result.TargetSubnet = ""
		}
	}
	if result.TargetIP != "" && result.TargetSubnet == "" {
		result.TargetSubnet = cidrForHostIP(result.TargetIP)
	}
	if result.Decision.CIDR != "" {
		if _, _, err := net.ParseCIDR(result.Decision.CIDR); err != nil || !requestedCIDRPattern.MatchString(result.Decision.CIDR) {
			result.Decision.CIDR = ""
		}
	}
	if result.Decision.TargetIP != "" && !requestedPrivateIPPattern.MatchString(result.Decision.TargetIP) {
		result.Decision.TargetIP = ""
	}
	if result.TargetSubnet == "" && result.Decision.CIDR != "" {
		result.TargetSubnet = result.Decision.CIDR
	}
	if result.TargetIP == "" && result.Decision.TargetIP != "" {
		result.TargetIP = result.Decision.TargetIP
	}
	if result.TargetSubnet == "" && result.TargetIP == "" && result.ShouldPlan {
		result.ShouldPlan = false
	}
	if result.ShouldPlan && result.TargetSubnet != "" && !result.Decision.Triggered {
		result.Decision = DetectExpansionIntent(result.TargetSubnet+" "+result.TargetGoal+" "+result.TargetService+" "+result.TargetFile, AgentProfile{})
	}
	if result.Decision.Triggered {
		if result.Decision.CIDR == "" {
			result.Decision.CIDR = result.TargetSubnet
		}
		if result.Decision.TargetIP == "" {
			result.Decision.TargetIP = result.TargetIP
		}
		if result.Decision.Theme == "" {
			result.Decision.Theme = detectTheme(strings.ToLower(result.TargetGoal+" "+result.TargetFile+" "+result.TargetService+" "+result.IntentType), AgentProfile{})
		}
		if result.Decision.Theme == "" {
			result.Decision.Theme = "network"
		}
		if result.Decision.Reason == "" {
			result.Decision.Reason = "llm_intent:" + result.IntentType
		}
	}
	return result, nil
}

func mergeIntentResults(fast, llmResult IntentResult, session *domain.SessionContext, topology *domain.VirtualTopology) IntentResult {
	if llmResult.Confidence < 0.55 {
		return fast
	}
	merged := fast
	if llmResult.IntentType != "" && (fast.IntentType == "general" || llmResult.Confidence >= fast.Confidence) {
		merged.IntentType = llmResult.IntentType
	}
	if llmResult.TargetIP != "" {
		merged.TargetIP = llmResult.TargetIP
	}
	if llmResult.TargetPort != "" {
		merged.TargetPort = llmResult.TargetPort
	}
	if llmResult.TargetService != "" {
		merged.TargetService = llmResult.TargetService
	}
	if llmResult.TargetSubnet != "" {
		merged.TargetSubnet = llmResult.TargetSubnet
	}
	if llmResult.TargetFile != "" {
		merged.TargetFile = llmResult.TargetFile
	}
	if llmResult.TargetGoal != "" {
		merged.TargetGoal = llmResult.TargetGoal
	}
	if llmResult.Confidence > merged.Confidence {
		merged.Confidence = llmResult.Confidence
	}
	merged.IsNewDiscovery = merged.IsNewDiscovery || llmResult.IsNewDiscovery
	merged.IsPlanBreaking = merged.IsPlanBreaking || llmResult.IsPlanBreaking
	merged.ShouldPlan = merged.ShouldPlan || llmResult.ShouldPlan
	merged.ShouldScheduleLLM = merged.ShouldScheduleLLM || llmResult.ShouldScheduleLLM
	if llmResult.Decision.Triggered {
		merged.Decision = llmResult.Decision
	}
	merged.Source = llmResult.Source
	finalizeIntent(&merged, session, topology)
	return merged
}

func finalizeIntent(result *IntentResult, session *domain.SessionContext, topology *domain.VirtualTopology) {
	if result == nil {
		return
	}
	if result.TargetIP != "" && result.TargetSubnet == "" {
		result.TargetSubnet = cidrForHostIP(result.TargetIP)
	}
	if result.Decision.Triggered && result.Decision.PivotIP == "" {
		result.Decision.PivotIP = DefaultPivotIP(topology, session)
	}
	if result.TargetGoal != "" && session != nil && session.Planning != nil {
		goalSig := fmt.Sprintf("%s:%s:%s", result.TargetGoal, result.TargetSubnet, result.TargetIP)
		if session.Planning.AttackerGoal != "" && session.Planning.AttackerGoal != goalSig {
			result.IsGoalShift = true
			result.ShouldPlan = true
		}
	}
	if topology != nil {
		if result.TargetIP != "" && topology.GetHost(result.TargetIP) != nil {
			result.IsPlanFollowing = true
			result.ShouldPlan = false
		}
		if result.TargetSubnet != "" && topologyHasGoalLeadSegment(topology, result.TargetSubnet) && result.TargetGoal == "" {
			result.IsPlanFollowing = true
			result.ShouldPlan = false
			result.ShouldScheduleLLM = false
		}
		if result.TargetSubnet != "" && topologyHasBaseSegment(topology, result.TargetSubnet) && result.TargetGoal == "" {
			result.IsPlanFollowing = true
			result.ShouldPlan = false
		}
	}
	if result.ShouldPlan {
		event := "plan:" + result.PlanKey()
		if !intentHasString(result.Events, event) {
			result.Events = append(result.Events, event)
		}
	}
}

func intentHasString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func looksLikeNaturalLanguageGoal(lower string) bool {
	if domain.IsNetworkTouchCommand(lower) {
		return false
	}
	words := strings.Fields(lower)
	if len(words) < 3 {
		return false
	}
	markers := []string{"find", "locate", "目标", "靶标", "flag", "proof", "finance", "财务", "domain", "域控", "crown", "jewel", "数据库", "系统"}
	for _, marker := range markers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func buildIntentRouterSystemPrompt() string {
	return `You are AlterHive Intent Router Agent.
Return ONLY a compact JSON object matching:
{
  "intent_type": "recon|subnet_recon|host_probe|flag_hunt|finance_hunt|domain_hunt|credential_search|service_probe|file_hunt|general",
  "target_ip": "private IPv4 if explicitly implied",
  "target_port": "port string if present",
  "target_service": "ssh|mysql|redis|ldap|smb|http|jenkins|gitlab|kubectl|...",
  "target_subnet": "private /24 CIDR if implied",
  "target_file": "flag|.env|id_rsa|...",
  "target_goal": "short stable attacker goal",
  "confidence": 0.0,
  "is_goal_shift": false,
  "is_new_discovery": false,
  "is_plan_following": false,
  "is_plan_breaking": false,
  "should_plan": false,
  "should_schedule_llm": false,
  "decision": {"triggered":false,"cidr":"","target_ip":"","theme":"","pivot_ip":"","reason":""}
}
Rules:
- Do not invent public targets. Ignore public IPs.
- If the attacker expresses a goal but not an exact subnet, infer a plausible private /24 only when useful for shadow planning.
- Flag/terminal target goals must request planning, but should not indicate direct success.
- This agent classifies intent only; it must not generate terminal output.`
}

func buildIntentRouterUserPrompt(event CommandEvent, session *domain.SessionContext, fast IntentResult, topology *domain.VirtualTopology) string {
	payload := map[string]interface{}{
		"command":          event.Command,
		"cwd":              event.CWD,
		"user":             event.User,
		"hostname":         event.Hostname,
		"fast_path_intent": fast,
	}
	if session != nil && session.Planning != nil {
		payload["session"] = map[string]interface{}{
			"active_goal":       session.Planning.AttackerGoal,
			"active_plan_id":    session.Planning.ActivePlanID,
			"phase":             session.Planning.CurrentPhase,
			"evidence":          session.Evidence.Tokens(),
			"access_states":     session.AccessStateList(),
			"recent_command_no": len(session.CommandLog),
		}
	}
	if topology != nil {
		var hosts []string
		for _, host := range topology.AllHosts() {
			hosts = append(hosts, host.IP+" "+host.Hostname+" "+host.Role)
			if len(hosts) >= 12 {
				break
			}
		}
		payload["known_hosts"] = hosts
	}
	b, _ := json.Marshal(payload)
	return string(b)
}

func topologyHasGoalLeadSegment(topology *domain.VirtualTopology, cidr string) bool {
	for _, segment := range topology.AllSegments() {
		if segment.CIDR == cidr && segment.Shadow && segment.Zone == "goal" {
			return true
		}
	}
	return false
}

func topologyHasBaseSegment(topology *domain.VirtualTopology, cidr string) bool {
	for _, segment := range topology.AllSegments() {
		if segment.CIDR == cidr && !segment.Shadow {
			return true
		}
	}
	return false
}

func targetFile(command string) string {
	for _, marker := range []string{"flag", "proof", "root.txt", "user.txt", ".env", "id_rsa", "shadow", "passwd", "bash_history"} {
		if strings.Contains(command, marker) {
			return marker
		}
	}
	return ""
}

func targetService(command string) string {
	for _, marker := range []string{"ssh", "mysql", "redis", "ldap", "smb", "kerberos", "jenkins", "gitlab", "kubectl", "k8s"} {
		if strings.Contains(command, marker) {
			return marker
		}
	}
	return ""
}

func normalizedCommand(command string) string {
	return strings.TrimSpace(whitespacePattern.ReplaceAllString(strings.ToLower(command), " "))
}
