package deception

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/alterhive/alterhive/internal/domain"
	"github.com/alterhive/alterhive/internal/llm"
)

// WorldPatch is the common structured output produced by specialist agents.
type WorldPatch struct {
	Source          string               `json:"source,omitempty"`
	Reason          string               `json:"reason,omitempty"`
	AddedHosts      []domain.VirtualHost `json:"added_hosts,omitempty"`
	Files           []FileMutation       `json:"files,omitempty"`
	ServicePersonas []ServicePersona     `json:"service_personas,omitempty"`
	ExploitProfiles []ExploitProfile     `json:"exploit_profiles,omitempty"`
	Rejected        bool                 `json:"rejected,omitempty"`
	RejectReason    string               `json:"reject_reason,omitempty"`
}

type FileMutation struct {
	Path         string   `json:"path"`
	Content      string   `json:"content"`
	Owner        string   `json:"owner,omitempty"`
	Permissions  string   `json:"permissions,omitempty"`
	EvidenceID   string   `json:"evidence_id,omitempty"`
	Phase        string   `json:"phase,omitempty"`
	VisibleAfter []string `json:"visible_after,omitempty"`
}

type ServicePersona struct {
	HostIP   string `json:"host_ip"`
	Hostname string `json:"hostname,omitempty"`
	Service  string `json:"service"`
	Summary  string `json:"summary"`
}

type ExploitProfile struct {
	HostIP string `json:"host_ip"`
	Stage  string `json:"stage"`
	Policy string `json:"policy"`
}

type OrchestrationResult struct {
	Decision   RuntimeDecision
	Patches    []WorldPatch
	AddedHosts []domain.VirtualHost
	Rejected   []string
}

// AgentOrchestrator coordinates the full agent-driven deception pipeline.
// Hot Path (synchronous): Safety → Intent → Cache → Plan Executor → Rule/Renderer → Consistency → return
// Cold Path (asynchronous): EventBus → DeceptionPlanner → WorldBuilder → Evidence → Consistency → Safety → Cache → World Store
type AgentOrchestrator struct {
	topology *domain.VirtualTopology
	llm      CompletionClient
	planner  *TopologyPlanner
	router   *IntentRouterAgent
	agents   []WorldAgent
	critic   *ConsistencyCriticAgent
	mu       sync.Mutex
	planned  map[string]bool

	// Agent-driven architecture additions
	eventBus         *EventBus
	memoryAgent      *MemoryAgent
	cacheMgr         *CacheManagerAgent
	planExecutor     *PlanExecutor
	responseAgent    *ResponseAgent
	safetyAgent      *SafetyAgent
	deceptionPlanner *DeceptionPlannerAgent
	worldBuilder     *WorldBuilderAgent
	evidenceAgent    *EvidenceAgent
}

type WorldAgent interface {
	Name() string
	Plan(session *domain.SessionContext, world *domain.WorldState, command string, added []domain.VirtualHost) WorldPatch
}

func NewAgentOrchestrator(topology *domain.VirtualTopology, llmClient CompletionClient, safetyPolicy *domain.SafetyPolicy) *AgentOrchestrator {
	eventBus := NewEventBus()
	cacheMgr := NewCacheManager()
	memoryAgent := NewMemoryAgent()
	planExecutor := NewPlanExecutor(eventBus, cacheMgr)
	responseAgent := NewResponseAgent(topology, safetyPolicy)
	safetyAgent := NewSafetyAgent(safetyPolicy, eventBus)
	deceptionPlanner := NewDeceptionPlannerAgent(llmClient, topology)
	worldBuilder := NewWorldBuilderAgent(topology, cacheMgr)
	evidenceAgent := NewEvidenceAgent(cacheMgr)

	orchestrator := &AgentOrchestrator{
		topology: topology,
		llm:      llmClient,
		planner:  NewTopologyPlanner(topology, llmClient),
		router:   NewIntentRouterAgent(topology, llmClient),
		agents: []WorldAgent{
			LLMWorldPatchAgent{llm: llmClient, topology: topology},
			evidenceAgent,
			ServicePersonaAgent{},
			ExploitStageAgent{},
		},
		critic:           &ConsistencyCriticAgent{},
		planned:          make(map[string]bool),
		eventBus:         eventBus,
		memoryAgent:      memoryAgent,
		cacheMgr:         cacheMgr,
		planExecutor:     planExecutor,
		responseAgent:    responseAgent,
		safetyAgent:      safetyAgent,
		deceptionPlanner: deceptionPlanner,
		worldBuilder:     worldBuilder,
		evidenceAgent:    evidenceAgent,
	}

	// Wire EventBus subscribers for the Cold Path
	eventBus.Subscribe(EventTargetShift, orchestrator.onPlanningEvent)
	eventBus.Subscribe(EventNewSubnet, orchestrator.onPlanningEvent)
	eventBus.Subscribe(EventFlagHunt, orchestrator.onPlanningEvent)
	eventBus.Subscribe(EventPlanInvalidated, orchestrator.onPlanningEvent)

	return orchestrator
}

func (o *AgentOrchestrator) BeforeResponse(session *domain.SessionContext, world *domain.WorldState, command string, profile AgentProfile) OrchestrationResult {
	return o.HandleCommandEvent(NewCommandEvent(session, command, profile), session, world)
}

// HandleCommandEvent runs the Hot Path synchronously and publishes Cold Path
// events asynchronously when planning triggers are detected.
//
// Hot Path (sync): Plan Executor → Promote → Intent Route → Plan Cache → Specialist Agents → Consistency → return
// Cold Path (async): EventBus → DeceptionPlanner → WorldBuilder → Evidence → Plan Cache update
func (o *AgentOrchestrator) HandleCommandEvent(event CommandEvent, session *domain.SessionContext, world *domain.WorldState) OrchestrationResult {
	if o == nil || session == nil {
		return OrchestrationResult{}
	}
	var result OrchestrationResult

	// Hot Path Step 1: Plan Executor — check active plan validity
	if o.planExecutor != nil && session.Planning != nil && session.Planning.ActivePlanID != "" {
		_, planAction := o.planExecutor.ExecuteCommand(session, event.Command, IntentResult{})
		if planAction == ActionFullReplan {
			result.Decision = RuntimeDecision{Action: ActionFullReplan, Reason: "plan_executor_invalidated"}
			// Cold Path: publish replan event
			if o.eventBus != nil {
				o.eventBus.PublishAsync(PlanningEvent{
					Type:      EventPlanInvalidated,
					SessionID: session.SessionID,
					Command:   event.Command,
				})
			}
		}
	}

	// Hot Path Step 2: Promote ready candidate files
	if promoted := promoteCandidateFiles(session, world, event.Command); len(promoted.Files) > 0 {
		result.Patches = append(result.Patches, promoted)
	}

	// Hot Path Step 3: Intent Router — fast classification
	route := o.router.Route(event, session)
	result.Decision = BuildRuntimeDecision(event, route, session)
	if session.Planning != nil && route.TargetGoal != "" {
		session.Planning.SetGoal(route.PlanKey(), route.IntentType)
	}

	// Hot Path Step 4: Handle plan invalidation
	if session.Planning != nil && result.Decision.Action == ActionFullReplan {
		session.Planning.InvalidateActivePlan(result.Decision.Reason + ":" + route.PlanKey())
		session.AppendEvent(domain.EventEntry{
			Type:      "plan_invalidated",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			SessionID: session.SessionID,
			Detail:    result.Decision.Reason + ":" + route.PlanKey(),
		})
	}

	// Hot Path Step 5: Topology Planner (with plan cache)
	var added []domain.VirtualHost
	if route.ShouldPlan || route.ShouldScheduleLLM || result.Decision.Action == ActionFullReplan {
		planKey := session.SessionID + ":" + route.PlanKey()
		shouldRunPlanner := route.ShouldPlan && o.markPlanMiss(planKey)
		if shouldRunPlanner {
			if session.Planning != nil {
				session.Planning.RecordPlanCacheMiss()
			}
			added = o.planner.PlanDecision(session, event.Command, event.Profile, route.Decision, route.ShouldScheduleLLM)
		} else if route.ShouldPlan && session.Planning != nil {
			session.Planning.RecordPlanCacheHit()
		} else if route.ShouldScheduleLLM || result.Decision.Action == ActionFullReplan {
			o.planner.PlanDecision(session, event.Command, event.Profile, ExpansionDecision{}, true)
		}
	}
	if len(added) > 0 {
		result.AddedHosts = append(result.AddedHosts, added...)
		result.Patches = append(result.Patches, WorldPatch{
			Source:     "topology_planner_agent",
			Reason:     "planner_added_hosts",
			AddedHosts: added,
		})
	}

	// Hot Path Step 6: Specialist agents (Evidence, Service Persona, Exploit)
	for _, agent := range o.agents {
		patch := agent.Plan(session, world, event.Command, added)
		if patch.Source == "" {
			patch.Source = agent.Name()
		}
		if isEmptyPatch(patch) {
			continue
		}
		if rejected := o.critic.Review(patch, o.topology, session); rejected.Rejected {
			result.Rejected = append(result.Rejected, rejected.RejectReason)
			session.AppendEvent(domain.EventEntry{
				Type:      "agent_patch_rejected",
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				SessionID: session.SessionID,
				Detail:    rejected.Source + ":" + rejected.RejectReason,
			})
			continue
		}
		applyWorldPatch(session, world, patch, event.Command)
		result.Patches = append(result.Patches, patch)
	}

	// Hot Path Step 7: Update Memory Agent
	if o.memoryAgent != nil {
		o.memoryAgent.UpdateAttackerModel(session)
	}

	// Cold Path: Publish planning events for async processing
	if o.eventBus != nil && (route.ShouldScheduleLLM || route.ShouldPlan || route.IsGoalShift || route.IsNewDiscovery) {
		events := MapIntentToEvent(route, session.SessionID, event.Command)
		for _, ev := range events {
			o.eventBus.PublishAsync(ev)
		}
	}

	if len(result.Patches) > 0 {
		session.AppendEvent(domain.EventEntry{
			Type:      "agent_orchestration",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			SessionID: session.SessionID,
			Detail:    orchestrationSummary(result.Patches),
		})
	}
	return result
}

// onPlanningEvent is the Cold Path subscriber. When a high-priority event fires,
// it triggers the DeceptionPlanner → WorldBuilder → Evidence pipeline async.
func (o *AgentOrchestrator) onPlanningEvent(event PlanningEvent) *RuntimeAction {
	if o == nil || o.deceptionPlanner == nil || !o.deceptionPlanner.IsActive() {
		return nil
	}

	// Only trigger Cold Path for high-priority events
	if !EventNeedsReplan(event.Type) {
		return nil
	}

	// Build a synthetic intent from the event for the planner
	intent := IntentResult{
		IntentType:        string(event.Type),
		ShouldPlan:        true,
		ShouldScheduleLLM: true,
		Source:            "event_bus",
	}
	if subnet, ok := event.Payload["subnet"].(string); ok {
		intent.TargetSubnet = subnet
	}
	if goal, ok := event.Payload["goal"].(string); ok {
		intent.TargetGoal = goal
	}
	if ip, ok := event.Payload["ip"].(string); ok {
		intent.TargetIP = ip
	}

	// Async: Planner → WorldBuilder → Evidence
	o.deceptionPlanner.PlanAsync(nil, intent, event, func(plan DeceptionPlan, err error) {
		if err != nil {
			return
		}
		// The plan is produced; TopologyPlanner.MergeDeceptionPlan applies it
		// WorldBuilder and EvidenceAgent process the result on the next Hot Path cycle
	})

	action := ActionFullReplan
	return &action
}

func (o *AgentOrchestrator) markPlanMiss(key string) bool {
	if key == "" {
		return true
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.planned[key] {
		return false
	}
	o.planned[key] = true
	return true
}

func isEmptyPatch(patch WorldPatch) bool {
	return len(patch.Files) == 0 && len(patch.ServicePersonas) == 0 && len(patch.ExploitProfiles) == 0 && len(patch.AddedHosts) == 0
}

func applyWorldPatch(session *domain.SessionContext, world *domain.WorldState, patch WorldPatch, command string) {
	if world != nil {
		for _, file := range patch.Files {
			if !fileMutationVisibleNow(session, file, command) {
				if session != nil && session.Planning != nil {
					if session.Planning.StoreCandidateFile(candidateFileFromMutation(file, patch)) {
						session.AppendEvent(domain.EventEntry{
							Type:      "candidate_world_patch",
							Timestamp: time.Now().UTC().Format(time.RFC3339),
							SessionID: session.SessionID,
							Detail:    file.Path,
						})
					}
				}
				continue
			}
			entry := domain.NewFileEntry(file.Content)
			if file.Owner != "" {
				entry.Owner = file.Owner
				entry.Group = file.Owner
			}
			if file.Permissions != "" {
				entry.Permissions = file.Permissions
			}
			world.AddFile(file.Path, entry)
			if session != nil && session.Planning != nil {
				session.Planning.RecordEvidenceFact(domain.EvidenceArtifactFact{
					EvidenceID:   file.EvidenceID,
					Path:         file.Path,
					Status:       "exposed",
					Phase:        file.Phase,
					VisibleAfter: append([]string{}, file.VisibleAfter...),
					Source:       patch.Source,
					Reason:       patch.Reason,
				})
				session.Planning.BumpWorldVersion("file:" + file.Path)
			}
		}
	}
	for _, persona := range patch.ServicePersonas {
		if session != nil && session.Planning != nil {
			session.Planning.StoreServicePersona(domain.ServicePersonaFact{
				HostIP:   persona.HostIP,
				Hostname: persona.Hostname,
				Service:  persona.Service,
				Summary:  persona.Summary,
				Phase:    currentPlanPhase(session),
				Source:   patch.Source,
			})
		}
		if session != nil && session.Memory != nil {
			session.Memory.SetInvariant("service."+persona.HostIP+"."+persona.Service, persona.Summary, patch.Source)
		}
	}
	for _, profile := range patch.ExploitProfiles {
		if session != nil && session.Planning != nil {
			session.Planning.StoreExploitProfile(domain.ExploitProfileFact{
				HostIP: profile.HostIP,
				Stage:  profile.Stage,
				Policy: profile.Policy,
				Phase:  currentPlanPhase(session),
				Source: patch.Source,
			})
		}
		if session != nil && session.Memory != nil {
			session.Memory.SetInvariant("exploit."+profile.HostIP+"."+profile.Stage, profile.Policy, patch.Source)
		}
	}
}

func promoteCandidateFiles(session *domain.SessionContext, world *domain.WorldState, command string) WorldPatch {
	if session == nil || session.Planning == nil || world == nil {
		return WorldPatch{}
	}
	candidates := session.Planning.PromoteCandidateFiles(command, session)
	if len(candidates) == 0 {
		return WorldPatch{}
	}
	patch := WorldPatch{Source: "candidate_world_promoter", Reason: "candidate_facts_promoted_by_evidence"}
	for _, candidate := range candidates {
		file := FileMutation{
			Path:         candidate.Path,
			Content:      candidate.Content,
			Owner:        candidate.Owner,
			Permissions:  candidate.Permissions,
			EvidenceID:   candidate.EvidenceID,
			Phase:        candidate.Phase,
			VisibleAfter: append([]string{}, candidate.VisibleAfter...),
		}
		writeFileMutation(world, file)
		patch.Files = append(patch.Files, file)
		session.AppendEvent(domain.EventEntry{
			Type:      "candidate_world_promoted",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			SessionID: session.SessionID,
			Detail:    candidate.Path,
		})
	}
	return patch
}

func writeFileMutation(world *domain.WorldState, file FileMutation) {
	if world == nil {
		return
	}
	entry := domain.NewFileEntry(file.Content)
	if file.Owner != "" {
		entry.Owner = file.Owner
		entry.Group = file.Owner
	}
	if file.Permissions != "" {
		entry.Permissions = file.Permissions
	}
	world.AddFile(file.Path, entry)
}

func candidateFileFromMutation(file FileMutation, patch WorldPatch) domain.CandidateFileFact {
	return domain.CandidateFileFact{
		Path:         file.Path,
		Content:      file.Content,
		Owner:        file.Owner,
		Permissions:  file.Permissions,
		EvidenceID:   file.EvidenceID,
		Phase:        file.Phase,
		VisibleAfter: append([]string{}, file.VisibleAfter...),
		Source:       patch.Source,
		Reason:       patch.Reason,
	}
}

func fileMutationVisibleNow(session *domain.SessionContext, file FileMutation, command string) bool {
	if file.Phase != "" && !phaseAllowsEvidence(currentPlanPhase(session), file.Phase) {
		return false
	}
	if len(file.VisibleAfter) == 0 {
		return true
	}
	return canRevealEvidence(session, command, file.VisibleAfter, "")
}

func orchestrationSummary(patches []WorldPatch) string {
	var parts []string
	for _, patch := range patches {
		parts = append(parts, fmt.Sprintf("%s(files=%d personas=%d exploits=%d hosts=%d)", patch.Source, len(patch.Files), len(patch.ServicePersonas), len(patch.ExploitProfiles), len(patch.AddedHosts)))
	}
	return strings.Join(parts, "; ")
}

type LLMWorldPatchAgent struct {
	llm      CompletionClient
	topology *domain.VirtualTopology
}

func (LLMWorldPatchAgent) Name() string { return "llm_world_patch_agent" }

func (a LLMWorldPatchAgent) Plan(session *domain.SessionContext, world *domain.WorldState, command string, added []domain.VirtualHost) WorldPatch {
	if !shouldAskWorldPatchLLM(command, added) {
		return WorldPatch{}
	}
	if target := readFileTarget(command, session); target != "" && world != nil && world.GetFileEntry(target) != nil {
		return WorldPatch{}
	} else if target != "" && session != nil && session.Planning != nil && session.Planning.HasCandidateFile(target) {
		return WorldPatch{}
	}

	// Hot Path: always use local fallback for immediate (<1ms) response.
	// LLM enrichment runs asynchronously and lands on the next command cycle.
	fallback := localWorldPatchFallback(session, a.topology, command, added, "fast_path")

	if !completionClientInactive(a.llm) {
		if !allowLLMContextExport() {
			return fallback
		}
		// Cold Path: fire-and-forget LLM call with a short timeout.
		// Results are stored as events for the next Hot Path cycle.
		go a.planAsync(session, command, added)
	}

	return fallback
}

func (a LLMWorldPatchAgent) planAsync(session *domain.SessionContext, command string, added []domain.VirtualHost) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	req := llm.CompletionRequest{
		MaxTokens:      900,
		Temperature:    0.25,
		ResponseFormat: "json_object",
		Messages: []llm.Message{
			{Role: "system", Content: buildWorldPatchSystemPrompt()},
			{Role: "user", Content: buildWorldPatchUserPrompt(session, a.topology, command, added)},
		},
	}
	resp, err := a.llm.Complete(ctx, req)
	if err != nil || strings.TrimSpace(resp.Content) == "" {
		return
	}
	patch, err := parseWorldPatchContent(resp.Content)
	if err != nil || patch.Source == "" {
		return
	}
	patch = sanitizeWorldPatch(patch)
	patch.Source = "llm_world_patch_agent"
	if patch.Reason == "" {
		patch.Reason = "llm_async_enrichment"
	}

	// Store enrichment patch as a pending event for next Hot Path cycle.
	if session != nil {
		session.AppendEvent(domain.EventEntry{
			Type:      "llm_world_patch_async",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			SessionID: session.SessionID,
			Detail:    fmt.Sprintf("files=%d hosts=%d", len(patch.Files), len(patch.AddedHosts)),
		})
		// Store the patch payload so the next cycle can apply it.
		if data, err := json.Marshal(patch); err == nil {
			session.AppendEvent(domain.EventEntry{
				Type:      "llm_world_patch_payload",
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				SessionID: session.SessionID,
				Detail:    string(data),
			})
		}
	}
}

func localWorldPatchFallback(session *domain.SessionContext, topology *domain.VirtualTopology, command string, added []domain.VirtualHost, reason string) WorldPatch {
	patch := WorldPatch{Source: "local_world_patch_fallback", Reason: reason}
	lower := strings.ToLower(command)
	dbIP := firstTopologyHostIP(topology, "database")
	if dbIP == "" && session != nil && session.SubnetCIDR != "" {
		dbIP = cidrHostIP(session.SubnetCIDR, 60)
	}
	cacheIP := firstTopologyHostIP(topology, "cache")
	if cacheIP == "" && session != nil && session.SubnetCIDR != "" {
		cacheIP = cidrHostIP(session.SubnetCIDR, 30)
	}
	gitIP := firstTopologyHostIP(topology, "gitlab")
	if gitIP == "" && session != nil && session.SubnetCIDR != "" {
		gitIP = cidrHostIP(session.SubnetCIDR, 80)
	}

	switch {
	case strings.Contains(lower, "database.yml"):
		patch.Files = append(patch.Files, FileMutation{
			Path:        "/opt/webapp/config/database.yml",
			Owner:       "www-data",
			Permissions: "-rw-r-----",
			Content:     fmt.Sprintf("production:\n  adapter: mysql2\n  encoding: utf8mb4\n  database: fin_readonly_%s\n  username: web_ro\n  password: WebApp@2024!Ro\n  host: %s\n  port: 3306\n  reconnect: false\n", domain.DeploySeed, dbIP),
		})
	case strings.Contains(lower, "requirements.txt"):
		patch.Files = append(patch.Files, FileMutation{
			Path:        "/opt/webapp/requirements.txt",
			Owner:       "www-data",
			Permissions: "-rw-r--r--",
			Content:     "Flask==2.3.2\ngunicorn==20.1.0\nmysqlclient==2.2.0\nredis==4.5.4\nrequests==2.31.0\npython-dotenv==1.0.0\n",
		})
	case strings.Contains(lower, ".git/config"):
		patch.Files = append(patch.Files, FileMutation{
			Path:        "/opt/webapp/.git/config",
			Owner:       "www-data",
			Permissions: "-rw-r--r--",
			Content:     fmt.Sprintf("[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n[remote \"origin\"]\n\turl = http://%s/devops/webapp.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n[credential]\n\thelper = store --file /opt/webapp/.git-credentials\n", gitIP),
		})
	case strings.Contains(lower, "logs") || strings.Contains(lower, "app.log"):
		patch.Files = append(patch.Files, FileMutation{
			Path:        "/opt/webapp/logs/app.log",
			Owner:       "www-data",
			Permissions: "-rw-r--r--",
			Content:     fmt.Sprintf("2024-01-15 08:12:34 [INFO] Connected to MySQL at %s:3306\n2024-01-15 08:12:35 [INFO] Redis cache available at %s:6379\n2024-01-15 08:25:12 [WARN] GitLab webhook timeout http://%s/devops/webapp\n", dbIP, cacheIP, gitIP),
		})
	}

	for _, host := range added {
		patch.Files = append(patch.Files, FileMutation{
			Path:        path.Clean("/tmp/agent-plan-" + strings.ReplaceAll(strings.TrimSuffix(host.SegmentCIDR, "/24"), ".", "_") + ".txt"),
			Owner:       "root",
			Permissions: "-rw-r--r--",
			Content:     fmt.Sprintf("segment=%s\npivot=%s\ncandidate=%s %s\nstatus=requires pivot and partial exploit gate\n", host.SegmentCIDR, host.ReachableVia, host.IP, host.Hostname),
		})
		patch.ServicePersonas = append(patch.ServicePersonas, ServicePersona{
			HostIP:   host.IP,
			Hostname: host.Hostname,
			Service:  primaryService(host),
			Summary:  fmt.Sprintf("%s appears reachable only after pivot; expose partial breadcrumbs, not terminal access", host.Hostname),
		})
		patch.ExploitProfiles = append(patch.ExploitProfiles, ExploitProfile{
			HostIP: host.IP,
			Stage:  "partial",
			Policy: "delay with auth, network ACL, or read-only failure; never return final shell/flag",
		})
	}

	if len(patch.Files) == 0 && len(patch.ServicePersonas) == 0 && len(patch.ExploitProfiles) == 0 {
		return WorldPatch{}
	}
	return patch
}

func shouldAskWorldPatchLLM(command string, added []domain.VirtualHost) bool {
	if len(added) > 0 {
		return true
	}
	lower := strings.ToLower(command)
	return mentionsDirtyData(command) ||
		strings.Contains(lower, "nuclei") ||
		strings.Contains(lower, "sqlmap") ||
		strings.Contains(lower, "cve-") ||
		strings.Contains(lower, "gobuster") ||
		strings.Contains(lower, "ffuf") ||
		strings.Contains(lower, "find /") ||
		strings.Contains(lower, "config") ||
		strings.Contains(lower, "logs")
}

func allowLLMContextExport() bool {
	return strings.EqualFold(os.Getenv("ALTERHIVE_ALLOW_LLM_CONTEXT_EXPORT"), "true")
}

func readFileTarget(command string, session *domain.SessionContext) string {
	parts := strings.Fields(command)
	if len(parts) < 2 {
		return ""
	}
	switch parts[0] {
	case "cat", "head", "tail", "stat", "file":
	default:
		return ""
	}
	for _, arg := range parts[1:] {
		if strings.HasPrefix(arg, "-") || strings.Contains(arg, ">") || strings.Contains(arg, "|") {
			continue
		}
		if strings.HasPrefix(arg, "/") {
			return path.Clean(arg)
		}
		if session != nil && session.CWD != "" {
			return path.Clean(path.Join(session.CWD, arg))
		}
		return path.Clean(arg)
	}
	return ""
}

func buildWorldPatchSystemPrompt() string {
	return `You are AlterHive WorldPatch specialist agent.
Return exactly one JSON object matching this schema:
{
  "reason": "short reason",
  "files": [{"path": "/absolute/path", "content": "terminal-realistic file content", "owner": "root|www-data|deploy", "permissions": "-rw-r--r--", "evidence_id": "ev_short_id", "phase": "pivot_discovery|service_validation|exploit_gated|evidence_followup", "visible_after": ["subnet_scan","gate_jump01_lowpriv_shell"]}],
  "service_personas": [{"host_ip": "approved IP", "hostname": "name", "service": "http|ssh|mysql|redis|ldap|smb", "summary": "stable service persona"}],
  "exploit_profiles": [{"host_ip": "approved IP or current", "stage": "check|probe|partial", "policy": "partial progress only; no terminal success"}]
}
Rules:
- JSON only. No markdown. No explanations.
- Do not add hosts or subnets here; topology changes are handled by TopologyPlanner.
- Do not create flag values, domain admin, root shell success, owned/pwned claims, or final compromise.
- Only mention approved topology IPs or protected target IPs from the prompt.
- Prefer breadcrumbs, read-only credentials, logs, backups, CI traces, and partial exploit gates.
- Add visible_after and phase to evidence files when the clue should not be exposed immediately.
- Keep files concise and realistic; max 4 files.`
}

func buildWorldPatchUserPrompt(session *domain.SessionContext, topology *domain.VirtualTopology, command string, added []domain.VirtualHost) string {
	var b strings.Builder
	b.WriteString("Command:\n")
	b.WriteString(command)
	b.WriteString("\n\nSession:\n")
	if session != nil {
		b.WriteString(fmt.Sprintf("host=%s user=%s cwd=%s profile=%s\n", session.Hostname, session.User, session.CWD, session.DeceptionProfile))
		b.WriteString(fmt.Sprintf("entry=%s subnet=%s protected_targets=%s\n", session.EntryLocalIP, session.SubnetCIDR, protectedTargetList(session)))
		b.WriteString("recent commands:\n" + orchestrationCommandTail(session, 6) + "\n")
	}
	b.WriteString("\nApproved topology:\n")
	b.WriteString(formatTopologyForWorldPatch(topology))
	if len(added) > 0 {
		b.WriteString("\n\nNewly added hosts this turn:\n")
		for _, host := range added {
			b.WriteString(fmt.Sprintf("- %s %s role=%s segment=%s via=%s theme=%s gates=%s\n", host.IP, host.Hostname, host.Role, host.SegmentCIDR, host.ReachableVia, host.Theme, strings.Join(host.RequiredState, ",")))
		}
	}
	return b.String()
}

func protectedTargetList(session *domain.SessionContext) string {
	if session == nil || session.Planning == nil {
		return ""
	}
	return strings.Join(session.Planning.ProtectedTargetList(), ",")
}

func parseWorldPatchContent(content string) (WorldPatch, error) {
	obj := extractBalancedJSONObject(content)
	if obj == "" {
		obj = extractJSONObject(content)
	}
	var patch WorldPatch
	if err := json.Unmarshal([]byte(obj), &patch); err != nil {
		return WorldPatch{}, err
	}
	return patch, nil
}

func orchestrationCommandTail(session *domain.SessionContext, limit int) string {
	if session == nil || limit <= 0 || len(session.CommandLog) == 0 {
		return ""
	}
	start := len(session.CommandLog) - limit
	if start < 0 {
		start = 0
	}
	var cmds []string
	for _, entry := range session.CommandLog[start:] {
		cmds = append(cmds, entry.Command)
	}
	return strings.Join(cmds, "\n")
}

func formatTopologyForWorldPatch(topology *domain.VirtualTopology) string {
	if topology == nil {
		return "unavailable"
	}
	var lines []string
	for _, segment := range topology.AllSegments() {
		lines = append(lines, fmt.Sprintf("segment %s name=%s zone=%s shadow=%t", segment.CIDR, segment.Name, segment.Zone, segment.Shadow))
	}
	for _, edge := range topology.AllEdges() {
		lines = append(lines, fmt.Sprintf("edge %s -> %s type=%s via=%s required=%s status=%s", edge.From, edge.To, edge.Type, edge.Via, strings.Join(edge.RequiredState, ","), edge.Status))
	}
	for _, host := range topology.AllHosts() {
		lines = append(lines, fmt.Sprintf("host %s %s role=%s segment=%s via=%s required=%s shadow=%t", host.IP, host.Hostname, host.Role, host.SegmentCIDR, host.ReachableVia, strings.Join(host.RequiredState, ","), host.Shadow))
	}
	return strings.Join(lines, "\n")
}

func sanitizeWorldPatch(patch WorldPatch) WorldPatch {
	patch.AddedHosts = nil
	if len(patch.Files) > 4 {
		patch.Files = patch.Files[:4]
	}
	files := make([]FileMutation, 0, len(patch.Files))
	for _, file := range patch.Files {
		file.Path = path.Clean(file.Path)
		if !strings.HasPrefix(file.Path, "/") || file.Content == "" {
			continue
		}
		if file.Owner == "" {
			file.Owner = "root"
		}
		if file.Permissions == "" {
			file.Permissions = "-rw-r--r--"
		}
		if len(file.Content) > 3000 {
			file.Content = file.Content[:3000]
		}
		files = append(files, file)
	}
	patch.Files = files
	return patch
}

func firstTopologyHostIP(topology *domain.VirtualTopology, roleNeedle string) string {
	if topology == nil {
		return ""
	}
	roleNeedle = strings.ToLower(roleNeedle)
	for _, host := range topology.AllHosts() {
		if strings.Contains(strings.ToLower(host.Role), roleNeedle) || strings.Contains(strings.ToLower(host.Hostname), roleNeedle) {
			return host.IP
		}
	}
	return ""
}

func cidrHostIP(cidr string, hostOctet int) string {
	base := strings.TrimSuffix(cidr, "/24")
	parts := strings.Split(base, ".")
	if len(parts) != 4 {
		return ""
	}
	parts[3] = fmt.Sprintf("%d", hostOctet)
	return strings.Join(parts, ".")
}

func primaryService(host domain.VirtualHost) string {
	if len(host.Services) == 0 {
		return "unknown"
	}
	return host.Services[0].Protocol
}

type DirtyDataAgent struct{}

func (DirtyDataAgent) Name() string { return "dirty_data_agent" }

func (DirtyDataAgent) Plan(session *domain.SessionContext, world *domain.WorldState, command string, added []domain.VirtualHost) WorldPatch {
	if len(added) == 0 && !mentionsDirtyData(command) {
		return WorldPatch{}
	}
	patch := WorldPatch{Source: "dirty_data_agent", Reason: "support topology with local artifacts"}
	phase := currentPlanPhase(session)
	evidenceHosts := added
	if len(evidenceHosts) == 0 && phaseAllowsEvidence(phase, "service_validation") {
		evidenceHosts = shadowHostsForEvidence(session)
	}
	for _, host := range evidenceHosts {
		pivotIP := host.ReachableVia
		if pivotIP == "" {
			pivotIP = DefaultPivotIP(nil, session)
		}
		safeCIDR := strings.ReplaceAll(strings.TrimSuffix(host.SegmentCIDR, "/24"), ".", "_")
		if safeCIDR == "" {
			safeCIDR = strings.ReplaceAll(host.IP, ".", "_")
		}
		if len(added) > 0 && canRevealEvidence(session, command, []string{"subnet_scan"}, "") {
			patch.Files = append(patch.Files, FileMutation{
				Path:         path.Clean("/tmp/discovered_" + safeCIDR + ".txt"),
				Owner:        session.User,
				Permissions:  "-rw-r--r--",
				EvidenceID:   "ev_subnet_discovery_" + safeCIDR,
				Phase:        phase,
				VisibleAfter: []string{"subnet_scan"},
				Content: fmt.Sprintf("# discovered during internal recon\nsegment=%s\npivot=%s\nhost=%s %s role=%s\nstate=filtered until next credential/pivot gate\n",
					host.SegmentCIDR, pivotIP, host.IP, host.Hostname, host.Role),
			})
		}
		if phaseAllowsEvidence(phase, "service_validation") && canRevealEvidence(session, command, []string{"subnet_scan"}, GateReconObserved) {
			patch.Files = append(patch.Files, FileMutation{
				Path:         path.Clean("/opt/webapp/logs/" + host.Theme + "_upstream.log"),
				Owner:        "www-data",
				Permissions:  "-rw-r--r--",
				EvidenceID:   "ev_service_upstream_" + safeCIDR,
				Phase:        phase,
				VisibleAfter: []string{"subnet_scan", GateReconObserved},
				Content: fmt.Sprintf("2024-01-15 09:11:42 [WARN] upstream %s (%s) reachable only via jump01\n2024-01-15 09:12:07 [INFO] cached credentials are low privilege and read-only\n",
					host.Hostname, host.IP),
			})
		}
		if phaseAllowsEvidence(phase, "evidence_followup") && canRevealEvidence(session, command, []string{"subnet_scan"}, GateExploitPartial) {
			patch.Files = append(patch.Files, FileMutation{
				Path:         path.Clean("/tmp/flag-trace-" + safeCIDR + ".txt"),
				Owner:        "root",
				Permissions:  "-rw-r-----",
				EvidenceID:   "ev_flag_trace_" + safeCIDR,
				Phase:        phase,
				VisibleAfter: []string{"subnet_scan", GateExploitPartial},
				Content: fmt.Sprintf("artifact_branch=%s\npivot=%s\ncandidate=%s %s\nnote=trace points to a second-hop evidence store; direct flag access remains unavailable\n",
					host.SegmentCIDR, pivotIP, host.IP, host.Hostname),
			})
		}
	}
	if mentionsDirtyData(command) && canRevealEvidence(session, command, []string{"app_config"}, "") {
		patch.Files = append(patch.Files, FileMutation{
			Path:         "/home/deploy/ops-notes.txt",
			Owner:        "deploy",
			Permissions:  "-rw-------",
			EvidenceID:   "ev_ops_notes",
			Phase:        phase,
			VisibleAfter: []string{"app_config"},
			Content:      "jump01 is the only approved pivot. Jenkins/GitLab tokens are read-only; finance and domain systems require a second service auth gate.\n",
		})
	}
	return patch
}

func currentPlanPhase(session *domain.SessionContext) string {
	if session == nil || session.Planning == nil || session.Planning.CurrentPhase == "" {
		return "recon"
	}
	return session.Planning.CurrentPhase
}

func shadowHostsForEvidence(session *domain.SessionContext) []domain.VirtualHost {
	if session == nil {
		return nil
	}
	var hosts []domain.VirtualHost
	for _, item := range session.ShadowHosts {
		ip := item["ip"]
		if ip == "" {
			continue
		}
		hosts = append(hosts, domain.VirtualHost{
			IP:           ip,
			Hostname:     item["hostname"],
			Role:         item["role"],
			SegmentCIDR:  item["segment_cidr"],
			ReachableVia: item["reachable_via"],
			Theme:        item["theme"],
		})
		if len(hosts) >= 3 {
			break
		}
	}
	return hosts
}

func phaseAllowsEvidence(current, required string) bool {
	if required == "" || current == required {
		return true
	}
	order := map[string]int{
		"recon":              0,
		"pivot_discovery":    1,
		"service_validation": 2,
		"exploit_gated":      3,
		"evidence_followup":  4,
	}
	return order[current] >= order[required]
}

func canRevealEvidence(session *domain.SessionContext, command string, visibleAfter []string, gate string) bool {
	if gate != "" && (session == nil || !session.HasAccessState(gate)) {
		return false
	}
	if len(visibleAfter) == 0 {
		return true
	}
	commandHits := map[string]bool{}
	for _, token := range domain.CheckEvidence(command, map[string]bool{}) {
		commandHits[token] = true
	}
	for _, token := range visibleAfter {
		if strings.HasPrefix(token, "gate_") {
			if session == nil || !session.HasAccessState(token) {
				return false
			}
			continue
		}
		if commandHits[token] {
			continue
		}
		if session != nil && session.Evidence != nil && session.Evidence.Has(token) {
			continue
		}
		return false
	}
	return true
}

type ServicePersonaAgent struct{}

func (ServicePersonaAgent) Name() string { return "service_persona_agent" }

func (ServicePersonaAgent) Plan(session *domain.SessionContext, world *domain.WorldState, command string, added []domain.VirtualHost) WorldPatch {
	if len(added) == 0 {
		return WorldPatch{}
	}
	patch := WorldPatch{Source: "service_persona_agent", Reason: "attach service identity invariants"}
	for _, host := range added {
		for _, svc := range host.Services {
			name := svc.NmapName
			if name == "" {
				name = svc.Protocol
			}
			patch.ServicePersonas = append(patch.ServicePersonas, ServicePersona{
				HostIP:   host.IP,
				Hostname: host.Hostname,
				Service:  svc.Protocol,
				Summary:  fmt.Sprintf("%s/%d on %s (%s) failure=%s", name, svc.Port, host.Hostname, host.OS, svc.FailureMode),
			})
		}
	}
	return patch
}

type ExploitStageAgent struct{}

func (ExploitStageAgent) Name() string { return "exploit_stage_agent" }

func (ExploitStageAgent) Plan(session *domain.SessionContext, world *domain.WorldState, command string, added []domain.VirtualHost) WorldPatch {
	lower := strings.ToLower(command)
	if len(added) == 0 && !strings.Contains(lower, "cve-") && !strings.Contains(lower, "nuclei") && !strings.Contains(lower, "sqlmap") && !strings.Contains(lower, "cmd=") {
		return WorldPatch{}
	}
	patch := WorldPatch{Source: "exploit_stage_agent", Reason: "stage exploit responses without terminal success"}
	for _, host := range added {
		patch.ExploitProfiles = append(patch.ExploitProfiles, ExploitProfile{
			HostIP: host.IP,
			Stage:  "check",
			Policy: "maybe_vulnerable; exploit requires auth/pivot; block terminal success",
		})
	}
	if len(patch.ExploitProfiles) == 0 {
		patch.ExploitProfiles = append(patch.ExploitProfiles, ExploitProfile{
			HostIP: "current",
			Stage:  "probe",
			Policy: "partial evidence only; prefer timeout, permission denied, or read-only sandbox",
		})
	}
	return patch
}

type ConsistencyCriticAgent struct{}

func (ConsistencyCriticAgent) Review(patch WorldPatch, topology *domain.VirtualTopology, session *domain.SessionContext) WorldPatch {
	for _, file := range patch.Files {
		lower := strings.ToLower(file.Content)
		if strings.Contains(lower, "flag{") || strings.Contains(lower, "domain admin") || strings.Contains(lower, "root shell established") {
			patch.Rejected = true
			patch.RejectReason = "terminal_success_in_file_patch"
			return patch
		}
		if guarded := GuardTerminalOutput(file.Content, session); guarded.Blocked {
			patch.Rejected = true
			patch.RejectReason = "unsafe_terminal_content:" + guarded.Reason
			return patch
		}
		if guarded := GuardResponseFacts(file.Content, session, topology); guarded.Blocked {
			patch.Rejected = true
			patch.RejectReason = "unsafe_file_fact:" + guarded.Reason
			return patch
		}
	}
	for _, host := range patch.AddedHosts {
		if host.CompromiseMode == "success" || host.CompromiseMode == "owned" {
			patch.Rejected = true
			patch.RejectReason = "terminal_success_host"
			return patch
		}
	}
	return patch
}

func mentionsDirtyData(command string) bool {
	lower := strings.ToLower(command)
	return strings.Contains(lower, ".env") ||
		strings.Contains(lower, "password") ||
		strings.Contains(lower, "token") ||
		strings.Contains(lower, "secret") ||
		strings.Contains(lower, "config") ||
		strings.Contains(lower, "log") ||
		strings.Contains(lower, "history") ||
		strings.Contains(lower, "backup")
}
