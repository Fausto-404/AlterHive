package deception

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/alterhive/alterhive/internal/domain"
	"github.com/alterhive/alterhive/internal/llm"
)

// MemoryLayer classifies information by how it is used during planning and response.
type MemoryLayer string

const (
	LayerHotState       MemoryLayer = "hot_state"       // current command context, always injected
	LayerExposedFacts   MemoryLayer = "exposed_facts"    // seen by attacker, permanently locked
	LayerCandidateFacts MemoryLayer = "candidate_facts"  // planned but unexposed, replaceable
	LayerHiddenPlan     MemoryLayer = "hidden_plan"      // internal deception plan, never returned
	LayerArchiveMemory  MemoryLayer = "archive_memory"   // compressed historical summaries
	LayerAttackerModel  MemoryLayer = "attacker_model"   // behavior profile
	LayerPlanGraph      MemoryLayer = "plan_graph"       // active deception plan graph
	LayerCacheMetadata  MemoryLayer = "cache_metadata"   // hit/miss tracking
)

// HotStateSnapshot captures everything needed for the current command context.
type HotStateSnapshot struct {
	Hostname      string   `json:"hostname"`
	User          string   `json:"user"`
	CWD           string   `json:"cwd"`
	ShellMode     string   `json:"shell_mode"`
	LocalIP       string   `json:"local_ip"`
	SubnetCIDR    string   `json:"subnet_cidr"`
	IsNested      bool     `json:"is_nested"`
	CurrentTarget string   `json:"current_target,omitempty"`
	AccessStates  []string `json:"access_states,omitempty"`
	ActivePlanID  string   `json:"active_plan_id,omitempty"`
	CurrentPhase  string   `json:"current_phase,omitempty"`
	CommandCount  int      `json:"command_count"`
}

// AttackerModelSummary captures the current understanding of attacker behavior.
type AttackerModelSummary struct {
	SkillLevel      string   `json:"skill_level"`
	BehaviorType    string   `json:"behavior_type"`
	ToolsUsed       []string `json:"tools_used"`
	PrimaryGoal     string   `json:"primary_goal"`
	DeadEndCount    int      `json:"dead_end_count"`
	EvidenceHits    int      `json:"evidence_hits"`
	PivotAttempts   int      `json:"pivot_attempts"`
	FlagHuntSignals int      `json:"flag_hunt_signals"`
}

// PlanGraphNode describes a node in the active deception plan graph.
type PlanGraphNode struct {
	ID          string   `json:"id"`
	Type        string   `json:"type"` // segment, host, gate, evidence, breadcrumb
	Status      string   `json:"status"`
	DependsOn   []string `json:"depends_on,omitempty"`
	UnlockedBy  []string `json:"unlocked_by,omitempty"`
	Description string   `json:"description"`
}

// MemoryAgent wraps domain.DeceptionMemory with explicit state layering for the
// multi-agent architecture. It manages Hot State, Exposed Facts, Candidate Facts,
// Hidden Plans, Archive Memory, Attacker Models, Plan Graphs, and Cache Metadata.
type MemoryAgent struct {
	mu              sync.RWMutex
	exposedFacts    map[string][]string // sessionID -> facts
	candidateFacts  map[string][]string
	hiddenPlans     map[string][]string
	planGraphs      map[string][]PlanGraphNode
	attackerModels  map[string]*AttackerModelSummary
	archiveSnapshots map[string][]string
}

// NewMemoryAgent creates a ready-to-use memory agent.
func NewMemoryAgent() *MemoryAgent {
	return &MemoryAgent{
		exposedFacts:     make(map[string][]string),
		candidateFacts:   make(map[string][]string),
		hiddenPlans:      make(map[string][]string),
		planGraphs:       make(map[string][]PlanGraphNode),
		attackerModels:   make(map[string]*AttackerModelSummary),
		archiveSnapshots: make(map[string][]string),
	}
}

// SnapshotHotState captures the current command context from a session.
func (m *MemoryAgent) SnapshotHotState(session *domain.SessionContext) HotStateSnapshot {
	if session == nil {
		return HotStateSnapshot{}
	}
	planID := ""
	phase := ""
	if session.Planning != nil {
		planID = session.Planning.ActivePlanID
		phase = session.Planning.CurrentPhase
	}
	return HotStateSnapshot{
		Hostname:      session.Hostname,
		User:          session.User,
		CWD:           session.CWD,
		ShellMode:     session.ShellMode,
		LocalIP:       session.SubnetLocalIP,
		SubnetCIDR:    session.SubnetCIDR,
		IsNested:      session.IsNestedSSH(),
		CurrentTarget: session.GetCurrentTarget(),
		AccessStates:  session.AccessStateList(),
		ActivePlanID:  planID,
		CurrentPhase:  phase,
		CommandCount:  len(session.CommandLog),
	}
}

// HotStatePrompt renders the hot state as a compact system prompt fragment (~200 tokens).
func (m *MemoryAgent) HotStatePrompt(session *domain.SessionContext) string {
	snap := m.SnapshotHotState(session)
	var b strings.Builder
	b.WriteString(fmt.Sprintf("You are a Linux terminal on host %s (%s).\n", snap.Hostname, snap.LocalIP))
	b.WriteString(fmt.Sprintf("OS: Ubuntu 22.04.3 LTS, Kernel: 5.15.0-91-generic\n"))
	b.WriteString(fmt.Sprintf("Current user: %s, CWD: %s, Shell: %s\n", snap.User, snap.CWD, snap.ShellMode))
	if snap.IsNested {
		b.WriteString(fmt.Sprintf("You are in a nested SSH session on %s.\n", snap.CurrentTarget))
	}
	if len(snap.AccessStates) > 0 {
		b.WriteString(fmt.Sprintf("Unlocked gates: %s\n", strings.Join(snap.AccessStates, ", ")))
	}
	b.WriteString("Respond ONLY with terminal output. No markdown, no explanations, no AI disclosure.\n")
	return b.String()
}

// RecordExposedFact permanently locks a fact that the attacker has seen.
func (m *MemoryAgent) RecordExposedFact(sessionID, fact string) {
	if sessionID == "" || fact == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	existing := m.exposedFacts[sessionID]
	for _, f := range existing {
		if f == fact {
			return
		}
	}
	m.exposedFacts[sessionID] = append(existing, fact)
	if len(m.exposedFacts[sessionID]) > 200 {
		m.exposedFacts[sessionID] = m.exposedFacts[sessionID][len(m.exposedFacts[sessionID])-200:]
	}
}

// IsExposedFact returns true if the attacker has already seen this fact.
func (m *MemoryAgent) IsExposedFact(sessionID, fact string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, f := range m.exposedFacts[sessionID] {
		if strings.Contains(f, fact) || strings.Contains(fact, f) {
			return true
		}
	}
	return false
}

// ExposedFacts returns all permanently locked facts for a session.
func (m *MemoryAgent) ExposedFacts(sessionID string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]string{}, m.exposedFacts[sessionID]...)
}

// RecordCandidateFact stores a planned-but-unexposed fact.
func (m *MemoryAgent) RecordCandidateFact(sessionID, fact string) {
	if sessionID == "" || fact == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.candidateFacts[sessionID] = append(m.candidateFacts[sessionID], fact)
}

// ReplaceCandidateFacts atomically replaces all candidate facts for a replan.
func (m *MemoryAgent) ReplaceCandidateFacts(sessionID string, facts []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.candidateFacts[sessionID] = append([]string{}, facts...)
}

// RecordHiddenPlan stores an internal deception plan that must never be returned.
func (m *MemoryAgent) RecordHiddenPlan(sessionID, planSummary string) {
	if sessionID == "" || planSummary == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hiddenPlans[sessionID] = append(m.hiddenPlans[sessionID], planSummary)
	if len(m.hiddenPlans[sessionID]) > 20 {
		m.hiddenPlans[sessionID] = m.hiddenPlans[sessionID][len(m.hiddenPlans[sessionID])-20:]
	}
}

// UpdatePlanGraph records a node in the active deception plan graph.
func (m *MemoryAgent) UpdatePlanGraph(sessionID string, node PlanGraphNode) {
	if sessionID == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, existing := range m.planGraphs[sessionID] {
		if existing.ID == node.ID {
			m.planGraphs[sessionID][i] = node
			return
		}
	}
	m.planGraphs[sessionID] = append(m.planGraphs[sessionID], node)
}

// PlanGraph returns the current plan graph for a session.
func (m *MemoryAgent) PlanGraph(sessionID string) []PlanGraphNode {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]PlanGraphNode{}, m.planGraphs[sessionID]...)
}

// UpdateAttackerModel refreshes the attacker behavior profile.
func (m *MemoryAgent) UpdateAttackerModel(session *domain.SessionContext) {
	if session == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	profile := ProfileFromSession(session)
	model := &AttackerModelSummary{
		SkillLevel:      profile.PrimaryStyle,
		BehaviorType:    profile.PrimaryStyle,
		DeadEndCount:    session.DeadEnd.DeadEndCount(),
		EvidenceHits:    session.Evidence.HitCount(),
		PrimaryGoal:     "",
	}
	if session.Planning != nil {
		model.PrimaryGoal = session.Planning.AttackerGoal
	}

	// Count flag hunt signals
	for _, entry := range session.CommandLog {
		lower := strings.ToLower(entry.Command)
		if strings.Contains(lower, "flag") || strings.Contains(lower, "proof") {
			model.FlagHuntSignals++
		}
		if strings.Contains(lower, "ssh ") || strings.Contains(lower, "mysql -h") {
			model.PivotAttempts++
		}
	}
	m.attackerModels[session.SessionID] = model
}

// AttackerModel returns the cached attacker model for a session.
func (m *MemoryAgent) AttackerModel(sessionID string) *AttackerModelSummary {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.attackerModels[sessionID]
}

// ArchiveCompress generates a compressed summary of recent commands.
func (m *MemoryAgent) ArchiveCompress(session *domain.SessionContext, maxEntries int) string {
	if session == nil || len(session.CommandLog) == 0 {
		return ""
	}
	log := session.CommandLog
	if len(log) > maxEntries {
		log = log[len(log)-maxEntries:]
	}
	var lines []string
	for _, entry := range log {
		summary := fmt.Sprintf("%s → %s", truncateCommand(entry.Command, 60), truncateOutput(entry.Output, 40))
		lines = append(lines, summary)
	}
	archive := strings.Join(lines, "\n")
	m.mu.Lock()
	m.archiveSnapshots[session.SessionID] = append(m.archiveSnapshots[session.SessionID], archive)
	if len(m.archiveSnapshots[session.SessionID]) > 10 {
		m.archiveSnapshots[session.SessionID] = m.archiveSnapshots[session.SessionID][1:]
	}
	m.mu.Unlock()
	return archive
}

// BuildLLMContext constructs the full LLM prompt context with L0/L1/L2 layering.
func (m *MemoryAgent) BuildLLMContext(session *domain.SessionContext, command string) []llm.Message {
	var messages []llm.Message

	// L0: Always inject — hot state (~200 tokens)
	messages = append(messages, llm.Message{
		Role:    "system",
		Content: m.HotStatePrompt(session),
	})

	// L1: Context-aware — recent activity summary
	if session.Memory != nil {
		summary := session.Memory.PromptSummary()
		if summary != "" {
			messages = append(messages, llm.Message{
				Role:    "system",
				Content: "## Recent activity:\n" + summary,
			})
		}
	}

	// Working memory — last 3 commands
	recent := recentCommandPairs(session, 3)
	for _, pair := range recent {
		messages = append(messages, llm.Message{Role: "user", Content: pair.Command})
		messages = append(messages, llm.Message{Role: "assistant", Content: pair.Output})
	}

	// Current command
	messages = append(messages, llm.Message{Role: "user", Content: command})
	return messages
}

// CleanupSession removes all per-session memory when a session is deleted.
func (m *MemoryAgent) CleanupSession(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.exposedFacts, sessionID)
	delete(m.candidateFacts, sessionID)
	delete(m.hiddenPlans, sessionID)
	delete(m.planGraphs, sessionID)
	delete(m.attackerModels, sessionID)
	delete(m.archiveSnapshots, sessionID)
}

func truncateCommand(cmd string, maxLen int) string {
	cmd = strings.TrimSpace(cmd)
	if len(cmd) <= maxLen {
		return cmd
	}
	return cmd[:maxLen-3] + "..."
}

func truncateOutput(out string, maxLen int) string {
	out = strings.TrimSpace(out)
	// Take first line only
	if idx := strings.Index(out, "\n"); idx > 0 {
		out = out[:idx]
	}
	if len(out) <= maxLen {
		return out
	}
	return out[:maxLen-3] + "..."
}

func recentCommandPairs(session *domain.SessionContext, limit int) []domain.CommandEntry {
	if session == nil || limit <= 0 || len(session.CommandLog) == 0 {
		return nil
	}
	start := len(session.CommandLog) - limit
	if start < 0 {
		start = 0
	}
	return session.CommandLog[start:]
}

// ExposedFactSet returns exposed facts as a set for fast lookup.
func (m *MemoryAgent) ExposedFactSet(sessionID string) map[string]bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	set := make(map[string]bool, len(m.exposedFacts[sessionID]))
	for _, f := range m.exposedFacts[sessionID] {
		set[f] = true
	}
	return set
}

// CandidateFactSummary returns candidate facts sorted for display.
func (m *MemoryAgent) CandidateFactSummary(sessionID string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	facts := append([]string{}, m.candidateFacts[sessionID]...)
	sort.Strings(facts)
	return facts
}
