package domain

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// VirtualService represents a service on a virtual host.
type VirtualService struct {
	Port        int    `yaml:"port"`
	Protocol    string `yaml:"protocol"`
	NmapName    string `yaml:"nmap_name"`
	Banner      string `yaml:"banner"`
	FailureMode string `yaml:"failure_mode"` // refused, auth_denied, access_denied, auth_required, stronger_auth_required, redirect_login
}

// VirtualHost represents a host in the virtual subnet.
type VirtualHost struct {
	IP             string           `yaml:"ip" json:"ip"`
	Hostname       string           `yaml:"hostname" json:"hostname"`
	Role           string           `yaml:"role" json:"role"`
	OS             string           `yaml:"os" json:"os"`
	Priority       int              `yaml:"priority" json:"priority"`
	CanaryID       string           `yaml:"canary_id" json:"canary_id"`
	Services       []VirtualService `yaml:"services" json:"services"`
	VisibleAfter   []string         `yaml:"visible_after" json:"visible_after"`
	SegmentCIDR    string           `yaml:"segment_cidr" json:"segment_cidr"`
	ReachableVia   string           `yaml:"reachable_via" json:"reachable_via"`
	RequiredState  []string         `yaml:"required_state" json:"required_state"`
	Shadow         bool             `yaml:"shadow" json:"shadow"`
	Theme          string           `yaml:"theme" json:"theme"`
	CompromiseMode string           `yaml:"compromise_mode" json:"compromise_mode"`
	Password       string           `yaml:"password" json:"password"` // SSH password for this host
	OwnerSessionID string           `yaml:"owner_session_id,omitempty" json:"owner_session_id,omitempty"`
}

// NetworkSegment represents a routed subnet in the simulated internal network.
type NetworkSegment struct {
	CIDR           string   `yaml:"cidr" json:"cidr"`
	Name           string   `yaml:"name" json:"name"`
	Zone           string   `yaml:"zone" json:"zone"`
	GatewayIP      string   `yaml:"gateway_ip" json:"gateway_ip"`
	Shadow         bool     `yaml:"shadow" json:"shadow"`
	VisibleAfter   []string `yaml:"visible_after" json:"visible_after"`
	OwnerSessionID string   `yaml:"owner_session_id,omitempty" json:"owner_session_id,omitempty"`
}

// NetworkEdge describes how a subnet or host is reachable in the illusion graph.
type NetworkEdge struct {
	From           string   `yaml:"from" json:"from"`
	To             string   `yaml:"to" json:"to"`
	Type           string   `yaml:"type" json:"type"`
	Via            string   `yaml:"via" json:"via"`
	RequiredState  []string `yaml:"required_state" json:"required_state"`
	Status         string   `yaml:"status" json:"status"`
	OwnerSessionID string   `yaml:"owner_session_id,omitempty" json:"owner_session_id,omitempty"`
}

// EvidenceState tracks discovered evidence tokens for a session.
type EvidenceState struct {
	mu   sync.RWMutex
	hits map[string]bool
}

func NewEvidenceState() *EvidenceState {
	return &EvidenceState{hits: make(map[string]bool)}
}

func (e *EvidenceState) Hit(token string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.hits[token] = true
}

func (e *EvidenceState) Has(token string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.hits[token]
}

func (e *EvidenceState) HitCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.hits)
}

func (e *EvidenceState) Tokens() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	tokens := make([]string, 0, len(e.hits))
	for t := range e.hits {
		tokens = append(tokens, t)
	}
	return tokens
}

func (e *EvidenceState) HitsMap() map[string]bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	m := make(map[string]bool, len(e.hits))
	for k, v := range e.hits {
		m[k] = v
	}
	return m
}

// LoopMetricsData tracks engagement metrics for a session.
type LoopMetricsData struct {
	mu                     sync.RWMutex
	EvidenceHitCount       int `json:"evidence_hit_count"`
	CredentialReuseAttempt int `json:"credential_reuse_attempt"`
	ProtocolSwitchCount    int `json:"protocol_switch_count"`
	VirtualTargetCalls     int `json:"virtual_target_calls"`
	RealNetworkTouchCount  int `json:"real_network_touch_count"`
	protocolsSeen          map[string]bool
}

func NewLoopMetricsData() *LoopMetricsData {
	return &LoopMetricsData{protocolsSeen: make(map[string]bool)}
}

func (m *LoopMetricsData) Score() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.EvidenceHitCount*10 +
		m.CredentialReuseAttempt*25 +
		m.ProtocolSwitchCount*15 -
		m.RealNetworkTouchCount*50
}

func (m *LoopMetricsData) AddProtocol(proto string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if proto == "shell" {
		return false
	}
	if m.protocolsSeen[proto] {
		return false
	}
	m.protocolsSeen[proto] = true
	m.ProtocolSwitchCount = len(m.protocolsSeen)
	return true
}

func (m *LoopMetricsData) IncrEvidence() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.EvidenceHitCount++
}

func (m *LoopMetricsData) IncrCredentialReuse() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CredentialReuseAttempt++
}

func (m *LoopMetricsData) IncrRealNetworkTouch() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.RealNetworkTouchCount++
}

// SafetyState tracks safety boundary violations.
type SafetyState struct {
	mu                    sync.RWMutex
	BoundaryRisk          float64  `json:"boundary_risk"`
	SafetyBlockCount      int      `json:"safety_block_count"`
	BlockedEvents         []string `json:"blocked_events"`
	RealNetworkTouchCount int      `json:"real_network_touch_count"`
}

func NewSafetyState() *SafetyState {
	return &SafetyState{}
}

func (s *SafetyState) AddBlockedEvent(event string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.BlockedEvents = append(s.BlockedEvents, event)
	s.SafetyBlockCount++
}

func (s *SafetyState) AddRealNetworkTouch(event string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if event != "" {
		s.BlockedEvents = append(s.BlockedEvents, event)
	}
	s.RealNetworkTouchCount++
}

// CachedResponse is a command response tied to a specific world/exposure view.
type CachedResponse struct {
	Output             string    `json:"output"`
	WorldVersion       int64     `json:"world_version"`
	ExposedFactVersion int64     `json:"exposed_fact_version"`
	CreatedAt          time.Time `json:"created_at"`
}

// CandidateFileFact is a planned file artifact that has not necessarily been
// exposed to the attacker yet. Evidence/gate checks promote it into WorldState.
type CandidateFileFact struct {
	Path         string   `json:"path"`
	Content      string   `json:"content"`
	Owner        string   `json:"owner,omitempty"`
	Permissions  string   `json:"permissions,omitempty"`
	EvidenceID   string   `json:"evidence_id,omitempty"`
	Phase        string   `json:"phase,omitempty"`
	VisibleAfter []string `json:"visible_after,omitempty"`
	Source       string   `json:"source,omitempty"`
	Reason       string   `json:"reason,omitempty"`
	CreatedAt    string   `json:"created_at,omitempty"`
}

// ServicePersonaFact is an agent-planned service identity used by scan and
// HTTP responders to keep protocol output consistent with the active plan.
type ServicePersonaFact struct {
	HostIP    string `json:"host_ip"`
	Hostname  string `json:"hostname,omitempty"`
	Service   string `json:"service"`
	Summary   string `json:"summary"`
	Phase     string `json:"phase,omitempty"`
	Source    string `json:"source,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// ExploitProfileFact describes how an apparent vulnerability should behave at
// a specific stage without handing the attacker a terminal win.
type ExploitProfileFact struct {
	HostIP    string `json:"host_ip"`
	Stage     string `json:"stage"`
	Policy    string `json:"policy"`
	Phase     string `json:"phase,omitempty"`
	Source    string `json:"source,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// EvidenceArtifactFact records evidence generated by an agent, whether it is
// still gated as a candidate or already exposed in the virtual filesystem.
type EvidenceArtifactFact struct {
	EvidenceID   string   `json:"evidence_id,omitempty"`
	Path         string   `json:"path"`
	Status       string   `json:"status"`
	Phase        string   `json:"phase,omitempty"`
	VisibleAfter []string `json:"visible_after,omitempty"`
	Source       string   `json:"source,omitempty"`
	Reason       string   `json:"reason,omitempty"`
	UpdatedAt    string   `json:"updated_at,omitempty"`
}

// PlanningState tracks agent-planning lifecycle and versioned response cache.
type PlanningState struct {
	mu sync.RWMutex

	WorldVersion               int64    `json:"world_version"`
	ExposedFactVersion         int64    `json:"exposed_fact_version"`
	ActivePlanID               string   `json:"active_plan_id"`
	ActiveBranchID             string   `json:"active_branch_id"`
	AttackerGoal               string   `json:"attacker_goal"`
	CurrentPhase               string   `json:"current_phase"`
	ActivePlanStartedAtCommand int      `json:"active_plan_started_at_command"`
	ActivePlanTTLCommands      int      `json:"active_plan_ttl_commands"`
	ActivePlanInvalidators     []string `json:"active_plan_invalidators,omitempty"`
	ResponseCacheable          bool     `json:"response_cacheable"`

	PlanCacheHits       int `json:"plan_cache_hits"`
	PlanCacheMisses     int `json:"plan_cache_misses"`
	ResponseCacheHits   int `json:"response_cache_hits"`
	ResponseCacheMisses int `json:"response_cache_misses"`
	LLMPlanningCalls    int `json:"llm_planning_calls"`

	recentEvents     []string
	responseCache    map[string]CachedResponse
	protectedTargets map[string]bool
	candidateFiles   map[string]CandidateFileFact
	servicePersonas  map[string]ServicePersonaFact
	exploitProfiles  map[string]ExploitProfileFact
	evidenceFacts    map[string]EvidenceArtifactFact
}

func NewPlanningState() *PlanningState {
	return &PlanningState{
		CurrentPhase:          "recon",
		ActivePlanTTLCommands: 20,
		ResponseCacheable:     true,
		recentEvents:          make([]string, 0, 32),
		responseCache:         make(map[string]CachedResponse),
		protectedTargets:      make(map[string]bool),
		candidateFiles:        make(map[string]CandidateFileFact),
		servicePersonas:       make(map[string]ServicePersonaFact),
		exploitProfiles:       make(map[string]ExploitProfileFact),
		evidenceFacts:         make(map[string]EvidenceArtifactFact),
	}
}

func (p *PlanningState) BumpWorldVersion(reason string) int64 {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.WorldVersion++
	p.appendEventLocked("world:" + reason)
	return p.WorldVersion
}

func (p *PlanningState) BumpExposedFactVersion(reason string) int64 {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ExposedFactVersion++
	p.appendEventLocked("exposed:" + reason)
	return p.ExposedFactVersion
}

func (p *PlanningState) SetGoal(signature, phase string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if signature != "" {
		p.AttackerGoal = signature
	}
	p.appendEventLocked("goal:" + signature)
}

func (p *PlanningState) SetActivePlan(planID, branchID string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	changed := false
	if planID != "" {
		changed = changed || p.ActivePlanID != planID
		p.ActivePlanID = planID
	}
	if branchID != "" {
		changed = changed || p.ActiveBranchID != branchID
		p.ActiveBranchID = branchID
	}
	if changed {
		p.appendEventLocked("active_plan:" + p.ActivePlanID)
	}
}

func (p *PlanningState) SetActivePlanMetadata(planID, branchID, phase string, invalidators []string, ttlCommands int, responseCacheable bool, commandIndex int) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	changed := false
	if planID != "" {
		changed = changed || p.ActivePlanID != planID
		p.ActivePlanID = planID
	}
	if branchID != "" {
		changed = changed || p.ActiveBranchID != branchID
		p.ActiveBranchID = branchID
	}
	if phase != "" {
		changed = changed || p.CurrentPhase != phase
		p.CurrentPhase = phase
	}
	if ttlCommands <= 0 {
		ttlCommands = 20
	}
	p.ActivePlanTTLCommands = ttlCommands
	p.ResponseCacheable = responseCacheable
	if len(invalidators) > 0 {
		p.ActivePlanInvalidators = append([]string{}, invalidators...)
	}
	if changed || p.ActivePlanStartedAtCommand == 0 {
		p.ActivePlanStartedAtCommand = commandIndex
		p.appendEventLocked("active_plan:" + p.ActivePlanID + ":" + p.CurrentPhase)
	}
}

func (p *PlanningState) InvalidateActivePlan(reason string) int64 {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ExposedFactVersion++
	p.responseCache = make(map[string]CachedResponse)
	p.ActivePlanID = ""
	p.ActiveBranchID = ""
	p.ActivePlanStartedAtCommand = 0
	p.ActivePlanInvalidators = nil
	p.ResponseCacheable = true
	p.appendEventLocked("plan_invalidated:" + reason)
	return p.ExposedFactVersion
}

func (p *PlanningState) EvaluateActivePlan(command string, commandIndex int, nested bool) (bool, string) {
	if p == nil {
		return false, ""
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.ActivePlanID == "" {
		return false, ""
	}
	invalidators := make(map[string]bool, len(p.ActivePlanInvalidators))
	for _, item := range p.ActivePlanInvalidators {
		invalidators[item] = true
	}
	if invalidators["plan_ttl"] && p.ActivePlanTTLCommands > 0 && commandIndex-p.ActivePlanStartedAtCommand >= p.ActivePlanTTLCommands {
		return true, "plan_ttl"
	}
	if invalidators["nested_shell"] && nested {
		return true, "nested_shell"
	}
	lower := strings.ToLower(command)
	if invalidators["critical_evidence_read"] && (strings.Contains(lower, "flag") || strings.Contains(lower, "proof") || strings.Contains(lower, "root.txt") || strings.Contains(lower, "user.txt")) {
		return true, "critical_evidence_read"
	}
	if invalidators["safety_block"] && strings.Contains(lower, "169.254.169.254") {
		return true, "safety_block"
	}
	return false, ""
}

func (p *PlanningState) RecordPlanCacheHit() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.PlanCacheHits++
}

func (p *PlanningState) RecordPlanCacheMiss() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.PlanCacheMisses++
}

func (p *PlanningState) RecordLLMPlanningCall() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.LLMPlanningCalls++
}

func (p *PlanningState) LookupResponse(key string) (string, bool) {
	if p == nil || key == "" {
		return "", false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.ResponseCacheable {
		p.ResponseCacheMisses++
		return "", false
	}
	cached, ok := p.responseCache[key]
	if !ok || cached.WorldVersion != p.WorldVersion || cached.ExposedFactVersion != p.ExposedFactVersion {
		p.ResponseCacheMisses++
		return "", false
	}
	p.ResponseCacheHits++
	return cached.Output, true
}

func (p *PlanningState) StoreResponse(key, output string) {
	if p == nil || key == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.ResponseCacheable {
		return
	}
	if len(p.responseCache) > 128 {
		p.responseCache = make(map[string]CachedResponse)
	}
	p.responseCache[key] = CachedResponse{
		Output:             output,
		WorldVersion:       p.WorldVersion,
		ExposedFactVersion: p.ExposedFactVersion,
		CreatedAt:          time.Now().UTC(),
	}
}

func (p *PlanningState) StoreCandidateFile(file CandidateFileFact) bool {
	if p == nil || file.Path == "" || file.Content == "" {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.candidateFiles == nil {
		p.candidateFiles = make(map[string]CandidateFileFact)
	}
	if existing, ok := p.candidateFiles[file.Path]; ok && existing.Content == file.Content {
		return false
	}
	if file.CreatedAt == "" {
		file.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	p.candidateFiles[file.Path] = file
	p.recordEvidenceFactLocked(EvidenceArtifactFact{
		EvidenceID:   file.EvidenceID,
		Path:         file.Path,
		Status:       "candidate",
		Phase:        file.Phase,
		VisibleAfter: append([]string{}, file.VisibleAfter...),
		Source:       file.Source,
		Reason:       file.Reason,
	})
	p.appendEventLocked("candidate_file:" + file.Path)
	return true
}

func (p *PlanningState) HasCandidateFile(path string) bool {
	if p == nil || path == "" {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, ok := p.candidateFiles[path]
	return ok
}

func (p *PlanningState) CandidateFileCount() int {
	if p == nil {
		return 0
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.candidateFiles)
}

func (p *PlanningState) PromoteCandidateFiles(command string, session *SessionContext) []CandidateFileFact {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.candidateFiles) == 0 {
		return nil
	}
	var promoted []CandidateFileFact
	for filePath, fact := range p.candidateFiles {
		if candidateFileVisibleLocked(p, fact, command, session) {
			promoted = append(promoted, fact)
			delete(p.candidateFiles, filePath)
			p.WorldVersion++
			p.ExposedFactVersion++
			p.recordEvidenceFactLocked(EvidenceArtifactFact{
				EvidenceID:   fact.EvidenceID,
				Path:         fact.Path,
				Status:       "exposed",
				Phase:        fact.Phase,
				VisibleAfter: append([]string{}, fact.VisibleAfter...),
				Source:       fact.Source,
				Reason:       fact.Reason,
			})
			p.appendEventLocked("candidate_promoted:" + filePath)
		}
	}
	return promoted
}

func (p *PlanningState) RecordEvidenceFact(fact EvidenceArtifactFact) bool {
	if p == nil || fact.Path == "" {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.recordEvidenceFactLocked(fact)
}

func (p *PlanningState) EvidenceFacts(status string) []EvidenceArtifactFact {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]EvidenceArtifactFact, 0, len(p.evidenceFacts))
	for _, fact := range p.evidenceFacts {
		if status == "" || fact.Status == status {
			out = append(out, fact)
		}
	}
	return out
}

func (p *PlanningState) recordEvidenceFactLocked(fact EvidenceArtifactFact) bool {
	if fact.Path == "" {
		return false
	}
	if fact.Status == "" {
		fact.Status = "exposed"
	}
	if fact.UpdatedAt == "" {
		fact.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if p.evidenceFacts == nil {
		p.evidenceFacts = make(map[string]EvidenceArtifactFact)
	}
	key := fact.Path
	if fact.EvidenceID != "" {
		key = fact.EvidenceID + ":" + fact.Path
	}
	if existing, ok := p.evidenceFacts[key]; ok &&
		existing.Status == fact.Status &&
		existing.Phase == fact.Phase &&
		strings.Join(existing.VisibleAfter, ",") == strings.Join(fact.VisibleAfter, ",") {
		return false
	}
	p.evidenceFacts[key] = fact
	p.appendEventLocked("evidence_" + fact.Status + ":" + fact.Path)
	return true
}

func (p *PlanningState) StoreServicePersona(fact ServicePersonaFact) bool {
	if p == nil || fact.HostIP == "" || fact.Service == "" || fact.Summary == "" {
		return false
	}
	fact.Service = normalizeFactKey(fact.Service)
	if fact.UpdatedAt == "" {
		fact.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	key := fact.HostIP + "." + fact.Service

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.servicePersonas == nil {
		p.servicePersonas = make(map[string]ServicePersonaFact)
	}
	if existing, ok := p.servicePersonas[key]; ok && existing.Summary == fact.Summary && existing.Phase == fact.Phase {
		return false
	}
	p.servicePersonas[key] = fact
	p.ExposedFactVersion++
	p.appendEventLocked("service_persona:" + key)
	return true
}

func (p *PlanningState) GetServicePersona(hostIP, service string) (ServicePersonaFact, bool) {
	if p == nil || hostIP == "" || service == "" {
		return ServicePersonaFact{}, false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	fact, ok := p.servicePersonas[hostIP+"."+normalizeFactKey(service)]
	return fact, ok
}

func (p *PlanningState) ServicePersonaFacts(hostIP string) []ServicePersonaFact {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]ServicePersonaFact, 0, len(p.servicePersonas))
	for _, fact := range p.servicePersonas {
		if hostIP == "" || fact.HostIP == hostIP {
			out = append(out, fact)
		}
	}
	return out
}

func (p *PlanningState) StoreExploitProfile(fact ExploitProfileFact) bool {
	if p == nil || fact.HostIP == "" || fact.Stage == "" || fact.Policy == "" {
		return false
	}
	fact.Stage = normalizeFactKey(fact.Stage)
	if fact.UpdatedAt == "" {
		fact.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	key := fact.HostIP + "." + fact.Stage

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.exploitProfiles == nil {
		p.exploitProfiles = make(map[string]ExploitProfileFact)
	}
	if existing, ok := p.exploitProfiles[key]; ok && existing.Policy == fact.Policy && existing.Phase == fact.Phase {
		return false
	}
	p.exploitProfiles[key] = fact
	p.ExposedFactVersion++
	p.appendEventLocked("exploit_profile:" + key)
	return true
}

func (p *PlanningState) GetExploitPolicy(hostIP string, stages ...string) (ExploitProfileFact, bool) {
	if p == nil || hostIP == "" {
		return ExploitProfileFact{}, false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, stage := range stages {
		if fact, ok := p.exploitProfiles[hostIP+"."+normalizeFactKey(stage)]; ok {
			return fact, true
		}
	}
	for _, stage := range stages {
		if fact, ok := p.exploitProfiles["current."+normalizeFactKey(stage)]; ok {
			return fact, true
		}
	}
	return ExploitProfileFact{}, false
}

func (p *PlanningState) ExploitProfileFacts(hostIP string) []ExploitProfileFact {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]ExploitProfileFact, 0, len(p.exploitProfiles))
	for _, fact := range p.exploitProfiles {
		if hostIP == "" || fact.HostIP == hostIP {
			out = append(out, fact)
		}
	}
	return out
}

func candidateFileVisibleLocked(p *PlanningState, fact CandidateFileFact, command string, session *SessionContext) bool {
	if fact.Phase != "" && !phaseAtLeast(p.CurrentPhase, fact.Phase) {
		return false
	}
	if len(fact.VisibleAfter) == 0 {
		return true
	}
	hits := map[string]bool{}
	if session != nil && session.Evidence != nil {
		for _, token := range session.Evidence.Tokens() {
			hits[token] = true
		}
	}
	for _, token := range CheckEvidence(command, map[string]bool{}) {
		hits[token] = true
	}
	for _, token := range fact.VisibleAfter {
		if strings.HasPrefix(token, "gate_") {
			if session == nil || !session.HasAccessState(token) {
				return false
			}
			continue
		}
		if !hits[token] {
			return false
		}
	}
	return true
}

func normalizeFactKey(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func phaseAtLeast(current, required string) bool {
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

func (p *PlanningState) ResponseCacheSize() int {
	if p == nil {
		return 0
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.responseCache)
}

func (p *PlanningState) AddProtectedTarget(ip string) {
	if p == nil || ip == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.protectedTargets == nil {
		p.protectedTargets = make(map[string]bool)
	}
	p.protectedTargets[ip] = true
	p.appendEventLocked("protected_target:" + ip)
}

func (p *PlanningState) IsProtectedTarget(ip string) bool {
	if p == nil || ip == "" {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.protectedTargets[ip]
}

func (p *PlanningState) ProtectedTargetList() []string {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]string, 0, len(p.protectedTargets))
	for ip := range p.protectedTargets {
		out = append(out, ip)
	}
	return out
}

func (p *PlanningState) appendEventLocked(event string) {
	if event == "" {
		return
	}
	p.recentEvents = append(p.recentEvents, event)
	if len(p.recentEvents) > 32 {
		p.recentEvents = p.recentEvents[len(p.recentEvents)-32:]
	}
}

// CommandEntry represents a logged command.
type CommandEntry struct {
	Command      string   `json:"command"`
	Output       string   `json:"output"`
	Timestamp    string   `json:"timestamp"`
	Intent       string   `json:"intent"`
	EvidenceHits []string `json:"evidence_hits"`
	Score        int      `json:"score"`
	SessionID    string   `json:"session_id,omitempty"`
	Username     string   `json:"username,omitempty"`
	RemoteAddr   string   `json:"remote_addr,omitempty"`
	Hostname     string   `json:"hostname,omitempty"`
	LLMGenerated bool     `json:"llm_generated,omitempty"`
}

// EventEntry represents a logged event.
type EventEntry struct {
	Type      string `json:"type"`
	Timestamp string `json:"timestamp"`
	SessionID string `json:"session_id"`
	Detail    string `json:"detail"`
}

// SSHContext stores the original session state when nested into another host.
type SSHContext struct {
	Hostname      string
	User          string
	CWD           string
	SubnetLocalIP string
	World         *WorldState // per-host virtual filesystem
}

// PendingSSH tracks a simulated SSH auth attempt waiting for password input.
type PendingSSH struct {
	TargetIP         string
	TargetUser       string
	Attempts         int
	MaxAttempt       int
	SelfSSH          bool   // true when SSH-ing to own IP (triggers success on final attempt)
	RemoteAddr       string // original attacker IP for self-SSH banner
	ExpectedPassword string // correct password for this host (empty = always deny)
}

// SessionContext holds all state for a single attacker session.
type SessionContext struct {
	mu sync.RWMutex

	SessionID      string     `json:"session_id"`
	Username       string     `json:"username"`
	RemoteAddr     string     `json:"remote_addr"`
	Hostname       string     `json:"hostname"`
	User           string     `json:"user"`
	CWD            string     `json:"cwd"`
	ConnectedAt    time.Time  `json:"connected_at"`
	DisconnectedAt *time.Time `json:"disconnected_at"`
	LastActivity   time.Time  `json:"last_activity"`

	// Subnet state
	ShellMode     string `json:"shell_mode"` // "bash", "python", "mysql"
	EntryCIDR     string `json:"entry_cidr"`
	EntryGateway  string `json:"entry_gateway"`
	EntryLocalIP  string `json:"entry_local_ip"`
	SubnetCIDR    string `json:"subnet_cidr"`
	SubnetGateway string `json:"subnet_gateway"`
	SubnetLocalIP string `json:"subnet_local_ip"`
	DNSSuffix     string `json:"dns_suffix"`

	// Nested SSH state
	SSHStack      []SSHContext `json:"ssh_stack,omitempty"`
	CurrentTarget string       `json:"current_target,omitempty"`

	// Pending SSH auth state — when set, next input is treated as a password attempt
	PendingSSHAuth *PendingSSH `json:"-"`

	// SuppressShellPrompt tells the SSH handler to skip the prompt for the next input cycle.
	// Used during SSH password auth to avoid showing root@host:~$ between password prompts.
	SuppressShellPrompt bool `json:"-"`

	// Domain state
	Evidence    *EvidenceState   `json:"evidence"`
	LoopMetrics *LoopMetricsData `json:"loop_metrics"`
	Safety      *SafetyState     `json:"safety"`
	World       *WorldState      `json:"-"` // per-session virtual filesystem

	// Topology tracking
	ShadowHosts  []map[string]string `json:"shadow_hosts"`
	AccessStates map[string]bool     `json:"access_states"`
	Memory       *DeceptionMemory    `json:"memory"`

	// Dead-end detection
	DeadEnd *DeadEndTracker `json:"-"`

	// Deception state (flat fields to avoid import cycle with internal/deception)
	DeceptionProfile string         `json:"deception_profile"`
	DeceptionScores  map[string]int `json:"deception_scores"`
	ActiveBranches   []string       `json:"active_branches"`
	LastStrategy     string         `json:"last_strategy"`
	HintDensity      string         `json:"hint_density"`
	Planning         *PlanningState `json:"planning"`

	// Logs
	CommandLog   []CommandEntry `json:"command_log"`
	EventLog     []EventEntry   `json:"event_log"`
	PPFTriggered bool           `json:"ppf_triggered"`
}

// NewSessionContext creates a new session for an attacker connection.
func NewSessionContext(username, remoteAddr string) *SessionContext {
	now := time.Now().UTC()

	user := username
	cwd := "/opt/webapp"
	if user == "" {
		user = "www-data"
	}
	if user == "root" {
		cwd = "/root"
	}

	return &SessionContext{
		SessionID:     uuid.New().String()[:12],
		Username:      username,
		RemoteAddr:    remoteAddr,
		Hostname:      "staging-web-01",
		User:          user,
		CWD:           cwd,
		ShellMode:     "bash",
		ConnectedAt:   now,
		LastActivity:  now,
		EntryCIDR:     "192.168.97.0/24",
		EntryGateway:  "192.168.97.1",
		EntryLocalIP:  "192.168.97.2",
		SubnetCIDR:    "192.168.56.0/24",
		SubnetGateway: "192.168.56.1",
		SubnetLocalIP: "192.168.56.23",
		DNSSuffix:     "corp.local",
		DeadEnd:       NewDeadEndTracker(),
		Evidence:      NewEvidenceState(),
		LoopMetrics:   NewLoopMetricsData(),
		Safety:        NewSafetyState(),
		ShadowHosts:   make([]map[string]string, 0),
		AccessStates:  make(map[string]bool),
		Memory:        NewDeceptionMemory(),
		Planning:      NewPlanningState(),
		CommandLog:    make([]CommandEntry, 0),
		EventLog:      make([]EventEntry, 0),
	}
}

// SetEntryNetwork updates the exposed SSH entry interface for this session.
func (s *SessionContext) SetEntryNetwork(ip, cidr, gateway string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ip != "" {
		s.EntryLocalIP = ip
	}
	if cidr != "" {
		s.EntryCIDR = cidr
	}
	if gateway != "" {
		s.EntryGateway = gateway
	}
}

// SetSubnetNetwork updates the simulated internal interface for this session.
func (s *SessionContext) SetSubnetNetwork(localIP, cidr, gateway string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if localIP != "" {
		s.SubnetLocalIP = localIP
	}
	if cidr != "" {
		s.SubnetCIDR = cidr
	}
	if gateway != "" {
		s.SubnetGateway = gateway
	}
	if s.Memory != nil {
		s.Memory.SetInvariant("host.identity", fmt.Sprintf("%s|Ubuntu 22.04|%s", s.Hostname, s.SubnetLocalIP), "session_network")
		s.Memory.SetInvariant("network.entry", fmt.Sprintf("dual-nic entry: eth0 dynamic, eth1 %s/%s", s.SubnetLocalIP, s.SubnetCIDR), "session_network")
	}
}

func (s *SessionContext) IsConnected() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.DisconnectedAt == nil
}

func (s *SessionContext) MarkDisconnected() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	s.DisconnectedAt = &now
}

// Touch updates the last activity timestamp.
func (s *SessionContext) Touch() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastActivity = time.Now().UTC()
}

// ReusableWithin reports whether this session can be reused for a new connection
// from the same IP+username. It must not be disconnected, or disconnected less than timeout ago.
func (s *SessionContext) ReusableWithin(timeout time.Duration) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.DisconnectedAt == nil {
		return true
	}
	return time.Since(*s.DisconnectedAt) < timeout
}

func (s *SessionContext) AppendCommand(entry CommandEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.CommandLog = append(s.CommandLog, entry)
}

// AppendToLastCommand appends output text to the most recent command entry.
// Used for multi-step flows like SSH password auth where the denial messages
// should appear under the original ssh command in the terminal replay.
func (s *SessionContext) AppendToLastCommand(output string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.CommandLog) == 0 {
		return
	}
	s.CommandLog[len(s.CommandLog)-1].Output += output
}

func (s *SessionContext) AppendEvent(entry EventEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.EventLog = append(s.EventLog, entry)
}

func (s *SessionContext) ClearPendingSSHAuth() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.PendingSSHAuth = nil
	s.SuppressShellPrompt = false
}

func (s *SessionContext) AddShadowHost(host map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ShadowHosts = append(s.ShadowHosts, host)
}

// UnlockAccessState marks a pivot/foothold condition as achieved for routing.
func (s *SessionContext) UnlockAccessState(state string) {
	if state == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.AccessStates == nil {
		s.AccessStates = make(map[string]bool)
	}
	s.AccessStates[state] = true
}

// HasAccessState reports whether a simulated pivot/foothold condition is unlocked.
func (s *SessionContext) HasAccessState(state string) bool {
	if state == "" {
		return true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.AccessStates[state]
}

// AccessStateList returns unlocked access states for API/UI rendering.
func (s *SessionContext) AccessStateList() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	states := make([]string, 0, len(s.AccessStates))
	for state, ok := range s.AccessStates {
		if ok {
			states = append(states, state)
		}
	}
	return states
}

// SetDeceptionState updates the deception profile fields atomically.
func (s *SessionContext) SetDeceptionState(profile string, scores map[string]int, branches []string, strategy, density string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.DeceptionProfile = profile
	s.DeceptionScores = scores
	s.ActiveBranches = branches
	s.LastStrategy = strategy
	s.HintDensity = density
}

// EnterRemoteHost saves current context and switches to remote host state.
// A new WorldState is created for the remote host; the caller should
// also call session.World = NewWorldStateForHost(hostname) if per-host
// filesystem isolation is desired.
func (s *SessionContext) EnterRemoteHost(targetIP, hostname, user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.SSHStack = append(s.SSHStack, SSHContext{
		Hostname:      s.Hostname,
		User:          s.User,
		CWD:           s.CWD,
		SubnetLocalIP: s.SubnetLocalIP,
		World:         s.World,
	})
	s.Hostname = hostname
	s.User = user
	s.CWD = "/root"
	s.SubnetLocalIP = targetIP
	s.CurrentTarget = targetIP
	// World is set by caller after this method returns
}

// ExitRemoteHost restores the previous context from SSH stack.
// Returns the restored WorldState (or nil if stack was empty).
func (s *SessionContext) ExitRemoteHost() (*WorldState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.SSHStack) == 0 {
		return nil, false
	}
	prev := s.SSHStack[len(s.SSHStack)-1]
	s.SSHStack = s.SSHStack[:len(s.SSHStack)-1]
	s.Hostname = prev.Hostname
	s.User = prev.User
	s.CWD = prev.CWD
	s.SubnetLocalIP = prev.SubnetLocalIP
	restoredWorld := prev.World
	if len(s.SSHStack) == 0 {
		s.CurrentTarget = ""
	}
	return restoredWorld, true
}

// IsNestedSSH returns true if the session is currently in a nested SSH.
func (s *SessionContext) IsNestedSSH() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.SSHStack) > 0
}

// ResetToEntryHost pops all SSH stack levels and restores the base (entry) host state.
// This ensures reconnecting to the entry port always lands on the entry machine.
func (s *SessionContext) ResetToEntryHost() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.SSHStack) == 0 {
		return false
	}
	// Restore the deepest (original) context
	base := s.SSHStack[0]
	s.Hostname = base.Hostname
	s.User = base.User
	s.CWD = base.CWD
	s.SubnetLocalIP = base.SubnetLocalIP
	s.World = base.World
	s.SSHStack = nil
	s.CurrentTarget = ""
	s.SuppressShellPrompt = false
	return true
}

// GetCurrentTarget returns the current SSH target IP, or empty string if not nested.
func (s *SessionContext) GetCurrentTarget() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.CurrentTarget
}
