package deception

import (
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/alterhive/alterhive/internal/domain"
)

// EvidenceType classifies the kind of decoy artifact being placed.
type EvidenceType string

const (
	EvidenceCICDLog      EvidenceType = "ci_cd_log"
	EvidenceEnvFile      EvidenceType = "env_file"
	EvidenceBashHistory  EvidenceType = "bash_history"
	EvidenceBackup       EvidenceType = "backup"
	EvidenceConfig       EvidenceType = "config"
	EvidenceKubeconfig   EvidenceType = "kubeconfig"
	EvidenceOpsNote      EvidenceType = "ops_note"
	EvidenceSubnetTrace  EvidenceType = "subnet_trace"
	EvidenceFlagTrace    EvidenceType = "flag_trace"
	EvidenceServiceLog   EvidenceType = "service_log"
	EvidenceCredential   EvidenceType = "credential"
)

// EvidenceSpec is a structured specification for a decoy artifact.
type EvidenceSpec struct {
	EvidenceID              string      `json:"evidence_id"`
	EvidenceType            EvidenceType `json:"evidence_type"`
	WhereToPlace            string      `json:"where_to_place"`
	Content                 string      `json:"content"`
	Owner                   string      `json:"owner,omitempty"`
	Permissions             string      `json:"permissions,omitempty"`
	WhenToReveal            []string    `json:"when_to_reveal,omitempty"`
	DiscoverableBy          []string    `json:"discoverable_by,omitempty"`
	GuidesTo                string      `json:"guides_to,omitempty"`
	RiskLevel               string      `json:"risk_level"`
	ConsistencyDependencies []string    `json:"consistency_dependencies,omitempty"`
	PlanID                  string      `json:"plan_id,omitempty"`
	Phase                   string      `json:"phase,omitempty"`
	Goal                    string      `json:"goal,omitempty"`
	Service                 string      `json:"service,omitempty"`
}

// EvidenceLifecycle tracks the state of a placed evidence artifact.
type EvidenceLifecycle string

const (
	EvidenceDraft    EvidenceLifecycle = "draft"
	EvidencePlaced   EvidenceLifecycle = "placed"
	EvidenceRevealed EvidenceLifecycle = "revealed"
	EvidenceConsumed EvidenceLifecycle = "consumed"
	EvidenceExpired  EvidenceLifecycle = "expired"
)

// EvidenceAgent plans and manages decoy artifacts for the deception topology.
// It implements WorldAgent for the orchestrator pipeline and adds structured
// evidence lifecycle management with gate-controlled reveal.
type EvidenceAgent struct {
	cacheManager *CacheManagerAgent
}

// NewEvidenceAgent creates a ready-to-use evidence agent.
func NewEvidenceAgent(cacheManager *CacheManagerAgent) *EvidenceAgent {
	return &EvidenceAgent{cacheManager: cacheManager}
}

// Name returns the agent identifier for the orchestrator pipeline.
func (e *EvidenceAgent) Name() string { return "evidence_agent" }

// Plan implements WorldAgent. It produces a WorldPatch with evidence files
// tailored to the current session state, goal, phase, and topology additions.
func (e *EvidenceAgent) Plan(session *domain.SessionContext, world *domain.WorldState, command string, added []domain.VirtualHost) WorldPatch {
	if session == nil {
		return WorldPatch{}
	}

	phase := currentPlanPhase(session)
	goal := ""
	if session.Planning != nil {
		goal = session.Planning.AttackerGoal
	}

	var specs []EvidenceSpec

	// Generate evidence for newly added shadow hosts
	for _, host := range added {
		specs = append(specs, e.specsForHost(host, session, phase, goal)...)
	}

	// If no hosts were added but command mentions evidence-triggering patterns,
	// generate evidence for existing shadow hosts
	if len(specs) == 0 && mentionsDirtyData(command) {
		existingHosts := shadowHostsForEvidence(session)
		for _, host := range existingHosts {
			specs = append(specs, e.specsForHost(host, session, phase, goal)...)
		}
	}

	if len(specs) == 0 {
		return WorldPatch{}
	}

	// Filter specs by reveal conditions
	var revealed []EvidenceSpec
	for _, spec := range specs {
		if canRevealEvidence(session, command, spec.WhenToReveal, "") {
			revealed = append(revealed, spec)
		}
	}
	if len(revealed) == 0 {
		return WorldPatch{}
	}

	// Convert specs to file mutations
	patch := WorldPatch{Source: "evidence_agent", Reason: fmt.Sprintf("placed %d evidence artifacts", len(revealed))}
	for _, spec := range revealed {
		patch.Files = append(patch.Files, FileMutation{
			Path:         spec.WhereToPlace,
			Content:      spec.Content,
			Owner:        spec.Owner,
			Permissions:  spec.Permissions,
			EvidenceID:   spec.EvidenceID,
			Phase:        spec.Phase,
			VisibleAfter: spec.WhenToReveal,
		})

		// Store in evidence cache
		if e.cacheManager != nil {
			e.cacheManager.StoreEvidence(EvidenceCacheEntry{
				Goal:        spec.Goal,
				Service:     spec.Service,
				Phase:       spec.Phase,
				EvidenceIDs: []string{spec.EvidenceID},
				PlanID:      spec.PlanID,
			})
		}
	}

	return patch
}

// specsForHost generates evidence specs tailored to a single virtual host.
func (e *EvidenceAgent) specsForHost(host domain.VirtualHost, session *domain.SessionContext, phase, goal string) []EvidenceSpec {
	pivotIP := host.ReachableVia
	if pivotIP == "" {
		pivotIP = DefaultPivotIP(nil, session)
	}
	safeCIDR := strings.ReplaceAll(strings.TrimSuffix(host.SegmentCIDR, "/24"), ".", "_")
	if safeCIDR == "" {
		safeCIDR = strings.ReplaceAll(host.IP, ".", "_")
	}
	theme := host.Theme
	if theme == "" {
		theme = "network"
	}

	var specs []EvidenceSpec

	// Subnet discovery trace
	specs = append(specs, EvidenceSpec{
		EvidenceID:   "ev_subnet_discovery_" + safeCIDR,
		EvidenceType: EvidenceSubnetTrace,
		WhereToPlace: path.Clean("/tmp/discovered_" + safeCIDR + ".txt"),
		Owner:        session.User,
		Permissions:  "-rw-r--r--",
		WhenToReveal: []string{"subnet_scan"},
		GuidesTo:     host.SegmentCIDR,
		RiskLevel:    "low",
		PlanID:       session.Planning.ActivePlanID,
		Phase:        phase,
		Goal:         goal,
		Content: fmt.Sprintf("# discovered during internal recon\nsegment=%s\npivot=%s\nhost=%s %s role=%s\nstate=filtered until next credential/pivot gate\n",
			host.SegmentCIDR, pivotIP, host.IP, host.Hostname, host.Role),
	})

	// Service upstream log (if in appropriate phase)
	if phaseAllowsEvidence(phase, "service_validation") {
		specs = append(specs, EvidenceSpec{
			EvidenceID:              "ev_service_upstream_" + safeCIDR,
			EvidenceType:            EvidenceServiceLog,
			WhereToPlace:            path.Clean("/opt/webapp/logs/" + theme + "_upstream.log"),
			Owner:                   "www-data",
			Permissions:             "-rw-r--r--",
			WhenToReveal:            []string{"subnet_scan", GateReconObserved},
			GuidesTo:                host.IP,
			RiskLevel:               "low",
			ConsistencyDependencies: []string{"ev_subnet_discovery_" + safeCIDR},
			PlanID:                  session.Planning.ActivePlanID,
			Phase:                   phase,
			Goal:                    goal,
			Service:                 "webapp",
			Content: fmt.Sprintf("2024-01-15 09:11:42 [WARN] upstream %s (%s) reachable only via jump01\n2024-01-15 09:12:07 [INFO] cached credentials are low privilege and read-only\n",
				host.Hostname, host.IP),
		})
	}

	// Flag trace (if in exploit/evidence followup phase)
	if phaseAllowsEvidence(phase, "evidence_followup") {
		specs = append(specs, EvidenceSpec{
			EvidenceID:              "ev_flag_trace_" + safeCIDR,
			EvidenceType:            EvidenceFlagTrace,
			WhereToPlace:            path.Clean("/tmp/flag-trace-" + safeCIDR + ".txt"),
			Owner:                   "root",
			Permissions:             "-rw-r-----",
			WhenToReveal:            []string{"subnet_scan", GateExploitPartial},
			GuidesTo:                host.SegmentCIDR,
			RiskLevel:               "medium",
			ConsistencyDependencies: []string{"ev_service_upstream_" + safeCIDR},
			PlanID:                  session.Planning.ActivePlanID,
			Phase:                   phase,
			Goal:                    goal,
			Content: fmt.Sprintf("artifact_branch=%s\npivot=%s\ncandidate=%s %s\nnote=trace points to a second-hop evidence store; direct flag access remains unavailable\n",
				host.SegmentCIDR, pivotIP, host.IP, host.Hostname),
		})
	}

	return specs
}

// PlaceEvidence directly places an evidence spec into the world state.
// Returns true if the placement succeeded.
func (e *EvidenceAgent) PlaceEvidence(session *domain.SessionContext, world *domain.WorldState, spec EvidenceSpec) bool {
	if session == nil || world == nil || spec.EvidenceID == "" {
		return false
	}
	if !canRevealEvidence(session, "", spec.WhenToReveal, "") {
		return false
	}
	world.InjectCatOutput(spec.WhereToPlace, spec.Content)
	if session.Planning != nil {
		session.Planning.RecordEvidenceFact(domain.EvidenceArtifactFact{
			EvidenceID:   spec.EvidenceID,
			Path:         spec.WhereToPlace,
			Status:       string(EvidenceRevealed),
			Phase:        spec.Phase,
			VisibleAfter: spec.WhenToReveal,
			Source:       "evidence_agent",
			Reason:       fmt.Sprintf("placed:%s", spec.EvidenceType),
			UpdatedAt:    time.Now().UTC().Format(time.RFC3339),
		})
	}
	return true
}

// ConsumeEvidence marks an evidence artifact as consumed by the attacker.
func (e *EvidenceAgent) ConsumeEvidence(session *domain.SessionContext, evidenceID string) bool {
	if session == nil || evidenceID == "" {
		return false
	}
	session.Evidence.Hit(evidenceID)
	if session.Planning != nil {
		session.Planning.RecordEvidenceFact(domain.EvidenceArtifactFact{
			EvidenceID: evidenceID,
			Status:     string(EvidenceConsumed),
			Source:     "evidence_agent",
			Reason:     "attacker_consumed",
			UpdatedAt:  time.Now().UTC().Format(time.RFC3339),
		})
	}
	return true
}

// LookupEvidence retrieves cached evidence specs by goal + service + phase.
func (e *EvidenceAgent) LookupEvidence(goal, service, phase string) ([]EvidenceSpec, bool) {
	if e.cacheManager == nil {
		return nil, false
	}
	key := EvidenceKey(goal, service, phase)
	entry, ok := e.cacheManager.LookupEvidence(key)
	if !ok {
		return nil, false
	}
	// Cache hit returns IDs; the caller resolves specs from PlanningState
	_ = entry
	return nil, true
}

// BuildFromPlan generates a full evidence plan from a DeceptionPlan.
func (e *EvidenceAgent) BuildFromPlan(session *domain.SessionContext, plan DeceptionPlan) []EvidenceSpec {
	if session == nil {
		return nil
	}
	var specs []EvidenceSpec
	phase := currentPlanPhase(session)

	// Generate subnet discovery traces for each shadow path CIDR
	for _, cidr := range plan.ShadowPath {
		safeCIDR := strings.ReplaceAll(strings.TrimSuffix(cidr, "/24"), ".", "_")
		specs = append(specs, EvidenceSpec{
			EvidenceID:   fmt.Sprintf("ev_plan_%s_%s", plan.PlanID, safeCIDR),
			EvidenceType: EvidenceSubnetTrace,
			WhereToPlace: path.Clean("/tmp/plan-" + safeCIDR + ".txt"),
			Owner:        session.User,
			Permissions:  "-rw-r--r--",
			WhenToReveal: []string{"subnet_scan"},
			GuidesTo:     cidr,
			RiskLevel:    "low",
			PlanID:       plan.PlanID,
			Phase:        phase,
			Goal:         plan.AttackerGoalHypothesis,
			Content: fmt.Sprintf("# deception plan artifact\nsegment=%s\nnote=follow shadow path to next segment\n",
				cidr),
		})
	}

	// Convert exposable facts into evidence specs
	for _, fact := range plan.ExposableFacts {
		specs = append(specs, EvidenceSpec{
			EvidenceID:   fmt.Sprintf("ev_fact_%s_%d", plan.PlanID, len(specs)),
			EvidenceType: EvidenceOpsNote,
			WhereToPlace: "/home/deploy/ops-notes.txt",
			Owner:        "deploy",
			Permissions:  "-rw-------",
			WhenToReveal: []string{"app_config"},
			RiskLevel:    "low",
			PlanID:       plan.PlanID,
			Phase:        phase,
			Goal:         plan.AttackerGoalHypothesis,
			Content:      fact + "\n",
		})
	}

	return specs
}
