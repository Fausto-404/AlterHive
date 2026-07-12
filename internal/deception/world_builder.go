package deception

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/alterhive/alterhive/internal/domain"
)

// FactGrade classifies information by its exposure and trust level in the
// world state store.
type FactGrade string

const (
	FactCandidate FactGrade = "candidate" // planned but unexposed, replaceable
	FactExposed   FactGrade = "exposed"   // seen by attacker, permanently locked
	FactHidden    FactGrade = "hidden"    // internal planning, never returned
	FactGated     FactGrade = "gated"     // unlock after gate conditions met
	FactDecoy     FactGrade = "decoy"     // intentionally misleading
	FactRejected  FactGrade = "rejected"  // rejected, must not reappear
)

// GradedFact is a fact annotated with its grade and metadata.
type GradedFact struct {
	Key        string    `json:"key"`
	Value      string    `json:"value"`
	Grade      FactGrade `json:"grade"`
	Source     string    `json:"source,omitempty"`
	PlanID     string    `json:"plan_id,omitempty"`
	Phase      string    `json:"phase,omitempty"`
	GatedUntil []string  `json:"gated_until,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// WorldBuildResult captures the output of a build operation.
type WorldBuildResult struct {
	FilesCreated     int      `json:"files_created"`
	CandidateFacts   int      `json:"candidate_facts"`
	PromotedFacts    int      `json:"promoted_facts"`
	RejectedFacts    int      `json:"rejected_facts"`
	NewSegments      int      `json:"new_segments"`
	NewHosts         int      `json:"new_hosts"`
	Errors           []string `json:"errors,omitempty"`
	WorldVersion     int64    `json:"world_version"`
	ExposedFactVersion int64  `json:"exposed_fact_version"`
}

// WorldBuilderAgent translates DeceptionPlan into concrete world mutations.
// It grades every fact and enforces the six-level fact grading system before
// any fact reaches the attacker.
type WorldBuilderAgent struct {
	mu            sync.RWMutex
	topology      *domain.VirtualTopology
	cacheMgr      *CacheManagerAgent
	gradedFacts   map[string]GradedFact // factKey → graded fact
	rejectedKeys  map[string]bool       // keys that must never reappear
}

// NewWorldBuilderAgent creates a ready-to-use world builder.
func NewWorldBuilderAgent(topology *domain.VirtualTopology, cacheMgr *CacheManagerAgent) *WorldBuilderAgent {
	return &WorldBuilderAgent{
		topology:     topology,
		cacheMgr:     cacheMgr,
		gradedFacts:  make(map[string]GradedFact),
		rejectedKeys: make(map[string]bool),
	}
}

// BuildFromPlan translates a DeceptionPlan into graded facts, candidate files,
// and service personas. It does NOT mutate the topology — that is done by
// TopologyPlanner.MergePlan after consistency/safety validation.
func (w *WorldBuilderAgent) BuildFromPlan(session *domain.SessionContext, plan DeceptionPlan) WorldBuildResult {
	result := WorldBuildResult{}
	if w == nil || session == nil {
		result.Errors = append(result.Errors, "world_builder: nil receiver or session")
		return result
	}
	if session.Planning == nil {
		result.Errors = append(result.Errors, "world_builder: session has no PlanningState")
		return result
	}

	// Grade exposable facts
	for _, fact := range plan.ExposableFacts {
		if w.isRejected(fact) {
			result.RejectedFacts++
			continue
		}
		graded := w.gradeFact(fact, FactCandidate, plan.PlanID, plan.Phase, nil)
		w.storeGradedFact(graded)
		result.CandidateFacts++
	}

	// Grade hidden facts (never returned to attacker)
	for _, fact := range plan.HiddenFacts {
		graded := w.gradeFact(fact, FactHidden, plan.PlanID, plan.Phase, nil)
		w.storeGradedFact(graded)
	}

	// Process proposal hosts into candidate files
	for _, host := range plan.Proposal.Hosts {
		if host.IP == "" {
			continue
		}

		// Each host generates a candidate file with its metadata
		safeIP := strings.ReplaceAll(host.IP, ".", "_")
		filePath := path.Clean("/tmp/host_" + safeIP + ".meta")
		content := fmt.Sprintf("ip=%s\nhostname=%s\nrole=%s\nos=%s\nreachable_via=%s\nsegment=%s\n",
			host.IP, host.Hostname, host.Role, host.OS, host.ReachableVia, host.SegmentCIDR)

		session.Planning.StoreCandidateFile(domain.CandidateFileFact{
			Path:         filePath,
			Content:      content,
			Owner:        "root",
			Permissions:  "-rw-r--r--",
			EvidenceID:   "ev_host_" + safeIP,
			Phase:        plan.Phase,
			VisibleAfter: []string{"subnet_scan"},
			Source:       "world_builder",
			Reason:       plan.PlanID,
			CreatedAt:    time.Now().UTC().Format(time.RFC3339),
		})
		result.FilesCreated++
	}

	// Process proposal segments
	result.NewSegments = len(plan.Proposal.Segments)
	result.NewHosts = len(plan.Proposal.Hosts)

	// Store service personas from proposal
	for _, host := range plan.Proposal.Hosts {
		if host.Hostname == "" {
			continue
		}
		persona := domain.ServicePersonaFact{
			HostIP:    host.IP,
			Hostname:  host.Hostname,
			Service:   host.Role,
			Summary:   fmt.Sprintf("%s running on %s (%s)", host.Role, host.Hostname, host.OS),
			Phase:     plan.Phase,
			Source:    "world_builder",
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		}
		session.Planning.StoreServicePersona(persona)
	}

	// Bump versions
	result.WorldVersion = session.Planning.BumpWorldVersion("world_builder:" + plan.PlanID)
	result.ExposedFactVersion = session.Planning.ExposedFactVersion

	return result
}

// PromoteCandidateFiles evaluates gate conditions and promotes ready candidate
// files into the world state filesystem.
func (w *WorldBuilderAgent) PromoteCandidateFiles(session *domain.SessionContext, world *domain.WorldState, command string) int {
	if w == nil || session == nil || world == nil || session.Planning == nil {
		return 0
	}

	promoted := session.Planning.PromoteCandidateFiles(command, session)
	for _, file := range promoted {
		world.InjectCatOutput(file.Path, file.Content)
		// Record as exposed fact
		graded := w.gradeFact(file.Path+"="+truncateForFact(file.Content, 80), FactExposed, "", "", nil)
		w.storeGradedFact(graded)
	}
	return len(promoted)
}

// GradeFact assigns a grade to a fact key-value pair.
func (w *WorldBuilderAgent) GradeFact(key, value string, grade FactGrade, planID string) GradedFact {
	return w.gradeFact(value, grade, planID, "", nil)
}

// RejectFact permanently rejects a fact so it cannot reappear.
func (w *WorldBuilderAgent) RejectFact(key string) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.rejectedKeys[key] = true
	// Downgrade any existing graded fact to rejected
	if existing, ok := w.gradedFacts[key]; ok {
		existing.Grade = FactRejected
		w.gradedFacts[key] = existing
	}
}

// IsRejected returns true if a fact key has been permanently rejected.
func (w *WorldBuilderAgent) IsRejected(key string) bool {
	if w == nil {
		return false
	}
	return w.isRejected(key)
}

// GetGradedFact returns the grading for a specific fact key.
func (w *WorldBuilderAgent) GetGradedFact(key string) (GradedFact, bool) {
	if w == nil {
		return GradedFact{}, false
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	fact, ok := w.gradedFacts[key]
	return fact, ok
}

// FactsByGrade returns all facts at a given grade level.
func (w *WorldBuilderAgent) FactsByGrade(grade FactGrade) []GradedFact {
	if w == nil {
		return nil
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	var facts []GradedFact
	for _, f := range w.gradedFacts {
		if f.Grade == grade {
			facts = append(facts, f)
		}
	}
	sort.Slice(facts, func(i, j int) bool {
		return facts[i].CreatedAt.Before(facts[j].CreatedAt)
	})
	return facts
}

// ExposedFactValues returns values of all exposed facts for consistency checks.
func (w *WorldBuilderAgent) ExposedFactValues() []string {
	if w == nil {
		return nil
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	var values []string
	for _, f := range w.gradedFacts {
		if f.Grade == FactExposed {
			values = append(values, f.Value)
		}
	}
	return values
}

// Summary returns a compact one-line summary of the fact grading state.
func (w *WorldBuilderAgent) Summary() string {
	if w == nil {
		return "world_builder:nil"
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	var candidate, exposed, hidden, gated, decoy, rejected int
	for _, f := range w.gradedFacts {
		switch f.Grade {
		case FactCandidate:
			candidate++
		case FactExposed:
			exposed++
		case FactHidden:
			hidden++
		case FactGated:
			gated++
		case FactDecoy:
			decoy++
		case FactRejected:
			rejected++
		}
	}
	return fmt.Sprintf("world_builder:candidate=%d exposed=%d hidden=%d gated=%d decoy=%d rejected=%d",
		candidate, exposed, hidden, gated, decoy, rejected)
}

// ---- Internal helpers -----------------------------------------------------

func (w *WorldBuilderAgent) gradeFact(value string, grade FactGrade, planID, phase string, gatedUntil []string) GradedFact {
	return GradedFact{
		Key:        fmt.Sprintf("fact_%d", time.Now().UnixNano()),
		Value:      value,
		Grade:      grade,
		Source:     "world_builder",
		PlanID:     planID,
		Phase:      phase,
		GatedUntil: gatedUntil,
		CreatedAt:  time.Now().UTC(),
	}
}

func (w *WorldBuilderAgent) storeGradedFact(fact GradedFact) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.gradedFacts[fact.Key] = fact
}

func (w *WorldBuilderAgent) isRejected(key string) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.rejectedKeys[key] {
		return true
	}
	if f, ok := w.gradedFacts[key]; ok && f.Grade == FactRejected {
		return true
	}
	return false
}

func truncateForFact(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
