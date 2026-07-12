package deception

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/alterhive/alterhive/internal/domain"
)

// PlanLifecycle tracks the state machine of a deception plan.
type PlanLifecycle string

const (
	PlanDraft            PlanLifecycle = "draft"
	PlanValidated        PlanLifecycle = "validated"
	PlanArmed            PlanLifecycle = "armed"
	PlanActive           PlanLifecycle = "active"
	PlanPartiallyExposed PlanLifecycle = "partially_exposed"
	PlanLocked           PlanLifecycle = "locked"
	PlanStale            PlanLifecycle = "stale"
	PlanRetired          PlanLifecycle = "retired"
)

// PlanExecutionState tracks runtime state of a single plan instance.
type PlanExecutionState struct {
	PlanID         string        `json:"plan_id"`
	Lifecycle      PlanLifecycle `json:"lifecycle"`
	CommandIndex   int           `json:"command_index"`
	TTLCommands    int           `json:"ttl_commands"`
	GoalSignature  string        `json:"goal_signature"`
	Phase          string        `json:"phase"`
	Invalidators   []string      `json:"invalidators,omitempty"`
	ExposedCount   int           `json:"exposed_count"`
	MaxExposed     int           `json:"max_exposed"`
	StartedAt      time.Time     `json:"started_at"`
	LastActivityAt time.Time     `json:"last_activity_at"`
}

// PlanExecutor executes approved plans synchronously. It checks whether the
// current command matches active plan expectations, returns cached responses
// for plan-following commands, detects plan deviations, and manages plan
// lifecycle transitions.
type PlanExecutor struct {
	mu        sync.RWMutex
	eventBus  *EventBus
	cacheMgr  *CacheManagerAgent
	sessions  map[string]*PlanExecutionState // sessionID -> active plan state
}

// NewPlanExecutor creates a ready-to-use plan executor.
func NewPlanExecutor(eventBus *EventBus, cacheMgr *CacheManagerAgent) *PlanExecutor {
	return &PlanExecutor{
		eventBus: eventBus,
		cacheMgr: cacheMgr,
		sessions: make(map[string]*PlanExecutionState),
	}
}

// ExecuteCommand evaluates the current command against the active plan and
// returns the recommended runtime action.
func (e *PlanExecutor) ExecuteCommand(session *domain.SessionContext, command string, intent IntentResult) (output string, action RuntimeAction) {
	if e == nil || session == nil {
		return "", ActionFastResponse
	}

	planning := session.Planning
	if planning == nil || planning.ActivePlanID == "" {
		return "", ActionFastResponse
	}

	commandIndex := len(session.CommandLog) + 1

	// Check if the active plan is still valid
	if invalid, reason := planning.EvaluateActivePlan(command, commandIndex, session.IsNestedSSH()); invalid {
		e.transitionLifecycle(session, PlanStale, reason)
		if e.eventBus != nil {
			e.eventBus.PublishAsync(PlanningEvent{
				Type:      EventPlanInvalidated,
				SessionID: session.SessionID,
				Command:   command,
				Payload:   map[string]interface{}{"reason": reason, "plan_id": planning.ActivePlanID},
				Timestamp: time.Now().UTC(),
			})
		}
		return "", ActionFullReplan
	}

	// Check if this command follows the plan or deviates
	if intent.IsPlanFollowing {
		// Try response cache first
		cacheKey := ResponseCacheKey(command, session.SessionID, planning.WorldVersion, planning.ExposedFactVersion)
		if e.cacheMgr != nil {
			if cached, ok := e.cacheMgr.LookupResponse(planning, cacheKey); ok {
				e.recordActivity(session)
				return cached, ActionFastResponse
			}
		} else if cached, ok := planning.LookupResponse(cacheKey); ok {
			e.recordActivity(session)
			return cached, ActionFastResponse
		}
		return "", ActionFastResponse
	}

	// Plan-breaking or goal-shifting intent
	if intent.IsPlanBreaking || intent.IsGoalShift {
		e.transitionLifecycle(session, PlanStale, "plan_breaking_intent")
		if e.eventBus != nil {
			e.eventBus.PublishAsync(PlanningEvent{
				Type:      EventPlanInvalidated,
				SessionID: session.SessionID,
				Command:   command,
				Payload:   map[string]interface{}{"intent": intent.IntentType, "goal_shift": intent.IsGoalShift},
				Timestamp: time.Now().UTC(),
			})
		}
		return "", ActionFullReplan
	}

	// New discovery — may need plan patch
	if intent.IsNewDiscovery {
		if e.eventBus != nil {
			events := MapIntentToEvent(intent, session.SessionID, command)
			for _, ev := range events {
				e.eventBus.PublishAsync(ev)
			}
		}
		return "", ActionPatchPlan
	}

	e.recordActivity(session)
	return "", ActionFastResponse
}

// ActivatePlan transitions a plan to Active lifecycle and records metadata.
func (e *PlanExecutor) ActivatePlan(session *domain.SessionContext, planID, goalSig, phase string, ttlCommands int, invalidators []string) {
	if e == nil || session == nil || planID == "" {
		return
	}
	if ttlCommands <= 0 {
		ttlCommands = 20
	}

	commandIndex := len(session.CommandLog) + 1
	state := &PlanExecutionState{
		PlanID:        planID,
		Lifecycle:     PlanActive,
		CommandIndex:  commandIndex,
		TTLCommands:   ttlCommands,
		GoalSignature: goalSig,
		Phase:         phase,
		Invalidators:  append([]string{}, invalidators...),
		MaxExposed:    200,
		StartedAt:     time.Now().UTC(),
		LastActivityAt: time.Now().UTC(),
	}

	e.mu.Lock()
	e.sessions[session.SessionID] = state
	e.mu.Unlock()

	if session.Planning != nil {
		session.Planning.SetActivePlanMetadata(planID, "", phase, invalidators, ttlCommands, true, commandIndex)
	}
}

// RecordExposure increments the exposed fact counter and checks lifecycle.
func (e *PlanExecutor) RecordExposure(session *domain.SessionContext) PlanLifecycle {
	if e == nil || session == nil {
		return PlanActive
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	state := e.sessions[session.SessionID]
	if state == nil {
		return PlanActive
	}

	state.ExposedCount++
	state.LastActivityAt = time.Now().UTC()

	switch {
	case state.ExposedCount >= state.MaxExposed:
		state.Lifecycle = PlanLocked
	case state.ExposedCount >= state.MaxExposed/2:
		state.Lifecycle = PlanPartiallyExposed
	}

	return state.Lifecycle
}

// GetLifecycle returns the current plan lifecycle for a session.
func (e *PlanExecutor) GetLifecycle(sessionID string) PlanLifecycle {
	if e == nil {
		return PlanActive
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	state := e.sessions[sessionID]
	if state == nil {
		return PlanDraft
	}
	return state.Lifecycle
}

// AdvanceLifecycle moves the plan to the next lifecycle stage.
func (e *PlanExecutor) AdvanceLifecycle(session *domain.SessionContext, next PlanLifecycle) {
	if e == nil || session == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	state := e.sessions[session.SessionID]
	if state == nil {
		return
	}

	// Validate transition
	if !isValidLifecycleTransition(state.Lifecycle, next) {
		return
	}

	state.Lifecycle = next
	state.LastActivityAt = time.Now().UTC()

	// On lock/retire, invalidate caches
	if next == PlanLocked || next == PlanRetired {
		if e.cacheMgr != nil {
			e.cacheMgr.InvalidatePlanAcrossLayers(state.PlanID)
		}
	}
}

// IsPlanActive returns true when the current plan is in an executable state.
func (e *PlanExecutor) IsPlanActive(session *domain.SessionContext) bool {
	if e == nil || session == nil {
		return false
	}
	lifecycle := e.GetLifecycle(session.SessionID)
	switch lifecycle {
	case PlanActive, PlanPartiallyExposed, PlanArmed:
		return true
	default:
		return false
	}
}

// CleanupSession removes plan execution state for a session.
func (e *PlanExecutor) CleanupSession(sessionID string) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.sessions, sessionID)
}

// Summary returns a compact summary of the active plan execution state.
func (e *PlanExecutor) Summary(sessionID string) string {
	if e == nil {
		return "executor:nil"
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	state := e.sessions[sessionID]
	if state == nil {
		return "executor:no_active_plan"
	}
	return fmt.Sprintf("executor:plan=%s lifecycle=%s phase=%s exposed=%d/%d cmd=%d/%d",
		state.PlanID, state.Lifecycle, state.Phase,
		state.ExposedCount, state.MaxExposed,
		state.CommandIndex, state.TTLCommands)
}

// ---- Internal helpers -----------------------------------------------------

func (e *PlanExecutor) transitionLifecycle(session *domain.SessionContext, next PlanLifecycle, reason string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	state := e.sessions[session.SessionID]
	if state == nil {
		return
	}

	if !isValidLifecycleTransition(state.Lifecycle, next) {
		return
	}

	state.Lifecycle = next
	state.LastActivityAt = time.Now().UTC()

	if session.Planning != nil {
		session.Planning.InvalidateActivePlan(reason)
	}
}

func (e *PlanExecutor) recordActivity(session *domain.SessionContext) {
	e.mu.Lock()
	defer e.mu.Unlock()
	state := e.sessions[session.SessionID]
	if state != nil {
		state.LastActivityAt = time.Now().UTC()
	}
}

func isValidLifecycleTransition(from, to PlanLifecycle) bool {
	// Ordered lifecycle: draft → validated → armed → active → partially_exposed → locked → stale → retired
	order := map[PlanLifecycle]int{
		PlanDraft:            0,
		PlanValidated:        1,
		PlanArmed:            2,
		PlanActive:           3,
		PlanPartiallyExposed: 4,
		PlanLocked:           5,
		PlanStale:            6,
		PlanRetired:          7,
	}
	fromOrd, fromOk := order[from]
	toOrd, toOk := order[to]
	if !fromOk || !toOk {
		return false
	}
	// Can only advance forward; stale can go to retired; active can be invalidated to stale
	return toOrd > fromOrd || (from == PlanActive && to == PlanStale)
}

// detectPlanDeviation checks if a command deviates from expected plan behavior.
func detectPlanDeviation(command string, invalidators []string) (bool, string) {
	lower := strings.ToLower(command)
	for _, pattern := range invalidators {
		if pattern == "" {
			continue
		}
		if strings.Contains(lower, strings.ToLower(pattern)) {
			return true, pattern
		}
	}
	return false, ""
}
