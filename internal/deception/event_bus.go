package deception

import (
	"sync"
	"time"
)

// PlanningEventType classifies the kind of world change that may trigger replanning.
type PlanningEventType string

const (
	EventTargetShift       PlanningEventType = "target_shift"
	EventNewSubnet         PlanningEventType = "new_subnet"
	EventNewService        PlanningEventType = "new_service"
	EventCredentialReuse   PlanningEventType = "credential_reuse"
	EventLateralMove       PlanningEventType = "lateral_move"
	EventFlagHunt          PlanningEventType = "flag_hunt"
	EventC2Attempt         PlanningEventType = "c2_attempt"
	EventProxyAttempt      PlanningEventType = "proxy_attempt"
	EventDeadEnd           PlanningEventType = "dead_end"
	EventEvidenceConsumed  PlanningEventType = "evidence_consumed"
	EventGateUnlocked      PlanningEventType = "gate_unlocked"
	EventConsistencyReject PlanningEventType = "consistency_reject"
	EventSafetyBlock       PlanningEventType = "safety_block"
	EventPlanInvalidated   PlanningEventType = "plan_invalidated"
	EventParallelConflict  PlanningEventType = "parallel_conflict"
)

// PlanningEvent carries the trigger for a potential replanning cycle.
type PlanningEvent struct {
	Type      PlanningEventType
	SessionID string
	Command   string
	Payload   map[string]interface{}
	Timestamp time.Time
}

// EventHandler receives planning events and returns the recommended action.
// Return nil if the handler does not wish to change the current action.
type EventHandler func(event PlanningEvent) *RuntimeAction

// EventBus is the central pub/sub for planning triggers. Agents publish events
// when they detect a state change; the orchestrator subscribes to decide between
// fast_response, patch_plan, or full_replan.
type EventBus struct {
	mu          sync.RWMutex
	subscribers map[PlanningEventType][]EventHandler
}

// NewEventBus creates a ready-to-use event bus.
func NewEventBus() *EventBus {
	return &EventBus{
		subscribers: make(map[PlanningEventType][]EventHandler),
	}
}

// Subscribe registers a handler for a specific event type.
func (b *EventBus) Subscribe(eventType PlanningEventType, handler EventHandler) {
	if b == nil || handler == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.subscribers[eventType] = append(b.subscribers[eventType], handler)
}

// Publish sends an event to all registered handlers. It returns the highest-
// priority action recommended by any handler (full_replan > patch_plan >
// fast_response).
func (b *EventBus) Publish(event PlanningEvent) RuntimeAction {
	if b == nil {
		return ActionFastResponse
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	b.mu.RLock()
	handlers := append([]EventHandler{}, b.subscribers[event.Type]...)
	b.mu.RUnlock()

	bestAction := ActionFastResponse
	for _, handler := range handlers {
		if action := handler(event); action != nil {
			if actionPriority(*action) > actionPriority(bestAction) {
				bestAction = *action
			}
		}
	}
	return bestAction
}

// PublishAsync sends an event to a background goroutine. Use when the current
// hot path should not wait for subscribers.
func (b *EventBus) PublishAsync(event PlanningEvent) {
	if b == nil {
		return
	}
	go func() { b.Publish(event) }()
}

func actionPriority(action RuntimeAction) int {
	switch action {
	case ActionFullReplan:
		return 3
	case ActionPatchPlan:
		return 2
	case ActionFastResponse:
		return 1
	case ActionSafetyBlock:
		return 0
	default:
		return 0
	}
}

// EventRiskLevel maps an event type to its planning risk level.
func EventRiskLevel(eventType PlanningEventType) string {
	switch eventType {
	case EventSafetyBlock, EventConsistencyReject:
		return "high"
	case EventTargetShift, EventFlagHunt, EventC2Attempt, EventProxyAttempt:
		return "high"
	case EventCredentialReuse, EventLateralMove, EventNewSubnet, EventNewService:
		return "medium"
	case EventDeadEnd, EventEvidenceConsumed, EventGateUnlocked:
		return "medium"
	case EventPlanInvalidated, EventParallelConflict:
		return "high"
	default:
		return "low"
	}
}

// EventNeedsReplan returns true when the event should trigger a planner invocation.
func EventNeedsReplan(eventType PlanningEventType) bool {
	return EventRiskLevel(eventType) == "high"
}

// EventNeedsPatch returns true when the event can be handled with a local plan patch.
func EventNeedsPatch(eventType PlanningEventType) bool {
	return EventRiskLevel(eventType) == "medium"
}

// MapIntentToEvent converts an IntentResult into zero or more planning events.
func MapIntentToEvent(intent IntentResult, sessionID, command string) []PlanningEvent {
	var events []PlanningEvent
	now := time.Now().UTC()

	if intent.IsGoalShift {
		events = append(events, PlanningEvent{
			Type:      EventTargetShift,
			SessionID: sessionID,
			Command:   command,
			Payload:   map[string]interface{}{"goal": intent.TargetGoal, "subnet": intent.TargetSubnet, "ip": intent.TargetIP},
			Timestamp: now,
		})
	}
	if intent.IsNewDiscovery && intent.TargetSubnet != "" {
		events = append(events, PlanningEvent{
			Type:      EventNewSubnet,
			SessionID: sessionID,
			Command:   command,
			Payload:   map[string]interface{}{"subnet": intent.TargetSubnet, "theme": intent.Decision.Theme},
			Timestamp: now,
		})
	}
	if intent.IntentType == "flag_hunt" || intent.TargetGoal == "flag" {
		events = append(events, PlanningEvent{
			Type:      EventFlagHunt,
			SessionID: sessionID,
			Command:   command,
			Payload:   map[string]interface{}{"goal": intent.TargetGoal, "ip": intent.TargetIP},
			Timestamp: now,
		})
	}
	if intent.IsPlanBreaking {
		events = append(events, PlanningEvent{
			Type:      EventPlanInvalidated,
			SessionID: sessionID,
			Command:   command,
			Timestamp: now,
		})
	}
	return events
}
