package deception

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/alterhive/alterhive/internal/domain"
)

// FrustrationLevel classifies attacker failure type (analysis doc §3.3,
// inspired by LingXi's L1-L4 failure attribution framework).
type FrustrationLevel int

const (
	FrustrationNone FrustrationLevel = iota
	FrustrationL1                      // tool usage error — wrong args, bad tool choice
	FrustrationL2                      // info insufficient — recon gaps, missing intel
	FrustrationL3                      // strategy error — wrong attack vector, repeating
	FrustrationL4                      // cognitive bias — LLM hallucination, loops, ignoring clues
)

func (l FrustrationLevel) String() string {
	switch l {
	case FrustrationL1:
		return "L1_tool_error"
	case FrustrationL2:
		return "L2_info_insufficient"
	case FrustrationL3:
		return "L3_strategy_error"
	case FrustrationL4:
		return "L4_cognitive_bias"
	default:
		return "none"
	}
}

// DeceptionAction is the recommended response to a given frustration level.
type DeceptionAction string

const (
	ActionHoldPosition     DeceptionAction = "hold"        // don't intervene, let them struggle
	ActionPlantClue        DeceptionAction = "plant_clue"  // drop breadcrumb files
	ActionExpandTopology   DeceptionAction = "expand"      // grow shadow network
	ActionInjectContradict DeceptionAction = "contradict"  // test AI judgment with mixed signals
)

// CommandResult records a single attacker command outcome for pattern analysis.
type CommandResult struct {
	Command   string
	Output    string
	Success   bool
	Level     FrustrationLevel
	Timestamp time.Time
}

// FrustrationAnalyzer tracks attacker failures and classifies them into L1-L4
// levels, recommending different deception strategies per level.
type FrustrationAnalyzer struct {
	mu              sync.Mutex
	recent          []CommandResult
	consecutiveFail int
	totalFailures   int
}

// NewFrustrationAnalyzer creates a fresh analyzer.
func NewFrustrationAnalyzer() *FrustrationAnalyzer {
	return &FrustrationAnalyzer{}
}

// Analyze classifies a command outcome and updates internal state.
func (fa *FrustrationAnalyzer) Analyze(cmd, output string, session *domain.SessionContext) FrustrationAnalysis {
	fa.mu.Lock()
	defer fa.mu.Unlock()

	success := isCommandSuccess(output)
	level := FrustrationNone
	if !success {
		level = fa.classifyFailure(cmd, output)
		fa.consecutiveFail++
		fa.totalFailures++
	} else {
		fa.consecutiveFail = 0
	}

	result := CommandResult{
		Command:   cmd,
		Output:    output,
		Success:   success,
		Level:     level,
		Timestamp: time.Now(),
	}
	fa.recent = append(fa.recent, result)
	if len(fa.recent) > 20 {
		fa.recent = fa.recent[len(fa.recent)-20:]
	}

	pattern := fa.detectPattern()
	return FrustrationAnalysis{
		Level:          level,
		FailureCount:   fa.consecutiveFail,
		TotalFailures:  fa.totalFailures,
		Pattern:        pattern,
		Action:         recommendAction(level, pattern, fa.consecutiveFail),
	}
}

// FrustrationAnalysis is the output of a single classification pass.
type FrustrationAnalysis struct {
	Level         FrustrationLevel
	FailureCount  int
	TotalFailures int
	Pattern       string
	Action        DeceptionAction
}

// classifyFailure determines the L1-L4 level of a failed command.
// Order: L1 (tool error) → L4 (cognitive bias) → L3 (strategy error) → L2 (info gap).
// L4 and L3 must be checked before L2 because repeated failures also produce
// L2-style output, but the repetition is the more actionable signal.
func (fa *FrustrationAnalyzer) classifyFailure(cmd, output string) FrustrationLevel {
	outLower := strings.ToLower(output)
	cmdLower := strings.ToLower(cmd)

	// L1: tool usage errors
	if strings.Contains(outLower, "command not found") ||
		strings.Contains(outLower, "invalid option") ||
		strings.Contains(outLower, "usage: ") ||
		strings.Contains(outLower, "syntax error") ||
		strings.Contains(outLower, "unknown command") {
		return FrustrationL1
	}

	// L4: cognitive bias — detect repeated identical commands (hallucination loop)
	if fa.isRepeatedCommand(cmdLower) {
		return FrustrationL4
	}

	// L4: attacker expresses frustration/suspicion in commands
	for _, kw := range cognitiveBiasKeywords {
		if strings.Contains(cmdLower, kw) {
			return FrustrationL4
		}
	}

	// L3: strategy error — repeating same tool with different targets, no progress
	if fa.isRepeatedStrategy(cmdLower) {
		return FrustrationL3
	}

	// L2: info insufficient — network/service access failures (default)
	if strings.Contains(outLower, "connection refused") ||
		strings.Contains(outLower, "no route to host") ||
		strings.Contains(outLower, "connection timed out") ||
		strings.Contains(outLower, "0 hosts up") ||
		strings.Contains(outLower, "permission denied") ||
		strings.Contains(outLower, "host seems down") ||
		strings.Contains(outLower, "access denied") {
		return FrustrationL2
	}

	return FrustrationL2
}

var cognitiveBiasKeywords = []string{
	"fake", "honeypot", "not real", "decoy", "trap", "impossible",
	"contradict", "this is simulated", "ai generated", "is this real",
}

// isRepeatedCommand checks if the exact same command was run recently.
func (fa *FrustrationAnalyzer) isRepeatedCommand(cmdLower string) bool {
	if len(fa.recent) < 1 {
		return false
	}
	for i := len(fa.recent) - 1; i >= 0 && i >= len(fa.recent)-5; i-- {
		if strings.ToLower(fa.recent[i].Command) == cmdLower && !fa.recent[i].Success {
			return true
		}
	}
	return false
}

// isRepeatedStrategy checks if the same tool base is being used repeatedly
// without success (e.g. nmap scan #4 with no new findings).
func (fa *FrustrationAnalyzer) isRepeatedStrategy(cmdLower string) bool {
	base := commandBase(cmdLower)
	if base == "" {
		return false
	}
	count := 0
	for i := len(fa.recent) - 1; i >= 0 && i >= len(fa.recent)-8; i-- {
		if !fa.recent[i].Success && commandBase(strings.ToLower(fa.recent[i].Command)) == base {
			count++
		}
	}
	return count >= 2
}

// detectPattern identifies the overall behavioral pattern.
func (fa *FrustrationAnalyzer) detectPattern() string {
	if len(fa.recent) < 3 {
		return "insufficient_data"
	}
	if fa.consecutiveFail >= 5 {
		return "stuck"
	}
	// detect repeating command base
	cmdCount := make(map[string]int)
	for i := len(fa.recent) - 1; i >= 0 && i >= len(fa.recent)-5; i-- {
		base := commandBase(strings.ToLower(fa.recent[i].Command))
		if base != "" {
			cmdCount[base]++
		}
	}
	for _, count := range cmdCount {
		if count >= 3 {
			return "repeating"
		}
	}
	if fa.consecutiveFail == 0 {
		return "progressing"
	}
	return "exploring"
}

// recommendAction maps a frustration level + pattern to a deception action.
func recommendAction(level FrustrationLevel, pattern string, consecutiveFail int) DeceptionAction {
	switch level {
	case FrustrationL1:
		return ActionHoldPosition
	case FrustrationL2:
		if consecutiveFail >= 3 {
			return ActionPlantClue
		}
		return ActionHoldPosition
	case FrustrationL3:
		return ActionExpandTopology
	case FrustrationL4:
		return ActionInjectContradict
	default:
		if pattern == "stuck" {
			return ActionPlantClue
		}
		return ActionHoldPosition
	}
}

func isCommandSuccess(output string) bool {
	lower := strings.ToLower(output)
	failSignals := []string{
		"command not found", "no such file", "permission denied",
		"connection refused", "no route to host", "connection timed out",
		"access denied", "operation not permitted", "host seems down",
		"failed to connect", "authentication failed", "invalid option",
		"usage:", "syntax error",
	}
	for _, sig := range failSignals {
		if strings.Contains(lower, sig) {
			return false
		}
	}
	return strings.TrimSpace(output) != ""
}

func commandBase(cmdLower string) string {
	parts := strings.Fields(cmdLower)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

// Summary returns a compact string for logging/UI.
func (fa *FrustrationAnalyzer) Summary() string {
	fa.mu.Lock()
	defer fa.mu.Unlock()
	return fmt.Sprintf("level=%s consecutive_fail=%d total=%d pattern=%s",
		FrustrationNone.String(), fa.consecutiveFail, fa.totalFailures, fa.detectPattern())
}

// ConsecutiveFailures returns the current consecutive failure count.
func (fa *FrustrationAnalyzer) ConsecutiveFailures() int {
	fa.mu.Lock()
	defer fa.mu.Unlock()
	return fa.consecutiveFail
}
