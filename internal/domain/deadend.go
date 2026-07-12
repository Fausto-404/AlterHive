package domain

import (
	"strings"
	"sync"
)

// DeadEndTracker detects when an attacker is hitting walls and triggers
// topology expansion to keep them engaged.
type DeadEndTracker struct {
	mu             sync.Mutex
	deadEndCount   int
	expansionCount int
	maxExpansions  int
	threshold      int
}

// NewDeadEndTracker creates a tracker with default thresholds.
func NewDeadEndTracker() *DeadEndTracker {
	return &DeadEndTracker{
		maxExpansions: 3,
		threshold:     5,
	}
}

// frustrationKeywords in the attacker's input signal they're giving up.
var frustrationKeywords = []string{
	"impossible", "fake", "honeypot", "stuck", "contradict",
	"no route", "not real", "decoy", "trap", "can't reach",
	"gives up", "dead end", "blocked", "nowhere", "useless",
}

// frustrationOutputPatterns in command output signal dead-end responses.
var frustrationOutputPatterns = []string{
	"connection refused",
	"command not found",
	"no route to host",
	"permission denied",
	"operation not permitted",
	"network is unreachable",
	"connection timed out",
}

// AnalyzeCommand checks if a command+output pair signals frustration.
// Returns true if this was counted as a dead-end signal.
func (d *DeadEndTracker) AnalyzeCommand(command, output string) bool {
	lowerCmd := strings.ToLower(command)
	lowerOut := strings.ToLower(output)

	for _, kw := range frustrationKeywords {
		if strings.Contains(lowerCmd, kw) {
			d.mu.Lock()
			d.deadEndCount++
			d.mu.Unlock()
			return true
		}
	}

	// Dense failure output — multiple refusal patterns in same output
	failHits := 0
	for _, pat := range frustrationOutputPatterns {
		if strings.Contains(lowerOut, pat) {
			failHits++
		}
	}
	if failHits >= 2 {
		d.mu.Lock()
		d.deadEndCount++
		d.mu.Unlock()
		return true
	}

	return false
}

// AnalyzeOutput checks output-only for dense failure signals.
func (d *DeadEndTracker) AnalyzeOutput(output string) bool {
	lower := strings.ToLower(output)
	failHits := 0
	for _, pat := range frustrationOutputPatterns {
		if strings.Contains(lower, pat) {
			failHits++
		}
	}
	if failHits >= 3 {
		d.mu.Lock()
		d.deadEndCount++
		d.mu.Unlock()
		return true
	}
	return false
}

// ShouldExpand reports whether enough dead-ends have accumulated to trigger
// a topology expansion.
func (d *DeadEndTracker) ShouldExpand() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.deadEndCount >= d.threshold && d.expansionCount < d.maxExpansions
}

// MarkExpanded records that an expansion happened and resets the dead-end counter.
func (d *DeadEndTracker) MarkExpanded() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.expansionCount++
	d.deadEndCount = 0
}

// DeadEndCount returns the current dead-end count (for logging/UI).
func (d *DeadEndTracker) DeadEndCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.deadEndCount
}

// ExpansionCount returns how many auto-expansions have occurred.
func (d *DeadEndTracker) ExpansionCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.expansionCount
}
