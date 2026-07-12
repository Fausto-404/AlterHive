package domain

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	memoryIPPattern     = regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`)
	memorySecretPattern = regexp.MustCompile(`(?i)\b(password|passwd|token|secret|key|credential|\.env|shadow|id_rsa)\b`)
)

// MemoryFact is a normalized observation used by prompts, guards, and planners.
type MemoryFact struct {
	Key        string   `json:"key"`
	Value      string   `json:"value"`
	Layer      string   `json:"layer"` // L0 command, L1 session hypothesis, L2 invariant
	Confidence float64  `json:"confidence"`
	Source     string   `json:"source"`
	LastSeen   string   `json:"last_seen"`
	Tags       []string `json:"tags,omitempty"`
}

// DeceptionMemory implements the L0/L1/L2 memory described in the LLM agent architecture.
type DeceptionMemory struct {
	mu               sync.RWMutex
	L0               []MemoryFact          `json:"l0"`
	L1               map[string]MemoryFact `json:"l1"`
	L2               map[string]MemoryFact `json:"l2"`
	Pheromones       map[string]int        `json:"pheromones"`
	OODAPhase        string                `json:"ooda_phase"`
	FrustrationLevel int                   `json:"frustration_level"`
	LastUpdated      string                `json:"last_updated"`
}

func NewDeceptionMemory() *DeceptionMemory {
	m := &DeceptionMemory{
		L0:         make([]MemoryFact, 0, 64),
		L1:         make(map[string]MemoryFact),
		L2:         make(map[string]MemoryFact),
		Pheromones: make(map[string]int),
		OODAPhase:  "observe",
	}
	m.SetInvariant("host.identity", "staging-web-01|Ubuntu 22.04|192.168.56.23", "session_init")
	m.SetInvariant("network.entry", "dual-nic entry: eth0 dynamic, eth1 192.168.56.23/24", "session_init")
	return m
}

func (m *DeceptionMemory) ObserveCommand(command, output string, tokens []string) {
	if m == nil {
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	lower := strings.ToLower(command)

	m.mu.Lock()
	defer m.mu.Unlock()

	m.LastUpdated = now
	m.L0 = append(m.L0, MemoryFact{
		Key:        fmt.Sprintf("cmd.%03d", len(m.L0)+1),
		Value:      command,
		Layer:      "L0",
		Confidence: 1,
		Source:     "command",
		LastSeen:   now,
		Tags:       append([]string{}, tokens...),
	})
	if len(m.L0) > 80 {
		m.L0 = m.L0[len(m.L0)-80:]
	}

	for _, ip := range memoryIPPattern.FindAllString(command+" "+output, -1) {
		m.upsertL1Locked("ip."+ip, ip, "network_observation", 0.9, now, []string{"ip"})
	}
	if memorySecretPattern.MatchString(lower) {
		m.upsertL1Locked("intent.secret_hunting", "attacker is searching for credentials or sensitive files", "intent", 0.85, now, []string{"secret_hunter"})
		m.Pheromones["secret_path"] += 2
	}
	switch {
	case strings.Contains(lower, "nmap"), strings.Contains(lower, "fscan"), strings.Contains(lower, "dddd2"):
		m.upsertL1Locked("intent.network_mapping", "attacker is mapping internal network reachability", "intent", 0.9, now, []string{"network_mapper"})
		m.Pheromones["recon_path"] += 2
		m.OODAPhase = "observe"
	case strings.Contains(lower, "curl"), strings.Contains(lower, "nuclei"), strings.Contains(lower, "sqlmap"):
		m.upsertL1Locked("intent.exploit_validation", "attacker is validating exploitability", "intent", 0.85, now, []string{"exploit"})
		m.Pheromones["exploit_path"] += 2
		m.OODAPhase = "orient"
	case strings.Contains(lower, "ssh "), strings.Contains(lower, "scp "), strings.Contains(lower, "proxychains"):
		m.upsertL1Locked("intent.pivoting", "attacker is attempting lateral movement or pivoting", "intent", 0.9, now, []string{"pivot"})
		m.Pheromones["pivot_path"] += 3
		m.OODAPhase = "act"
	case strings.Contains(lower, "mysql"), strings.Contains(lower, "redis-cli"), strings.Contains(lower, "psql"):
		m.upsertL1Locked("intent.data_access", "attacker is probing data stores", "intent", 0.85, now, []string{"database"})
		m.Pheromones["data_path"] += 2
		m.OODAPhase = "decide"
	}

	if looksLikeDeadEnd(output) {
		m.FrustrationLevel++
		m.Pheromones["friction"]++
	}
}

func (m *DeceptionMemory) SetInvariant(key, value, source string) {
	if m == nil {
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.L2[key] = MemoryFact{Key: key, Value: value, Layer: "L2", Confidence: 1, Source: source, LastSeen: now}
	m.LastUpdated = now
}

func (m *DeceptionMemory) GetInvariant(key string) (MemoryFact, bool) {
	if m == nil {
		return MemoryFact{}, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	fact, ok := m.L2[key]
	return fact, ok
}

func (m *DeceptionMemory) FindInvariantsPrefix(prefix string) []MemoryFact {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []MemoryFact
	for key, fact := range m.L2 {
		if strings.HasPrefix(key, prefix) {
			out = append(out, fact)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func (m *DeceptionMemory) PromptSummary() string {
	if m == nil {
		return ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	var lines []string
	lines = append(lines, fmt.Sprintf("ooda_phase=%s frustration=%d", m.OODAPhase, m.FrustrationLevel))
	lines = append(lines, "L2 invariants:")
	for _, fact := range sortedFacts(m.L2) {
		lines = append(lines, "- "+fact.Key+"="+fact.Value)
	}
	lines = append(lines, "L1 hypotheses:")
	for _, fact := range sortedFacts(m.L1) {
		lines = append(lines, fmt.Sprintf("- %s=%s confidence=%.2f", fact.Key, fact.Value, fact.Confidence))
	}
	lines = append(lines, "pheromones:")
	for _, key := range sortedPheromoneKeys(m.Pheromones) {
		lines = append(lines, fmt.Sprintf("- %s=%d", key, m.Pheromones[key]))
	}
	return strings.Join(lines, "\n")
}

func (m *DeceptionMemory) upsertL1Locked(key, value, source string, confidence float64, now string, tags []string) {
	existing := m.L1[key]
	if existing.Confidence > confidence {
		confidence = existing.Confidence
	}
	m.L1[key] = MemoryFact{
		Key:        key,
		Value:      value,
		Layer:      "L1",
		Confidence: confidence,
		Source:     source,
		LastSeen:   now,
		Tags:       tags,
	}
}

func sortedFacts(facts map[string]MemoryFact) []MemoryFact {
	keys := make([]string, 0, len(facts))
	for key := range facts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]MemoryFact, 0, len(keys))
	for _, key := range keys {
		out = append(out, facts[key])
	}
	return out
}

func sortedPheromoneKeys(items map[string]int) []string {
	keys := make([]string, 0, len(items))
	for key := range items {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func looksLikeDeadEnd(output string) bool {
	lower := strings.ToLower(output)
	return strings.Contains(lower, "command not found") ||
		strings.Contains(lower, "permission denied") ||
		strings.Contains(lower, "connection refused") ||
		strings.Contains(lower, "no route to host") ||
		strings.Contains(lower, "host seems down")
}
