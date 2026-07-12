package deception

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/alterhive/alterhive/internal/domain"
)

// CacheLayer identifies which cache tier a lookup targets.
type CacheLayer string

const (
	CacheLayerPlan     CacheLayer = "plan"
	CacheLayerResponse CacheLayer = "response"
	CacheLayerIntent   CacheLayer = "intent"
	CacheLayerPersona  CacheLayer = "persona"
	CacheLayerEvidence CacheLayer = "evidence"
	CacheLayerWorld    CacheLayer = "world"
)

// CacheEntry is the common metadata every cache entry carries.
type CacheEntry struct {
	Key        string    `json:"key"`
	Layer      CacheLayer `json:"layer"`
	CreatedAt  time.Time `json:"created_at"`
	LastAccess time.Time `json:"last_access"`
	HitCount   int       `json:"hit_count"`
	TTL        time.Duration `json:"ttl,omitempty"`
}

// PersonaCacheEntry stores a service fingerprint keyed by host+service.
type PersonaCacheEntry struct {
	HostIP    string `json:"host_ip"`
	Service   string `json:"service"`
	Banner    string `json:"banner"`
	Version   string `json:"version,omitempty"`
	Port      int    `json:"port"`
	PlanID    string `json:"plan_id,omitempty"`
}

// EvidenceCacheEntry stores evidence specs keyed by goal+service+phase.
type EvidenceCacheEntry struct {
	Goal        string   `json:"goal"`
	Service     string   `json:"service"`
	Phase       string   `json:"phase"`
	EvidenceIDs []string `json:"evidence_ids"`
	PlanID      string   `json:"plan_id,omitempty"`
}

// WorldCacheEntry tracks a world state snapshot.
type WorldCacheEntry struct {
	WorldVersion       int64  `json:"world_version"`
	ExposedFactVersion int64  `json:"exposed_fact_version"`
	SessionID          string `json:"session_id"`
	BranchID           string `json:"branch_id,omitempty"`
	Status             string `json:"status"` // active, branch, retired
}

// CacheStats holds aggregate hit/miss/eviction counters per layer.
type CacheStats struct {
	Layer      CacheLayer `json:"layer"`
	Hits       int64      `json:"hits"`
	Misses     int64      `json:"misses"`
	Evictions  int64      `json:"evictions"`
	Entries    int        `json:"entries"`
	MaxEntries int        `json:"max_entries"`
}

// CacheManagerAgent provides a unified multi-layer cache with precise
// invalidation. It wraps existing caches (PlanningState response cache,
// IntentRouterAgent intent cache, AgentOrchestrator plan cache) and adds
// persona, evidence, and world caches.
type CacheManagerAgent struct {
	mu sync.RWMutex

	// Plan cache: keyed by session_id + goal_signature + phase + world_version
	planCache map[string]bool

	// Persona cache: keyed by host_ip + service
	personaCache map[string]PersonaCacheEntry

	// Evidence cache: keyed by goal + service + phase
	evidenceCache map[string]EvidenceCacheEntry

	// World cache: keyed by session_id + branch_id
	worldCache map[string]WorldCacheEntry

	// Per-layer stats
	stats map[CacheLayer]*CacheStats

	// Per-layer max sizes
	maxPlanEntries     int
	maxPersonaEntries  int
	maxEvidenceEntries int
	maxWorldEntries    int

	// Invalidation hooks
	onInvalidate []func(layer CacheLayer, key string)
}

// NewCacheManager creates a ready-to-use cache manager with sensible defaults.
func NewCacheManager() *CacheManagerAgent {
	return &CacheManagerAgent{
		planCache:          make(map[string]bool),
		personaCache:       make(map[string]PersonaCacheEntry),
		evidenceCache:      make(map[string]EvidenceCacheEntry),
		worldCache:         make(map[string]WorldCacheEntry),
		stats:              make(map[CacheLayer]*CacheStats),
		maxPlanEntries:     256,
		maxPersonaEntries:  128,
		maxEvidenceEntries: 128,
		maxWorldEntries:    32,
	}
}

// OnInvalidate registers a callback fired when a cache entry is evicted or
// explicitly invalidated. Use for metrics or secondary index cleanup.
func (c *CacheManagerAgent) OnInvalidate(fn func(layer CacheLayer, key string)) {
	if c == nil || fn == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onInvalidate = append(c.onInvalidate, fn)
}

// ---- Plan Cache -----------------------------------------------------------

// PlanKey builds a deterministic plan cache key.
func PlanCacheKey(sessionID, goalSig, phase string, worldVersion int64) string {
	return fmt.Sprintf("plan:%s:%s:%s:%d", sessionID, goalSig, phase, worldVersion)
}

// HasPlan returns true if a plan has already been executed for this key.
func (c *CacheManagerAgent) HasPlan(key string) bool {
	if c == nil || key == "" {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	ok := c.planCache[key]
	c.recordAccess(CacheLayerPlan, ok)
	return ok
}

// MarkPlan records a plan as executed. Returns false if it was already marked.
func (c *CacheManagerAgent) MarkPlan(key string) bool {
	if c == nil || key == "" {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.planCache[key] {
		c.recordHitLocked(CacheLayerPlan)
		return false
	}
	if len(c.planCache) >= c.maxPlanEntries {
		c.evictPlanLocked()
	}
	c.planCache[key] = true
	c.recordMissLocked(CacheLayerPlan)
	return true
}

// InvalidatePlan removes a specific plan cache entry.
func (c *CacheManagerAgent) InvalidatePlan(key string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.planCache, key)
	c.fireInvalidate(CacheLayerPlan, key)
}

// InvalidatePlanBySession removes all plan entries for a session.
func (c *CacheManagerAgent) InvalidatePlanBySession(sessionID string) {
	if c == nil || sessionID == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	prefix := "plan:" + sessionID + ":"
	for k := range c.planCache {
		if strings.HasPrefix(k, prefix) {
			delete(c.planCache, k)
			c.fireInvalidate(CacheLayerPlan, k)
		}
	}
}

// ---- Response Cache (delegates to PlanningState) --------------------------

// LookupResponse checks the versioned response cache in PlanningState.
func (c *CacheManagerAgent) LookupResponse(planning *domain.PlanningState, key string) (string, bool) {
	if planning == nil {
		return "", false
	}
	output, ok := planning.LookupResponse(key)
	if c != nil {
		c.mu.Lock()
		c.recordAccessLocked(CacheLayerResponse, ok)
		c.mu.Unlock()
	}
	return output, ok
}

// StoreResponse stores a response in the versioned cache.
func (c *CacheManagerAgent) StoreResponse(planning *domain.PlanningState, key, output string) {
	if planning == nil {
		return
	}
	planning.StoreResponse(key, output)
}

// ResponseCacheKey builds a deterministic response cache key.
func ResponseCacheKey(command, contextID string, worldVersion, exposedFactVersion int64) string {
	hash := sha256.Sum256([]byte(command + "|" + contextID))
	return fmt.Sprintf("resp:%x:%d:%d", hash[:8], worldVersion, exposedFactVersion)
}

// ---- Intent Cache ---------------------------------------------------------

// IntentCacheKey builds a deterministic intent cache key.
func IntentCacheKey(sessionID, planID, goal, command string) string {
	return fmt.Sprintf("intent:%s:%s:%s:%s", sessionID, planID, goal, normalizedCommand(command))
}

// ---- Persona Cache --------------------------------------------------------

// PersonaKey builds a deterministic persona cache key.
func PersonaKey(hostIP, service string) string {
	return fmt.Sprintf("persona:%s:%s", hostIP, service)
}

// LookupPersona returns a cached service persona if present.
func (c *CacheManagerAgent) LookupPersona(key string) (PersonaCacheEntry, bool) {
	if c == nil || key == "" {
		return PersonaCacheEntry{}, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.personaCache[key]
	if ok {
		c.recordAccessLocked(CacheLayerPersona, true)
	}
	return entry, ok
}

// StorePersona caches a service persona fingerprint.
func (c *CacheManagerAgent) StorePersona(entry PersonaCacheEntry) {
	if c == nil || entry.HostIP == "" || entry.Service == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	key := PersonaKey(entry.HostIP, entry.Service)
	if len(c.personaCache) >= c.maxPersonaEntries {
		c.evictPersonaLocked()
	}
	c.personaCache[key] = entry
}

// InvalidatePersonaByPlan removes all persona entries for a plan.
func (c *CacheManagerAgent) InvalidatePersonaByPlan(planID string) {
	if c == nil || planID == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, v := range c.personaCache {
		if v.PlanID == planID {
			delete(c.personaCache, k)
			c.fireInvalidate(CacheLayerPersona, k)
		}
	}
}

// ---- Evidence Cache -------------------------------------------------------

// EvidenceKey builds a deterministic evidence cache key.
func EvidenceKey(goal, service, phase string) string {
	return fmt.Sprintf("evidence:%s:%s:%s", goal, service, phase)
}

// LookupEvidence returns cached evidence specs.
func (c *CacheManagerAgent) LookupEvidence(key string) (EvidenceCacheEntry, bool) {
	if c == nil || key == "" {
		return EvidenceCacheEntry{}, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.evidenceCache[key]
	if ok {
		c.recordAccessLocked(CacheLayerEvidence, true)
	}
	return entry, ok
}

// StoreEvidence caches evidence specs.
func (c *CacheManagerAgent) StoreEvidence(entry EvidenceCacheEntry) {
	if c == nil || entry.Goal == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	key := EvidenceKey(entry.Goal, entry.Service, entry.Phase)
	if len(c.evidenceCache) >= c.maxEvidenceEntries {
		c.evictEvidenceLocked()
	}
	c.evidenceCache[key] = entry
}

// InvalidateEvidenceByPlan removes all evidence entries for a plan.
func (c *CacheManagerAgent) InvalidateEvidenceByPlan(planID string) {
	if c == nil || planID == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, v := range c.evidenceCache {
		if v.PlanID == planID {
			delete(c.evidenceCache, k)
			c.fireInvalidate(CacheLayerEvidence, k)
		}
	}
}

// ---- World Cache ----------------------------------------------------------

// WorldKey builds a deterministic world cache key.
func WorldKey(sessionID, branchID string) string {
	return fmt.Sprintf("world:%s:%s", sessionID, branchID)
}

// LookupWorld returns a cached world state entry.
func (c *CacheManagerAgent) LookupWorld(key string) (WorldCacheEntry, bool) {
	if c == nil || key == "" {
		return WorldCacheEntry{}, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.worldCache[key]
	if ok {
		c.recordAccessLocked(CacheLayerWorld, true)
	}
	return entry, ok
}

// StoreWorld caches a world state snapshot.
func (c *CacheManagerAgent) StoreWorld(entry WorldCacheEntry) {
	if c == nil || entry.SessionID == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	key := WorldKey(entry.SessionID, entry.BranchID)
	if len(c.worldCache) >= c.maxWorldEntries {
		c.evictWorldLocked()
	}
	c.worldCache[key] = entry
}

// InvalidateWorldBySession removes all world entries for a session.
func (c *CacheManagerAgent) InvalidateWorldBySession(sessionID string) {
	if c == nil || sessionID == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	prefix := "world:" + sessionID + ":"
	for k := range c.worldCache {
		if strings.HasPrefix(k, prefix) {
			delete(c.worldCache, k)
			c.fireInvalidate(CacheLayerWorld, k)
		}
	}
}

// ---- Bulk invalidation ----------------------------------------------------

// InvalidateSession removes all cache entries for a session across all layers.
func (c *CacheManagerAgent) InvalidateSession(sessionID string) {
	if c == nil || sessionID == "" {
		return
	}
	c.InvalidatePlanBySession(sessionID)
	c.InvalidateWorldBySession(sessionID)
}

// InvalidatePlanAcrossLayers removes all cache entries for a plan across persona and evidence layers.
func (c *CacheManagerAgent) InvalidatePlanAcrossLayers(planID string) {
	if c == nil || planID == "" {
		return
	}
	c.InvalidatePersonaByPlan(planID)
	c.InvalidateEvidenceByPlan(planID)
}

// ClearAll wipes every cache layer. Use with caution — primarily for testing.
func (c *CacheManagerAgent) ClearAll() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.planCache = make(map[string]bool)
	c.personaCache = make(map[string]PersonaCacheEntry)
	c.evidenceCache = make(map[string]EvidenceCacheEntry)
	c.worldCache = make(map[string]WorldCacheEntry)
	for layer := range c.stats {
		c.stats[layer].Entries = 0
	}
}

// ---- Stats ----------------------------------------------------------------

// Stats returns a snapshot of cache statistics for all layers.
func (c *CacheManagerAgent) Stats() []CacheStats {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	var result []CacheStats
	layers := []CacheLayer{CacheLayerPlan, CacheLayerResponse, CacheLayerIntent, CacheLayerPersona, CacheLayerEvidence, CacheLayerWorld}
	maxes := map[CacheLayer]int{
		CacheLayerPlan:     c.maxPlanEntries,
		CacheLayerResponse: 128, // managed by PlanningState
		CacheLayerIntent:   128, // managed by IntentRouterAgent
		CacheLayerPersona:  c.maxPersonaEntries,
		CacheLayerEvidence: c.maxEvidenceEntries,
		CacheLayerWorld:    c.maxWorldEntries,
	}
	entries := map[CacheLayer]int{
		CacheLayerPlan:     len(c.planCache),
		CacheLayerPersona:  len(c.personaCache),
		CacheLayerEvidence: len(c.evidenceCache),
		CacheLayerWorld:    len(c.worldCache),
	}
	for _, layer := range layers {
		st := c.stats[layer]
		if st == nil {
			st = &CacheStats{Layer: layer}
		}
		st.Entries = entries[layer]
		st.MaxEntries = maxes[layer]
		result = append(result, *st)
	}
	return result
}

// StatsSummary returns a compact one-line summary of total hits/misses.
func (c *CacheManagerAgent) StatsSummary() string {
	if c == nil {
		return "cache_manager:nil"
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	var totalHits, totalMisses int64
	for _, st := range c.stats {
		totalHits += st.Hits
		totalMisses += st.Misses
	}
	total := totalHits + totalMisses
	if total == 0 {
		return "cache_manager:no_activity"
	}
	rate := float64(totalHits) / float64(total) * 100
	return fmt.Sprintf("cache_manager:hits=%d misses=%d rate=%.1f%%", totalHits, totalMisses, rate)
}

// ---- Internal helpers -----------------------------------------------------

func (c *CacheManagerAgent) recordAccess(layer CacheLayer, hit bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.recordAccessLocked(layer, hit)
}

func (c *CacheManagerAgent) recordAccessLocked(layer CacheLayer, hit bool) {
	st := c.stats[layer]
	if st == nil {
		st = &CacheStats{Layer: layer}
		c.stats[layer] = st
	}
	if hit {
		st.Hits++
	} else {
		st.Misses++
	}
}

func (c *CacheManagerAgent) recordHitLocked(layer CacheLayer) {
	c.recordAccessLocked(layer, true)
}

func (c *CacheManagerAgent) recordMissLocked(layer CacheLayer) {
	c.recordAccessLocked(layer, false)
}

func (c *CacheManagerAgent) evictPlanLocked() {
	// Evict oldest 25% of plan entries (map iteration is random, good enough)
	count := len(c.planCache) / 4
	if count < 1 {
		count = 1
	}
	var keys []string
	for k := range c.planCache {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i := 0; i < count && i < len(keys); i++ {
		delete(c.planCache, keys[i])
		c.stats[CacheLayerPlan].Evictions++
		c.fireInvalidate(CacheLayerPlan, keys[i])
	}
}

func (c *CacheManagerAgent) evictPersonaLocked() {
	count := len(c.personaCache) / 4
	if count < 1 {
		count = 1
	}
	var keys []string
	for k := range c.personaCache {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i := 0; i < count && i < len(keys); i++ {
		delete(c.personaCache, keys[i])
		c.stats[CacheLayerPersona].Evictions++
		c.fireInvalidate(CacheLayerPersona, keys[i])
	}
}

func (c *CacheManagerAgent) evictEvidenceLocked() {
	count := len(c.evidenceCache) / 4
	if count < 1 {
		count = 1
	}
	var keys []string
	for k := range c.evidenceCache {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i := 0; i < count && i < len(keys); i++ {
		delete(c.evidenceCache, keys[i])
		c.stats[CacheLayerEvidence].Evictions++
		c.fireInvalidate(CacheLayerEvidence, keys[i])
	}
}

func (c *CacheManagerAgent) evictWorldLocked() {
	count := len(c.worldCache) / 4
	if count < 1 {
		count = 1
	}
	var keys []string
	for k := range c.worldCache {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i := 0; i < count && i < len(keys); i++ {
		delete(c.worldCache, keys[i])
		c.stats[CacheLayerWorld].Evictions++
		c.fireInvalidate(CacheLayerWorld, keys[i])
	}
}

func (c *CacheManagerAgent) fireInvalidate(layer CacheLayer, key string) {
	for _, fn := range c.onInvalidate {
		fn(layer, key)
	}
}
