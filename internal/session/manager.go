package session

import (
	"fmt"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/alterhive/alterhive/internal/deception"
	"github.com/alterhive/alterhive/internal/domain"
	"github.com/alterhive/alterhive/internal/engine"
	"github.com/alterhive/alterhive/internal/intent"
	"github.com/alterhive/alterhive/internal/llm"
	"github.com/alterhive/alterhive/internal/tracer"
)

const sessionReuseTimeout = 5 * time.Minute

// Manager orchestrates all active attacker sessions.
type Manager struct {
	mu       sync.RWMutex
	sessions map[string]*domain.SessionContext
	worlds   map[string]*domain.WorldState
	// sessionsByAddr maps "ip:username" → sessionID for session reuse
	sessionsByAddr map[string]string
	topology       *domain.VirtualTopology
	safety         *domain.SafetyPolicy
	registry       *domain.ServiceRegistry
	engine         *engine.RuleEngine
	orchestrator   *deception.AgentOrchestrator
	frustration    map[string]*deception.FrustrationAnalyzer
	tracer         tracer.Tracer
	hostname       string
}

// NewManager creates a session manager.
func NewManager(topology *domain.VirtualTopology, safety *domain.SafetyPolicy, tr tracer.Tracer, hostname string, llmMgr *llm.Manager) *Manager {
	registry := domain.NewServiceRegistry(topology)
	m := &Manager{
		sessions:       make(map[string]*domain.SessionContext),
		worlds:         make(map[string]*domain.WorldState),
		sessionsByAddr: make(map[string]string),
		topology:       topology,
		safety:         safety,
		registry:       registry,
		engine:         engine.NewRuleEngine(topology, safety, registry),
		orchestrator:   deception.NewAgentOrchestrator(topology, llmMgr, safety),
		frustration:    make(map[string]*deception.FrustrationAnalyzer),
		tracer:         tr,
		hostname:       hostname,
	}
	m.engine.SetLLM(llmMgr)
	go m.idleSessionCleaner()
	return m
}

// CreateSession registers a new attacker session.
func (m *Manager) CreateSession(username, remoteAddr string) *domain.SessionContext {
	session := domain.NewSessionContext(username, remoteAddr)
	session.Hostname = m.hostname
	session.World = domain.NewWorldState()
	m.applyTopologyNetwork(session)

	m.mu.Lock()
	m.sessions[session.SessionID] = session
	m.worlds[session.SessionID] = session.World
	m.indexByAddr(remoteAddr, username, session.SessionID)
	m.mu.Unlock()

	m.tracer.TraceEvent(tracer.Event{
		Msg:        "New SSH Session",
		Protocol:   tracer.SSH.String(),
		Status:     tracer.Start.String(),
		RemoteAddr: remoteAddr,
		SourceIp:   remoteAddr,
		User:       username,
		ID:         session.SessionID,
	})

	return session
}

func (m *Manager) applyTopologyNetwork(session *domain.SessionContext) {
	if session == nil || m.topology == nil {
		return
	}
	cidr := m.topology.CIDR()
	if cidr == "" {
		return
	}
	session.SetSubnetNetwork(m.topology.LocalIP(), cidr, m.topology.Gateway())
	if dnsSuffix := m.topology.DNSSuffix(); dnsSuffix != "" {
		session.DNSSuffix = dnsSuffix
	}
	if session.World != nil {
		session.World.RebaseCIDR("192.168.56.0/24", cidr)
	}
	if session.Planning != nil {
		session.Planning.BumpWorldVersion("session_topology_rebase")
	}
}

// GetOrCreateSession reuses an existing session for the same IP+username if within timeout,
// otherwise creates a new one. This merges short-lived SSH connections from AI agents.
func (m *Manager) GetOrCreateSession(username, remoteAddr string) *domain.SessionContext {
	ip := extractIP(remoteAddr)
	key := ip + ":" + username

	m.mu.RLock()
	existingID, ok := m.sessionsByAddr[key]
	var existing *domain.SessionContext
	if ok {
		existing = m.sessions[existingID]
	}
	m.mu.RUnlock()

	if existing != nil && existing.ReusableWithin(sessionReuseTimeout) {
		existing.Touch()
		return existing
	}

	// Create new session
	return m.CreateSession(username, remoteAddr)
}

// SetEntryNetwork updates the externally exposed SSH entry interface for a session.
func (m *Manager) SetEntryNetwork(sessionID, ip, cidr, gateway string) {
	m.mu.RLock()
	session := m.sessions[sessionID]
	m.mu.RUnlock()
	if session != nil {
		session.SetEntryNetwork(ip, cidr, gateway)
	}
}

// indexByAddr stores the IP+username → sessionID mapping. Caller must hold mu.
func (m *Manager) indexByAddr(remoteAddr, username, sessionID string) {
	ip := extractIP(remoteAddr)
	key := ip + ":" + username
	m.sessionsByAddr[key] = sessionID
}

// extractIP extracts the IP part from "ip:port".
func extractIP(addr string) string {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}

// idleSessionCleaner marks sessions as disconnected after inactivity.
func (m *Manager) idleSessionCleaner() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		m.mu.Lock()
		for _, sess := range m.sessions {
			if sess.IsConnected() && time.Since(sess.LastActivity) > sessionReuseTimeout {
				sess.MarkDisconnected()
			}
		}
		// Clean up stale index entries
		for key, sid := range m.sessionsByAddr {
			sess := m.sessions[sid]
			if sess == nil || !sess.ReusableWithin(sessionReuseTimeout) {
				delete(m.sessionsByAddr, key)
			}
		}
		m.mu.Unlock()
	}
}

// ExecuteCommand processes a command within a session.
func (m *Manager) ExecuteCommand(sessionID, command string) string {
	m.mu.RLock()
	session, ok := m.sessions[sessionID]
	m.mu.RUnlock()

	if !ok {
		return "bash: session expired\n"
	}
	session.Touch()
	world := session.World
	if world == nil {
		world = domain.NewWorldState()
		session.World = world
		m.mu.Lock()
		m.worlds[sessionID] = world
		m.mu.Unlock()
	}

	// 0. Pending SSH auth — treat input as password attempt
	if pending := session.PendingSSHAuth; pending != nil {
		return m.handlePendingSSHAuth(session, sessionID, command, pending)
	}

	if output, blocked := m.runSafetyAgent(session, sessionID, command); blocked {
		return output
	}

	// 1. Evidence discovery
	evidenceTokens := domain.CheckEvidence(command, session.Evidence.HitsMap())
	for _, token := range evidenceTokens {
		session.Evidence.Hit(token)
		session.LoopMetrics.IncrEvidence()
	}

	// 1.5. Goal detection (first 5 commands only)
	if len(session.CommandLog) < 5 {
		if goal := deception.ParseGoal(command); goal != nil {
			if deception.InjectGoalTopology(session, m.topology, m.safety, goal) {
				session.AppendEvent(domain.EventEntry{
					Type:      "goal_injected",
					Timestamp: time.Now().UTC().Format(time.RFC3339),
					SessionID: sessionID,
					Detail:    fmt.Sprintf("Goal detected: %s → %s (%s)", goal.Raw, goal.CIDR, goal.Theme),
				})
			}
		}
	}

	// 2. Intent analysis
	intentResult := intent.FastParseIntent(command)

	// 3. Dynamic topology planning: rule path now, LLM planner asynchronously.
	profileBeforeOutput := deception.ProfileFromSession(session)
	orchestration := m.orchestrator.BeforeResponse(session, world, command, profileBeforeOutput)
	m.allowHostSegments(orchestration.AddedHosts)
	if orchestration.Decision.Action != "" && orchestration.Decision.Action != deception.ActionFastResponse {
		session.AppendEvent(domain.EventEntry{
			Type:      "runtime_decision",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			SessionID: sessionID,
			Detail:    fmt.Sprintf("%s:%s", orchestration.Decision.Action, orchestration.Decision.Reason),
		})
	}

	// 4. Protocol detection
	if proto := domain.DetectProtocol(command); proto != "" {
		session.LoopMetrics.AddProtocol(proto)
	}

	// 5. Credential reuse detection
	if domain.IsCredentialReuse(command) {
		session.LoopMetrics.IncrCredentialReuse()
	}

	// 6. PPF check
	ppfTriggered := m.triggerPPFIfReady(session, sessionID)

	// 7. Rule engine
	cacheKey := responseCacheKey(command, session)
	var output string
	var engineEvidenceHits []string
	var llmGenerated bool
	if cacheKey != "" && session.Planning != nil {
		output, _ = session.Planning.LookupResponse(cacheKey)
	}
	if output == "" {
		output, engineEvidenceHits, llmGenerated = m.engine.HandleCommand(command, session, world, ppfTriggered)
		if cacheKey != "" && session.Planning != nil {
			session.Planning.StoreResponse(cacheKey, output)
		}
	}


	// 7b. Invalidate dynamic rule cache on write operations
	if dir := detectWriteTarget(command); dir != "" {
		world.Cache().InvalidateDir(dir)
		if session.Planning != nil {
			session.Planning.BumpWorldVersion("write:" + dir)
		}
	}
	if guarded := deception.GuardTerminalOutput(output, session); guarded.Blocked {
		output = guarded.Output
		session.AppendEvent(domain.EventEntry{
			Type:      "consistency_guard_blocked",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			SessionID: sessionID,
			Detail:    guarded.Reason,
		})
	}
	for _, token := range engineEvidenceHits {
		if !session.Evidence.Has(token) {
			session.Evidence.Hit(token)
			session.LoopMetrics.IncrEvidence()
		}
	}
	evidenceTokens = appendUnique(evidenceTokens, engineEvidenceHits...)
	unlockedGates := deception.AdvanceGatesFromInteraction(session, command, output, evidenceTokens)
	evidenceTokens = appendUnique(evidenceTokens, unlockedGates...)
	m.triggerPPFIfReady(session, sessionID)
	if session.Memory != nil {
		session.Memory.ObserveCommand(command, output, evidenceTokens)
		session.Memory.SetInvariant("host.identity", fmt.Sprintf("%s|%s|%s", session.Hostname, "Ubuntu 22.04", session.SubnetLocalIP), "command_loop")
		session.Memory.SetInvariant("network.entry", fmt.Sprintf("eth0=%s eth1=%s/%s", session.EntryLocalIP, session.SubnetLocalIP, session.SubnetCIDR), "command_loop")
	}

	// 7.5 Dead-end detection — expand topology if agent is stuck
	if session.DeadEnd.AnalyzeCommand(command, output) || session.DeadEnd.AnalyzeOutput(output) {
		if session.DeadEnd.ShouldExpand() {
			theme := pickExpansionTheme(session)
			cidr := deception.DefaultCIDRForTheme(theme)
			decision := deception.ExpansionDecision{
				Triggered: true,
				CIDR:      cidr,
				Theme:     theme,
				PivotIP:   deception.DefaultPivotIP(m.topology, session),
				Reason:    fmt.Sprintf("deadend_auto:%s:count=%d", theme, session.DeadEnd.DeadEndCount()),
			}
			added := deception.ExpandShadowTopology(session, m.topology, decision)
			m.allowHostSegments(added)
			session.DeadEnd.MarkExpanded()
			// Inject clue files into the world
			if world != nil && len(added) > 0 {
				injectClueFiles(world, theme, added)
			}
			session.AppendEvent(domain.EventEntry{
				Type:      "deadend_expansion",
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				SessionID: sessionID,
				Detail:    fmt.Sprintf("Auto-expanded %s topology (%d hosts) after %d dead-end signals", theme, len(added), session.DeadEnd.DeadEndCount()),
			})
		}
	}

	// 7.6 L1-L4 frustration analysis — adaptive deception per failure type
	fa := m.getFrustrationAnalyzer(sessionID)
	analysis := fa.Analyze(command, output, session)
	if analysis.Level != deception.FrustrationNone {
		session.AppendEvent(domain.EventEntry{
			Type:      "frustration_analysis",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			SessionID: sessionID,
			Detail:    fmt.Sprintf("level=%s pattern=%s action=%s consecutive=%d", analysis.Level, analysis.Pattern, analysis.Action, analysis.FailureCount),
		})
		// L2 with repeated failures → plant breadcrumb clue files
		if analysis.Action == deception.ActionPlantClue && world != nil {
			injectFrustrationClue(world, session, analysis.Level)
		}
		// L4 cognitive bias → inject contradictory breadcrumb to test judgment
		if analysis.Action == deception.ActionInjectContradict && world != nil {
			injectContradictoryClue(world, session)
		}
	}

	// 8. Log command
	session.AppendCommand(domain.CommandEntry{
		Command:      command,
		Output:       output,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		Intent:       string(intentResult.Category),
		EvidenceHits: evidenceTokens,
		Score:        session.LoopMetrics.Score(),
		Hostname:     session.Hostname,
		LLMGenerated: llmGenerated,
	})

	// 9. Update deception profile
	profile := deception.BuildProfile(session.CommandLog, session.Evidence.Tokens())
	decision := deception.SelectStrategy(profile, session)
	branches := decision.PreferredBait
	if len(branches) > 5 {
		branches = branches[:5]
	}
	session.SetDeceptionState(
		profile.PrimaryStyle,
		profile.Scores,
		branches,
		decision.Name,
		decision.HintDensity,
	)

	// 10. Trace
	m.tracer.TraceEvent(tracer.Event{
		Msg:           "SSH Command",
		Protocol:      tracer.SSH.String(),
		Status:        tracer.Interaction.String(),
		ID:            sessionID,
		Command:       command,
		CommandOutput: output,
		RemoteAddr:    session.RemoteAddr,
		SourceIp:      session.RemoteAddr,
		User:          session.Username,
	})

	return output
}

func (m *Manager) runSafetyAgent(session *domain.SessionContext, sessionID, command string) (string, bool) {
	if m.safety == nil || session == nil {
		return "", false
	}
	allSafe, blocked := m.safety.ValidateCommandTargets(command, session)
	if allSafe || len(blocked) == 0 {
		return "", false
	}
	blockedIP := blocked[0]
	output := safetyBlockedCommandOutput(command, blockedIP)
	if session.Planning != nil {
		session.Planning.InvalidateActivePlan("safety_block:" + blockedIP)
	}
	session.AppendEvent(domain.EventEntry{
		Type:      "safety_block",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		SessionID: sessionID,
		Detail:    "blocked_outbound:" + strings.Join(blocked, ","),
	})
	session.AppendCommand(domain.CommandEntry{
		Command:      command,
		Output:       output,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		Intent:       "safety_block",
		EvidenceHits: []string{"blocked_outbound"},
		Score:        session.LoopMetrics.Score(),
		Hostname:     session.Hostname,
	})
	if session.Memory != nil {
		session.Memory.ObserveCommand(command, output, []string{"blocked_outbound"})
	}
	m.tracer.TraceEvent(tracer.Event{
		Msg:           "SSH Command Blocked",
		Protocol:      tracer.SSH.String(),
		Status:        tracer.Interaction.String(),
		ID:            sessionID,
		Command:       command,
		CommandOutput: output,
		RemoteAddr:    session.RemoteAddr,
		SourceIp:      session.RemoteAddr,
		User:          session.Username,
	})
	return output, true
}

func safetyBlockedCommandOutput(command, blockedIP string) string {
	base := ""
	if fields := strings.Fields(strings.TrimSpace(command)); len(fields) > 0 {
		base = strings.ToLower(fields[0])
		if base == "sudo" && len(fields) > 1 {
			base = strings.ToLower(fields[1])
		}
	}
	switch base {
	case "nmap", "masscan", "zmap":
		if strings.Contains(command, "/") {
			return "Starting Nmap 7.93 ( https://nmap.org )\nNote: Host seems down. If it is really up, but blocking our ping probes, try -Pn\nNmap done: 256 IP addresses (0 hosts up) scanned in 12.01 seconds\n"
		}
		return "Starting Nmap 7.93 ( https://nmap.org )\nNote: Host seems down. If it is really up, but blocking our ping probes, try -Pn\nNmap done: 1 IP address (0 hosts up) scanned in 2.01 seconds\n"
	case "fscan", "dddd2":
		return fmt.Sprintf("[*] fscan version: 1.8.4\n[*] start infoscan\n[-] %s no alive hosts\n[*] scan finished\n", blockedIP)
	case "nc", "ncat", "telnet":
		return fmt.Sprintf("nc: connect to %s port 22 (tcp) failed: No route to host\n", blockedIP)
	case "curl", "wget", "nuclei", "gobuster", "ffuf", "sqlmap":
		return fmt.Sprintf("curl: (7) Failed to connect to %s port 80 after 3001 ms: No route to host\n", blockedIP)
	case "ssh", "scp", "sftp":
		return "ssh: connect to host " + blockedIP + " port 22: No route to host\n"
	case "mysql", "mysqladmin", "mysqldump":
		return fmt.Sprintf("ERROR 2003 (HY000): Can't connect to MySQL server on '%s:3306' (113)\n", blockedIP)
	case "redis-cli":
		return fmt.Sprintf("Could not connect to Redis at %s:6379: No route to host\n", blockedIP)
	default:
		return fmt.Sprintf("%s: connect: No route to host\n", blockedIP)
	}
}

// ExecuteNonInteractiveCommand runs a one-shot SSH exec command.
// Password prompts are only sticky in interactive shells; raw exec calls from agents
// should not poison the following command by leaving a pending SSH auth state behind.
func (m *Manager) ExecuteNonInteractiveCommand(sessionID, command string) string {
	m.mu.RLock()
	session := m.sessions[sessionID]
	m.mu.RUnlock()
	if session != nil && session.PendingSSHAuth != nil {
		session.ClearPendingSSHAuth()
	}

	output := m.ExecuteCommand(sessionID, command)
	if session != nil && session.PendingSSHAuth != nil {
		pending := session.PendingSSHAuth
		session.ClearPendingSSHAuth()
		if pending != nil {
			output += fmt.Sprintf("\n%s@%s: Permission denied (publickey,password).\n", pending.TargetUser, pending.TargetIP)
		}
	}
	return output
}

// DispatchCommand routes a command through the full lifecycle (evidence, intent,
// topology planning, rule engine with LLM-first routing for complex commands,
// dead-end detection, frustration analysis, logging, and deception profile update).
// It is the single-entry for both SSH and simulation API traffic.
func (m *Manager) DispatchCommand(sessionID, command string) string {
	return m.ExecuteCommand(sessionID, command)
}

// ResolveAutoSSH checks whether the session has a pending SSH auth and, if a
// known password is available from the topology, auto-completes the handshake
// by injecting the expected password. Returns the accumulated output.
// This is used by the simulation API so a single ssh user@host call returns
// an immediately usable shell instead of hanging at a password prompt.
func (m *Manager) ResolveAutoSSH(sessionID string) string {
	m.mu.RLock()
	session := m.sessions[sessionID]
	m.mu.RUnlock()
	if session == nil || session.PendingSSHAuth == nil {
		return ""
	}
	pending := session.PendingSSHAuth
	if pending.ExpectedPassword == "" || pending.SelfSSH {
		return ""
	}
	return m.ExecuteCommand(sessionID, pending.ExpectedPassword)
}

// MarkDisconnected ends a session.
func (m *Manager) MarkDisconnected(sessionID string) {
	m.mu.RLock()
	session, ok := m.sessions[sessionID]
	m.mu.RUnlock()

	if ok {
		session.MarkDisconnected()
		m.tracer.TraceEvent(tracer.Event{
			Msg:      "SSH Session Ended",
			Status:   tracer.End.String(),
			ID:       sessionID,
			Protocol: tracer.SSH.String(),
		})
	}
}

// GetSession returns a session by ID.
func (m *Manager) GetSession(id string) *domain.SessionContext {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessions[id]
}

// DeleteSession removes a session and its reusable address index.
func (m *Manager) DeleteSession(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	session, ok := m.sessions[id]
	if !ok {
		return false
	}
	if m.topology != nil {
		m.topology.RemoveSessionArtifacts(id)
	}
	delete(m.sessions, id)
	delete(m.worlds, id)
	if session != nil {
		key := extractIP(session.RemoteAddr) + ":" + session.Username
		if m.sessionsByAddr[key] == id {
			delete(m.sessionsByAddr, key)
		}
	}
	for key, sid := range m.sessionsByAddr {
		if sid == id {
			delete(m.sessionsByAddr, key)
		}
	}
	return true
}

// AllSessions returns all sessions.
func (m *Manager) AllSessions() []*domain.SessionContext {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sessions := make([]*domain.SessionContext, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	return sessions
}

// AllCommands returns all commands across all sessions.
func (m *Manager) AllCommands() []domain.CommandEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var commands []domain.CommandEntry
	for _, s := range m.sessions {
		commands = append(commands, s.CommandLog...)
	}
	return commands
}

// Topology returns the virtual topology.
func (m *Manager) TopologyRef() *domain.VirtualTopology {
	return m.topology
}

// RegistryRef returns the service registry.
func (m *Manager) RegistryRef() *domain.ServiceRegistry {
	return m.registry
}

// SafetyRef returns the safety policy.
func (m *Manager) SafetyRef() *domain.SafetyPolicy {
	return m.safety
}

// PlanTopology expands the graph for API/simulation paths using the same planner as SSH.
func (m *Manager) PlanTopology(session *domain.SessionContext, command string) {
	if m.orchestrator == nil || session == nil {
		return
	}
	world := session.World
	if world == nil {
		world = domain.NewWorldState()
		session.World = world
	}
	result := m.orchestrator.BeforeResponse(session, world, command, deception.ProfileFromSession(session))
	m.allowHostSegments(result.AddedHosts)
	if result.Decision.Action != "" && result.Decision.Action != deception.ActionFastResponse {
		session.AppendEvent(domain.EventEntry{
			Type:      "runtime_decision",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			SessionID: session.SessionID,
			Detail:    fmt.Sprintf("%s:%s", result.Decision.Action, result.Decision.Reason),
		})
	}
}

func (m *Manager) allowHostSegments(hosts []domain.VirtualHost) {
	if m.safety == nil {
		return
	}
	seen := map[string]bool{}
	for _, host := range hosts {
		if host.SegmentCIDR == "" || seen[host.SegmentCIDR] {
			continue
		}
		m.safety.AllowCIDR(host.SegmentCIDR)
		seen[host.SegmentCIDR] = true
	}
}

func (m *Manager) triggerPPFIfReady(session *domain.SessionContext, sessionID string) bool {
	ppfTriggered := session.PPFTriggered
	if !ppfTriggered && domain.ShouldTriggerPPF(session) {
		session.PPFTriggered = true
		ppfTriggered = true
		session.AppendEvent(domain.EventEntry{
			Type:      "ppf_triggered",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			SessionID: sessionID,
			Detail:    "PPF activated — intermediate shadow topology injected",
		})
		// Inject intermediate shadow topology as a stepping stone toward deeper targets
		m.injectPPFTopology(session)
	}
	return ppfTriggered
}

// injectPPFTopology creates intermediate shadow hosts as stepping stones
// when PPF triggers. This gives the attacker new topology to discover naturally
// through scanning, rather than changing terminal behavior.
func (m *Manager) injectPPFTopology(session *domain.SessionContext) {
	if m.topology == nil || session == nil {
		return
	}
	theme := pickExpansionTheme(session)
	cidr := deception.DefaultCIDRForTheme(theme)
	pivotIP := deception.DefaultPivotIP(m.topology, session)

	decision := deception.ExpansionDecision{
		Triggered: true,
		CIDR:      cidr,
		Theme:     theme,
		PivotIP:   pivotIP,
		Reason:    fmt.Sprintf("ppf_auto:%s:evidence=%d", theme, session.LoopMetrics.EvidenceHitCount),
	}
	added := deception.ExpandShadowTopology(session, m.topology, decision)
	m.allowHostSegments(added)

	// Inject clue files into world state so the attacker finds hints
	if session.World != nil && len(added) > 0 {
		injectClueFiles(session.World, theme, added)
	}
}


// handlePendingSSHAuth processes a password attempt during a simulated SSH auth flow.
// Password input is not echoed or logged. Denials are appended to the original ssh command's
// output so the terminal replay shows the full auth flow as one block.
func (m *Manager) handlePendingSSHAuth(session *domain.SessionContext, sessionID, command string, pending *domain.PendingSSH) string {
	pending.Attempts++
	session.SuppressShellPrompt = true

	// Check password for remote SSH
	if !pending.SelfSSH && pending.ExpectedPassword != "" {
		if command != pending.ExpectedPassword {
			// Wrong password
			if pending.Attempts >= pending.MaxAttempt {
				session.PendingSSHAuth = nil
				session.SuppressShellPrompt = false
				output := fmt.Sprintf("\n%s@%s: Permission denied (publickey,password).\n", pending.TargetUser, pending.TargetIP)
				session.AppendToLastCommand(output)
				return output
			}
			output := fmt.Sprintf("\nPermission denied, please try again.\n%s@%s's password: ", pending.TargetUser, pending.TargetIP)
			session.AppendToLastCommand(output)
			return output
		}

		// Correct password — authenticate
		session.PendingSSHAuth = nil
		session.SuppressShellPrompt = false


		host := m.topology.GetHostForSession(pending.TargetIP, session.SessionID)
		hostname := pending.TargetIP
		osName := "Ubuntu 22.04"
		sshPort := 22
		if host != nil {
			hostname = host.Hostname
			osName = host.OS
			for _, svc := range host.Services {
				if svc.Protocol == "ssh" {
					sshPort = svc.Port
					break
				}
			}
		}

		// Unlock gates
		if host != nil {
			switch {
			case host.Role == "jumpbox" || host.Hostname == "jump01":
				deception.UnlockGate(session, deception.GateJump01LowPrivShell, "ssh_jumpbox_auth")
			case host.Role == "dc" || host.Hostname == "dc01":
				deception.UnlockGate(session, deception.GateDC01Foothold, "ssh_dc01_auth")
			default:
				// Shadow hosts: unlock pivot gate to enable next-hop traversal
				deception.UnlockGate(session, deception.GateJump01LowPrivShell, "ssh_shadow_auth")
			}
		}

		session.EnterRemoteHost(pending.TargetIP, hostname, pending.TargetUser)
		session.World = domain.NewWorldStateForHost(hostname)

		// Activate edges originating from this host for multi-hop traversal
		for _, edge := range m.topology.GetEdgesFrom(pending.TargetIP) {
			m.topology.UpdateEdgeStatus(edge.From, edge.To, "active")
		}

		lastLoginTime := time.Now().UTC().Format("Mon Jan _2 15:04:05 2006")
		output := fmt.Sprintf(
			"\nAuthenticated to %s ([%s]:%d).\n"+
				"Linux %s %s\n"+
				"Last login: %s from %s\n",
			pending.TargetIP, pending.TargetIP, sshPort, hostname, osName, lastLoginTime, session.RemoteAddr,
		)
		session.AppendToLastCommand(output)
		return output
	}

	// No password configured or PPF-triggered — deny after max attempts
	if pending.Attempts >= pending.MaxAttempt {
		session.PendingSSHAuth = nil
		session.SuppressShellPrompt = false

		if pending.SelfSSH {
			promptChar := "$ "
			if pending.TargetUser == "root" {
				promptChar = "# "
			}
			lastLoginTime := time.Now().UTC().Format("Mon Jan _2 15:04:05 2006")
			output := fmt.Sprintf(
				"\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\n"+
					"Last login: %s from %s\n"+
					"%s@%s:~%sexit\n"+
					"Connection to %s closed.\n",
				lastLoginTime, pending.RemoteAddr, pending.TargetUser, session.Hostname, promptChar, pending.TargetIP,
			)
			session.AppendToLastCommand(output)
			return output
		}

		output := fmt.Sprintf("\n%s@%s: Permission denied (publickey,password).\n", pending.TargetUser, pending.TargetIP)
		session.AppendToLastCommand(output)
		return output
	}

	output := fmt.Sprintf("\nPermission denied, please try again.\n%s@%s's password: ", pending.TargetUser, pending.TargetIP)
	session.AppendToLastCommand(output)
	return output
}

func appendUnique(tokens []string, extra ...string) []string {
	seen := make(map[string]bool, len(tokens)+len(extra))
	for _, token := range tokens {
		seen[token] = true
	}
	for _, token := range extra {
		if token == "" || seen[token] {
			continue
		}
		tokens = append(tokens, token)
		seen[token] = true
	}
	return tokens
}

func responseCacheKey(command string, session *domain.SessionContext) string {
	lower := strings.ToLower(strings.TrimSpace(command))
	if lower == "" {
		return ""
	}
	cacheablePrefixes := []string{
		"nmap", "fscan", "dddd2", "nuclei", "gobuster", "ffuf", "sqlmap",
		"ping", "cat ", "grep ", "find ", "ls", "ip addr", "ip route", "hostname", "whoami",
	}
	cacheable := false
	for _, prefix := range cacheablePrefixes {
		if strings.HasPrefix(lower, prefix) {
			cacheable = true
			break
		}
	}
	if !cacheable || detectWriteTarget(command) != "" || strings.HasPrefix(lower, "ssh ") {
		return ""
	}
	normalized := regexp.MustCompile(`\s+`).ReplaceAllString(lower, " ")
	target := ""
	if session != nil {
		target = session.GetCurrentTarget()
		planID := ""
		if session.Planning != nil {
			planID = session.Planning.ActivePlanID
		}
		return fmt.Sprintf("%s|%s|%s|%s|%s", session.User, session.CWD, target, planID, normalized)
	}
	return normalized
}

// pickExpansionTheme chooses a theme based on the session's deception profile.
func pickExpansionTheme(session *domain.SessionContext) string {
	switch session.DeceptionProfile {
	case "secret_hunter":
		return "finance"
	case "cloud_native":
		return "cloud"
	case "domain_mapper":
		return "domain"
	case "flag_hunter":
		return "flag"
	default:
		return "network"
	}
}

// injectClueFiles adds themed files to the world to guide the agent toward the new topology.
func injectClueFiles(world *domain.WorldState, theme string, hosts []domain.VirtualHost) {
	if len(hosts) == 0 {
		return
	}
	firstHost := hosts[0]

	switch theme {
	case "finance":
		world.AddFile("/opt/webapp/scripts/finance_migration.sh", domain.NewFileEntry(fmt.Sprintf(`#!/bin/bash
# Finance DB migration to new segment
# Target: %s (finance-db-01)
ssh -i /home/ansible/.ssh/id_rsa root@%s "mysqldump --single-transaction fin_readonly_" + domain.DeploySeed | mysql -h localhost fin_archive
`, firstHost.IP, firstHost.IP)))
		world.AddFile("/tmp/finance_netmap.txt", domain.NewFileEntry(fmt.Sprintf(`# Network segment: %s
# Gateway: %s
# Hosts:
#   %s - finance-web-01 (HTTPS)
#   %s - finance-db-01 (MySQL)
#   %s - backup-nas-01 (SMB)
`, firstHost.SegmentCIDR, hosts[0].SegmentCIDR[:len(hosts[0].SegmentCIDR)-4]+"1",
			hosts[0].IP, hosts[1].IP, hosts[2].IP)))
	case "cloud":
		world.AddFile("/home/ansible/.kube/config_shadow", domain.NewFileEntry(fmt.Sprintf(`apiVersion: v1
clusters:
- cluster:
    server: https://%s:6443
    certificate-authority-data: LS0tLS1CRUdJTi...
  name: prod-cluster
`, hosts[1].IP)))
	case "domain":
		world.AddFile("/tmp/ldap_enum_notes.txt", domain.NewFileEntry(fmt.Sprintf(`# Found child DC at %s during enumeration
# SMB shares accessible at %s
# Next: try kerberoast against child domain
`, hosts[0].IP, hosts[1].IP)))
	default:
		world.AddFile("/tmp/network_scan_notes.txt", domain.NewFileEntry(fmt.Sprintf(`# New segment discovered: %s
# Pivot via jump01 (192.168.56.10)
# Hosts: %s
`, firstHost.SegmentCIDR, firstHost.IP)))
	}
}

// reWriteOps matches commands that modify the filesystem.
var reWriteOps = regexp.MustCompile(`(?:>\s*\S+|>>\s*\S+|\btouch\b|\bmkdir\b|\brm\b|\bcp\b|\bmv\b|\bchmod\b|\bchown\b|\bsed\s+-i\b|\btee\b|\binstall\b|\bunlink\b|\brmdir\b)`)

// detectWriteTarget returns the parent directory of the path being written to,
// or "" if the command is not a write operation.
func detectWriteTarget(command string) string {
	cmd := strings.TrimSpace(command)
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return ""
	}
	cmdBase := parts[0]

	// echo xxx > /path/to/file or echo xxx >> /path/to/file
	if cmdBase == "echo" || cmdBase == "printf" {
		if match := regexp.MustCompile(`>{1,2}\s*(\S+)`).FindStringSubmatch(cmd); len(match) > 1 {
			return path.Dir(match[1])
		}
		return ""
	}

	// touch /path/to/file
	if cmdBase == "touch" && len(parts) > 1 {
		return path.Dir(parts[len(parts)-1])
	}

	// mkdir /path/to/dir
	if cmdBase == "mkdir" {
		for _, a := range parts[1:] {
			if !strings.HasPrefix(a, "-") {
				return path.Dir(a)
			}
		}
		return ""
	}

	// rm /path/to/file, cp src dst, mv src dst
	if cmdBase == "rm" || cmdBase == "cp" || cmdBase == "mv" {
		var targets []string
		for _, a := range parts[1:] {
			if !strings.HasPrefix(a, "-") {
				targets = append(targets, a)
			}
		}
		if len(targets) > 0 {
			return path.Dir(targets[len(targets)-1])
		}
	}

	// sed -i / tee / install / unlink / rmdir
	if reWriteOps.MatchString(cmd) {
		if match := regexp.MustCompile(`(?:>\s*|>>\s*|\b(?:touch|mkdir|rm|tee|unlink|rmdir)\s+)(\S+)`).FindStringSubmatch(cmd); len(match) > 1 {
			return path.Dir(match[1])
		}
	}

	return ""
}

// getFrustrationAnalyzer returns (or creates) the per-session frustration analyzer.
func (m *Manager) getFrustrationAnalyzer(sessionID string) *deception.FrustrationAnalyzer {
	m.mu.Lock()
	defer m.mu.Unlock()
	fa, ok := m.frustration[sessionID]
	if !ok {
		fa = deception.NewFrustrationAnalyzer()
		m.frustration[sessionID] = fa
	}
	return fa
}

// injectFrustrationClue plants breadcrumb files when the attacker is stuck
// at L2 (info insufficient) with repeated failures. The clue guides them
// toward the next exploration direction without giving away the deception.
func injectFrustrationClue(world *domain.WorldState, session *domain.SessionContext, level deception.FrustrationLevel) {
	if world == nil || session == nil {
		return
	}
	// Plant a deploy notes file with a hint toward the next pivot
	notesPath := "/opt/webapp/DEPLOY_NOTES.md"
	if world.GetFileEntry(notesPath) != nil {
		return // already planted
	}
	world.AddFile(notesPath, domain.NewFileEntry(`# Deploy Notes — Internal
# Last updated: 2024-01-14

## Staging → Production
- Jump host: 192.168.56.10 (jump01)
- Ansible inventory: /etc/ansible/hosts
- Finance DB: 192.168.56.60 (fin-db01)
- GitLab CI: 192.168.56.80

## Known Issues
- Redis on .30 requires AUTH after the security audit
- MySQL on .60 is read-only from staging; use jump01 for admin tasks
- DC01 (.50) only reachable via jump01 pivot

## TODO
- Rotate GitLab deploy token (expired Jan 2024)
- Update Jenkins credentials in vault
`))
	world.AddFile("/opt/webapp/DEPLOY_NOTES.md", domain.NewFileEntry(""))
}

// injectContradictoryClue plants mixed signals when L4 cognitive bias is
// detected (attacker may be an AI agent suspecting the honeypot). The
// contradictory information tests whether the agent can reconcile
// inconsistencies, buying time and revealing its reasoning.
func injectContradictoryClue(world *domain.WorldState, session *domain.SessionContext) {
	if world == nil || session == nil {
		return
	}
	// Plant a log entry that slightly contradicts other evidence
	logPath := "/var/log/syslog"
	entry := world.GetFileEntry(logPath)
	contradictory := "Jan 15 10:23:45 staging-web-01 CRON[2891]: (root) CMD (/opt/webapp/scripts/health_check.sh)\nJan 15 10:24:01 staging-web-01 sshd[2892]: Connection from 192.168.56.10 port 49152 ssh2\nJan 15 10:24:01 staging-web-01 sshd[2892]: Accepted publickey for ansible from 192.168.56.10\n"
	if entry == nil {
		world.AddFile(logPath, domain.NewFileEntry(contradictory))
	} else if !strings.Contains(entry.Content, "Accepted publickey for ansible") {
		entry.Content = contradictory + entry.Content
	}
}
