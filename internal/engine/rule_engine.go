package engine

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/alterhive/alterhive/internal/deception"
	"github.com/alterhive/alterhive/internal/domain"
	"github.com/alterhive/alterhive/internal/llm"
	"github.com/alterhive/alterhive/internal/responders"
)

var (
	reDangerous = regexp.MustCompile(`(?i)^\s*(shutdown|reboot|halt|poweroff|mkfs|dd\s+if=|rm\s+-rf\s+/|chmod\s+-R\s+777\s+/|wget\s.*\|\s*sh|curl\s.*\|\s*sh)`)
	reIP        = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)
	reCIDR      = regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+`)
)

// RuleEngine routes commands to appropriate responders.
type RuleEngine struct {
	Topology *domain.VirtualTopology
	Safety   *domain.SafetyPolicy
	Registry *domain.ServiceRegistry
	LLM      completionClient
}

type completionClient interface {
	IsActive() bool
	Complete(context.Context, llm.CompletionRequest) (*llm.CompletionResponse, error)
}

// NewRuleEngine creates a new rule engine.
func NewRuleEngine(topology *domain.VirtualTopology, safety *domain.SafetyPolicy, registry *domain.ServiceRegistry) *RuleEngine {
	return &RuleEngine{
		Topology: topology,
		Safety:   safety,
		Registry: registry,
	}
}

// SetLLM attaches the optional LLM fallback generator.
func (e *RuleEngine) SetLLM(manager *llm.Manager) {
	e.LLM = manager
}

// SetLLMClient is used by tests and adapters that implement the completion surface.
func (e *RuleEngine) SetLLMClient(client completionClient) {
	e.LLM = client
}

// HandleCommand processes a command and returns (output, evidence_hits, llm_generated).
func (e *RuleEngine) HandleCommand(cmd string, session *domain.SessionContext, world *domain.WorldState, ppfTriggered bool) (string, []string, bool) {
	cmdStripped := strings.TrimSpace(cmd)
	if cmdStripped == "" {
		return "", nil, false
	}

	// Block dangerous commands
	if reDangerous.MatchString(cmdStripped) {
		return "Operation not permitted\n", nil, false
	}

	// Safety: validate targets
	allSafe, blocked := e.Safety.ValidateCommandTargets(cmdStripped, session)
	if !allSafe {
		return blockedCommandOutput(cmdStripped, blocked[0]), []string{"blocked_outbound"}, false
	}

	cmdBase := strings.Fields(cmdStripped)[0]
	cmdLower := strings.ToLower(cmdStripped)

	// ── Complex commands: LLM-driven first, rule engine as fallback ──
	// Architecture §2.2: nmap/curl/ssh/mysql/redis-cli/docker/kubectl etc. are
	// ClassComplex and should be authored by the LLM Orchestrator with topology
	// context. The rule engine remains the deterministic fallback so the system
	// still works when LLM is unavailable or returns nothing usable.
	if isComplexCommand(cmdBase) {
		if out, hits := e.handleComplexViaLLM(cmdStripped, cmdBase, session, world, ppfTriggered); out != "" {
			return e.renderApproved(cmdStripped, out, session), hits, true
		}
	}

	// Python REPL mode — route all input to Python handler
	if session.ShellMode == "python" {
		output := responders.HandlePythonREPL(cmdStripped, session, world)
		return e.renderApproved(cmdStripped, output, session), nil, false
	}

	// MySQL interactive mode — route all input to MySQL handler
	if session.ShellMode == "mysql" {
		output := responders.HandleMySQLQuery(cmdStripped, session.SessionID)
		output = responders.LocalizeMySQLOutput(output, session)
		// exit/quit returns "Bye\n" — switch back to bash
		if strings.HasPrefix(strings.TrimSpace(output), "Bye") {
			session.ShellMode = "bash"
			return e.renderApproved(cmdStripped, output, session), nil, false
		}
		return e.renderApproved(cmdStripped, output, session), nil, false
	}

	// Redis interactive mode — route all input to Redis handler
	if session.ShellMode == "redis" {
		if cmdStripped == "exit" || cmdStripped == "quit" {
			session.ShellMode = "bash"
			return e.renderApproved(cmdStripped, "", session), nil, false
		}
		out, _ := handleRedisCommand(cmdStripped, session, e.Topology, ppfTriggered)
		return e.renderApproved(cmdStripped, out, session), nil, false
	}

	switch cmdBase {
	case "nmap", "nc", "ncat", "fscan", "dddd2", "nuclei", "gobuster", "ffuf", "sqlmap":
		out, hits := responders.HandleNetworkCommand(cmdStripped, session, e.Topology)
		return e.renderApproved(cmdStripped, out, session), hits, false
	case "sliver-client", "sliver", "msfconsole", "msf":
		out, hits := responders.HandleC2Command(cmdStripped, session)
		return e.renderApproved(cmdStripped, out, session), hits, false
	case "curl", "wget":
		out, hits := responders.HandleHTTPCommand(cmdStripped, session, e.Topology)
		return e.renderApproved(cmdStripped, out, session), hits, false
	case "ssh":
		out, hits := responders.HandleSSHCommand(cmdStripped, session, e.Topology, ppfTriggered)
		return e.renderApproved(cmdStripped, out, session), hits, false
	case "scp":
		out, hits := handleSCPCommand(cmdStripped, session, e.Topology)
		return e.renderApproved(cmdStripped, out, session), hits, false
	case "mysql", "mysqldump", "mysqladmin":
		out, hits := responders.HandleMySQLCommand(cmdStripped, ppfTriggered, session.DeceptionProfile, session)
		out = responders.LocalizeMySQLOutput(out, session)
		return e.renderApproved(cmdStripped, out, session), hits, false
	case "psql", "pg_dump":
		out, hits := responders.HandlePostgresCommand(cmdStripped, session, ppfTriggered)
		return e.renderApproved(cmdStripped, out, session), hits, false
	case "ldapsearch":
		out, hits := responders.HandleLDAPCommand(cmdStripped, session, e.Topology)
		return e.renderApproved(cmdStripped, out, session), hits, false
	case "smbclient", "rpcclient":
		out, hits := responders.HandleSMBCommand(cmdStripped, session, e.Topology)
		return e.renderApproved(cmdStripped, out, session), hits, false
	case "kinit", "klist":
		out, hits := responders.HandleKerberosCommand(cmdStripped)
		return e.renderApproved(cmdStripped, out, session), hits, false
	case "dig", "nslookup":
		out, hits := responders.HandleDNSCommand(cmdStripped, session, e.Topology)
		return e.renderApproved(cmdStripped, out, session), hits, false
	case "redis-cli":
		out, hits := handleRedisCommand(cmdStripped, session, e.Topology, ppfTriggered)
		return e.renderApproved(cmdStripped, out, session), hits, false
	case "docker":
		return e.renderApproved(cmdStripped, handleDockerCommand(cmdLower, session.SessionID), session), []string{"service_enum"}, false
	case "kubectl":
		return e.renderApproved(cmdStripped, handleKubectlCommand(cmdLower, session.SessionID), session), []string{"service_enum"}, false
	}

	// Shell commands (local filesystem only)
	output, handled := responders.HandleShellCommand(cmdStripped, session, world, e.Registry)
	if handled {
		return e.renderApproved(cmdStripped, output, session), nil, false
	}

	// Check dynamic rule cache before calling LLM
	cacheKey := buildCacheKey(cmdStripped, session.CWD)
	if cached := world.Cache().Lookup(cacheKey); cached != nil {
		return e.renderApproved(cmdStripped, cached.Output, session), nil, false
	}

	if output := e.llmFallback(cmdStripped, session, world); output != "" {
		// Cache the LLM response and inject into WorldState for consistency
		storeAndInject(cmdStripped, output, world, session.CWD)
		return e.renderApproved(cmdStripped, output, session), nil, true
	}

	if fallback := shellLikeFallback(cmdStripped, session); fallback != "" {
		return e.renderApproved(cmdStripped, fallback, session), nil, false
	}

	return "bash: " + cmdBase + ": command not found\n", nil, false
}

// isComplexCommand reports whether a command base is ClassComplex per the
// architecture doc §2.1 — these are routed through the LLM Orchestrator first.
// ssh is intentionally included but the password-prompt state machine is still
// driven by the rule-engine fallback so the interactive flow stays consistent.
func isComplexCommand(cmdBase string) bool {
	switch cmdBase {
	case "nmap", "nc", "ncat", "fscan", "dddd2", "nuclei", "gobuster", "ffuf",
		"sqlmap", "nikto", "hydra", "john", "hashcat", "masscan",
		"curl", "wget",
		"ssh", "scp",
		"mysql", "mysqldump", "mysqladmin", "psql", "pg_dump",
		"redis-cli",
		"ldapsearch", "smbclient", "rpcclient", "kinit", "klist",
		"dig", "nslookup",
		"docker", "kubectl",
		"sliver-client", "sliver", "msfconsole", "msf",
		"python3", "python":
		return true
	}
	return false
}

// handleComplexViaLLM returns the terminal output for a complex command.
// On first invocation it returns the deterministic rule-engine output instantly
// and fires an async LLM call whose result is cached for subsequent invocations.
// Returns ("", nil) only when the LLM is unavailable, in which case
// HandleCommand falls through to the rule-engine switch.
func (e *RuleEngine) handleComplexViaLLM(cmd, cmdBase string, session *domain.SessionContext, world *domain.WorldState, ppfTriggered bool) (string, []string) {
	if e.LLM == nil || !e.LLM.IsActive() {
		return "", nil
	}

	ruleOutput, evidenceHits := e.ruleEngineDispatch(cmd, cmdBase, session, world, ppfTriggered)
	if !allowLLMContextExport() {
		return ruleOutput, evidenceHits
	}

	// Check cache first — if the LLM already authored a response for this
	// command, return it immediately (fast path).
	cacheKey := buildCacheKey(cmd, session.CWD)
	if cached := world.Cache().Lookup(cacheKey); cached != nil {
		return cached.Output, evidenceHits
	}

	// Fire async LLM call to enrich future responses. The deterministic
	// rule-engine output is returned instantly so the terminal stays snappy.
	go e.handleComplexAsync(cmd, cmdBase, session, world, ruleOutput)

	return ruleOutput, evidenceHits
}

// handleComplexAsync calls the LLM asynchronously and caches the result
// so subsequent invocations of the same command use the LLM-authored output.
func (e *RuleEngine) handleComplexAsync(cmd, cmdBase string, session *domain.SessionContext, world *domain.WorldState, ruleOutput string) {
	structuredFacts := formatStructuredFacts(cmd, cmdBase, ruleOutput, session, e.Topology)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	profile := deception.ProfileFromSession(session)
	decision := deception.SelectStrategy(profile, session)
	strategyPrompt := deception.BuildStrategyPrompt(profile, decision, session)
	topologyContext := formatTopologyForPrompt(e.Topology)
	protectedTargets := ""
	if session != nil && session.Planning != nil {
		protectedTargets = strings.Join(session.Planning.ProtectedTargetList(), ", ")
	}

	seed := time.Now().UnixNano() % 1000
	scanVariant := seed % 5

	systemContent := fmt.Sprintf(`You are a Linux terminal on host %s (Ubuntu 22.04). User: %s. CWD: %s.
An attacker (AI pentest agent or human) just ran a network/service command. You must produce the exact raw terminal output that command would print.

RANDOMIZATION SEED: %d  VARIANT: %d

COMMAND FACTS (authoritative ground truth — USE these facts, do NOT COPY them verbatim):
%s

CRITICAL: Author fresh terminal output. Do NOT echo the fact strings. Vary with the seed:
- nmap version: pick from [7.92, 7.93, 7.94, 7.95] based on variant %% 4
- latency: 0.0012s-0.0089s range, jittered by seed
- scan time: 1.8s-4.5s range, jittered by seed
- timestamp format: vary between ISO 8601 and Unix-style
- spacing/alignment: vary column widths slightly
- banner strings: use realistic variations (e.g. "OpenSSH 8.9p1" vs "OpenSSH 8.4p1")

Return ONLY raw terminal output. No markdown, fences, prompts, or analysis.
Every IP/port/service from the facts MUST appear. Do not invent new facts.
Keep output under 40 lines.
Topology: %s
Protected targets already known to the attacker: %s
%s
%s`, session.Hostname, session.User, session.CWD, seed, scanVariant, structuredFacts, topologyContext, protectedTargets, memorySummary(session), strategyPrompt)

	req := llm.CompletionRequest{
		MaxTokens:   800,
		Temperature: 0.9,
		Messages: []llm.Message{
			{Role: "system", Content: systemContent},
			{Role: "user", Content: fmt.Sprintf("Recent commands:\n%s\nFiles in cwd: %s\n%s\nProduce the raw terminal output for this command:\n%s", commandHistoryTail(session, 5), strings.Join(world.ListFiles(session.CWD), ", "), contextAwareSlice(cmd, session), cmd)},
		},
	}

	resp, err := e.LLM.Complete(ctx, req)
	if err != nil {
		recordLLMFallbackEvent(session, "complex_complete_error:"+err.Error(), cmd)
		return
	}
	output := sanitizeTerminalOutput(resp.Content)
	if output == "" {
		recordLLMFallbackEvent(session, "complex_empty_after_sanitize", cmd)
		return
	}
	guarded := deception.GuardTerminalOutput(output, session)
	if guarded.Blocked {
		recordLLMFallbackEvent(session, "complex_terminal_guard:"+guarded.Reason, cmd)
		return
	}
	factGuarded := deception.GuardResponseFacts(guarded.Output, session, e.Topology)
	if factGuarded.Blocked {
		recordLLMFallbackEvent(session, "complex_fact_guard:"+factGuarded.Reason, cmd)
		return
	}
	// Cache the LLM-rendered output for consistency on repeat commands.
	storeAndInject(cmd, factGuarded.Output, world, session.CWD)
	// Bump world version to invalidate Manager's planning response cache,
	// so subsequent invocations reach HandleCommand → world cache → LLM output.
	if session.Planning != nil {
		session.Planning.BumpWorldVersion("llm_async_cached:" + cmdBase)
	}
	recordLLMFallbackEvent(session, "complex_llm_authored", cmd)
}

// formatStructuredFacts converts raw rule-engine output into a compact
// structured fact summary that the LLM can author diverse terminal output from.
// Without this step, the LLM receives a pre-rendered terminal text and can only
// echo it verbatim instead of producing varied, realistic output.
func formatStructuredFacts(cmd, cmdBase, ruleOutput string, session *domain.SessionContext, topology *domain.VirtualTopology) string {
	lower := strings.ToLower(cmd)

	switch {
	case strings.HasPrefix(lower, "nmap"), strings.HasPrefix(lower, "fscan"), strings.HasPrefix(lower, "dddd2"), strings.HasPrefix(lower, "nuclei"), strings.HasPrefix(lower, "gobuster"), strings.HasPrefix(lower, "ffuf"):
		return formatNetworkScanFacts(cmd, ruleOutput, topology, session)
	case strings.HasPrefix(lower, "curl"), strings.HasPrefix(lower, "wget"):
		return formatHTTPFacts(cmd, ruleOutput, topology, session)
	case strings.HasPrefix(lower, "ssh"), strings.HasPrefix(lower, "scp"):
		return formatSSHFacts(cmd, ruleOutput, topology, session)
	case strings.HasPrefix(lower, "mysql"), strings.HasPrefix(lower, "mysqldump"), strings.HasPrefix(lower, "mysqladmin"),
		strings.HasPrefix(lower, "psql"), strings.HasPrefix(lower, "pg_dump"):
		return formatDBFacts(cmd, ruleOutput)
	case strings.HasPrefix(lower, "redis-cli"):
		return formatRedisFacts(cmd, ruleOutput)
	case strings.HasPrefix(lower, "docker"):
		return formatDockerFacts(cmd, ruleOutput)
	case strings.HasPrefix(lower, "kubectl"):
		return formatKubectlFacts(cmd, ruleOutput)
	case strings.HasPrefix(lower, "nc "), strings.HasPrefix(lower, "ncat "):
		return formatNCFacts(cmd, ruleOutput, topology)
	case strings.HasPrefix(lower, "ping "):
		return formatPingFacts(cmd, ruleOutput)
	case strings.HasPrefix(lower, "python3"), strings.HasPrefix(lower, "python"):
		return formatPythonFacts(ruleOutput)
	default:
		// For less-common complex commands, pass the raw output but prefix it
		return "RAW_REFERENCE_OUTPUT:\n" + truncateOutput(ruleOutput, 2000)
	}
}

func formatNetworkScanFacts(cmd, ruleOutput string, topology *domain.VirtualTopology, session *domain.SessionContext) string {
	var facts []string

	// Extract target from cmd
	if ipMatch := reIP.FindString(cmd); ipMatch != "" {
		facts = append(facts, fmt.Sprintf("scan_target: %s (single host)", ipMatch))
	} else if cidrMatch := reCIDR.FindString(cmd); cidrMatch != "" {
		facts = append(facts, fmt.Sprintf("scan_target: %s (subnet range)", cidrMatch))
	}

	// Extract hosts and their ports from rule output
	hostBlocks := regexp.MustCompile(`(?m)^Nmap scan report for (\S+)`).FindAllStringSubmatch(ruleOutput, -1)
	portBlocks := regexp.MustCompile(`(?m)^(\d+/tcp)\s+(\S+)\s+(\S+)`).FindAllStringSubmatch(ruleOutput, -1)

	if len(hostBlocks) == 0 {
		// Try fscan format
		hostBlocks = regexp.MustCompile(`(?m)\[\*\] alive (\S+)`).FindAllStringSubmatch(ruleOutput, -1)
	}

	for _, match := range hostBlocks {
		ip := match[1]
		host := topology.GetHost(ip)
		if host != nil {
			facts = append(facts, fmt.Sprintf("host: %s (%s, role=%s, os=%s)", ip, host.Hostname, host.Role, host.OS))
			for _, svc := range host.Services {
				name := svc.NmapName
				if name == "" {
					name = svc.Protocol
				}
				facts = append(facts, fmt.Sprintf("  port: %d/%s %s %s (failure=%s)", svc.Port, svc.Protocol, "open", name, svc.FailureMode))
				if persona := servicePersonaValue(session, host.IP, svc.Protocol); persona != "" {
					facts = append(facts, fmt.Sprintf("  service_persona: %s/%s %s", host.IP, svc.Protocol, compactFactValue(persona, 180)))
				}
				if policy := bestExploitPolicy(session, host.IP); policy != "" {
					facts = append(facts, fmt.Sprintf("  exploit_policy: %s", compactFactValue(policy, 180)))
				}
			}
		}
	}

	// If no structured host data found, extract port lines from raw output
	if len(facts) == 0 {
		for _, match := range portBlocks {
			facts = append(facts, fmt.Sprintf("port: %s %s %s", match[1], match[2], match[3]))
		}
		if len(facts) == 0 {
			facts = append(facts, "scan_result: no hosts found or all filtered")
		}
	}

	return "SCAN FACTS:\n" + strings.Join(facts, "\n")
}

func formatHTTPFacts(cmd, ruleOutput string, topology *domain.VirtualTopology, session *domain.SessionContext) string {
	var facts []string
	// Extract target URL/IP
	if ipMatch := reIP.FindString(cmd); ipMatch != "" {
		host := topology.GetHost(ipMatch)
		if host != nil {
			facts = append(facts, fmt.Sprintf("target: %s (%s, role=%s)", ipMatch, host.Hostname, host.Role))
			for _, svc := range host.Services {
				if svc.Protocol == "http" || svc.Protocol == "https" || svc.Protocol == "http-proxy" {
					facts = append(facts, fmt.Sprintf("http_service: port=%d protocol=%s banner=%s failure=%s", svc.Port, svc.Protocol, svc.Banner, svc.FailureMode))
					if persona := servicePersonaValue(session, ipMatch, svc.Protocol); persona != "" {
						facts = append(facts, fmt.Sprintf("service_persona: %s", compactFactValue(persona, 180)))
					}
				}
			}
			if policy := bestExploitPolicy(session, ipMatch); policy != "" {
				facts = append(facts, fmt.Sprintf("exploit_policy: %s", compactFactValue(policy, 180)))
			}
		} else {
			facts = append(facts, fmt.Sprintf("target: %s (virtual, no host in topology)", ipMatch))
		}
	}
	// Extract key output characteristics
	if strings.Contains(ruleOutput, "200 OK") || strings.Contains(ruleOutput, "HTTP/1.1 200") {
		facts = append(facts, "http_status: 200 OK — return realistic web page content")
	} else if strings.Contains(ruleOutput, "302") || strings.Contains(ruleOutput, "301") {
		facts = append(facts, "http_status: redirect — return realistic redirect response")
	} else if strings.Contains(ruleOutput, "401") || strings.Contains(ruleOutput, "403") {
		facts = append(facts, "http_status: auth denied — return realistic forbidden page")
	}
	if len(facts) == 0 {
		return "HTTP FACTS:\ntarget: unknown (see raw reference)\nRAW_REFERENCE:\n" + truncateOutput(ruleOutput, 1000)
	}
	return "HTTP FACTS:\n" + strings.Join(facts, "\n")
}

func memoryInvariantValue(session *domain.SessionContext, key string) string {
	if session == nil || session.Memory == nil || key == "" {
		return ""
	}
	fact, ok := session.Memory.GetInvariant(key)
	if !ok {
		return ""
	}
	return fact.Value
}

func servicePersonaValue(session *domain.SessionContext, hostIP, service string) string {
	if session == nil || hostIP == "" || service == "" {
		return ""
	}
	if session.Planning != nil {
		if fact, ok := session.Planning.GetServicePersona(hostIP, service); ok {
			return fact.Summary
		}
	}
	return memoryInvariantValue(session, "service."+hostIP+"."+service)
}

func bestExploitPolicy(session *domain.SessionContext, hostIP string) string {
	if session == nil || hostIP == "" {
		return ""
	}
	stages := []string{"partial", "exploit", "check", "probe"}
	if session.Planning != nil {
		if fact, ok := session.Planning.GetExploitPolicy(hostIP, stages...); ok {
			return fact.Policy
		}
	}
	if session.Memory == nil {
		return ""
	}
	for _, stage := range stages {
		if policy := memoryInvariantValue(session, "exploit."+hostIP+"."+stage); policy != "" {
			return policy
		}
	}
	for _, stage := range stages {
		if policy := memoryInvariantValue(session, "exploit.current."+stage); policy != "" {
			return policy
		}
	}
	return ""
}

func compactFactValue(value string, maxLen int) string {
	value = strings.Join(strings.Fields(value), " ")
	if maxLen > 0 && len(value) > maxLen {
		return value[:maxLen-3] + "..."
	}
	return value
}

func formatSSHFacts(cmd, ruleOutput string, topology *domain.VirtualTopology, session *domain.SessionContext) string {
	var facts []string
	if ipMatch := reIP.FindString(cmd); ipMatch != "" {
		host := topology.GetHost(ipMatch)
		if host != nil {
			facts = append(facts, fmt.Sprintf("target: %s (%s, role=%s, os=%s)", ipMatch, host.Hostname, host.Role, host.OS))
			hasSSH := false
			for _, svc := range host.Services {
				if svc.Protocol == "ssh" {
					hasSSH = true
					facts = append(facts, fmt.Sprintf("ssh_port: %d", svc.Port))
					break
				}
			}
			if !hasSSH {
				facts = append(facts, "ssh_service: none — connection refused")
			}
			if host.Password != "" {
				facts = append(facts, fmt.Sprintf("auth: password configured (accepts known password, max %d attempts)", 3))
			} else {
				facts = append(facts, "auth: no known password — always denied")
			}
		} else {
			facts = append(facts, fmt.Sprintf("target: %s — no route or connection refused", ipMatch))
		}
	}
	// Detect outcome from raw output
	if strings.Contains(ruleOutput, "password:") {
		facts = append(facts, "outcome: password prompt shown — attacker must supply password")
	} else if strings.Contains(ruleOutput, "Permission denied") {
		facts = append(facts, "outcome: auth failed — permission denied")
	} else if strings.Contains(ruleOutput, "Connection refused") {
		facts = append(facts, "outcome: connection refused")
	} else if strings.Contains(ruleOutput, "No route to host") {
		facts = append(facts, "outcome: no route to host")
	}
	return "SSH FACTS:\n" + strings.Join(facts, "\n")
}

func formatDBFacts(cmd, ruleOutput string) string {
	var facts []string
	lower := strings.ToLower(cmd)
	if strings.Contains(lower, "mysqldump") {
		facts = append(facts, "operation: mysqldump — return realistic MySQL dump with table structure and data")
	} else if strings.Contains(lower, "mysql") {
		facts = append(facts, "operation: mysql query — return tabular query results or MySQL prompt")
	} else if strings.Contains(lower, "psql") {
		facts = append(facts, "operation: postgres query — return psql-style output")
	}
	if strings.Contains(ruleOutput, "Access denied") {
		facts = append(facts, "outcome: access denied — return MySQL access denied error")
	} else if strings.Contains(ruleOutput, "NOAUTH") {
		facts = append(facts, "outcome: authentication required")
	} else {
		facts = append(facts, "outcome: connected — return query results or interactive prompt")
	}
	return "DATABASE FACTS:\n" + strings.Join(facts, "\n")
}

func formatRedisFacts(cmd, ruleOutput string) string {
	var facts []string
	lower := strings.ToLower(cmd)
	if strings.Contains(lower, "info") {
		facts = append(facts, "operation: INFO — return Redis server info block")
	} else if strings.Contains(lower, "keys") {
		facts = append(facts, "operation: KEYS — return key list")
	} else if strings.Contains(lower, "get") {
		facts = append(facts, "operation: GET — return key value")
	} else if strings.Contains(lower, "config get") {
		facts = append(facts, "operation: CONFIG GET — return config values")
	}
	if strings.Contains(ruleOutput, "NOAUTH") {
		facts = append(facts, "outcome: authentication required — return NOAUTH error")
	} else if strings.Contains(ruleOutput, "PONG") {
		facts = append(facts, "outcome: connected — return PONG")
	} else if strings.Contains(ruleOutput, "READONLY") {
		facts = append(facts, "outcome: read-only replica — return READONLY error for writes")
	} else {
		facts = append(facts, "outcome: connected — return appropriate Redis response")
	}
	return "REDIS FACTS:\n" + strings.Join(facts, "\n")
}

func formatDockerFacts(cmd, ruleOutput string) string {
	var facts []string
	lower := strings.ToLower(cmd)
	if strings.Contains(lower, " ps") {
		facts = append(facts, "operation: docker ps — list running containers (webapp, cache-sidecar)")
	} else if strings.Contains(lower, " images") {
		facts = append(facts, "operation: docker images — list images (registry.local/web:2.4, redis:6.2-alpine)")
	} else {
		facts = append(facts, "operation: docker command — permission denied (no docker socket access)")
	}
	return "DOCKER FACTS:\n" + strings.Join(facts, "\n")
}

func formatKubectlFacts(cmd, ruleOutput string) string {
	var facts []string
	if strings.Contains(ruleOutput, "Unauthorized") {
		facts = append(facts, "outcome: unauthorized — return kubectl auth error")
	} else if strings.Contains(ruleOutput, "Forbidden") {
		facts = append(facts, "outcome: forbidden — return kubectl RBAC error")
	} else {
		facts = append(facts, "outcome: connected — return kubectl resource listing")
	}
	return "KUBECTL FACTS:\n" + strings.Join(facts, "\n")
}

func formatNCFacts(cmd, ruleOutput string, topology *domain.VirtualTopology) string {
	var facts []string
	if ipMatch := reIP.FindString(cmd); ipMatch != "" {
		facts = append(facts, fmt.Sprintf("target: %s", ipMatch))
	}
	if strings.Contains(ruleOutput, "succeeded") {
		facts = append(facts, "outcome: connection succeeded")
	} else if strings.Contains(ruleOutput, "Connection refused") {
		facts = append(facts, "outcome: connection refused")
	}
	return "NC FACTS:\n" + strings.Join(facts, "\n")
}

func formatPingFacts(cmd, ruleOutput string) string {
	var facts []string
	if ipMatch := reIP.FindString(cmd); ipMatch != "" {
		facts = append(facts, fmt.Sprintf("target: %s — host is up, return realistic ping statistics", ipMatch))
	}
	return "PING FACTS:\n" + strings.Join(facts, "\n")
}

func formatPythonFacts(ruleOutput string) string {
	return "PYTHON FACTS:\noperation: python REPL — return Python interactive interpreter output\n" + truncateOutput(ruleOutput, 500)
}

func truncateOutput(output string, maxLen int) string {
	if len(output) <= maxLen {
		return output
	}
	return output[:maxLen] + "\n...[truncated]"
}

// ruleEngineDispatch is the deterministic fallback for complex commands. It is
// the same switch logic HandleCommand used inline before the LLM-first routing
// was added, factored out so handleComplexViaLLM can call it for ground truth.
func (e *RuleEngine) ruleEngineDispatch(cmd, cmdBase string, session *domain.SessionContext, world *domain.WorldState, ppfTriggered bool) (string, []string) {
	cmdLower := strings.ToLower(cmd)
	switch cmdBase {
	case "nmap", "nc", "ncat", "fscan", "dddd2", "nuclei", "gobuster", "ffuf", "sqlmap":
		out, hits := responders.HandleNetworkCommand(cmd, session, e.Topology)
		return out, hits
	case "sliver-client", "sliver", "msfconsole", "msf":
		out, hits := responders.HandleC2Command(cmd, session)
		return out, hits
	case "curl", "wget":
		out, hits := responders.HandleHTTPCommand(cmd, session, e.Topology)
		return out, hits
	case "ssh":
		out, hits := responders.HandleSSHCommand(cmd, session, e.Topology, ppfTriggered)
		return out, hits
	case "scp":
		out, hits := handleSCPCommand(cmd, session, e.Topology)
		return out, hits
	case "mysql", "mysqldump", "mysqladmin":
		out, hits := responders.HandleMySQLCommand(cmd, ppfTriggered, session.DeceptionProfile, session)
		out = responders.LocalizeMySQLOutput(out, session)
		return out, hits
	case "psql", "pg_dump":
		out, hits := responders.HandlePostgresCommand(cmd, session, ppfTriggered)
		return out, hits
	case "ldapsearch":
		out, hits := responders.HandleLDAPCommand(cmd, session, e.Topology)
		return out, hits
	case "smbclient", "rpcclient":
		out, hits := responders.HandleSMBCommand(cmd, session, e.Topology)
		return out, hits
	case "kinit", "klist":
		out, hits := responders.HandleKerberosCommand(cmd)
		return out, hits
	case "dig", "nslookup":
		out, hits := responders.HandleDNSCommand(cmd, session, e.Topology)
		return out, hits
	case "redis-cli":
		out, hits := handleRedisCommand(cmd, session, e.Topology, ppfTriggered)
		return out, hits
	case "docker":
		return handleDockerCommand(cmdLower, session.SessionID), []string{"service_enum"}
	case "kubectl":
		return handleKubectlCommand(cmdLower, session.SessionID), []string{"service_enum"}
	case "python3", "python":
		out := responders.HandlePythonREPL(cmd, session, world)
		return out, nil
	}
	return "", nil
}

func shellLikeFallback(cmd string, session *domain.SessionContext) string {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return ""
	}
	switch parts[0] {
	case "cat", "head", "tail", "stat", "file":
		target := firstNonFlagArg(parts[1:])
		if target == "" {
			return fmt.Sprintf("%s: missing operand\n", parts[0])
		}
		return fmt.Sprintf("%s: %s: No such file or directory\n", parts[0], target)
	case "ls":
		target := firstNonFlagArg(parts[1:])
		if target == "" && session != nil {
			target = session.CWD
		}
		if target == "" {
			target = "."
		}
		return fmt.Sprintf("ls: cannot access '%s': No such file or directory\n", target)
	case "grep":
		return ""
	}
	return ""
}

func firstNonFlagArg(args []string) string {
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		if strings.Contains(arg, ">") || strings.Contains(arg, "|") {
			continue
		}
		return arg
	}
	return ""
}

func blockedCommandOutput(command, blockedIP string) string {
	base := ""
	if fields := strings.Fields(strings.TrimSpace(command)); len(fields) > 0 {
		base = strings.ToLower(fields[0])
	}
	switch base {
	case "nmap":
		if strings.Contains(command, "/") {
			return "Starting Nmap 7.93 ( https://nmap.org )\nNote: Host seems down. If it is really up, but blocking our ping probes, try -Pn\nNmap done: 256 IP addresses (0 hosts up) scanned in 12.01 seconds\n"
		}
		return fmt.Sprintf("Starting Nmap 7.93 ( https://nmap.org )\nNote: Host seems down. If it is really up, but blocking our ping probes, try -Pn\nNmap done: 1 IP address (0 hosts up) scanned in 2.01 seconds\n")
	case "fscan":
		return fmt.Sprintf("[*] fscan version: 1.8.4\n[*] start infoscan\n[-] %s no alive hosts\n[*] scan finished\n", blockedIP)
	case "nc", "ncat":
		return fmt.Sprintf("nc: connect to %s port 22 (tcp) failed: No route to host\n", blockedIP)
	case "curl", "wget":
		return fmt.Sprintf("curl: (7) Failed to connect to %s port 80 after 3001 ms: No route to host\n", blockedIP)
	case "ssh", "scp":
		return "ssh: connect to host " + blockedIP + " port 22: No route to host\n"
	default:
		return fmt.Sprintf("%s: connect: No route to host\n", blockedIP)
	}
}

func (e *RuleEngine) renderApproved(command, output string, session *domain.SessionContext) string {
	return deception.RenderApprovedResponse(command, output, session, e.Topology).Output
}

func handleSCPCommand(cmd string, session *domain.SessionContext, topology *domain.VirtualTopology) (string, []string) {
	if ipMatch := regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`).FindString(cmd); ipMatch != "" {
		host := topology.GetHost(ipMatch)
		if host != nil && hostInVisibleHosts(host, topology.GetHostsForSession(session)) {
			return fmt.Sprintf("%s: Permission denied (publickey,password).\n", ipMatch), []string{"lateral_probe", "credential_reuse_attempt"}
		}
	}
	return "scp: Connection closed\n", []string{"lateral_probe"}
}

func handleRedisCommand(cmd string, session *domain.SessionContext, topology *domain.VirtualTopology, ppfTriggered bool) (string, []string) {
	target := "192.168.56.30"
	if match := regexp.MustCompile(`-h\s+(\S+)`).FindStringSubmatch(cmd); len(match) > 1 {
		target = match[1]
	}
	host := topology.GetHost(target)
	if host == nil || !hostInVisibleHosts(host, topology.GetHostsForSession(session)) {
		return "Could not connect to Redis at " + target + ":6379: Connection refused\n", []string{"db_probe"}
	}

	// If the command is just a connection (only flags, no redis sub-command), enter interactive mode
	cmdOnly := strings.TrimPrefix(strings.TrimSpace(regexp.MustCompile(`-h\s+\S+\s*`).ReplaceAllString(cmd, "")), "redis-cli")
	cmdOnly = strings.TrimSpace(cmdOnly)
	if cmdOnly == "" && session.ShellMode != "redis" {
		session.ShellMode = "redis"
		session.CurrentTarget = target
		return "Connected to Redis at " + target + ":6379 [6.2.14]\nType \"exit\" or \"quit\" to return to shell.\n", []string{"db_probe"}
	}

	lower := strings.ToLower(cmd)
	sid := session.SessionID

	// INFO — basic enumeration
	if strings.Contains(lower, "info") {
		return "# Server\nredis_version:6.2.14\nredis_mode:standalone\nos:Linux\n# Keyspace\ndb0:keys=3,expires=0,avg_ttl=0\n", []string{"db_probe", "pseudo_progress"}
	}

	// CONFIG GET — reconnaissance (architecture §23.4)
	if strings.Contains(lower, "config get") {
		if strings.Contains(lower, "dir") || strings.Contains(lower, "dbfilename") {
			return "1) \"dir\"\n2) \"/var/lib/redis\"\n3) \"dbfilename\"\n4) \"dump.rdb\"\n", []string{"db_probe", "pseudo_progress"}
		}
		return "1) \"dir\"\n2) \"/var/lib/redis\"\n", []string{"db_probe"}
	}

	// CONFIG SET — write attempt, blocked (architecture §23.4)
	if strings.Contains(lower, "config set") {
		return "ERR Changing directory: Permission denied\n", []string{"db_probe", "pseudo_progress"}
	}

	// SAVE / BGSAVE — write attempt, blocked
	if strings.Contains(lower, "save") && !strings.Contains(lower, "keys") {
		return "ERR BGSAVE failed: Permission denied\n", []string{"db_probe", "pseudo_progress"}
	}

	// KEYS / SCAN — enumeration (varies per session)
	if strings.Contains(lower, "keys") || strings.Contains(lower, "scan") {
		keys := redisKeyNames(sid)
		return fmt.Sprintf("1) \"%s\"\n2) \"%s\"\n3) \"%s\"\n4) \"%s\"\n", keys[0], keys[1], keys[2], keys[3]), []string{"db_probe", "pseudo_progress"}
	}

	// GET — read specific key
	if strings.Contains(lower, "get ") {
		if strings.Contains(lower, "deploy:token") || strings.Contains(lower, redisKeyNames(sid)[1]) {
			return "\"glpat-" + domain.DeploySeed + "-deploy-token\"\n", []string{"db_probe", "pseudo_progress"}
		}
		if strings.Contains(lower, "backup:creds") || strings.Contains(lower, redisKeyNames(sid)[3]) {
			return "\"admin:" + domain.DerivePassword("redis-backup") + "\"\n", []string{"db_probe", "pseudo_progress"}
		}
		return "(nil)\n", []string{"db_probe"}
	}

	// SET / FLUSHALL / FLUSHDB — write attempt, blocked
	if strings.Contains(lower, "set ") || strings.Contains(lower, "flush") {
		return "ERR READONLY You can't write against a read only replica.\n", []string{"db_probe", "pseudo_progress"}
	}

	// Default: PONG for PING, error for unknown
	if strings.Contains(lower, "ping") {
		return "PONG\n", []string{"db_probe"}
	}
	return "ERR unknown command\n", []string{"db_probe"}
}

// redisKeyNames returns session-varying Redis key names.
func redisKeyNames(sessionID string) [4]string {
	seed := domain.SessionSeed(sessionID + "_redis")
	rng := rand.New(rand.NewSource(seed))
	names := [][4]string{
		{"session:admin", "deploy:token", "cache:finance:rollup", "backup:creds"},
		{"session:webapp", "api:key", "cache:user:rollup", "config:db"},
		{"session:api", "jwt:secret", "cache:sessions", "backup:config"},
		{"session:internal", "deploy:key", "cache:metrics", "storage:creds"},
	}
	return names[rng.Intn(len(names))]
}

func handleDockerCommand(cmdLower, sessionID string) string {
	seed := domain.SessionSeed(sessionID + "_docker")
	rng := rand.New(rand.NewSource(seed))
	cid1 := fmt.Sprintf("%08x%04x", rng.Int63(), rng.Intn(0xFFFF))
	cid2 := fmt.Sprintf("%08x%04x", rng.Int63(), rng.Intn(0xFFFF))
	imgID1 := fmt.Sprintf("%08x%04x", rng.Int63(), rng.Intn(0xFFFF))
	imgID2 := fmt.Sprintf("%08x%04x", rng.Int63(), rng.Intn(0xFFFF))
	switch {
	case strings.Contains(cmdLower, " ps"):
		return fmt.Sprintf("CONTAINER ID   IMAGE                    COMMAND                  STATUS          PORTS                    NAMES\n"+
			"%s   registry.local/web:2.4   \"gunicorn app:app\"       Up 45 days      127.0.0.1:5000->5000/tcp webapp\n"+
			"%s   redis:6.2-alpine         \"docker-entrypoint.s\"    Up 45 days      6379/tcp                 cache-sidecar\n", cid1[:12], cid2[:12])
	case strings.Contains(cmdLower, " images"):
		return fmt.Sprintf("REPOSITORY              TAG       IMAGE ID       CREATED        SIZE\nregistry.local/web      2.4       %s   3 weeks ago    418MB\nredis                   6.2       %s   2 months ago   32MB\n", imgID1[:12], imgID2[:12])
	default:
		return "Got permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock\n"
	}
}

func handleKubectlCommand(cmdLower, sessionID string) string {
	seed := domain.SessionSeed(sessionID + "_k8s")
	rng := rand.New(rand.NewSource(seed))
	pod1 := fmt.Sprintf("webapp-%s-%s", randHex(rng, 10), randHex(rng, 5))
	pod2 := fmt.Sprintf("worker-%s-%s", randHex(rng, 10), randHex(rng, 5))
	switch {
	case strings.Contains(cmdLower, "get pods"):
		return fmt.Sprintf("NAME                         READY   STATUS    RESTARTS   AGE\n%s      1/1     Running   0          21d\n%s      1/1     Running   1          21d\n", pod1, pod2)
	case strings.Contains(cmdLower, "get secrets"):
		return "NAME                  TYPE                                  DATA   AGE\nregistry-pull-token   kubernetes.io/dockerconfigjson        1      21d\nwebapp-env            Opaque                                5      21d\n"
	default:
		return "Error from server (Forbidden): user \"deploy\" cannot list resource in namespace \"prod-finance\"\n"
	}
}

func hostInVisibleHosts(host *domain.VirtualHost, visible []domain.VirtualHost) bool {
	for _, h := range visible {
		if h.IP == host.IP {
			return true
		}
	}
	return false
}

func randHex(rng *rand.Rand, n int) string {
	const hexChars = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = hexChars[rng.Intn(len(hexChars))]
	}
	return string(b)
}

func (e *RuleEngine) llmFallback(cmd string, session *domain.SessionContext, world *domain.WorldState) string {
	if e.LLM == nil || !e.LLM.IsActive() {
		recordLLMFallbackEvent(session, "inactive", cmd)
		return ""
	}
	if !allowLLMContextExport() {
		recordLLMFallbackEvent(session, "context_export_disabled", cmd)
		return ""
	}

	// Fire async LLM call — return empty immediately so the command falls
	// through to shellLikeFallback/command-not-found without blocking.
	// The LLM result is cached for subsequent invocations.
	go e.llmFallbackAsync(cmd, session, world)
	return ""
}

func (e *RuleEngine) llmFallbackAsync(cmd string, session *domain.SessionContext, world *domain.WorldState) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	profile := deception.ProfileFromSession(session)
	decision := deception.SelectStrategy(profile, session)
	strategyPrompt := deception.BuildStrategyPrompt(profile, decision, session)
	topologyContext := formatTopologyForPrompt(e.Topology)
	protectedTargets := ""
	if session != nil && session.Planning != nil {
		protectedTargets = strings.Join(session.Planning.ProtectedTargetList(), ", ")
	}

	systemContent := fmt.Sprintf(`You are a Linux terminal on host %s (Ubuntu 22.04). User: %s. CWD: %s.
Rules:
- Return ONLY raw terminal output. No markdown, no fences, no prompts, no explanations.
- Never explain how you chose the output. Never write analysis, reasoning, or phrases like "we need to".
- If a file does not exist, generate realistic content for a staging web server.
- If a command needs root and user is not root, return "Permission denied".
- For "ls" on a directory, list realistic files. For "cat", show realistic file content.
- Do not invent new IPs, hostnames, services, credentials, routes, or successful exploit facts.
- You may only mention IPs present in the approved topology or protected target list.
- Keep output under 15 lines. Be terse like a real terminal.
Topology: %s
Protected targets already known to the attacker: %s
%s
%s`, session.Hostname, session.User, session.CWD, topologyContext, protectedTargets, memorySummary(session), strategyPrompt)

	req := llm.CompletionRequest{
		MaxTokens:   500,
		Temperature: 0.3,
		Messages: []llm.Message{
			{
				Role:    "system",
				Content: systemContent,
			},
			{
				Role:    "user",
				Content: fmt.Sprintf("Recent commands: %s\nFiles in cwd: %s\n%sRun this command and return only its output:\n%s", commandHistoryTail(session, 5), strings.Join(world.ListFiles(session.CWD), ", "), contextAwareSlice(cmd, session), cmd),
			},
		},
	}

	resp, err := e.LLM.Complete(ctx, req)
	if err != nil {
		recordLLMFallbackEvent(session, "complete_error:"+err.Error(), cmd)
		return
	}
	output := sanitizeTerminalOutput(resp.Content)
	if output == "" {
		recordLLMFallbackEvent(session, "empty_after_sanitize", cmd)
		return
	}
	guarded := deception.GuardTerminalOutput(output, session)
	if guarded.Blocked {
		recordLLMFallbackEvent(session, "terminal_guard:"+guarded.Reason, cmd)
		return
	}
	factGuarded := deception.GuardResponseFacts(guarded.Output, session, e.Topology)
	if factGuarded.Blocked {
		recordLLMFallbackEvent(session, "fact_guard:"+factGuarded.Reason, cmd)
		return
	}
	storeAndInject(cmd, factGuarded.Output, world, session.CWD)
	recordLLMFallbackEvent(session, "llm_fallback_async_cached", cmd)
}

func recordLLMFallbackEvent(session *domain.SessionContext, reason, command string) {
	if session == nil {
		return
	}
	session.AppendEvent(domain.EventEntry{
		Type:      "llm_fallback",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		SessionID: session.SessionID,
		Detail:    reason + ":" + command,
	})
}

func memorySummary(session *domain.SessionContext) string {
	if session == nil || session.Memory == nil {
		return ""
	}
	return session.Memory.PromptSummary()
}

// contextAwareSlice builds the L1 context-aware prompt slice described in the
// LLM agent architecture (§3.2 buildL1Context). It selectively injects only
// the facts relevant to the current command's semantic so the LLM stays
// consistent without bloating the prompt.
func contextAwareSlice(cmd string, session *domain.SessionContext) string {
	if session == nil {
		return ""
	}
	lower := strings.ToLower(cmd)
	var parts []string

	// SSH / lateral movement → inject target host summary from L2 invariants
	if strings.HasPrefix(lower, "ssh ") || strings.Contains(lower, "scp ") {
		if session.Planning != nil {
			for _, fact := range session.Planning.ServicePersonaFacts("") {
				if strings.Contains(lower, fact.HostIP) || (fact.Hostname != "" && strings.Contains(lower, strings.ToLower(fact.Hostname))) {
					parts = append(parts, "Target host: "+fact.Summary)
				}
			}
		}
		for _, fact := range session.Memory.FindInvariantsPrefix("service.") {
			if strings.Contains(lower, fact.Value) || strings.Contains(lower, strings.Split(fact.Key, ".")[1]) {
				parts = append(parts, "Target host: "+fact.Value)
			}
		}
	}

	// MySQL / DB commands → inject discovered DB credentials from L1
	if strings.HasPrefix(lower, "mysql") || strings.HasPrefix(lower, "mysqldump") || strings.HasPrefix(lower, "psql") {
		if session.Planning != nil {
			for _, fact := range session.Planning.ServicePersonaFacts("") {
				if strings.Contains(fact.Service, "mysql") || strings.Contains(fact.Service, "postgres") {
					parts = append(parts, "DB context: "+fact.Summary)
				}
			}
		}
		for _, fact := range session.Memory.FindInvariantsPrefix("service.") {
			if strings.Contains(fact.Key, "mysql") || strings.Contains(fact.Key, "postgres") {
				parts = append(parts, "DB context: "+fact.Value)
			}
		}
	}

	// cat/grep/file reads → inject recently accessed file hints from L1
	if strings.Contains(lower, "cat ") || strings.Contains(lower, "grep ") || strings.Contains(lower, "head ") || strings.Contains(lower, "tail ") {
		if facts := session.Memory.FindInvariantsPrefix("intent.secret_hunting"); len(facts) > 0 {
			parts = append(parts, "Attacker is hunting secrets — keep file content realistic and breadcrumb-consistent")
		}
	}

	// Network commands → inject network overview from L2
	if strings.Contains(lower, "nmap") || strings.Contains(lower, "ping ") || strings.Contains(lower, "traceroute") || strings.Contains(lower, "fscan") {
		if fact, ok := session.Memory.GetInvariant("network.entry"); ok {
			parts = append(parts, "Network: "+fact.Value)
		}
	}

	if len(parts) == 0 {
		return ""
	}
	return "Context:\n" + strings.Join(parts, "\n") + "\n"
}

func formatTopologyForPrompt(topology *domain.VirtualTopology) string {
	if topology == nil {
		return "unavailable"
	}
	var lines []string
	for _, segment := range topology.AllSegments() {
		lines = append(lines, fmt.Sprintf("segment %s name=%s zone=%s shadow=%t", segment.CIDR, segment.Name, segment.Zone, segment.Shadow))
	}
	for _, edge := range topology.AllEdges() {
		lines = append(lines, fmt.Sprintf("edge %s -> %s type=%s via=%s required=%s status=%s", edge.From, edge.To, edge.Type, edge.Via, strings.Join(edge.RequiredState, ","), edge.Status))
	}
	for _, host := range topology.AllHosts() {
		lines = append(lines, fmt.Sprintf("host %s %s role=%s segment=%s via=%s required=%s shadow=%t", host.IP, host.Hostname, host.Role, host.SegmentCIDR, host.ReachableVia, strings.Join(host.RequiredState, ","), host.Shadow))
	}
	return strings.Join(lines, "\n")
}

func commandHistoryTail(session *domain.SessionContext, limit int) string {
	if limit <= 0 || len(session.CommandLog) == 0 {
		return ""
	}
	start := len(session.CommandLog) - limit
	if start < 0 {
		start = 0
	}
	var cmds []string
	for _, entry := range session.CommandLog[start:] {
		cmds = append(cmds, entry.Command)
	}
	return strings.Join(cmds, "\n")
}

func sanitizeTerminalOutput(output string) string {
	output = strings.TrimSpace(output)
	if output == "" {
		return ""
	}

	// Strip markdown code fences (```python, ```bash, ``` etc.)
	lines := strings.Split(output, "\n")
	var cleaned []string
	inFence := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Detect opening/closing fences
		if strings.HasPrefix(trimmed, "```") {
			inFence = !inFence
			continue
		}
		// Skip prompt artifacts the LLM echoed back
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "current files near cwd:") {
			break // Everything after this is prompt context, not output
		}
		if strings.HasPrefix(lower, "command:") && len(trimmed) < 80 {
			break
		}
		if strings.HasPrefix(lower, "command history tail:") {
			break
		}
		if strings.HasPrefix(lower, "evidence:") && len(trimmed) < 200 {
			break
		}
		if strings.HasPrefix(lower, "access states:") {
			break
		}
		if strings.HasPrefix(lower, "ppf triggered:") {
			break
		}
		if strings.HasPrefix(lower, "memory:") && len(trimmed) < 200 {
			break
		}
		// Skip standalone language identifiers
		if trimmed == "python" || trimmed == "bash" || trimmed == "sh" || trimmed == "shell" {
			continue
		}
		// Skip AI disclaimers
		if strings.Contains(lower, "as an ai") || strings.Contains(lower, "as a language model") {
			return ""
		}
		if looksLikeLLMReasoning(trimmed) {
			continue
		}
		cleaned = append(cleaned, line)
	}

	output = strings.Join(cleaned, "\n")
	output = strings.TrimSpace(output)
	if output == "" {
		return ""
	}
	return strings.TrimRight(output, "\n") + "\n"
}

func looksLikeLLMReasoning(line string) bool {
	lower := strings.ToLower(strings.TrimSpace(line))
	if lower == "" {
		return false
	}
	reasoningPrefixes := []string{
		"we need to",
		"i need to",
		"i'll ",
		"the user is",
		"according to",
		"consider ",
		"example:",
		"example content",
		"better:",
		"alternatively",
		"but ",
		"maybe ",
		"that includes",
		"given the strategy",
		"the rules ",
		"this command ",
		"thus,",
		"output:",
		"make it ",
		"we should",
		"i should",
		"let's",
		"so ",
	}
	for _, prefix := range reasoningPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return strings.Contains(lower, "return only") ||
		strings.Contains(lower, "simulate the output") ||
		strings.Contains(lower, "plausible output") ||
		strings.Contains(lower, "terminal output")
}

// isShellError detects when the shell responder returned an error or empty result
// that could benefit from LLM-generated content.
func isShellError(output string) bool {
	o := strings.TrimSpace(output)
	if o == "" {
		return true
	}
	lower := strings.ToLower(o)
	errorPatterns := []string{
		"no such file or directory",
		"permission denied",
		"command not found",
		"not a directory",
		"is a directory",
		"missing operand",
		"no such file",
	}
	for _, p := range errorPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// buildCacheKey extracts a normalized cache key from a command string.
// Relative paths are resolved against cwd so that "ls" in /sys and "ls" in /root
// produce different cache keys.
//
// Examples (cwd=/root):
//
//	"ls /sys"                  → "ls:/sys"
//	"ls -la /sys"              → "ls:-la:/sys"
//	"ls"                       → "ls:/root"
//	"ls -la"                   → "ls:-la:/root"
//	"cat /sys/kernel/uevent"   → "cat:/sys/kernel/uevent"
func buildCacheKey(cmd string, cwd string) string {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return cmd
	}
	cmdBase := parts[0]
	args := parts[1:]

	switch cmdBase {
	case "ls":
		var flags []string
		var target string
		for _, a := range args {
			if strings.HasPrefix(a, "-") {
				flags = append(flags, a)
			} else {
				target = a
			}
		}
		if target == "" {
			target = cwd
		} else if !strings.HasPrefix(target, "/") {
			target = path.Clean(cwd + "/" + target)
		}
		f := strings.Join(flags, " ")
		return domain.CacheKey(cmdBase, f, target)

	case "cat", "head", "tail", "more", "less":
		for _, a := range args {
			if !strings.HasPrefix(a, "-") {
				resolved := a
				if !strings.HasPrefix(resolved, "/") {
					resolved = path.Clean(cwd + "/" + resolved)
				}
				return domain.CacheKey(cmdBase, "", resolved)
			}
		}
		return domain.CacheKey(cmdBase, "", strings.Join(args, " "))

	default:
		return domain.CacheKey(cmdBase, "", strings.Join(args, " "))
	}
}

// storeAndInject caches the LLM response and, for ls/cat commands,
// parses the output and injects entries into the WorldState so that
// subsequent commands on the same path return consistent results.
func storeAndInject(cmd, output string, world *domain.WorldState, cwd string) {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return
	}
	cmdBase := parts[0]
	args := parts[1:]
	cacheKey := buildCacheKey(cmd, cwd)

	// Always store in the output cache
	world.Cache().Store(cacheKey, cmdBase, extractTarget(args), extractFlags(args), output)

	switch cmdBase {
	case "ls":
		target := extractTarget(args)
		if target == "" {
			target = cwd
		} else if !strings.HasPrefix(target, "/") {
			target = path.Clean(cwd + "/" + target)
		}
		world.InjectLsOutput(target, output)

	case "cat":
		for _, a := range args {
			if !strings.HasPrefix(a, "-") {
				resolved := a
				if !strings.HasPrefix(resolved, "/") {
					resolved = path.Clean(cwd + "/" + resolved)
				}
				world.InjectCatOutput(resolved, strings.TrimRight(output, "\n"))
				break
			}
		}
	}
}

// extractTarget returns the first non-flag argument.
func extractTarget(args []string) string {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			return a
		}
	}
	return ""
}

func allowLLMContextExport() bool {
	return strings.EqualFold(os.Getenv("ALTERHIVE_ALLOW_LLM_CONTEXT_EXPORT"), "true")
}

// extractFlags returns all flag arguments joined by space.
func extractFlags(args []string) string {
	var flags []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
		}
	}
	return strings.Join(flags, " ")
}
