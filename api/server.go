package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alterhive/alterhive/internal/domain"
	"github.com/alterhive/alterhive/internal/llm"
	"github.com/alterhive/alterhive/internal/session"

	"github.com/gin-gonic/gin"
)

// Server is the REST API server.
type Server struct {
	manager *session.Manager
	llm     *llm.Manager
	token   string // Bearer token for auth
}

var (
	runtimeRestartMu     sync.Mutex
	runtimeRestartQueued bool
)

// NewServer creates a new API server.
func NewServer(manager *session.Manager, llmMgr *llm.Manager) *Server {
	return &Server{
		manager: manager,
		llm:     llmMgr,
		token:   "alterhive-admin-token",
	}
}

// RegisterRoutes registers all API routes.
func (s *Server) RegisterRoutes(r *gin.Engine) {
	r.GET("/healthz", s.healthz)

	v1 := r.Group("/api/v1")
	{
		v1.POST("/auth/login", s.login)
		v1.GET("/auth/me", s.authMiddleware(), s.me)

		v1.GET("/dashboard/summary", s.authMiddleware(), s.dashboardSummary)
		v1.GET("/nodes", s.authMiddleware(), s.nodes)
		v1.GET("/sessions", s.authMiddleware(), s.sessions)
		v1.GET("/sessions/:id", s.authMiddleware(), s.sessionDetail)
		v1.GET("/sessions/:id/topology", s.authMiddleware(), s.sessionTopology)
		v1.GET("/sessions/:id/commands", s.authMiddleware(), s.sessionCommands)
		v1.DELETE("/sessions/:id", s.authMiddleware(), s.deleteSession)
		v1.GET("/commands", s.authMiddleware(), s.commands)
		v1.GET("/config/runtime", s.authMiddleware(), s.getRuntimeConfig)
		v1.PATCH("/config/runtime", s.authMiddleware(), s.updateRuntimeConfig)
		v1.GET("/config/runtime/update-status", s.authMiddleware(), s.getRuntimeUpdateStatus)

		// LLM management
		v1.GET("/llm/providers", s.authMiddleware(), s.llmProviders)
		v1.GET("/llm/active", s.authMiddleware(), s.llmActive)
		v1.POST("/llm/switch/:id", s.authMiddleware(), s.llmSwitch)
		v1.PUT("/llm/providers/:id", s.authMiddleware(), s.llmUpdateProvider)
		v1.POST("/llm/test/:id", s.authMiddleware(), s.llmTest)
		v1.GET("/llm/providers/:id/models", s.authMiddleware(), s.llmModels)
		v1.PUT("/llm/enabled", s.authMiddleware(), s.llmSetEnabled)

		v1.GET("/system/info", s.authMiddleware(), s.systemInfo)

		// Network simulation API (for AI agents)
		v1.POST("/simulate/nmap", s.simNmap)
		v1.POST("/simulate/fscan", s.simFscan)
		v1.POST("/simulate/curl", s.simCurl)
		v1.POST("/simulate/ssh", s.simSSH)
		v1.POST("/simulate/nc", s.simNC)
		v1.POST("/simulate/ping", s.simPing)
		v1.POST("/simulate/goal", s.simGoal)
		v1.GET("/simulate/session/:id", s.simSessionStatus)
	}
}

func (s *Server) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") || strings.TrimPrefix(auth, "Bearer ") != s.token {
			c.JSON(http.StatusUnauthorized, gin.H{"ok": false, "message": "Unauthorized"})
			c.Abort()
			return
		}
		c.Next()
	}
}

func (s *Server) healthz(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) login(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "message": "Invalid request"})
		return
	}
	if req.Username == "admin" && req.Password == "admin" {
		c.JSON(http.StatusOK, gin.H{
			"ok": true,
			"data": gin.H{
				"access_token": s.token,
				"token_type":   "Bearer",
				"user": gin.H{
					"id":           1,
					"username":     "admin",
					"display_name": "Admin",
					"role":         "admin",
					"active":       true,
					"permissions":  []string{"system:read", "session:read", "config:read", "config:write"},
				},
			},
			"message": "Login successful",
		})
		return
	}
	c.JSON(http.StatusUnauthorized, gin.H{"ok": false, "message": "Invalid credentials"})
}

func (s *Server) me(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"ok": true,
		"data": gin.H{
			"id":           1,
			"username":     "admin",
			"display_name": "Admin",
			"role":         "admin",
			"active":       true,
			"permissions":  []string{"system:read", "session:read", "config:read", "config:write"},
		},
		"message": "ok",
	})
}

func (s *Server) dashboardSummary(c *gin.Context) {
	sessions := s.manager.AllSessions()
	commands := s.manager.AllCommands()

	activeSessions := 0
	totalEvidence := 0
	totalScore := 0
	uniqueIPs := make(map[string]int)
	protocolCounts := make(map[string]int)

	for _, sess := range sessions {
		if sess.IsConnected() {
			activeSessions++
		}
		totalEvidence += sess.Evidence.HitCount()
		totalScore += sess.LoopMetrics.Score()
		uniqueIPs[extractIP(sess.RemoteAddr)]++
	}

	// Count handler types
	for _, cmd := range commands {
		if cmd.Intent != "" {
			protocolCounts[cmd.Intent]++
		}
	}

	var playbookMetrics []gin.H
	for handler, count := range protocolCounts {
		playbookMetrics = append(playbookMetrics, gin.H{
			"handler": handler,
			"count":   count,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"ok": true,
		"data": gin.H{
			"total_sessions":      len(sessions),
			"active_sessions":     activeSessions,
			"total_commands":      len(commands),
			"total_evidence_hits": totalEvidence,
			"total_score":         totalScore,
			"unique_attackers":    len(uniqueIPs),
			"ppf_triggered_count": countPPF(sessions),
			"playbook_metrics":    playbookMetrics,
			"top_attackers":       topAttackers(sessions),
			"recent_sessions":     recentSessions(sessions, 5),
		},
		"message": "ok",
	})
}

func (s *Server) nodes(c *gin.Context) {
	topology := s.manager.TopologyRef()
	hosts := topology.AllHosts()

	var nodes []gin.H
	for _, h := range hosts {
		var services []gin.H
		for _, svc := range h.Services {
			services = append(services, gin.H{
				"port":     svc.Port,
				"protocol": svc.Protocol,
				"state":    "open",
			})
		}
		nodes = append(nodes, gin.H{
			"ip":              h.IP,
			"hostname":        h.Hostname,
			"role":            h.Role,
			"os":              h.OS,
			"services":        services,
			"segment_cidr":    h.SegmentCIDR,
			"reachable_via":   h.ReachableVia,
			"required_state":  h.RequiredState,
			"shadow":          h.Shadow,
			"theme":           h.Theme,
			"compromise_mode": h.CompromiseMode,
			"status":          nodeStatus(h),
			"last_seen":       time.Now().UTC().Format(time.RFC3339),
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"ok": true,
		"data": gin.H{
			"nodes":    nodes,
			"segments": topology.AllSegments(),
			"edges":    topology.AllEdges(),
			"total":    len(nodes),
		},
		"message": "ok",
	})
}

func (s *Server) sessions(c *gin.Context) {
	page, pageSize := paginationParams(c, 20)

	allSessions := s.manager.AllSessions()
	if query := strings.ToLower(strings.TrimSpace(c.Query("query"))); query != "" {
		filtered := allSessions[:0]
		for _, sess := range allSessions {
			haystack := strings.ToLower(sess.SessionID + " " + sess.Username + " " + sess.RemoteAddr + " " + sess.Hostname)
			if strings.Contains(haystack, query) {
				filtered = append(filtered, sess)
			}
		}
		allSessions = filtered
	}
	sort.Slice(allSessions, func(i, j int) bool {
		return allSessions[i].ConnectedAt.After(allSessions[j].ConnectedAt)
	})

	total := len(allSessions)
	start := (page - 1) * pageSize
	end := start + pageSize
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	rows := []gin.H{}
	for _, sess := range allSessions[start:end] {
		rows = append(rows, sessionToRow(sess))
	}

	c.JSON(http.StatusOK, gin.H{
		"ok": true,
		"data": gin.H{
			"items":     rows,
			"total":     total,
			"page":      page,
			"page_size": pageSize,
		},
		"message": "ok",
	})
}

func (s *Server) sessionDetail(c *gin.Context) {
	id := c.Param("id")
	sess := s.manager.GetSession(id)
	if sess == nil {
		c.JSON(http.StatusNotFound, gin.H{"ok": false, "message": "Session not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"ok":      true,
		"data":    sessionDetail(sess, c.DefaultQuery("include_commands", "true") != "false"),
		"message": "ok",
	})
}

// sessionTopology returns the base deception graph plus dynamic assets owned by
// one session. Dynamic nodes from other attacker sessions are never included.
func (s *Server) sessionTopology(c *gin.Context) {
	id := c.Param("id")
	sess := s.manager.GetSession(id)
	if sess == nil {
		c.JSON(http.StatusNotFound, gin.H{"ok": false, "message": "Session not found"})
		return
	}

	topology := s.manager.TopologyRef()
	hosts := make([]gin.H, 0)
	visibleIPs := make(map[string]bool)
	visibleSegments := make(map[string]bool)
	discovered := strings.ToLower(sess.CurrentTarget + " " + sess.SubnetLocalIP + " " + sess.Hostname)
	for _, cmd := range sess.CommandLog {
		discovered += " " + strings.ToLower(cmd.Command+" "+cmd.Output+" "+cmd.Hostname)
	}
	allHosts := topology.AllHosts()
	selectedHosts := make([]domain.VirtualHost, 0)
	for _, host := range allHosts {
		if host.OwnerSessionID != "" && host.OwnerSessionID != id {
			continue
		}
		isEntry := host.IP == sess.SubnetLocalIP || host.Hostname == sess.Hostname
		isOwned := host.OwnerSessionID == id
		isObserved := strings.Contains(discovered, strings.ToLower(host.IP)) || strings.Contains(discovered, strings.ToLower(host.Hostname))
		if !isEntry && !isOwned && !isObserved {
			continue
		}
		selectedHosts = append(selectedHosts, host)
		visibleIPs[host.IP] = true
		if host.SegmentCIDR != "" {
			visibleSegments[host.SegmentCIDR] = true
		}
	}
	// Include upstream pivots needed to make every selected node's path readable.
	for changed := true; changed; {
		changed = false
		for _, host := range allHosts {
			if host.OwnerSessionID != "" && host.OwnerSessionID != id || visibleIPs[host.IP] {
				continue
			}
			for _, selected := range selectedHosts {
				if selected.ReachableVia == host.IP {
					selectedHosts = append(selectedHosts, host)
					visibleIPs[host.IP] = true
					visibleSegments[host.SegmentCIDR] = true
					changed = true
					break
				}
			}
		}
	}
	for _, host := range selectedHosts {
		hosts = append(hosts, topologyHostRow(host))
	}

	segments := make([]domain.NetworkSegment, 0)
	for _, segment := range topology.AllSegments() {
		if segment.OwnerSessionID != "" && segment.OwnerSessionID != id {
			continue
		}
		if segment.OwnerSessionID == id || visibleSegments[segment.CIDR] {
			segments = append(segments, segment)
		}
	}

	edges := make([]domain.NetworkEdge, 0)
	for _, edge := range topology.AllEdges() {
		if edge.OwnerSessionID != "" && edge.OwnerSessionID != id {
			continue
		}
		fromVisible := visibleIPs[edge.From] || visibleSegments[edge.From]
		toVisible := visibleIPs[edge.To] || visibleSegments[edge.To]
		if edge.OwnerSessionID == id || (fromVisible && toVisible) {
			edges = append(edges, edge)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"ok": true,
		"data": gin.H{
			"nodes": hosts, "segments": segments, "edges": edges, "total": len(hosts),
			"session": gin.H{
				"session_id": id, "username": sess.Username, "remote_addr": sess.RemoteAddr,
				"current_target": sess.CurrentTarget, "access_states": sess.AccessStateList(),
				"current_host_ip": sess.SubnetLocalIP,
			},
		},
		"message": "ok",
	})
}

func (s *Server) sessionCommands(c *gin.Context) {
	id := c.Param("id")
	sess := s.manager.GetSession(id)
	if sess == nil {
		c.JSON(http.StatusNotFound, gin.H{"ok": false, "message": "Session not found"})
		return
	}

	page, pageSize := paginationParams(c, 50)

	commands := sess.CommandLog
	if query := strings.ToLower(strings.TrimSpace(c.Query("query"))); query != "" {
		filtered := make([]domain.CommandEntry, 0)
		for _, cmd := range commands {
			haystack := strings.ToLower(cmd.Command + " " + cmd.Output + " " + cmd.Intent)
			if strings.Contains(haystack, query) {
				filtered = append(filtered, cmd)
			}
		}
		commands = filtered
	}
	total := len(commands)
	start := (page - 1) * pageSize
	end := start + pageSize
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	items := []gin.H{}
	for _, cmd := range commands[start:end] {
		items = append(items, gin.H{
			"command":       cmd.Command,
			"output":        cmd.Output,
			"timestamp":     cmd.Timestamp,
			"intent":        cmd.Intent,
			"evidence_hits": cmd.EvidenceHits,
			"score":         cmd.Score,
			"hostname":      firstNonEmpty(cmd.Hostname, sess.Hostname),
			"llm_generated": cmd.LLMGenerated,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"ok": true,
		"data": gin.H{
			"items":     items,
			"total":     total,
			"page":      page,
			"page_size": pageSize,
		},
		"message": "ok",
	})
}

func (s *Server) deleteSession(c *gin.Context) {
	id := c.Param("id")
	if !s.manager.DeleteSession(id) {
		c.JSON(http.StatusNotFound, gin.H{"ok": false, "message": "Session not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "message": "Session deleted"})
}

func (s *Server) commands(c *gin.Context) {
	page, pageSize := paginationParams(c, 50)

	allCommands := s.manager.AllCommands()
	sort.Slice(allCommands, func(i, j int) bool {
		return allCommands[i].Timestamp > allCommands[j].Timestamp
	})

	total := len(allCommands)
	start := (page - 1) * pageSize
	end := start + pageSize
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	items := []gin.H{}
	for _, cmd := range allCommands[start:end] {
		items = append(items, gin.H{
			"command":       cmd.Command,
			"output":        cmd.Output,
			"timestamp":     cmd.Timestamp,
			"intent":        cmd.Intent,
			"evidence_hits": cmd.EvidenceHits,
			"score":         cmd.Score,
			"session_id":    cmd.SessionID,
			"username":      cmd.Username,
			"remote_addr":   cmd.RemoteAddr,
			"llm_generated": cmd.LLMGenerated,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"ok": true,
		"data": gin.H{
			"items":     items,
			"total":     total,
			"page":      page,
			"page_size": pageSize,
		},
		"message": "ok",
	})
}

func (s *Server) getRuntimeConfig(c *gin.Context) {
	cfg := loadRuntimeConfig()
	c.JSON(http.StatusOK, gin.H{
		"ok": true,
		"data": gin.H{
			"honeypot": gin.H{
				"ssh_port":        cfg.SSHPort,
				"api_port":        cfg.APIPort,
				"topology_cidr":   cfg.TopologyCIDR,
				"session_timeout": cfg.SessionTimeout,
			},
			"llm": gin.H{
				"enabled":  false,
				"provider": "openai",
				"base_url": "https://api.openai.com/v1",
				"model":    "gpt-4",
				"api_key":  "",
			},
		},
		"message": "ok",
	})
}

func (s *Server) updateRuntimeConfig(c *gin.Context) {
	var payload struct {
		Honeypot runtimeConfig `json:"honeypot"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "message": "Invalid JSON"})
		return
	}
	cfg := payload.Honeypot.withDefaults()
	if err := validateRuntimeConfig(cfg); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "message": err.Error()})
		return
	}
	if err := saveRuntimeConfig(cfg); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "message": err.Error()})
		return
	}
	writeRuntimeUpdateStatus(runtimeUpdateStatus{
		Phase:     "queued",
		Message:   "配置已写入，等待 Docker 更新任务启动",
		Config:    cfg,
		UpdatedAt: time.Now().Format(time.RFC3339),
	})
	scheduleRuntimeRestart()
	c.JSON(http.StatusOK, gin.H{
		"ok": true,
		"data": gin.H{
			"honeypot": gin.H{
				"ssh_port":        cfg.SSHPort,
				"api_port":        cfg.APIPort,
				"topology_cidr":   cfg.TopologyCIDR,
				"session_timeout": cfg.SessionTimeout,
			},
			"restart_queued": true,
		},
		"message": "Config saved. Restart queued.",
	})
}

func (s *Server) getRuntimeUpdateStatus(c *gin.Context) {
	status, err := readRuntimeUpdateStatus()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"ok": true,
			"data": gin.H{
				"phase":      "idle",
				"message":    "暂无配置更新任务",
				"updated_at": time.Now().Format(time.RFC3339),
			},
			"message": "ok",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "data": status, "message": "ok"})
}

type runtimeConfig struct {
	SSHPort        int    `json:"ssh_port"`
	APIPort        int    `json:"api_port"`
	TopologyCIDR   string `json:"topology_cidr"`
	SessionTimeout int    `json:"session_timeout"`
}

type runtimeUpdateStatus struct {
	Phase     string        `json:"phase"`
	Message   string        `json:"message"`
	Config    runtimeConfig `json:"config"`
	UpdatedAt string        `json:"updated_at"`
	Error     string        `json:"error,omitempty"`
}

func defaultRuntimeConfig() runtimeConfig {
	return runtimeConfig{SSHPort: 2222, APIPort: 8000, TopologyCIDR: "192.168.56.0/24", SessionTimeout: 600}
}

func (cfg runtimeConfig) withDefaults() runtimeConfig {
	defaults := defaultRuntimeConfig()
	if cfg.SSHPort == 0 {
		cfg.SSHPort = defaults.SSHPort
	}
	if cfg.APIPort == 0 {
		cfg.APIPort = defaults.APIPort
	}
	if cfg.TopologyCIDR == "" {
		cfg.TopologyCIDR = defaults.TopologyCIDR
	}
	if cfg.SessionTimeout == 0 {
		cfg.SessionTimeout = defaults.SessionTimeout
	}
	return cfg
}

func loadRuntimeConfig() runtimeConfig {
	cfg := defaultRuntimeConfig()
	env := readDotEnv(".env")
	if value := firstNonEmpty(env["SSH_PORT"], os.Getenv("SSH_PORT")); value != "" {
		cfg.SSHPort = atoiOrDefault(value, cfg.SSHPort)
	}
	if value := firstNonEmpty(env["API_PORT"], os.Getenv("API_PORT")); value != "" {
		cfg.APIPort = atoiOrDefault(value, cfg.APIPort)
	}
	if value := firstNonEmpty(env["TOPOLOGY_CIDR"], os.Getenv("TOPOLOGY_CIDR")); value != "" {
		cfg.TopologyCIDR = value
	}
	if value := firstNonEmpty(env["SESSION_TIMEOUT"], os.Getenv("SESSION_TIMEOUT")); value != "" {
		cfg.SessionTimeout = atoiOrDefault(value, cfg.SessionTimeout)
	}
	return cfg
}

func validateRuntimeConfig(cfg runtimeConfig) error {
	if cfg.SSHPort < 1 || cfg.SSHPort > 65535 {
		return fmt.Errorf("SSH 端口必须在 1-65535 之间")
	}
	if cfg.APIPort < 1 || cfg.APIPort > 65535 {
		return fmt.Errorf("API 端口必须在 1-65535 之间")
	}
	if cfg.SSHPort == cfg.APIPort {
		return fmt.Errorf("SSH 端口和 API 端口不能相同")
	}
	if _, _, err := net.ParseCIDR(cfg.TopologyCIDR); err != nil {
		return fmt.Errorf("拓扑网段必须是合法 CIDR")
	}
	if cfg.SessionTimeout < 60 || cfg.SessionTimeout > 86400 {
		return fmt.Errorf("会话超时必须在 60-86400 秒之间")
	}
	return nil
}

func saveRuntimeConfig(cfg runtimeConfig) error {
	env := readDotEnv("configs/.env")
	env["SSH_PORT"] = strconv.Itoa(cfg.SSHPort)
	env["API_PORT"] = strconv.Itoa(cfg.APIPort)
	env["TOPOLOGY_CIDR"] = cfg.TopologyCIDR
	env["SESSION_TIMEOUT"] = strconv.Itoa(cfg.SessionTimeout)
	return writeDotEnv("configs/.env", env, []string{"SSH_PORT", "API_PORT", "TOPOLOGY_CIDR", "SESSION_TIMEOUT"})
}

func scheduleRuntimeRestart() {
	runtimeRestartMu.Lock()
	if runtimeRestartQueued {
		writeRuntimeUpdateStatus(runtimeUpdateStatus{
			Phase:     "queued",
			Message:   "已有配置更新任务正在执行，当前请求已合并",
			Config:    loadRuntimeConfig(),
			UpdatedAt: time.Now().Format(time.RFC3339),
		})
		runtimeRestartMu.Unlock()
		return
	}
	runtimeRestartQueued = true
	runtimeRestartMu.Unlock()

	go func() {
		time.Sleep(1500 * time.Millisecond)
		if err := restartRuntimeContainers(); err != nil {
			runtimeRestartMu.Lock()
			runtimeRestartQueued = false
			runtimeRestartMu.Unlock()
			writeRuntimeUpdateStatus(runtimeUpdateStatus{
				Phase:     "failed",
				Message:   "Docker 更新任务启动失败",
				Config:    loadRuntimeConfig(),
				UpdatedAt: time.Now().Format(time.RFC3339),
				Error:     err.Error(),
			})
			fmt.Fprintf(os.Stderr, "failed to restart AlterHive containers: %v\n", err)
		} else {
			runtimeRestartMu.Lock()
			runtimeRestartQueued = false
			runtimeRestartMu.Unlock()
		}
	}()
}

func restartRuntimeContainers() error {
	running, err := exec.Command("docker", "ps", "-q", "--filter", "label=alterhive.role=config-applier").CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to inspect running config appliers: %w: %s", err, strings.TrimSpace(string(running)))
	}
	if strings.TrimSpace(string(running)) != "" {
		return nil
	}

	projectDir := firstNonEmpty(os.Getenv("ALTERHIVE_PROJECT_DIR"), "/workspace/alterhive", ".")
	helperImage := firstNonEmpty(os.Getenv("ALTERHIVE_HELPER_IMAGE"), "alterhive-v100-honeypot:latest")
	helperName := fmt.Sprintf("alterhive-config-applier-%d", time.Now().UnixNano())
	script := "status_file=configs/runtime-update-status.json; now() { date -u +%Y-%m-%dT%H:%M:%SZ; }; printf '{\"phase\":\"running\",\"message\":\"Docker 正在重建并重启 honeypot/frontend\",\"updated_at\":\"%s\"}\\n' \"$(now)\" > \"$status_file\"; sleep 2; if docker compose --env-file configs/.env up -d --build --remove-orphans --force-recreate honeypot frontend; then printf '{\"phase\":\"complete\",\"message\":\"蜜罐配置已应用，容器已重新运行\",\"updated_at\":\"%s\"}\\n' \"$(now)\" > \"$status_file\"; docker container prune -f --filter label=com.docker.compose.project=alterhive-v1 >/dev/null 2>&1 || true; else code=$?; printf '{\"phase\":\"failed\",\"message\":\"Docker Compose 更新失败\",\"error\":\"exit %s\",\"updated_at\":\"%s\"}\\n' \"$code\" \"$(now)\" > \"$status_file\"; exit $code; fi"
	cmd := exec.Command(
		"docker", "run", "--rm", "-d",
		"--name", helperName,
		"--label", "alterhive.role=config-applier",
		"-v", "/var/run/docker.sock:/var/run/docker.sock",
		"-v", fmt.Sprintf("%s:%s", projectDir, projectDir),
		"-w", projectDir,
		"--entrypoint", "sh",
		helperImage,
		"-c", script,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func runtimeUpdateStatusPath() string {
	return firstNonEmpty(os.Getenv("RUNTIME_UPDATE_STATUS_PATH"), "configs/runtime-update-status.json")
}

func writeRuntimeUpdateStatus(status runtimeUpdateStatus) {
	if status.UpdatedAt == "" {
		status.UpdatedAt = time.Now().Format(time.RFC3339)
	}
	data, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(runtimeUpdateStatusPath(), append(data, '\n'), 0644)
}

func readRuntimeUpdateStatus() (runtimeUpdateStatus, error) {
	var status runtimeUpdateStatus
	data, err := os.ReadFile(runtimeUpdateStatusPath())
	if err != nil {
		return status, err
	}
	err = json.Unmarshal(data, &status)
	return status, err
}

func readDotEnv(path string) map[string]string {
	result := map[string]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		return result
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		result[strings.TrimSpace(parts[0])] = strings.Trim(strings.TrimSpace(parts[1]), `"`)
	}
	return result
}

func writeDotEnv(path string, env map[string]string, orderedKeys []string) error {
	var lines []string
	lines = append(lines, "# AlterHive runtime configuration")
	lines = append(lines, "# Changes are applied by the automatic Docker Compose restart.")
	written := map[string]bool{}
	for _, key := range orderedKeys {
		lines = append(lines, fmt.Sprintf("%s=%s", key, env[key]))
		written[key] = true
	}
	var extraKeys []string
	for key := range env {
		if !written[key] {
			extraKeys = append(extraKeys, key)
		}
	}
	sort.Strings(extraKeys)
	for _, key := range extraKeys {
		lines = append(lines, fmt.Sprintf("%s=%s", key, env[key]))
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0644)
}

func atoiOrDefault(value string, fallback int) int {
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return fallback
	}
	return parsed
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (s *Server) systemInfo(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"ok": true,
		"data": gin.H{
			"app_name":    "AlterHive",
			"app_version": "1.0.0",
			"api_prefix":  "/api/v1",
			"mode":        "honeypot",
		},
		"message": "ok",
	})
}

// Helper functions

func sessionToRow(sess *domain.SessionContext) gin.H {
	return gin.H{
		"session_id":        sess.SessionID,
		"username":          sess.Username,
		"remote_addr":       sess.RemoteAddr,
		"hostname":          sess.Hostname,
		"connected_at":      sess.ConnectedAt.Format(time.RFC3339),
		"last_activity":     sess.LastActivity.Format(time.RFC3339),
		"command_count":     len(sess.CommandLog),
		"evidence_hits":     sess.Evidence.HitCount(),
		"score":             sess.LoopMetrics.Score(),
		"ppf_triggered":     sess.PPFTriggered,
		"deception_profile": sess.DeceptionProfile,
		"status":            sessionStatus(sess),
	}
}

func sessionDetail(sess *domain.SessionContext, includeCommands bool) gin.H {
	result := gin.H{
		"session_id":        sess.SessionID,
		"username":          sess.Username,
		"remote_addr":       sess.RemoteAddr,
		"hostname":          sess.Hostname,
		"user":              sess.User,
		"cwd":               sess.CWD,
		"connected_at":      sess.ConnectedAt.Format(time.RFC3339),
		"command_count":     len(sess.CommandLog),
		"evidence_hits":     sess.Evidence.HitCount(),
		"evidence_tokens":   sess.Evidence.Tokens(),
		"score":             sess.LoopMetrics.Score(),
		"ppf_triggered":     sess.PPFTriggered,
		"deception_profile": sess.DeceptionProfile,
		"deception_scores":  sess.DeceptionScores,
		"active_branches":   sess.ActiveBranches,
		"last_strategy":     sess.LastStrategy,
		"hint_density":      sess.HintDensity,
		"shell_mode":        sess.ShellMode,
		"current_target":    sess.CurrentTarget,
		"current_host_ip":   sess.SubnetLocalIP,
		"ssh_stack":         sess.SSHStack,
		"loop_metrics": gin.H{
			"evidence_hit_count":       sess.LoopMetrics.EvidenceHitCount,
			"credential_reuse_attempt": sess.LoopMetrics.CredentialReuseAttempt,
			"protocol_switch_count":    sess.LoopMetrics.ProtocolSwitchCount,
			"real_network_touch_count": sess.LoopMetrics.RealNetworkTouchCount,
		},
		"shadow_hosts":  sess.ShadowHosts,
		"access_states": sess.AccessStateList(),
		"events":        sess.EventLog,
		"status":        sessionStatus(sess),
	}
	if includeCommands {
		result["commands"] = sess.CommandLog
	} else {
		result["commands"] = []domain.CommandEntry{}
	}
	return result
}

func topologyHostRow(host domain.VirtualHost) gin.H {
	services := make([]gin.H, 0, len(host.Services))
	for _, svc := range host.Services {
		services = append(services, gin.H{
			"port": svc.Port, "protocol": svc.Protocol, "state": "open",
		})
	}
	return gin.H{
		"ip": host.IP, "hostname": host.Hostname, "role": host.Role, "os": host.OS,
		"services": services, "segment_cidr": host.SegmentCIDR,
		"reachable_via": host.ReachableVia, "required_state": host.RequiredState,
		"shadow": host.Shadow, "theme": host.Theme, "compromise_mode": host.CompromiseMode,
		"status": nodeStatus(host), "password": host.Password,
	}
}

func paginationParams(c *gin.Context, defaultSize int) (int, int) {
	page, err := strconv.Atoi(c.DefaultQuery("page", "1"))
	if err != nil || page < 1 {
		page = 1
	}
	pageSize, err := strconv.Atoi(c.DefaultQuery("page_size", strconv.Itoa(defaultSize)))
	if err != nil || pageSize < 1 {
		pageSize = defaultSize
	}
	if pageSize > 100 {
		pageSize = 100
	}
	return page, pageSize
}

func nodeStatus(host domain.VirtualHost) string {
	if len(host.RequiredState) > 0 {
		return "locked"
	}
	return "active"
}

func sessionStatus(sess *domain.SessionContext) string {
	if sess.IsConnected() {
		return "active"
	}
	return "closed"
}

func countPPF(sessions []*domain.SessionContext) int {
	count := 0
	for _, s := range sessions {
		if s.PPFTriggered {
			count++
		}
	}
	return count
}

func topAttackers(sessions []*domain.SessionContext) []gin.H {
	counts := make(map[string]int)
	for _, s := range sessions {
		counts[extractIP(s.RemoteAddr)]++
	}
	var result []gin.H
	for ip, count := range counts {
		result = append(result, gin.H{"ip": ip, "sessions": count})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i]["sessions"].(int) > result[j]["sessions"].(int)
	})
	if len(result) > 5 {
		result = result[:5]
	}
	return result
}

func extractIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func recentSessions(sessions []*domain.SessionContext, limit int) []gin.H {
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].ConnectedAt.After(sessions[j].ConnectedAt)
	})
	var result []gin.H
	for i, s := range sessions {
		if i >= limit {
			break
		}
		result = append(result, gin.H{
			"session_id":   s.SessionID,
			"username":     s.Username,
			"remote_addr":  s.RemoteAddr,
			"connected_at": s.ConnectedAt.Format(time.RFC3339),
			"commands":     len(s.CommandLog),
		})
	}
	return result
}

// --- LLM Handlers ---

func (s *Server) llmProviders(c *gin.Context) {
	if s.llm == nil {
		c.JSON(http.StatusOK, gin.H{"ok": true, "data": []interface{}{}, "message": "LLM not configured"})
		return
	}
	cfg := s.llm.GetConfig()
	c.JSON(http.StatusOK, gin.H{
		"ok":      true,
		"data":    cfg.Providers,
		"message": "ok",
	})
}

func (s *Server) llmActive(c *gin.Context) {
	if s.llm == nil {
		c.JSON(http.StatusOK, gin.H{"ok": true, "data": nil, "message": "LLM not configured"})
		return
	}
	cfg := s.llm.GetConfig()
	c.JSON(http.StatusOK, gin.H{
		"ok": true,
		"data": gin.H{
			"active_provider": cfg.ActiveProvider,
			"enabled":         cfg.Enabled,
			"is_active":       s.llm.IsActive(),
			"providers":       cfg.Providers,
		},
		"message": "ok",
	})
}

func (s *Server) llmSwitch(c *gin.Context) {
	if s.llm == nil {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "message": "LLM not configured"})
		return
	}
	id := c.Param("id")
	if err := s.llm.SwitchProvider(id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "message": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "message": "Switched to " + id})
}

func (s *Server) llmSetEnabled(c *gin.Context) {
	if s.llm == nil {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "message": "LLM not configured"})
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "message": "Invalid request"})
		return
	}
	if err := s.llm.SetEnabled(body.Enabled); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "message": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "message": "LLM enabled updated"})
}

func (s *Server) llmUpdateProvider(c *gin.Context) {
	if s.llm == nil {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "message": "LLM not configured"})
		return
	}
	id := c.Param("id")
	var cfg llm.ProviderConfig
	if err := c.ShouldBindJSON(&cfg); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "message": "Invalid request"})
		return
	}
	cfg.ID = id

	// Preserve existing API key if the incoming value is empty or masked
	if strings.Contains(cfg.APIKey, "****") || cfg.APIKey == "" {
		if existing := s.llm.GetProviderReal(id); existing != nil && existing.APIKey != "" {
			cfg.APIKey = existing.APIKey
		}
	}

	if err := s.llm.UpdateProvider(cfg); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "message": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "message": "Provider updated"})
}

func (s *Server) llmTest(c *gin.Context) {
	if s.llm == nil {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "message": "LLM not configured"})
		return
	}
	id := c.Param("id")
	overrideBaseURL := c.Query("base_url")
	overrideAPIKey := c.Query("api_key")
	ctx := c.Request.Context()
	if err := s.llm.TestConnection(ctx, id, overrideBaseURL, overrideAPIKey); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"ok":      false,
			"message": err.Error(),
			"data":    gin.H{"provider": id, "status": "failed"},
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":      true,
		"message": "Connection successful",
		"data":    gin.H{"provider": id, "status": "ok"},
	})
}

func (s *Server) llmModels(c *gin.Context) {
	if s.llm == nil {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "message": "LLM not configured"})
		return
	}
	id := c.Param("id")
	overrideBaseURL := c.Query("base_url")
	overrideAPIKey := c.Query("api_key")
	ctx := c.Request.Context()
	models, err := s.llm.FetchModels(ctx, id, overrideBaseURL, overrideAPIKey)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"ok":      false,
			"message": err.Error(),
			"data":    []interface{}{},
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":      true,
		"data":    models,
		"message": "ok",
	})
}
