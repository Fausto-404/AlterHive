package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/alterhive/alterhive/internal/deception"
	"github.com/alterhive/alterhive/internal/domain"

	"github.com/gin-gonic/gin"
)

// --- Request/Response types ---

type SimNmapRequest struct {
	Target    string `json:"target" binding:"required"` // "192.168.56.0/24" or "192.168.56.60"
	SessionID string `json:"session_id"`
}

type SimFscanRequest struct {
	Target    string `json:"target" binding:"required"` // "192.168.56.0/24" or "192.168.56.60"
	SessionID string `json:"session_id"`
}

type SimCurlRequest struct {
	URL       string `json:"url" binding:"required"` // "http://192.168.56.80"
	SessionID string `json:"session_id"`
	Headers   bool   `json:"headers_only"`
}

type SimSSHRequest struct {
	Target    string `json:"target" binding:"required"` // "192.168.56.60"
	User      string `json:"user"`
	Command   string `json:"command"` // optional inline command
	SessionID string `json:"session_id"`
}

type SimNCRequest struct {
	Target    string `json:"target" binding:"required"`
	Port      int    `json:"port" binding:"required"`
	SessionID string `json:"session_id"`
}

type SimPingRequest struct {
	Target    string `json:"target" binding:"required"`
	SessionID string `json:"session_id"`
}

type SimGoalRequest struct {
	Target    string `json:"target" binding:"required"` // IP or CIDR, e.g. "172.16.56.50"
	SessionID string `json:"session_id"`
}

type SimResponse struct {
	OK               bool           `json:"ok"`
	SessionID        string         `json:"session_id,omitempty"`
	Output           string         `json:"output"`
	EvidenceHits     []string       `json:"evidence_hits,omitempty"`
	Score            int            `json:"score,omitempty"`
	DeceptionProfile string         `json:"deception_profile,omitempty"`
	DeceptionScores  map[string]int `json:"deception_scores,omitempty"`
	ActiveBranches   []string       `json:"active_branches,omitempty"`
	LastStrategy     string         `json:"last_strategy,omitempty"`
	HintDensity      string         `json:"hint_density,omitempty"`
	Message          string         `json:"message"`
}

// --- Handlers ---

// applySimEvidence consolidates post-command state updates for simulation endpoints.
// dispatchSim runs a command through the full Manager.ExecuteCommand lifecycle
// (evidence discovery, intent analysis, topology planning, RuleEngine with
// LLM-first routing for complex commands, dead-end detection, frustration
// analysis, command/event logging, and deception profile update).
// This replaces the old applySimEvidence + direct responder calls so the
// simulation API gets the exact same treatment as interactive SSH traffic.
func (s *Server) dispatchSim(session *domain.SessionContext, cmd string) string {
	s.manager.PlanTopology(session, cmd)
	output := s.manager.DispatchCommand(session.SessionID, cmd)
	return output
}

// buildSimResponse creates a SimResponse with deception fields.
func buildSimResponse(session *domain.SessionContext, output string, evidenceHits []string) SimResponse {
	return SimResponse{
		OK:               true,
		Output:           output,
		EvidenceHits:     evidenceHits,
		Score:            session.LoopMetrics.Score(),
		DeceptionProfile: session.DeceptionProfile,
		DeceptionScores:  session.DeceptionScores,
		ActiveBranches:   session.ActiveBranches,
		LastStrategy:     session.LastStrategy,
		HintDensity:      session.HintDensity,
		Message:          "ok",
		SessionID:        session.SessionID,
	}
}

func (s *Server) renderSimOutput(session *domain.SessionContext, cmd, output string) string {
	rendered := deception.RenderApprovedResponse(cmd, output, session, s.manager.TopologyRef())
	return rendered.Output
}

func (s *Server) simNmap(c *gin.Context) {
	var req SimNmapRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, SimResponse{OK: false, Message: "target required"})
		return
	}

	session := s.getOrCreateSimSession(req.SessionID)
	cmd := "nmap " + req.Target
	output := s.dispatchSim(session, cmd)
	c.JSON(http.StatusOK, buildSimResponse(session, output, session.Evidence.Tokens()))
}

func (s *Server) simFscan(c *gin.Context) {
	var req SimFscanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, SimResponse{OK: false, Message: "target required"})
		return
	}

	session := s.getOrCreateSimSession(req.SessionID)
	cmd := "fscan -h " + req.Target
	output := s.dispatchSim(session, cmd)
	c.JSON(http.StatusOK, buildSimResponse(session, output, session.Evidence.Tokens()))
}

func (s *Server) simCurl(c *gin.Context) {
	var req SimCurlRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, SimResponse{OK: false, Message: "url required"})
		return
	}

	session := s.getOrCreateSimSession(req.SessionID)
	cmd := "curl " + req.URL
	if req.Headers {
		cmd = "curl -I " + req.URL
	}
	output := s.dispatchSim(session, cmd)
	c.JSON(http.StatusOK, buildSimResponse(session, output, session.Evidence.Tokens()))
}

func (s *Server) simSSH(c *gin.Context) {
	var req SimSSHRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, SimResponse{OK: false, Message: "target required"})
		return
	}

	session := s.getOrCreateSimSession(req.SessionID)
	user := req.User
	if user == "" {
		user = "root"
	}

	cmd := "ssh " + user + "@" + req.Target
	if req.Command != "" {
		cmd += " " + req.Command
	}

	// Run the ssh command, then auto-complete the password prompt if the
	// target host has a known password in the topology. This lets the
	// simulation API return a usable lateral-movement result in one call.
	output := s.dispatchSim(session, cmd)
	if extra := s.manager.ResolveAutoSSH(session.SessionID); extra != "" {
		output += extra
	}
	c.JSON(http.StatusOK, buildSimResponse(session, output, session.Evidence.Tokens()))
}

func (s *Server) simNC(c *gin.Context) {
	var req SimNCRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, SimResponse{OK: false, Message: "target and port required"})
		return
	}

	session := s.getOrCreateSimSession(req.SessionID)
	cmd := "nc -zv " + req.Target + " " + itoa(req.Port)
	output := s.dispatchSim(session, cmd)
	c.JSON(http.StatusOK, buildSimResponse(session, output, session.Evidence.Tokens()))
}

func (s *Server) simPing(c *gin.Context) {
	var req SimPingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, SimResponse{OK: false, Message: "target required"})
		return
	}

	session := s.getOrCreateSimSession(req.SessionID)
	cmd := "ping " + req.Target
	output := s.dispatchSim(session, cmd)
	c.JSON(http.StatusOK, buildSimResponse(session, output, session.Evidence.Tokens()))
}

// simGoal injects a goal target into the topology so the agent can reach it.
func (s *Server) simGoal(c *gin.Context) {
	var req SimGoalRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, SimResponse{OK: false, Message: "target required"})
		return
	}

	session := s.getOrCreateSimSession(req.SessionID)

	goal := deception.ParseGoal(req.Target)
	if goal == nil {
		c.JSON(http.StatusBadRequest, SimResponse{OK: false, Message: "No private IP/CIDR found in target"})
		return
	}

	injected := deception.InjectGoalTopology(session, s.manager.TopologyRef(), s.manager.SafetyRef(), goal)
	if injected {
		session.AppendEvent(domain.EventEntry{
			Type:      "goal_injected",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			SessionID: session.SessionID,
			Detail:    fmt.Sprintf("Goal injected via API: %s → %s", goal.Raw, goal.CIDR),
		})
	} else {
		session.AppendEvent(domain.EventEntry{
			Type:      "goal_observed",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			SessionID: session.SessionID,
			Detail:    fmt.Sprintf("Goal observed via API: %s → %s", goal.Raw, goal.CIDR),
		})
	}
	s.manager.PlanTopology(session, req.Target)

	c.JSON(http.StatusOK, gin.H{
		"ok": true,
		"data": gin.H{
			"target":     goal.TargetIP,
			"cidr":       goal.CIDR,
			"theme":      goal.Theme,
			"injected":   injected,
			"session_id": session.SessionID,
			"topology": gin.H{
				"segments": s.manager.TopologyRef().AllSegments(),
				"edges":    s.manager.TopologyRef().AllEdges(),
				"hosts":    s.manager.TopologyRef().AllHosts(),
			},
		},
		"message": "ok",
	})
}

// simSessionStatus returns the current state of a simulation session.
func (s *Server) simSessionStatus(c *gin.Context) {
	sessionID := c.Param("id")
	sess := s.manager.GetSession(sessionID)
	if sess == nil {
		c.JSON(http.StatusNotFound, gin.H{"ok": false, "message": "Session not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"ok": true,
		"data": gin.H{
			"session_id":     sess.SessionID,
			"evidence_hits":  sess.Evidence.Tokens(),
			"evidence_count": sess.Evidence.HitCount(),
			"score":          sess.LoopMetrics.Score(),
			"ppf_triggered":  sess.PPFTriggered,
			"shadow_hosts":   sess.ShadowHosts,
			"access_states":  sess.AccessStateList(),
			"planning":       sess.Planning,
			"event_log":      sess.EventLog,
			"topology": gin.H{
				"segments": s.manager.TopologyRef().AllSegments(),
				"edges":    s.manager.TopologyRef().AllEdges(),
				"hosts":    s.manager.TopologyRef().AllHosts(),
			},
			"protocols_seen":    sess.LoopMetrics.ProtocolSwitchCount,
			"deception_profile": sess.DeceptionProfile,
			"deception_scores":  sess.DeceptionScores,
			"active_branches":   sess.ActiveBranches,
			"last_strategy":     sess.LastStrategy,
			"hint_density":      sess.HintDensity,
			"loop_metrics": gin.H{
				"evidence_hit_count":       sess.LoopMetrics.EvidenceHitCount,
				"credential_reuse_attempt": sess.LoopMetrics.CredentialReuseAttempt,
				"protocol_switch_count":    sess.LoopMetrics.ProtocolSwitchCount,
				"real_network_touch_count": sess.LoopMetrics.RealNetworkTouchCount,
			},
		},
		"message": "ok",
	})
}

// --- Helpers ---

func (s *Server) getOrCreateSimSession(sessionID string) *domain.SessionContext {
	if sessionID != "" {
		if sess := s.manager.GetSession(sessionID); sess != nil {
			return sess
		}
	}
	// Create a new simulation session (not tied to SSH)
	return s.manager.CreateSession("sim-agent", "127.0.0.1:0")
}

func (s *Server) expandSimTopology(session *domain.SessionContext, cmd string) {
	s.manager.PlanTopology(session, cmd)
}

func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}
