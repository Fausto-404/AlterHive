package deception

import (
	"strings"
	"time"

	"github.com/alterhive/alterhive/internal/domain"
)

const (
	legacyJump01FootholdState = "jump01_fake_foothold"

	GateReconObserved             = "gate_recon_observed"
	GateCredentialValidated       = "gate_credential_validated"
	GateJump01LowPrivShell        = "gate_jump01_lowpriv_shell"
	GateServiceAuthLimited        = "gate_service_auth_limited"
	GateExploitPartial            = "gate_exploit_partial"
	GateDataAccessLimited         = "gate_data_access_limited"
	GateC2DecoySession            = "gate_c2_decoy_session"
	GateTargetPartialReachability = "gate_target_partial_reachability"
	GateDC01Foothold              = "gate_dc01_foothold"
)

// Jump01FootholdState keeps compatibility with older configs and tests.
func Jump01FootholdState() string {
	return legacyJump01FootholdState
}

// PivotGateStates returns both the new pivot gate and the legacy alias.
func PivotGateStates() []string {
	return []string{GateJump01LowPrivShell}
}

// TargetGateStates represents the deeper gates needed before the target looks reachable.
func TargetGateStates() []string {
	return []string{GateJump01LowPrivShell, GateTargetPartialReachability}
}

// UnlockGate marks a gate as passed and records a session event. The legacy
// jump state is also unlocked when the new jump gate is reached.
func UnlockGate(session *domain.SessionContext, state, reason string) bool {
	if session == nil || state == "" || session.HasAccessState(state) {
		return false
	}
	session.UnlockAccessState(state)
	if state == GateJump01LowPrivShell {
		session.UnlockAccessState(legacyJump01FootholdState)
	}
	session.AppendEvent(domain.EventEntry{
		Type:      "gate_unlocked",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		SessionID: session.SessionID,
		Detail:    state + ":" + reason,
	})
	return true
}

// AdvanceGatesFromInteraction maps responder evidence and outputs into layered
// PPF gates. Each gate exposes only the next slice of the illusion.
func AdvanceGatesFromInteraction(session *domain.SessionContext, command, output string, hits []string) []string {
	if session == nil {
		return nil
	}
	lower := strings.ToLower(command + "\n" + output)
	hitSet := map[string]bool{}
	for _, hit := range hits {
		hitSet[hit] = true
	}
	var unlocked []string
	unlock := func(state, reason string) {
		if UnlockGate(session, state, reason) {
			unlocked = append(unlocked, state)
		}
	}

	if hitSet["subnet_scan"] || hitSet["service_enum"] {
		unlock(GateReconObserved, "recon_tool_or_scan")
	}
	if hitSet["credential_reuse_attempt"] || strings.Contains(lower, "db_password") || strings.Contains(lower, "token=") || strings.Contains(lower, "private key") {
		unlock(GateCredentialValidated, "credential_artifact_or_reuse")
	}
	if hitSet["jumpbox_foothold"] {
		unlock(GateJump01LowPrivShell, "jumpbox_partial_auth")
	}
	if hitSet["mysql_auth_success"] || strings.Contains(lower, "authenticated to") || strings.Contains(lower, "401 unauthorized") || strings.Contains(lower, "forbidden") {
		unlock(GateServiceAuthLimited, "limited_service_auth")
	}
	if hitSet["vuln_probe"] || strings.Contains(lower, "maybe vulnerable") || strings.Contains(lower, "appears to be vulnerable") {
		unlock(GateExploitPartial, "exploit_check_partial")
	}
	if hitSet["data_exfiltration"] || strings.Contains(lower, "available databases") || strings.Contains(lower, "dump") {
		unlock(GateDataAccessLimited, "limited_data_access")
	}
	if hitSet["c2_attempt"] || strings.Contains(lower, "command shell session") || strings.Contains(lower, "tense-pine") {
		unlock(GateC2DecoySession, "c2_decoy_session")
	}
	if hitSet["dc01_foothold"] {
		unlock(GateDC01Foothold, "dc01_auth_success")
	}
	if session.HasAccessState(GateJump01LowPrivShell) &&
		(session.HasAccessState(GateExploitPartial) || session.HasAccessState(GateDataAccessLimited) || session.HasAccessState(GateC2DecoySession)) {
		unlock(GateTargetPartialReachability, "pivot_plus_partial_progress")
	}
	return unlocked
}
