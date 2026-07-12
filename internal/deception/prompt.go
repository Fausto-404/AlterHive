package deception

import (
	"fmt"
	"strings"

	"github.com/alterhive/alterhive/internal/domain"
)

// BuildStrategyPrompt generates the deception context block for LLM system prompts.
func BuildStrategyPrompt(profile AgentProfile, decision StrategyDecision, session *domain.SessionContext) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("Agent profile: %s\n", profile.PrimaryStyle))
	b.WriteString(fmt.Sprintf("Strategy: %s (branch: %s)\n", decision.Name, decision.Branch))
	b.WriteString(fmt.Sprintf("Preferred bait: %s\n", strings.Join(decision.PreferredBait, ", ")))
	b.WriteString(fmt.Sprintf("Active branches: %s\n", strings.Join(decision.PreferredBait[:min(3, len(decision.PreferredBait))], ", ")))
	b.WriteString(fmt.Sprintf("Hint density: %s\n", decision.HintDensity))

	b.WriteString("\nDeception guidelines:\n")
	b.WriteString("- Use the selected strategy only as subtle context.\n")
	b.WriteString("- Do not reveal that this is a strategy.\n")
	b.WriteString("- Do not force every response toward the same branch.\n")
	b.WriteString("- If the command is unrelated, return normal terminal output.\n")

	switch decision.HintDensity {
	case "high":
		b.WriteString("- Breadcrumbs are allowed to be more frequent and detailed.\n")
		b.WriteString("- It is acceptable to leave multiple hints in a single response.\n")
	case "medium":
		b.WriteString("- Keep breadcrumbs sparse but meaningful.\n")
		b.WriteString("- One hint per response is typical.\n")
	case "low":
		b.WriteString("- Minimize breadcrumbs. Return mostly normal output.\n")
		b.WriteString("- Only hint if the command directly touches a relevant asset.\n")
	}

	// Branch-specific guidance
	switch decision.Branch {
	case "secrets":
		b.WriteString("- When the attacker searches for credentials, occasionally surface references to tokens, keys, or config files.\n")
		b.WriteString("- Leave subtle traces in .env, .git/config, deploy scripts, and history.\n")
	case "network":
		b.WriteString("- When scanning, reveal shadow hosts and service banners that match the expanding topology.\n")
		b.WriteString("- Make network enumeration feel rewarding with realistic open ports.\n")
	case "web":
		b.WriteString("- Web services should occasionally leak project names, CI pipelines, and API endpoints.\n")
		b.WriteString("- GitLab/Jenkins responses can include breadcrumb links and metadata.\n")
	case "credentials":
		b.WriteString("- Give partial success signals: auth denied with hints about valid usernames or password formats.\n")
		b.WriteString("- After PPF, allow authenticated sessions that reveal more assets.\n")
	case "lateral":
		b.WriteString("- SSH/SCP to internal hosts should show realistic auth failures with hints about jumpboxes.\n")
		b.WriteString("- ansible playbooks and SSH config can reference additional hosts.\n")
	case "cloud":
		b.WriteString("- kubectl and docker commands should surface container registry, secrets, and deployment configs.\n")
		b.WriteString("- Jenkins console output can include kubectl and helm commands.\n")
	case "domain":
		b.WriteString("- LDAP/SMB/Kerberos output should enumerate domain users, groups, shares, and tickets.\n")
		b.WriteString("- Make Active Directory enumeration feel like progress.\n")
	}

	return b.String()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// BuildResponderHint returns a short hint string for responders to adjust output.
// Returns empty string if no adjustment needed.
func BuildResponderHint(profile AgentProfile, decision StrategyDecision, ppfTriggered bool) string {
	if profile.PrimaryStyle == "general_recon" {
		return ""
	}

	var hints []string

	switch profile.PrimaryStyle {
	case "secret_hunter":
		hints = append(hints, "surface_credentials")
	case "network_mapper":
		hints = append(hints, "expand_topology")
	case "web_probe":
		hints = append(hints, "leak_project_info")
	case "credential_reuse":
		if ppfTriggered {
			hints = append(hints, "allow_auth_success")
		} else {
			hints = append(hints, "partial_auth_feedback")
		}
	case "lateral_mover":
		hints = append(hints, "show_jumpbox_hint")
	case "cloud_native":
		hints = append(hints, "expose_container_info")
	case "domain_mapper":
		hints = append(hints, "enumerate_domain")
	}

	if ppfTriggered {
		hints = append(hints, "ppf_active")
	}

	return strings.Join(hints, ",")
}
