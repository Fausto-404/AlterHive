package deception

import "github.com/alterhive/alterhive/internal/domain"

// StrategyDecision represents the deception strategy selected for a session.
type StrategyDecision struct {
	Name          string   `json:"name"`
	Branch        string   `json:"branch"`
	HintDensity   string   `json:"hint_density"` // low, medium, high
	PreferredBait []string `json:"preferred_bait"`
	SuppressBait  []string `json:"suppress_bait"`
}

var strategyMap = map[string]StrategyDecision{
	"secret_hunter": {
		Name:        "breadcrumb_trail",
		Branch:      "secrets",
		HintDensity: "high",
		PreferredBait: []string{
			"gitlab_token", "jenkins_token", "kubeconfig",
			"ssh_key_reference", "deploy_script_env",
		},
		SuppressBait: []string{"shadow_hosts", "service_banner"},
	},
	"network_mapper": {
		Name:        "expanding_topology",
		Branch:      "network",
		HintDensity: "medium",
		PreferredBait: []string{
			"shadow_hosts", "service_banner", "jenkins",
			"dc", "redis", "k8s_api",
		},
		SuppressBait: []string{"gitlab_token", "ssh_key_reference"},
	},
	"web_probe": {
		Name:        "app_surface",
		Branch:      "web",
		HintDensity: "medium",
		PreferredBait: []string{
			"gitlab_project", "jenkins_console", "internal_api",
			"webapp_source", "ci_pipeline",
		},
		SuppressBait: []string{"shadow_hosts"},
	},
	"credential_reuse": {
		Name:        "auth_ladder",
		Branch:      "credentials",
		HintDensity: "high",
		PreferredBait: []string{
			"mysql_partial_success", "redis_auth_required",
			"ssh_auth_denied_then_ppf", "svc_account_hint",
		},
		SuppressBait: []string{},
	},
	"lateral_mover": {
		Name:        "pivot_chain",
		Branch:      "lateral",
		HintDensity: "medium",
		PreferredBait: []string{
			"jumpbox", "ansible", "k8s_master",
			"ssh_config_hosts", "scp_artifact",
		},
		SuppressBait: []string{},
	},
	"cloud_native": {
		Name:        "container_escape",
		Branch:      "cloud",
		HintDensity: "high",
		PreferredBait: []string{
			"kubeconfig", "jenkins_kubectl_console",
			"registry_secret", "helm_values",
		},
		SuppressBait: []string{"gitlab_token"},
	},
	"domain_mapper": {
		Name:        "ad_enumeration",
		Branch:      "domain",
		HintDensity: "medium",
		PreferredBait: []string{
			"dc01", "ldap_users", "smb_shares",
			"kerberos_ticket", "gpo_hint",
		},
		SuppressBait: []string{},
	},
}

// SelectStrategy picks a deception strategy based on the agent profile.
func SelectStrategy(profile AgentProfile, session *domain.SessionContext) StrategyDecision {
	decision, ok := strategyMap[profile.PrimaryStyle]
	if !ok {
		// general_recon or unknown — use a balanced default
		return StrategyDecision{
			Name:        "passive_observation",
			Branch:      "general",
			HintDensity: "low",
			PreferredBait: []string{
				"service_banner", "env_file_read",
			},
			SuppressBait: []string{},
		}
	}

	// If PPF is triggered, boost hint density
	if session.PPFTriggered && decision.HintDensity != "high" {
		decision.HintDensity = "high"
	}

	return decision
}
