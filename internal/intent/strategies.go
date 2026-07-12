package intent

import (
	"github.com/alterhive/alterhive/internal/domain"
)

// ChainTemplate defines a shadow host template for topology expansion.
type ChainTemplate struct {
	IP           string
	Hostname     string
	Role         string
	OS           string
	Services     []domain.VirtualService
	VisibleAfter []string // evidence tokens required before this host is discoverable
}

// chainTemplates maps intent categories to shadow host templates.
var chainTemplates = map[string][]ChainTemplate{
	"db_probe": {
		{
			IP: "192.168.56.31", Hostname: "db-replica-01", Role: "db_shadow", OS: "CentOS 7",
			VisibleAfter: []string{"subnet_scan"},
			Services: []domain.VirtualService{
				{Port: 22, Protocol: "ssh", FailureMode: "auth_denied"},
				{Port: 3306, Protocol: "mysql", NmapName: "mysql", FailureMode: "auth_denied"},
				{Port: 6379, Protocol: "redis", NmapName: "redis", FailureMode: "refused"},
			},
		},
	},
	"http_probe": {
		{
			IP: "192.168.56.45", Hostname: "jenkins-internal", Role: "jenkins_shadow", OS: "Ubuntu 22.04",
			VisibleAfter: []string{"subnet_scan"},
			Services: []domain.VirtualService{
				{Port: 22, Protocol: "ssh", FailureMode: "auth_denied"},
				{Port: 8080, Protocol: "http-proxy", NmapName: "http-proxy", Banner: "Jetty", FailureMode: "redirect_login"},
				{Port: 50000, Protocol: "java-rmi", NmapName: "java-rmi", FailureMode: "refused"},
			},
		},
		{
			IP: "192.168.56.44", Hostname: "gitlab-ci", Role: "gitlab_shadow", OS: "Ubuntu 20.04",
			VisibleAfter: []string{"subnet_scan"},
			Services: []domain.VirtualService{
				{Port: 22, Protocol: "ssh", FailureMode: "auth_denied"},
				{Port: 443, Protocol: "https", NmapName: "ssl/http", Banner: "nginx", FailureMode: "redirect_login"},
			},
		},
	},
	"domain_probe": {
		{
			IP: "192.168.56.10", Hostname: "dc01", Role: "dc_shadow", OS: "Windows Server 2019",
			VisibleAfter: []string{"subnet_scan"},
			Services: []domain.VirtualService{
				{Port: 53, Protocol: "dns", NmapName: "domain", FailureMode: "refused"},
				{Port: 88, Protocol: "kerberos", NmapName: "kerberos-sec", FailureMode: "auth_required"},
				{Port: 135, Protocol: "msrpc", NmapName: "msrpc", FailureMode: "refused"},
				{Port: 389, Protocol: "ldap", NmapName: "ldap", FailureMode: "stronger_auth_required"},
				{Port: 445, Protocol: "smb", NmapName: "microsoft-ds", FailureMode: "access_denied"},
				{Port: 636, Protocol: "ldaps", NmapName: "ldapssl", FailureMode: "stronger_auth_required"},
			},
		},
	},
	"lateral_movement": {
		{
			IP: "192.168.56.53", Hostname: "k8s-master-01", Role: "k8s_shadow", OS: "Ubuntu 22.04",
			VisibleAfter: []string{"subnet_scan", "lateral_probe"},
			Services: []domain.VirtualService{
				{Port: 22, Protocol: "ssh", FailureMode: "auth_denied"},
				{Port: 6443, Protocol: "https", NmapName: "https", FailureMode: "auth_required"},
				{Port: 10250, Protocol: "https", NmapName: "https", FailureMode: "auth_required"},
				{Port: 2379, Protocol: "etcd", NmapName: "etcd-client", FailureMode: "refused"},
			},
		},
	},
}

// MaybeExpandTopology dynamically adds shadow hosts based on intent.
// Shadow hosts are only added to the topology when their VisibleAfter evidence is already met.
func MaybeExpandTopology(session *domain.SessionContext, topology *domain.VirtualTopology, intent Intent, maxShadowHosts int) []domain.VirtualHost {
	templates, ok := chainTemplates[string(intent.Category)]
	if !ok {
		return nil
	}

	var added []domain.VirtualHost
	for _, tmpl := range templates {
		// Skip if IP already in topology
		if topology.GetHost(tmpl.IP) != nil {
			continue
		}

		// Skip if role already exists as active in session
		roleExists := false
		for _, sh := range session.ShadowHosts {
			if sh["role"] == tmpl.Role && sh["status"] == "active" {
				roleExists = true
				break
			}
		}
		if roleExists {
			continue
		}

		// Only add to topology if all required evidence is already collected
		evidenceReady := len(tmpl.VisibleAfter) == 0
		for _, token := range tmpl.VisibleAfter {
			if session.Evidence.Has(token) {
				evidenceReady = true
				break
			}
		}

		if !evidenceReady {
			continue
		}

		if len(session.ShadowHosts) >= maxShadowHosts {
			break
		}

		host := domain.VirtualHost{
			IP:           tmpl.IP,
			Hostname:     tmpl.Hostname,
			Role:         tmpl.Role,
			OS:           tmpl.OS,
			Services:     tmpl.Services,
			VisibleAfter: tmpl.VisibleAfter,
			CanaryID:     domain.DeploySeed,
		}

		topology.AppendShadowHost(host)
		session.AddShadowHost(map[string]string{
			"ip":           host.IP,
			"hostname":     host.Hostname,
			"role":         host.Role,
			"triggered_by": string(intent.Category),
			"status":       "active",
		})
		added = append(added, host)
	}
	return added
}

// PromotePendingShadowHosts checks all chain templates and promotes hosts
// whose evidence requirements are now met. Called after evidence is collected.
func PromotePendingShadowHosts(session *domain.SessionContext, topology *domain.VirtualTopology, maxShadowHosts int) {
	for _, templates := range chainTemplates {
		for _, tmpl := range templates {
			if topology.GetHost(tmpl.IP) != nil {
				continue
			}

			// Check if role already active
			roleActive := false
			for _, sh := range session.ShadowHosts {
				if sh["role"] == tmpl.Role && sh["status"] == "active" {
					roleActive = true
					break
				}
			}
			if roleActive {
				continue
			}

			// Check if ALL required evidence tokens are met
			allEvidenceMet := true
			for _, token := range tmpl.VisibleAfter {
				if !session.Evidence.Has(token) {
					allEvidenceMet = false
					break
				}
			}
			if !allEvidenceMet {
				continue
			}

			if len(session.ShadowHosts) >= maxShadowHosts {
				return
			}

			host := domain.VirtualHost{
				IP:           tmpl.IP,
				Hostname:     tmpl.Hostname,
				Role:         tmpl.Role,
				OS:           tmpl.OS,
				Services:     tmpl.Services,
				VisibleAfter: tmpl.VisibleAfter,
				CanaryID:     domain.DeploySeed,
			}

			topology.AppendShadowHost(host)
			session.AddShadowHost(map[string]string{
				"ip":           host.IP,
				"hostname":     host.Hostname,
				"role":         host.Role,
				"triggered_by": "evidence_promotion",
				"status":       "active",
			})
		}
	}
}
