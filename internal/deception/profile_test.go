package deception

import (
	"testing"

	"github.com/alterhive/alterhive/internal/domain"
)

func TestBuildProfile_SecretHunter(t *testing.T) {
	commands := []domain.CommandEntry{
		{Command: "grep -Ri token /opt/webapp"},
		{Command: "cat /opt/webapp/.env"},
		{Command: "find / -name '*.key'"},
		{Command: "cat /etc/shadow"},
	}
	evidence := []string{"app_config", "pseudo_progress"}

	profile := BuildProfile(commands, evidence)

	if profile.PrimaryStyle != "secret_hunter" {
		t.Errorf("expected secret_hunter, got %s", profile.PrimaryStyle)
	}
	if profile.Scores["secret_hunter"] < 2 {
		t.Errorf("expected secret_hunter score >= 2, got %d", profile.Scores["secret_hunter"])
	}
}

func TestBuildProfile_NetworkMapper(t *testing.T) {
	commands := []domain.CommandEntry{
		{Command: "nmap -sn 192.168.56.0/24"},
		{Command: "fscan -h 192.168.56.0/24"},
		{Command: "nc -zv 192.168.56.50 22"},
		{Command: "ping 192.168.56.1"},
	}
	evidence := []string{"subnet_scan"}

	profile := BuildProfile(commands, evidence)

	if profile.PrimaryStyle != "network_mapper" {
		t.Errorf("expected network_mapper, got %s", profile.PrimaryStyle)
	}
}

func TestBuildProfile_CloudNative(t *testing.T) {
	commands := []domain.CommandEntry{
		{Command: "kubectl get pods"},
		{Command: "kubectl get secrets"},
		{Command: "docker ps"},
	}
	evidence := []string{"service_enum"}

	profile := BuildProfile(commands, evidence)

	if profile.PrimaryStyle != "cloud_native" {
		t.Errorf("expected cloud_native, got %s", profile.PrimaryStyle)
	}
}

func TestBuildProfile_DomainMapper(t *testing.T) {
	commands := []domain.CommandEntry{
		{Command: "ldapsearch -h 192.168.56.50 -b dc=corp,dc=local"},
		{Command: "smbclient -L //192.168.56.50"},
		{Command: "kinit admin@CORP.LOCAL"},
		{Command: "dig corp.local SOA"},
	}
	evidence := []string{"domain_probe"}

	profile := BuildProfile(commands, evidence)

	if profile.PrimaryStyle != "domain_mapper" {
		t.Errorf("expected domain_mapper, got %s", profile.PrimaryStyle)
	}
}

func TestBuildProfile_CredentialReuse(t *testing.T) {
	commands := []domain.CommandEntry{
		{Command: "mysql -h 192.168.56.60 -u web_ro -p"},
		{Command: "ssh root@192.168.56.50"},
		{Command: "redis-cli -h 192.168.56.30 -a test123"},
	}
	evidence := []string{"db_probe", "lateral_probe"}

	profile := BuildProfile(commands, evidence)

	if profile.PrimaryStyle != "credential_reuse" && profile.PrimaryStyle != "lateral_mover" {
		t.Errorf("expected credential_reuse or lateral_mover, got %s", profile.PrimaryStyle)
	}
}

func TestBuildProfile_GeneralRecon(t *testing.T) {
	commands := []domain.CommandEntry{
		{Command: "whoami"},
		{Command: "id"},
		{Command: "hostname"},
	}
	evidence := []string{}

	profile := BuildProfile(commands, evidence)

	if profile.PrimaryStyle != "general_recon" {
		t.Errorf("expected general_recon, got %s", profile.PrimaryStyle)
	}
}

func TestSelectStrategy_SecretHunter(t *testing.T) {
	profile := AgentProfile{PrimaryStyle: "secret_hunter", Scores: map[string]int{"secret_hunter": 5}}
	session := &domain.SessionContext{PPFTriggered: false}

	decision := SelectStrategy(profile, session)

	if decision.Name != "breadcrumb_trail" {
		t.Errorf("expected breadcrumb_trail, got %s", decision.Name)
	}
	if decision.HintDensity != "high" {
		t.Errorf("expected high hint density, got %s", decision.HintDensity)
	}
	if len(decision.PreferredBait) == 0 {
		t.Error("expected non-empty preferred bait")
	}
}

func TestSelectStrategy_NetworkMapper(t *testing.T) {
	profile := AgentProfile{PrimaryStyle: "network_mapper", Scores: map[string]int{"network_mapper": 4}}
	session := &domain.SessionContext{PPFTriggered: false}

	decision := SelectStrategy(profile, session)

	if decision.Name != "expanding_topology" {
		t.Errorf("expected expanding_topology, got %s", decision.Name)
	}
	if decision.HintDensity != "medium" {
		t.Errorf("expected medium hint density, got %s", decision.HintDensity)
	}
}

func TestSelectStrategy_PPFBoostsDensity(t *testing.T) {
	profile := AgentProfile{PrimaryStyle: "network_mapper", Scores: map[string]int{"network_mapper": 4}}
	session := &domain.SessionContext{PPFTriggered: true}

	decision := SelectStrategy(profile, session)

	if decision.HintDensity != "high" {
		t.Errorf("expected high hint density after PPF, got %s", decision.HintDensity)
	}
}

func TestSelectStrategy_GeneralRecon(t *testing.T) {
	profile := AgentProfile{PrimaryStyle: "general_recon", Scores: map[string]int{}}
	session := &domain.SessionContext{PPFTriggered: false}

	decision := SelectStrategy(profile, session)

	if decision.Name != "passive_observation" {
		t.Errorf("expected passive_observation, got %s", decision.Name)
	}
	if decision.HintDensity != "low" {
		t.Errorf("expected low hint density, got %s", decision.HintDensity)
	}
}
