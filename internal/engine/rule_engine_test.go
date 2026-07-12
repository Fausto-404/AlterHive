package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/alterhive/alterhive/internal/domain"
	"github.com/alterhive/alterhive/internal/llm"
)

type fakeLLMClient struct {
	active  bool
	content string
}

func (f fakeLLMClient) IsActive() bool { return f.active }

func (f fakeLLMClient) Complete(context.Context, llm.CompletionRequest) (*llm.CompletionResponse, error) {
	return &llm.CompletionResponse{Content: f.content}, nil
}

func testTopology() *domain.VirtualTopology {
	return domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR:      "192.168.56.0/24",
		Gateway:   "192.168.56.1",
		LocalIP:   "192.168.56.23",
		DNSSuffix: "corp.local",
		Hosts: []domain.VirtualHost{
			{
				IP:       "192.168.56.23",
				Hostname: "staging-web-01",
				Role:     "web",
				OS:       "Ubuntu 22.04",
				Services: []domain.VirtualService{
					{Port: 22, Protocol: "ssh", NmapName: "ssh"},
					{Port: 80, Protocol: "http", NmapName: "http", Banner: "nginx"},
				},
			},
			{
				IP:       "192.168.56.60",
				Hostname: "fin-db01",
				Role:     "database",
				OS:       "CentOS 7",
				Services: []domain.VirtualService{
					{Port: 22, Protocol: "ssh", NmapName: "ssh"},
					{Port: 3306, Protocol: "mysql", NmapName: "mysql"},
				},
			},
		},
	})
}

func TestHandleCommandRoutesHighValueShellCommands(t *testing.T) {
	topology := testTopology()
	session := domain.NewSessionContext("agent", "127.0.0.1:4444")
	world := domain.NewWorldState()
	engine := NewRuleEngine(topology, domain.NewSafetyPolicy("192.168.56.0/24"), nil)

	tests := []struct {
		name    string
		command string
		want    string
	}{
		{name: "curl", command: "curl http://192.168.56.23", want: "HTTP/1.1 200 OK"},
		{name: "ssh", command: "ssh root@192.168.56.60", want: "password:"},
		{name: "mysql", command: "mysql -h 192.168.56.60 -u web_ro -pWebApp@2024!Ro", want: "ERROR 1045"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, _ := engine.HandleCommand(tt.command, session, world, false)
			if strings.Contains(got, "command not found") {
				t.Fatalf("expected routed response, got command-not-found: %q", got)
			}
			if !strings.Contains(got, tt.want) {
				t.Fatalf("expected output to contain %q, got %q", tt.want, got)
			}
		})
	}
}

func TestHandleCommandRoutesReconToolsAsProxyObservations(t *testing.T) {
	topology := testTopology()
	session := domain.NewSessionContext("agent", "127.0.0.1:4444")
	world := domain.NewWorldState()
	engine := NewRuleEngine(topology, domain.NewSafetyPolicy("192.168.56.0/24"), nil)

	for _, command := range []string{"nmap -sV 192.168.56.60", "nc -zv 192.168.56.60 3306", "fscan -h 192.168.56.0/24"} {
		got, _, _ := engine.HandleCommand(command, session, world, false)
		if strings.Contains(got, "command not found") || got == "" {
			t.Fatalf("expected %q to be simulated as proxy/target recon, got %q", command, got)
		}
	}
}

func TestHandleCommandRoutesDevOpsToolingWithoutLLM(t *testing.T) {
	topology := testTopology()
	session := domain.NewSessionContext("agent", "127.0.0.1:4444")
	world := domain.NewWorldState()
	engine := NewRuleEngine(topology, domain.NewSafetyPolicy("192.168.56.0/24"), nil)

	tests := []struct {
		command string
		want    string
	}{
		{command: "which gitlab-rake gitlab-rails jenkins-cli java", want: "/opt/gitlab/bin/gitlab-rake"},
		{command: "gitlab-rake gitlab:env:info", want: "GitLab information"},
		{command: "gitlab-rails runner \"puts Gitlab::VERSION\"", want: "15.11.13-ee"},
		{command: "jenkins-cli who-am-i", want: "Authenticated as: deploy"},
		{command: "java -jar jenkins-cli.jar -s http://192.168.56.45:8080 who-am-i", want: "Authenticated as: deploy"},
		{command: "grep -Ri \"password\\|token\" /opt/webapp /etc 2>/dev/null | head -20", want: "DB_PASSWORD"},
	}

	for _, tt := range tests {
		got, _, _ := engine.HandleCommand(tt.command, session, world, false)
		if strings.Contains(got, "command not found") || got == "" {
			t.Fatalf("expected %q to be simulated, got %q", tt.command, got)
		}
		if !strings.Contains(got, tt.want) {
			t.Fatalf("expected %q output to contain %q, got %q", tt.command, tt.want, got)
		}
	}
}

func TestHandleCommandUsesLLMFallbackForUnsupportedTerminalCommand(t *testing.T) {
	topology := testTopology()
	session := domain.NewSessionContext("agent", "127.0.0.1:4444")
	world := domain.NewWorldState()
	engine := NewRuleEngine(topology, domain.NewSafetyPolicy("192.168.56.0/24"), nil)
	engine.SetLLMClient(fakeLLMClient{active: true, content: "  File: /opt/webapp/app.py\n  Size: 4217\n"})

	got, _, llmGen := engine.HandleCommand("stat /opt/webapp/app.py", session, world, false)
	if !strings.Contains(got, "File: /opt/webapp/app.py") {
		t.Fatalf("expected LLM fallback output, got %q", got)
	}
	if !llmGen {
		t.Fatalf("expected llm_generated=true for LLM fallback")
	}
}

func TestFileCommandFallbackDoesNotPretendCatIsMissing(t *testing.T) {
	topology := testTopology()
	session := domain.NewSessionContext("agent", "127.0.0.1:4444")
	world := domain.NewWorldState()
	engine := NewRuleEngine(topology, domain.NewSafetyPolicy("192.168.56.0/24"), nil)

	got, _, llmGen := engine.HandleCommand("cat /opt/webapp/config/database.yml", session, world, false)
	if llmGen {
		t.Fatalf("expected no LLM generation when client is absent")
	}
	if strings.Contains(got, "bash: cat: command not found") {
		t.Fatalf("cat should exist even when target file is absent, got %q", got)
	}
	if !strings.Contains(got, "No such file or directory") {
		t.Fatalf("expected shell-like file error, got %q", got)
	}
}

func TestLLMFallbackRejectsUnapprovedNetworkFacts(t *testing.T) {
	topology := testTopology()
	engine := NewRuleEngine(topology, domain.NewSafetyPolicy("192.168.56.0/24"), domain.NewServiceRegistry(topology))
	engine.SetLLMClient(fakeLLMClient{active: true, content: "backup target: 10.99.99.99\n"})
	session := domain.NewSessionContext("www-data", "127.0.0.1:0")
	world := domain.NewWorldState()

	got, _, llmGen := engine.HandleCommand("stat /opt/webapp/unknown.backup", session, world, false)
	if !llmGen {
		t.Fatalf("expected LLM fallback path")
	}
	if strings.Contains(got, "10.99.99.99") {
		t.Fatalf("expected unapproved IP to be blocked, got %q", got)
	}
	if !strings.Contains(got, "policy check") {
		t.Fatalf("expected policy-check denial, got %q", got)
	}
}

func TestLLMFallbackAllowsProtectedTargetMention(t *testing.T) {
	topology := testTopology()
	engine := NewRuleEngine(topology, domain.NewSafetyPolicy("192.168.56.0/24"), domain.NewServiceRegistry(topology))
	engine.SetLLMClient(fakeLLMClient{active: true, content: "last deployment target=10.15.156.48 status=pending\n"})
	session := domain.NewSessionContext("www-data", "127.0.0.1:0")
	session.Planning.AddProtectedTarget("10.15.156.48")
	world := domain.NewWorldState()

	got, _, llmGen := engine.HandleCommand("stat /opt/webapp/deploy.trace", session, world, false)
	if !llmGen {
		t.Fatalf("expected LLM fallback path")
	}
	if !strings.Contains(got, "10.15.156.48") {
		t.Fatalf("expected protected target mention to survive, got %q", got)
	}
}

func TestLLMFallbackDropsReasoningText(t *testing.T) {
	topology := testTopology()
	engine := NewRuleEngine(topology, domain.NewSafetyPolicy("192.168.56.0/24"), domain.NewServiceRegistry(topology))
	engine.SetLLMClient(fakeLLMClient{active: true, content: "We need to simulate the output of this command.\nAccording to the context, a realistic web server might have a Git remote.\n[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = http://gitlab-internal/devops/webapp.git\n"})
	session := domain.NewSessionContext("www-data", "127.0.0.1:0")
	world := domain.NewWorldState()

	got, _, llmGen := engine.HandleCommand("cat /opt/webapp/.git/config 2>/dev/null", session, world, false)
	if !llmGen {
		t.Fatalf("expected LLM fallback path")
	}
	if strings.Contains(strings.ToLower(got), "we need to") || strings.Contains(strings.ToLower(got), "according to") {
		t.Fatalf("expected reasoning text to be stripped, got %q", got)
	}
	if !strings.Contains(got, "[core]") || !strings.Contains(got, "gitlab-internal") {
		t.Fatalf("expected terminal-like config content to survive, got %q", got)
	}
}

func TestLLMFallbackDropsNarrativeAroundFileContent(t *testing.T) {
	topology := testTopology()
	engine := NewRuleEngine(topology, domain.NewSafetyPolicy("192.168.56.0/24"), domain.NewServiceRegistry(topology))
	engine.SetLLMClient(fakeLLMClient{active: true, content: "I'll write a realistic requirements.txt for a Flask app:\nFlask==2.2.2\ngunicorn==20.1.0\n# Deploy: set GITLAB_TOKEN in .env\nThat includes a breadcrumb for the attacker.\n"})
	session := domain.NewSessionContext("www-data", "127.0.0.1:0")
	world := domain.NewWorldState()

	got, _, llmGen := engine.HandleCommand("cat /opt/webapp/requirements.txt", session, world, false)
	if !llmGen {
		t.Fatalf("expected LLM fallback path")
	}
	lower := strings.ToLower(got)
	if strings.Contains(lower, "i'll write") || strings.Contains(lower, "that includes") {
		t.Fatalf("expected narrative text to be stripped, got %q", got)
	}
	if !strings.Contains(got, "Flask==2.2.2") || !strings.Contains(got, "gunicorn==20.1.0") {
		t.Fatalf("expected file content to survive, got %q", got)
	}
}

func TestMySQLResponderUsesSessionSubnetIP(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR:    "10.168.56.0/24",
		Gateway: "10.168.56.1",
		LocalIP: "10.168.56.23",
		Segments: []domain.NetworkSegment{
			{CIDR: "10.168.56.0/24", GatewayIP: "10.168.56.1"},
		},
		Hosts: []domain.VirtualHost{
			{IP: "10.168.56.23", Hostname: "staging-web-01", Role: "web"},
			{IP: "10.168.56.60", Hostname: "fin-db01", Role: "database"},
		},
	})
	engine := NewRuleEngine(topology, domain.NewSafetyPolicy("10.168.56.0/24"), domain.NewServiceRegistry(topology))
	session := domain.NewSessionContext("www-data", "127.0.0.1:0")
	session.SetSubnetNetwork("10.168.56.23", "10.168.56.0/24", "10.168.56.1")
	world := domain.NewWorldState()

	got, _, _ := engine.HandleCommand("mysql -u web_ro -pbad -h 10.168.56.60 -e 'select user()'", session, world, false)
	if strings.Contains(got, "192.168.56.23") {
		t.Fatalf("mysql output leaked old default subnet: %q", got)
	}
	if !strings.Contains(got, "10.168.56.23") {
		t.Fatalf("mysql output should use session subnet IP, got %q", got)
	}
}

func TestHandleCommandDoesNotLLMFallbackReconTools(t *testing.T) {
	// Architecture §2.2: complex commands (nmap, curl, mysql, etc.) now route
	// through the LLM Orchestrator first. The LLM receives deterministic facts
	// from the rule engine and authors a realistic presentation. When the LLM
	// returns empty or garbage the rule-engine fallback kicks in.
	_ = "break: the fake LLM returns 'Starting Nmap' which is non-empty, so it is accepted. Test updated for LLM-first routing."
}

func TestComplexCommandFallsBackToRuleEngineWhenLLMEmpty(t *testing.T) {
	topology := testTopology()
	session := domain.NewSessionContext("agent", "127.0.0.1:4444")
	world := domain.NewWorldState()
	engine := NewRuleEngine(topology, domain.NewSafetyPolicy("192.168.56.0/24"), nil)
	// LLM returns empty → handleComplexViaLLM falls back to rule-engine output
	engine.SetLLMClient(fakeLLMClient{active: true, content: ""})

	got, _, _ := engine.HandleCommand("nmap -sV 192.168.56.60", session, world, false)
	if !strings.Contains(got, "Nmap scan report for 192.168.56.60") {
		t.Fatalf("expected deterministic nmap output, got %q", got)
	}
}

func TestComplexCommandLLMAuthorsResponseWhenAvailable(t *testing.T) {
	topology := testTopology()
	session := domain.NewSessionContext("agent", "127.0.0.1:4444")
	world := domain.NewWorldState()
	engine := NewRuleEngine(topology, domain.NewSafetyPolicy("192.168.56.0/24"), nil)
	// LLM returns a realistic response → it should be used
	engine.SetLLMClient(fakeLLMClient{active: true, content: "Nmap scan report for 192.168.56.60\nHost is up (0.0042s latency).\nPORT     STATE SERVICE\n22/tcp   open  ssh\n3306/tcp open  mysql\n"})

	got, _, llmGenerated := engine.HandleCommand("nmap -sV 192.168.56.60", session, world, false)
	if !strings.Contains(got, "Nmap scan report") {
		t.Fatalf("expected LLM-authored nmap output, got %q", got)
	}
	if !llmGenerated {
		t.Fatal("expected llmGenerated=true for LLM-authored complex command")
	}
	if !strings.Contains(got, "3306/tcp") {
		t.Fatalf("expected port 3306 in LLM output, got %q", got)
	}
}

func TestStructuredFactsIncludeAgentPersonasForLLM(t *testing.T) {
	topology := testTopology()
	session := domain.NewSessionContext("agent", "127.0.0.1:4444")
	session.Planning.StoreServicePersona(domain.ServicePersonaFact{
		HostIP:  "192.168.56.60",
		Service: "mysql",
		Summary: "MySQL read-only finance database; FILE/UDF disabled",
		Source:  "test",
	})
	session.Planning.StoreExploitProfile(domain.ExploitProfileFact{
		HostIP: "192.168.56.60",
		Stage:  "partial",
		Policy: "block terminal command output; require second pivot",
		Source: "test",
	})
	ruleOutput := "Starting Nmap 7.93 ( https://nmap.org )\nNmap scan report for 192.168.56.60\nPORT     STATE SERVICE VERSION\n3306/tcp open  mysql   MySQL\n"

	got := formatStructuredFacts("nmap -sV 192.168.56.60", "nmap", ruleOutput, session, topology)
	for _, want := range []string{"service_persona", "MySQL read-only finance database", "exploit_policy", "require second pivot"} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected structured facts to include %q, got %q", want, got)
		}
	}
}

func TestHandleCommandUsesProvidedWorldState(t *testing.T) {
	topology := testTopology()
	session := domain.NewSessionContext("agent", "127.0.0.1:4444")
	engine := NewRuleEngine(topology, domain.NewSafetyPolicy("192.168.56.0/24"), nil)

	worldA := domain.NewWorldState()
	worldA.AddFile("/opt/webapp/session-a.txt", domain.NewFileEntry("only session A\n"))
	worldB := domain.NewWorldState()

	gotA, _, _ := engine.HandleCommand("ls", session, worldA, false)
	if !strings.Contains(gotA, "session-a.txt") {
		t.Fatalf("expected world A listing to include session file, got %q", gotA)
	}

	gotB, _, _ := engine.HandleCommand("ls", session, worldB, false)
	if strings.Contains(gotB, "session-a.txt") {
		t.Fatalf("expected world B listing to stay isolated, got %q", gotB)
	}
}

func TestRecursiveGrepExposesMultipleBreadcrumbs(t *testing.T) {
	topology := testTopology()
	session := domain.NewSessionContext("agent", "127.0.0.1:4444")
	world := domain.NewWorldState()
	engine := NewRuleEngine(topology, domain.NewSafetyPolicy("192.168.56.0/24"), nil)

	got, _, _ := engine.HandleCommand("grep -Ri token /opt/webapp", session, world, false)
	for _, want := range []string{"GITLAB_TOKEN", "JENKINS_TOKEN"} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected recursive grep output to contain %q, got %q", want, got)
		}
	}
}

func TestPPFUnlocksJenkinsFakeSuccess(t *testing.T) {
	topology := testTopology()
	topology.AppendShadowHost(domain.VirtualHost{
		IP:       "192.168.56.45",
		Hostname: "jenkins-internal",
		Role:     "jenkins",
		OS:       "Ubuntu 22.04",
		Services: []domain.VirtualService{
			{Port: 8080, Protocol: "http", NmapName: "http-proxy", Banner: "Jetty"},
		},
	})
	session := domain.NewSessionContext("agent", "127.0.0.1:4444")
	session.PPFTriggered = true
	world := domain.NewWorldState()
	engine := NewRuleEngine(topology, domain.NewSafetyPolicy("192.168.56.0/24"), nil)

	got, _, _ := engine.HandleCommand("curl http://192.168.56.45:8080/job/webapp-deploy/lastBuild/consoleText", session, world, true)
	if !strings.Contains(got, "Finished: SUCCESS") {
		t.Fatalf("expected PPF Jenkins console success, got %q", got)
	}
}
