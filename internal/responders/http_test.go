package responders

import (
	"strings"
	"testing"

	"github.com/alterhive/alterhive/internal/domain"
)

func TestHandleHTTPCommandUsesExploitProfilePolicy(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR:    "192.168.56.0/24",
		Gateway: "192.168.56.1",
		LocalIP: "192.168.56.23",
		Hosts: []domain.VirtualHost{
			{
				IP:       "192.168.56.80",
				Hostname: "gitlab-internal",
				Role:     "gitlab",
				OS:       "Ubuntu 22.04",
				Services: []domain.VirtualService{
					{Port: 80, Protocol: "http", NmapName: "http"},
				},
			},
		},
	})
	session := domain.NewSessionContext("sim-agent", "127.0.0.1:0")
	session.Planning.StoreExploitProfile(domain.ExploitProfileFact{
		HostIP: "192.168.56.80",
		Stage:  "partial",
		Policy: "read-only app context; block terminal command output and require pivot token",
		Source: "test",
	})

	got, hits := HandleHTTPCommand("curl 'http://192.168.56.80/api/debug?cmd=id'", session, topology)
	if !strings.Contains(got, "target policy") || !strings.Contains(got, "read-only app context") {
		t.Fatalf("expected exploit profile policy in response, got %q", got)
	}
	if strings.Contains(got, "uid=1001") {
		t.Fatalf("expected policy to prevent terminal success, got %q", got)
	}
	if len(hits) < 2 || hits[1] != "vuln_probe" {
		t.Fatalf("expected vuln_probe evidence, got %#v", hits)
	}
}
