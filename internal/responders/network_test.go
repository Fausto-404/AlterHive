package responders

import (
	"strings"
	"testing"

	"github.com/alterhive/alterhive/internal/domain"
)

func TestHandleNetworkCommandFscanOutput(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR:      "192.168.56.0/24",
		Gateway:   "192.168.56.1",
		LocalIP:   "192.168.56.23",
		DNSSuffix: "corp.local",
		Hosts: []domain.VirtualHost{
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
	session := domain.NewSessionContext("sim-agent", "127.0.0.1:0")

	got, hits := HandleNetworkCommand("fscan -h 192.168.56.0/24", session, topology)
	if !strings.Contains(got, "[*] fscan version") || !strings.Contains(got, "[+] Mysql 192.168.56.60:3306 open") {
		t.Fatalf("expected fscan-like output, got %q", got)
	}
	if len(hits) == 0 || hits[0] != "subnet_scan" {
		t.Fatalf("expected subnet_scan evidence, got %#v", hits)
	}
}

func TestHandleNetworkCommandEmptyNmapUsesRequestedCIDR(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR:    "10.168.56.0/24",
		Gateway: "10.168.56.1",
		LocalIP: "10.168.56.23",
	})
	session := domain.NewSessionContext("sim-agent", "127.0.0.1:0")
	session.SetSubnetNetwork("10.168.56.23", "10.168.56.0/24", "10.168.56.1")

	got, hits := HandleNetworkCommand("nmap 10.15.156.0/24", session, topology)
	if strings.Contains(got, "192.168.56.0/24") {
		t.Fatalf("expected no hard-coded legacy CIDR, got %q", got)
	}
	if !strings.Contains(got, "10.15.156.0/24") || !strings.Contains(got, "0 hosts up") {
		t.Fatalf("expected requested CIDR with 0 hosts up, got %q", got)
	}
	if len(hits) == 0 || hits[0] != "subnet_scan" {
		t.Fatalf("expected subnet_scan evidence, got %#v", hits)
	}
}

func TestHandleNetworkCommandNmapUsesServicePersona(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR:    "192.168.56.0/24",
		Gateway: "192.168.56.1",
		LocalIP: "192.168.56.23",
		Hosts: []domain.VirtualHost{
			{
				IP:       "192.168.56.60",
				Hostname: "fin-db01",
				Role:     "database",
				OS:       "Ubuntu 22.04",
				Services: []domain.VirtualService{
					{Port: 3306, Protocol: "mysql", NmapName: "mysql", Banner: "MySQL 5.7.38"},
				},
			},
		},
	})
	session := domain.NewSessionContext("sim-agent", "127.0.0.1:0")
	session.Planning.StoreServicePersona(domain.ServicePersonaFact{
		HostIP:  "192.168.56.60",
		Service: "mysql",
		Summary: "MySQL read-only finance database; FILE/UDF disabled; auth required",
		Source:  "test",
	})

	got, _ := HandleNetworkCommand("nmap -sV 192.168.56.60", session, topology)
	if !strings.Contains(got, "MySQL read-only finance database") {
		t.Fatalf("expected nmap to render agent service persona, got %q", got)
	}
	if strings.Contains(got, "MySQL 5.7.38") {
		t.Fatalf("expected persona to override static banner, got %q", got)
	}
}
