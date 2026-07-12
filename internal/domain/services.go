package domain

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// ServiceRegistry is the single source of truth for what services exist on
// which hosts. Every responder must consult this registry so that scan results
// always match connection behavior.
type ServiceRegistry struct {
	mu       sync.RWMutex
	topology *VirtualTopology
}

// NewServiceRegistry creates a registry backed by the given topology.
func NewServiceRegistry(topology *VirtualTopology) *ServiceRegistry {
	return &ServiceRegistry{topology: topology}
}

// ResolveService looks up whether a specific service (by protocol or port)
// exists on a given IP, visible to the session.
func (r *ServiceRegistry) ResolveService(session *SessionContext, ip string, protocol string, port int) (*VirtualService, *VirtualHost) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	host := r.topology.GetHost(ip)
	if host == nil {
		return nil, nil
	}

	// Check visibility
	visible := r.topology.GetHostsForSession(session)
	found := false
	for _, h := range visible {
		if h.IP == ip {
			found = true
			break
		}
	}
	if !found {
		return nil, host
	}

	for i := range host.Services {
		svc := &host.Services[i]
		if protocol != "" && svc.Protocol == protocol {
			return svc, host
		}
		if port > 0 && svc.Port == port {
			return svc, host
		}
	}
	return nil, host
}

// GetListeningServices returns all services visible on the local host,
// formatted as netstat-style lines.
func (r *ServiceRegistry) GetListeningServices(session *SessionContext, localIP string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var lines []string
	// Always show SSH on the local host
	lines = append(lines, "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN")

	localHost := r.resolveLocalHost(localIP, session)
	if localHost != nil {
		for _, svc := range localHost.Services {
			if svc.Port == 22 {
				continue
			}
			bindAddr := "0.0.0.0"
			if svc.Port == 3306 {
				bindAddr = "127.0.0.1"
			}
			lines = append(lines, fmt.Sprintf(
				"tcp        0      0 %s:%-18d 0.0.0.0:*               LISTEN",
				bindAddr, svc.Port,
			))
		}
	}
	sort.Strings(lines[1:])
	return strings.Join(lines, "\n") + "\n"
}

// GetSSOutput returns services in ss -tlnp format.
func (r *ServiceRegistry) GetSSOutput(session *SessionContext, localIP string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var lines []string
	lines = append(lines, `State    Recv-Q   Send-Q     Local Address:Port     Peer Address:Port  Process`)
	lines = append(lines, `LISTEN   0        128              0.0.0.0:22            0.0.0.0:*      users:(("sshd",pid=412,fd=3))`)

	localHost := r.resolveLocalHost(localIP, session)
	if localHost != nil {
		pid := 500
		for _, svc := range localHost.Services {
			if svc.Port == 22 {
				continue
			}
			pid++
			bindAddr := "0.0.0.0"
			process := "unknown"
			switch svc.Protocol {
			case "mysql":
				bindAddr = "127.0.0.1"
				process = "mysqld"
			case "http", "https", "http-proxy":
				process = "nginx"
			case "redis":
				process = "redis-server"
			default:
				process = svc.Protocol
			}
			lines = append(lines, fmt.Sprintf(
				"LISTEN   0        128            %s:%-5d          0.0.0.0:*      users:(\"%s\",pid=%d,fd=%d)",
				bindAddr, svc.Port, process, pid, svc.Port%100+10,
			))
		}
	}
	return strings.Join(lines, "\n") + "\n"
}

// GetArpTable returns an ARP table derived from topology hosts visible to the session.
func (r *ServiceRegistry) GetArpTable(session *SessionContext, localIP string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	visible := r.topology.GetHostsForSession(session)
	var lines []string
	for _, host := range visible {
		if host.IP == localIP {
			continue
		}
		mac := fakeMAC(host.IP)
		lines = append(lines, fmt.Sprintf(
			"? (%s) at %s [ether] on eth0", host.IP, mac,
		))
	}
	if len(lines) == 0 {
		return ""
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n") + "\n"
}

func fakeMAC(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return "00:50:56:xx:xx:xx"
	}
	var b1, b2, b3 int
	fmt.Sscanf(parts[1], "%d", &b1)
	fmt.Sscanf(parts[2], "%d", &b2)
	fmt.Sscanf(parts[3], "%d", &b3)
	return fmt.Sprintf("00:50:56:%02x:%02x:%02x", b1%256, b2%256, b3%256)
}

// IsVirtualIP delegates to the topology's check.
func (r *ServiceRegistry) IsVirtualIP(ip string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.topology.IsVirtualIP(ip)
}

// GetHost returns the host for the given IP.
func (r *ServiceRegistry) GetHost(ip string) *VirtualHost {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.topology.GetHost(ip)
}

// GetHostsForSession returns visible hosts for the session.
func (r *ServiceRegistry) GetHostsForSession(session *SessionContext) []VirtualHost {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.topology.GetHostsForSession(session)
}

// TopologyRef returns the underlying topology (for callers that need direct access).
func (r *ServiceRegistry) TopologyRef() *VirtualTopology {
	return r.topology
}

// resolveLocalHost tries to find the local host by entry IP first, then by subnet IP.
func (r *ServiceRegistry) resolveLocalHost(localIP string, session *SessionContext) *VirtualHost {
	host := r.topology.GetHost(localIP)
	if host != nil {
		return host
	}
	// Fallback: try subnet local IP
	if session.SubnetLocalIP != "" && session.SubnetLocalIP != localIP {
		host = r.topology.GetHost(session.SubnetLocalIP)
		if host != nil {
			return host
		}
	}
	return nil
}
