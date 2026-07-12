package domain

import (
	"net"
	"sync"

	"gopkg.in/yaml.v3"
)

// TopologyConfig is the YAML structure for topology configuration.
type TopologyConfig struct {
	CIDR      string           `yaml:"cidr"`
	Gateway   string           `yaml:"gateway"`
	LocalIP   string           `yaml:"local_ip"`
	DNSSuffix string           `yaml:"dns_suffix"`
	Segments  []NetworkSegment `yaml:"segments"`
	Edges     []NetworkEdge    `yaml:"edges"`
	Hosts     []VirtualHost    `yaml:"hosts"`
}

// VirtualTopology manages the routed illusion graph.
type VirtualTopology struct {
	mu       sync.RWMutex
	config   TopologyConfig
	hosts    []*VirtualHost
	segments []NetworkSegment
	edges    []NetworkEdge
	cidrNets []*net.IPNet
}

// NewVirtualTopology creates a topology from config.
func NewVirtualTopology(config TopologyConfig) *VirtualTopology {
	t := &VirtualTopology{
		config: config,
	}
	t.segments = append(t.segments, config.Segments...)
	if len(t.segments) == 0 && config.CIDR != "" {
		t.segments = append(t.segments, NetworkSegment{
			CIDR:      config.CIDR,
			Name:      "corp-access",
			Zone:      "internal",
			GatewayIP: config.Gateway,
		})
	}
	t.edges = append(t.edges, config.Edges...)
	for i := range config.Hosts {
		if config.Hosts[i].SegmentCIDR == "" {
			config.Hosts[i].SegmentCIDR = segmentForIP(config.Hosts[i].IP, t.segments)
		}
		// Derive password from deploy seed if not explicitly set or if it's a known default
		if config.Hosts[i].Password == "" || config.Hosts[i].Password == "ansible123" || config.Hosts[i].Password == "P@ssw0rd!" {
			config.Hosts[i].Password = DerivePassword(config.Hosts[i].Hostname)
		}
		t.hosts = append(t.hosts, &config.Hosts[i])
	}
	t.rebuildCIDRNetsLocked()
	return t
}

// LoadTopologyConfig parses a YAML file into TopologyConfig.
func LoadTopologyConfig(data []byte) (TopologyConfig, error) {
	var config TopologyConfig
	err := yaml.Unmarshal(data, &config)
	return config, err
}

func (t *VirtualTopology) CIDR() string      { return t.config.CIDR }
func (t *VirtualTopology) Gateway() string   { return t.config.Gateway }
func (t *VirtualTopology) LocalIP() string   { return t.config.LocalIP }
func (t *VirtualTopology) DNSSuffix() string { return t.config.DNSSuffix }

// AllHosts returns a copy of all hosts.
func (t *VirtualTopology) AllHosts() []VirtualHost {
	t.mu.RLock()
	defer t.mu.RUnlock()
	hosts := make([]VirtualHost, len(t.hosts))
	for i, h := range t.hosts {
		hosts[i] = *h
	}
	return hosts
}

// AllSegments returns a copy of all simulated network segments.
func (t *VirtualTopology) AllSegments() []NetworkSegment {
	t.mu.RLock()
	defer t.mu.RUnlock()
	segments := make([]NetworkSegment, len(t.segments))
	copy(segments, t.segments)
	return segments
}

// AllEdges returns a copy of all topology edges.
func (t *VirtualTopology) AllEdges() []NetworkEdge {
	t.mu.RLock()
	defer t.mu.RUnlock()
	edges := make([]NetworkEdge, len(t.edges))
	copy(edges, t.edges)
	return edges
}

// GetHost looks up a host by IP.
func (t *VirtualTopology) GetHost(ip string) *VirtualHost {
	t.mu.RLock()
	defer t.mu.RUnlock()
	for _, h := range t.hosts {
		if h.IP == ip {
			return h
		}
	}
	return nil
}

// GetHostForSession prefers a dynamic host owned by the requested session and
// falls back to a base (ownerless) host. This keeps identical illusion IPs in
// separate attacker sessions from shadowing one another.
func (t *VirtualTopology) GetHostForSession(ip, sessionID string) *VirtualHost {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var base *VirtualHost
	for _, h := range t.hosts {
		if h.IP != ip {
			continue
		}
		if h.OwnerSessionID == sessionID && sessionID != "" {
			copy := *h
			return &copy
		}
		if h.OwnerSessionID == "" {
			copy := *h
			base = &copy
		}
	}
	return base
}

// IsVirtualIP checks if an IP is in the virtual subnet.
func (t *VirtualTopology) IsVirtualIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	for _, cidrNet := range t.cidrNets {
		if cidrNet.Contains(parsed) {
			return true
		}
	}
	return false
}

// GetHostsForSession returns hosts visible to a session based on evidence tokens.
func (t *VirtualTopology) GetHostsForSession(session *SessionContext) []VirtualHost {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var visible []VirtualHost
	for _, h := range t.hosts {
		if !requiredStatesMet(session, h.RequiredState) {
			continue
		}
		allMet := true
		for _, token := range h.VisibleAfter {
			if !session.Evidence.Has(token) {
				allMet = false
				break
			}
		}
		if allMet {
			visible = append(visible, *h)
		}
	}
	return visible
}

// AppendShadowHost adds a dynamically generated host.
func (t *VirtualTopology) AppendShadowHost(host VirtualHost) {
	t.AppendHost(host)
}

// AppendHost adds a host to the topology graph.
func (t *VirtualTopology) AppendHost(host VirtualHost) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, h := range t.hosts {
		if h.IP == host.IP && (h.OwnerSessionID == "" || host.OwnerSessionID == "" || h.OwnerSessionID == host.OwnerSessionID) {
			return
		}
	}
	if host.SegmentCIDR == "" {
		host.SegmentCIDR = segmentForIP(host.IP, t.segments)
	}
	t.hosts = append(t.hosts, &host)
}

// AppendSegment adds a routed subnet to the topology graph.
func (t *VirtualTopology) AppendSegment(segment NetworkSegment) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, existing := range t.segments {
		if existing.CIDR == segment.CIDR && (existing.OwnerSessionID == "" || segment.OwnerSessionID == "" || existing.OwnerSessionID == segment.OwnerSessionID) {
			return false
		}
	}
	t.segments = append(t.segments, segment)
	t.rebuildCIDRNetsLocked()
	return true
}

// AppendEdge adds a relationship/pivot requirement to the topology graph.
func (t *VirtualTopology) AppendEdge(edge NetworkEdge) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, existing := range t.edges {
		if existing.From == edge.From && existing.To == edge.To && existing.Type == edge.Type &&
			(existing.OwnerSessionID == "" || edge.OwnerSessionID == "" || existing.OwnerSessionID == edge.OwnerSessionID) {
			return false
		}
	}
	t.edges = append(t.edges, edge)
	return true
}

// UpdateEdgeStatus changes the status of an edge matching from→to.
func (t *VirtualTopology) UpdateEdgeStatus(from, to, status string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := range t.edges {
		if t.edges[i].From == from && t.edges[i].To == to {
			t.edges[i].Status = status
			return true
		}
	}
	return false
}

// GetEdgesFrom returns all edges originating from the given IP.
func (t *VirtualTopology) GetEdgesFrom(ip string) []NetworkEdge {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var result []NetworkEdge
	for _, e := range t.edges {
		if e.From == ip {
			result = append(result, e)
		}
	}
	return result
}

// RemoveSessionArtifacts removes dynamic shadow graph elements owned by a session.
func (t *VirtualTopology) RemoveSessionArtifacts(sessionID string) {
	if sessionID == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	var hosts []*VirtualHost
	for _, host := range t.hosts {
		if host != nil && host.Shadow && host.OwnerSessionID == sessionID {
			continue
		}
		hosts = append(hosts, host)
	}
	t.hosts = hosts

	var segments []NetworkSegment
	for _, segment := range t.segments {
		if segment.Shadow && segment.OwnerSessionID == sessionID {
			continue
		}
		segments = append(segments, segment)
	}
	t.segments = segments

	var edges []NetworkEdge
	for _, edge := range t.edges {
		if edge.OwnerSessionID == sessionID {
			continue
		}
		edges = append(edges, edge)
	}
	t.edges = edges
	t.rebuildCIDRNetsLocked()
}

// GetServicesForIP returns services for a given IP.
func (t *VirtualTopology) GetServicesForIP(ip string) []VirtualService {
	h := t.GetHost(ip)
	if h == nil {
		return nil
	}
	return h.Services
}

func (t *VirtualTopology) rebuildCIDRNetsLocked() {
	t.cidrNets = nil
	for _, segment := range t.segments {
		_, cidrNet, err := net.ParseCIDR(segment.CIDR)
		if err == nil {
			t.cidrNets = append(t.cidrNets, cidrNet)
		}
	}
}

func segmentForIP(ip string, segments []NetworkSegment) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	for _, segment := range segments {
		_, cidrNet, err := net.ParseCIDR(segment.CIDR)
		if err == nil && cidrNet.Contains(parsed) {
			return segment.CIDR
		}
	}
	return ""
}

func requiredStatesMet(session *SessionContext, states []string) bool {
	for _, state := range states {
		if !session.HasAccessState(state) {
			return false
		}
	}
	return true
}
