package domain

import (
	"encoding/binary"
	"fmt"
	"net"
)

// RebasePrimaryCIDR moves the entry subnet template to a new CIDR while
// preserving host offsets, e.g. 192.168.56.23 -> 10.8.0.23.
func RebasePrimaryCIDR(config TopologyConfig, newCIDR string) (TopologyConfig, error) {
	if newCIDR == "" || newCIDR == config.CIDR {
		return config, nil
	}
	oldIP, oldNet, err := net.ParseCIDR(config.CIDR)
	if err != nil {
		return config, fmt.Errorf("invalid original topology cidr: %w", err)
	}
	newIP, newNet, err := net.ParseCIDR(newCIDR)
	if err != nil {
		return config, fmt.Errorf("invalid topology cidr override: %w", err)
	}
	old4 := oldIP.To4()
	new4 := newIP.To4()
	if old4 == nil || new4 == nil {
		return config, fmt.Errorf("topology cidr only supports IPv4")
	}
	oldOnes, oldBits := oldNet.Mask.Size()
	newOnes, newBits := newNet.Mask.Size()
	if oldBits != 32 || newBits != 32 || oldOnes != newOnes {
		return config, fmt.Errorf("topology cidr prefix must stay /%d", oldOnes)
	}

	rebase := func(value string) string {
		ip := net.ParseIP(value).To4()
		if ip == nil || !oldNet.Contains(ip) {
			return value
		}
		oldBase := binary.BigEndian.Uint32(oldNet.IP.To4())
		newBase := binary.BigEndian.Uint32(newNet.IP.To4())
		offset := binary.BigEndian.Uint32(ip) - oldBase
		next := make(net.IP, 4)
		binary.BigEndian.PutUint32(next, newBase+offset)
		if !newNet.Contains(next) {
			return value
		}
		return next.String()
	}

	oldCIDR := config.CIDR
	config.CIDR = newCIDR
	config.Gateway = rebase(config.Gateway)
	config.LocalIP = rebase(config.LocalIP)
	for i := range config.Segments {
		if config.Segments[i].CIDR == oldCIDR {
			config.Segments[i].CIDR = newCIDR
			config.Segments[i].GatewayIP = rebase(config.Segments[i].GatewayIP)
		}
	}
	for i := range config.Hosts {
		config.Hosts[i].IP = rebase(config.Hosts[i].IP)
		config.Hosts[i].ReachableVia = rebase(config.Hosts[i].ReachableVia)
		if config.Hosts[i].SegmentCIDR == oldCIDR {
			config.Hosts[i].SegmentCIDR = newCIDR
		}
	}
	for i := range config.Edges {
		if config.Edges[i].From == oldCIDR {
			config.Edges[i].From = newCIDR
		} else {
			config.Edges[i].From = rebase(config.Edges[i].From)
		}
		if config.Edges[i].To == oldCIDR {
			config.Edges[i].To = newCIDR
		} else {
			config.Edges[i].To = rebase(config.Edges[i].To)
		}
		config.Edges[i].Via = rebase(config.Edges[i].Via)
	}
	return config, nil
}
