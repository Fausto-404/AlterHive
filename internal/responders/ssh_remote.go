package responders

import (
	"fmt"
	"regexp"

	"github.com/alterhive/alterhive/internal/domain"
)

var reSSHUser = regexp.MustCompile(`(\w+)@\d`)

// HandleSSHCommand simulates SSH connections to virtual hosts.
func HandleSSHCommand(cmd string, session *domain.SessionContext, topology *domain.VirtualTopology, ppfTriggered bool) (string, []string) {
	var evidenceHits []string

	ipMatch := reIP.FindString(cmd)
	if ipMatch == "" {
		return "ssh: usage: ssh [-p port] [user@]hostname [command]\n", evidenceHits
	}

	targetIP := ipMatch
	targetUser := "root"
	if userMatch := reSSHUser.FindStringSubmatch(cmd); len(userMatch) > 1 {
		targetUser = userMatch[1]
	}

	// SSH to self - simulate local login
	if targetIP == session.SubnetLocalIP {
		session.PendingSSHAuth = &domain.PendingSSH{
			TargetIP:   targetIP,
			TargetUser: targetUser,
			Attempts:   0,
			MaxAttempt: 1,
			SelfSSH:    true,
			RemoteAddr: session.RemoteAddr,
		}
		session.SuppressShellPrompt = true
		return fmt.Sprintf("%s@%s's password: ", targetUser, targetIP), evidenceHits
	}

	host := topology.GetHost(targetIP)
	evidenceHits = append(evidenceHits, "lateral_probe")

	if host == nil {
		if topology.IsVirtualIP(targetIP) {
			return fmt.Sprintf("ssh: connect to host %s port 22: Connection refused\n", targetIP), evidenceHits
		}
		return fmt.Sprintf("ssh: connect to host %s port 22: No route to host\n", targetIP), evidenceHits
	}

	// Check visibility - shadow hosts (goal targets) are always accessible once injected
	// For non-shadow hosts, check normal visibility rules
	isVisible := host.Shadow // Shadow/goal hosts are always accessible

	if !isVisible {
		visible := topology.GetHostsForSession(session)
		isVisible = hostInListPtr(host, visible)

		// Also check if there's a direct edge from current host to target's segment
		if !isVisible && host.SegmentCIDR != "" {
			currentIP := session.SubnetLocalIP
			edges := topology.AllEdges()
			for _, edge := range edges {
				if edge.From == currentIP && edge.To == host.SegmentCIDR && edge.Status == "active" {
					isVisible = true
					break
				}
			}
		}
	}

	if !isVisible {
		if topology.IsVirtualIP(targetIP) {
			return fmt.Sprintf("ssh: connect to host %s port 22: Connection refused\n", targetIP), evidenceHits
		}
		return fmt.Sprintf("ssh: connect to host %s port 22: No route to host\n", targetIP), evidenceHits
	}

	// Check SSH service
	hasSSH := false
	for _, svc := range host.Services {
		if svc.Protocol == "ssh" {
			hasSSH = true
			break
		}
	}
	if !hasSSH {
		return fmt.Sprintf("ssh: connect to host %s port 22: Connection refused\n", targetIP), evidenceHits
	}

	evidenceHits = append(evidenceHits, "credential_reuse_attempt")

	// All remote SSH: prompt for password first
	maxAttempts := 3
	if host.Role == "gateway" || host.Role == "dc_shadow" {
		maxAttempts = 2
	}

	session.PendingSSHAuth = &domain.PendingSSH{
		TargetIP:         targetIP,
		TargetUser:       targetUser,
		Attempts:         0,
		MaxAttempt:       maxAttempts,
		ExpectedPassword: host.Password,
	}
	session.SuppressShellPrompt = true
	return fmt.Sprintf("%s@%s's password: ", targetUser, targetIP), evidenceHits
}

func hostInListPtr(host *domain.VirtualHost, list []domain.VirtualHost) bool {
	for _, h := range list {
		if h.IP == host.IP {
			return true
		}
	}
	return false
}
