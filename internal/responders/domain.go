package responders

import (
	"fmt"
	"strings"

	"github.com/alterhive/alterhive/internal/domain"
)

var (
	ldapSearchResults = `# extended LDIF
#
# LDAPv3
# base <dc=corp,dc=local> with scope subtree
# filter: (objectClass=*)
# requesting: ALL
#

# corp.local
dn: dc=corp,dc=local
objectClass: domain
objectClass: top
dc: corp

# Users, corp.local
dn: cn=Users,dc=corp,dc=local
objectClass: container
cn: Users

# admin, Users, corp.local
dn: cn=admin,cn=Users,dc=corp,dc=local
objectClass: user
cn: admin
sAMAccountName: admin
memberOf: cn=Domain Admins,cn=Users,dc=corp,dc=local

# svc_web, Users, corp.local
dn: cn=svc_web,cn=Users,dc=corp,dc=local
objectClass: user
cn: svc_web
sAMAccountName: svc_web
memberOf: cn=WebServers,cn=Users,dc=corp,dc=local

# svc_backup, Users, corp.local
dn: cn=svc_backup,cn=Users,dc=corp,dc=local
objectClass: user
cn: svc_backup
sAMAccountName: svc_backup
memberOf: cn=BackupOperators,cn=Users,dc=corp,dc=local

# search result
search: 2
result: 0 Success

# numResponses: 5
# numEntries: 4
`

	smbList = `  Sharename       Type      Comment
  ---------       ----      -------
  IPC$            IPC       Remote IPC
  NETLOGON        Disk      Network Logon Service
  SYSVOL          Disk      Domain share
  C$              Disk      Default share
  ADMIN$          Disk      Remote Admin
  Finance         Disk      Financial Documents
  IT-Share        Disk      IT Department Files

Reconnecting with SMB1 for workgroup listing.

  Server               Comment
  ---------            -------
  DC01                 Domain Controller

  Workgroup            Master
  ---------            -------
  CORP                 DC01
`

	kinitSuccess = "Password for admin@CORP.LOCAL:\n"

	klistOutput = `Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: admin@CORP.LOCAL

Valid starting       Expires              Service principal
01/15/2024 08:15:22  01/15/2024 18:15:22  krbtgt/CORP.LOCAL@CORP.LOCAL
01/15/2024 08:15:45  01/15/2024 18:15:22  cifs/dc01.corp.local@CORP.LOCAL
`

	smbExtendedShares = `
  HR-Confidential   Disk      HR Department
  DevOps            Disk      DevOps Shared Storage
  Backup            Disk      Backup Storage
`

	dnsQuery = `;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 42
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; QUESTION SECTION:
;corp.local.                    IN      SOA

;; ANSWER SECTION:
corp.local.             3600    IN      SOA     dc01.corp.local. admin.corp.local. 2024011501 3600 900 604800 86400

;; ADDITIONAL SECTION:
dc01.corp.local.        3600    IN      A       192.168.56.50
`
)

// HandleLDAPCommand simulates LDAP queries.
func HandleLDAPCommand(cmd string, session *domain.SessionContext, topology *domain.VirtualTopology) (string, []string) {
	evidenceHits := []string{"domain_probe"}

	targetIP := "192.168.56.50"
	if ipMatch := reIP.FindString(cmd); ipMatch != "" {
		targetIP = ipMatch
	}

	host := topology.GetHost(targetIP)
	if host == nil || !hostInList(host, topology.GetHostsForSession(session)) {
		return "ldap_sasl_bind(SIMPLE): Can't contact LDAP server (-1)\n", evidenceHits
	}

	hasLDAP := false
	for _, svc := range host.Services {
		if svc.Protocol == "ldap" || svc.Protocol == "ldaps" {
			hasLDAP = true
			break
		}
	}
	if !hasLDAP {
		return "ldap_sasl_bind(SIMPLE): Can't contact LDAP server (-1)\n", evidenceHits
	}

	cmdLower := strings.ToLower(cmd)
	if strings.Contains(cmdLower, "-D") && strings.Contains(cmdLower, "-w") {
		evidenceHits = append(evidenceHits, "credential_reuse_attempt")
	}

	// Strategy-aware: domain_mapper gets richer LDAP output with more users/groups
	if session.DeceptionProfile == "domain_mapper" {
		return ldapSearchResults + ldapExtendedResults, evidenceHits
	}

	return ldapSearchResults, evidenceHits
}

// ldapExtendedResults adds extra domain enumeration data for domain_mapper profiles.
var ldapExtendedResults = `
# svc_finance, Users, corp.local
dn: cn=svc_finance,cn=Users,dc=corp,dc=local
objectClass: user
cn: svc_finance
sAMAccountName: svc_finance
memberOf: cn=Finance,cn=Users,dc=corp,dc=local

# svc_deploy, Users, corp.local
dn: cn=svc_deploy,cn=Users,dc=corp,dc=local
objectClass: user
cn: svc_deploy
sAMAccountName: svc_deploy
memberOf: cn=DevOps,cn=Users,dc=corp,dc=local
memberOf: cn=RemoteDesktopUsers,cn=Users,dc=corp,dc=local

# numResponses: 8
# numEntries: 7
`

// HandleSMBCommand simulates SMB client commands.
func HandleSMBCommand(cmd string, session *domain.SessionContext, topology *domain.VirtualTopology) (string, []string) {
	evidenceHits := []string{"domain_probe"}

	targetIP := "192.168.56.50"
	if ipMatch := reIP.FindString(cmd); ipMatch != "" {
		targetIP = ipMatch
	}

	host := topology.GetHost(targetIP)
	if host == nil || !hostInList(host, topology.GetHostsForSession(session)) {
		return fmt.Sprintf("Connection to %s failed (Error NT_STATUS_CONNECTION_REFUSED)\n", targetIP), evidenceHits
	}

	hasSMB := false
	for _, svc := range host.Services {
		if svc.Protocol == "smb" {
			hasSMB = true
			break
		}
	}
	if !hasSMB {
		return fmt.Sprintf("Connection to %s failed (Error NT_STATUS_CONNECTION_REFUSED)\n", targetIP), evidenceHits
	}

	cmdLower := strings.ToLower(cmd)
	if strings.Contains(cmdLower, "-u") {
		evidenceHits = append(evidenceHits, "credential_reuse_attempt")
	}

	if strings.Contains(cmdLower, "-L") || strings.Contains(cmdLower, "--list") {
		// Strategy-aware: domain_mapper gets more shares listed
		if session.DeceptionProfile == "domain_mapper" {
			return smbList + smbExtendedShares, evidenceHits
		}
		return smbList, evidenceHits
	}

	return "Try 'help' to get a list of possible commands.\nsmb: \\> ", evidenceHits
}

// HandleKerberosCommand simulates Kerberos commands.
func HandleKerberosCommand(cmd string) (string, []string) {
	evidenceHits := []string{"domain_probe"}

	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(cmd)), "kinit") {
		evidenceHits = append(evidenceHits, "credential_reuse_attempt")
		return kinitSuccess, evidenceHits
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(cmd)), "klist") {
		return klistOutput, evidenceHits
	}

	return "", evidenceHits
}

// HandleDNSCommand simulates DNS queries.
func HandleDNSCommand(cmd string, session *domain.SessionContext, topology *domain.VirtualTopology) (string, []string) {
	evidenceHits := []string{"domain_probe"}

	if ipMatch := reIP.FindString(cmd); ipMatch != "" {
		host := topology.GetHost(ipMatch)
		if host == nil || !hostInList(host, topology.GetHostsForSession(session)) {
			return ";; connection timed out; no servers could be reached\n", evidenceHits
		}
	}

	return dnsQuery, evidenceHits
}
