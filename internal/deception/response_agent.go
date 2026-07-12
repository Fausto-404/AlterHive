package deception

import (
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"time"

	"github.com/alterhive/alterhive/internal/domain"
)

// ResponseRenderResult wraps rendered output with safety metadata.
type ResponseRenderResult struct {
	Output  string
	Blocked bool
	Reason  string
}

// ResponseAgent renders structured facts into tool-specific terminal output.
// It is the only path through which command output reaches the attacker;
// every response is built from approved World State Store facts.
type ResponseAgent struct {
	topology *domain.VirtualTopology
	registry *domain.ServiceRegistry
	safety   *domain.SafetyPolicy
}

// NewResponseAgent creates a ready-to-use response agent.
func NewResponseAgent(topology *domain.VirtualTopology, safety *domain.SafetyPolicy) *ResponseAgent {
	return &ResponseAgent{
		topology: topology,
		registry: domain.NewServiceRegistry(topology),
		safety:   safety,
	}
}

// RenderApprovedResponse is the Response Agent boundary: renderers may format
// approved facts, but all terminal output must pass consistency/fact guards.
func RenderApprovedResponse(command, output string, session *domain.SessionContext, topology *domain.VirtualTopology) ResponseRenderResult {
	guarded := GuardTerminalOutput(output, session)
	if guarded.Blocked {
		recordResponseGuard(command, session, guarded.Reason)
		return ResponseRenderResult{Output: guarded.Output, Blocked: true, Reason: guarded.Reason}
	}
	factGuarded := GuardResponseFacts(guarded.Output, session, topology)
	if factGuarded.Blocked {
		recordResponseGuard(command, session, factGuarded.Reason)
		return ResponseRenderResult{Output: factGuarded.Output, Blocked: true, Reason: factGuarded.Reason}
	}
	return ResponseRenderResult{Output: factGuarded.Output}
}

// Render dispatches to the appropriate format method based on command type.
// All output is built exclusively from approved facts.
func (r *ResponseAgent) Render(command string, session *domain.SessionContext, ruleOutput string) string {
	if r == nil || command == "" {
		return sanitizeOutput(ruleOutput)
	}
	lower := strings.ToLower(strings.TrimSpace(command))
	cmdBase := extractBaseCommand(lower)

	switch {
	case cmdBase == "nmap":
		return r.RenderNmap(session, command)
	case cmdBase == "fscan", cmdBase == "dddd2", cmdBase == "nuclei":
		return r.RenderFscan(session, command)
	case cmdBase == "curl", cmdBase == "wget":
		return r.RenderCurl(session, command)
	case cmdBase == "ssh", cmdBase == "scp":
		return r.RenderSSH(session, command)
	case cmdBase == "mysql", cmdBase == "mysqldump", cmdBase == "mysqladmin",
		cmdBase == "psql", cmdBase == "pg_dump":
		return r.RenderDB(session, command)
	case cmdBase == "redis-cli":
		return r.RenderRedis(session, command)
	case cmdBase == "nc", cmdBase == "ncat":
		return r.RenderNetcat(session, command)
	case cmdBase == "ping":
		return r.RenderPing(command)
	case cmdBase == "ls", cmdBase == "dir":
		return r.RenderLs(session, command)
	case cmdBase == "cat", cmdBase == "head", cmdBase == "tail", cmdBase == "less":
		return r.RenderCat(session, command)
	case cmdBase == "whoami", cmdBase == "id":
		return r.RenderWhoami(session)
	case cmdBase == "hostname":
		return r.RenderHostname(session)
	case cmdBase == "ifconfig", cmdBase == "ip":
		return r.RenderIfconfig(session)
	case cmdBase == "netstat", cmdBase == "ss":
		return r.RenderNetstat(session)
	case cmdBase == "ps", cmdBase == "top":
		return r.RenderPS(session)
	case cmdBase == "env":
		return r.RenderEnv(session)
	default:
		return sanitizeOutput(ruleOutput)
	}
}

// RenderNmap produces realistic nmap output from topology hosts.
func (r *ResponseAgent) RenderNmap(session *domain.SessionContext, command string) string {
	target := extractTarget(command)
	if target == "" {
		return "Nmap 7.80 ( https://nmap.org )\nNo targets specified.\n"
	}

	var hosts []domain.VirtualHost
	if r.topology != nil {
		hosts = r.topology.AllHosts()
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("Starting Nmap 7.80 ( https://nmap.org ) at %s\n", fakeNmapTimestamp()))
	b.WriteString(fmt.Sprintf("Nmap scan report for %s\n", target))

	filtered := filterHostsForTarget(hosts, target)
	if len(filtered) == 0 {
		b.WriteString("Host is up (0.0010s latency).\n")
		b.WriteString("All 1000 scanned ports are filtered\n")
		return b.String()
	}

	for _, host := range filtered {
		b.WriteString(fmt.Sprintf("Nmap scan report for %s (%s)\n", host.Hostname, host.IP))
		b.WriteString(fmt.Sprintf("Host is up (0.00%02ds latency).\n", rand.Intn(50)))
		if len(host.Services) == 0 {
			b.WriteString("All 1000 scanned ports are filtered\n")
			continue
		}
		for _, svc := range host.Services {
			name := svc.NmapName
			if name == "" {
				name = svc.Protocol
			}
			state := "open"
			if svc.FailureMode == "timeout" || svc.FailureMode == "filtered" {
				state = "filtered"
			}
			b.WriteString(fmt.Sprintf("%-5d/%-5s %-7s %s\n", svc.Port, svc.Protocol, state, name))
		}
	}
	b.WriteString(fmt.Sprintf("Nmap done: %d IP address scanned in %.2f seconds\n", len(filtered), 1.5+rand.Float64()*3))
	return b.String()
}

// RenderFscan produces realistic fscan output.
func (r *ResponseAgent) RenderFscan(session *domain.SessionContext, command string) string {
	target := extractTarget(command)
	var hosts []domain.VirtualHost
	if r.topology != nil {
		hosts = r.topology.AllHosts()
	}
	filtered := filterHostsForTarget(hosts, target)

	var b strings.Builder
	b.WriteString("   ___                              _\n")
	b.WriteString("  / _ \\     Fscan 1.8.4\n")
	b.WriteString(" / /_\\ \\___  ___  __ _ _ __\n")
	b.WriteString("/ /_\\\\ / __|/ __|/ _` | '_ \\\n")
	b.WriteString("\\____/ \\__| \\__ \\ (_| | | | |\n")
	b.WriteString(fmt.Sprintf("Starting scan at %s\n\n", fakeNmapTimestamp()))

	if len(filtered) == 0 {
		b.WriteString("[*] No alive hosts found in target range\n")
		return b.String()
	}

	for _, host := range filtered {
		b.WriteString(fmt.Sprintf("[*] alive %s\n", host.IP))
		b.WriteString(fmt.Sprintf("[+] %s:%s (%s)\n", host.IP, host.Hostname, host.OS))
		for _, svc := range host.Services {
			b.WriteString(fmt.Sprintf("[+] %s:%d open (%s)\n", host.IP, svc.Port, svc.Protocol))
		}
	}
	b.WriteString(fmt.Sprintf("\n[*] Scan complete: %d hosts found\n", len(filtered)))
	return b.String()
}

// RenderCurl produces realistic HTTP response output.
func (r *ResponseAgent) RenderCurl(session *domain.SessionContext, command string) string {
	target := extractTarget(command)
	host := r.lookupHost(target)
	if host == nil {
		return fmt.Sprintf("curl: (6) Could not resolve host: %s\n", target)
	}

	httpSvc := findService(host, "http", "https")
	if httpSvc == nil {
		return fmt.Sprintf("curl: (7) Failed to connect to %s port 80: Connection refused\n", target)
	}

	switch httpSvc.FailureMode {
	case "timeout":
		return "curl: (28) Connection timed out after 30001 ms\n"
	case "connection_refused":
		return fmt.Sprintf("curl: (7) Failed to connect to %s port %d: Connection refused\n", target, httpSvc.Port)
	case "auth_required":
		return "HTTP/1.1 401 Unauthorized\r\nContent-Type: text/html\r\n\r\n<html><body><h1>401 Unauthorized</h1></body></html>\n"
	case "redirect":
		return fmt.Sprintf("HTTP/1.1 302 Found\r\nLocation: https://%s/login\r\n\r\n", host.Hostname)
	default:
		return "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 0\r\n\r\n"
	}
}

// RenderSSH produces realistic SSH connection output.
func (r *ResponseAgent) RenderSSH(session *domain.SessionContext, command string) string {
	target := extractTarget(command)
	host := r.lookupHost(target)
	if host == nil {
		return fmt.Sprintf("ssh: connect to host %s port 22: No route to host\n", target)
	}

	sshSvc := findService(host, "ssh")
	if sshSvc == nil {
		return fmt.Sprintf("ssh: connect to host %s port 22: Connection refused\n", target)
	}

	switch sshSvc.FailureMode {
	case "timeout":
		return fmt.Sprintf("ssh: connect to host %s port 22: Connection timed out\n", target)
	case "auth_failure":
		return "Permission denied, please try again.\n"
	case "password_prompt":
		return fmt.Sprintf("The authenticity of host '%s (%s)' can't be established.\nECDSA key fingerprint is SHA256:%s.\nAre you sure you want to continue connecting (yes/no)? ", target, host.Hostname, fakeSSHFingerprint())
	case "banner_only":
		return fmt.Sprintf("%s\nPermission denied (publickey).\n", sshSvc.Banner)
	case "low_priv":
		if session != nil && session.IsNestedSSH() {
			return fmt.Sprintf("Last login: Mon Jan 15 08:30:12 2024 from %s\n%s@%s:~$ \n", session.SubnetLocalIP, "user", host.Hostname)
		}
		return fmt.Sprintf("Welcome to Ubuntu 22.04.3 LTS\nLast login: Mon Jan 15 08:30:12 2024\nuser@%s:~$ \n", host.Hostname)
	default:
		return "Permission denied, please try again.\n"
	}
}

// RenderDB produces realistic database query output.
func (r *ResponseAgent) RenderDB(session *domain.SessionContext, command string) string {
	target := extractTarget(command)
	host := r.lookupHost(target)
	if host == nil {
		return fmt.Sprintf("ERROR 2003 (HY000): Can't connect to MySQL server on '%s' (111)\n", target)
	}
	mysqlSvc := findService(host, "mysql", "postgresql")
	if mysqlSvc == nil {
		return fmt.Sprintf("ERROR 2003 (HY000): Can't connect to MySQL server on '%s' (111)\n", target)
	}
	switch mysqlSvc.FailureMode {
	case "auth_failure":
		return "ERROR 1045 (28000): Access denied for user 'root'@'localhost' (using password: YES)\n"
	case "empty_db":
		return "Empty set (0.00 sec)\n"
	case "readonly":
		return "ERROR 1142 (42000): INSERT command denied to user 'readonly'@'%' for table 'users'\n"
	default:
		return "mysql: [Warning] Using a password on the command line interface can be insecure.\nEmpty set (0.00 sec)\n"
	}
}

// RenderRedis produces realistic Redis output.
func (r *ResponseAgent) RenderRedis(session *domain.SessionContext, command string) string {
	target := extractTarget(command)
	host := r.lookupHost(target)
	if host == nil {
		return fmt.Sprintf("Could not connect to Redis at %s:6379: No route to host\n", target)
	}
	redisSvc := findService(host, "redis")
	if redisSvc == nil {
		return fmt.Sprintf("Could not connect to Redis at %s:6379: Connection refused\n", target)
	}
	if redisSvc.FailureMode == "auth_required" {
		return "NOAUTH Authentication required.\n"
	}
	return "OK\n"
}

// RenderNetcat produces realistic netcat output.
func (r *ResponseAgent) RenderNetcat(session *domain.SessionContext, command string) string {
	target := extractTarget(command)
	host := r.lookupHost(target)
	if host == nil {
		return fmt.Sprintf("nc: connect to %s port 80 (tcp) failed: No route to host\n", target)
	}
	return fmt.Sprintf("Connection to %s 80 port [tcp/*] succeeded!\n", target)
}

// RenderPing produces realistic ping output.
func (r *ResponseAgent) RenderPing(command string) string {
	target := extractTarget(command)
	if target == "" {
		return "ping: usage error: Destination address required\n"
	}
	if r.safety != nil && !r.safety.IsVirtualIP(target) {
		return fmt.Sprintf("PING %s 56(84) bytes of data.\n64 bytes from %s: icmp_seq=1 ttl=64 time=0.050 ms\n", target, target)
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("PING %s 56(84) bytes of data.\n", target))
	for i := 1; i <= 4; i++ {
		b.WriteString(fmt.Sprintf("64 bytes from %s: icmp_seq=%d ttl=64 time=0.%03d ms\n", target, i, 10+rand.Intn(90)))
	}
	b.WriteString(fmt.Sprintf("\n--- %s ping statistics ---\n4 packets transmitted, 4 received, 0%% packet loss\n", target))
	return b.String()
}

// RenderLs produces realistic ls output from world state.
func (r *ResponseAgent) RenderLs(session *domain.SessionContext, command string) string {
	if session == nil || session.World == nil {
		return "total 0\n"
	}
	dir := extractLsDir(command, session.CWD)
	entries := session.World.GetDirectoryListing(dir)
	if len(entries) == 0 {
		return "total 0\n"
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("total %d\n", len(entries)*4))
	for _, e := range entries {
		b.WriteString(fmt.Sprintf("%s %3s %-8s %-8s %6s %s %s\n",
			e["permissions"], e["links"], e["owner"], e["group"],
			e["size"], e["mtime"], e["name"]))
	}
	return b.String()
}

// RenderCat produces realistic cat output from world state.
func (r *ResponseAgent) RenderCat(session *domain.SessionContext, command string) string {
	if session == nil || session.World == nil {
		return ""
	}
	filePath := extractCatFile(command, session.CWD)
	content := session.World.ReadFile(filePath)
	if content == "" {
		return fmt.Sprintf("cat: %s: No such file or directory\n", filePath)
	}
	return content
}

// RenderWhoami produces user identity output.
func (r *ResponseAgent) RenderWhoami(session *domain.SessionContext) string {
	if session == nil {
		return "root\n"
	}
	if session.IsNestedSSH() {
		return "user\n"
	}
	return session.User + "\n"
}

// RenderHostname produces hostname output.
func (r *ResponseAgent) RenderHostname(session *domain.SessionContext) string {
	if session == nil {
		return "localhost\n"
	}
	return session.Hostname + "\n"
}

// RenderIfconfig produces realistic ifconfig/ip addr output.
func (r *ResponseAgent) RenderIfconfig(session *domain.SessionContext) string {
	if session == nil {
		return "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
	}
	var b strings.Builder
	b.WriteString("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n")
	b.WriteString(fmt.Sprintf("        inet %s  netmask 255.255.255.0  broadcast %s.255\n", session.SubnetLocalIP, extractSubnetBase(session.SubnetLocalIP)))
	b.WriteString(fmt.Sprintf("        inet6 fe80::%s  prefixlen 64  scopeid 0x20<link>\n", fakeIPv6Suffix()))
	b.WriteString(fmt.Sprintf("        ether %s  txqueuelen 1000  (Ethernet)\n", fakeMACAddress()))
	b.WriteString("        RX packets 284731  bytes 342156789 (326.3 MiB)\n")
	b.WriteString("        TX packets 129384  bytes 18234756 (17.3 MiB)\n")
	return b.String()
}

// RenderNetstat produces realistic netstat/ss output.
func (r *ResponseAgent) RenderNetstat(session *domain.SessionContext) string {
	if session == nil || r.registry == nil {
		return "Active Internet connections\nProto Recv-Q Send-Q Local Address           Foreign Address         State\n"
	}
	return r.registry.GetSSOutput(session, session.SubnetLocalIP)
}

// RenderPS produces realistic ps output.
func (r *ResponseAgent) RenderPS(session *domain.SessionContext) string {
	return `  PID TTY          TIME CMD
    1 ?        00:00:02 systemd
  423 ?        00:00:00 sshd
  587 ?        00:00:01 mysqld
  612 ?        00:00:00 redis-server
  723 ?        00:00:00 nginx
  891 ?        00:00:00 bash
  904 ?        00:00:00 ps
`
}

// RenderEnv produces realistic env output.
func (r *ResponseAgent) RenderEnv(session *domain.SessionContext) string {
	if session == nil {
		return "HOME=/root\nUSER=root\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
	}
	return fmt.Sprintf("HOME=/home/%s\nUSER=%s\nPWD=%s\nSHELL=/bin/bash\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nHOSTNAME=%s\n", session.User, session.User, session.CWD, session.Hostname)
}

// ---- Helpers --------------------------------------------------------------

func (r *ResponseAgent) lookupHost(target string) *domain.VirtualHost {
	if r.topology == nil || target == "" {
		return nil
	}
	return r.topology.GetHost(target)
}

var reBaseCommand = regexp.MustCompile(`^(\w[\w-]*)`)

func extractBaseCommand(lower string) string {
	match := reBaseCommand.FindString(lower)
	return match
}

var reTarget = regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)`)

func extractTarget(command string) string {
	match := reTarget.FindString(command)
	return match
}

func filterHostsForTarget(hosts []domain.VirtualHost, target string) []domain.VirtualHost {
	if target == "" {
		return hosts
	}
	var filtered []domain.VirtualHost
	for _, h := range hosts {
		if h.IP == target || strings.HasPrefix(h.IP, extractSubnetBase(target)) {
			filtered = append(filtered, h)
		}
	}
	if len(filtered) == 0 {
		for _, h := range hosts {
			if h.IP == target {
				filtered = append(filtered, h)
			}
		}
	}
	return filtered
}

func extractSubnetBase(ip string) string {
	lastDot := strings.LastIndex(ip, ".")
	if lastDot < 0 {
		return ip
	}
	return ip[:lastDot] + "."
}

func findService(host *domain.VirtualHost, protocols ...string) *domain.VirtualService {
	if host == nil {
		return nil
	}
	for i := range host.Services {
		for _, p := range protocols {
			if host.Services[i].Protocol == p {
				return &host.Services[i]
			}
		}
	}
	return nil
}

func fakeNmapTimestamp() string {
	return time.Now().UTC().Format("2006-01-02 15:04 UTC")
}

func fakeSSHFingerprint() string {
	hex := "0123456789abcdef"
	var b strings.Builder
	for i := 0; i < 43; i++ {
		b.WriteByte(hex[rand.Intn(len(hex))])
		if i > 0 && i%2 == 1 && i < 42 {
			b.WriteByte(':')
		}
	}
	return b.String()
}

func fakeMACAddress() string {
	hex := "0123456789abcdef"
	var b strings.Builder
	for i := 0; i < 6; i++ {
		b.WriteByte(hex[rand.Intn(len(hex))])
		b.WriteByte(hex[rand.Intn(len(hex))])
		if i < 5 {
			b.WriteByte(':')
		}
	}
	return b.String()
}

func fakeIPv6Suffix() string {
	hex := "0123456789abcdef"
	var b strings.Builder
	for i := 0; i < 16; i++ {
		b.WriteByte(hex[rand.Intn(len(hex))])
		b.WriteByte(hex[rand.Intn(len(hex))])
		if i < 15 {
			b.WriteByte(':')
		}
	}
	return b.String()
}

func recordResponseGuard(command string, session *domain.SessionContext, reason string) {
	if session == nil {
		return
	}
	session.AppendEvent(domain.EventEntry{
		Type:      "response_agent_blocked",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		SessionID: session.SessionID,
		Detail:    fmt.Sprintf("%s:%s", reason, command),
	})
	if session.Planning != nil {
		session.Planning.BumpExposedFactVersion("response_block:" + reason)
	}
}

func sanitizeOutput(output string) string {
	output = strings.TrimSpace(output)
	if len(output) > 2000 {
		output = output[:1997] + "..."
	}
	return output
}

func extractLsDir(command, cwd string) string {
	// Remove the command prefix (ls, dir) and flags
	parts := strings.Fields(command)
	var args []string
	for _, p := range parts[1:] {
		if !strings.HasPrefix(p, "-") {
			args = append(args, p)
		}
	}
	if len(args) > 0 {
		return resolvePath(args[0], cwd)
	}
	return cwd
}

func extractCatFile(command, cwd string) string {
	parts := strings.Fields(command)
	for _, p := range parts[1:] {
		if !strings.HasPrefix(p, "-") {
			return resolvePath(p, cwd)
		}
	}
	return ""
}

func resolvePath(p, cwd string) string {
	if strings.HasPrefix(p, "/") {
		return p
	}
	if cwd == "/" {
		return "/" + p
	}
	return cwd + "/" + p
}
