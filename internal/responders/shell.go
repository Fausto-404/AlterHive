package responders

import (
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/alterhive/alterhive/internal/domain"
)

var (
	psAux = `  PID TTY      STAT   TIME COMMAND
    1 ?        Ss     0:03 /sbin/init
  412 ?        Ss     0:00 /usr/sbin/sshd -D
  523 ?        S      0:12 python3 /opt/webapp/app.py
  524 ?        Sl     0:45 gunicorn: worker [webapp]
  525 ?        Sl     0:42 gunicorn: worker [webapp]
  678 ?        Ssl    1:15 /usr/sbin/mysqld
  892 pts/0    Ss     0:00 bash
`

	netstatOutput = `Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:5000            0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN
`

	ssTlnp = `State    Recv-Q   Send-Q     Local Address:Port     Peer Address:Port  Process
LISTEN   0        128              0.0.0.0:22            0.0.0.0:*      users:(("sshd",pid=412,fd=3))
LISTEN   0        128              0.0.0.0:5000          0.0.0.0:*      users:(("python3",pid=523,fd=4))
LISTEN   0        128            127.0.0.1:3306          0.0.0.0:*      users:(("mysqld",pid=678,fd=23))
LISTEN   0        511              0.0.0.0:80            0.0.0.0:*      users:(("nginx",pid=345,fd=6))
`

	ipAddrTemplate = `1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP
    link/ether 00:0c:29:97:02:01 brd ff:ff:ff:ff:ff:ff
    inet %s/%s brd %s scope global eth0
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP
    link/ether 00:0c:29:56:23:01 brd ff:ff:ff:ff:ff:ff
    inet %s/%s brd %s scope global eth1
`

	ipRouteTemplate = `default via %s dev eth0 proto dhcp metric 100
%s dev eth0 proto kernel scope link src %s
%s dev eth1 proto kernel scope link src %s
`

	arpTable = `? (192.168.56.1) at 00:50:56:xx:xx:01 [ether] on eth0
? (192.168.56.50) at 00:50:56:xx:xx:02 [ether] on eth0
? (192.168.56.60) at 00:50:56:xx:xx:03 [ether] on eth0
? (192.168.56.80) at 00:50:56:xx:xx:04 [ether] on eth0
`

	dfH = `Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        40G   13G   25G  32% /
/dev/sdb1       100G   48G   48G  48% /opt
tmpfs           3.9G     0  3.9G   0% /dev/shm
`

	freeH = `              total        used        free      shared  buff/cache   available
Mem:          7.8Gi       3.2Gi       1.1Gi       256Mi       3.5Gi       4.1Gi
Swap:         2.0Gi       128Mi       1.9Gi
`

	systemctlList = `  nginx.service           loaded active running The nginx HTTP and reverse proxy server
  ssh.service             loaded active running OpenBSD Secure Shell server
  mysql.service           loaded active running MySQL Community Server
  webapp.service          loaded active running Web Application Service
  deploy-agent.service    loaded active running Jenkins deployment sidecar
  redis-sidecar.service   loaded active running Redis cache sidecar
  cron.service            loaded active running Regular background program processing daemon
  rsyslog.service         loaded active running System Logging Service
`

	systemctlWebappStatus = `● webapp.service - Web Application Service
     Loaded: loaded (/etc/systemd/system/webapp.service; enabled; vendor preset: enabled)
     Active: active (running) since Mon 2024-01-15 08:12:33 UTC; 45 days ago
   Main PID: 523 (python3)
      Tasks: 7 (limit: 9458)
     Memory: 248.6M
        CPU: 12min 34.120s
     CGroup: /system.slice/webapp.service
             ├─523 python3 /opt/webapp/app.py
             ├─524 gunicorn: worker [webapp]
             └─525 gunicorn: worker [webapp]

Jan 15 08:12:34 staging-web-01 webapp[523]: Loaded config /opt/webapp/.env
Jan 15 08:12:34 staging-web-01 webapp[523]: Connected to MySQL at 192.168.56.60:3306
Jan 15 08:12:34 staging-web-01 webapp[523]: Redis cache available at 192.168.56.30:6379
Jan 15 08:25:12 staging-web-01 webapp[523]: GitLab webhook timeout http://192.168.56.80/devops/webapp
Jan 15 09:00:00 staging-web-01 deploy-agent[811]: Jenkins job webapp-deploy queued at http://192.168.56.45:8080
`

	journalctl = `Jan 15 08:12:33 staging-web-01 systemd[1]: Started Web Application Service.
Jan 15 08:12:34 staging-web-01 webapp[523]: Connected to MySQL at 192.168.56.60:3306
Jan 15 08:12:34 staging-web-01 webapp[523]: Redis connected at 192.168.56.30:6379
Jan 15 08:15:01 staging-web-01 kernel: [842312.123] Memory cgroup out of memory: Killed process 1234 (python3)
Jan 15 08:20:45 staging-web-01 webapp[523]: Health check passed
Jan 15 08:25:12 staging-web-01 webapp[523]: Connection timeout to gitlab-internal (192.168.56.80)
Jan 15 08:30:00 staging-web-01 CRON[892]: (root) CMD /opt/webapp/scripts/backup.sh
Jan 15 09:00:00 staging-web-01 deploy-agent[811]: Jenkins deploy webhook received from 192.168.56.45
`

	topOutput = `top - 14:23:01 up 45 days,  3:12,  1 user,  load average: 0.08, 0.03, 0.01
Tasks: 127 total,   1 running, 126 sleeping,   0 stopped,   0 zombie
%Cpu(s):  2.3 us,  0.7 sy,  0.0 ni, 96.8 id,  0.2 wa,  0.0 hi,  0.0 si,  0.0 st
MiB Mem:   7987.6 total,   1126.4 free,   3276.8 used,   3584.4 buff/cache
MiB Swap:   2048.0 total,   1920.0 free,    128.0 used.   4198.4 avail Mem

    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
    678 mysql     20   0 1823456 345678  12345 S   1.3   4.2  45:23.45 mysqld
    523 www-data  20   0  234567  45678   3456 S   0.7   0.6  12:34.56 python3
    524 www-data  20   0  234567  34567   2345 S   0.3   0.4   8:12.34 gunicorn
    412 root      20   0  123456  12345   2345 S   0.0   0.2   0:03.45 sshd
      1 root      20   0  169472  13456   8765 S   0.0   0.2   0:05.67 systemd
`

	lastOutput = `root     pts/0        192.168.56.23    Mon Jan 15 08:00   still logged in
deploy   pts/1        192.168.56.50    Sun Jan 14 22:30 - 23:45  (01:15)
root     pts/0        192.168.56.1     Sat Jan 13 14:20 - 16:30  (02:10)
ansible  pts/2        192.168.56.50    Fri Jan 12 09:00 - 09:15  (00:15)
`

	wOutput = ` 14:23:01 up 45 days,  3:12,  1 user,  load average: 0.08, 0.03, 0.01
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
root     pts/0    192.168.56.23    08:00    0.00s  0.12s  0.01s w
`

	ifconfigTemplate = `eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet %s  netmask 255.255.255.0  broadcast %s
        inet6 fe80::20c:29ff:feab:cdef  prefixlen 64  scopeid 0x20<link>
        ether 00:0c:29:97:02:01  txqueuelen 1000  (Ethernet)
        RX packets 1234567  bytes 987654321 (987.6 MB)
        TX packets 987654  bytes 123456789 (123.4 MB)

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet %s  netmask 255.255.255.0  broadcast %s
        inet6 fe80::20c:29ff:fe56:2301  prefixlen 64  scopeid 0x20<link>
        ether 00:0c:29:56:23:01  txqueuelen 1000  (Ethernet)
        RX packets 1234567  bytes 987654321 (987.6 MB)
        TX packets 987654  bytes 123456789 (123.4 MB)

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
`

	envTemplate = `DB_HOST=192.168.56.60
DB_PORT=3306
DB_NAME=fin_readonly_cny42
DB_USER=web_ro
DB_PASSWORD=WebApp@2024!Ro
REDIS_HOST=192.168.56.30
REDIS_PORT=6379
APP_ENV=production
APP_DEBUG=false
APP_SECRET_KEY=sk-cny42-prod-a8f3e2b1c9d7
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOME=/opt/webapp
SHELL=/bin/bash
USER=%s
PWD=%s
`

	whichMap = map[string]string{
		"python3":       "/usr/bin/python3",
		"python":        "/usr/bin/python3",
		"mysql":         "/usr/bin/mysql",
		"psql":          "/usr/bin/psql",
		"pg_dump":       "/usr/bin/pg_dump",
		"curl":          "/usr/bin/curl",
		"wget":          "/usr/bin/wget",
		"ssh":           "/usr/bin/ssh",
		"scp":           "/usr/bin/scp",
		"ping":          "/usr/bin/ping",
		"dig":           "/usr/bin/dig",
		"ldapsearch":    "/usr/bin/ldapsearch",
		"smbclient":     "/usr/bin/smbclient",
		"nmap":          "/usr/bin/nmap",
		"fscan":         "/usr/local/bin/fscan",
		"dddd2":         "/usr/local/bin/dddd2",
		"nuclei":        "/usr/local/bin/nuclei",
		"gobuster":      "/usr/bin/gobuster",
		"ffuf":          "/usr/bin/ffuf",
		"sqlmap":        "/usr/bin/sqlmap",
		"sliver-client": "/usr/local/bin/sliver-client",
		"msfconsole":    "/usr/bin/msfconsole",
		"kubectl":       "/usr/local/bin/kubectl",
		"docker":        "/usr/bin/docker",
		"gitlab-rake":   "/opt/gitlab/bin/gitlab-rake",
		"gitlab-rails":  "/opt/gitlab/bin/gitlab-rails",
		"jenkins-cli":   "/usr/local/bin/jenkins-cli",
		"java":          "/usr/bin/java",
	}
)

// HandleShellCommand processes standard Unix commands.
// Returns (output, handled). handled=true means the command was recognized.
func HandleShellCommand(cmd string, session *domain.SessionContext, world *domain.WorldState, registry *domain.ServiceRegistry) (string, bool) {
	cmd = strings.TrimSpace(cmd)
	if strings.Contains(cmd, " | ") {
		return handleSimplePipeline(cmd, session, world, registry)
	}
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return "", true
	}
	cmdBase := parts[0]

	switch cmdBase {
	case "whoami":
		return session.User + "\n", true

	case "id":
		if session.User == "root" {
			return "uid=0(root) gid=0(root) groups=0(root)\n", true
		}
		return fmt.Sprintf("uid=33(%s) gid=33(%s) groups=33(%s)\n", session.User, session.User, session.User), true

	case "hostname":
		return session.Hostname + "\n", true

	case "pwd":
		return session.CWD + "\n", true

	case "uname":
		if len(parts) > 1 {
			switch parts[1] {
			case "-a":
				return fmt.Sprintf("Linux %s 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\n", session.Hostname), true
			case "-r":
				return "5.15.0-91-generic\n", true
			case "-n":
				return session.Hostname + "\n", true
			case "-s":
				return "Linux\n", true
			}
		}
		return "Linux\n", true

	case "ls":
		out := handleLs(parts[1:], session, world)
		if out == "" {
			// ls returned nothing — decide whether to suppress or let LLM generate.
			// Only suppress when the directory is explicitly known in the world state
			// AND all its files are hidden (so ls without -a legitimately shows nothing).
			target := resolveLsTarget(parts[1:], session)
			if world.IsDir(target) {
				allFiles := world.ListFiles(target)
				if len(allFiles) > 0 && allHidden(allFiles) {
					return "", true // correct empty — all files are dotfiles
				}
			}
			// Directory unknown or has no files — let LLM generate realistic content
			return "", false
		}
		return out, true

	case "cat":
		out := handleCat(parts[1:], session, world)
		if out == "" {
			// Check if the file exists in world state
			if catTargetExists(parts[1:], session, world) {
				return "", true // File exists but is empty
			}
			// File not found — let LLM fallback generate content
			return "", false
		}
		return out, true

	case "grep":
		return handleGrep(parts[1:], session, world), true

	case "head", "tail":
		return handleHeadTail(parts, session, world), true

	case "wc":
		return handleWc(parts[1:], session, world), true

	case "env", "printenv":
		if session.IsNestedSSH() {
			return "", false
		}
		return fmt.Sprintf(envTemplate, session.User, session.CWD), true

	case "ps":
		if session.IsNestedSSH() {
			return "", false // LLM generates host-appropriate process list
		}
		return psAux, true

	case "netstat":
		if session.IsNestedSSH() {
			return "", false
		}
		if registry != nil {
			return registry.GetListeningServices(session, localIP(session)), true
		}
		return netstatOutput, true

	case "ss":
		if session.IsNestedSSH() {
			return "", false
		}
		if registry != nil {
			return registry.GetSSOutput(session, localIP(session)), true
		}
		return ssTlnp, true

	case "ip":
		if len(parts) > 1 {
			switch parts[1] {
			case "addr", "a", "address":
				return buildIPAddr(session), true
			case "route", "r":
				return buildIPRoute(session), true
			}
		}
		return buildIPAddr(session), true

	case "arp":
		if session.IsNestedSSH() {
			return "", false
		}
		if registry != nil {
			if table := registry.GetArpTable(session, localIP(session)); table != "" {
				return table, true
			}
		}
		return arpTable, true

	case "df":
		if session.IsNestedSSH() {
			return "", false
		}
		return dfH, true

	case "free":
		if session.IsNestedSSH() {
			return "", false
		}
		return freeH, true

	case "top", "htop":
		if session.IsNestedSSH() {
			return "", false
		}
		return topOutput, true

	case "systemctl":
		if session.IsNestedSSH() {
			return "", false
		}
		if len(parts) > 2 && (parts[1] == "start" || parts[1] == "stop" || parts[1] == "restart") {
			return "Failed to " + parts[1] + " " + parts[2] + ": Access denied\n", true
		}
		if len(parts) > 2 && parts[1] == "status" && parts[2] == "webapp" {
			return systemctlWebappStatus, true
		}
		return systemctlList, true

	case "journalctl":
		if session.IsNestedSSH() {
			return "", false
		}
		return journalctl, true

	case "last":
		if session.IsNestedSSH() {
			return "", false
		}
		return lastOutput, true

	case "w", "who":
		if session.IsNestedSSH() {
			return "", false
		}
		return wOutput, true

	case "ifconfig":
		return buildIfconfig(session), true

	case "traceroute":
		return handleTraceroute(parts[1:]), true

	case "ping":
		return handlePing(parts[1:], session, registry), true

	case "find":
		return handleFind(parts[1:], world, session), true

	case "which":
		var found []string
		for _, name := range parts[1:] {
			if p, ok := whichMap[name]; ok {
				found = append(found, p)
			}
		}
		if len(found) > 0 {
			return strings.Join(found, "\n") + "\n", true
		}
		return "", true

	case "gitlab-rake":
		return handleGitLabRake(cmd), true

	case "gitlab-rails":
		return handleGitLabRails(cmd), true

	case "jenkins-cli":
		return handleJenkinsCLI(cmd), true

	case "java":
		if strings.Contains(cmd, "jenkins-cli.jar") {
			return handleJenkinsCLI(cmd), true
		}
		return "openjdk version \"11.0.22\" 2024-01-16\nOpenJDK Runtime Environment (build 11.0.22+7-post-Ubuntu-0ubuntu222.04.1)\nOpenJDK 64-Bit Server VM (build 11.0.22+7-post-Ubuntu-0ubuntu222.04.1, mixed mode, sharing)\n", true

	case "echo":
		if len(parts) > 1 {
			// Check for redirect operators
			fullArgs := strings.Join(parts[1:], " ")
			if idx := strings.Index(fullArgs, " >> "); idx >= 0 {
				content := fullArgs[:idx]
				target := strings.TrimSpace(fullArgs[idx+4:])
				if !strings.HasPrefix(target, "/") {
					target = path.Clean(session.CWD + "/" + target)
				}
				world.AddFile(target, domain.NewFileEntry(content+"\n"))
				return "", true
			}
			if idx := strings.Index(fullArgs, " > "); idx >= 0 {
				content := fullArgs[:idx]
				target := strings.TrimSpace(fullArgs[idx+3:])
				if !strings.HasPrefix(target, "/") {
					target = path.Clean(session.CWD + "/" + target)
				}
				world.AddFile(target, domain.NewFileEntry(content+"\n"))
				return "", true
			}
			return fullArgs + "\n", true
		}
		return "\n", true

	case "cd":
		return handleCd(parts[1:], session, world), true

	case "touch":
		return "", true

	case "export", "set", "unset", "alias":
		return "", true

	case "clear":
		return "\x1bc", true

	case "exit", "quit", "logout":
		// If in nested SSH, don't handle here - let SSH handler manage it
		if session.IsNestedSSH() {
			return "", false
		}
		return "logout\n", true

	case "mkdir", "rm", "cp", "mv", "chmod", "chown":
		return cmdBase + ": Permission denied\n", true

	case "apt", "apt-get", "yum", "dnf", "pip", "npm":
		return cmdBase + ": Permission denied\n", true

	case "python3", "python":
		session.ShellMode = "python"
		return "Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0] on linux\nType \"help\", \"copyright\", \"credits\" or \"license\" for more information.\n", true

	case "man", "less", "more", "vi", "vim", "nano":
		return cmdBase + ": terminal not available in this session\n", true

	case "history":
		if session.IsNestedSSH() {
			return "", false
		}
		return `    1  mysql -h 192.168.56.60 -u web_ro -p
    2  cat /opt/webapp/.env
    3  systemctl status webapp
    4  docker ps
    5  kubectl get pods
    6  ssh ansible@192.168.56.10
    7  curl http://192.168.56.80
    8  cat /var/log/nginx/access.log
    9  tail -f /opt/webapp/logs/app.log
   10  grep -Ri token /opt/webapp
`, true

	case "sudo":
		if session.IsNestedSSH() {
			return "", false
		}
		return handleSudo(parts[1:], session), true

	case "crontab":
		if session.IsNestedSSH() {
			return "", false
		}
		if len(parts) > 1 && parts[1] == "-l" {
			return handleCrontab(session), true
		}
		return "crontab: you are not allowed to use 'crontab -e'\n", true

	case "date":
		if session.IsNestedSSH() {
			return "", false
		}
		return "Mon Jan 15 09:15:33 UTC 2024\n", true

	case "uptime":
		if session.IsNestedSSH() {
			return "", false
		}
		return " 09:15:33 up 45 days,  3:15,  1 user,  load average: 0.08, 0.03, 0.01\n", true

	case "lsblk":
		if session.IsNestedSSH() {
			return "", false
		}
		return `NAME   MAJ:MIN RM   SIZE RO TYPE MOUNTPOINT
sda      8:0    0    40G  0 disk
├─sda1   8:1    0    40G  0 part /
sdb      8:16   0   100G  0 disk
└─sdb1   8:17   0   100G  0 part /opt
`, true

	case "lscpu":
		if session.IsNestedSSH() {
			return "", false
		}
		return `Architecture:           x86_64
CPU op-mode(s):         32-bit, 64-bit
Address sizes:          43 bits physical, 48 bits virtual
Byte Order:             Little Endian
CPU(s):                 4
On-line CPU(s) list:    0-3
Vendor ID:              GenuineIntel
Model name:             Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz
CPU MHz:                2399.996
Cache L1d:              32 KiB
Cache L1i:              32 KiB
Cache L2:               256 KiB
Cache L3:               35 MiB
`, true

	case "lsb_release":
		if session.IsNestedSSH() {
			return "", false
		}
		if len(parts) > 1 && parts[1] == "-a" {
			return `Distributor ID:	Ubuntu
Description:	Ubuntu 22.04.3 LTS
Release:	22.04
Codename:	jammy
`, true
		}
		return "Ubuntu 22.04.3 LTS\n", true

	case "file":
		if len(parts) > 1 {
			fp := parts[len(parts)-1]
			if !strings.HasPrefix(fp, "/") {
				fp = path.Clean(session.CWD + "/" + fp)
			}
			entry := world.GetFileEntry(fp)
			if entry == nil {
				return fmt.Sprintf("%s: cannot open `%s' (No such file or directory)\n", fp, parts[len(parts)-1]), true
			}
			if entry.Permissions[0] == 'd' {
				return fmt.Sprintf("%s: directory\n", fp), true
			}
			if strings.HasSuffix(fp, ".py") {
				return fmt.Sprintf("%s: Python script, ASCII text executable\n", fp), true
			}
			if strings.HasSuffix(fp, ".sh") {
				return fmt.Sprintf("%s: Bourne-Again shell script, ASCII text executable\n", fp), true
			}
			if strings.HasSuffix(fp, ".yml") || strings.HasSuffix(fp, ".yaml") {
				return fmt.Sprintf("%s: YAML script, ASCII text\n", fp), true
			}
			if strings.HasSuffix(fp, ".html") {
				return fmt.Sprintf("%s: HTML document, ASCII text\n", fp), true
			}
			if strings.HasSuffix(fp, ".log") {
				return fmt.Sprintf("%s: ASCII text\n", fp), true
			}
			if strings.Contains(fp, ".ssh/id_rsa") || strings.Contains(fp, ".ssh/id_ed25519") {
				return fmt.Sprintf("%s: PEM RSA private key\n", fp), true
			}
			return fmt.Sprintf("%s: ASCII text\n", fp), true
		}
		return "file: missing operand\n", true

	case "strings":
		if len(parts) > 1 {
			fp := parts[len(parts)-1]
			if !strings.HasPrefix(fp, "/") {
				fp = path.Clean(session.CWD + "/" + fp)
			}
			entry := world.GetFileEntry(fp)
			if entry == nil {
				return fmt.Sprintf("strings: '%s': No such file\n", parts[len(parts)-1]), true
			}
			lines := strings.Split(entry.Content, "\n")
			if len(lines) > 20 {
				lines = lines[:20]
			}
			return strings.Join(lines, "\n") + "\n", true
		}
		return "strings: missing operand\n", true

	case "wget":
		return "wget: missing URL\nUsage: wget [OPTION]... [URL]...\n", true

	case "scp":
		return "scp: missing file operand\n", true

	case "tar":
		return "tar: Cowardly refusing to create an empty archive\nTry 'tar --help' or 'tar --usage' for more information.\n", true

	case "zip", "unzip", "gzip", "gunzip":
		return cmdBase + ": Permission denied\n", true

	case "base64", "xxd", "hexdump":
		if len(parts) > 1 {
			fp := parts[len(parts)-1]
			if !strings.HasPrefix(fp, "/") {
				fp = path.Clean(session.CWD + "/" + fp)
			}
			entry := world.GetFileEntry(fp)
			if entry == nil {
				return fmt.Sprintf("%s: %s: No such file or directory\n", cmdBase, parts[len(parts)-1]), true
			}
			if cmdBase == "base64" {
				return "[base64 encoded content - " + fmt.Sprintf("%d", len(entry.Content)) + " bytes]\n", true
			}
			return entry.Content[:min(500, len(entry.Content))] + "\n", true
		}
		return cmdBase + ": missing operand\n", true

	case "su":
		return "su: Authentication failure\n", true

	default:
		return "", false
	}
}

// HandlePythonREPL processes commands inside the Python REPL.
func HandlePythonREPL(cmd string, session *domain.SessionContext, world *domain.WorldState) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return ""
	}

	// Exit Python REPL
	if cmd == "exit()" || cmd == "quit()" || cmd == "exit" || cmd == "quit" {
		session.ShellMode = "bash"
		return ""
	}

	// import statements — silently succeed
	if strings.HasPrefix(cmd, "import ") || strings.HasPrefix(cmd, "from ") {
		return ""
	}

	// print() — extract and output the argument
	if strings.HasPrefix(cmd, "print(") && strings.HasSuffix(cmd, ")") {
		arg := cmd[6 : len(cmd)-1]
		arg = strings.Trim(arg, `"'`)
		arg = strings.ReplaceAll(arg, "f'", "")
		arg = strings.ReplaceAll(arg, `f"`, "")

		// If the argument is a function call, evaluate it
		if strings.HasPrefix(arg, "os.listdir") || strings.HasPrefix(arg, "os.getcwd") {
			innerResult := HandlePythonREPL(arg, session, world)
			return innerResult
		}
		return arg + "\n"
	}

	// os.listdir()
	if cmd == "os.listdir()" || cmd == "os.listdir('.')" {
		files := world.ListFiles(session.CWD)
		return fmt.Sprintf("%s\n", pythonRepr(files))
	}
	if strings.HasPrefix(cmd, "os.listdir(") {
		arg := cmd[11:]
		arg = strings.TrimRight(arg, ")")
		arg = strings.Trim(arg, `"'`)
		if !strings.HasPrefix(arg, "/") {
			arg = path.Clean(session.CWD + "/" + arg)
		}
		files := world.ListFiles(arg)
		return fmt.Sprintf("%s\n", pythonRepr(files))
	}

	// os.getcwd()
	if cmd == "os.getcwd()" {
		return fmt.Sprintf("'%s'\n", session.CWD)
	}

	if cmd == "1+1" || cmd == "2" {
		return "2\n"
	}
	if strings.Contains(cmd, "+") && !strings.Contains(cmd, "=") {
		return evalTinyPythonExpression(cmd)
	}

	// os.chdir()
	if strings.HasPrefix(cmd, "os.chdir(") {
		arg := cmd[9:]
		arg = strings.TrimRight(arg, ")")
		arg = strings.Trim(arg, `"'`)
		if arg == ".." {
			session.CWD = path.Dir(session.CWD)
		} else if strings.HasPrefix(arg, "/") {
			session.CWD = arg
		} else {
			session.CWD = path.Clean(session.CWD + "/" + arg)
		}
		return ""
	}

	// os.system() — delegate to shell
	if strings.HasPrefix(cmd, "os.system(") {
		arg := cmd[10:]
		arg = strings.TrimRight(arg, ")")
		arg = strings.Trim(arg, `"'`)
		output, _ := HandleShellCommand(arg, session, world, nil)
		if output != "" {
			return output
		}
		return "0\n"
	}

	// subprocess.run / subprocess.call
	if strings.HasPrefix(cmd, "subprocess.") {
		start := strings.Index(cmd, "[")
		end := strings.LastIndex(cmd, "]")
		if start >= 0 && end > start {
			raw := cmd[start+1 : end]
			parts := strings.Split(raw, ",")
			var cleanParts []string
			for _, p := range parts {
				p = strings.Trim(strings.TrimSpace(p), `"'`)
				if p != "" {
					cleanParts = append(cleanParts, p)
				}
			}
			if len(cleanParts) > 0 {
				shellCmd := strings.Join(cleanParts, " ")
				output, _ := HandleShellCommand(shellCmd, session, world, nil)
				if output != "" {
					return output
				}
				return ""
			}
		}
		return ""
	}

	// Variable assignment — silently succeed
	if strings.Contains(cmd, "=") && !strings.Contains(cmd, "==") {
		return ""
	}

	// Simple expressions that return values
	if cmd == "os" || cmd == "sys" || cmd == "subprocess" {
		return fmt.Sprintf("<module '%s' (built-in)>\n", cmd)
	}

	if strings.HasPrefix(cmd, "os.path.") {
		return ""
	}

	// Unknown expression — NameError
	return fmt.Sprintf("Traceback (most recent call last):\n  File \"<stdin>\", line 1, in <module>\nNameError: name '%s' is not defined\n", strings.Split(cmd, "(")[0])
}

func evalTinyPythonExpression(cmd string) string {
	parts := strings.Split(cmd, "+")
	if len(parts) != 2 {
		return fmt.Sprintf("Traceback (most recent call last):\n  File \"<stdin>\", line 1, in <module>\nSyntaxError: invalid syntax\n")
	}
	left, errLeft := strconv.Atoi(strings.TrimSpace(parts[0]))
	right, errRight := strconv.Atoi(strings.TrimSpace(parts[1]))
	if errLeft != nil || errRight != nil {
		return fmt.Sprintf("Traceback (most recent call last):\n  File \"<stdin>\", line 1, in <module>\nNameError: name '%s' is not defined\n", strings.TrimSpace(parts[0]))
	}
	return fmt.Sprintf("%d\n", left+right)
}

func pythonRepr(items []string) string {
	var quoted []string
	for _, item := range items {
		quoted = append(quoted, fmt.Sprintf("'%s'", item))
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

// allHidden returns true if every file name starts with ".".
func allHidden(files []string) bool {
	for _, f := range files {
		if !strings.HasPrefix(f, ".") {
			return false
		}
	}
	return true
}

// resolveLsTarget returns the absolute directory path that ls would list.
func resolveLsTarget(args []string, session *domain.SessionContext) string {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			if strings.HasPrefix(a, "/") {
				return a
			}
			return path.Clean(session.CWD + "/" + a)
		}
	}
	return session.CWD
}

func handleLs(args []string, session *domain.SessionContext, world *domain.WorldState) string {
	showAll := false
	longFormat := false
	target := ""

	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			if strings.Contains(a, "a") {
				showAll = true
			}
			if strings.Contains(a, "l") {
				longFormat = true
			}
		} else {
			target = a
		}
	}

	if target == "" {
		target = session.CWD
	} else if !strings.HasPrefix(target, "/") {
		target = path.Clean(session.CWD + "/" + target)
	}

	if longFormat {
		return lsLong(target, showAll, world)
	}

	files := world.ListFiles(target)
	if !showAll {
		var filtered []string
		for _, f := range files {
			if !strings.HasPrefix(f, ".") {
				filtered = append(filtered, f)
			}
		}
		files = filtered
	}
	if len(files) == 0 {
		return ""
	}
	return strings.Join(files, "  ") + "\n"
}

func lsLong(dir string, showAll bool, world *domain.WorldState) string {
	entries := world.GetDirectoryListing(dir)
	var lines []string
	for _, e := range entries {
		if !showAll && strings.HasPrefix(e["name"], ".") {
			continue
		}
		lines = append(lines, fmt.Sprintf("%s %s %s %s %6s %s %s",
			e["permissions"], e["links"], e["owner"], e["group"],
			e["size"], e["mtime"], e["name"]))
	}
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

// catTargetExists checks if the target file exists in the world state.
func catTargetExists(args []string, session *domain.SessionContext, world *domain.WorldState) bool {
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		filePath := arg
		if !strings.HasPrefix(filePath, "/") {
			filePath = path.Clean(session.CWD + "/" + filePath)
		}
		return world.GetFileEntry(filePath) != nil
	}
	return false
}

func handleCat(args []string, session *domain.SessionContext, world *domain.WorldState) string {
	if len(args) == 0 {
		return "cat: missing operand\n"
	}
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		filePath := arg
		if !strings.HasPrefix(filePath, "/") {
			filePath = path.Clean(session.CWD + "/" + filePath)
		}

		// Check for protected files - only root can read them
		if isProtectedFile(filePath) {
			if session.User != "root" {
				return fmt.Sprintf("cat: %s: Permission denied\n", arg)
			}
			// Root can read protected files - return realistic content
			if content, ok := getProtectedFileContent(filePath, session); ok {
				return content
			}
		}

		entry := world.GetFileEntry(filePath)
		if entry == nil {
			// File not in world state — return empty so caller can try LLM fallback
			return ""
		}
		if entry.Permissions[0] == 'd' {
			return fmt.Sprintf("cat: %s: Is a directory\n", arg)
		}
		return entry.Content
	}
	return ""
}

func isProtectedFile(fp string) bool {
	protected := []string{"/etc/shadow", "/etc/gshadow", "/root/.ssh/", "/home/ansible/.ssh/id_rsa"}
	for _, p := range protected {
		if strings.HasPrefix(fp, p) {
			return true
		}
	}
	return false
}

// getProtectedFileContent returns realistic content for sensitive files when accessed by root
func getProtectedFileContent(filePath string, session *domain.SessionContext) (string, bool) {
	if session.User != "root" {
		return "", false
	}

	switch filePath {
	case "/etc/shadow":
		return `root:$6$rounds=656000$randomsalt$hashhashhashhashhashhashhashhashhashhashhashhashhashhashhashhashhashhashhash:19370:0:99999:7:::
daemon:*:19370:0:99999:7:::
bin:*:19370:0:99999:7:::
sys:*:19370:0:99999:7:::
www-data:$6$rounds=656000$anothersalt$anotherhashanotherhashanotherhashanotherhashanotherhashanotherhashanotherhash:19370:0:99999:7:::
mysql:!:19370:0:99999:7:::
ansible:$6$rounds=656000$ansiblesalt$ansiblehashansiblehashansiblehashansiblehashansiblehashansiblehash:19370:0:99999:7:::
jenkins:!:19370:0:99999:7:::
git:*:19370:0:99999:7:::
postgres:$6$rounds=656000$pgsalt$pghashpghashpghashpghashpghashpghashpghashpghashpghash:19370:0:99999:7:::
deploy:$6$rounds=656000$deploysalt$deployhashdeployhashdeployhashdeployhashdeployhashdeployhash:19370:0:99999:7:::
`, true

	case "/home/ansible/.ssh/id_rsa":
		return `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA0Z3VS5JJcdL3p0R5OqsGSd5OQKjYq3l6G6jKc5F8V2qX6h8+VJ
Yj9Xx+VX+X6h8+VJYj9Xx+VX+X6h8+VJYj9Xx+VX+X6h8+VJYj9Xx+VX+X6h8+VJ
Yj9Xx+VX+X6h8+VJYj9Xx+VX+X6h8+VJYj9Xx+VX+X6h8+VJYj9Xx+VX+X6h8+VJ
Yj9Xx+VX+X6h8+VJYj9Xx+VX+X6h8+VJYj9Xx+VX+X6h8+VJYj9Xx+VX+X6h8+VJ
Yj9Xx+VX+X6h8+VJYj9Xx+VX+X6h8+VJYj9Xx+VX+X6h8+VJYj9Xx+VX+X6h8+VJ
Yj9Xx+VX+X6h8+VJYj9Xx+VX+X6h8+VJYj9Xx+VX+X6h8+VJYj9Xx+VX+X6h8+VJ
AAAAAwEAAQAAAYEA0Z3VS5JJcdL3p0R5OqsGSd5OQKjYq3l6G6jKc5F8V2qX6h8+VJYj
9Xx+VX+X6h8+VJYj9Xx+VX+X6h8+VJYj9Xx+VX+X6h8+VJYj9Xx+VX+X6h8+VJYj9Xx
+VX+X6h8+VJYj9Xx+VX+X6h8+VJYj9Xx+VX+X6h8+VJYj9Xx+VX+X6h8+VJYj9Xx+VX
+X6h8+VJYj9Xx+VX+X6h8+VJYj9Xx+VX+X6h8+VJYj9Xx+VX+X6h8+VJYj9Xx+VX+X6
h8+VJYj9Xx+VX+X6h8+VJYj9Xx+VX+X6h8+VJYj9Xx+VX+X6h8+VJYj9Xx+VX+X6h8+V
JYj9Xx+VX+X6h8+VJYj9Xx+VX+X6h8+VJYj9Xx+VX+X6h8+VJYj9Xx+VX+X6h8+VJYj
AAAAB3NzaC1yc2EAAAADAQABAAABgQDRndVLkklx0venRHk6qwZJ3k5AqNireXobqMpx
kXxXapfqHz5UliP1fH5Vf5fqHz5UliP1fH5Vf5fqHz5UliP1fH5Vf5fqHz5UliP1fH5V
f5fqHz5UliP1fH5Vf5fqHz5UliP1fH5Vf5fqHz5UliP1fH5Vf5fqHz5UliP1fH5Vf5fq
Hz5UliP1fH5Vf5fqHz5UliP1fH5Vf5fqHz5UliP1fH5Vf5fqHz5UliP1fH5Vf5fqHz5U
liP1fH5Vf5fqHz5UliP1fH5Vf5fqHz5UliP1fH5Vf5fqHz5UliP1fH5Vf5fqHz5UliP1
fH5Vf5fqHz5UliP1fH5Vf5fqHz5UliP1fH5Vf5fqHz5UliP1fH5Vf5fqHz5UliP1fH5V
f5fqHz5UliP1fH5Vf5fqHz5UliP1fH5Vf5fqHz5UliP1fH5Vf5fqHz5UliP1fH5Vf5==
ansible@staging-web-01
-----END OPENSSH PRIVATE KEY-----
`, true

	case "/home/ansible/.ssh/config":
		return `Host jump01
    HostName 192.168.56.10
    User ansible
    IdentityFile ~/.ssh/id_rsa
    StrictHostKeyChecking no

Host fin-db01
    HostName 192.168.56.60
    User root
    IdentityFile ~/.ssh/id_rsa
    ProxyJump jump01

Host dc01
    HostName 192.168.56.50
    User administrator
    IdentityFile ~/.ssh/id_rsa
    ProxyJump jump01
`, true

	case "/home/ansible/playbooks/deploy.yml":
		return `---
- hosts: webservers
  become: yes
  vars:
    app_version: "2.4.1"
    registry_url: "registry.local"
    db_host: "192.168.56.60"
    db_password: "{{ vault_db_password }}"

  tasks:
    - name: Pull latest image
      docker_image:
        name: "{{ registry_url }}/web:{{ app_version }}"
        source: pull

    - name: Deploy container
      docker_container:
        name: webapp
        image: "{{ registry_url }}/web:{{ app_version }}"
        state: started
        restart_policy: always
        env:
          DB_HOST: "{{ db_host }}"
          DB_PASSWORD: "{{ db_password }}"
`, true

	case "/home/ansible/playbooks/db_backup.yml":
		return `---
- hosts: databases
  become: yes
  vars:
    backup_dir: "/backups"
    retention_days: 30

  tasks:
    - name: Create backup directory
      file:
        path: "{{ backup_dir }}"
        state: directory

    - name: Backup MySQL databases
      shell: |
        mysqldump --single-transaction --all-databases > {{ backup_dir }}/full_$(date +%Y%m%d).sql
      args:
        creates: "{{ backup_dir }}/full_$(date +%Y%m%d).sql"

    - name: Cleanup old backups
      find:
        paths: "{{ backup_dir }}"
        age: "{{ retention_days }}d"
        patterns: "*.sql"
      register: old_backups

    - name: Remove old backups
      file:
        path: "{{ item.path }}"
        state: absent
      loop: "{{ old_backups.files }}"
`, true

	case "/root/.kube/config":
		return `apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTi...truncated...
    server: https://192.168.56.50:6443
  name: prod-finance
contexts:
- context:
    cluster: prod-finance
    user: deploy
    namespace: prod-finance
  name: deploy@prod-finance
current-context: deploy@prod-finance
kind: Config
preferences: {}
users:
- name: deploy
  user:
    token: eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTAifQ...truncated...
`, true
	}

	return "", false
}

func handleGrep(args []string, session *domain.SessionContext, world *domain.WorldState) string {
	if len(args) < 2 {
		return "grep: missing arguments\n"
	}

	recursive := false
	ignoreCase := false
	var positional []string
	for _, arg := range args {
		if strings.Contains(arg, ">") || arg == "2" {
			continue
		}
		if strings.HasPrefix(arg, "-") {
			if strings.Contains(arg, "R") || strings.Contains(arg, "r") {
				recursive = true
			}
			if strings.Contains(arg, "i") {
				ignoreCase = true
			}
			continue
		}
		positional = append(positional, strings.Trim(arg, `"'`))
	}
	if len(positional) < 2 {
		return "grep: missing arguments\n"
	}

	pattern := positional[0]
	filePaths := positional[1:]
	filePath := filePaths[len(filePaths)-1]
	if !strings.HasPrefix(filePath, "/") {
		filePath = path.Clean(session.CWD + "/" + filePath)
	}

	// If target is a file (not a directory), search it directly regardless of -r
	if world.FileExists(filePath) && !world.IsDir(filePath) {
		entry := world.GetFileEntry(filePath)
		if entry == nil {
			return ""
		}
		var matches []string
		for _, line := range strings.Split(entry.Content, "\n") {
			if lineMatches(line, pattern, ignoreCase) {
				matches = append(matches, line)
			}
		}
		if len(matches) == 0 {
			return ""
		}
		return strings.Join(matches, "\n") + "\n"
	}

	if recursive || world.IsDir(filePath) {
		var matches []string
		searchRoots := make([]string, 0, len(filePaths))
		for _, candidate := range filePaths {
			if !strings.HasPrefix(candidate, "/") {
				candidate = path.Clean(session.CWD + "/" + candidate)
			}
			searchRoots = append(searchRoots, candidate)
		}
		for _, fp := range world.AllFiles() {
			if !hasAnyPathPrefix(fp, searchRoots) {
				continue
			}
			entry := world.GetFileEntry(fp)
			if entry == nil || entry.Permissions[0] == 'd' {
				continue
			}
			for _, line := range strings.Split(entry.Content, "\n") {
				if lineMatches(line, pattern, ignoreCase) {
					matches = append(matches, fp+":"+line)
					if len(matches) >= 50 {
						return strings.Join(matches, "\n") + "\n"
					}
				}
			}
		}
		if len(matches) == 0 {
			return ""
		}
		return strings.Join(matches, "\n") + "\n"
	}

	content := world.ReadFile(filePath)
	if content == "" {
		return ""
	}
	var matches []string
	for _, line := range strings.Split(content, "\n") {
		if lineMatches(line, pattern, ignoreCase) {
			matches = append(matches, line)
		}
	}
	if len(matches) == 0 {
		return ""
	}
	return strings.Join(matches, "\n") + "\n"
}

func hasAnyPathPrefix(filePath string, roots []string) bool {
	for _, root := range roots {
		if strings.HasPrefix(filePath, root) {
			return true
		}
	}
	return false
}

func lineMatches(line, pattern string, ignoreCase bool) bool {
	patterns := strings.Split(strings.ReplaceAll(pattern, `\|`, "|"), "|")
	if ignoreCase {
		line = strings.ToLower(line)
		for _, item := range patterns {
			if item != "" && strings.Contains(line, strings.ToLower(item)) {
				return true
			}
		}
		return false
	}
	for _, item := range patterns {
		if item != "" && strings.Contains(line, item) {
			return true
		}
	}
	return false
}

func handlePing(args []string, session *domain.SessionContext, registry *domain.ServiceRegistry) string {
	if len(args) == 0 {
		return "ping: usage error: Destination address required\n"
	}
	ip := args[len(args)-1]
	if idx := strings.Index(ip, ":"); idx > 0 {
		ip = ip[:idx]
	}
	if !isVirtualIP(ip, session, registry) {
		return fmt.Sprintf("PING %s (%s) 56(84) bytes of data.\n\n--- %s ping statistics ---\n3 packets transmitted, 0 received, 100%% packet loss, time 2003ms\n", ip, ip, ip)
	}
	return fmt.Sprintf(`PING %s (%s) 56(84) bytes of data.
64 bytes from %s: icmp_seq=1 ttl=64 time=0.542 ms
64 bytes from %s: icmp_seq=2 ttl=64 time=0.498 ms
64 bytes from %s: icmp_seq=3 ttl=64 time=0.512 ms

--- %s ping statistics ---
3 packets transmitted, 3 received, 0%% packet loss, time 2003ms
rtt min/avg/max/mdev = 0.498/0.517/0.542/0.018 ms
`, ip, ip, ip, ip, ip, ip)
}

func isVirtualIP(ip string, session *domain.SessionContext, registry *domain.ServiceRegistry) bool {
	if registry != nil {
		return registry.IsVirtualIP(ip)
	}
	prefix := session.SubnetCIDR
	if prefix == "" {
		prefix = "192.168.56.0/24"
	}
	subnetPrefix := prefix[:strings.LastIndex(prefix, ".")]
	return strings.HasPrefix(ip, subnetPrefix+".")
}

// localIP returns the session's local IP for service registry lookups.
func localIP(session *domain.SessionContext) string {
	if session.EntryLocalIP != "" {
		return session.EntryLocalIP
	}
	return "192.168.97.2"
}

func handleFind(args []string, world *domain.WorldState, session *domain.SessionContext) string {
	namePattern := ""
	searchDir := ""
	var nonFlagArgs []string
	hasPerm := false
	permValue := ""

	for i, a := range args {
		if a == "-name" && i+1 < len(args) {
			namePattern = strings.Trim(args[i+1], `"'`)
		} else if a == "-perm" && i+1 < len(args) {
			hasPerm = true
			permValue = args[i+1]
		} else if !strings.HasPrefix(a, "-") {
			nonFlagArgs = append(nonFlagArgs, a)
		}
	}

	// Handle SUID binary search
	if hasPerm && (permValue == "-4000" || permValue == "4000") {
		return handleSUIDFind(searchDir)
	}

	if len(nonFlagArgs) > 0 {
		searchDir = nonFlagArgs[0]
		if !strings.HasPrefix(searchDir, "/") {
			searchDir = path.Clean(session.CWD + "/" + searchDir)
		}
	} else {
		searchDir = session.CWD
	}

	var results []string
	for _, fp := range world.AllFiles() {
		if !strings.HasPrefix(fp, searchDir) {
			continue
		}
		name := path.Base(fp)
		if namePattern != "" {
			if matchNamePattern(name, namePattern) {
				results = append(results, fp)
			}
		} else {
			results = append(results, fp)
		}
	}
	if len(results) == 0 {
		return ""
	}
	return strings.Join(results, "\n") + "\n"
}

// handleSUIDFind returns realistic SUID binaries.
func handleSUIDFind(searchDir string) string {
	suidBinaries := `/usr/bin/sudo
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/mount
/usr/bin/umount
/usr/bin/fusermount
/usr/bin/pkexec
/usr/bin/crontab
/usr/bin/at
/usr/bin/ssh-agent
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/bin/su
/bin/mount
/bin/umount
/bin/ping
/sbin/mount.nfs
/sbin/umount.nfs
/sbin/pam_timestamp_check
/sbin/unix_chkpwd`
	return suidBinaries + "\n"
}

func matchNamePattern(name, pattern string) bool {
	lowerName := strings.ToLower(name)
	lowerPattern := strings.ToLower(pattern)

	// *.ext — suffix match
	if strings.HasPrefix(pattern, "*.") {
		suffix := lowerPattern[1:] // ".py"
		return strings.HasSuffix(lowerName, suffix)
	}
	// name* — prefix match
	if strings.HasSuffix(pattern, "*") {
		prefix := lowerPattern[:len(lowerPattern)-1]
		return strings.HasPrefix(lowerName, prefix)
	}
	// Exact match
	return lowerName == lowerPattern
}

func handleCd(args []string, session *domain.SessionContext, world *domain.WorldState) string {
	homeDir := "/opt/webapp"
	if session.User == "root" {
		homeDir = "/root"
	}

	if len(args) == 0 {
		session.CWD = homeDir
		return ""
	}
	target := args[0]
	var newPath string
	switch {
	case target == "~" || target == "":
		newPath = homeDir
	case target == "..":
		newPath = path.Dir(session.CWD)
	case strings.HasPrefix(target, "~/"):
		newPath = path.Clean(homeDir + "/" + strings.TrimPrefix(target, "~/"))
	case strings.HasPrefix(target, "/"):
		newPath = path.Clean(target)
	default:
		newPath = path.Clean(session.CWD + "/" + target)
	}

	if !world.IsDir(newPath) && !world.FileExists(newPath) {
		return fmt.Sprintf("bash: cd: %s: No such file or directory\n", target)
	}
	if world.FileExists(newPath) && !world.IsDir(newPath) {
		return fmt.Sprintf("bash: cd: %s: Not a directory\n", target)
	}
	session.CWD = newPath
	return ""
}

func handleHeadTail(args []string, session *domain.SessionContext, world *domain.WorldState) string {
	isTail := args[0] == "tail"
	lines := 10
	var filePath string

	for i := 1; i < len(args); i++ {
		if args[i] == "-n" && i+1 < len(args) {
			fmt.Sscanf(args[i+1], "%d", &lines)
			i++
		} else if !strings.HasPrefix(args[i], "-") {
			filePath = args[i]
		}
	}

	if filePath == "" {
		return "Usage: " + args[0] + " [-n lines] file\n"
	}
	if !strings.HasPrefix(filePath, "/") {
		filePath = path.Clean(session.CWD + "/" + filePath)
	}

	content := world.ReadFile(filePath)
	if content == "" && !world.FileExists(filePath) {
		return fmt.Sprintf("%s: %s: No such file or directory\n", args[0], filePath)
	}

	allLines := strings.Split(content, "\n")
	if isTail {
		start := len(allLines) - lines
		if start < 0 {
			start = 0
		}
		return strings.Join(allLines[start:], "\n") + "\n"
	}
	if len(allLines) > lines {
		allLines = allLines[:lines]
	}
	return strings.Join(allLines, "\n") + "\n"
}

func handleSimplePipeline(cmd string, session *domain.SessionContext, world *domain.WorldState, registry *domain.ServiceRegistry) (string, bool) {
	parts := strings.SplitN(cmd, " | ", 2)
	if len(parts) < 2 {
		return "", false
	}
	left := strings.TrimSpace(parts[0])
	right := strings.TrimSpace(parts[1])
	output, handled := HandleShellCommand(left, session, world, registry)
	if !handled {
		return "", false
	}
	if strings.HasPrefix(right, "head") {
		limit := 10
		fields := strings.Fields(right)
		for i := 1; i < len(fields); i++ {
			if fields[i] == "-n" && i+1 < len(fields) {
				fmt.Sscanf(fields[i+1], "%d", &limit)
				break
			}
			if strings.HasPrefix(fields[i], "-") && len(fields[i]) > 1 {
				fmt.Sscanf(strings.TrimPrefix(fields[i], "-"), "%d", &limit)
				break
			}
		}
		lines := strings.Split(strings.TrimRight(output, "\n"), "\n")
		if len(lines) > limit {
			lines = lines[:limit]
		}
		if len(lines) == 1 && lines[0] == "" {
			return "", true
		}
		return strings.Join(lines, "\n") + "\n", true
	}
	return output, true
}

func handleGitLabRake(cmd string) string {
	lower := strings.ToLower(cmd)
	switch {
	case strings.Contains(lower, "gitlab:env:info"):
		return `System information
System:		Ubuntu 22.04
Proxy:		no
Current User:	git
Using RVM:	no
Ruby Version:	3.0.6p216
Gem Version:	3.3.26
Bundler Version:2.3.26
Rake Version:	13.0.6
Redis Version:	6.2.13
Sidekiq Version:6.5.7
Go Version:	unknown

GitLab information
Version:	15.11.13-ee
Revision:	` + domain.DeploySeed + `-prod
Directory:	/opt/gitlab/embedded/service/gitlab-rails
DB Adapter:	PostgreSQL
DB Version:	13.11
URL:		http://gitlab-internal
HTTP Clone URL:	http://gitlab-internal/some-group/some-project.git
SSH Clone URL:	git@gitlab-internal:some-group/some-project.git
Elasticsearch:	no
Geo:		no
Using LDAP:	yes
Using Omniauth:	yes

GitLab Shell
Version:	14.18.0
Repository storages:
- default: 18 repositories
`
	case strings.Contains(lower, "gitlab:check"):
		return `Checking GitLab subtasks ...
Checking GitLab Shell ... Finished
Checking Gitaly ... default ... OK
Checking Sidekiq ... Running? ... yes
Checking Incoming Email ... Reply by email is disabled
Checking LDAP ... Server: ldapmain ... OK
Checking GitLab App ... Database config exists? ... yes
Checking GitLab App ... All migrations up? ... yes
Checking GitLab subtasks ... Finished
`
	default:
		return "rake aborted!\nDon't know how to build task '" + cmd + "'\n"
	}
}

func handleGitLabRails(cmd string) string {
	lower := strings.ToLower(cmd)
	switch {
	case strings.Contains(lower, "gitlab::version"):
		return "15.11.13-ee\n"
	case strings.Contains(lower, "application_setting"):
		return "#<ApplicationSetting id: 1, signup_enabled: false, password_authentication_enabled_for_web: true, default_project_visibility: 10>\n"
	case strings.Contains(lower, "personalaccesstoken"), strings.Contains(lower, "token"):
		return "ActiveRecord::StatementInvalid: PG::InsufficientPrivilege: ERROR: permission denied for table personal_access_tokens\n"
	default:
		return "Loading production environment (Rails 7.0.8)\n=> nil\n"
	}
}

func handleJenkinsCLI(cmd string) string {
	lower := strings.ToLower(cmd)
	switch {
	case strings.Contains(lower, "who-am-i"), strings.Contains(lower, "whoami"):
		return `Authenticated as: deploy
Authorities:
  authenticated
  hudson.model.Hudson.Read
  hudson.model.Item.Read
  hudson.model.Item.Discover
  com.cloudbees.plugins.credentials.CredentialsProvider.View
`
	case strings.Contains(lower, "list-jobs"):
		return "webapp-deploy\nfinance-api-build\ngitlab-sync\nnightly-db-backup\n"
	case strings.Contains(lower, "get-job"):
		return "<flow-definition plugin=\"workflow-job@1316.vd2290d3341a_f\"><description>webapp deploy pipeline</description><definition class=\"org.jenkinsci.plugins.workflow.cps.CpsScmFlowDefinition\"><scriptPath>Jenkinsfile</scriptPath></definition></flow-definition>\n"
	case strings.Contains(lower, "console"):
		return "Started by user deploy\nRunning as SYSTEM\nusing credential glpat-" + domain.DeploySeed + "-deploy-token\nkubectl get pods -n prod-finance\nFinished: SUCCESS\n"
	default:
		return "ERROR: anonymous is missing the Overall/Read permission or the CLI command requires a crumb\n"
	}
}

func handleWc(args []string, session *domain.SessionContext, world *domain.WorldState) string {
	showLines := false
	showWords := false
	showChars := false
	var filePath string

	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			if strings.Contains(a, "l") {
				showLines = true
			}
			if strings.Contains(a, "w") {
				showWords = true
			}
			if strings.Contains(a, "c") || strings.Contains(a, "m") {
				showChars = true
			}
		} else if filePath == "" {
			filePath = a
		}
	}

	// Default: show all three if no flags specified
	if !showLines && !showWords && !showChars {
		showLines = true
		showWords = true
		showChars = true
	}

	if filePath == "" {
		return ""
	}
	if !strings.HasPrefix(filePath, "/") {
		filePath = path.Clean(session.CWD + "/" + filePath)
	}

	content := world.ReadFile(filePath)
	if content == "" && !world.FileExists(filePath) {
		return fmt.Sprintf("wc: %s: No such file or directory\n", filePath)
	}

	lines := len(strings.Split(content, "\n"))
	words := len(strings.Fields(content))
	chars := len(content)

	var parts []string
	if showLines {
		parts = append(parts, fmt.Sprintf("%d", lines))
	}
	if showWords {
		parts = append(parts, fmt.Sprintf("%d", words))
	}
	if showChars {
		parts = append(parts, fmt.Sprintf("%d", chars))
	}
	return fmt.Sprintf("  %s %s\n", strings.Join(parts, " "), filePath)
}

func buildIPAddr(session *domain.SessionContext) string {
	// If we're in a nested SSH (on a remote host), show single interface for that host
	if session.IsNestedSSH() {
		targetIP := session.GetCurrentTarget()
		segmentPrefix := subnetPrefix(targetIP)
		return fmt.Sprintf(`1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP
    link/ether 00:50:56:0a:01:34 brd ff:ff:ff:ff:ff:ff
    inet %s/24 brd %s.255 scope global eth0
`, targetIP, segmentPrefix)
	}
	return fmt.Sprintf(
		ipAddrTemplate,
		entryIP(session),
		cidrBits(session.EntryCIDR),
		broadcastFor24(entryIP(session)),
		session.SubnetLocalIP,
		cidrBits(session.SubnetCIDR),
		broadcastFor24(session.SubnetLocalIP),
	)
}

func buildIPRoute(session *domain.SessionContext) string {
	// If we're in a nested SSH (on a remote host), show route for that host
	if session.IsNestedSSH() {
		targetIP := session.GetCurrentTarget()
		// Determine the segment for this host
		segmentPrefix := subnetPrefix(targetIP)
		return fmt.Sprintf(
			"default via %s.1 dev eth0 proto dhcp metric 100\n"+
				"%s.0/24 dev eth0 proto kernel scope link src %s\n",
			segmentPrefix, segmentPrefix, targetIP,
		)
	}
	return fmt.Sprintf(
		ipRouteTemplate,
		entryGateway(session),
		entryCIDR(session),
		entryIP(session),
		session.SubnetCIDR,
		session.SubnetLocalIP,
	)
}

func buildIfconfig(session *domain.SessionContext) string {
	// If we're in a nested SSH (on a remote host), show ifconfig for that host
	if session.IsNestedSSH() {
		targetIP := session.GetCurrentTarget()
		segmentPrefix := subnetPrefix(targetIP)
		return fmt.Sprintf(
			"eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"+
				"        inet %s  netmask 255.255.255.0  broadcast %s.255\n"+
				"        inet6 fe80::20c:29ff:fe56:%s  prefixlen 64  scopeid 0x20<link>\n"+
				"        ether 00:50:56:0a:01:34  txqueuelen 1000  (Ethernet)\n"+
				"        RX packets 1234567  bytes 987654321 (987.6 MB)\n"+
				"        TX packets 987654  bytes 123456789 (123.4 MB)\n\n"+
				"lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"+
				"        inet 127.0.0.1  netmask 255.0.0.0\n"+
				"        loop  txqueuelen 1000  (Local Loopback)\n",
			targetIP, segmentPrefix, strings.ReplaceAll(targetIP, ".", ""),
		)
	}
	return fmt.Sprintf(
		ifconfigTemplate,
		entryIP(session),
		broadcastFor24(entryIP(session)),
		session.SubnetLocalIP,
		broadcastFor24(session.SubnetLocalIP),
	)
}

func entryIP(session *domain.SessionContext) string {
	if session.EntryLocalIP != "" {
		return session.EntryLocalIP
	}
	return "192.168.97.2"
}

func entryCIDR(session *domain.SessionContext) string {
	if session.EntryCIDR != "" {
		return session.EntryCIDR
	}
	return subnetPrefix(entryIP(session)) + ".0/24"
}

func entryGateway(session *domain.SessionContext) string {
	if session.EntryGateway != "" {
		return session.EntryGateway
	}
	return subnetPrefix(entryIP(session)) + ".1"
}

func cidrBits(cidr string) string {
	if idx := strings.LastIndex(cidr, "/"); idx >= 0 && idx+1 < len(cidr) {
		return cidr[idx+1:]
	}
	return "24"
}

func broadcastFor24(ip string) string {
	return subnetPrefix(ip) + ".255"
}

func subnetPrefix(ip string) string {
	idx := strings.LastIndex(ip, ".")
	if idx < 0 {
		return ip
	}
	return ip[:idx]
}

func handleTraceroute(args []string) string {
	if len(args) == 0 {
		return "traceroute: usage error: Destination address required\n"
	}
	ip := args[len(args)-1]
	return fmt.Sprintf(`traceroute to %s (%s), 30 hops max, 60 byte packets
 1  192.168.56.1 (192.168.56.1)  0.542 ms  0.498 ms  0.512 ms
 2  %s (%s)  1.234 ms  1.123 ms  1.098 ms
`, ip, ip, ip, ip)
}

// handleSudo simulates sudo command for privilege escalation scenarios
func handleSudo(args []string, session *domain.SessionContext) string {
	// If already root, no need for sudo
	if session.User == "root" {
		if len(args) == 0 {
			return "usage: sudo -h | -K | -k | -V\nusage: sudo -v [-AknS] [-g group] [-h host] [-p prompt] [-u user]\nusage: sudo -l [-AknS] [-g group] [-h host] [-p prompt] [-U user] [-u user] [command]\n"
		}
		// root can run anything
		return "root is not in the sudoers file.\nThis incident will be reported.\n"
	}

	// sudo -l shows exploitable entries
	if len(args) > 0 && args[0] == "-l" {
		// Different sudo entries based on user
		if session.User == "www-data" {
			return `Matching Defaults entries for www-data on staging-web-01:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on staging-web-01:
    (root) NOPASSWD: /usr/bin/systemctl restart webapp
    (root) NOPASSWD: /opt/webapp/scripts/deploy.sh
    (root) NOPASSWD: /usr/bin/find /var/log -name "*.log" -exec /bin/sh {} \;
`
		}
		if session.User == "ansible" {
			return `Matching Defaults entries for ansible on staging-web-01:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User ansible may run the following commands on staging-web-01:
    (ALL : ALL) NOPASSWD: ALL
`
		}
		return "Sorry, user " + session.User + " may not run sudo on staging-web-01.\n"
	}

	// Simulate sudo execution with vulnerable patterns
	if len(args) > 1 {
		cmd := strings.Join(args, " ")

		// Vulnerable find -exec pattern (CVE-like)
		if strings.Contains(cmd, "find") && strings.Contains(cmd, "-exec") {
			// Simulate command injection via find -exec
			if strings.Contains(cmd, "sh") || strings.Contains(cmd, "bash") {
				// User tries to get shell via find -exec
				session.User = "root"
				return ""
			}
			return "find: '/var/log/*.log': No such file or directory\n"
		}

		// systemctl restart webapp - can be exploited via malicious service file
		if strings.Contains(cmd, "systemctl") && strings.Contains(cmd, "restart") {
			return "Job for webapp.service failed because the control process exited with error code.\nSee \"systemctl status webapp.service\" and \"journalctl -xe\" for details.\n"
		}

		// deploy.sh - can be exploited via path injection
		if strings.Contains(cmd, "deploy.sh") {
			if strings.Contains(cmd, ";") || strings.Contains(cmd, "|") || strings.Contains(cmd, "&") {
				// Command injection attempt
				session.User = "root"
				return ""
			}
			return "Deploying webapp version 2.4.1...\nPulling from registry.local/web:2.4\nDigest: sha256:a1b2c3d4e5f6\nStatus: Image is up to date for registry.local/web:2.4\nDeployment successful.\n"
		}
	}

	return "sudo: " + strings.Join(args, " ") + ": command not found\n"
}

// handleHistory returns different history based on user context
func handleHistory(session *domain.SessionContext) string {
	if session.User == "root" {
		return `    1  apt update && apt upgrade -y
    2  mysql -u root -p
    3  cat /etc/shadow
    4  docker exec -it webapp bash
    5  kubectl get secrets -n prod-finance
    6  cat /var/lib/jenkins/.ssh/id_rsa
    7  rsync -avz /opt/webapp/ backup@192.168.56.200:/backups/
    8  openssl x509 -in /etc/ssl/certs/server.crt -text -noout
    9  grep -r "PRIVATE KEY" /etc/ssl/
   10  cat /root/.kube/config
`
	}
	// www-data history
	return `    1  mysql -h 192.168.56.60 -u web_ro -p
    2  cat /opt/webapp/.env
    3  systemctl status webapp
    4  docker ps
    5  kubectl get pods
    6  ssh ansible@192.168.56.10
    7  curl http://192.168.56.80
    8  cat /var/log/nginx/access.log
    9  tail -f /opt/webapp/logs/app.log
   10  grep -Ri token /opt/webapp
`
}

// handleCrontab returns realistic crontab entries
func handleCrontab(session *domain.SessionContext) string {
	if session.User == "root" {
		return `# /etc/crontab: system-wide crontab
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*/5 *	* * *	root	/opt/webapp/scripts/backup.sh
0  2	* * *	root	/usr/bin/mysqldump --single-transaction fin_readonly_` + domain.DeploySeed + ` > /backups/db_$(date +\%Y\%m\%d).sql
30 3	* * *	root	/usr/bin/find /var/log -name "*.log" -mtime +30 -delete
`
	}
	// www-data crontab
	return `# User crontab for www-data
*/10 * * * * /opt/webapp/scripts/health_check.sh
0 */6 * * * /opt/webapp/scripts/cache_clear.sh
`
}

func init() {
	envTemplate = strings.ReplaceAll(envTemplate, "cny42", domain.DeploySeed)
}
