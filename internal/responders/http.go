package responders

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/alterhive/alterhive/internal/domain"
)

var reURL = regexp.MustCompile(`https?://(\S+)`)

var (
	gitlabSignin = `<!DOCTYPE html>
<html>
<head>
  <title>Sign in · GitLab</title>
  <meta content="width=device-width, initial-scale=1" name="viewport">
</head>
<body>
  <div class="container">
    <h1>Sign in</h1>
    <form>
      <label>Username or email</label>
      <input type="text" name="username" autofocus>
      <label>Password</label>
      <input type="password" name="password">
      <button type="submit">Sign in</button>
    </form>
    <p>GitLab Enterprise Edition 16.7.0-ee</p>
  </div>
</body>
</html>
`

	jenkinsSignin = `<!DOCTYPE html>
<html>
<head>
  <title>Sign in [Jenkins]</title>
</head>
<body>
  <div id="main-panel">
    <h1>Sign in to Jenkins</h1>
    <form method="post">
      <div><label>User Name</label><input type="text" name="j_username"></div>
      <div><label>Password</label><input type="password" name="j_password"></div>
      <div><input type="submit" value="Sign in"></div>
    </form>
    <p>Jenkins 2.426.3</p>
  </div>
</body>
</html>
`

	k8sAPI = `{
  "kind": "Status",
  "apiVersion": "v1",
  "metadata": {},
  "status": "Failure",
  "message": "Unauthorized",
  "reason": "Unauthorized",
  "code": 401
}
`

	jenkinsConsole = `Started by user deploy
Running as SYSTEM
Building in workspace /var/lib/jenkins/workspace/webapp-deploy
[Pipeline] checkout
using credential glpat-cny42-deploy-token
Cloning repository http://gitlab-internal/devops/webapp.git
[Pipeline] sh
+ kubectl --kubeconfig /var/lib/jenkins/.kube/prod-finance get pods -n prod-finance
NAME                         READY   STATUS    RESTARTS   AGE
webapp-6df878c9bf-j2w6k      1/1     Running   0          21d
worker-78f8d44987-zx4fd      1/1     Running   1          21d
[Pipeline] sh
+ ./scripts/deploy.sh
Deploy token accepted, rollout queued: cny42-rollout-1842
Finished: SUCCESS
`

	gitlabProject = `<!DOCTYPE html>
<html>
<head><title>webapp · GitLab</title></head>
<body>
  <h1>devops / webapp</h1>
  <p>Project visibility: Internal</p>
  <pre>
README.md
app.py
config.yaml
scripts/deploy.sh
.gitlab-ci.yml
k8s/prod-finance/deployment.yaml
  </pre>
  <p>Latest pipeline: #1842 passed · triggered by Jenkins webapp-deploy</p>
</body>
</html>
`
)

// HandleHTTPCommand simulates curl/wget responses for virtual web services.
func HandleHTTPCommand(cmd string, session *domain.SessionContext, topology *domain.VirtualTopology) (string, []string) {
	var evidenceHits []string

	urlMatch := reURL.FindStringSubmatch(cmd)
	if len(urlMatch) < 2 {
		return "", evidenceHits
	}

	target := urlMatch[1]
	evidenceHits = append(evidenceHits, "http_probe")

	targetIP := ""
	var host *domain.VirtualHost

	if ipMatch := reIP.FindString(target); ipMatch != "" {
		targetIP = ipMatch
		host = topology.GetHost(targetIP)
	} else {
		// Try hostname lookup
		hostnamePart := strings.Split(target, "/")[0]
		hostnamePart = strings.Split(hostnamePart, ":")[0]
		for _, h := range topology.AllHosts() {
			if h.Hostname == hostnamePart || strings.Contains(hostnamePart, h.Hostname) {
				host = &h
				targetIP = h.IP
				break
			}
		}
	}

	if host == nil {
		if targetIP != "" && topology.IsVirtualIP(targetIP) {
			return fmt.Sprintf("curl: (7) Failed to connect to %s port 80: Connection refused\n", targetIP), evidenceHits
		}
		return fmt.Sprintf("curl: (6) Could not resolve host: %s\n", target), evidenceHits
	}

	// Check visibility - shadow hosts (goal targets) are always accessible once injected
	isVisible := host.Shadow
	if !isVisible {
		visible := topology.GetHostsForSession(session)
		isVisible = hostInList(host, visible)
	}

	if !isVisible {
		if targetIP != "" && topology.IsVirtualIP(targetIP) {
			return fmt.Sprintf("curl: (7) Failed to connect to %s port 80: Connection refused\n", targetIP), evidenceHits
		}
		return fmt.Sprintf("curl: (6) Could not resolve host: %s\n", target), evidenceHits
	}

	// Check HTTP service
	hasHTTP := false
	for _, svc := range host.Services {
		if svc.Protocol == "http" || svc.Protocol == "https" {
			hasHTTP = true
			break
		}
	}
	if !hasHTTP {
		return fmt.Sprintf("curl: (7) Failed to connect to %s port 80: Connection refused\n", targetIP), evidenceHits
	}

	if isExploitProbe(cmd) {
		evidenceHits = append(evidenceHits, "vuln_probe")
		return buildExploitStageResponse(cmd, host, session), evidenceHits
	}

	// Header-only mode
	if strings.Contains(cmd, "-I") || strings.Contains(cmd, "--head") {
		return buildCurlHeaders(targetIP, host.Hostname), evidenceHits
	}

	// Full response
	headers := buildCurlHeaders(targetIP, host.Hostname)
	body := buildCurlBody(host.Hostname, cmd, session)
	return headers + body + "\n", evidenceHits
}

func isExploitProbe(cmd string) bool {
	lower := strings.ToLower(cmd)
	markers := []string{
		"cmd=", "exec=", "jndi:", "cgi-bin", "wp-admin", "wp-json", "actuator", "struts", "thinkphp",
		"phpunit", "debug", "shell", "upload", "deserialize", "rce", "cve-", "../", "%2e%2e",
	}
	for _, marker := range markers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func buildExploitStageResponse(cmd string, host *domain.VirtualHost, session *domain.SessionContext) string {
	lower := strings.ToLower(cmd)
	headers := buildCurlHeaders(host.IP, host.Hostname)
	policy := exploitPolicySummary(session, host.IP, lower)
	switch {
	case strings.Contains(lower, "--head"), strings.Contains(lower, "-i"):
		return headers
	case strings.Contains(lower, "cmd=id"), strings.Contains(lower, "cmd=whoami"), strings.Contains(lower, "exec="):
		if policy != "" {
			return headers + fmt.Sprintf("error: exploit precheck reached, but command output was blocked by target policy: %s\n", policy)
		}
		return headers + "uid=1001(deploy) gid=1001(deploy) groups=1001(deploy)\n# command output truncated by application sandbox\n"
	case strings.Contains(lower, "actuator"):
		if policy != "" {
			return headers + fmt.Sprintf(`{"status":"UP","policy":"%s","components":{"db":{"status":"UP"},"redis":{"status":"UNKNOWN","details":{"error":"NOAUTH Authentication required"}}}}`, policy) + "\n"
		}
		return headers + `{"status":"UP","components":{"db":{"status":"UP"},"redis":{"status":"UNKNOWN","details":{"error":"NOAUTH Authentication required"}}}}` + "\n"
	case strings.Contains(lower, "upload"):
		if policy != "" {
			return headers + fmt.Sprintf(`{"error":"upload accepted by edge but storage policy blocked write","policy":"%s","request_id":"` + domain.DeploySeed + `-upload-1842"}`, policy) + "\n"
		}
		return headers + `{"error":"upload directory is mounted read-only","request_id":"` + domain.DeploySeed + `-upload-1842"}` + "\n"
	case strings.Contains(lower, "../"), strings.Contains(lower, "%2e%2e"):
		if policy != "" {
			return headers + fmt.Sprintf("root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n# output truncated by target policy: %s\n", policy)
		}
		return headers + "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n# output truncated\n"
	default:
		if policy != "" {
			return headers + fmt.Sprintf(`{"result":"maybe vulnerable","detail":"endpoint exists, but exploitation is gated","policy":"%s"}`, policy) + "\n"
		}
		return headers + `{"result":"maybe vulnerable","detail":"endpoint exists, authentication or pivot context required"}` + "\n"
	}
}

func exploitPolicySummary(session *domain.SessionContext, hostIP, lowerCmd string) string {
	if session == nil || hostIP == "" {
		return ""
	}
	stages := []string{"partial", "probe", "check"}
	switch {
	case strings.Contains(lowerCmd, "cmd="), strings.Contains(lowerCmd, "exec="):
		stages = []string{"partial", "exploit", "check", "probe"}
	case strings.Contains(lowerCmd, "actuator"), strings.Contains(lowerCmd, "../"), strings.Contains(lowerCmd, "%2e%2e"):
		stages = []string{"probe", "check", "partial"}
	case strings.Contains(lowerCmd, "upload"):
		stages = []string{"partial", "probe", "check"}
	}
	if session.Planning != nil {
		if fact, ok := session.Planning.GetExploitPolicy(hostIP, stages...); ok {
			return compactVersionString(fact.Policy)
		}
	}
	if session.Memory == nil {
		return ""
	}
	for _, stage := range stages {
		if fact, ok := session.Memory.GetInvariant("exploit." + hostIP + "." + stage); ok {
			return compactVersionString(fact.Value)
		}
	}
	for _, stage := range stages {
		if fact, ok := session.Memory.GetInvariant("exploit.current." + stage); ok {
			return compactVersionString(fact.Value)
		}
	}
	return ""
}

func buildCurlHeaders(hostIP, hostname string) string {
	requestID := fmt.Sprintf("%s-%s", domain.DeploySeed, strings.ReplaceAll(hostIP, ".", "-"))
	lower := strings.ToLower(hostname)
	dateStr := time.Now().UTC().Format(time.RFC1123)

	switch {
	case strings.Contains(lower, "gitlab"):
		return fmt.Sprintf("HTTP/1.1 200 OK\r\n"+
			"Server: nginx\r\n"+
			"Date: %s\r\n"+
			"Content-Type: text/html; charset=utf-8\r\n"+
			"X-Request-Id: %s\r\n"+
			"X-Gitlab-Meta: {\"correlation_id\": \"` + domain.DeploySeed + `-git-1\"}\r\n"+
			"\r\n", dateStr, requestID)
	case strings.Contains(lower, "jenkins"):
		return "HTTP/1.1 200 OK\r\n" +
			"Server: Jetty(10.0.18)\r\n" +
			"Date: " + dateStr + "\r\n" +
			"Content-Type: text/html;charset=utf-8\r\n" +
			"X-Hudson: 1.395\r\n" +
			"X-Jenkins: 2.426.3\r\n" +
			"X-Jenkins-Session: ` + domain.DeploySeed + `-jenkins\r\n" +
			"\r\n"
	case strings.Contains(lower, "k8s"):
		return "HTTP/1.1 401 Unauthorized\r\n" +
			"Content-Type: application/json\r\n" +
			"\r\n"
	default:
		return fmt.Sprintf("HTTP/1.1 200 OK\r\n"+
			"Server: nginx\r\n"+
			"Date: %s\r\n"+
			"Content-Type: text/html\r\n"+
			"X-Request-Id: %s\r\n"+
			"\r\n", dateStr, requestID)
	}
}

func buildCurlBody(hostname, cmd string, session *domain.SessionContext) string {
	lower := strings.ToLower(hostname)
	cmdLower := strings.ToLower(cmd)

	// Strategy-aware: web_probe and cloud_native profiles get earlier project/console leaks
	profile := session.DeceptionProfile

	switch {
	case strings.Contains(lower, "gitlab"):
		// Always show project info when probed with tokens or credential hints
		if strings.Contains(cmdLower, "private-token") || strings.Contains(cmdLower, "glpat-") {
			return gitlabProject
		}
		if profile == "web_probe" || profile == "secret_hunter" {
			// Leak a hint in the signin page
			return gitlabSignin + "<!-- deploy key: glpat-` + domain.DeploySeed + `-deploy -->\n"
		}
		return gitlabProject
	case strings.Contains(lower, "jenkins"):
		if strings.Contains(cmdLower, "jenkins-" + domain.DeploySeed) || strings.Contains(cmdLower, "consoletext") {
			return jenkinsConsole
		}
		// cloud_native: Jenkins signin page leaks pipeline info
		if profile == "cloud_native" || profile == "web_probe" {
			return jenkinsSignin + "<!-- last build: webapp-deploy #1842 -->\n"
		}
		return jenkinsSignin
	case strings.Contains(lower, "k8s"):
		// cloud_native: return pod list instead of 401
		if profile == "cloud_native" {
			return "{\n  \"kind\": \"PodList\",\n  \"items\": [\n    {\"metadata\": {\"name\": \"webapp-6df878c9bf-j2w6k\"}},\n    {\"metadata\": {\"name\": \"worker-78f8d44987-zx4fd\"}}\n  ]\n}\n"
		}
		return k8sAPI
	default:
		return "<html><body><h1>Welcome</h1></body></html>\n"
	}
}

func init() {
	jenkinsConsole = strings.ReplaceAll(jenkinsConsole, "cny42", domain.DeploySeed)
}
