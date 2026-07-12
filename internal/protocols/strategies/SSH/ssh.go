package SSH

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/alterhive/alterhive/internal/domain"
	"github.com/alterhive/alterhive/internal/parser"
	"github.com/alterhive/alterhive/internal/session"
	"github.com/alterhive/alterhive/internal/tracer"

	"github.com/gliderlabs/ssh"
	log "github.com/sirupsen/logrus"
	"golang.org/x/term"
)

// SSHStrategy implements the SSH honeypot with session-level virtual worlds.
type SSHStrategy struct {
	Manager *session.Manager
}

func (s *SSHStrategy) Init(servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) error {
	go func() {
		server := &ssh.Server{
			Addr:        servConf.Address,
			MaxTimeout:  time.Duration(servConf.DeadlineTimeoutSeconds) * time.Second,
			IdleTimeout: time.Duration(servConf.DeadlineTimeoutSeconds) * time.Second,
			Version:     servConf.ServerVersion,
			Handler: func(sess ssh.Session) {
				host, port, _ := net.SplitHostPort(sess.RemoteAddr().String())
				remoteAddr := host + ":" + port

				// Reuse or create session (merges short-lived agent connections)
				sessionCtx := s.Manager.GetOrCreateSession(sess.User(), remoteAddr)
				entryIP, entryCIDR, entryGateway := resolveEntryNetwork(sess.LocalAddr().String())
				s.Manager.SetEntryNetwork(sessionCtx.SessionID, entryIP, entryCIDR, entryGateway)

				// Always reset to entry host on new connection — the entry port
				// is the front door; lateral movement happens in-band via SSH.
				sessionCtx.ResetToEntryHost()

				// Inline SSH command (non-interactive)
				if sess.RawCommand() != "" {
					output := s.Manager.ExecuteNonInteractiveCommand(sessionCtx.SessionID, sess.RawCommand())
					sess.Write([]byte(output + "\n"))
					// Don't mark disconnected — idle cleaner handles timeout.
					// This allows subsequent commands from the same agent to reuse the session.
					return
				}

				// Interactive terminal
				terminal := term.NewTerminal(sess, shellPrompt(sessionCtx))

				for {
					// Use ReadPassword during SSH auth to suppress echo
					var commandInput string
					var err error
					if sessionCtx.SuppressShellPrompt {
						passwordBytes, pErr := terminal.ReadPassword("")
						commandInput = string(passwordBytes)
						err = pErr
					} else {
						commandInput, err = terminal.ReadLine()
					}
					if err != nil {
						break
					}
					if sessionCtx.ShellMode == "bash" && (commandInput == "exit" || commandInput == "quit") {
						// Check if we're in nested SSH
						if sessionCtx.IsNestedSSH() {
							restoredWorld, _ := sessionCtx.ExitRemoteHost()
							if restoredWorld != nil {
								sessionCtx.World = restoredWorld
							}
							terminal.Write([]byte("logout\n"))
							terminal.Write([]byte(fmt.Sprintf("Connection to %s closed.\n", sessionCtx.GetCurrentTarget())))
							terminal.SetPrompt(shellPrompt(sessionCtx))
							continue
						}
						terminal.Write([]byte("logout\n"))
						break
					}

					output := s.Manager.ExecuteCommand(sessionCtx.SessionID, commandInput)
					if output != "" {
						terminal.Write([]byte(output))
					}

					// Suppress prompt during SSH password auth flow
					if sessionCtx.SuppressShellPrompt {
						terminal.SetPrompt("")
					} else {
						terminal.SetPrompt(shellPrompt(sessionCtx))
					}
				}

				s.Manager.MarkDisconnected(sessionCtx.SessionID)
			},
			PasswordHandler: func(ctx ssh.Context, password string) bool {
				host, port, _ := net.SplitHostPort(ctx.RemoteAddr().String())

				tr.TraceEvent(tracer.Event{
					Msg:         "SSH Login Attempt",
					Protocol:    tracer.SSH.String(),
					Status:      tracer.Stateless.String(),
					User:        ctx.User(),
					Password:    password,
					Client:      ctx.ClientVersion(),
					RemoteAddr:  ctx.RemoteAddr().String(),
					SourceIp:    host,
					SourcePort:  port,
					Description: servConf.Description,
				})

				// Reject empty passwords
				if password == "" {
					return false
				}

				// If no regex configured, accept all non-empty passwords
				if servConf.PasswordRegex == "" {
					return true
				}
				matched, err := regexp.MatchString(servConf.PasswordRegex, password)
				if err != nil {
					log.Errorf("error regex: %s, %s", servConf.PasswordRegex, err.Error())
					return false
				}
				return matched
			},
		}
		if err := server.ListenAndServe(); err != nil {
			log.Errorf("error during init SSH Protocol: %s", err.Error())
		}
	}()

	log.WithFields(log.Fields{
		"port": servConf.Address,
	}).Infof("AlterHive SSH honeypot started on %s", servConf.Address)
	return nil
}

func resolveEntryNetwork(localAddr string) (ip, cidr, gateway string) {
	ip = envFirst("ENTRY_IP", "TOPOLOGY_ENTRY_IP")
	cidr = envFirst("ENTRY_CIDR", "TOPOLOGY_ENTRY_CIDR")
	gateway = envFirst("ENTRY_GATEWAY", "TOPOLOGY_ENTRY_GATEWAY")

	if ip == "" {
		host, _, err := net.SplitHostPort(localAddr)
		if err == nil {
			ip = host
		} else {
			ip = localAddr
		}
	}
	if ip == "" || ip == "0.0.0.0" || ip == "::" || ip == "127.0.0.1" || ip == "::1" {
		ip = "192.168.97.2"
	}
	if cidr == "" {
		cidr = cidr24(ip)
	}
	if gateway == "" {
		gateway = gatewayFor24(ip)
	}
	return ip, cidr, gateway
}

func envFirst(keys ...string) string {
	for _, key := range keys {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			return v
		}
	}
	return ""
}

func cidr24(ip string) string {
	if parsed := net.ParseIP(ip); parsed == nil || parsed.To4() == nil {
		return "192.168.97.0/24"
	}
	parts := strings.Split(ip, ".")
	return strings.Join(parts[:3], ".") + ".0/24"
}

func gatewayFor24(ip string) string {
	if parsed := net.ParseIP(ip); parsed == nil || parsed.To4() == nil {
		return "192.168.97.1"
	}
	parts := strings.Split(ip, ".")
	return strings.Join(parts[:3], ".") + ".1"
}

// shellPrompt returns the prompt string based on the current shell mode.
func shellPrompt(sessionCtx *domain.SessionContext) string {
	switch sessionCtx.ShellMode {
	case "python":
		return ">>> "
	case "mysql":
		return "mysql> "
	default:
		promptChar := "$ "
		if sessionCtx.User == "root" {
			promptChar = "# "
		}
		return fmt.Sprintf("%s@%s:%s%s", sessionCtx.User, sessionCtx.Hostname, shortenCWD(sessionCtx.CWD), promptChar)
	}
}

// shortenCWD returns ~ for /root, /opt/webapp, or the full path.
func shortenCWD(cwd string) string {
	if cwd == "/root" || cwd == "/opt/webapp" {
		return "~"
	}
	if strings.HasPrefix(cwd, "/root/") {
		return "~" + strings.TrimPrefix(cwd, "/root")
	}
	if strings.HasPrefix(cwd, "/opt/webapp/") {
		return "~" + strings.TrimPrefix(cwd, "/opt/webapp")
	}
	return cwd
}
