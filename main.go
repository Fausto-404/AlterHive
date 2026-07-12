package main

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/alterhive/alterhive/api"
	"github.com/alterhive/alterhive/internal/domain"
	"github.com/alterhive/alterhive/internal/llm"
	"github.com/alterhive/alterhive/internal/parser"
	"github.com/alterhive/alterhive/internal/protocols/strategies/SSH"
	"github.com/alterhive/alterhive/internal/session"
	"github.com/alterhive/alterhive/internal/tracer"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

const banner = "\n  AlterHive v3.0 - Honeypot for Adversarial AI Agents (Go)\n\n"

func main() {
	fmt.Print(banner)

	// Deploy seed from env (used for canary IDs, tokens, etc.)
	if seed := os.Getenv("DEPLOY_SEED"); seed != "" {
		domain.DeploySeed = seed
	}

	// Determine config directory
	configDir := getEnv("CONFIG_DIR", "configs")
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		configDir = "/app/configs" // Docker fallback
	}

	// --- Load topology from YAML ---
	topologyPath := filepath.Join(configDir, "topology.yaml")
	topologyData, err := os.ReadFile(topologyPath)
	if err != nil {
		log.Fatalf("Failed to read topology config %s: %v", topologyPath, err)
	}
	topologyConfig, err := domain.LoadTopologyConfig(topologyData)
	if err != nil {
		log.Fatalf("Failed to parse topology config: %v", err)
	}

	// Allow env overrides
	if v := os.Getenv("TOPOLOGY_CIDR"); v != "" {
		topologyConfig, err = domain.RebasePrimaryCIDR(topologyConfig, v)
		if err != nil {
			log.Fatalf("Failed to rebase topology CIDR: %v", err)
		}
	}

	topology := domain.NewVirtualTopology(topologyConfig)
	safety := domain.NewSafetyPolicy(topologyConfig.CIDR)
	for _, segment := range topology.AllSegments() {
		safety.AllowCIDR(segment.CIDR)
	}

	log.WithFields(log.Fields{
		"cidr":  topologyConfig.CIDR,
		"hosts": len(topologyConfig.Hosts),
	}).Info("Topology loaded")

	// --- Init tracer ---
	tr := tracer.GetInstance(func(event tracer.Event) {
		log.WithFields(log.Fields{
			"protocol": event.Protocol,
			"status":   event.Status,
			"command":  event.Command,
			"user":     event.User,
		}).Info("Honeypot Event")
	})

	// --- Load LLM config ---
	llmConfigPath := filepath.Join(configDir, "llm.yaml")
	llmConfig, err := llm.LoadLLMConfig(llmConfigPath)
	if err != nil {
		log.WithError(err).Warn("Failed to load LLM config, LLM features disabled")
		llmConfig = &llm.LLMConfig{Providers: []llm.ProviderConfig{}}
	}
	llmMgr := llm.NewManager(llmConfig, llmConfigPath)

	if llmMgr.IsActive() {
		log.WithField("provider", llmConfig.ActiveProvider).Info("LLM active")
	} else {
		log.Info("LLM disabled (no provider configured)")
	}

	// --- Session manager ---
	mgr := session.NewManager(topology, safety, tr, "staging-web-01", llmMgr)

	// --- Load SSH service config from YAML ---
	servicesDir := filepath.Join(configDir, "services")
	p := parser.Init("", servicesDir)
	services, err := p.ReadConfigurationsServices()
	if err != nil {
		log.Fatalf("Failed to read SSH service config: %v", err)
	}

	if len(services) == 0 {
		log.Fatal("No service configurations found in configs/services/")
	}

	sshConf := services[0] // First service config (ssh.yaml)

	// Allow env overrides for SSH
	if v := os.Getenv("SSH_ADDR"); v != "" {
		sshConf.Address = v
	}
	if v := os.Getenv("SESSION_TIMEOUT"); v != "" {
		if seconds, err := strconv.Atoi(v); err == nil && seconds > 0 {
			sshConf.DeadlineTimeoutSeconds = seconds
		}
	}

	// --- Start SSH honeypot ---
	sshStrategy := &SSH.SSHStrategy{Manager: mgr}
	if err := sshStrategy.Init(sshConf, tr); err != nil {
		log.Fatalf("Failed to start SSH: %v", err)
	}

	log.WithField("address", sshConf.Address).Info("SSH honeypot started")

	// --- REST API ---
	apiAddr := getEnv("API_ADDR", ":8000")
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	})

	apiServer := api.NewServer(mgr, llmMgr)
	apiServer.RegisterRoutes(router)

	log.WithField("api", apiAddr).Info("API server started")

	go func() {
		if err := http.ListenAndServe(apiAddr, router); err != nil && err != http.ErrServerClosed {
			log.Fatalf("API server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down AlterHive...")
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
