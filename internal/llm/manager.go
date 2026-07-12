package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// Manager manages LLM providers and handles request routing.
type Manager struct {
	mu         sync.RWMutex
	config     *LLMConfig
	configPath string
	providers  map[string]Provider
	active     Provider
}

// NewManager creates a new LLM manager from config.
func NewManager(config *LLMConfig, configPath string) *Manager {
	m := &Manager{
		config:     config,
		configPath: configPath,
		providers:  make(map[string]Provider),
	}

	// Initialize all enabled providers
	for _, cfg := range config.Providers {
		if cfg.Enabled && (cfg.HasAPIKey() || cfg.Type == "ollama") {
			live := cfg
			if key, _ := cfg.ResolveAPIKey(); key != "" {
				live.APIKey = key
			}
			p := NewProvider(live)
			m.providers[cfg.ID] = p
			log.WithField("provider", cfg.ID).Info("LLM provider initialized")
		}
	}

	// Set active provider
	if active := config.GetActiveProvider(); active != nil && active.Enabled {
		if p, ok := m.providers[active.ID]; ok {
			m.active = p
			log.WithField("provider", active.ID).Info("Active LLM provider set")
		}
	}

	return m
}

// IsActive returns whether an LLM provider is active and ready.
func (m *Manager) IsActive() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config.Enabled && m.active != nil
}

// GetActiveProvider returns the active provider config.
func (m *Manager) GetActiveProvider() *ProviderConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.active == nil {
		return nil
	}
	return m.config.GetActiveProvider()
}

// Complete sends a completion request to the active provider.
func (m *Manager) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	if !allowProviderNetworkRequests() {
		return nil, fmt.Errorf("LLM provider network requests are disabled")
	}

	m.mu.RLock()
	p := m.active
	m.mu.RUnlock()

	if p == nil {
		return nil, fmt.Errorf("no active LLM provider configured")
	}
	return p.Complete(ctx, req)
}

func allowProviderNetworkRequests() bool {
	return strings.EqualFold(os.Getenv("ALTERHIVE_ALLOW_LLM_NETWORK"), "true")
}

// TestConnection tests a specific provider's connection.
// If overrideBaseURL or overrideAPIKey are non-empty, they override the saved config values.
func (m *Manager) TestConnection(ctx context.Context, providerID, overrideBaseURL, overrideAPIKey string) error {
	if !allowProviderNetworkRequests() {
		return fmt.Errorf("LLM provider network requests are disabled")
	}

	m.mu.RLock()
	cfg := m.config.GetProvider(providerID)
	m.mu.RUnlock()

	if cfg == nil {
		return fmt.Errorf("provider %q not found", providerID)
	}

	// Always start from the env-aware resolved key so an unset YAML
	// field doesn't silently disable TestConnection.
	resolved, _ := cfg.ResolveAPIKey()
	if cfg.BaseURL == "" && overrideBaseURL == "" {
		return fmt.Errorf("provider %q has no base URL configured", providerID)
	}
	if resolved == "" && overrideAPIKey == "" {
		return fmt.Errorf("provider %q has no API key configured (set env %s or fill api_key)", providerID, cfg.APIKeyEnv())
	}

	if overrideBaseURL != "" {
		cfg.BaseURL = overrideBaseURL
	}
	if overrideAPIKey != "" {
		cfg.APIKey = overrideAPIKey
	} else {
		cfg.APIKey = resolved
	}

	p := NewProvider(*cfg)
	return p.TestConnection(ctx)
}

// SwitchProvider changes the active provider.
func (m *Manager) SwitchProvider(providerID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cfg := m.config.GetProvider(providerID)
	if cfg == nil {
		return fmt.Errorf("provider %q not found", providerID)
	}
	if !cfg.Enabled {
		return fmt.Errorf("provider %q is not enabled", providerID)
	}

	p, ok := m.providers[providerID]
	if !ok {
		live := *cfg
		if key, _ := cfg.ResolveAPIKey(); key != "" {
			live.APIKey = key
		}
		p = NewProvider(live)
		m.providers[providerID] = p
	}

	m.active = p
	m.config.ActiveProvider = providerID

	// Save config
	if m.configPath != "" {
		if err := m.config.Save(m.configPath); err != nil {
			log.WithError(err).Warn("Failed to save LLM config")
		}
	}

	log.WithField("provider", providerID).Info("Switched LLM provider")
	return nil
}

// SetEnabled globally enables or disables LLM.
func (m *Manager) SetEnabled(enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.config.Enabled = enabled
	if !enabled {
		m.active = nil
	} else if m.config.ActiveProvider != "" {
		// Re-activate the configured provider
		if p, ok := m.providers[m.config.ActiveProvider]; ok {
			m.active = p
		}
	}

	if m.configPath != "" {
		if err := m.config.Save(m.configPath); err != nil {
			return err
		}
	}
	return nil
}

// UpdateProvider updates a provider's configuration.
func (m *Manager) UpdateProvider(cfg ProviderConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Find and update in config
	found := false
	for i := range m.config.Providers {
		if m.config.Providers[i].ID == cfg.ID {
			m.config.Providers[i] = cfg
			found = true
			break
		}
	}
	if !found {
		m.config.Providers = append(m.config.Providers, cfg)
	}

	// Recreate provider if enabled. Use HasAPIKey so a key coming from the
	// environment still allows the provider to come up without forcing
	// the user to duplicate the secret back into YAML.
	if cfg.Enabled && (cfg.HasAPIKey() || cfg.Type == "ollama") {
		live := cfg
		if key, _ := cfg.ResolveAPIKey(); key != "" {
			live.APIKey = key
		}
		p := NewProvider(live)
		m.providers[cfg.ID] = p
	} else {
		delete(m.providers, cfg.ID)
	}

	// Update active if this was the active provider
	if m.config.ActiveProvider == cfg.ID {
		if cfg.Enabled {
			m.active = m.providers[cfg.ID]
		} else {
			m.active = nil
		}
	}

	// Save config
	if m.configPath != "" {
		if err := m.config.Save(m.configPath); err != nil {
			log.WithError(err).Warn("Failed to save LLM config")
		}
	}

	return nil
}

// ListProviders returns all provider configs.
func (m *Manager) ListProviders() []ProviderConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config.Providers
}

// GetProviderReal returns the real (unmasked) provider config by ID.
func (m *Manager) GetProviderReal(id string) *ProviderConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config.GetProvider(id)
}

// GetConfig returns the full LLM config.
// API keys are returned as-is (frontend uses Input.Password to hide them visually).
func (m *Manager) GetConfig() LLMConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()

	cfg := *m.config
	return cfg
}

// FetchModels fetches the available model list from a provider's API.
// If overrideBaseURL or overrideAPIKey are non-empty, they override the saved config values.
func (m *Manager) FetchModels(ctx context.Context, providerID, overrideBaseURL, overrideAPIKey string) ([]ModelInfo, error) {
	if !allowProviderNetworkRequests() {
		return nil, fmt.Errorf("LLM provider network requests are disabled")
	}

	m.mu.RLock()
	cfg := m.config.GetProvider(providerID)
	m.mu.RUnlock()

	if cfg == nil {
		return nil, fmt.Errorf("provider %q not found", providerID)
	}

	resolved, _ := cfg.ResolveAPIKey()
	baseURL := cfg.BaseURL
	apiKey := resolved
	if overrideBaseURL != "" {
		baseURL = overrideBaseURL
	}
	if overrideAPIKey != "" {
		apiKey = overrideAPIKey
	}

	switch cfg.Type {
	case "anthropic":
		return fetchAnthropicModels()
	case "ollama":
		return fetchOllamaModels(ctx, baseURL)
	default:
		return fetchOpenAIModels(ctx, baseURL, apiKey)
	}
}

// fetchOllamaModels fetches models from Ollama's /api/tags endpoint (no API key needed).
func fetchOllamaModels(ctx context.Context, baseURL string) ([]ModelInfo, error) {
	base := strings.TrimRight(baseURL, "/")
	// Strip /v1 suffix if present — Ollama API is at root
	base = strings.TrimSuffix(base, "/v1")
	if base == "" {
		base = "http://127.0.0.1:11434"
	}

	url := base + "/api/tags"
	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Ollama API error (%d): %s", resp.StatusCode, string(body))
	}

	var result struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	models := make([]ModelInfo, 0, len(result.Models))
	for _, m := range result.Models {
		if m.Name != "" {
			models = append(models, ModelInfo{ID: m.Name, OwnedBy: "ollama"})
		}
	}
	return models, nil
}

// fetchOpenAIModels fetches models from an OpenAI-compatible /v1/models endpoint.
// Tries multiple URL patterns to handle different provider configurations.
func fetchOpenAIModels(ctx context.Context, baseURL, apiKey string) ([]ModelInfo, error) {
	base := strings.TrimRight(baseURL, "/")

	// Build candidate URLs (mirrors V1.0.0 logic)
	var candidates []string
	seen := make(map[string]bool)
	addCandidate := func(u string) {
		if !seen[u] {
			candidates = append(candidates, u)
			seen[u] = true
		}
	}

	if strings.Contains(base, "/chat/completions") {
		addCandidate(strings.Replace(base, "/chat/completions", "/models", 1))
	}
	if strings.HasSuffix(base, "/v1") {
		addCandidate(base + "/models")
	} else {
		addCandidate(base + "/v1/models")
		addCandidate(base + "/models")
	}

	client := &http.Client{Timeout: 15 * time.Second}

	for _, url := range candidates {
		httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		if apiKey != "" {
			httpReq.Header.Set("Authorization", "Bearer "+apiKey)
		}

		resp, err := client.Do(httpReq)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode >= 400 {
			continue
		}

		// Try standard OpenAI format: {"data": [{"id": "...", "owned_by": "..."}]}
		var openAIResult struct {
			Data []struct {
				ID      string `json:"id"`
				OwnedBy string `json:"owned_by"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &openAIResult); err == nil && len(openAIResult.Data) > 0 {
			models := make([]ModelInfo, 0, len(openAIResult.Data))
			for _, m := range openAIResult.Data {
				models = append(models, ModelInfo{ID: m.ID, OwnedBy: m.OwnedBy})
			}
			return models, nil
		}

		// Try plain array format: [{"id": "..."}]
		var plainResult []struct {
			ID      string `json:"id"`
			OwnedBy string `json:"owned_by"`
		}
		if err := json.Unmarshal(body, &plainResult); err == nil && len(plainResult) > 0 {
			models := make([]ModelInfo, 0, len(plainResult))
			for _, m := range plainResult {
				models = append(models, ModelInfo{ID: m.ID, OwnedBy: m.OwnedBy})
			}
			return models, nil
		}
	}

	return nil, fmt.Errorf("no models endpoint reachable for %s", baseURL)
}

func fetchAnthropicModels() ([]ModelInfo, error) {
	// Anthropic has no public models API — return known models
	return []ModelInfo{
		{ID: "claude-opus-4-20250514", OwnedBy: "anthropic"},
		{ID: "claude-sonnet-4-20250514", OwnedBy: "anthropic"},
		{ID: "claude-haiku-4-5-20251001", OwnedBy: "anthropic"},
		{ID: "claude-3-5-sonnet-20241022", OwnedBy: "anthropic"},
		{ID: "claude-3-5-haiku-20241022", OwnedBy: "anthropic"},
		{ID: "claude-3-opus-20240229", OwnedBy: "anthropic"},
	}, nil
}
