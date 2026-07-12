package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Message represents a chat message.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// CompletionRequest is the request to generate a completion.
type CompletionRequest struct {
	Messages       []Message `json:"messages"`
	MaxTokens      int       `json:"max_tokens,omitempty"`
	Temperature    float64   `json:"temperature,omitempty"`
	ResponseFormat string    `json:"response_format,omitempty"`
}

// CompletionResponse is the response from a completion.
type CompletionResponse struct {
	Content string `json:"content"`
	Model   string `json:"model"`
	Usage   struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

// Provider is the interface for LLM providers.
type Provider interface {
	// Name returns the provider display name.
	Name() string
	// Complete sends a completion request and returns the response.
	Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error)
	// TestConnection verifies the provider is reachable and credentials are valid.
	TestConnection(ctx context.Context) error
}

// NewProvider creates a Provider from config.
func NewProvider(cfg ProviderConfig) Provider {
	switch cfg.Type {
	case "anthropic":
		return newAnthropicProvider(cfg)
	case "ollama":
		return newOllamaProvider(cfg)
	default: // "openai" and compatible
		return newOpenAIProvider(cfg)
	}
}

// --- OpenAI-Compatible Provider ---

type openAIProvider struct {
	cfg    ProviderConfig
	client *http.Client
}

func newOpenAIProvider(cfg ProviderConfig) *openAIProvider {
	return &openAIProvider{
		cfg:    cfg,
		client: &http.Client{Timeout: 120 * time.Second},
	}
}

func (p *openAIProvider) Name() string { return p.cfg.Name }

func (p *openAIProvider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	url := strings.TrimRight(p.cfg.BaseURL, "/") + "/chat/completions"

	body := map[string]interface{}{
		"model":       p.cfg.Model,
		"messages":    req.Messages,
		"max_tokens":  req.MaxTokens,
		"temperature": req.Temperature,
	}
	if body["max_tokens"] == 0 {
		body["max_tokens"] = p.cfg.MaxTokens
	}
	if body["temperature"] == 0 {
		body["temperature"] = p.cfg.Temperature
	}
	if req.ResponseFormat == "json_object" {
		body["response_format"] = map[string]string{"type": "json_object"}
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if p.cfg.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+p.cfg.APIKey)
	}

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error (%d): %s", resp.StatusCode, string(respBody))
	}

	var openAIResp struct {
		Choices []struct {
			Message struct {
				Content          string `json:"content"`
				ReasoningContent string `json:"reasoning_content"`
			} `json:"message"`
		} `json:"choices"`
		Model string `json:"model"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
			TotalTokens      int `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(respBody, &openAIResp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	if len(openAIResp.Choices) == 0 {
		return nil, fmt.Errorf("no choices in response")
	}

	content := openAIResp.Choices[0].Message.Content
	if strings.TrimSpace(content) == "" {
		content = openAIResp.Choices[0].Message.ReasoningContent
	}
	result := &CompletionResponse{
		Content: content,
		Model:   openAIResp.Model,
	}
	result.Usage = openAIResp.Usage
	return result, nil
}

func (p *openAIProvider) TestConnection(ctx context.Context) error {
	base := strings.TrimRight(p.cfg.BaseURL, "/")

	// Try multiple URL patterns (same as fetchOpenAIModels)
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

	for _, url := range candidates {
		httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		if p.cfg.APIKey != "" {
			httpReq.Header.Set("Authorization", "Bearer "+p.cfg.APIKey)
		}

		resp, err := p.client.Do(httpReq)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			return nil
		}
		if resp.StatusCode == http.StatusUnauthorized {
			return fmt.Errorf("authentication failed (invalid API key)")
		}
	}

	return fmt.Errorf("no models endpoint reachable for %s", base)
}

// --- Anthropic Provider ---

type anthropicProvider struct {
	cfg    ProviderConfig
	client *http.Client
}

func newAnthropicProvider(cfg ProviderConfig) *anthropicProvider {
	return &anthropicProvider{
		cfg:    cfg,
		client: &http.Client{Timeout: 120 * time.Second},
	}
}

func (p *anthropicProvider) Name() string { return p.cfg.Name }

func (p *anthropicProvider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	url := strings.TrimRight(p.cfg.BaseURL, "/") + "/v1/messages"

	// Convert messages to Anthropic format
	var systemPrompt string
	var messages []map[string]string
	for _, msg := range req.Messages {
		if msg.Role == "system" {
			systemPrompt = msg.Content
			continue
		}
		messages = append(messages, map[string]string{
			"role":    msg.Role,
			"content": msg.Content,
		})
	}

	body := map[string]interface{}{
		"model":      p.cfg.Model,
		"messages":   messages,
		"max_tokens": req.MaxTokens,
	}
	if body["max_tokens"] == 0 {
		body["max_tokens"] = p.cfg.MaxTokens
	}
	if systemPrompt != "" {
		body["system"] = systemPrompt
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", p.cfg.APIKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error (%d): %s", resp.StatusCode, string(respBody))
	}

	var anthropicResp struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		Model string `json:"model"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(respBody, &anthropicResp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	if len(anthropicResp.Content) == 0 {
		return nil, fmt.Errorf("no content in response")
	}

	var textParts []string
	for _, c := range anthropicResp.Content {
		if c.Type == "text" {
			textParts = append(textParts, c.Text)
		}
	}

	result := &CompletionResponse{
		Content: strings.Join(textParts, ""),
		Model:   anthropicResp.Model,
	}
	result.Usage.PromptTokens = anthropicResp.Usage.InputTokens
	result.Usage.CompletionTokens = anthropicResp.Usage.OutputTokens
	result.Usage.TotalTokens = anthropicResp.Usage.InputTokens + anthropicResp.Usage.OutputTokens
	return result, nil
}

func (p *anthropicProvider) TestConnection(ctx context.Context) error {
	url := strings.TrimRight(p.cfg.BaseURL, "/") + "/v1/messages"

	body := map[string]interface{}{
		"model":      p.cfg.Model,
		"max_tokens": 1,
		"messages":   []map[string]string{{"role": "user", "content": "hi"}},
	}
	jsonBody, _ := json.Marshal(body)

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(jsonBody))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", p.cfg.APIKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("authentication failed (invalid API key)")
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error (%d): %s", resp.StatusCode, string(body))
	}
	return nil
}

// --- Ollama Provider (native /api/chat) ---

type ollamaProvider struct {
	cfg    ProviderConfig
	client *http.Client
}

func newOllamaProvider(cfg ProviderConfig) *ollamaProvider {
	return &ollamaProvider{
		cfg:    cfg,
		client: &http.Client{Timeout: 120 * time.Second},
	}
}

func (p *ollamaProvider) Name() string { return p.cfg.Name }

func (p *ollamaProvider) ollamaBase() string {
	base := strings.TrimRight(p.cfg.BaseURL, "/")
	base = strings.TrimSuffix(base, "/v1")
	if base == "" {
		base = "http://127.0.0.1:11434"
	}
	return base
}

func (p *ollamaProvider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	url := p.ollamaBase() + "/api/chat"

	maxTokens := req.MaxTokens
	if maxTokens == 0 {
		maxTokens = p.cfg.MaxTokens
	}

	var messages []map[string]string
	for _, msg := range req.Messages {
		messages = append(messages, map[string]string{
			"role":    msg.Role,
			"content": msg.Content,
		})
	}

	body := map[string]interface{}{
		"model":    p.cfg.Model,
		"messages": messages,
		"stream":   false,
		"options": map[string]interface{}{
			"num_predict": maxTokens,
		},
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Ollama API error (%d): %s", resp.StatusCode, string(respBody))
	}

	var ollamaResp struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		Model string `json:"model"`
	}
	if err := json.Unmarshal(respBody, &ollamaResp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return &CompletionResponse{
		Content: ollamaResp.Message.Content,
		Model:   ollamaResp.Model,
	}, nil
}

func (p *ollamaProvider) TestConnection(ctx context.Context) error {
	url := p.ollamaBase() + "/api/tags"

	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Ollama API error (%d): %s", resp.StatusCode, string(body))
	}
	return nil
}
