package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/alterhive/alterhive/internal/domain"
	"github.com/alterhive/alterhive/internal/llm"
)

// capturingLLMClient records the system prompt sent to the LLM so tests can
// assert that the L0/L1/L2 layered memory context was injected.
type capturingLLMClient struct {
	active       bool
	content      string
	systemPrompt string
}

func (f *capturingLLMClient) IsActive() bool { return f.active }

func (f *capturingLLMClient) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	f.systemPrompt = ""
	for _, msg := range req.Messages {
		if msg.Role == "system" {
			f.systemPrompt += msg.Content + "\n"
		}
	}
	return &llm.CompletionResponse{Content: f.content}, nil
}

// TestLLMFallbackInjectsMemoryContext verifies that the LLM system prompt
// includes the L2 invariants (host identity, network entry) from the Memory
// Manager, per architecture §3.2 (L0/L1/L2 layered context).
func TestLLMFallbackInjectsMemoryContext(t *testing.T) {
	topology := testTopology()
	engine := NewRuleEngine(topology, domain.NewSafetyPolicy("192.168.56.0/24"), domain.NewServiceRegistry(topology))
	client := &capturingLLMClient{active: true, content: "deploy:x:1001:1001::/home/deploy:/bin/bash\n"}
	engine.SetLLMClient(client)

	session := domain.NewSessionContext("www-data", "127.0.0.1:0")
	session.Memory.SetInvariant("host.identity", "staging-web-01|Ubuntu 22.04|192.168.56.23", "test")
	session.Memory.SetInvariant("network.entry", "dual-nic entry: eth0 dynamic, eth1 192.168.56.23/24", "test")
	world := domain.NewWorldState()

	// stat of an unknown file path triggers LLM fallback (not in world state, not a protected file)
	engine.HandleCommand("stat /opt/webapp/deploy.trace", session, world, false)

	if client.systemPrompt == "" {
		t.Fatal("expected non-empty system prompt sent to LLM")
	}
	// L2 invariant: host identity must be in the prompt
	if !strings.Contains(client.systemPrompt, "host.identity") {
		t.Fatalf("expected L2 host.identity invariant in system prompt, got: %q", client.systemPrompt)
	}
	// L2 invariant: network entry must be in the prompt
	if !strings.Contains(client.systemPrompt, "network.entry") {
		t.Fatalf("expected L2 network.entry invariant in system prompt, got: %q", client.systemPrompt)
	}
}

// TestLLMFallbackInjectsContextAwareSlice verifies that context-aware L1 facts
// are selectively injected based on command semantics (architecture §3.2
// buildL1Context). A secret-hunting cat command should include the secret
// hunting hint.
func TestLLMFallbackInjectsContextAwareSlice(t *testing.T) {
	topology := testTopology()
	engine := NewRuleEngine(topology, domain.NewSafetyPolicy("192.168.56.0/24"), domain.NewServiceRegistry(topology))
	client := &capturingLLMClient{active: true, content: "DB_PASSWORD=Summer2023_backup!\n"}
	engine.SetLLMClient(client)

	session := domain.NewSessionContext("www-data", "127.0.0.1:0")
	// Simulate that the memory has observed secret-hunting behavior
	session.Memory.ObserveCommand("grep password /opt/webapp/.env", "", []string{"pseudo_progress"})
	world := domain.NewWorldState()

	// cat of an unknown config file triggers LLM fallback and matches the
	// cat/grep context-aware slice
	engine.HandleCommand("cat /opt/webapp/secrets.env", session, world, false)

	if client.systemPrompt == "" {
		t.Fatal("expected non-empty system prompt")
	}
	// The context-aware slice should mention secret hunting
	if !strings.Contains(client.systemPrompt, "secret") {
		t.Fatalf("expected secret-hunting context in prompt for cat command, got: %q", client.systemPrompt)
	}
}
