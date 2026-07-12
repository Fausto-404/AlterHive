package domain

import (
	"strings"
	"testing"
)

func TestDeceptionMemoryTracksIntentAndPheromones(t *testing.T) {
	memory := NewDeceptionMemory()
	memory.ObserveCommand("nmap -sV 172.16.56.50", "Nmap scan report for 172.16.56.50\n", []string{"subnet_scan"})
	memory.ObserveCommand("grep -Ri password /opt/webapp", "DB_PASSWORD=redacted\n", []string{"secret_file"})

	summary := memory.PromptSummary()
	for _, want := range []string{"intent.network_mapping", "intent.secret_hunting", "recon_path", "secret_path", "172.16.56.50"} {
		if !strings.Contains(summary, want) {
			t.Fatalf("expected memory summary to contain %q, got %q", want, summary)
		}
	}
}
