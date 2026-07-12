package responders

import (
	"strings"
	"testing"

	"github.com/alterhive/alterhive/internal/deception"
	"github.com/alterhive/alterhive/internal/domain"
)

func TestC2DecoyUnlocksOnlyJumpFoothold(t *testing.T) {
	session := domain.NewSessionContext("agent", "127.0.0.1:4444")
	out, hits := HandleC2Command("sliver-client shell", session)
	if !strings.Contains(out, "jump01") {
		t.Fatalf("expected jump01 decoy shell, got %q", out)
	}
	if !session.HasAccessState(deception.Jump01FootholdState()) {
		t.Fatalf("expected jump foothold state to unlock")
	}
	if len(hits) == 0 || hits[0] != "c2_attempt" {
		t.Fatalf("expected c2 evidence hit, got %#v", hits)
	}
}
