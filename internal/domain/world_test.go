package domain

import "testing"

func TestInjectLsOutputIgnoresShortLongFormatWithoutPanic(t *testing.T) {
	world := NewWorldState()

	world.InjectLsOutput("/tmp/llm-noise", "-rw-r--r-- 1 root root 42 Jun")

	if !world.FileExists("/tmp/llm-noise") {
		t.Fatalf("expected target directory to be created")
	}
}
