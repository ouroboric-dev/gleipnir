package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The architecture page says what Grade does and the guarantees it keeps. A change that drops a word here
// has to change the page too.
func TestTheArchitecturePageDescribesGrade(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "docs", "architecture.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"`Grade`", "`BuildGrader`", "/app", "/tests", "/logs/verifier", "ygg.grader", "`GraderLeftovers`", "`RemoveGrader`", "no network"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("docs/architecture.md does not mention %q", want)
		}
	}
}

// A sandbox with no stack is the factory layer on the Node image (scratch sessions run on it).
func TestTheArchitecturePageDescribesASandboxWithNoStack(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "docs", "architecture.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"FactoryImages", "no stack"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("docs/architecture.md does not mention %q", want)
		}
	}
}
