package scripted

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ouroboric-dev/gungnir"
)

func load(t *testing.T, script string) *Agent {
	t.Helper()
	p := filepath.Join(t.TempDir(), "script.yaml")
	if err := os.WriteFile(p, []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
	a, err := Load(p)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	return a
}

func TestScriptedReplaysOneStepPerAttempt(t *testing.T) {
	a := load(t, `
steps:
  design:
    - actions:
        - write: { path: docs/design.md, content: "# Design\n" }
      result: { status: ok, summary: wrote the design, usage: { in: 1000, out: 200, cache: 50, turns: 3, cost_usd: 0.01 } }
    - result: { status: failed, summary: gave up }
`)
	work, transcripts := t.TempDir(), t.TempDir()
	task := gungnir.Task{Role: "planner", Node: "design", Attempt: 1, Prompt: "Write the design.", Workdir: work, TranscriptDir: transcripts}
	r, err := a.Run(context.Background(), task)
	if err != nil {
		t.Fatalf("attempt 1: %v", err)
	}
	if r.Status != gungnir.StatusOK || r.Usage.InTok != 1000 || r.Usage.Turns != 3 || r.Usage.CostUSD != 0.01 {
		t.Errorf("attempt 1 = %+v", r)
	}
	if b, err := os.ReadFile(filepath.Join(work, "docs/design.md")); err != nil || string(b) != "# Design\n" {
		t.Errorf("docs/design.md = %q, %v", b, err)
	}
	if b, err := os.ReadFile(r.TranscriptPath); err != nil || !strings.Contains(string(b), "Write the design.") {
		t.Errorf("transcript %s = %q, %v; want the prompt in it", r.TranscriptPath, b, err)
	}
	task.Attempt = 2
	if r, err := a.Run(context.Background(), task); err != nil || r.Status != gungnir.StatusFailed {
		t.Errorf("attempt 2 = %+v, %v; want a failed result", r, err)
	}
	task.Attempt = 3
	if _, err := a.Run(context.Background(), task); err == nil {
		t.Error("attempt 3 has no step, but Run returned no error")
	}
	if _, err := a.Run(context.Background(), gungnir.Task{Node: "spec", Attempt: 1, Workdir: work}); err == nil {
		t.Error("node spec has no steps, but Run returned no error")
	}
}

func TestScriptedHangsUntilTheContextEnds(t *testing.T) {
	a := load(t, "steps:\n  build:\n    - hang: true\n")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := a.Run(ctx, gungnir.Task{Node: "build", Attempt: 1, Workdir: t.TempDir()})
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run() = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run() did not return after the context was cancelled")
	}
}

func TestScriptedErrorStepIsAnAgentFailure(t *testing.T) {
	a := load(t, "steps:\n  build:\n    - error: the CLI crashed\n")
	if _, err := a.Run(context.Background(), gungnir.Task{Node: "build", Attempt: 1, Workdir: t.TempDir()}); err == nil || err.Error() != "the CLI crashed" {
		t.Errorf("Run() = %v, want the script's error", err)
	}
}

func TestScriptedCannotWriteOutsideTheWorkdir(t *testing.T) {
	outside := t.TempDir()
	work := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(work, "link")); err != nil {
		t.Fatal(err)
	}
	a := load(t, "steps:\n  build:\n    - actions:\n        - write: { path: link/escaped.txt, content: x }\n      result: { status: ok }\n")
	if _, err := a.Run(context.Background(), gungnir.Task{Node: "build", Attempt: 1, Workdir: work}); err == nil {
		t.Error("a write through a symlink out of the workdir succeeded")
	}
	if _, err := os.Stat(filepath.Join(outside, "escaped.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("escaped.txt exists outside the workdir (stat: %v)", err)
	}
}

func TestLoadRefusesAmbiguousScripts(t *testing.T) {
	cases := map[string]string{
		"two outcomes":       "steps:\n  a:\n    - { hang: true, result: { status: ok } }\n",
		"no outcome":         "steps:\n  a:\n    - actions: [ { remove: x } ]\n",
		"an unknown status":  "steps:\n  a:\n    - result: { status: passed }\n",
		"an unknown field":   "steps:\n  a:\n    - result: { status: ok }\n      sleep: 5\n",
		"a path that climbs": "steps:\n  a:\n    - actions: [ { write: { path: ../x, content: y } } ]\n      result: { status: ok }\n",
		"an absolute path":   "steps:\n  a:\n    - actions: [ { remove: /etc/passwd } ]\n      result: { status: ok }\n",
		"write and remove":   "steps:\n  a:\n    - actions: [ { write: { path: x, content: y }, remove: z } ]\n      result: { status: ok }\n",
		"two YAML documents": "steps:\n  a:\n    - result: { status: ok }\n---\nsteps:\n  b:\n    - result: { status: ok }\n",
	}
	for name, s := range cases {
		p := filepath.Join(t.TempDir(), "script.yaml")
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil {
			t.Errorf("%s: Load() = nil error", name)
		}
	}
}
