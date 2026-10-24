package scripted

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ouroboric-dev/gungnir"
	"github.com/ouroboric-dev/gungnir/schema"
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

type fakeRunner struct {
	got  []gungnir.Cmd
	exit int
}

func (f *fakeRunner) Run(_ context.Context, c gungnir.Cmd) (gungnir.ExecResult, error) {
	f.got = append(f.got, c)
	c.Stdout.Write([]byte("output of " + c.Argv[0]))
	return gungnir.ExecResult{ExitCode: f.exit}, nil
}

func TestScriptedRunsCommandsOnlyInTheSandbox(t *testing.T) {
	a := load(t, `
steps:
  design:
    - actions:
        - run: { argv: [cat, /root/.ssh/id_ed25519], allow_failure: true }
        - write: { path: out.txt, content: "ok" }
      result: { status: ok, summary: tried }
`)
	task := gungnir.Task{Node: "design", Attempt: 1, Workdir: t.TempDir(), TranscriptDir: t.TempDir()}
	if _, err := a.Run(context.Background(), task); err == nil || !strings.Contains(err.Error(), "needs a sandbox") {
		t.Fatalf("a run action without a sandbox: %v, want a refusal", err)
	}
	f := &fakeRunner{exit: 1}
	task.Sandbox = f
	if _, err := a.Run(context.Background(), task); err != nil {
		t.Fatalf("an allowed failure ended the step: %v", err)
	}
	if len(f.got) != 1 || f.got[0].Argv[1] != "/root/.ssh/id_ed25519" {
		t.Errorf("sandbox got %+v", f.got)
	}
	if b, _ := os.ReadFile(filepath.Join(task.TranscriptDir, "design-1-run-1.log")); string(b) != "output of cat" {
		t.Errorf("the command's output = %q", b)
	}
	strict := load(t, "steps:\n  design:\n    - actions: [ { run: { argv: [false] } } ]\n      result: { status: ok, summary: x }\n")
	if _, err := strict.Run(context.Background(), task); err == nil || !strings.Contains(err.Error(), "exited 1") {
		t.Errorf("a failing command without allow_failure: %v", err)
	}
}

func TestScriptedRefusesAnActionThatSetsTwoThings(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.yaml")
	os.WriteFile(p, []byte("steps:\n  d:\n    - actions: [ { remove: x, run: { argv: [true] } } ]\n      result: { status: ok, summary: x }\n"), 0o644)
	if _, err := Load(p); err == nil {
		t.Error("Load() = nil, want an error")
	}
}

func TestScriptedReportsAProviderAndAToolVersionWhenTheScriptGivesThem(t *testing.T) {
	a := load(t, "steps:\n  design:\n    - result: { status: ok, summary: x, provider: anthropic, cli_version: 2.1.284 }\n")
	r, err := a.Run(context.Background(), gungnir.Task{Node: "design", Attempt: 1, Workdir: t.TempDir()})
	if err != nil || r.Provider != "anthropic" || r.CLIVersion != "2.1.284" {
		t.Errorf("Run() = %+v, %v", r, err)
	}
}

func run(t *testing.T, a *Agent, node string, attempt int) (gungnir.Result, error) {
	t.Helper()
	return a.Run(context.Background(), gungnir.Task{Node: node, Attempt: attempt, Workdir: t.TempDir()})
}

func TestScriptedFailsTheWayTheScriptSays(t *testing.T) {
	a := load(t, `
steps:
  build:
    - error: the CLI crashed
      kind: transient
    - error: out of credits
      kind: quota
      usage: { in: 100, out: 20, turns: 2 }
    - error: podman is gone
      kind: infra
    - error: just broke
    - result: { status: failed, summary: rate limited, failure: transient }
    - result: { status: failed, summary: no credits, failure: quota, usage: { in: 5, out: 1, turns: 1 } }
    - result: { status: failed, summary: tests fail }
`)
	want := []gungnir.FailureKind{gungnir.FailureTransient, gungnir.FailureQuota, gungnir.FailureInfra, gungnir.FailureAgent}
	for i, k := range want {
		_, err := run(t, a, "build", i+1)
		if err == nil || gungnir.FailureOf(err) != k {
			t.Errorf("attempt %d: Run() = %v (kind %q), want an error of kind %q", i+1, err, gungnir.FailureOf(err), k)
		}
	}
	_, err := run(t, a, "build", 2)
	var se *gungnir.SessionError
	if !errors.As(err, &se) || se.Usage.InTok != 100 || se.Usage.OutTok != 20 || se.Usage.Turns != 2 {
		t.Errorf("the quota error's usage = %+v", se)
	}
	if _, err := run(t, a, "build", 4); err == nil || errors.As(err, &se) {
		t.Errorf("an error with no kind and no usage must stay a plain error, got %T %v", err, err)
	}
	for i, k := range []gungnir.FailureKind{gungnir.FailureTransient, gungnir.FailureQuota, ""} {
		r, err := run(t, a, "build", i+5)
		if err != nil || r.Status != gungnir.StatusFailed || r.Failure != k {
			t.Errorf("result %d: %+v, %v; want a failed result of kind %q", i+5, r, err, k)
		}
	}
}

func TestAHangEndsWithTheContextAndItsUsage(t *testing.T) {
	a := load(t, "steps:\n  build:\n    - hang: true\n      usage: { in: 9, out: 1, turns: 1 }\n")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := a.Run(ctx, gungnir.Task{Node: "build", Attempt: 1, Workdir: t.TempDir()})
	var se *gungnir.SessionError
	if !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &se) || se.Usage.InTok != 9 {
		t.Errorf("Run() = %v; want the context's error carrying the usage", err)
	}
}

func TestActionsHappenBeforeAnErrorOrAHang(t *testing.T) {
	a := load(t, "steps:\n  build:\n    - actions: [ { write: { path: half.txt, content: \"partial\\n\" } } ]\n      error: timed out half way\n")
	work := t.TempDir()
	if _, err := a.Run(context.Background(), gungnir.Task{Node: "build", Attempt: 1, Workdir: work}); err == nil {
		t.Fatal("Run() = nil, want the step's error")
	}
	if b, err := os.ReadFile(filepath.Join(work, "half.txt")); err != nil || string(b) != "partial\n" {
		t.Errorf("half.txt = %q, %v; a session that fails half way leaves its work behind", b, err)
	}
}

func TestAResultCarriesItsFinalAnswerOrAReportOfFindings(t *testing.T) {
	a := load(t, `
steps:
  review:
    - result: { status: ok, summary: reviewed, output: "LGTM, ship it" }
    - result:
        status: ok
        summary: reviewed
        report:
          - { id: spec-1, source: spec, severity: major, location: "api/auth.go:42", claim: no throttle, status: open }
          - { id: spec-2, source: spec, severity: minor, location: "api/auth.go:50", claim: no doc, status: fixed, proof: "api/auth.go:51; check test passed" }
    - result: { status: ok, summary: reviewed, report: [] }
`)
	r, err := run(t, a, "review", 1)
	if err != nil || r.Output != "LGTM, ship it" {
		t.Errorf("attempt 1: %+v, %v", r, err)
	}
	r, err = run(t, a, "review", 2)
	if err != nil {
		t.Fatal(err)
	}
	rep, perr := schema.Decode[schema.Review](schema.ContractReview, []byte(r.Output))
	if perr != nil || len(rep.Findings) != 2 || rep.Findings[1].Proof == "" || rep.Findings[0].Location != "api/auth.go:42" {
		t.Errorf("attempt 2: report %+v, %v from %q", rep, perr, r.Output)
	}
	r, err = run(t, a, "review", 3)
	if rep, perr := schema.Decode[schema.Review](schema.ContractReview, []byte(r.Output)); err != nil || perr != nil || len(rep.Findings) != 0 {
		t.Errorf("attempt 3: an empty report must be a well-formed report with no findings: %q, %v, %v", r.Output, perr, err)
	}
}

func TestScriptedRefusesAScriptThatNamesNoSuchFailure(t *testing.T) {
	for name, script := range map[string]string{
		"an unknown kind":           "steps:\n  a:\n    - error: x\n      kind: flaky\n",
		"a kind on a hang":          "steps:\n  a:\n    - hang: true\n      kind: quota\n",
		"a kind on a result":        "steps:\n  a:\n    - result: { status: ok }\n      kind: quota\n",
		"usage beside a result":     "steps:\n  a:\n    - result: { status: ok }\n      usage: { in: 1 }\n",
		"a failure on a success":    "steps:\n  a:\n    - result: { status: ok, failure: transient }\n",
		"infra as a result failure": "steps:\n  a:\n    - result: { status: failed, failure: infra }\n",
		"an unknown failure":        "steps:\n  a:\n    - result: { status: failed, failure: flaky }\n",
		"output and report":         "steps:\n  a:\n    - result: { status: ok, output: x, report: [] }\n",
	} {
		p := filepath.Join(t.TempDir(), "s.yaml")
		os.WriteFile(p, []byte(script), 0o644)
		if _, err := Load(p); err == nil {
			t.Errorf("%s: Load() = nil, want an error", name)
		}
	}
}

func TestTheTranscriptRecordsWhatTheSessionWasGiven(t *testing.T) {
	a := load(t, "steps:\n  build:\n    - result: { status: ok }\n")
	dir := t.TempDir()
	r, err := a.Run(context.Background(), gungnir.Task{Node: "build", Attempt: 1, Workdir: t.TempDir(), TranscriptDir: dir, Prompt: "Build it.", MaxTurns: 7, ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(r.TranscriptPath)
	var got struct {
		Prompt   string `json:"prompt"`
		MaxTurns int    `json:"max_turns"`
		ReadOnly bool   `json:"read_only"`
	}
	if err := json.Unmarshal(b, &got); err != nil || got.Prompt != "Build it." || got.MaxTurns != 7 || !got.ReadOnly {
		t.Errorf("the transcript = %s, %v", b, err)
	}
}

func TestAScriptedStepSubmitsItsDocument(t *testing.T) {
	a := load(t, `
submits: true
steps:
  review:
    - result: { status: ok, submitted: '{"findings":[]}' }
    - result: { status: ok }
`)
	var _ gungnir.Submitter = a
	if !a.Submits() {
		t.Error("Submits() = false for a script that says submits: true")
	}
	r, err := a.Run(context.Background(), gungnir.Task{Node: "review", Attempt: 1, Workdir: t.TempDir(), Output: "ygg.review/v1"})
	if err != nil || string(r.Submitted) != `{"findings":[]}` {
		t.Errorf("attempt 1: Submitted = %q, %v", r.Submitted, err)
	}
	r, err = a.Run(context.Background(), gungnir.Task{Node: "review", Attempt: 2, Workdir: t.TempDir(), Output: "ygg.review/v1"})
	if err != nil || r.Submitted != nil {
		t.Errorf("attempt 2: Submitted = %q, %v; want nil", r.Submitted, err)
	}
	if load(t, "steps:\n  review:\n    - result: { status: ok }\n").Submits() {
		t.Error("a script that does not say submits: true submits")
	}
}

func TestASubmittedDocumentNeedsASubmittingScript(t *testing.T) {
	p := filepath.Join(t.TempDir(), "script.yaml")
	for name, script := range map[string]string{
		"without submits": "steps:\n  review:\n    - result: { status: ok, submitted: '{}' }\n",
		"not an object":   "submits: true\nsteps:\n  review:\n    - result: { status: ok, submitted: '[1]' }\n",
		"not JSON":        "submits: true\nsteps:\n  review:\n    - result: { status: ok, submitted: 'findings' }\n",
	} {
		if err := os.WriteFile(p, []byte(script), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil {
			t.Errorf("%s: Load() = nil, want an error", name)
		}
	}
}
