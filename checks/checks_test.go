package checks

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

type runner struct {
	out  string
	exit int
	err  error
	hang bool
	got  gungnir.Cmd
}

func (r *runner) Run(ctx context.Context, c gungnir.Cmd) (gungnir.ExecResult, error) {
	r.got = c
	if r.hang {
		<-ctx.Done()
		return gungnir.ExecResult{}, ctx.Err()
	}
	c.Stdout.Write([]byte(r.out))
	return gungnir.ExecResult{ExitCode: r.exit}, r.err
}

func spec() Spec {
	return Spec{Name: "test", Argv: []string{"go", "test", "./..."}, Timeout: time.Minute}
}

func TestAPassingCheckHasNoFinding(t *testing.T) {
	log := filepath.Join(t.TempDir(), "logs", "build-1-test.log")
	r, err := Run(context.Background(), &runner{out: "ok  \tpkg\t0.1s\n"}, spec(), log)
	if err != nil || !r.Passed || r.ExitCode != 0 || r.TimedOut || r.Log != log {
		t.Fatalf("Run() = %+v, %v", r, err)
	}
	if b, _ := os.ReadFile(log); string(b) != "ok  \tpkg\t0.1s\n" {
		t.Errorf("the log = %q", b)
	}
	if f, ok := r.Finding("logs/build-1-test.log:1"); ok {
		t.Errorf("a passing check reported %+v", f)
	}
}

func TestAFailingCheckReportsAStableFindingWithTheEndOfItsOutput(t *testing.T) {
	out := strings.Repeat("noise line\n", 1000) + "--- FAIL: TestThrottle (0.00s)\n    auth_test.go:42: want 429, got 200\nFAIL\n"
	r, err := Run(context.Background(), &runner{out: out, exit: 1}, spec(), filepath.Join(t.TempDir(), "t.log"))
	if err != nil || r.Passed || r.ExitCode != 1 {
		t.Fatalf("Run() = %+v, %v; a failing check is a result, not an error", r, err)
	}
	f, ok := r.Finding("logs/build-1-test.log:1")
	if !ok {
		t.Fatal("a failing check has no finding")
	}
	if err := f.Validate(); err != nil {
		t.Errorf("the finding is not a valid finding: %v", err)
	}
	if f.ID != "check-test" || f.ID != FindingID("test") || f.Source != "test" || f.Severity != gungnir.SeverityBlocker || f.Status != gungnir.FindingOpen {
		t.Errorf("finding = %+v", f)
	}
	if !strings.Contains(f.Claim, "exit status 1") || !strings.Contains(f.Claim, "want 429, got 200") || len(f.Claim) > TailBytes+200 {
		t.Errorf("the claim is %d bytes: %q", len(f.Claim), f.Claim)
	}
	// The same failure on the next attempt keeps its id: the finding is the same problem.
	r2, _ := Run(context.Background(), &runner{out: "different output\n", exit: 2}, spec(), filepath.Join(t.TempDir(), "t.log"))
	if f2, _ := r2.Finding("logs/build-2-test.log:1"); f2.ID != f.ID {
		t.Errorf("ids differ between attempts: %q and %q", f.ID, f2.ID)
	}
}

func TestACheckThatRunsTooLongIsAFailedCheck(t *testing.T) {
	s := spec()
	s.Timeout = 100 * time.Millisecond
	r, err := Run(context.Background(), &runner{hang: true}, s, filepath.Join(t.TempDir(), "t.log"))
	if err != nil || r.Passed || !r.TimedOut {
		t.Fatalf("Run() = %+v, %v; want a timed-out result", r, err)
	}
	if f, ok := r.Finding("t.log:1"); !ok || !strings.Contains(f.Claim, "timed out") {
		t.Errorf("finding = %+v, %v", f, ok)
	}
}

func TestARunnerThatFailsIsAnErrorNeverAFailedCheck(t *testing.T) {
	if r, err := Run(context.Background(), &runner{err: errors.New("podman couldn't run go")}, spec(), filepath.Join(t.TempDir(), "t.log")); err == nil {
		t.Errorf("Run() = %+v, nil; the sandbox failing is not the check failing", r)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Run(ctx, &runner{hang: true}, spec(), filepath.Join(t.TempDir(), "t.log")); !errors.Is(err, context.Canceled) {
		t.Errorf("a cancelled context: Run() = %v, want context.Canceled", err)
	}
	s := spec()
	s.Timeout = 0
	if _, err := Run(context.Background(), &runner{}, s, filepath.Join(t.TempDir(), "t.log")); err == nil {
		t.Error("a check with no timeout ran")
	}
	if _, err := Run(context.Background(), &runner{}, spec(), filepath.Join(t.TempDir(), "log-is-a-dir", "x", "..", "..")); err == nil {
		t.Error("a log that can't be written was ignored")
	}
}

func TestTheLogIsBoundedAndTheTailKeepsWholeCharacters(t *testing.T) {
	r, err := Run(context.Background(), &runner{out: strings.Repeat("é", TailBytes), exit: 1}, spec(), filepath.Join(t.TempDir(), "t.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(r.Tail, "é") || len(r.Tail) > TailBytes {
		t.Errorf("the tail starts %q and is %d bytes", r.Tail[:4], len(r.Tail))
	}
	big := strings.Repeat("x", 100)
	r, err = Run(context.Background(), &bigRunner{n: MaxLog/100 + 50, line: big}, spec(), filepath.Join(t.TempDir(), "t.log"))
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(r.Log); fi.Size() > MaxLog {
		t.Errorf("the log is %d bytes, over the bound %d", fi.Size(), MaxLog)
	}
}

type bigRunner struct {
	n    int
	line string
}

func (b *bigRunner) Run(_ context.Context, c gungnir.Cmd) (gungnir.ExecResult, error) {
	for i := 0; i < b.n; i++ {
		c.Stdout.Write([]byte(b.line))
	}
	return gungnir.ExecResult{}, nil
}
