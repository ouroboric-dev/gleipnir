package checks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ouroboric-dev/gungnir"
)

// runner is a fake sandbox: it answers rm and head (the result's read) itself and runs the check as exit and out.
type runner struct {
	out    string
	exit   int
	err    error
	hang   bool
	result string // what the result file holds after the check; "" is no file
	left   string // what the file holds before it, until the rm removes it
	cmds   []gungnir.Cmd
	got    gungnir.Cmd // the check's own command
	file   string
}

func (r *runner) Run(ctx context.Context, c gungnir.Cmd) (gungnir.ExecResult, error) {
	r.cmds = append(r.cmds, c)
	switch c.Argv[0] {
	case "rm":
		r.file = ""
		return gungnir.ExecResult{}, nil
	case "head":
		if r.file == "" {
			return gungnir.ExecResult{ExitCode: 1}, nil
		}
		c.Stdout.Write([]byte(r.file))
		return gungnir.ExecResult{}, nil
	}
	r.got = c
	if r.hang {
		<-ctx.Done()
		return gungnir.ExecResult{}, ctx.Err()
	}
	r.file = r.result
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
	if fs := r.Findings(); len(fs) != 0 {
		t.Errorf("a passing check reported %+v", fs)
	}
}

func TestAFailingCheckWithNoResultReportsOneFindingWithTheEndOfItsOutput(t *testing.T) {
	out := strings.Repeat("noise line\n", 1000) + "--- FAIL: TestThrottle (0.00s)\n    auth_test.go:42: want 429, got 200\nFAIL\n"
	log := filepath.Join(t.TempDir(), "t.log")
	r, err := Run(context.Background(), &runner{out: out, exit: 1}, spec(), log)
	if err != nil || r.Passed || r.ExitCode != 1 {
		t.Fatalf("Run() = %+v, %v; a failing check is a result, not an error", r, err)
	}
	fs := r.Findings()
	if len(fs) != 1 {
		t.Fatalf("findings = %+v", fs)
	}
	f := fs[0]
	if err := f.Validate(); err != nil {
		t.Errorf("the finding is not a valid finding: %v", err)
	}
	if f.ID != "check-test-result" || f.ID != FindingID("test", "result") || f.Source != "test" || f.Severity != gungnir.SeverityBlocker || f.Status != gungnir.FindingOpen || f.Location != log+":1" {
		t.Errorf("finding = %+v", f)
	}
	if !strings.Contains(f.Claim, "the check wrote no valid result (a fault of the realm, not of the task)") || !strings.Contains(f.Claim, "want 429, got 200") {
		t.Errorf("the claim is %d bytes: %q", len(f.Claim), f.Claim)
	}
}

func TestACheckThatRunsTooLongIsAFailedCheck(t *testing.T) {
	s := spec()
	s.Timeout = 100 * time.Millisecond
	r, err := Run(context.Background(), &runner{hang: true}, s, filepath.Join(t.TempDir(), "t.log"))
	if err != nil || r.Passed || !r.TimedOut {
		t.Fatalf("Run() = %+v, %v; want a timed-out result", r, err)
	}
	if fs := r.Findings(); len(fs) != 1 || fs[0].ID != "check-test-result" || !strings.Contains(fs[0].Claim, "timed out") {
		t.Errorf("findings = %+v", fs)
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
	switch c.Argv[0] {
	case "rm":
		return gungnir.ExecResult{}, nil
	case "head": // no result file
		return gungnir.ExecResult{ExitCode: 1}, nil
	}
	for i := 0; i < b.n; i++ {
		c.Stdout.Write([]byte(b.line))
	}
	return gungnir.ExecResult{}, nil
}

const threeFailures = `{"check":"test","passed":false,"exit_code":1,"timed_out":false,"duration_ms":5,
"failures":[
 {"kind":"test","test":"pkg.TestA","location":"a_test.go:10:3","message":"want 1, got 2"},
 {"kind":"test","test":"pkg.TestB","message":"boom"},
 {"kind":"lint","location":"x.go:4","message":"unused"}],
"passed_tests":["pkg.TestC","pkg.TestD"]}`

func TestOneFindingPerFailure(t *testing.T) {
	run := func() Result {
		r, err := Run(context.Background(), &runner{exit: 1, result: threeFailures}, spec(), filepath.Join(t.TempDir(), "t.log"))
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	r := run()
	if r.Typed == nil || r.TypedErr != nil || r.Passed {
		t.Fatalf("Run() = %+v", r)
	}
	fs, again := r.Findings(), run().Findings()
	if len(fs) != 3 || len(again) != 3 {
		t.Fatalf("findings = %+v", fs)
	}
	seen := map[string]bool{}
	for i, f := range fs {
		if err := f.Validate(); err != nil {
			t.Errorf("finding %d is invalid: %v", i, err)
		}
		if !regexp.MustCompile(`^check-test-[0-9a-f]{12}$`).MatchString(f.ID) || f.ID != again[i].ID || seen[f.ID] || f.Source != "test" || f.Status != gungnir.FindingOpen {
			t.Errorf("finding %d = %+v; again %+v", i, f, again[i])
		}
		seen[f.ID] = true
	}
	if fs[0].Claim != "want 1, got 2" || fs[0].Location != "a_test.go:10" || !strings.HasSuffix(fs[1].Location, "t.log:1") || fs[2].Location != "x.go:4" {
		t.Errorf("findings = %+v", fs)
	}
	sum := sha256.Sum256([]byte("test\x00pkg.TestA\x00a_test.go:10:3"))
	if want := "check-test-" + hex.EncodeToString(sum[:])[:12]; fs[0].ID != want {
		t.Errorf("id = %s, want %s", fs[0].ID, want)
	}
	if got := r.Failed(); !slices.Equal(got, []string{"pkg.TestA", "pkg.TestB"}) {
		t.Errorf("Failed() = %v", got)
	}
	if got := r.PassedTests(); !slices.Equal(got, []string{"pkg.TestC", "pkg.TestD"}) {
		t.Errorf("PassedTests() = %v", got)
	}
}

func TestTwoFailuresThatHashAlikeKeepDistinctStableIDs(t *testing.T) {
	res := `{"check":"test","passed":false,"exit_code":1,"timed_out":false,"duration_ms":5,"failures":[
 {"kind":"lint","message":"one"},{"kind":"lint","message":"two"}]}`
	r, _ := Run(context.Background(), &runner{exit: 1, result: res}, spec(), filepath.Join(t.TempDir(), "t.log"))
	fs := r.Findings()
	if len(fs) != 2 || fs[0].ID == fs[1].ID {
		t.Errorf("findings = %+v", fs)
	}
}

func TestTheExitCodeDecides(t *testing.T) {
	pass := `{"check":"test","passed":true,"exit_code":0,"timed_out":false,"duration_ms":5,"passed_tests":["pkg.TestC"]}`
	r, err := Run(context.Background(), &runner{exit: 1, result: pass}, spec(), filepath.Join(t.TempDir(), "t.log"))
	if err != nil || r.Passed || r.TypedErr == nil || !strings.Contains(r.TypedErr.Error(), "contradicts its exit code") {
		t.Fatalf("a pass with exit 1: %+v, %v", r, err)
	}
	fs := r.Findings()
	if len(fs) != 1 || fs[0].ID != "check-test-result" {
		t.Errorf("findings = %+v", fs)
	}
	if len(r.Failed()) != 0 || len(r.PassedTests()) != 0 {
		t.Errorf("a contradicting result gave Failed %v and PassedTests %v", r.Failed(), r.PassedTests())
	}
	r, err = Run(context.Background(), &runner{result: threeFailures}, spec(), filepath.Join(t.TempDir(), "t.log"))
	if err != nil || !r.Passed || r.TypedErr == nil || len(r.Findings()) != 0 {
		t.Errorf("a fail with exit 0: %+v, %v", r, err)
	}
}

func TestNoResultIsTheRealmsFault(t *testing.T) {
	for name, res := range map[string]string{"missing": "", "not json": "oops", "wrong contract": `{"check":"test"}`} {
		r, err := Run(context.Background(), &runner{exit: 1, out: "boom\n", result: res}, spec(), filepath.Join(t.TempDir(), "t.log"))
		if err != nil || r.Typed != nil || r.TypedErr == nil {
			t.Errorf("%s: %+v, %v", name, r, err)
			continue
		}
		fs := r.Findings()
		if len(fs) != 1 || fs[0].ID != "check-test-result" || !strings.Contains(fs[0].Claim, "a fault of the realm, not of the task") || !strings.Contains(fs[0].Claim, "boom") {
			t.Errorf("%s: findings = %+v", name, fs)
		}
	}
}

func TestAFailingExitWithAResultThatListsNoFailureIsOneFinding(t *testing.T) {
	res := `{"check":"test","passed":false,"exit_code":137,"timed_out":false,"duration_ms":5}`
	r, err := Run(context.Background(), &runner{exit: 137, out: "Killed\n", result: res}, spec(), filepath.Join(t.TempDir(), "t.log"))
	if err != nil || r.Typed == nil || r.TypedErr != nil {
		t.Fatalf("%+v, %v", r, err)
	}
	fs := r.Findings()
	if len(fs) != 1 || fs[0].ID != "check-test-result" || !strings.Contains(fs[0].Claim, "the check failed and its result lists no failure") || !strings.Contains(fs[0].Claim, "Killed") {
		t.Errorf("findings = %+v", fs)
	}
}

func TestTheResultIsFreshEachRun(t *testing.T) {
	rn := &runner{result: `{"check":"test","passed":true,"exit_code":0,"timed_out":false,"duration_ms":5}`}
	if _, err := Run(context.Background(), rn, spec(), filepath.Join(t.TempDir(), "t.log")); err != nil {
		t.Fatal(err)
	}
	// The next run's check writes nothing: the last run's file must be gone, not read again.
	rn.result, rn.exit, rn.cmds = "", 1, nil
	r, err := Run(context.Background(), rn, spec(), filepath.Join(t.TempDir(), "t.log"))
	if err != nil || r.Typed != nil || r.TypedErr == nil {
		t.Fatalf("a stale result was read: %+v, %v", r, err)
	}
	var argvs []string
	for _, c := range rn.cmds {
		argvs = append(argvs, strings.Join(c.Argv, " "))
	}
	want := []string{"rm -f -- " + ResultPath, "go test ./...", "head -c 1048577 -- " + ResultPath}
	if !slices.Equal(argvs, want) {
		t.Errorf("commands = %q, want %q", argvs, want)
	}
	if rn.cmds[1].Env["YGG_CHECK_RESULT"] != ResultPath || rn.cmds[0].Env != nil && len(rn.cmds[0].Env) != 0 {
		t.Errorf("env of the check = %v", rn.cmds[1].Env)
	}
}

func TestAResultOverOneMebibyteIsNoResult(t *testing.T) {
	big := `{"check":"test","passed":false,"exit_code":1,"timed_out":false,"duration_ms":5,"notes":["` + strings.Repeat("x", MaxResult) + `"]}`
	r, err := Run(context.Background(), &runner{exit: 1, result: big}, spec(), filepath.Join(t.TempDir(), "t.log"))
	if err != nil || r.Typed != nil || r.TypedErr == nil || !strings.Contains(r.TypedErr.Error(), "over") {
		t.Errorf("%+v, %v", r, err)
	}
}

func TestATimedOutCheckStillReadsItsResult(t *testing.T) {
	// The runner kills the check at the timeout; the read after it runs on the caller's context.
	s := spec()
	s.Timeout = 50 * time.Millisecond
	r, err := Run(context.Background(), &runner{hang: true}, s, filepath.Join(t.TempDir(), "t.log"))
	if err != nil || !r.TimedOut || r.Typed != nil || r.TypedErr == nil {
		t.Errorf("%+v, %v", r, err)
	}
}
