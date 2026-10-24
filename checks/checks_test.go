package checks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ouroboric-dev/gungnir"
)

// runner is a fake sandbox: it answers rm and the guarded read of the result itself and runs the check as exit and out.
type runner struct {
	out     string
	exit    int
	err     error
	hang    bool
	result  string // what the result file holds after the check; "" is no file
	left    string // what the file holds before it, until the rm removes it
	cmds    []gungnir.Cmd
	got     gungnir.Cmd // the check's own command
	file    string
	onCheck func()          // runs when the check ends, before its result
	readCtx context.Context // the context the result was read on
	readErr error           // that context's error when the read began
}

func (r *runner) Run(ctx context.Context, c gungnir.Cmd) (gungnir.ExecResult, error) {
	r.cmds = append(r.cmds, c)
	switch {
	case c.Argv[0] == "rm":
		r.file = ""
		return gungnir.ExecResult{}, nil
	case isResultRead(c.Argv):
		r.readCtx, r.readErr = ctx, ctx.Err()
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
	if r.onCheck != nil {
		r.onCheck()
	}
	return gungnir.ExecResult{ExitCode: r.exit}, r.err
}

// isResultRead tells the guarded read of the result: a shell script that gets the path as $1, tests that it is a
// regular file and reads one byte more than the bound.
func isResultRead(argv []string) bool {
	return len(argv) == 5 && argv[0] == "sh" && argv[1] == "-c" && strings.Contains(argv[2], `test -f "$1"`) &&
		strings.Contains(argv[2], "head -c 1048577") && !strings.Contains(argv[2], ResultPath) && argv[3] == "sh" && argv[4] == ResultPath
}

func spec() Spec {
	return Spec{Name: "test", Argv: []string{"go", "test", "./..."}, Timeout: time.Minute}
}

// typed is a check asked for its typed result, as the loop's ladder asks.
func typed() Spec {
	s := spec()
	s.Typed = true
	return s
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
	r, err := Run(context.Background(), &runner{out: out, exit: 1}, typed(), log)
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
	s := typed()
	s.Timeout = 100 * time.Millisecond
	r, err := Run(context.Background(), &runner{hang: true}, s, filepath.Join(t.TempDir(), "t.log"))
	if err != nil || r.Passed || !r.TimedOut {
		t.Fatalf("Run() = %+v, %v; want a timed-out result", r, err)
	}
	// It ran out of time before it could write a result: that is not the realm's fault.
	fs := r.Findings()
	if len(fs) != 1 || fs[0].ID != "check-test-result" || !strings.HasPrefix(fs[0].Claim, "check test timed out before writing a result") || strings.Contains(fs[0].Claim, "fault of the realm") {
		t.Errorf("findings = %+v", fs)
	}
	r, err = Run(context.Background(), &runner{hang: true}, func() Spec { s := spec(); s.Timeout = 50 * time.Millisecond; return s }(), filepath.Join(t.TempDir(), "t.log"))
	if fs := r.Findings(); err != nil || len(fs) != 1 || !strings.Contains(fs[0].Claim, "timed out") || strings.Contains(fs[0].Claim, "fault of the realm") {
		t.Errorf("an untyped check that timed out: %v, findings = %+v", err, fs)
	}
}

// An untyped check (odin's exec nodes, generators, host runs) runs exactly its command: no environment, no rm, no
// read, so a host runner that refuses an Env and shares one /tmp still runs it (R28).
func TestAnUntypedRunPassesNoEnvAndRunsOneCommand(t *testing.T) {
	log := filepath.Join(t.TempDir(), "t.log")
	rn := &runner{out: "--- FAIL: TestThrottle\n    auth_test.go:42: want 429, got 200\n", exit: 1, result: threeFailures}
	r, err := Run(context.Background(), rn, spec(), log)
	if err != nil || r.Passed || r.ExitCode != 1 {
		t.Fatalf("Run() = %+v, %v", r, err)
	}
	if len(rn.cmds) != 1 || strings.Join(rn.cmds[0].Argv, " ") != "go test ./..." || rn.cmds[0].Env != nil {
		t.Errorf("commands = %+v; want the check alone, with no Env", rn.cmds)
	}
	if r.Typed != nil || r.TypedErr != nil || r.TypedRun {
		t.Errorf("an untyped run has Typed %v, TypedErr %v, TypedRun %t", r.Typed, r.TypedErr, r.TypedRun)
	}
	fs := r.Findings()
	if len(fs) != 1 || fs[0].ID != "check-test-result" || fs[0].Location != log+":1" || fs[0].Validate() != nil {
		t.Fatalf("findings = %+v", fs)
	}
	if c := fs[0].Claim; !strings.Contains(c, "the check failed; it does not write a typed result") || !strings.Contains(c, "want 429, got 200") ||
		strings.Contains(c, "fault of the realm") || strings.Contains(c, "its result") {
		t.Errorf("the claim = %q", c)
	}
	if len(r.Failed()) != 0 || len(r.PassedTests()) != 0 {
		t.Errorf("an untyped run gave Failed %v and PassedTests %v", r.Failed(), r.PassedTests())
	}
	rn = &runner{out: "ok\n"}
	if r, err := Run(context.Background(), rn, spec(), log); err != nil || !r.Passed || len(r.Findings()) != 0 || len(rn.cmds) != 1 || rn.cmds[0].Env != nil {
		t.Errorf("an untyped pass: %+v, %v, commands %+v", r, err, rn.cmds)
	}
}

// A typed result that names another check or another exit code contradicts the run, as a wrong passed does.
func TestAResultThatNamesAnotherCheckOrExitContradictsTheRun(t *testing.T) {
	for name, res := range map[string]string{
		"another exit code": strings.Replace(threeFailures, `"exit_code":1`, `"exit_code":2`, 1),
		"another check":     strings.Replace(threeFailures, `"check":"test"`, `"check":"lint"`, 1),
	} {
		r, err := Run(context.Background(), &runner{exit: 1, out: "boom\n", result: res}, typed(), filepath.Join(t.TempDir(), "t.log"))
		if err != nil || r.Typed == nil || r.TypedErr == nil || !strings.Contains(r.TypedErr.Error(), "contradicts") {
			t.Errorf("%s: %+v, %v", name, r, err)
			continue
		}
		if fs := r.Findings(); len(fs) != 1 || fs[0].ID != "check-test-result" || len(r.Failed()) != 0 {
			t.Errorf("%s: findings = %+v", name, fs)
		}
	}
}

// The read of the result has its own bound in time, on a context of its own: a caller cancelled once the check has
// ended still gets its result read.
func TestTheResultIsReadOnItsOwnBoundedContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rn := &runner{exit: 1, result: threeFailures, onCheck: cancel}
	r, err := Run(ctx, rn, typed(), filepath.Join(t.TempDir(), "t.log"))
	if err != nil || r.Typed == nil || r.TypedErr != nil {
		t.Fatalf("Run() = %+v, %v", r, err)
	}
	if rn.readErr != nil {
		t.Errorf("the result was read on a context that had ended: %v", rn.readErr)
	}
	dl, ok := rn.readCtx.Deadline()
	if !ok || time.Until(dl) > ReadTimeout || ReadTimeout != 10*time.Second {
		t.Errorf("the read's deadline = %v, %t; want at most %v from now", dl, ok, ReadTimeout)
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
	}
	if isResultRead(c.Argv) { // no result file
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
		r, err := Run(context.Background(), &runner{exit: 1, result: threeFailures}, typed(), filepath.Join(t.TempDir(), "t.log"))
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
	// A failure with a test id names it first (R30); the id does not change with the claim.
	if fs[0].Claim != "pkg.TestA: want 1, got 2" || fs[1].Claim != "pkg.TestB: boom" || fs[2].Claim != "unused" ||
		fs[0].Location != "a_test.go:10" || !strings.HasSuffix(fs[1].Location, "t.log:1") || fs[2].Location != "x.go:4" {
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
	r, _ := Run(context.Background(), &runner{exit: 1, result: res}, typed(), filepath.Join(t.TempDir(), "t.log"))
	fs := r.Findings()
	if len(fs) != 2 || fs[0].ID == fs[1].ID {
		t.Errorf("findings = %+v", fs)
	}
}

func TestTheExitCodeDecides(t *testing.T) {
	pass := `{"check":"test","passed":true,"exit_code":0,"timed_out":false,"duration_ms":5,"passed_tests":["pkg.TestC"]}`
	r, err := Run(context.Background(), &runner{exit: 1, result: pass}, typed(), filepath.Join(t.TempDir(), "t.log"))
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
	r, err = Run(context.Background(), &runner{result: threeFailures}, typed(), filepath.Join(t.TempDir(), "t.log"))
	if err != nil || !r.Passed || r.TypedErr == nil || len(r.Findings()) != 0 {
		t.Errorf("a fail with exit 0: %+v, %v", r, err)
	}
}

func TestNoResultIsTheRealmsFault(t *testing.T) {
	for name, res := range map[string]string{"missing": "", "not json": "oops", "wrong contract": `{"check":"test"}`} {
		r, err := Run(context.Background(), &runner{exit: 1, out: "boom\n", result: res}, typed(), filepath.Join(t.TempDir(), "t.log"))
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
	r, err := Run(context.Background(), &runner{exit: 137, out: "Killed\n", result: res}, typed(), filepath.Join(t.TempDir(), "t.log"))
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
	if _, err := Run(context.Background(), rn, typed(), filepath.Join(t.TempDir(), "t.log")); err != nil {
		t.Fatal(err)
	}
	// The next run's check writes nothing: the last run's file must be gone, not read again.
	rn.result, rn.exit, rn.cmds = "", 1, nil
	r, err := Run(context.Background(), rn, typed(), filepath.Join(t.TempDir(), "t.log"))
	if err != nil || r.Typed != nil || r.TypedErr == nil {
		t.Fatalf("a stale result was read: %+v, %v", r, err)
	}
	var argvs []string
	for _, c := range rn.cmds {
		argvs = append(argvs, strings.Join(c.Argv, " "))
	}
	want := []string{"rm -f -- " + ResultPath, "go test ./..."}
	if len(argvs) != 3 || !slices.Equal(argvs[:2], want) || !isResultRead(rn.cmds[2].Argv) {
		t.Errorf("commands = %q, want %q and the guarded read", argvs, want)
	}
	if rn.cmds[1].Env["YGG_CHECK_RESULT"] != ResultPath || rn.cmds[0].Env != nil && len(rn.cmds[0].Env) != 0 {
		t.Errorf("env of the check = %v", rn.cmds[1].Env)
	}
}

func TestAResultOverOneMebibyteIsNoResult(t *testing.T) {
	big := `{"check":"test","passed":false,"exit_code":1,"timed_out":false,"duration_ms":5,"notes":["` + strings.Repeat("x", MaxResult) + `"]}`
	r, err := Run(context.Background(), &runner{exit: 1, result: big}, typed(), filepath.Join(t.TempDir(), "t.log"))
	if err != nil || r.Typed != nil || r.TypedErr == nil || !strings.Contains(r.TypedErr.Error(), "over") {
		t.Errorf("%+v, %v", r, err)
	}
}

func TestATimedOutCheckStillReadsItsResult(t *testing.T) {
	// The runner kills the check at the timeout; the read after it runs on the caller's context.
	s := typed()
	s.Timeout = 50 * time.Millisecond
	r, err := Run(context.Background(), &runner{hang: true}, s, filepath.Join(t.TempDir(), "t.log"))
	if err != nil || !r.TimedOut || r.Typed != nil || r.TypedErr == nil {
		t.Errorf("%+v, %v", r, err)
	}
}

func TestALongClaimKeepsItsTestAndItsBound(t *testing.T) {
	res := `{"check":"test","passed":false,"exit_code":1,"timed_out":false,"duration_ms":5,"failures":[
 {"kind":"test","test":"pkg.TestLong","message":"` + strings.Repeat("m", gungnir.MaxClaim) + `"}]}`
	r, err := Run(context.Background(), &runner{exit: 1, result: res}, typed(), filepath.Join(t.TempDir(), "t.log"))
	if err != nil || r.TypedErr != nil {
		t.Fatalf("%+v, %v", r, err)
	}
	fs := r.Findings()
	if len(fs) != 1 || !strings.HasPrefix(fs[0].Claim, "pkg.TestLong: mmm") || utf8.RuneCountInString(fs[0].Claim) > gungnir.MaxClaim || fs[0].Validate() != nil {
		t.Errorf("findings = %+v", fs)
	}
	sum := sha256.Sum256([]byte("test\x00pkg.TestLong\x00"))
	if want := "check-test-" + hex.EncodeToString(sum[:])[:12]; fs[0].ID != want {
		t.Errorf("id = %s, want %s", fs[0].ID, want)
	}
}

// local runs the commands on this machine in dir, with the sandbox's result path moved into dir: the read's guard is
// a shell script, so its test runs it.
type local struct{ dir string }

func (l local) Run(ctx context.Context, c gungnir.Cmd) (gungnir.ExecResult, error) {
	moved := filepath.Join(l.dir, "ygg-check-result.json")
	argv := slices.Clone(c.Argv)
	for i, a := range argv {
		if a == ResultPath {
			argv[i] = moved
		}
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir, cmd.Stdout, cmd.Stderr, cmd.WaitDelay = l.dir, c.Stdout, c.Stderr, time.Second
	cmd.Env = os.Environ()
	for k, v := range c.Env {
		if v == ResultPath {
			v = moved
		}
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	err := cmd.Run()
	if ctx.Err() != nil {
		return gungnir.ExecResult{}, ctx.Err()
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return gungnir.ExecResult{ExitCode: ee.ExitCode()}, nil
	}
	return gungnir.ExecResult{}, err
}

func TestTheResultReadRefusesAFIFOAndReadsAFile(t *testing.T) {
	run := func(script string, args ...string) (Result, error, time.Duration) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s := typed()
		s.Argv = append([]string{"sh", "-c", script, "sh"}, args...)
		began := time.Now()
		r, err := Run(ctx, local{dir: t.TempDir()}, s, filepath.Join(t.TempDir(), "t.log"))
		return r, err, time.Since(began)
	}
	r, err, took := run(`mkfifo "$YGG_CHECK_RESULT"; exit 1`)
	if err != nil || r.Typed != nil || r.TypedErr == nil || took > 4*time.Second {
		t.Errorf("a FIFO at the result path: %+v, %v after %v; want no result, at once", r, err, took)
	}
	r, err, _ = run(`mkdir "$YGG_CHECK_RESULT"; exit 1`)
	if err != nil || r.Typed != nil || r.TypedErr == nil {
		t.Errorf("a directory at the result path: %+v, %v", r, err)
	}
	r, err, _ = run(`printf %s "$1" > "$YGG_CHECK_RESULT"; exit 1`, threeFailures)
	if err != nil || r.Typed == nil || r.TypedErr != nil || len(r.Findings()) != 3 {
		t.Errorf("a plain file: %+v, %v", r, err)
	}
}
