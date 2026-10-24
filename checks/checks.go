// Package checks runs a realm's checks (spec §2.1, §9.5): one command in a leaf's sandbox, with its
// output kept in a log and its end read as a pass, a fail or a timeout. A check that fails is a result
// and feeds a typed finding to the loop; an error is the runner's own (the sandbox, the log file), which
// is never a failed check (spec §12).
package checks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ouroboric-dev/gleipnir/bounded"
	"github.com/ouroboric-dev/gungnir"
	"github.com/ouroboric-dev/gungnir/schema"
)

const (
	// MaxLog is the most bytes of a check's output the log keeps.
	MaxLog = 8 << 20
	// TailBytes is how much of the end of a check's output a finding carries.
	TailBytes = 3000
	// MaxResult is the most bytes of a typed result that is read; a bigger one is no result.
	MaxResult = 1 << 20
	// ResultPath is where, inside the sandbox, a check writes its typed result (ygg.check/v1), and ResultEnv the
	// variable that names it to the check.
	ResultPath = "/tmp/ygg-check-result.json"
	ResultEnv  = "YGG_CHECK_RESULT"
)

// Spec is one check to run.
type Spec struct {
	Name    string
	Argv    []string // the command, without a shell
	Timeout time.Duration
}

// Result is how a check ended.
type Result struct {
	Name     string
	Passed   bool // decided by the exit code alone
	ExitCode int
	TimedOut bool
	Tail     string // the last TailBytes of the output
	Log      string // the log file: the whole output, up to MaxLog bytes
	Duration time.Duration
	// Typed is the check's own result (ygg.check/v1), read back from the sandbox. It is nil when the check wrote
	// none or none that decodes; TypedErr then says why. A result that contradicts the exit code is kept in Typed
	// for the record, and TypedErr is set: the exit code is the truth.
	Typed    *schema.CheckResult
	TypedErr error
}

// Run runs s through runner and writes its output to logPath. The result file is removed first, the check runs with
// YGG_CHECK_RESULT set, and the file is read back from the same sandbox. A command that exits non-zero, or runs
// past its timeout, is a Result that did not pass. An error means the check could not be judged: the runner
// failed, the log could not be written, or ctx ended. A result that is missing or invalid is no error: it is in
// TypedErr, and Findings reports it.
func Run(ctx context.Context, runner gungnir.Runner, s Spec, logPath string) (Result, error) {
	if s.Timeout <= 0 {
		return Result{}, fmt.Errorf("check %s has no timeout", s.Name)
	}
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return Result{}, err
	}
	f, err := os.Create(logPath)
	if err != nil {
		return Result{}, err
	}
	defer f.Close()
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if res, err := runner.Run(ctx, gungnir.Cmd{Argv: []string{"rm", "-f", "--", ResultPath}}); err != nil {
		return Result{}, fmt.Errorf("check %s: removing the last result: %w", s.Name, err)
	} else if res.ExitCode != 0 {
		return Result{}, fmt.Errorf("check %s: removing the last result exited %d", s.Name, res.ExitCode)
	}
	log := bounded.NewWriter(f, MaxLog)
	tail := &tailWriter{max: TailBytes}
	out := io.MultiWriter(log, tail)
	cctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()
	began := time.Now()
	res, err := runner.Run(cctx, gungnir.Cmd{Argv: s.Argv, Env: map[string]string{ResultEnv: ResultPath}, Stdout: out, Stderr: out})
	r := Result{Name: s.Name, Log: logPath, Duration: time.Since(began), Tail: tail.String()}
	switch {
	case err != nil && ctx.Err() != nil:
		return Result{}, ctx.Err()
	case err != nil && errors.Is(cctx.Err(), context.DeadlineExceeded):
		r.TimedOut = true
	case err != nil:
		return Result{}, err
	default:
		r.ExitCode, r.Passed = res.ExitCode, res.ExitCode == 0
	}
	if err := log.Err(); err != nil {
		return r, err
	}
	if err := r.readResult(ctx, runner); err != nil {
		return Result{}, err
	}
	return r, nil
}

// readResult reads the typed result in the sandbox the check ran in. An error is the runner's own; a result that
// is missing, too big or invalid sets TypedErr.
func (r *Result) readResult(ctx context.Context, runner gungnir.Runner) error {
	buf := bounded.NewBuffer(MaxResult + 1)
	res, err := runner.Run(ctx, gungnir.Cmd{Argv: []string{"head", "-c", strconv.Itoa(MaxResult + 1), "--", ResultPath}, Stdout: buf})
	switch {
	case err != nil && ctx.Err() != nil:
		return ctx.Err()
	case err != nil:
		return fmt.Errorf("check %s: reading its result: %w", r.Name, err)
	case res.ExitCode != 0:
		r.TypedErr = errors.New("the check left no result file")
		return nil
	case len(buf.Bytes()) > MaxResult:
		r.TypedErr = fmt.Errorf("the check's result is over the limit of %d bytes", MaxResult)
		return nil
	}
	typed, err := schema.Decode[schema.CheckResult](schema.ContractCheck, buf.Bytes())
	if err != nil {
		r.TypedErr = err
		return nil
	}
	r.Typed = &typed
	if typed.Passed != r.Passed {
		r.TypedErr = fmt.Errorf("the check's result contradicts its exit code (exit %d, timed out %t, passed %t)", r.ExitCode, r.TimedOut, typed.Passed)
	}
	return nil
}

// valid is the typed result when it can be trusted: it decoded and agrees with the exit code.
func (r Result) valid() *schema.CheckResult {
	if r.TypedErr != nil {
		return nil
	}
	return r.Typed
}

// Failed lists the ids of the tests the typed result says failed. A missing, invalid or contradicting result gives none.
func (r Result) Failed() []string {
	var ids []string
	if t := r.valid(); t != nil {
		for _, f := range t.Failures {
			if f.Test != "" {
				ids = append(ids, f.Test)
			}
		}
	}
	return ids
}

// PassedTests lists the ids of the tests the typed result says ran and passed. A missing, invalid or contradicting
// result gives none.
func (r Result) PassedTests() []string {
	if t := r.valid(); t != nil {
		return slices.Clone(t.PassedTests)
	}
	return nil
}

// Findings are the findings a check that did not pass reports (spec §4.6): one per failure its typed result lists.
// A failing exit with no valid typed result, or one that lists no failure, gives the one finding check-<name>-result,
// carrying the end of the output. A check that passed has none. Ids are stable across attempts, so the same failure
// keeps the same finding; every location is a file and a line the loop can read.
func (r Result) Findings() []gungnir.Finding {
	if r.Passed {
		return nil
	}
	t := r.valid()
	if t == nil || len(t.Failures) == 0 {
		claim := "the check wrote no valid result (a fault of the realm, not of the task)"
		if t != nil {
			claim = "the check failed and its result lists no failure"
		}
		why := fmt.Sprintf("exit status %d", r.ExitCode)
		if r.TimedOut {
			why = "it timed out"
		}
		claim = fmt.Sprintf("check %s failed (%s): %s", r.Name, why, claim)
		if r.TypedErr != nil {
			claim += "\nits result: " + r.TypedErr.Error()
		}
		if tl := strings.TrimSpace(r.Tail); tl != "" {
			claim += "\nthe end of its output:\n" + tl
		}
		return []gungnir.Finding{r.finding(FindingID(r.Name, "result"), r.Log+":1", claim)}
	}
	var out []gungnir.Finding
	used := map[string]int{}
	for _, f := range t.Failures {
		sum := sha256.Sum256([]byte(f.Kind + "\x00" + f.Test + "\x00" + f.Location))
		id := FindingID(r.Name, hex.EncodeToString(sum[:])[:12])
		if used[id]++; used[id] > 1 { // the same kind, test and place twice: keep both, in order
			id += "-" + strconv.Itoa(used[id])
		}
		out = append(out, r.finding(id, findingLocation(f.Location, r.Log), f.Message))
	}
	return out
}

// finding is an open blocker from this check.
func (r Result) finding(id, loc, claim string) gungnir.Finding {
	if utf8.RuneCountInString(claim) > gungnir.MaxClaim {
		rs := []rune(claim)
		claim = string(rs[:gungnir.MaxClaim-14]) + "…[truncated]"
	}
	return gungnir.Finding{ID: id, Source: r.Name, Severity: gungnir.SeverityBlocker, Location: loc, Claim: claim, Status: gungnir.FindingOpen}
}

var fileLine = regexp.MustCompile(`^([^\t\n\v\f\r :]+:[0-9]+)(:[0-9]+)?$`)

// findingLocation is a finding's location from a failure's: file:line without the column, or the log's first line
// when the failure has none that a finding can hold.
func findingLocation(loc, log string) string {
	if m := fileLine.FindStringSubmatch(loc); m != nil && utf8.RuneCountInString(m[1]) <= gungnir.MaxLocation {
		return m[1]
	}
	return log + ":1"
}

// FindingID is the id of a finding a check of this name reports: check-<name>-<suffix>.
func FindingID(check, suffix string) string { return "check-" + check + "-" + suffix }

// tailWriter keeps the last max bytes written to it, cut at a character boundary.
type tailWriter struct {
	max int
	buf []byte
}

func (w *tailWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	if len(w.buf) > 2*w.max { // trim in bigger steps than one write, so a chatty check costs little
		w.buf = append([]byte(nil), w.buf[len(w.buf)-w.max:]...)
	}
	return len(p), nil
}

func (w *tailWriter) String() string {
	b := w.buf
	if len(b) > w.max {
		b = b[len(b)-w.max:]
	}
	for len(b) > 0 && !utf8.RuneStart(b[0]) {
		b = b[1:]
	}
	return string(b)
}
