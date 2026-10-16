// Package checks runs a realm's checks (spec §2.1, §9.5): one command in a leaf's sandbox, with its
// output kept in a log and its end read as a pass, a fail or a timeout. A check that fails is a result
// and feeds a typed finding to the loop; an error is the runner's own (the sandbox, the log file), which
// is never a failed check (spec §12).
package checks

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ouroboric-dev/gleipnir/bounded"
	"github.com/ouroboric-dev/gungnir"
)

const (
	// MaxLog is the most bytes of a check's output the log keeps.
	MaxLog = 8 << 20
	// TailBytes is how much of the end of a check's output a finding carries.
	TailBytes = 3000
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
	Passed   bool
	ExitCode int
	TimedOut bool
	Tail     string // the last TailBytes of the output
	Log      string // the log file: the whole output, up to MaxLog bytes
	Duration time.Duration
}

// Run runs s through runner and writes its output to logPath. A command that exits non-zero, or runs
// past its timeout, is a Result that did not pass. An error means the check could not be judged: the
// runner failed, the log could not be written, or ctx ended.
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
	log := bounded.NewWriter(f, MaxLog)
	tail := &tailWriter{max: TailBytes}
	out := io.MultiWriter(log, tail)
	cctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()
	began := time.Now()
	res, err := runner.Run(cctx, gungnir.Cmd{Argv: s.Argv, Stdout: out, Stderr: out})
	r := Result{Name: s.Name, Log: logPath, Duration: time.Since(began), Tail: tail.String()}
	switch {
	case err != nil && ctx.Err() != nil:
		return Result{}, ctx.Err()
	case err != nil && errors.Is(cctx.Err(), context.DeadlineExceeded):
		r.TimedOut = true
		return r, log.Err()
	case err != nil:
		return Result{}, err
	}
	r.ExitCode, r.Passed = res.ExitCode, res.ExitCode == 0
	return r, log.Err()
}

// Finding is the finding a check that did not pass reports (spec §4.6). Its id is stable across
// attempts, so the same failing check keeps the same finding; location is where the loop can read the
// output (a file and a line). A check that passed has no finding.
func (r Result) Finding(location string) (gungnir.Finding, bool) {
	if r.Passed {
		return gungnir.Finding{}, false
	}
	why := fmt.Sprintf("exit status %d", r.ExitCode)
	if r.TimedOut {
		why = "it timed out"
	}
	claim := fmt.Sprintf("check %s failed: %s", r.Name, why)
	if t := strings.TrimSpace(r.Tail); t != "" {
		claim += "\nthe end of its output:\n" + t
	}
	return gungnir.Finding{ID: FindingID(r.Name), Source: r.Name, Severity: gungnir.SeverityBlocker,
		Location: location, Claim: claim, Status: gungnir.FindingOpen}, true
}

// FindingID is the id of the finding a failing check of this name reports.
func FindingID(check string) string { return "check-" + check }

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
