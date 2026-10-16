// Package scan looks for secrets before a checkpoint commit (spec §14). The scan runs in the leaf's
// sandbox, where gitleaks is pinned in the image; Odin never runs it on the host.
package scan

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/ouroboric-dev/gungnir"
)

//go:embed scan.sh
var script string

// Script is the scan, for tests that run it on the host with a stand-in for gitleaks.
func Script() string { return script }

// Finding is one secret gitleaks found. It never holds the secret: the report is redacted.
type Finding struct {
	Rule string
	File string
	Line int
}

func (f Finding) String() string { return fmt.Sprintf("%s:%d (%s)", f.File, f.Line, f.Rule) }

// FoundError is a scan that found secrets.
type FoundError struct{ Findings []Finding }

func (e *FoundError) Error() string {
	var parts []string
	for _, f := range e.Findings {
		parts = append(parts, f.String())
	}
	return fmt.Sprintf("%d possible secret(s) in what would be committed: %s", len(e.Findings), strings.Join(parts, ", "))
}

// exitFound is the exit code the script gives gitleaks for "secrets found", so it can't be mistaken
// for a failure of the tool.
const exitFound = 7

// Run scans the leaf behind r. A clean tree is nil. Secrets are a *FoundError. A scan that couldn't
// run, or whose report can't be read, is an ordinary error: no answer is never "clean".
func Run(ctx context.Context, r gungnir.Runner) error {
	var out, errOut bytes.Buffer
	res, err := r.Run(ctx, gungnir.Cmd{Argv: []string{"bash", "-s"}, Stdin: strings.NewReader(script), Stdout: &out, Stderr: &errOut})
	if err != nil {
		return fmt.Errorf("the secret scan couldn't run: %w", err)
	}
	switch res.ExitCode {
	case 0:
		return nil
	case exitFound:
		return found(out.Bytes())
	}
	return fmt.Errorf("the secret scan failed (exit %d): %s", res.ExitCode, strings.TrimSpace(errOut.String()))
}

func found(report []byte) error {
	var rows []struct {
		RuleID    string `json:"RuleID"`
		File      string `json:"File"`
		StartLine int    `json:"StartLine"`
	}
	if err := json.Unmarshal(report, &rows); err != nil {
		return fmt.Errorf("the secret scan found something, and its report can't be read: %w", err)
	}
	if len(rows) == 0 {
		return errors.New("the secret scan exited as if it found secrets, with an empty report")
	}
	fe := &FoundError{}
	for _, r := range rows {
		fe.Findings = append(fe.Findings, Finding{Rule: r.RuleID, File: strings.TrimPrefix(r.File, "/"), Line: r.StartLine})
	}
	return fe
}
