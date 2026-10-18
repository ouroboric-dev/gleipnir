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
var template string

// Gitleaks is where the sandbox image keeps the pinned gitleaks (assets/Containerfile in sandbox).
// The scan runs it by this path, never from the sandbox's PATH.
const Gitleaks = "/opt/ygg/bin/gitleaks"

// pinnedConfig is the factory's gitleaks config: gitleaks's own default rules and nothing else. The
// scan gives it by absolute path, so no config in the leaf applies.
const pinnedConfig = `# The factory's gitleaks config: the default rules of the pinned gitleaks, with no allowlist.
[extend]
useDefault = true
`

// script is the scan with the gitleaks at path. Tests run it on the host with a stand-in. The
// template's @CONFIG@ line ends with the newline the config's own last one would repeat, so the
// heredoc's terminator stays on a line of its own and the config arrives as pinned.
func script(gitleaks string) string {
	return strings.NewReplacer("@GITLEAKS@", gitleaks, "@CONFIG@", strings.TrimSuffix(pinnedConfig, "\n")).Replace(template)
}

// Argv is the command the scan runs in the sandbox, by an absolute bash: a fake sandbox knows the
// scan by it.
func Argv() []string { return []string{"/bin/bash", "-c", script(Gitleaks)} }

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

// Run scans files, paths in the leaf behind r, which must be exactly what the checkpoint would
// commit: the caller lists them with its own git, never the sandbox's. A clean tree is nil. Secrets
// are a *FoundError. A scan that couldn't run, or whose report can't be read, is an ordinary error:
// no answer is never "clean".
func Run(ctx context.Context, r gungnir.Runner, files []string) error {
	var list strings.Builder
	for _, f := range files {
		list.WriteString(f)
		list.WriteByte(0)
	}
	var out, errOut bytes.Buffer
	res, err := r.Run(ctx, gungnir.Cmd{Argv: Argv(), Stdin: strings.NewReader(list.String()), Stdout: &out, Stderr: &errOut})
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
		fe.Findings = append(fe.Findings, Finding{Rule: r.RuleID, File: leafPath(r.File), Line: r.StartLine})
	}
	return fe
}

// leafPath turns a path in gitleaks's report into the file's path in the leaf: the scan copies the
// leaf's files to t/ in the folder gitleaks scans.
func leafPath(p string) string {
	p = strings.TrimPrefix(strings.TrimPrefix(p, "./"), "/")
	return strings.TrimPrefix(p, "t/")
}
