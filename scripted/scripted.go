// Package scripted is the agent adapter that replays canned actions, at no model cost. It is for
// tests only (spec §5, §13).
package scripted

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ouroboric-dev/gungnir"
	"go.yaml.in/yaml/v3"
)

// Script says what each attempt of each node does: steps[node][attempt-1].
type Script struct {
	Steps map[string][]Step `yaml:"steps"`
}

// Step is one attempt. Exactly one of Result, Hang and Error is set.
type Step struct {
	Actions []Action `yaml:"actions"` // applied in order, inside the workdir, before the result
	Result  *Outcome `yaml:"result"`
	Hang    bool     `yaml:"hang"`  // block until the context ends: a session the factory must stop
	Error   string   `yaml:"error"` // Run returns this error: an agent failure
}

// Action changes one file in the workdir, or runs one command in the task's sandbox. Exactly one
// field is set. A run action is how escape tests act as a hostile agent inside the sandbox.
type Action struct {
	Write  *Write `yaml:"write"`
	Remove string `yaml:"remove"`
	Run    *Run   `yaml:"run"`
}

// Run is a command in the sandbox, without a shell. A non-zero exit fails the step, unless
// AllowFailure is set: an escape attempt is meant to fail, and the test then checks what it left.
type Run struct {
	Argv         []string `yaml:"argv"`
	AllowFailure bool     `yaml:"allow_failure"`
}

// Write writes Content to Path, creating parent directories.
type Write struct {
	Path    string `yaml:"path"`
	Content string `yaml:"content"`
}

// Outcome is the result a step reports.
type Outcome struct {
	Status     gungnir.Status `yaml:"status"`
	Summary    string         `yaml:"summary"`
	Provider   string         `yaml:"provider"`    // who served the model, as a real adapter reports it
	CLIVersion string         `yaml:"cli_version"` // the agent tool's version, as a real adapter reports it
	Usage      struct {
		In            int64   `yaml:"in"`
		Out           int64   `yaml:"out"`
		Cache         int64   `yaml:"cache"`
		Turns         int64   `yaml:"turns"`
		CostUSD       float64 `yaml:"cost_usd"`
		CostEstimated bool    `yaml:"cost_estimated"`
	} `yaml:"usage"`
}

// Agent replays a Script.
type Agent struct{ script Script }

var _ gungnir.Agent = (*Agent)(nil)

// Load reads and checks a script. A script that could be read two ways is refused.
func Load(path string) (*Agent, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var s Script
	if err := dec.Decode(&s); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: holds more than one YAML document", path)
	}
	for node, steps := range s.Steps {
		for i, st := range steps {
			if err := st.check(); err != nil {
				return nil, fmt.Errorf("%s: steps.%s[%d]: %w", path, node, i, err)
			}
		}
	}
	return &Agent{script: s}, nil
}

func (st Step) check() error {
	set := 0
	for _, b := range []bool{st.Result != nil, st.Hang, st.Error != ""} {
		if b {
			set++
		}
	}
	if set != 1 {
		return errors.New("set exactly one of result, hang and error")
	}
	if st.Result != nil && st.Result.Status != gungnir.StatusOK && st.Result.Status != gungnir.StatusFailed {
		return fmt.Errorf("result status %q is neither ok nor failed", st.Result.Status)
	}
	for _, a := range st.Actions {
		set := 0
		for _, b := range []bool{a.Write != nil, a.Remove != "", a.Run != nil} {
			if b {
				set++
			}
		}
		switch {
		case set != 1:
			return errors.New("an action sets exactly one of write, remove and run")
		case a.Run != nil && (len(a.Run.Argv) == 0 || a.Run.Argv[0] == ""):
			return errors.New("a run action needs a command")
		case a.Write != nil && !filepath.IsLocal(a.Write.Path), a.Remove != "" && !filepath.IsLocal(a.Remove):
			return errors.New("an action's path must be a relative path inside the workdir")
		}
	}
	return nil
}

func (a *Agent) Name() string { return "scripted" }

// Run replays the step for t.Node's attempt t.Attempt. Files change only inside t.Workdir: the
// workdir is opened as an os.Root, so neither ".." nor a symlink leads out of it.
func (a *Agent) Run(ctx context.Context, t gungnir.Task) (gungnir.Result, error) {
	steps := a.script.Steps[t.Node]
	if t.Attempt < 1 || t.Attempt > len(steps) {
		return gungnir.Result{}, fmt.Errorf("scripted: the script has no attempt %d for node %q", t.Attempt, t.Node)
	}
	st := steps[t.Attempt-1]
	transcript, err := writeTranscript(t)
	if err != nil {
		return gungnir.Result{}, err
	}
	if st.Hang {
		<-ctx.Done()
		return gungnir.Result{}, ctx.Err()
	}
	if st.Error != "" {
		return gungnir.Result{}, errors.New(st.Error)
	}
	root, err := os.OpenRoot(t.Workdir)
	if err != nil {
		return gungnir.Result{}, err
	}
	defer root.Close()
	for i, act := range st.Actions {
		if act.Run != nil {
			if err := runInSandbox(ctx, t, i, act.Run); err != nil {
				return gungnir.Result{}, fmt.Errorf("scripted: %w", err)
			}
			continue
		}
		if err := apply(root, act); err != nil {
			return gungnir.Result{}, fmt.Errorf("scripted: %w", err)
		}
	}
	o := st.Result
	return gungnir.Result{
		Status:     o.Status,
		Summary:    o.Summary,
		Provider:   o.Provider,
		CLIVersion: o.CLIVersion,
		Usage: gungnir.Usage{InTok: o.Usage.In, OutTok: o.Usage.Out, CacheTok: o.Usage.Cache,
			Turns: o.Usage.Turns, CostUSD: o.Usage.CostUSD, CostEstimated: o.Usage.CostEstimated},
		TranscriptPath: transcript,
	}, nil
}

// runInSandbox runs one command through the task's sandbox, and keeps its output beside the
// transcript. A task without a sandbox can't run one: the scripted adapter never runs commands on the
// host.
func runInSandbox(ctx context.Context, t gungnir.Task, i int, r *Run) error {
	if t.Sandbox == nil {
		return errors.New("a run action needs a sandbox, and the task has none")
	}
	var out bytes.Buffer
	res, err := t.Sandbox.Run(ctx, gungnir.Cmd{Argv: r.Argv, Stdout: &out, Stderr: &out})
	if t.TranscriptDir != "" {
		name := filepath.Join(t.TranscriptDir, fmt.Sprintf("%s-%d-run-%d.log", t.Node, t.Attempt, i+1))
		if werr := os.WriteFile(name, out.Bytes(), 0o644); werr != nil && err == nil {
			err = werr
		}
	}
	switch {
	case err != nil:
		return err
	case res.ExitCode != 0 && !r.AllowFailure:
		return fmt.Errorf("%v exited %d", r.Argv, res.ExitCode)
	}
	return nil
}

func apply(root *os.Root, act Action) error {
	if act.Write == nil {
		return root.Remove(act.Remove)
	}
	if dir := filepath.Dir(act.Write.Path); dir != "." {
		if err := root.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return root.WriteFile(act.Write.Path, []byte(act.Write.Content), 0o644)
}

// writeTranscript records the task the session got, so tests can check what reached the agent.
func writeTranscript(t gungnir.Task) (string, error) {
	if t.TranscriptDir == "" {
		return "", nil
	}
	if err := os.MkdirAll(t.TranscriptDir, 0o755); err != nil {
		return "", err
	}
	data, err := json.MarshalIndent(map[string]any{
		"role": t.Role, "node": t.Node, "attempt": t.Attempt, "model": t.Model, "prompt": t.Prompt,
	}, "", "  ")
	if err != nil {
		return "", err
	}
	p := filepath.Join(t.TranscriptDir, fmt.Sprintf("%s-%d.json", t.Node, t.Attempt))
	return p, os.WriteFile(p, data, 0o644)
}
