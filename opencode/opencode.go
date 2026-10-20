// Package opencode is the adapter for opencode run with JSON events (spec §5), on OpenRouter
// models. It runs only in a sandbox. Its configuration goes in through the environment, and the
// repository's own opencode configuration, plugins and skills are switched off, because a plugin
// in a hostile repository ran on startup in the sandbox spike's check.
package opencode

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/ouroboric-dev/gleipnir/bounded"
	"github.com/ouroboric-dev/gleipnir/failure"
	"github.com/ouroboric-dev/gungnir"
)

// KeyVar is the one credential the adapter passes: a dedicated OpenRouter key with a hard credit
// limit (spec §6.3).
const KeyVar = "OPENROUTER_API_KEY"

// maxStream is the most bytes of a session's output the adapter keeps in memory, and the most it
// writes to the transcript. A chatty session is an agent failure, not a host that runs out of memory
// (backlog B-021). A variable so a test can lower it.
var maxStream = 32 << 20

// Hosts are what the sandbox's firewall must open for a session.
var Hosts = []string{"openrouter.ai"}

// Price is a model's price in dollars per million tokens. An operator sets it in factory.yaml when
// the tool's own cost figure is missing or wrong.
type Price struct{ Input, Output, CacheRead, CacheWrite float64 }

// Config holds what one role's adapter needs.
type Config struct {
	Privacy string              // "standard" or "strict"
	Price   *Price              // optional: cost is then computed from tokens, and marked estimated
	Getenv  func(string) string // the host's environment; os.Getenv by default
}

// Agent is the opencode adapter for one role's model.
type Agent struct {
	cfg   Config
	model string // the id on OpenRouter, without the openrouter/ prefix
}

var _ gungnir.Agent = (*Agent)(nil)

// strictProvider is what privacy: strict means on OpenRouter (sandbox spike C, decided 2026-10-14):
// providers that keep no data and don't train, and no fallback to another one.
var strictProvider = map[string]any{"data_collection": "deny", "zdr": true, "allow_fallbacks": false}

// New returns the adapter for model, such as openrouter/deepseek/deepseek-v4-flash. It refuses
// privacy: strict for a model it can't tighten: the setting is made on OpenRouter's requests, so
// it can't cover a model served any other way.
func New(model string, cfg Config) (*Agent, error) {
	id, ok := strings.CutPrefix(model, "openrouter/")
	if !ok || id == "" {
		return nil, fmt.Errorf("opencode: model %q must be openrouter/<model>: v0 runs opencode on OpenRouter only", model)
	}
	switch cfg.Privacy {
	case "", "standard", "strict":
	default:
		return nil, fmt.Errorf("opencode: privacy %q is neither standard nor strict", cfg.Privacy)
	}
	return &Agent{cfg: cfg, model: id}, nil
}

func (a *Agent) Name() string { return "opencode" }

func (a *Agent) getenv(k string) string {
	if a.cfg.Getenv != nil {
		return a.cfg.Getenv(k)
	}
	return os.Getenv(k)
}

// ConfigJSON is the configuration of a session, which reaches opencode as OPENCODE_CONFIG_CONTENT.
// The key is a reference to the environment, never a value. Under strict privacy the provider
// settings sit on the model, and small_model, which opencode uses for titles, is the same model: a
// second model without them would send the prompt to a provider chosen with no filter (spike C).
func (a *Agent) ConfigJSON(t gungnir.Task) (string, error) {
	// A reasoning effort is named on every request: a model left to its default effort sometimes thinks that its
	// prompt holds no request and asks what to do (see TestEverySessionNamesAReasoningEffort).
	options := map[string]any{"reasoning": map[string]any{"effort": "high"}}
	if a.cfg.Privacy == "strict" {
		options["provider"] = strictProvider
	}
	model := map[string]any{"options": options}
	c := map[string]any{
		"$schema": "https://opencode.ai/config.json", "autoupdate": false, "share": "disabled",
		"provider": map[string]any{"openrouter": map[string]any{
			"options": map[string]any{"apiKey": "{env:" + KeyVar + "}"},
			"models":  map[string]any{a.model: model},
		}},
		"small_model": "openrouter/" + a.model,
	}
	if t.MaxTurns > 0 {
		c["agent"] = map[string]any{"build": map[string]any{"steps": t.MaxTurns}}
	}
	if t.ReadOnly {
		c["permission"] = map[string]any{"edit": "deny", "bash": "deny", "webfetch": "deny", "external_directory": "deny", "task": "deny", "question": "deny"}
	}
	b, err := json.Marshal(c)
	return string(b), err
}

// Args returns the command line of a session, apart from its prompt, which goes on stdin.
func Args(t gungnir.Task, model string) []string {
	args := []string{"opencode", "run", "--format", "json", "-m", "openrouter/" + model}
	if !t.ReadOnly {
		args = append(args, "--auto")
	}
	return args
}

// Run runs one session in the task's sandbox and reports how it ended and what it used.
func (a *Agent) Run(ctx context.Context, t gungnir.Task) (gungnir.Result, error) {
	if t.Sandbox == nil {
		return gungnir.Result{}, gungnir.ErrNoSandbox
	}
	if t.Model != "" && t.Model != "openrouter/"+a.model {
		return gungnir.Result{}, fmt.Errorf("opencode: the task's model %q isn't the adapter's %q", t.Model, "openrouter/"+a.model)
	}
	key := a.getenv(KeyVar)
	if key == "" {
		return gungnir.Result{}, fmt.Errorf("opencode: %s is not set; use a dedicated OpenRouter key with a credit limit", KeyVar)
	}
	conf, err := a.ConfigJSON(t)
	if err != nil {
		return gungnir.Result{}, err
	}
	env := map[string]string{
		KeyVar: key, "OPENCODE_CONFIG_CONTENT": conf,
		"OPENCODE_DISABLE_PROJECT_CONFIG": "1", "OPENCODE_DISABLE_CLAUDE_CODE": "1", "OPENCODE_DISABLE_EXTERNAL_SKILLS": "1",
		"OPENCODE_DISABLE_AUTOUPDATE": "true", "OPENCODE_DISABLE_SHARE": "true", "OPENCODE_DISABLE_MODELS_FETCH": "true",
	}
	for _, k := range t.EnvAllowlist {
		if k == KeyVar || strings.HasPrefix(k, "OPENCODE_") || slices.Contains([]string{"ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"}, k) {
			return gungnir.Result{}, fmt.Errorf("opencode: %s may not be on a task's allowlist: the adapter sets its own variables, and holds no Anthropic credential", k)
		}
		if v := a.getenv(k); v != "" {
			env[k] = v
		}
	}
	if t.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t.Timeout)
		defer cancel()
	}
	transcript, closeT, err := openTranscript(t)
	if err != nil {
		return gungnir.Result{}, err
	}
	defer closeT()
	version := a.version(ctx, t, env)
	out, errOut := bounded.NewBuffer(maxStream), bounded.NewBuffer(maxStream)
	tw := bounded.NewWriter(transcript, int64(maxStream))
	res, err := t.Sandbox.Run(ctx, gungnir.Cmd{Argv: Args(t, a.model), Env: env, Stdin: strings.NewReader(t.Prompt),
		Stdout: io.MultiWriter(out, tw), Stderr: errOut})
	// The steps that finished before the session ended were spent, whatever way it ended (backlog B-020).
	_, spent, _, _ := a.parse(bytes.NewReader(out.Bytes()), 0)
	if err != nil {
		// A session the timeout or the operator ended is the agent's; any other failure to run the
		// command is the sandbox's (spec §12).
		kind := gungnir.FailureInfra
		if ctx.Err() != nil {
			kind = gungnir.FailureAgent
		}
		return gungnir.Result{}, &gungnir.SessionError{Kind: kind, Err: fmt.Errorf("opencode: %w", err), Usage: spent}
	}
	if out.Truncated() || tw.Truncated() {
		return gungnir.Result{}, &gungnir.SessionError{Kind: gungnir.FailureAgent, Usage: spent,
			Err: fmt.Errorf("opencode: the session wrote more than %d MiB of output", maxStream>>20)}
	}
	r, used, seen, err := a.parse(bytes.NewReader(out.Bytes()), res.ExitCode)
	if err != nil {
		kind := gungnir.FailureAgent
		if k := failure.Classify(0, string(errOut.Bytes())); k == gungnir.FailureQuota {
			kind = k
		} else if !seen && res.ExitCode != 0 {
			kind = gungnir.FailureTransient // the tool crashed before it printed an event (spec §12)
		}
		return gungnir.Result{}, &gungnir.SessionError{Kind: kind, Usage: used,
			Err: fmt.Errorf("opencode: %w (exit %d; stderr: %s)", err, res.ExitCode, tail(string(errOut.Bytes())))}
	}
	r.TranscriptPath, r.Provider, r.CLIVersion = transcriptPath(t), "openrouter", version
	return r, nil
}

// version asks the tool for its version in the sandbox. A session that can't say is still a
// session; the version is for the ledger.
func (a *Agent) version(ctx context.Context, t gungnir.Task, env map[string]string) string {
	var out bytes.Buffer
	res, err := t.Sandbox.Run(ctx, gungnir.Cmd{Argv: []string{"opencode", "--version"}, Env: map[string]string{"OPENCODE_DISABLE_PROJECT_CONFIG": "1"}, Stdout: &out})
	if err != nil || res.ExitCode != 0 {
		return ""
	}
	return strings.TrimSpace(out.String())
}

func transcriptPath(t gungnir.Task) string {
	if t.TranscriptDir == "" {
		return ""
	}
	return filepath.Join(t.TranscriptDir, fmt.Sprintf("%s-%d.jsonl", t.Node, t.Attempt))
}

func openTranscript(t gungnir.Task) (io.Writer, func(), error) {
	p := transcriptPath(t)
	if p == "" {
		return io.Discard, func() {}, nil
	}
	if err := os.MkdirAll(t.TranscriptDir, 0o755); err != nil {
		return nil, nil, err
	}
	f, err := os.Create(p)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { f.Close() }, nil
}

func tail(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 300 {
		return "…" + s[len(s)-300:]
	}
	return s
}

type event struct {
	Type string `json:"type"`
	Part struct {
		Type   string `json:"type"`
		Text   string `json:"text"`
		Reason string `json:"reason"`
		Tokens *struct {
			Input     *int64 `json:"input"`
			Output    *int64 `json:"output"`
			Reasoning *int64 `json:"reasoning"`
			Cache     *struct {
				Write *int64 `json:"write"`
				Read  *int64 `json:"read"`
			} `json:"cache"`
		} `json:"tokens"`
		Cost *float64 `json:"cost"`
	} `json:"part"`
	Error *struct {
		Name string `json:"name"`
		Data struct {
			Message    string `json:"message"`
			StatusCode int    `json:"statusCode"`
		} `json:"data"`
	} `json:"error"`
}

// parse reads a session's events. Each step_finish carries one step's tokens, and the session's
// usage is their sum: cache reads stay separate from other input tokens, because they bill at
// another rate (spike C). The cost is the tool's own figure, or the price's, and is marked
// estimated either way: the provider's real bill isn't in the events. used is what the events
// reported, whether or not the session is usable, and seen says whether there was any event at all.
// The final answer is the text of the last step that said anything.
func (a *Agent) parse(r io.Reader, exit int) (res gungnir.Result, used gungnir.Usage, seen bool, err error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	var text, answer, failed string
	status := 0
	steps := 0
	var cost float64
	var in, out, reason, cw, cacheRead int64
	broken := false // a step_finish lacked a number
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var e event
		if json.Unmarshal(line, &e) != nil {
			continue
		}
		seen = true
		switch e.Type {
		case "step_start":
			text = ""
		case "text":
			text += e.Part.Text
		case "error":
			failed = "error"
			if e.Error != nil {
				failed = fmt.Sprintf("%s: %s", e.Error.Name, e.Error.Data.Message)
				status = e.Error.Data.StatusCode
				if status != 0 {
					failed += fmt.Sprintf(" (API status %d)", status)
				}
			}
		case "step_finish":
			tk := e.Part.Tokens
			if tk == nil || tk.Input == nil || tk.Output == nil || tk.Cache == nil || tk.Cache.Read == nil || tk.Cache.Write == nil || e.Part.Cost == nil {
				broken = true
				continue
			}
			steps++
			in += *tk.Input
			out += *tk.Output
			cw += *tk.Cache.Write
			cacheRead += *tk.Cache.Read
			if tk.Reasoning != nil {
				reason += *tk.Reasoning
			}
			cost += *e.Part.Cost
			if strings.TrimSpace(text) != "" {
				answer = text
			}
		}
	}
	if err := sc.Err(); err != nil {
		return gungnir.Result{}, used, seen, err
	}
	used = gungnir.Usage{InTok: in + cw, OutTok: out + reason, CacheTok: cacheRead, Turns: int64(steps)}
	if a.cfg.Price != nil {
		p := *a.cfg.Price
		cost = (float64(in)*p.Input + float64(out+reason)*p.Output + float64(cacheRead)*p.CacheRead + float64(cw)*p.CacheWrite) / 1e6
	}
	used.CostUSD, used.CostEstimated = cost, true
	switch {
	case broken:
		return gungnir.Result{}, used, seen, errors.New("a step_finish event lacks tokens or cost; refusing to read missing numbers as zero")
	case failed == "" && steps == 0:
		return gungnir.Result{}, used, seen, errors.New("the session ended without a single step")
	case cost == 0 && used.InTok+used.OutTok+used.CacheTok > 0:
		// Whether the session succeeded or not: tokens with no dollars leave the dollar cap blind.
		return gungnir.Result{}, used, seen, errors.New("opencode reported tokens but no cost for this model; set roles.<role>.price in factory.yaml so the caps can count dollars")
	}
	res = gungnir.Result{Status: gungnir.StatusOK, Summary: clip(answer), Output: strings.TrimSpace(answer), Usage: used}
	switch {
	case failed != "":
		res.Status, res.Summary, res.Failure = gungnir.StatusFailed, failed, failure.Classify(status, failed)
	case exit != 0:
		res.Status, res.Summary, res.Failure = gungnir.StatusFailed, fmt.Sprintf("opencode exited %d: %s", exit, res.Summary), gungnir.FailureAgent
	}
	return res, used, seen, res.Validate()
}

func clip(s string) string {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) <= 1000 {
		return s
	}
	return string([]rune(s)[:1000]) + "…"
}
