// Package claudecode is the adapter for Claude Code's headless mode, claude -p with stream-json
// output (spec §5). It runs only in a sandbox. It authenticates with CLAUDE_CODE_OAUTH_TOKEN and
// nothing else, and starts every session with --setting-sources user --strict-mcp-config, never
// --bare, which can't use that token (sandbox spike B, decided 2026-10-14).
package claudecode

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
	"strconv"
	"strings"
	"sync/atomic"
	"unicode/utf8"

	"github.com/ouroboric-dev/gleipnir/bounded"
	"github.com/ouroboric-dev/gleipnir/failure"
	"github.com/ouroboric-dev/gleipnir/submit"
	"github.com/ouroboric-dev/gungnir"
)

// TokenVar is the one credential the adapter passes to a session.
const TokenVar = "CLAUDE_CODE_OAUTH_TOKEN"

// refused are variables that would bill per token, or change who is billed: never passed, and a
// task whose allowlist names one is refused (spec §6.3; sandbox spike B).
var refused = []string{"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL", "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY"}

// maxStream is the most bytes of a session's output the adapter keeps in memory, and the most it
// writes to the transcript. A chatty session is an agent failure, not a host that runs out of memory
// (backlog B-021). A variable so a test can lower it.
var maxStream = 32 << 20

// Hosts are what the sandbox's firewall must open for a session.
var Hosts = []string{"api.anthropic.com"}

// Agent is the claude-code adapter.
type Agent struct {
	// Getenv reads the host's environment; os.Getenv by default. Tests set it.
	Getenv func(string) string
}

var _ gungnir.Agent = (*Agent)(nil)

func (a *Agent) Name() string { return "claude-code" }

func (a *Agent) getenv(k string) string {
	if a.Getenv != nil {
		return a.Getenv(k)
	}
	return os.Getenv(k)
}

// Submits says that the adapter hands a session's typed output back through ygg-submit (gungnir.Submitter).
func (a *Agent) Submits() bool { return true }

var _ gungnir.Submitter = (*Agent)(nil)

// submitTools are the two tools of ygg-submit, as Claude Code names the tools of an MCP server.
const submitTools = "mcp__" + submit.Server + "__submit,mcp__" + submit.Server + "__check"

// mcpConfig is the one MCP server of a session that returns contract: ygg-submit by its command, with no
// arguments, and the contract in its environment. The managed settings allow exactly that command.
func mcpConfig(contract string) string {
	b, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{submit.Server: map[string]any{
		"command": submit.Command, "env": map[string]string{submit.ContractVar: contract}}}})
	return string(b)
}

// Args returns the command line of one session, apart from its prompt, which goes on stdin. A
// read-only role gets read and search tools and nothing else; the others get the file and shell
// tools, which the sandbox contains. A session that returns a contract (t.Output) also gets the
// two tools of ygg-submit, from the one server --mcp-config names; --strict-mcp-config stays, so a
// server in the leaf's own .mcp.json is never read.
func Args(t gungnir.Task) []string {
	args := []string{"claude", "-p", "--output-format", "stream-json", "--verbose", "--no-session-persistence",
		"--setting-sources", "user", "--strict-mcp-config"}
	tools := "Bash,Edit,Write,Read,Grep,Glob"
	if t.ReadOnly {
		tools = "Read,Grep,Glob"
	}
	if t.Output != "" {
		args = append(args, "--mcp-config", mcpConfig(t.Output))
		tools += "," + submitTools
	}
	if t.Model != "" {
		args = append(args, "--model", t.Model)
	}
	if t.MaxTurns > 0 {
		args = append(args, "--max-turns", strconv.Itoa(t.MaxTurns))
	}
	if t.ReadOnly {
		return append(args, "--tools", tools, "--allowedTools", tools, "--permission-mode", "dontAsk")
	}
	return append(args, "--tools", tools, "--allowedTools", tools, "--permission-mode", "acceptEdits")
}

// Run runs one session in the task's sandbox and reports how it ended and what it used.
func (a *Agent) Run(ctx context.Context, t gungnir.Task) (gungnir.Result, error) {
	if t.Sandbox == nil {
		return gungnir.Result{}, gungnir.ErrNoSandbox
	}
	env := map[string]string{}
	for _, k := range t.EnvAllowlist {
		if slices.Contains(refused, k) {
			return gungnir.Result{}, fmt.Errorf("claude-code: %s is never passed to a session: it would bill per token or change who is billed", k)
		}
		if v := a.getenv(k); v != "" {
			env[k] = v
		}
	}
	tok := a.getenv(TokenVar)
	if tok == "" {
		return gungnir.Result{}, fmt.Errorf("claude-code: %s is not set; make one with claude setup-token and put it in the environment of ygg", TokenVar)
	}
	env[TokenVar] = tok
	if t.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t.Timeout)
		defer cancel()
	}
	ctx, stop := context.WithCancel(ctx)
	defer stop()
	transcript, closeT, err := openTranscript(t)
	if err != nil {
		return gungnir.Result{}, err
	}
	defer closeT()
	out, errOut := bounded.NewBuffer(maxStream), bounded.NewBuffer(maxStream)
	tw := bounded.NewWriter(transcript, int64(maxStream))
	// The session's tokens are added up as its messages arrive; the first message that takes them over
	// the limit ends the session, as a timeout does: its context is cancelled and the sandbox kills the command.
	var live tally
	var over atomic.Bool
	watch := bounded.NewLineWriter(func(line []byte) {
		live.add(line)
		if u := live.usage(); t.MaxTokens > 0 && u.InTok+u.OutTok > int64(t.MaxTokens) && !over.Swap(true) {
			stop()
		}
	}, maxStream)
	res, err := t.Sandbox.Run(ctx, gungnir.Cmd{Argv: Args(t), Env: env, Stdin: strings.NewReader(t.Prompt),
		Stdout: io.MultiWriter(out, tw, watch), Stderr: errOut})
	used := partialUsage(out.Bytes())
	if over.Load() {
		return gungnir.Result{}, &gungnir.SessionError{Kind: gungnir.FailureTokenLimit, Usage: used,
			Err: fmt.Errorf("claude-code: the session used %d tokens (input plus output, not cache reads), over its limit of %d", used.InTok+used.OutTok, t.MaxTokens)}
	}
	if err != nil {
		// A session the timeout or the operator ended is the agent's; any other failure to run the
		// command is the sandbox's (spec §12).
		kind := gungnir.FailureInfra
		if ctx.Err() != nil {
			kind = gungnir.FailureAgent
		}
		return gungnir.Result{}, &gungnir.SessionError{Kind: kind, Err: fmt.Errorf("claude-code: %w", err), Usage: used}
	}
	if out.Truncated() || tw.Truncated() {
		return gungnir.Result{}, &gungnir.SessionError{Kind: gungnir.FailureAgent, Usage: used,
			Err: fmt.Errorf("claude-code: the session wrote more than %d MiB of output", maxStream>>20)}
	}
	r, seen, err := parse(bytes.NewReader(out.Bytes()))
	if err != nil {
		return gungnir.Result{}, &gungnir.SessionError{Kind: unfinished(seen, res.ExitCode, string(errOut.Bytes())), Usage: used,
			Err: fmt.Errorf("claude-code: %w (exit %d; stderr: %s)", err, res.ExitCode, tail(string(errOut.Bytes())))}
	}
	r.TranscriptPath = transcriptPath(t)
	r.Provider = "anthropic"
	if t.Output != "" {
		// A read failure is an error, not a nil Submitted: Result has no field to say why, and Odin would repair
		// blind. The session's usage goes with it.
		if r.Submitted, err = lastSubmit(ctx, t, out.Bytes()); err != nil {
			return gungnir.Result{}, &gungnir.SessionError{Kind: gungnir.FailureAgent, Usage: r.Usage, Err: fmt.Errorf("claude-code: %w", err)}
		}
	}
	return r, nil
}

// lastSubmit is the output document of the last submit call of the stream that its tool result accepted, or nil.
// A call is an assistant message's tool_use block; its result is a tool_result block of a later user message,
// with the same id. A stream that held no such pair, or only refused calls, gives nil.
func lastSubmit(ctx context.Context, t gungnir.Task, stream []byte) ([]byte, error) {
	tr := submit.NewTracker(t.Output)
	sc := bufio.NewScanner(bytes.NewReader(stream))
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' || !bytes.Contains(line, []byte("submit")) && !bytes.Contains(line, []byte(`"tool_result"`)) {
			continue
		}
		var e struct {
			Message struct {
				Content []struct {
					Type      string          `json:"type"`
					ID        string          `json:"id"`
					Name      string          `json:"name"`
					Input     json.RawMessage `json:"input"`
					ToolUseID string          `json:"tool_use_id"`
					Content   json.RawMessage `json:"content"`
					IsError   bool            `json:"is_error"`
				} `json:"content"`
			} `json:"message"`
		}
		if json.Unmarshal(line, &e) != nil {
			continue
		}
		for _, b := range e.Message.Content {
			switch {
			case b.Type == "tool_use" && b.Name == "mcp__"+submit.Server+"__submit":
				tr.Call(b.ID, b.Input)
			case b.Type == "tool_result":
				tr.Result(b.ToolUseID, resultText(b.Content), b.IsError)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	input := tr.Last()
	if input == nil {
		return nil, nil
	}
	return submit.Document(ctx, t.Sandbox, input)
}

// resultText is the text of a tool result's content, which is a string or a list of blocks.
func resultText(c json.RawMessage) string {
	var s string
	if json.Unmarshal(c, &s) == nil {
		return s
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(c, &blocks) != nil {
		return ""
	}
	var parts []string
	for _, b := range blocks {
		if b.Type == "text" {
			parts = append(parts, b.Text)
		}
	}
	return strings.Join(parts, "\n")
}

// unfinished says how a session failed that ended without a usable result. A tool that crashed before
// it printed a single event is the transient failure of spec §12, unless its stderr says the quota is
// used up; one that got going and then died, or printed numbers we can't read, failed as an agent does.
func unfinished(seen bool, exit int, stderr string) gungnir.FailureKind {
	if k := failure.Classify(0, stderr); k == gungnir.FailureQuota {
		return k
	}
	if !seen && exit != 0 {
		return gungnir.FailureTransient
	}
	return gungnir.FailureAgent
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
	Type    string `json:"type"`
	Subtype string `json:"subtype"`
	Version string `json:"claude_code_version"`

	IsError      *bool           `json:"is_error"`
	Result       string          `json:"result"`
	NumTurns     *int64          `json:"num_turns"`
	TotalCost    *float64        `json:"total_cost_usd"`
	APIErrStatus json.RawMessage `json:"api_error_status"`
	Usage        *struct {
		Input         *int64 `json:"input_tokens"`
		Output        *int64 `json:"output_tokens"`
		CacheCreation *int64 `json:"cache_creation_input_tokens"`
		CacheRead     *int64 `json:"cache_read_input_tokens"`
	} `json:"usage"`
}

// parse reads a session's stream and returns what its result event says; seen reports whether the
// stream held any event at all. Anything the result event should hold and doesn't is an error:
// missing usage is never read as zero (spec §4.6).
func parse(r io.Reader) (res gungnir.Result, seen bool, err error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	var version string
	var final *event
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
		case "system":
			if e.Subtype == "init" && e.Version != "" {
				version = e.Version
			}
		case "result":
			ev := e
			final = &ev
		}
	}
	if err := sc.Err(); err != nil {
		return gungnir.Result{}, seen, err
	}
	if final == nil {
		return gungnir.Result{}, seen, errors.New("the session ended without a result event")
	}
	u := final.Usage
	if u == nil || u.Input == nil || u.Output == nil || u.CacheRead == nil || u.CacheCreation == nil || final.NumTurns == nil || final.TotalCost == nil || final.IsError == nil {
		return gungnir.Result{}, seen, errors.New("the result event lacks usage, turns, cost or is_error; refusing to read missing numbers as zero")
	}
	r2 := gungnir.Result{
		Status:     gungnir.StatusOK,
		Summary:    clip(final.Result),
		Output:     strings.TrimSpace(final.Result),
		CLIVersion: version,
		Usage: gungnir.Usage{
			InTok: *u.Input + *u.CacheCreation, OutTok: *u.Output, CacheTok: *u.CacheRead,
			Turns: *final.NumTurns, CostUSD: *final.TotalCost,
		},
	}
	if *final.IsError || final.Subtype != "success" {
		r2.Status, r2.Failure = gungnir.StatusFailed, gungnir.FailureAgent
		if r2.Summary == "" {
			r2.Summary = final.Subtype
		}
		status := 0
		if s := strings.Trim(string(final.APIErrStatus), "\" "); s != "" && s != "null" {
			r2.Summary += " (API status " + s + ")"
			status, _ = strconv.Atoi(s)
		}
		// A turn limit or a crash inside the session is the agent's; only what the API said can be
		// transient or a used-up quota.
		if final.Subtype == "success" {
			r2.Failure = failure.Classify(status, final.Result)
		}
	}
	return r2, seen, r2.Validate()
}

func clip(s string) string {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) <= 1000 {
		return s
	}
	return string([]rune(s)[:1000]) + "…"
}

// partialUsage adds up what a session's assistant messages reported before it ended, for a session
// that left no result event (a timeout, a crash). The numbers are a lower bound: the last message may be
// cut off, and the cost isn't known (it is zero, marked estimated). A message the stream repeats, one
// event per content block, counts once, at its largest figures; one with no id counts on its own, which
// can only overcount, and a cap should err that way.
func partialUsage(stream []byte) gungnir.Usage {
	var t tally
	sc := bufio.NewScanner(bytes.NewReader(stream))
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		t.add(sc.Bytes())
	}
	return t.usage()
}

// tally adds up the usage of a stream's assistant messages, line by line, by the rules of partialUsage.
type tally struct {
	byID map[string]tokens
	anon []tokens
}

type tokens struct{ in, out, cacheNew, cacheRead int64 }

// add reads one line of the stream; a line that is not an assistant message changes nothing.
func (t *tally) add(line []byte) {
	var e struct {
		Type    string `json:"type"`
		Message struct {
			ID  string `json:"id"`
			Raw struct {
				Input     int64 `json:"input_tokens"`
				Output    int64 `json:"output_tokens"`
				CacheNew  int64 `json:"cache_creation_input_tokens"`
				CacheRead int64 `json:"cache_read_input_tokens"`
			} `json:"usage"`
		} `json:"message"`
	}
	line = bytes.TrimSpace(line)
	if len(line) == 0 || line[0] != '{' || json.Unmarshal(line, &e) != nil || e.Type != "assistant" {
		return
	}
	u := tokens{e.Message.Raw.Input, e.Message.Raw.Output, e.Message.Raw.CacheNew, e.Message.Raw.CacheRead}
	if e.Message.ID == "" {
		t.anon = append(t.anon, u)
		return
	}
	if t.byID == nil {
		t.byID = map[string]tokens{}
	}
	old := t.byID[e.Message.ID]
	t.byID[e.Message.ID] = tokens{max(old.in, u.in), max(old.out, u.out), max(old.cacheNew, u.cacheNew), max(old.cacheRead, u.cacheRead)}
}

func (t *tally) usage() gungnir.Usage {
	var sum gungnir.Usage
	add := func(t tokens) {
		sum.InTok += t.in + t.cacheNew
		sum.OutTok += t.out
		sum.CacheTok += t.cacheRead
		sum.Turns++
	}
	for _, m := range t.byID {
		add(m)
	}
	for _, m := range t.anon {
		add(m)
	}
	sum.CostEstimated = sum.Turns > 0
	return sum
}
