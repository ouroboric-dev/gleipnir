package opencode

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/ouroboric-dev/gungnir"
)

type fake struct {
	stdout map[string]string // by the program's first argument: run or --version
	stderr string
	err    error // what the run command returns, beside its output
	exit   int
	calls  []gungnir.Cmd
	prompt string
}

func (f *fake) Run(_ context.Context, c gungnir.Cmd) (gungnir.ExecResult, error) {
	f.calls = append(f.calls, c)
	if c.Argv[1] == "--version" {
		c.Stdout.Write([]byte("1.18.32\n"))
		return gungnir.ExecResult{}, nil
	}
	if c.Stdin != nil {
		b, _ := io.ReadAll(c.Stdin)
		f.prompt = string(b)
	}
	c.Stdout.Write([]byte(f.stdout["run"]))
	if c.Stderr != nil {
		c.Stderr.Write([]byte(f.stderr))
	}
	return gungnir.ExecResult{ExitCode: f.exit}, f.err
}

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func newAgent(t *testing.T, privacy string, price *Price) *Agent {
	t.Helper()
	a, err := New("openrouter/openai/gpt-4o-mini", Config{Privacy: privacy, Price: price,
		Getenv: func(k string) string { return map[string]string{KeyVar: "or-key-secret"}[k] }})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func task(f *fake, t *testing.T) gungnir.Task {
	return gungnir.Task{Node: "review", Attempt: 1, Prompt: "Review it.", Model: "openrouter/openai/gpt-4o-mini", Sandbox: f, TranscriptDir: t.TempDir()}
}

// success.jsonl and auth-error.jsonl are what opencode 1.18.32 printed against a local stand-in for
// OpenRouter: one step of 7 input, 5 output and 80 cache-read tokens, and a 401.
func TestUsageKeepsCachedTokensSeparate(t *testing.T) {
	f := &fake{stdout: map[string]string{"run": fixture(t, "success.jsonl")}}
	r, err := newAgent(t, "standard", nil).Run(context.Background(), task(f, t))
	if err != nil {
		t.Fatal(err)
	}
	want := gungnir.Usage{InTok: 7, OutTok: 5, CacheTok: 80, Turns: 1, CostUSD: 0.00001005, CostEstimated: true}
	if r.Status != gungnir.StatusOK || r.Usage != want || r.Summary != "Hello from the fake." || r.Provider != "openrouter" || r.CLIVersion != "1.18.32" {
		t.Errorf("Result = %+v, want usage %+v", r, want)
	}
	if f.prompt != "Review it." {
		t.Errorf("the prompt on stdin = %q", f.prompt)
	}
}

func TestAPriceFromTheOperatorReplacesTheToolsCost(t *testing.T) {
	f := &fake{stdout: map[string]string{"run": fixture(t, "success.jsonl")}}
	r, err := newAgent(t, "standard", &Price{Input: 1, Output: 2, CacheRead: 0.1}).Run(context.Background(), task(f, t))
	if err != nil {
		t.Fatal(err)
	}
	if want := (7*1.0 + 5*2.0 + 80*0.1) / 1e6; r.Usage.CostUSD != want || !r.Usage.CostEstimated {
		t.Errorf("cost = %v (estimated %v), want %v", r.Usage.CostUSD, r.Usage.CostEstimated, want)
	}
	noCost := strings.Replace(fixture(t, "success.jsonl"), `"cost":0.00001005`, `"cost":0`, 1)
	f2 := &fake{stdout: map[string]string{"run": noCost}}
	if _, err := newAgent(t, "standard", nil).Run(context.Background(), task(f2, t)); err == nil || !strings.Contains(err.Error(), "price") {
		t.Errorf("a session with tokens and no cost: %v; the caps need dollars", err)
	}
}

func TestAnAPIErrorIsAFailedResultWithItsReason(t *testing.T) {
	f := &fake{stdout: map[string]string{"run": fixture(t, "auth-error.jsonl")}, exit: 1}
	r, err := newAgent(t, "standard", nil).Run(context.Background(), task(f, t))
	if err != nil || r.Status != gungnir.StatusFailed || r.Summary != "APIError: No auth credentials found (API status 401)" {
		t.Errorf("Run() = %+v, %v; want a failed result that says why", r, err)
	}
	for name, out := range map[string]string{"no events": "", "garbage": "panic: boom\n"} {
		f := &fake{stdout: map[string]string{"run": out}, exit: 2}
		if _, err := newAgent(t, "standard", nil).Run(context.Background(), task(f, t)); err == nil {
			t.Errorf("%s: Run() = nil, want an error", name)
		}
	}
	missing := strings.Replace(fixture(t, "success.jsonl"), `"cache":{"write":0,"read":80}`, `"cache":{}`, 1)
	f2 := &fake{stdout: map[string]string{"run": missing}}
	if _, err := newAgent(t, "standard", nil).Run(context.Background(), task(f2, t)); err == nil {
		t.Error("a step_finish without cache counts was read as zero")
	}
}

func TestStrictPrivacyIsSetOnEveryModelTheToolMayCall(t *testing.T) {
	f := &fake{stdout: map[string]string{"run": fixture(t, "success.jsonl")}}
	a := newAgent(t, "strict", nil)
	conf, err := a.ConfigJSON(task(f, t))
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Small    string `json:"small_model"`
		Provider map[string]struct {
			Options map[string]string `json:"options"`
			Models  map[string]struct {
				Options struct{ Provider map[string]any } `json:"options"`
			} `json:"models"`
		} `json:"provider"`
	}
	if err := json.Unmarshal([]byte(conf), &c); err != nil {
		t.Fatal(err)
	}
	m := c.Provider["openrouter"].Models["openai/gpt-4o-mini"].Options.Provider
	if m["data_collection"] != "deny" || m["zdr"] != true || m["allow_fallbacks"] != false {
		t.Errorf("the model's provider settings = %v", m)
	}
	if c.Small != "openrouter/openai/gpt-4o-mini" {
		t.Errorf("small_model = %q: it must be a model that carries the settings, or titles go out unfiltered", c.Small)
	}
	if strings.Contains(conf, "or-key-secret") || !strings.Contains(conf, "{env:"+KeyVar+"}") {
		t.Errorf("the config holds the key instead of a reference: %s", conf)
	}
	if _, err := a.Run(context.Background(), task(f, t)); err != nil {
		t.Fatal(err)
	}
	standard, _ := newAgent(t, "standard", nil).ConfigJSON(task(f, t))
	if strings.Contains(standard, "data_collection") {
		t.Error("standard privacy sets provider restrictions")
	}
}

func TestStrictRefusesAModelItCannotTighten(t *testing.T) {
	for _, model := range []string{"anthropic/claude-sonnet", "openrouter/", "gpt-4o"} {
		if _, err := New(model, Config{Privacy: "strict"}); err == nil {
			t.Errorf("New(%q) = nil, want a refusal", model)
		}
	}
	if _, err := New("openrouter/x/y", Config{Privacy: "paranoid"}); err == nil {
		t.Error("an unknown privacy level was accepted")
	}
}

func TestTheSessionRunsLockedDownInTheSandbox(t *testing.T) {
	f := &fake{stdout: map[string]string{"run": fixture(t, "success.jsonl")}}
	tk := task(f, t)
	if _, err := newAgent(t, "standard", nil).Run(context.Background(), tk); err != nil {
		t.Fatal(err)
	}
	run := f.calls[len(f.calls)-1]
	argv := strings.Join(run.Argv, " ")
	if argv != "opencode run --format json -m openrouter/openai/gpt-4o-mini --auto" {
		t.Errorf("argv = %q", argv)
	}
	for _, k := range []string{"OPENCODE_DISABLE_PROJECT_CONFIG", "OPENCODE_DISABLE_CLAUDE_CODE", "OPENCODE_DISABLE_EXTERNAL_SKILLS", "OPENCODE_DISABLE_AUTOUPDATE", "OPENCODE_DISABLE_SHARE"} {
		if run.Env[k] == "" {
			t.Errorf("%s isn't set: the repository's own opencode configuration could run code", k)
		}
	}
	if run.Env[KeyVar] != "or-key-secret" || strings.Contains(argv, "or-key-secret") {
		t.Error("the key is missing from the environment, or on the command line")
	}
	tk.ReadOnly = true
	if _, err := newAgent(t, "standard", nil).Run(context.Background(), tk); err != nil {
		t.Fatal(err)
	}
	run = f.calls[len(f.calls)-1]
	if strings.Contains(strings.Join(run.Argv, " "), "--auto") || !strings.Contains(run.Env["OPENCODE_CONFIG_CONTENT"], `"edit":"deny"`) {
		t.Errorf("a read-only role's session = %v", run)
	}
}

// Without --auto a permission that is set to "ask" is rejected on the spot, and the session ends with no
// answer (the real-agent smoke, v0-H17: a reviewer read /app, outside its folder). Denied, the call is an
// error the model reads, and it goes on to answer.
func TestAReadOnlySessionDeniesTheFoldersOutsideItsOwn(t *testing.T) {
	f := &fake{stdout: map[string]string{"run": fixture(t, "success.jsonl")}}
	tk := task(f, t)
	tk.ReadOnly = true
	conf, err := newAgent(t, "standard", nil).ConfigJSON(tk)
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Permission map[string]string `json:"permission"`
	}
	if err := json.Unmarshal([]byte(conf), &c); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"edit", "bash", "webfetch", "external_directory"} {
		if c.Permission[k] != "deny" {
			t.Errorf("permission %q = %q in a read-only session, want deny", k, c.Permission[k])
		}
	}
}

func TestRefusals(t *testing.T) {
	if _, err := newAgent(t, "standard", nil).Run(context.Background(), gungnir.Task{Node: "n", Attempt: 1}); !errors.Is(err, gungnir.ErrNoSandbox) {
		t.Errorf("no sandbox: %v", err)
	}
	f := &fake{stdout: map[string]string{"run": fixture(t, "success.jsonl")}}
	tk := task(f, t)
	tk.EnvAllowlist = []string{"ANTHROPIC_API_KEY"}
	if _, err := newAgent(t, "standard", nil).Run(context.Background(), tk); err == nil {
		t.Error("an Anthropic credential on the allowlist was accepted")
	}
	tk.EnvAllowlist = nil
	a, _ := New("openrouter/openai/gpt-4o-mini", Config{Getenv: func(string) string { return "" }})
	if _, err := a.Run(context.Background(), tk); err == nil || !strings.Contains(err.Error(), KeyVar) {
		t.Errorf("no key: %v", err)
	}
	tk.Model = "openrouter/other/model"
	if _, err := newAgent(t, "standard", nil).Run(context.Background(), tk); err == nil {
		t.Error("a task for another model ran")
	}
}

func apiError(status int, message string) string {
	return fmt.Sprintf(`{"type":"error","error":{"name":"APIError","data":{"message":%q,"statusCode":%d}}}`, message, status) + "\n"
}

func TestAnAPIErrorSaysHowItFailed(t *testing.T) {
	cases := map[string]struct {
		status  int
		message string
		want    gungnir.FailureKind
	}{
		"a rate limit":         {429, "Rate limit exceeded: free-models-per-min", gungnir.FailureTransient},
		"a server error":       {502, "Bad gateway", gungnir.FailureTransient},
		"credits used up":      {402, "Insufficient credits. Add more using https://openrouter.ai/credits", gungnir.FailureQuota},
		"a key over its limit": {403, "Key limit exceeded (monthly limit)", gungnir.FailureQuota},
		"a quota in the words": {429, "You exceeded your current quota", gungnir.FailureQuota},
		"a rejected key":       {401, "No auth credentials found", gungnir.FailureAgent},
		"a bad request":        {400, "invalid model", gungnir.FailureAgent},
	}
	for name, c := range cases {
		f := &fake{stdout: map[string]string{"run": apiError(c.status, c.message)}, exit: 1}
		r, err := newAgent(t, "standard", nil).Run(context.Background(), task(f, t))
		if err != nil || r.Status != gungnir.StatusFailed || r.Failure != c.want {
			t.Errorf("%s: %+v, %v; want a failed result of kind %q", name, r, err, c.want)
		}
	}
}

func TestTheFinalAnswerIsTheTextOfTheLastStepThatSaidAnything(t *testing.T) {
	step := func(text string, cost string) string {
		out := `{"type":"step_start","part":{"type":"step-start"}}` + "\n"
		for _, part := range text {
			out += fmt.Sprintf(`{"type":"text","part":{"type":"text","text":%q}}`, string(part)) + "\n"
		}
		return out + `{"type":"step_finish","part":{"type":"step-finish","reason":"stop","tokens":{"input":1,"output":1,"reasoning":0,"cache":{"write":0,"read":0}},"cost":` + cost + `}}` + "\n"
	}
	// The second step's text comes in two parts; the third step, a tool call, says nothing.
	two := `{"type":"step_start","part":{"type":"step-start"}}` + "\n" +
		`{"type":"text","part":{"type":"text","text":"{\"findings\":"}}` + "\n" +
		`{"type":"text","part":{"type":"text","text":"[]}\n"}}` + "\n" +
		`{"type":"step_finish","part":{"type":"step-finish","tokens":{"input":1,"output":1,"reasoning":0,"cache":{"write":0,"read":0}},"cost":0.001}}` + "\n"
	f := &fake{stdout: map[string]string{"run": step("x", "0.001") + two + step("", "0.001")}}
	r, err := newAgent(t, "standard", nil).Run(context.Background(), task(f, t))
	if err != nil || r.Output != `{"findings":[]}` || r.Usage.Turns != 3 {
		t.Errorf("Run() = %+v, %v; want the output {\"findings\":[]}", r, err)
	}
}

// Backlog B-019: a session that failed after it spent tokens, with no dollar figure, is refused like
// one that succeeded, and the tokens it spent still count.
func TestAFailedSessionWithTokensAndNoCostIsRefused(t *testing.T) {
	stream := strings.Replace(fixture(t, "success.jsonl"), `"cost":0.00001005`, `"cost":0`, 1) + apiError(500, "upstream died")
	f := &fake{stdout: map[string]string{"run": stream}, exit: 1}
	_, err := newAgent(t, "standard", nil).Run(context.Background(), task(f, t))
	var se *gungnir.SessionError
	if !errors.As(err, &se) || !strings.Contains(err.Error(), "price") {
		t.Fatalf("Run() = %v, want a refusal that names the price", err)
	}
	if se.Usage.InTok != 7 || se.Usage.OutTok != 5 || se.Usage.CacheTok != 80 || se.Usage.Turns != 1 {
		t.Errorf("the refusal's usage = %+v; the tokens must still be counted", se.Usage)
	}
}

func TestASessionThatEndedWithoutAnyStepSaysHowItFailed(t *testing.T) {
	cases := map[string]struct {
		stdout, stderr string
		exit           int
		want           gungnir.FailureKind
	}{
		"a tool that crashed at start": {"", "bun: command not found", 127, gungnir.FailureTransient},
		"garbage and a bad exit":       {"panic: boom\n", "", 2, gungnir.FailureTransient},
		"a quota said on stderr":       {"", "insufficient credits", 1, gungnir.FailureQuota},
		"a clean exit and no events":   {"", "", 0, gungnir.FailureAgent},
		"a step with a number missing": {strings.Replace(fixture(t, "success.jsonl"), `"cache":{"write":0,"read":80}`, `"cache":{}`, 1), "", 0, gungnir.FailureAgent},
	}
	for name, c := range cases {
		f := &fake{stdout: map[string]string{"run": c.stdout}, stderr: c.stderr, exit: c.exit}
		_, err := newAgent(t, "standard", nil).Run(context.Background(), task(f, t))
		if err == nil || gungnir.FailureOf(err) != c.want {
			t.Errorf("%s: Run() = %v (kind %q), want an error of kind %q", name, err, gungnir.FailureOf(err), c.want)
		}
	}
}

func TestACommandThatCouldNotRunIsTheSandboxsFailure(t *testing.T) {
	f := &fake{err: errors.New("podman exec: no such container")}
	if _, err := newAgent(t, "standard", nil).Run(context.Background(), task(f, t)); gungnir.FailureOf(err) != gungnir.FailureInfra {
		t.Errorf("Run() = %v (kind %q), want an infra failure", err, gungnir.FailureOf(err))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f = &fake{err: ctx.Err()}
	if _, err := newAgent(t, "standard", nil).Run(ctx, task(f, t)); gungnir.FailureOf(err) != gungnir.FailureAgent {
		t.Errorf("a session the context ended: Run() = %v (kind %q), want an agent failure", err, gungnir.FailureOf(err))
	}
}

// Backlog B-020: a session the timeout killed still spent the steps that finished.
func TestATimedOutSessionStillCountsItsUsage(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cut := fixture(t, "success.jsonl") + `{"type":"step_start","part":{"type":"step-start"}}` + "\n" + `{"type":"text","part":{"type":"text","text":"half a th`
	f := &fake{stdout: map[string]string{"run": cut}, err: ctx.Err()}
	_, err := newAgent(t, "standard", nil).Run(ctx, task(f, t))
	var se *gungnir.SessionError
	if !errors.As(err, &se) || se.Kind != gungnir.FailureAgent {
		t.Fatalf("Run() = %v, want an agent failure", err)
	}
	want := gungnir.Usage{InTok: 7, OutTok: 5, CacheTok: 80, Turns: 1, CostUSD: 0.00001005, CostEstimated: true}
	if se.Usage != want {
		t.Errorf("usage = %+v, want %+v", se.Usage, want)
	}
}

// Backlog B-021: a chatty session is stopped by the bound, and the host never holds it all.
func TestSessionOutputIsBounded(t *testing.T) {
	old := maxStream
	maxStream = 300
	defer func() { maxStream = old }()
	f := &fake{stdout: map[string]string{"run": fixture(t, "success.jsonl") + strings.Repeat("noise\n", 200)}}
	tk := task(f, t)
	_, err := newAgent(t, "standard", nil).Run(context.Background(), tk)
	if err == nil || gungnir.FailureOf(err) != gungnir.FailureAgent || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("Run() = %v; want an agent failure that says the output was too long", err)
	}
	if fi, err := os.Stat(tk.TranscriptDir + "/review-1.jsonl"); err != nil || fi.Size() > 300 {
		t.Errorf("the transcript = %v, %v; want at most 300 bytes", fi, err)
	}
}
