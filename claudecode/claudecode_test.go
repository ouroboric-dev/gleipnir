package claudecode

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ouroboric-dev/gungnir"
)

const initLine = `{"type":"system","subtype":"init","session_id":"s1","claude_code_version":"2.1.284","model":"claude-sonnet-5-5","apiKeySource":"none","tools":["Read"]}`
const assistantLine = `{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"working"}],"usage":{"input_tokens":4}},"session_id":"s1"}`

// The numbers are the ones sandbox spike B recorded for a real session: 4 input tokens, 3,134
// cache-creation, 26,776 cache-read, 97 output, two turns, 0.0189 dollars.
const okResult = `{"type":"result","subtype":"success","is_error":false,"duration_ms":2523,"duration_api_ms":2100,"num_turns":2,"result":"wrote design.md","session_id":"s1","total_cost_usd":0.0189,"usage":{"input_tokens":4,"cache_creation_input_tokens":3134,"cache_read_input_tokens":26776,"output_tokens":97},"modelUsage":{"claude-sonnet-5-5":{"costUSD":0.0189}},"permission_denials":[]}`

type fake struct {
	stdout string
	stderr string
	exit   int
	err    error
	got    gungnir.Cmd
	stdin  string
}

func (f *fake) Run(_ context.Context, c gungnir.Cmd) (gungnir.ExecResult, error) {
	f.got = c
	if c.Stdin != nil {
		b := new(strings.Builder)
		buf := make([]byte, 4096)
		for {
			n, err := c.Stdin.Read(buf)
			b.Write(buf[:n])
			if err != nil {
				break
			}
		}
		f.stdin = b.String()
	}
	c.Stdout.Write([]byte(f.stdout))
	if c.Stderr != nil {
		c.Stderr.Write([]byte(f.stderr))
	}
	return gungnir.ExecResult{ExitCode: f.exit}, f.err
}

func agent() *Agent {
	return &Agent{Getenv: func(k string) string {
		return map[string]string{TokenVar: "tok-secret", "LANG": "C.UTF-8"}[k]
	}}
}

func task(f *fake) gungnir.Task {
	return gungnir.Task{Role: "implementer", Node: "build", Attempt: 1, Prompt: "Build it.", Model: "sonnet", MaxTurns: 20,
		Sandbox: f, TranscriptDir: filepath.Join(os.TempDir(), "claudecode-test-"+filepath.Base(os.TempDir()))}
}

func TestARunReportsUsageFromTheResultEvent(t *testing.T) {
	f := &fake{stdout: strings.Join([]string{initLine, assistantLine, okResult}, "\n") + "\n"}
	tk := task(f)
	tk.TranscriptDir = t.TempDir()
	r, err := agent().Run(context.Background(), tk)
	if err != nil {
		t.Fatal(err)
	}
	want := gungnir.Usage{InTok: 4 + 3134, OutTok: 97, CacheTok: 26776, Turns: 2, CostUSD: 0.0189}
	if r.Status != gungnir.StatusOK || r.Usage != want || r.Summary != "wrote design.md" || r.CLIVersion != "2.1.284" || r.Provider != "anthropic" {
		t.Errorf("Result = %+v\nwant usage %+v", r, want)
	}
	if b, err := os.ReadFile(r.TranscriptPath); err != nil || !strings.Contains(string(b), `"type":"result"`) {
		t.Errorf("the transcript = %q, %v; want the raw stream", b, err)
	}
	if f.stdin != "Build it." {
		t.Errorf("the prompt on stdin = %q", f.stdin)
	}
}

func TestACommandLineKeepsToThePinnedAuthAndFlags(t *testing.T) {
	f := &fake{stdout: okResult + "\n"}
	tk := task(f)
	tk.TranscriptDir = t.TempDir()
	if _, err := agent().Run(context.Background(), tk); err != nil {
		t.Fatal(err)
	}
	argv := strings.Join(f.got.Argv, " ")
	for _, want := range []string{"claude -p", "--output-format stream-json", "--setting-sources user", "--strict-mcp-config", "--model sonnet", "--max-turns 20", "--permission-mode acceptEdits"} {
		if !strings.Contains(argv, want) {
			t.Errorf("argv %q lacks %q", argv, want)
		}
	}
	if strings.Contains(argv, "--bare") || strings.Contains(argv, "tok-secret") || strings.Contains(argv, "Build it.") {
		t.Errorf("argv %q holds --bare, the token or the prompt", argv)
	}
	if f.got.Env[TokenVar] != "tok-secret" || len(f.got.Env) != 1 {
		t.Errorf("env = %v; want only the OAuth token", f.got.Env)
	}
}

func TestAReadOnlyRoleGetsReadAndSearchToolsOnly(t *testing.T) {
	f := &fake{stdout: okResult + "\n"}
	tk := task(f)
	tk.TranscriptDir, tk.ReadOnly = t.TempDir(), true
	if _, err := agent().Run(context.Background(), tk); err != nil {
		t.Fatal(err)
	}
	argv := strings.Join(f.got.Argv, " ")
	if !strings.Contains(argv, "--tools Read,Grep,Glob") || strings.Contains(argv, "Bash") || strings.Contains(argv, "Write") || strings.Contains(argv, "Edit") {
		t.Errorf("a read-only role's argv = %q", argv)
	}
}

func TestAFailedSessionIsAFailedResultWithItsUsage(t *testing.T) {
	failed := `{"type":"result","subtype":"error_max_turns","is_error":false,"num_turns":20,"total_cost_usd":0.5,"usage":{"input_tokens":10,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":5}}`
	authFail := `{"type":"result","subtype":"success","is_error":true,"api_error_status":401,"result":"Invalid bearer token","num_turns":1,"total_cost_usd":0,"usage":{"input_tokens":0,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":0}}`
	for name, c := range map[string]struct{ line, summary string }{"max turns": {failed, "error_max_turns"}, "a rejected token": {authFail, "Invalid bearer token (API status 401)"}} {
		f := &fake{stdout: c.line + "\n", exit: 1}
		tk := task(f)
		tk.TranscriptDir = t.TempDir()
		r, err := agent().Run(context.Background(), tk)
		if err != nil || r.Status != gungnir.StatusFailed || r.Summary != c.summary {
			t.Errorf("%s: %+v, %v; want a failed result saying %q", name, r, err, c.summary)
		}
	}
}

func TestMissingDataIsNeverReadAsZero(t *testing.T) {
	for name, stdout := range map[string]string{
		"no result event":   initLine + "\n" + assistantLine + "\n",
		"no usage":          `{"type":"result","subtype":"success","is_error":false,"num_turns":1,"total_cost_usd":0.1}` + "\n",
		"no cost":           `{"type":"result","subtype":"success","is_error":false,"num_turns":1,"usage":{"input_tokens":1,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":1}}` + "\n",
		"no is_error":       `{"type":"result","subtype":"success","num_turns":1,"total_cost_usd":0,"usage":{"input_tokens":1,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":1}}` + "\n",
		"garbage":           "Segmentation fault\n",
		"a negative number": `{"type":"result","subtype":"success","is_error":false,"num_turns":-1,"total_cost_usd":0,"usage":{"input_tokens":1,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":1}}` + "\n",
	} {
		f := &fake{stdout: stdout, exit: 2}
		tk := task(f)
		tk.TranscriptDir = t.TempDir()
		if _, err := agent().Run(context.Background(), tk); err == nil {
			t.Errorf("%s: Run() = nil, want an error", name)
		}
	}
}

func TestTheAdapterNeverRunsOnTheHostOrWithAPerTokenKey(t *testing.T) {
	tk := gungnir.Task{Node: "build", Attempt: 1, Prompt: "x"}
	if _, err := agent().Run(context.Background(), tk); !errors.Is(err, gungnir.ErrNoSandbox) {
		t.Errorf("a task without a sandbox: %v, want ErrNoSandbox", err)
	}
	f := &fake{stdout: okResult + "\n"}
	tk = task(f)
	tk.TranscriptDir, tk.EnvAllowlist = t.TempDir(), []string{"ANTHROPIC_API_KEY"}
	a := &Agent{Getenv: func(k string) string { return "x" }}
	if _, err := a.Run(context.Background(), tk); err == nil || !strings.Contains(err.Error(), "ANTHROPIC_API_KEY") || f.got.Argv != nil {
		t.Errorf("an allowlist with ANTHROPIC_API_KEY: %v; ran: %v", err, f.got.Argv)
	}
	noTok := &Agent{Getenv: func(string) string { return "" }}
	tk.EnvAllowlist = nil
	if _, err := noTok.Run(context.Background(), tk); err == nil || !strings.Contains(err.Error(), TokenVar) {
		t.Errorf("no token: %v", err)
	}
}

func resultLine(subtype string, isError bool, status, text string) string {
	st := "null"
	if status != "" {
		st = status
	}
	return fmt.Sprintf(`{"type":"result","subtype":%q,"is_error":%v,"api_error_status":%s,"result":%q,"num_turns":1,"total_cost_usd":0,"usage":{"input_tokens":0,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":0}}`,
		subtype, isError, st, text) + "\n"
}

func TestARunKeepsTheWholeFinalAnswerAndClipsOnlyTheSummary(t *testing.T) {
	answer := `{"findings":[` + strings.Repeat(`{"id":"a"},`, 300) + `]}`
	f := &fake{stdout: initLine + "\n" + resultLine("success", false, "", "  "+answer+"\n")}
	tk := task(f)
	tk.TranscriptDir = t.TempDir()
	r, err := agent().Run(context.Background(), tk)
	if err != nil || r.Output != answer || len(r.Summary) >= len(answer) || !strings.HasSuffix(r.Summary, "…") {
		t.Errorf("Run() = %d-byte output, %d-byte summary, %v; want the whole answer and a clipped summary", len(r.Output), len(r.Summary), err)
	}
}

func TestAnAnswerOverTheLimitIsAnAgentFailure(t *testing.T) {
	f := &fake{stdout: initLine + "\n" + resultLine("success", false, "", strings.Repeat("x", gungnir.MaxOutput+1))}
	tk := task(f)
	tk.TranscriptDir = t.TempDir()
	_, err := agent().Run(context.Background(), tk)
	if err == nil || gungnir.FailureOf(err) != gungnir.FailureAgent {
		t.Errorf("Run() = %v, want an agent failure", err)
	}
}

func TestAFailedSessionSaysHowItFailed(t *testing.T) {
	cases := map[string]struct {
		line string
		want gungnir.FailureKind
	}{
		"a rate limit":              {resultLine("success", true, "429", "API Error: Rate limit exceeded"), gungnir.FailureTransient},
		"an overloaded API":         {resultLine("success", true, "529", "Overloaded"), gungnir.FailureTransient},
		"a server error":            {resultLine("success", true, "500", "Internal server error"), gungnir.FailureTransient},
		"a plan's usage limit":      {resultLine("success", true, "429", "Claude usage limit reached. Your limit will reset at 3pm."), gungnir.FailureQuota},
		"a limit with no status":    {resultLine("success", true, "", "5-hour limit reached ∙ resets 3pm"), gungnir.FailureQuota},
		"a rejected token":          {resultLine("success", true, "401", "Invalid bearer token"), gungnir.FailureAgent},
		"the turn limit":            {resultLine("error_max_turns", false, "", ""), gungnir.FailureAgent},
		"a crash inside the run":    {resultLine("error_during_execution", true, "", "tool failed"), gungnir.FailureAgent},
		"the turn limit that talks": {resultLine("error_max_turns", true, "429", "usage limit reached in the test I ran"), gungnir.FailureAgent},
	}
	for name, c := range cases {
		f := &fake{stdout: initLine + "\n" + c.line, exit: 1}
		tk := task(f)
		tk.TranscriptDir = t.TempDir()
		r, err := agent().Run(context.Background(), tk)
		if err != nil || r.Status != gungnir.StatusFailed || r.Failure != c.want {
			t.Errorf("%s: %+v, %v; want a failed result of kind %q", name, r, err, c.want)
		}
	}
}

func TestASessionThatEndedWithoutAResultSaysHowItFailed(t *testing.T) {
	cases := map[string]struct {
		stdout, stderr string
		exit           int
		want           gungnir.FailureKind
	}{
		"a tool that crashed at start":    {"", "node: command not found", 127, gungnir.FailureTransient},
		"garbage and a non-zero exit":     {"Segmentation fault\n", "", 139, gungnir.FailureTransient},
		"a quota said on stderr":          {"", "Claude usage limit reached", 1, gungnir.FailureQuota},
		"a session that died after start": {initLine + "\n" + assistantLine + "\n", "", 137, gungnir.FailureAgent},
		"a clean exit with no events":     {"", "", 0, gungnir.FailureAgent},
		"a result with a number missing":  {initLine + "\n" + `{"type":"result","subtype":"success","is_error":false,"num_turns":1,"total_cost_usd":0.1}` + "\n", "", 0, gungnir.FailureAgent},
	}
	for name, c := range cases {
		f := &fake{stdout: c.stdout, exit: c.exit}
		f.stderr = c.stderr
		tk := task(f)
		tk.TranscriptDir = t.TempDir()
		_, err := agent().Run(context.Background(), tk)
		if err == nil || gungnir.FailureOf(err) != c.want {
			t.Errorf("%s: Run() = %v (kind %q), want an error of kind %q", name, err, gungnir.FailureOf(err), c.want)
		}
	}
}

func TestACommandThatCouldNotRunIsTheSandboxsFailure(t *testing.T) {
	f := &fake{err: errors.New("podman exec: no such container")}
	tk := task(f)
	tk.TranscriptDir = t.TempDir()
	if _, err := agent().Run(context.Background(), tk); gungnir.FailureOf(err) != gungnir.FailureInfra {
		t.Errorf("Run() = %v (kind %q), want an infra failure", err, gungnir.FailureOf(err))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f = &fake{err: ctx.Err()}
	tk = task(f)
	tk.TranscriptDir = t.TempDir()
	if _, err := agent().Run(ctx, tk); gungnir.FailureOf(err) != gungnir.FailureAgent {
		t.Errorf("a session the context ended: Run() = %v (kind %q), want an agent failure", err, gungnir.FailureOf(err))
	}
}

func assistant(id string, in, out, cacheNew, cacheRead int) string {
	idField := ""
	if id != "" {
		idField = fmt.Sprintf(`"id":%q,`, id)
	}
	return fmt.Sprintf(`{"type":"assistant","message":{%s"role":"assistant","content":[{"type":"text","text":"x"}],"usage":{"input_tokens":%d,"output_tokens":%d,"cache_creation_input_tokens":%d,"cache_read_input_tokens":%d}}}`,
		idField, in, out, cacheNew, cacheRead) + "\n"
}

// Backlog B-020: a session the timeout killed still spent what its messages reported, and the caps
// must count it.
func TestATimedOutSessionStillCountsItsUsage(t *testing.T) {
	stream := initLine + "\n" +
		assistant("m1", 3, 10, 100, 1000) + assistant("m1", 3, 40, 100, 1000) + // one message, repeated per content block
		assistant("m2", 5, 20, 0, 2000) + assistant("", 1, 1, 0, 0)
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()
	f := &fake{stdout: stream, err: ctx.Err()}
	tk := task(f)
	tk.TranscriptDir = t.TempDir()
	_, err := agent().Run(ctx, tk)
	var se *gungnir.SessionError
	if !errors.As(err, &se) || se.Kind != gungnir.FailureAgent {
		t.Fatalf("Run() = %v, want an agent failure", err)
	}
	want := gungnir.Usage{InTok: (3 + 100) + 5 + 1, OutTok: 40 + 20 + 1, CacheTok: 3000, Turns: 3, CostEstimated: true}
	if se.Usage != want {
		t.Errorf("usage = %+v, want %+v", se.Usage, want)
	}
}

func TestASessionWithoutAResultCountsWhatItReported(t *testing.T) {
	f := &fake{stdout: initLine + "\n" + assistant("m1", 7, 9, 0, 11) + "not json at all\n", exit: 137}
	tk := task(f)
	tk.TranscriptDir = t.TempDir()
	_, err := agent().Run(context.Background(), tk)
	var se *gungnir.SessionError
	if !errors.As(err, &se) || se.Usage.InTok != 7 || se.Usage.OutTok != 9 || se.Usage.CacheTok != 11 || se.Usage.Turns != 1 {
		t.Errorf("Run() = %v, usage %+v", err, se)
	}
	f = &fake{stdout: "", exit: 1}
	tk = task(f)
	tk.TranscriptDir = t.TempDir()
	_, err = agent().Run(context.Background(), tk)
	if !errors.As(err, &se) || se.Usage != (gungnir.Usage{}) {
		t.Errorf("a session that printed nothing: usage %+v, want none", se.Usage)
	}
}

// Backlog B-021: a chatty session is stopped by the bound, and the host never holds it all.
func TestSessionOutputIsBounded(t *testing.T) {
	old := maxStream
	maxStream = 200
	defer func() { maxStream = old }()
	f := &fake{stdout: initLine + "\n" + assistant("m1", 1, 2, 0, 0) + strings.Repeat("noise\n", 100) + okResult + "\n"}
	tk := task(f)
	tk.TranscriptDir = t.TempDir()
	r, err := agent().Run(context.Background(), tk)
	if err == nil || gungnir.FailureOf(err) != gungnir.FailureAgent || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("Run() = %+v, %v; want an agent failure that says the output was too long", r, err)
	}
	if fi, err := os.Stat(filepath.Join(tk.TranscriptDir, "build-1.jsonl")); err != nil || fi.Size() > 200 {
		t.Errorf("the transcript = %v, %v; want at most 200 bytes", fi, err)
	}
}
