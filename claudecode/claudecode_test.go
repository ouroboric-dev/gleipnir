package claudecode

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ouroboric-dev/gungnir"
)

const initLine = `{"type":"system","subtype":"init","session_id":"s1","claude_code_version":"2.1.284","model":"claude-sonnet-5-5","apiKeySource":"none","tools":["Read"]}`
const assistantLine = `{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"working"}],"usage":{"input_tokens":4}},"session_id":"s1"}`

// The numbers are the ones sandbox spike B recorded for a real session: 4 input tokens, 3,134
// cache-creation, 26,776 cache-read, 97 output, two turns, 0.0189 dollars.
const okResult = `{"type":"result","subtype":"success","is_error":false,"duration_ms":2523,"duration_api_ms":2100,"num_turns":2,"result":"wrote design.md","session_id":"s1","total_cost_usd":0.0189,"usage":{"input_tokens":4,"cache_creation_input_tokens":3134,"cache_read_input_tokens":26776,"output_tokens":97},"modelUsage":{"claude-sonnet-5-5":{"costUSD":0.0189}},"permission_denials":[]}`

type fake struct {
	stdout string
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
