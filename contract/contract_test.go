// Package contract_test holds the one suite every agent adapter passes: given the same session, each hands Odin the
// same result. Odin reads Status, Usage.Turns and Submitted; an adapter that differs in one of them would make
// a graph behave by the CLI behind a role.
package contract_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ouroboric-dev/gleipnir/claudecode"
	"github.com/ouroboric-dev/gleipnir/opencode"
	"github.com/ouroboric-dev/gleipnir/scripted"
	"github.com/ouroboric-dev/gungnir"
)

// review is the output of the recorded session, as the fixtures hold it.
const review = `{"findings":[{"id":"spec-1","source":"spec","severity":"blocker","location":"api/auth.go:42","claim":"The signup route has no throttle.","status":"open"}]}`

// notes is how the last text of each capped session ends, and capped is the summary of a session at its cap of 20.
const (
	notes  = "I read the handler and its tests; no finding yet."
	capped = "the session reached its turn cap (20 turns) without handing back its output"
)

// stream is a sandbox that answers the agent's command with a recorded stream.
type stream string

func (s stream) Run(_ context.Context, c gungnir.Cmd) (gungnir.ExecResult, error) {
	if len(c.Argv) > 1 && c.Argv[1] == "--version" {
		c.Stdout.Write([]byte("1.18.32\n"))
		return gungnir.ExecResult{}, nil
	}
	c.Stdout.Write([]byte(s))
	return gungnir.ExecResult{}, nil
}

func fixture(t *testing.T, dir, name string) stream {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", dir, "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return stream(b)
}

type adapter struct {
	name  string
	agent func(t *testing.T) gungnir.Agent
	// sandbox is the recorded session of the named fixture ("review": one review submitted; "refused": one refused call).
	sandbox func(t *testing.T, which string) gungnir.Runner
}

func adapters() []adapter {
	return []adapter{
		{"claude-code",
			func(*testing.T) gungnir.Agent {
				return &claudecode.Agent{Getenv: func(k string) string { return map[string]string{claudecode.TokenVar: "tok"}[k] }}
			},
			func(t *testing.T, which string) gungnir.Runner {
				return fixture(t, "claudecode", "stream-submit-"+which+".jsonl")
			}},
		{"opencode",
			func(t *testing.T) gungnir.Agent {
				a, err := opencode.New("openrouter/openai/gpt-4o-mini", opencode.Config{Price: &opencode.Price{Input: 1, Output: 1},
					Getenv: func(k string) string { return map[string]string{opencode.KeyVar: "key"}[k] }})
				if err != nil {
					t.Fatal(err)
				}
				return a
			},
			func(t *testing.T, which string) gungnir.Runner {
				return fixture(t, "opencode", "stream-submit-"+which+".jsonl")
			}},
		{"scripted",
			func(t *testing.T) gungnir.Agent {
				p := filepath.Join(t.TempDir(), "script.yaml")
				script := "submits: true\nsteps:\n  review:\n" +
					"    - result: { status: ok, usage: { turns: 2 }, submitted: '" + review + "' }\n" +
					"    - result: { status: ok, usage: { turns: 2 } }\n" +
					"    - result: { status: failed, failure: turn-limit, summary: '" + capped + "', output: '" + notes + "', usage: { turns: 20 } }\n" +
					"    - result: { status: ok, usage: { turns: 20 }, submitted: '" + review + "' }\n"
				if err := os.WriteFile(p, []byte(script), 0o644); err != nil {
					t.Fatal(err)
				}
				a, err := scripted.Load(p)
				if err != nil {
					t.Fatal(err)
				}
				return a
			},
			// The scripted adapter runs no command: attempt 1 submits the review, attempt 2 only a refused call,
			// attempt 3 reaches its cap without a valid submit, attempt 4 reaches it after one.
			func(*testing.T, string) gungnir.Runner { return nil }},
	}
}

func TestEveryAdapterPassesTheContractSuite(t *testing.T) {
	cases := []struct {
		which    string
		attempt  int
		maxTurns int
		want     string // the submitted document, "" for none
		status   gungnir.Status
		failure  gungnir.FailureKind
		summary  string // the summary of a failed session; an ok one's is the adapter's
		turns    int64
	}{
		{"review", 1, 0, review, gungnir.StatusOK, "", "", 2},
		{"refused", 2, 0, "", gungnir.StatusOK, "", "", 2},
		{"capped", 3, 20, "", gungnir.StatusFailed, gungnir.FailureTurnLimit, capped, 20},
		{"capped-valid", 4, 20, review, gungnir.StatusOK, "", "", 20},
	}
	type outcome struct {
		submitted string
		isNil     bool
		status    gungnir.Status
		failure   gungnir.FailureKind
		summary   string
		turns     int64
	}
	for _, c := range cases {
		var first *outcome
		var firstName string
		for _, a := range adapters() {
			t.Run(c.which+"/"+a.name, func(t *testing.T) {
				ag := a.agent(t)
				if s, ok := ag.(gungnir.Submitter); !ok || !s.Submits() {
					t.Fatalf("%s does not say it submits", a.name)
				}
				tk := gungnir.Task{Node: "review", Attempt: c.attempt, Prompt: "Review it.", Model: "openrouter/openai/gpt-4o-mini",
					Output: "ygg.review/v1", MaxTurns: c.maxTurns, Workdir: t.TempDir(), TranscriptDir: t.TempDir(), Sandbox: a.sandbox(t, c.which)}
				if a.name == "claude-code" {
					tk.Model = "sonnet"
				}
				r, err := ag.Run(context.Background(), tk)
				if err != nil {
					t.Fatal(err)
				}
				got := outcome{string(r.Submitted), r.Submitted == nil, r.Status, r.Failure, "", r.Usage.Turns}
				if r.Status == gungnir.StatusFailed {
					got.summary = r.Summary
				}
				want := outcome{c.want, c.want == "", c.status, c.failure, c.summary, c.turns}
				if got != want {
					t.Errorf("%s: %+v; want %+v", a.name, got, want)
				}
				// A capped session's last text is its notes, for the session that asks once more.
				if c.failure == gungnir.FailureTurnLimit && !strings.HasSuffix(r.Output, notes) {
					t.Errorf("%s: Output = %q, want the session's last text, ending %q", a.name, r.Output, notes)
				}
				if first == nil {
					first, firstName = &got, a.name
				} else if *first != got {
					t.Errorf("%s gives %+v, %s gives %+v", a.name, got, firstName, *first)
				}
			})
		}
	}
}
