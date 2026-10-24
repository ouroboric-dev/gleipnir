package submit

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/ouroboric-dev/gungnir"
)

const contract = "ygg.review/v1"

func TestOnlyAnExactAcceptanceCounts(t *testing.T) {
	tr := NewTracker(contract)
	tr.Call("a", json.RawMessage(`{"output":{"n":1}}`))
	tr.Result("a", "ygg.review/v1: the document breaks its contract.\n/findings: is required", true)
	tr.Call("b", json.RawMessage(`{"output":{"n":2}}`))
	tr.Result("b", "accepted: the document is a valid ygg.plan/v1", false) // another contract's acceptance
	tr.Call("c", json.RawMessage(`{"output":{"n":3}}`))
	tr.Result("c", "accepted: the document is a valid ygg.review/v1", true) // isError wins
	if got := tr.Last(); got != nil {
		t.Fatalf("Last() = %s, want none", got)
	}
	tr.Call("d", json.RawMessage(`{"output":{"n":4}}`))
	tr.Result("d", "accepted: the document is a valid ygg.review/v1\n", false)
	tr.Result("unknown", "accepted: the document is a valid ygg.review/v1", false) // a result with no call
	if got := string(tr.Last()); got != `{"output":{"n":4}}` {
		t.Errorf("Last() = %s", got)
	}
}

type reader struct {
	out  string
	exit int
	got  []gungnir.Cmd
}

func (r *reader) Run(_ context.Context, c gungnir.Cmd) (gungnir.ExecResult, error) {
	r.got = append(r.got, c)
	io.WriteString(c.Stdout, r.out)
	return gungnir.ExecResult{ExitCode: r.exit}, nil
}

func TestADocumentIsTheOutputWholeOrTheDraftFile(t *testing.T) {
	doc, err := Document(context.Background(), nil, json.RawMessage(`{"output":{"a": [1, 2]}}`))
	if err != nil || string(doc) != `{"a": [1, 2]}` {
		t.Errorf("inline: %q, %v", doc, err)
	}
	r := &reader{out: `{"tasks":[]}`}
	doc, err = Document(context.Background(), r, json.RawMessage(`{"file":"./out//plan.json"}`))
	if err != nil || string(doc) != `{"tasks":[]}` {
		t.Fatalf("file: %q, %v", doc, err)
	}
	if len(r.got) != 1 || strings.Join(r.got[0].Argv, " ") != "head -c 4194305 -- out/plan.json" || r.got[0].Dir != "" {
		t.Errorf("the read = %+v", r.got)
	}
}

func TestADraftPathFollowsTheServersRules(t *testing.T) {
	for _, file := range []string{"", "/out/a.json", "../out/a.json", "out/../a.json", "out/a/../../b", "a.json", "out", "out/", "outer/a.json", "out/a\x00.json", "-c/out/a"} {
		r := &reader{out: "{}"}
		if _, err := Document(context.Background(), r, mustJSON(map[string]string{"file": file})); err == nil || len(r.got) != 0 {
			t.Errorf("file %q: err %v, ran %v; want a refusal that runs nothing", file, err, r.got)
		}
	}
}

func TestADraftThatCannotBeReadIsAnErrorWithItsReason(t *testing.T) {
	big := &reader{out: strings.Repeat("x", MaxFile+1)}
	if _, err := Document(context.Background(), big, json.RawMessage(`{"file":"out/a.json"}`)); err == nil || !strings.Contains(err.Error(), "over the limit") {
		t.Errorf("over 4 MiB: %v", err)
	}
	gone := &reader{exit: 1}
	if _, err := Document(context.Background(), gone, json.RawMessage(`{"file":"out/a.json"}`)); err == nil || !strings.Contains(err.Error(), "out/a.json") {
		t.Errorf("exit 1: %v", err)
	}
	if _, err := Document(context.Background(), &reader{}, json.RawMessage(`{"file":"out/a.json"}`)); err == nil {
		t.Error("an empty file is no document")
	}
	if _, err := Document(context.Background(), &reader{out: "{}"}, json.RawMessage(`{"file":"out/a.json","output":{}}`)); err == nil {
		t.Error("both forms")
	}
	if _, err := Document(context.Background(), nil, json.RawMessage(`{"output":[1]}`)); err == nil {
		t.Error("an output that is not an object")
	}
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
