package submit

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

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
	if len(r.got) != 1 || !isGuardedRead(r.got[0].Argv, "out/plan.json") || r.got[0].Dir != "" {
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

// isGuardedRead tells the guarded read of p: a shell script that gets the path as $1, never in the script text.
func isGuardedRead(argv []string, p string) bool {
	return len(argv) == 5 && argv[0] == "sh" && argv[1] == "-c" && strings.Contains(argv[2], "realpath") &&
		strings.Contains(argv[2], "test -f") && strings.Contains(argv[2], "head -c 4194305") && !strings.Contains(argv[2], p) &&
		argv[3] == "sh" && argv[4] == p
}

// local runs the command on this machine, in dir: the guard is a shell script, so its test runs it.
type local struct{ dir string }

func (l local) Run(ctx context.Context, c gungnir.Cmd) (gungnir.ExecResult, error) {
	cmd := exec.CommandContext(ctx, c.Argv[0], c.Argv[1:]...)
	cmd.Dir, cmd.Stdout = l.dir, c.Stdout
	err := cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok {
		return gungnir.ExecResult{ExitCode: ee.ExitCode()}, nil
	}
	return gungnir.ExecResult{}, err
}

func TestTheDraftReadRefusesSymlinksAndFIFOsAndReadsAFile(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.json")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.Mkdir(filepath.Join(root, "out"), 0o755))
	must(os.WriteFile(outside, []byte(`{"secret":true}`), 0o644))
	must(os.WriteFile(filepath.Join(root, "out", "ok.json"), []byte(`{"ok":true}`), 0o644))
	must(os.Symlink(outside, filepath.Join(root, "out", "link.json")))
	must(os.Symlink(filepath.Join(root, "out", "ok.json"), filepath.Join(root, "out", "inside.json")))
	must(syscall.Mkfifo(filepath.Join(root, "out", "pipe.json"), 0o644))
	must(os.Mkdir(filepath.Join(root, "out", "sub"), 0o755))
	must(os.Symlink(t.TempDir(), filepath.Join(root, "out", "dir")))
	r := local{dir: root}
	read := func(name string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return Document(ctx, r, mustJSON(map[string]string{"file": name}))
	}
	if doc, err := read("out/ok.json"); err != nil || !bytes.Equal(doc, []byte(`{"ok":true}`)) {
		t.Errorf("a plain file: %q, %v", doc, err)
	}
	if doc, err := read("out/inside.json"); err != nil || !bytes.Equal(doc, []byte(`{"ok":true}`)) {
		t.Errorf("a symlink that stays under out/: %q, %v", doc, err)
	}
	for _, name := range []string{"out/link.json", "out/pipe.json", "out/sub", "out/missing.json"} {
		if doc, err := read(name); err == nil {
			t.Errorf("%s was read: %q", name, doc)
		}
	}
	if doc, err := read("out/dir/x.json"); err == nil {
		t.Errorf("a path through a symlinked folder was read: %q", doc)
	}
}
