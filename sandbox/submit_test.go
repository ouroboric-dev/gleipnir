package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ouroboric-dev/gungnir"
	"github.com/ouroboric-dev/gungnir/schema"
)

// The tests of ygg-submit run the real script under node, in the layout of the work image: bin/ygg-submit,
// lib/ygg-submit/node_modules (ajv, installed from the lock file in assets/submit) and schemas/.
var (
	submitOnce sync.Once
	submitRoot string
	submitErr  error
)

// submitLayout builds the image's /opt/ygg once per test run and returns its root.
func submitLayout(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("node"); err != nil {
		t.Fatal("node is needed for the sandbox tools' tests")
	}
	submitOnce.Do(func() {
		submitRoot, submitErr = buildSubmitLayout()
	})
	if submitErr != nil {
		t.Fatal(submitErr)
	}
	return submitRoot
}

func buildSubmitLayout() (string, error) {
	root, err := os.MkdirTemp("", "ygg-submit-")
	if err != nil {
		return "", err
	}
	lib := filepath.Join(root, "lib", "ygg-submit")
	for _, d := range []string{filepath.Join(root, "bin"), lib, filepath.Join(root, "schemas")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return "", err
		}
	}
	if err := os.WriteFile(filepath.Join(root, "bin", "ygg-submit.mjs"), []byte(submitScript), 0o755); err != nil {
		return "", err
	}
	if err := os.Symlink("ygg-submit.mjs", filepath.Join(root, "bin", "ygg-submit")); err != nil {
		return "", err
	}
	if err := writeSchemas(filepath.Join(root, "schemas")); err != nil {
		return "", err
	}
	// The image's own lock file, so the test and the image install the same tree.
	for f, body := range map[string]string{"package.json": submitPackage, "package-lock.json": submitLock} {
		if err := os.WriteFile(filepath.Join(lib, f), []byte(body), 0o644); err != nil {
			return "", err
		}
	}
	cmd := exec.Command("npm", "ci", "--prefix", lib, "--no-audit", "--no-fund")
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", &installError{err, string(out)}
	}
	return root, nil
}

type installError struct {
	err error
	out string
}

func (e *installError) Error() string {
	return "npm ci of the test's ajv failed: " + e.err.Error() + "\n" + e.out
}

func TestMain(m *testing.M) {
	code := m.Run()
	if submitRoot != "" {
		os.RemoveAll(submitRoot)
	}
	os.Exit(code)
}

// rpc is one JSON-RPC answer.
type rpc struct {
	ID     any             `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// toolResult is the result of a tools/call.
type toolResult struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	IsError bool `json:"isError"`
}

func (r toolResult) text() string {
	var b strings.Builder
	for _, c := range r.Content {
		b.WriteString(c.Text)
	}
	return b.String()
}

// serve starts ygg-submit in dir for the contract, sends the requests as lines, closes its input and returns
// the answers by id.
func serve(t *testing.T, dir, contract string, requests ...map[string]any) map[int]rpc {
	t.Helper()
	return serveAt(t, submitLayout(t), dir, contract, requests...)
}

// serveAt is serve with the image layout at root.
func serveAt(t *testing.T, root, dir, contract string, requests ...map[string]any) map[int]rpc {
	t.Helper()
	var in bytes.Buffer
	for _, r := range requests {
		r["jsonrpc"] = "2.0"
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		in.Write(b)
		in.WriteByte('\n')
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second) // a server that hangs fails the test
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(root, "bin", "ygg-submit"))
	cmd.WaitDelay = 2 * time.Second
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "YGG_OUTPUT_CONTRACT="+contract)
	cmd.Stdin = &in
	cmd.WaitDelay = 2 * time.Second
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("ygg-submit: %v\n%s", err, stderr.String())
	}
	got := map[int]rpc{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(nil, 16<<20)
	for sc.Scan() {
		var r rpc
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("ygg-submit wrote a line that is not JSON: %q", sc.Text())
		}
		id, ok := r.ID.(float64)
		if !ok {
			t.Fatalf("an answer with no numeric id: %s", sc.Text())
		}
		got[int(id)] = r
	}
	return got
}

func call(id int, tool string, args map[string]any) map[string]any {
	return map[string]any{"id": id, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": args}}
}

// verdict submits doc inline and returns the tool's result.
func verdict(t *testing.T, dir, contract string, doc []byte) toolResult {
	t.Helper()
	var output any
	if err := json.Unmarshal(doc, &output); err != nil {
		t.Fatal(err)
	}
	got := serve(t, dir, contract, call(1, "submit", map[string]any{"output": output}))
	return toolOf(t, got[1])
}

func toolOf(t *testing.T, r rpc) toolResult {
	t.Helper()
	if r.Error != nil {
		t.Fatalf("a protocol error: %+v", r.Error)
	}
	var tr toolResult
	if err := json.Unmarshal(r.Result, &tr); err != nil {
		t.Fatal(err)
	}
	return tr
}

func TestSubmitAnswersTheProtocol(t *testing.T) {
	got := serve(t, t.TempDir(), string(schema.ContractReview),
		map[string]any{"id": 1, "method": "initialize", "params": map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "t", "version": "1"}}},
		map[string]any{"method": "notifications/initialized"},
		map[string]any{"id": 2, "method": "tools/list"},
		map[string]any{"id": 3, "method": "ping"},
		map[string]any{"id": 4, "method": "resources/list"},
		call(5, "nothing", map[string]any{}),
	)
	if len(got) != 5 {
		t.Fatalf("want 5 answers (the notification gets none), got %d: %+v", len(got), got)
	}
	var init struct {
		ProtocolVersion string         `json:"protocolVersion"`
		Capabilities    map[string]any `json:"capabilities"`
		ServerInfo      struct{ Name string }
	}
	if err := json.Unmarshal(got[1].Result, &init); err != nil || init.ProtocolVersion != "2025-06-18" || init.ServerInfo.Name != "ygg" || init.Capabilities["tools"] == nil {
		t.Errorf("initialize = %s, %v", got[1].Result, err)
	}
	var list struct {
		Tools []struct {
			Name        string         `json:"name"`
			InputSchema map[string]any `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(got[2].Result, &list); err != nil || len(list.Tools) != 2 {
		t.Fatalf("tools/list = %s, %v", got[2].Result, err)
	}
	byName := map[string]map[string]any{}
	for _, tool := range list.Tools {
		byName[tool.Name] = tool.InputSchema
	}
	if byName["submit"] == nil || byName["check"] == nil {
		t.Fatalf("the tools are %v; want submit and check", byName)
	}
	// The Anthropic API refuses a tool whose input schema has a oneOf, anyOf or allOf at its root (R21).
	for name, sch := range byName {
		for _, k := range []string{"oneOf", "anyOf", "allOf", "not", "enum"} {
			if _, ok := sch[k]; ok {
				t.Errorf("%s's input schema has %s at its root", name, k)
			}
		}
		if sch["type"] != "object" || sch["additionalProperties"] != false {
			t.Errorf("%s's input schema = %v; want a closed object", name, sch)
		}
	}
	if props, _ := byName["submit"]["properties"].(map[string]any); props["output"] == nil || props["file"] == nil || byName["submit"]["required"] != nil {
		t.Errorf("submit's input schema = %v; want optional output and file", byName["submit"])
	}
	if props, _ := byName["check"]["properties"].(map[string]any); props["file"] == nil || byName["check"]["required"] == nil {
		t.Errorf("check's input schema = %v; want a required file", byName["check"])
	}
	if got[3].Error != nil || string(got[3].Result) != "{}" {
		t.Errorf("ping = %+v", got[3])
	}
	if got[4].Error == nil || got[4].Error.Code != -32601 {
		t.Errorf("an unknown method answered %+v; want -32601", got[4])
	}
	if got[5].Error == nil || got[5].Error.Code != -32602 {
		t.Errorf("an unknown tool answered %+v; want -32602", got[5])
	}
}

const goodReview = `{"findings":[{"id":"a-1","source":"spec","severity":"major","location":"api/auth.go:42","claim":"No throttle.","status":"open"}]}`

func TestSubmitValidatesAgainstTheContract(t *testing.T) {
	dir := t.TempDir()
	if r := verdict(t, dir, "ygg.review/v1", []byte(goodReview)); r.IsError || !strings.Contains(r.text(), "accepted") {
		t.Errorf("a valid review answered %+v", r)
	}
	bad := strings.Replace(goodReview, `"location":"api/auth.go:42",`, "", 1)
	r := verdict(t, dir, "ygg.review/v1", []byte(bad))
	if !r.IsError || !strings.Contains(r.text(), "/findings/0") || !strings.Contains(r.text(), "location") {
		t.Errorf("a finding with no location answered %+v; want an error at /findings/0 naming location", r)
	}
	bad = strings.Replace(goodReview, "api/auth.go:42", "nowhere", 1)
	if r := verdict(t, dir, "ygg.review/v1", []byte(bad)); !r.IsError || !strings.Contains(r.text(), "/findings/0/location") {
		t.Errorf("a malformed location answered %+v; want an error at /findings/0/location", r)
	}
	// The rules the schema cannot say.
	dup := strings.Replace(goodReview, "]}", `,{"id":"a-1","source":"spec","severity":"minor","location":"x.go:1","claim":"c","status":"open"}]}`, 1)
	if r := verdict(t, dir, "ygg.review/v1", []byte(dup)); !r.IsError || !strings.Contains(r.text(), "/findings/1") || !strings.Contains(r.text(), "used twice") {
		t.Errorf("a repeated finding id answered %+v; want an error at /findings/1 saying used twice", r)
	}
	// check validates a draft in out/ and writes nothing; no contract is an error, not a pass.
	if err := os.MkdirAll(filepath.Join(dir, "out"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "out", "r.json"), []byte(goodReview), 0o644); err != nil {
		t.Fatal(err)
	}
	got := serve(t, dir, "ygg.review/v1", call(1, "check", map[string]any{"file": "out/r.json"}), call(2, "submit", map[string]any{"file": "out/r.json"}))
	for id := 1; id <= 2; id++ {
		if r := toolOf(t, got[id]); r.IsError || !strings.Contains(r.text(), "accepted") {
			t.Errorf("call %d on a valid draft answered %+v", id, r)
		}
	}
	if r := verdict(t, dir, "ygg.nothing/v1", []byte(goodReview)); !r.IsError {
		t.Errorf("an unknown contract answered %+v; want an error", r)
	}
}

// A model may pass output as a JSON string that holds the object (the probe's finding, typed-boundaries R38): the
// server takes it as that object, and refuses a string that holds anything else, saying what it held.
func TestSubmitTakesAnOutputGivenAsAJSONString(t *testing.T) {
	dir := t.TempDir()
	submit := func(s string) toolResult {
		return toolOf(t, serve(t, dir, "ygg.review/v1", call(1, "submit", map[string]any{"output": s}))[1])
	}
	if r := submit(goodReview); r.IsError || !strings.Contains(r.text(), "accepted") {
		t.Errorf("a stringified valid review answered %+v", r)
	}
	bad := strings.Replace(goodReview, `"location":"api/auth.go:42",`, "", 1)
	if r := submit(bad); !r.IsError || !strings.Contains(r.text(), "/findings/0") {
		t.Errorf("a stringified review with no location answered %+v; want the contract errors", r)
	}
	for name, s := range map[string]string{"invalid JSON": `{"findings": [`, "an array": `[1, 2]`, "two documents": goodReview + goodReview} {
		r := submit(s)
		if !r.IsError || !strings.Contains(r.text(), "output is a string that does not hold one JSON object") {
			t.Errorf("a string holding %s answered %+v; want a refusal that says so", name, r)
		}
	}
}

func TestSubmitTakesALargeOutput(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal([]byte(goodReview), &doc); err != nil {
		t.Fatal(err)
	}
	doc["notes"] = []string{}
	findings := doc["findings"].([]any)
	for i := range 80 {
		findings = append(findings, map[string]any{"id": "f-" + strconv.Itoa(i), "source": "spec", "severity": "minor", "location": "a.go:1",
			"claim": strings.Repeat("c", 3800), "status": "open"})
	}
	doc["findings"] = findings
	b, _ := json.Marshal(doc)
	if len(b) < 300_000 {
		t.Fatalf("the review is only %d bytes", len(b))
	}
	if r := verdict(t, t.TempDir(), "ygg.review/v1", b); r.IsError || !strings.Contains(r.text(), "accepted") {
		t.Errorf("a %d-byte review answered %.300s", len(b), r.text())
	}
}

func TestSubmitReadsOnlyDraftsInTheWorkspace(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	if err := os.MkdirAll(filepath.Join(out, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "x.json"), []byte(goodReview), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "ok.json"), []byte(goodReview), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "big.json"), append([]byte(goodReview[:len(goodReview)-1]+`,"notes":["`), append(bytes.Repeat([]byte("n"), 4<<20), []byte(`"]}`)...)...), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{"link.json": filepath.Join(dir, "x.json"), "sub/inner.json": filepath.Join(out, "ok.json")} {
		if err := os.Symlink(target, filepath.Join(out, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(out, filepath.Join(dir, "outlink")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(out, "fifo.json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(out, "dir.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	refused := []string{"../x.json", "out/../x.json", "/etc/passwd", filepath.Join(out, "ok.json"), "out/link.json", "out/sub/inner.json", "outlink/ok.json",
		"x.json", "out", "out/missing.json", "out/big.json", "", "out/ok.json/", "out/fifo.json", "out/dir.json"}
	var requests []map[string]any
	for i, f := range refused {
		requests = append(requests, call(i*2+1, "submit", map[string]any{"file": f}), call(i*2+2, "check", map[string]any{"file": f}))
	}
	pingID := len(refused)*2 + 1 // a FIFO must not hang the server: a later request is still answered
	requests = append(requests, map[string]any{"id": pingID, "method": "ping"})
	got := serve(t, dir, "ygg.review/v1", requests...)
	for i, f := range refused {
		for _, id := range []int{i*2 + 1, i*2 + 2} {
			if r := toolOf(t, got[id]); !r.IsError || strings.Contains(r.text(), "accepted") {
				t.Errorf("file %q (call %d) answered %+v; want a refusal", f, id, r)
			}
		}
	}
	if got[pingID].Error != nil || string(got[pingID].Result) != "{}" {
		t.Errorf("the ping after the refusals answered %+v", got[pingID])
	}
	// The draft that is fine is read, and nothing is written anywhere.
	before := listTree(t, dir)
	got = serve(t, dir, "ygg.review/v1", call(1, "submit", map[string]any{"file": "out/ok.json"}))
	if r := toolOf(t, got[1]); r.IsError {
		t.Errorf("a draft under out/ answered %+v", r)
	}
	if after := listTree(t, dir); strings.Join(before, "\n") != strings.Join(after, "\n") {
		t.Errorf("the workspace changed:\n%v\n%v", before, after)
	}
	// Both fields, or neither, is a refusal too.
	got = serve(t, dir, "ygg.review/v1", call(1, "submit", map[string]any{}), call(2, "submit", map[string]any{"file": "out/ok.json", "output": map[string]any{}}), call(3, "submit", map[string]any{"output": []any{}}))
	for id := 1; id <= 3; id++ {
		if r := toolOf(t, got[id]); !r.IsError {
			t.Errorf("call %d answered %+v; want a refusal", id, r)
		}
	}
}

func TestSubmitAnswersWhenItIsBroken(t *testing.T) {
	// The script with no ajv beside it, as an image that lost its lib would have it.
	root := t.TempDir()
	for _, d := range []string{"bin", "schemas"} {
		if err := os.Mkdir(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "bin", "ygg-submit.mjs"), []byte(submitScript), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("ygg-submit.mjs", filepath.Join(root, "bin", "ygg-submit")); err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Fatal("node is needed for the sandbox tools' tests")
	}
	got := serveAt(t, root, t.TempDir(), "ygg.review/v1", call(1, "submit", map[string]any{"output": map[string]any{}}), map[string]any{"id": 2, "method": "ping"})
	if r := toolOf(t, got[1]); !r.IsError || !strings.Contains(r.text(), "ygg-submit is broken") {
		t.Errorf("a submit with no ajv answered %+v; want an error result saying ygg-submit is broken", got[1])
	}
	if got[2].Error != nil {
		t.Errorf("the ping after answered %+v", got[2])
	}
}

func listTree(t *testing.T, dir string) []string {
	t.Helper()
	var names []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, _ := d.Info()
		names = append(names, p+" "+info.Mode().String()+" "+strconv.FormatInt(info.Size(), 10)+" "+info.ModTime().String())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return names
}

// gungnirTestdata returns gungnir's schema/testdata/contracts, read through the module the way a Go test of
// gungnir reads it.
func gungnirTestdata(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/ouroboric-dev/gungnir").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	return filepath.Join(strings.TrimSpace(string(out)), "schema", "testdata", "contracts")
}

// goVerdict is what gungnir says of a document: Decode into the contract's Go type, which also runs the Check
// methods, except where the type is missing or the two readers differ for a reason the case names.
func goVerdict(kind, name string, data []byte) (err error, via string) {
	if name == "check-exit-code-float" {
		// The schema takes 1.0 as an integer, as JSON Schema says; Go's decoder refuses 1.0 for an int field. The
		// server follows the schema, so the case is compared with Validate.
		return schema.Validate(schema.ContractCheck, data), "Validate"
	}
	switch kind {
	case "design":
		_, err = schema.Decode[schema.Design](schema.ContractDesign, data)
	case "spec":
		if strings.HasPrefix(name, "spec-bad-check-") {
			// Spec.Check also runs the leaves rules (paths, nesting, consumes, ring), which ygg-submit does not.
			return schema.Validate(schema.ContractSpec, data), "Validate"
		}
		_, err = schema.Decode[schema.Spec](schema.ContractSpec, data)
	case "plan":
		_, err = schema.Decode[schema.Plan](schema.ContractPlan, data)
	case "reuse":
		_, err = schema.Decode[schema.ReuseReview](schema.ContractReuseReview, data)
	case "review":
		_, err = schema.Decode[schema.Review](schema.ContractReview, data)
	case "implement":
		_, err = schema.Decode[schema.Implement](schema.ContractImplement, data)
	case "conformance":
		_, err = schema.Decode[gungnir.Conformance](schema.ContractConformance, data)
	case "check":
		_, err = schema.Decode[schema.CheckResult](schema.ContractCheck, data)
	case "decisions":
		_, err = schema.Decode[schema.Decisions](schema.ContractDecisions, data)
	case "judgement":
		_, err = schema.Decode[schema.Judgement](schema.ContractJudgement, data)
	case "retro":
		_, err = schema.Decode[schema.Retro](schema.ContractRetro, data)
	case "run-record":
		// No Go type yet.
		return schema.Validate(schema.ContractRecord, data), "Validate"
	default:
		panic("no contract for " + kind)
	}
	return err, "Decode"
}

var kindContracts = map[string]schema.Contract{
	"design": schema.ContractDesign, "spec": schema.ContractSpec, "plan": schema.ContractPlan, "reuse": schema.ContractReuseReview,
	"review": schema.ContractReview, "implement": schema.ContractImplement, "conformance": schema.ContractConformance,
	"check": schema.ContractCheck, "decisions": schema.ContractDecisions, "judgement": schema.ContractJudgement,
	"retro": schema.ContractRetro, "run-record": schema.ContractRecord,
}

func kindOf(base string) string {
	if strings.HasPrefix(base, "run-record-") {
		return "run-record"
	}
	kind, _, _ := strings.Cut(base, "-")
	return kind
}

func TestSubmitAgreesWithGungnir(t *testing.T) {
	submitLayout(t)
	dirs := []string{gungnirTestdata(t), filepath.Join("testdata", "submit", "parity")}
	counts := map[string]int{}
	for _, d := range dirs {
		names, err := filepath.Glob(filepath.Join(d, "*.json"))
		if err != nil || len(names) == 0 {
			t.Fatalf("no fixtures in %s: %v", d, err)
		}
		for _, name := range names {
			base := strings.TrimSuffix(filepath.Base(name), ".json")
			kind := kindOf(base)
			contract, ok := kindContracts[kind]
			if !ok {
				t.Errorf("%s: no contract is named %q", name, kind)
				continue
			}
			data, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			counts[d]++
			t.Run(base, func(t *testing.T) {
				want, via := goVerdict(kind, base, data)
				// The document goes in as a draft file, so its bytes (1.0, a null, a vertical tab) reach the
				// server as they are.
				dir := t.TempDir()
				if err := os.MkdirAll(filepath.Join(dir, "out"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "out", "d.json"), data, 0o644); err != nil {
					t.Fatal(err)
				}
				got := serve(t, dir, string(contract), call(1, "check", map[string]any{"file": "out/d.json"}))
				r := toolOf(t, got[1])
				if (want == nil) == r.IsError {
					t.Fatalf("gungnir (%s) says %v; ygg-submit says %+v", via, want, r)
				}
				if want == nil && !strings.Contains(r.text(), "accepted") {
					t.Errorf("accepted, but the text is %q", r.text())
				}
				if want != nil {
					lines := strings.Split(r.text(), "\n")
					for _, l := range lines[1:] {
						if !strings.HasPrefix(l, "/") && !strings.HasPrefix(l, "(document)") {
							t.Errorf("an error line with no pointer: %q", l)
						}
					}
					if len(lines) < 2 {
						t.Errorf("a refusal that lists no error: %q", r.text())
					}
				}
			})
		}
	}
	t.Logf("compared %d fixtures of gungnir and %d parity cases", counts[dirs[0]], counts[dirs[1]])
}

// ygg-submit knows exactly gungnir's contracts, each by its own id: a version it does not know, or a schema that is
// no contract (graph.yaml's), is refused, never checked against a schema of the same name.
func TestSubmitKnowsExactlyGungnirsContracts(t *testing.T) {
	block := regexp.MustCompile(`(?s)const CONTRACTS = \{(.*?)\};`).FindStringSubmatch(submitScript)
	if block == nil {
		t.Fatal("ygg-submit.mjs has no CONTRACTS table")
	}
	listed := map[string]string{}
	for _, m := range regexp.MustCompile(`'([^']+)':\s*'([^']+)'`).FindAllStringSubmatch(block[1], -1) {
		listed[m[1]] = m[2]
	}
	want := map[string]string{}
	for _, c := range schema.Contracts() {
		file, ok := c.SchemaFile()
		if !ok {
			t.Fatalf("gungnir has no schema for %s", c)
		}
		want[string(c)] = file
	}
	if !maps.Equal(listed, want) {
		t.Errorf("ygg-submit's contracts = %v; want schema.Contracts() %v", listed, want)
	}
	dir := t.TempDir()
	for _, c := range []string{"ygg.review/v2", "ygg.graph/v1", "ygg.review/v1x", "ygg.review", ""} {
		if r := verdict(t, dir, c, []byte(goodReview)); !r.IsError || !strings.Contains(r.text(), "is not a contract this session can submit") {
			t.Errorf("contract %q answered %+v; want a refusal", c, r)
		}
	}
	for _, c := range schema.Contracts() {
		if r := verdict(t, dir, string(c), []byte(`{}`)); strings.Contains(r.text(), "is not a contract") {
			t.Errorf("contract %s answered %+v; want it known", c, r)
		}
	}
}
