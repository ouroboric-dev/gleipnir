package sandbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ouroboric-dev/gungnir/schema"
)

// The tests of ygg-check-result run the real script under node, installed as the work image installs it:
// bin/ygg-check-result.mjs with a link for the name a check script calls. It needs nothing but node.
func checkResultTool(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("node"); err != nil {
		t.Fatal("node is needed for the sandbox tools' tests")
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "ygg-check-result.mjs"), []byte(checkResultScript), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("ygg-check-result.mjs", filepath.Join(bin, "ygg-check-result")); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(bin, "ygg-check-result")
}

// convert runs the tool in dir with args and returns the result file (nil if none was written), the exit code
// and stderr.
func convert(t *testing.T, tool, dir string, args []string) (result []byte, code int, stderr string) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "check.json")
	cmd := exec.Command(tool, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "YGG_CHECK_RESULT="+out)
	var errb bytes.Buffer
	cmd.Stderr = &errb
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		code = ee.ExitCode()
	default:
		t.Fatal(err)
	}
	result, rerr := os.ReadFile(out)
	if rerr != nil {
		result = nil
	}
	if entries, _ := os.ReadDir(filepath.Dir(out)); len(entries) > 1 || (len(entries) == 1 && result == nil) {
		t.Errorf("the tool left %d files beside the result, want the result or nothing", len(entries))
	}
	return result, code, errb.String()
}

// caseArgs reads a case's args file: one argument per line, as the check script would pass them, with the
// case's own files by relative name (the tool runs in the case's folder).
func caseArgs(t *testing.T, dir string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "args"))
	if err != nil {
		t.Fatal(err)
	}
	var args []string
	for _, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if l != "" {
			args = append(args, l)
		}
	}
	return args
}

// runCases runs every testdata/checkresult/<format>-<case> of the formats. A case holds args, its inputs and
// either expected.json (the result, which must also decode as a ygg.check/v1) or wantstderr (the converter
// refuses with exit 2, and stderr holds that text). Each format needs a pass, a fail and a malformed case.
func runCases(t *testing.T, formats ...string) {
	tool := checkResultTool(t)
	for _, format := range formats {
		for _, kind := range []string{"pass", "fail", "malformed"} {
			if _, err := os.Stat(filepath.Join("testdata", "checkresult", format+"-"+kind)); err != nil {
				t.Errorf("format %s has no %s case: %v", format, kind, err)
			}
		}
		dirs, err := filepath.Glob(filepath.Join("testdata", "checkresult", format+"-*"))
		if err != nil {
			t.Fatal(err)
		}
		for _, dir := range dirs {
			t.Run(filepath.Base(dir), func(t *testing.T) {
				got, code, stderr := convert(t, tool, dir, caseArgs(t, dir))
				if want, err := os.ReadFile(filepath.Join(dir, "wantstderr")); err == nil {
					if code != 2 || got != nil || !strings.Contains(stderr, strings.TrimSpace(string(want))) {
						t.Fatalf("exit %d, result %q, stderr %q; want exit 2, no result and %q", code, got, stderr, strings.TrimSpace(string(want)))
					}
					return
				}
				if code != 0 {
					t.Fatalf("exit %d: %s", code, stderr)
				}
				wantBytes, err := os.ReadFile(filepath.Join(dir, "expected.json"))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := schema.Decode[schema.CheckResult](schema.ContractCheck, wantBytes); err != nil {
					t.Fatalf("expected.json is not a ygg.check/v1: %v", err)
				}
				if _, err := schema.Decode[schema.CheckResult](schema.ContractCheck, got); err != nil {
					t.Fatalf("the result is not a ygg.check/v1: %v\n%s", err, got)
				}
				var g, w any
				if err := json.Unmarshal(got, &g); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(wantBytes, &w); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(g, w) {
					t.Errorf("result:\n%s\nwant:\n%s", got, wantBytes)
				}
			})
		}
	}
}

func TestTheConverterReadsEachGoTool(t *testing.T) {
	runCases(t, "go-test-json", "go-vet-json", "golangci-json", "govulncheck-json", "osv-json", "sqlc-text", "oasdiff-json", "none")
}

func TestTheConverterReadsEachWebTool(t *testing.T) {
	runCases(t, "vitest-json", "playwright-json", "eslint-json", "tsc-text", "npm-audit-json")
}

// fixture writes files into a new folder and returns it.
func fixture(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func decodeResult(t *testing.T, b []byte) schema.CheckResult {
	t.Helper()
	r, err := schema.Decode[schema.CheckResult](schema.ContractCheck, b)
	if err != nil {
		t.Fatalf("not a ygg.check/v1: %v\n%s", err, b)
	}
	return r
}

const onePass = `{"Action":"pass","Package":"p","Test":"TestA"}` + "\n" + `{"Action":"pass","Package":"p"}` + "\n"
const oneFail = `{"Action":"output","Package":"p","Test":"TestA","Output":"    a_test.go:9: boom\n"}` + "\n" +
	`{"Action":"fail","Package":"p","Test":"TestA"}` + "\n" + `{"Action":"fail","Package":"p"}` + "\n"

func TestThePassedFlagFollowsTheExitCode(t *testing.T) {
	tool := checkResultTool(t)
	base := []string{"--check", "unit", "--duration-ms", "40", "--format", "go-test-json", "--input", "in"}
	for _, c := range []struct {
		name       string
		input      string
		extra      []string
		exit       string
		passed     bool
		failures   int
		timedOut   bool
		wantExitIn int
	}{
		{"clean", onePass, nil, "0", true, 0, false, 0},
		{"failures and exit 1", oneFail, nil, "1", false, 1, false, 1},
		// A tool that exits 0 while its output shows a failure contradicts itself; the result says so, and Odin refuses it.
		{"failures but exit 0", oneFail, nil, "0", false, 1, false, 0},
		// A non-zero exit with nothing found is a result with no failures; the check script's caller names the finding.
		{"exit 1 but nothing found", onePass, nil, "1", false, 0, false, 1},
		{"timed out", onePass, []string{"--timed-out"}, "124", false, 0, true, 124},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := fixture(t, map[string]string{"in": c.input})
			args := append(append([]string{}, base...), "--exit", c.exit)
			args = append(args, c.extra...)
			got, code, stderr := convert(t, tool, dir, args)
			if code != 0 {
				t.Fatalf("exit %d: %s", code, stderr)
			}
			r := decodeResult(t, got)
			if r.Passed != c.passed || len(r.Failures) != c.failures || r.TimedOut != c.timedOut || r.ExitCode != c.wantExitIn || r.DurationMS != 40 {
				t.Errorf("got %+v", r)
			}
			if !strings.Contains(string(got), `"failures": []`) && !strings.Contains(string(got), `"failures":[]`) && c.failures == 0 {
				t.Errorf("a result with no failures has an empty failures list: %s", got)
			}
		})
	}
}

func TestAParentIsNeverListedBothWays(t *testing.T) {
	tool := checkResultTool(t)
	in := `{"Action":"run","Package":"p","Test":"TestP"}
{"Action":"run","Package":"p","Test":"TestP/ok"}
{"Action":"pass","Package":"p","Test":"TestP/ok"}
{"Action":"run","Package":"p","Test":"TestP/bad"}
{"Action":"output","Package":"p","Test":"TestP/bad","Output":"    p_test.go:3: nope\n"}
{"Action":"fail","Package":"p","Test":"TestP/bad"}
{"Action":"fail","Package":"p","Test":"TestP"}
{"Action":"fail","Package":"p"}
`
	dir := fixture(t, map[string]string{"in": in})
	got, code, stderr := convert(t, tool, dir, []string{"--check", "unit", "--exit", "1", "--duration-ms", "1", "--format", "go-test-json", "--input", "in"})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	r := decodeResult(t, got) // Decode runs Verify, which refuses a test in both lists
	if !reflect.DeepEqual(r.PassedTests, []string{"p.TestP/ok"}) || len(r.Failures) != 2 {
		t.Errorf("got %+v", r)
	}
}

func TestTheConverterRefusesWhatItCannotRead(t *testing.T) {
	tool := checkResultTool(t)
	good := []string{"--check", "c", "--exit", "0", "--duration-ms", "1", "--format", "go-test-json"}
	dir := fixture(t, map[string]string{"in": onePass})
	big := filepath.Join(dir, "big")
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(64<<20 + 1); err != nil { // sparse: one byte over the bound
		t.Fatal(err)
	}
	f.Close()
	for name, args := range map[string][]string{
		"a missing input":         append(append([]string{}, good...), "--input", "nope"),
		"an input over 64 MiB":    append(append([]string{}, good...), "--input", "big"),
		"a directory as input":    append(append([]string{}, good...), "--input", "."),
		"an unknown format":       {"--check", "c", "--exit", "0", "--duration-ms", "1", "--format", "tap", "--input", "in"},
		"an unknown flag":         append(append([]string{}, good...), "--input", "in", "--frobnicate"),
		"a format with no input":  good,
		"a non-numeric exit":      {"--check", "c", "--exit", "x", "--duration-ms", "1", "--format", "go-test-json", "--input", "in"},
		"a message with no kind":  {"--check", "c", "--exit", "1", "--duration-ms", "1", "--format", "none", "--message", "m"},
		"a kind outside the enum": {"--check", "c", "--exit", "1", "--duration-ms", "1", "--format", "none", "--kind", "vibes", "--message", "m"},
		"no check name":           {"--exit", "0", "--duration-ms", "1", "--format", "none"},
		"a negative duration":     {"--check", "c", "--exit", "0", "--duration-ms", "-1", "--format", "none"},
	} {
		t.Run(name, func(t *testing.T) {
			got, code, stderr := convert(t, tool, dir, args)
			if code != 2 || got != nil || strings.TrimSpace(stderr) == "" {
				t.Errorf("exit %d, result %q, stderr %q; want exit 2, no result, a reason", code, got, stderr)
			}
		})
	}
	t.Run("no output path", func(t *testing.T) {
		cmd := exec.Command(tool, append(append([]string{}, good...), "--input", "in")...)
		cmd.Dir = dir
		cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
		var errb bytes.Buffer
		cmd.Stderr = &errb
		err := cmd.Run()
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != 2 || !strings.Contains(errb.String(), "YGG_CHECK_RESULT") {
			t.Errorf("%v, %q; want exit 2 naming YGG_CHECK_RESULT", err, errb.String())
		}
	})
}

func TestATimedOutRunMayEndInHalfALine(t *testing.T) {
	tool := checkResultTool(t)
	dir := fixture(t, map[string]string{"in": onePass + `{"Action":"run","Pack`})
	args := []string{"--check", "unit", "--exit", "124", "--timed-out", "--duration-ms", "9", "--format", "go-test-json", "--input", "in"}
	got, code, stderr := convert(t, tool, dir, args)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	r := decodeResult(t, got)
	if r.Passed || !r.TimedOut || len(r.Notes) == 0 {
		t.Errorf("got %+v; want a failed, timed out result with a note on the cut line", r)
	}
}

func TestTheCountsAndTheBoundsHold(t *testing.T) {
	tool := checkResultTool(t)
	var b strings.Builder
	for i := 0; i < 600; i++ {
		b.WriteString(`{"Action":"fail","Package":"p","Test":"T` + strings.Repeat("x", i%7) + string(rune('A'+i%26)) + itoa(i) + `"}` + "\n")
	}
	dir := fixture(t, map[string]string{"in": b.String()})
	got, code, stderr := convert(t, tool, dir, []string{"--check", "unit", "--exit", "1", "--duration-ms", "1", "--format", "go-test-json", "--input", "in"})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	r := decodeResult(t, got)
	if len(r.Failures) != 500 || r.Counts == nil || r.Counts.Failed != 600 || r.Counts.Run != 600 || len(r.Notes) == 0 {
		t.Errorf("got %d failures, counts %+v, notes %v; want 500 failures, 600 failed of 600, and a note", len(r.Failures), r.Counts, r.Notes)
	}
}

func itoa(i int) string { b, _ := json.Marshal(i); return string(b) }

func TestAPackageThatDiesInsideATestNamesIt(t *testing.T) {
	tool := checkResultTool(t)
	// Nothing else failed: the package failure carries the unfinished test's output too, and the test has its own failure.
	in := `{"Action":"run","Package":"q","Test":"TestC"}
{"Action":"output","Package":"q","Test":"TestC","Output":"panic: test timed out after 1s\n"}
{"Action":"output","Package":"q","Output":"FAIL\tq\t1.004s\n"}
{"Action":"fail","Package":"q"}
`
	dir := fixture(t, map[string]string{"in": in})
	got, code, stderr := convert(t, tool, dir, []string{"--check", "unit", "--exit", "1", "--duration-ms", "1", "--format", "go-test-json", "--input", "in"})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	r := decodeResult(t, got)
	if len(r.Failures) != 2 || r.Failures[0].Test != "q.TestC" || r.Failures[1].Test != "" || !strings.Contains(r.Failures[1].Message, "panic: test timed out") {
		t.Errorf("got %+v", r.Failures)
	}
}

func TestTheNoticesOfTheJSONToolsAreRead(t *testing.T) {
	tool := checkResultTool(t)
	run := func(format, in string) schema.CheckResult {
		dir := fixture(t, map[string]string{"in": in})
		got, code, stderr := convert(t, tool, dir, []string{"--check", "c", "--exit", "0", "--duration-ms", "1", "--format", format, "--input", "in"})
		if code != 0 {
			t.Fatalf("%s: exit %d: %s", format, code, stderr)
		}
		return decodeResult(t, got)
	}
	if r := run("osv-json", `{"results": null}`); !r.Passed || len(r.Failures) != 0 {
		t.Errorf("results null: %+v", r)
	}
	// A typecheck issue's Pos is a placeholder; with no position in its Text, it has no location.
	r := run("golangci-json", `{"Issues":[{"FromLinter":"typecheck","Text":"could not import x","Pos":{"Filename":"","Line":1,"Column":0}}]}`)
	if len(r.Failures) != 1 || r.Failures[0].Location != "" || r.Failures[0].Kind != "type" {
		t.Errorf("got %+v", r.Failures)
	}
}

func TestTheWebToolsHandleTheirEdgeCases(t *testing.T) {
	tool := checkResultTool(t)
	advisory := func(src int, name, sev string) string {
		return `{"source":1` + string(rune('0'+src)) + `,"name":"` + name + `","title":"t ` + name + `","url":"https://x/` + name + `","severity":"` + sev + `","range":"<2"}`
	}
	audit := `{"auditReportVersion":2,"vulnerabilities":{` +
		`"a":{"name":"a","severity":"critical","via":[` + advisory(1, "a", "moderate") + `,` + advisory(2, "a", "critical") + `],"fixAvailable":false},` +
		`"b":{"name":"b","severity":"critical","via":["a"],"fixAvailable":{"name":"a","version":"2.0.0","isSemVerMajor":true}},` +
		`"c":{"name":"c","severity":"low","via":[` + advisory(2, "a", "critical") + `],"fixAvailable":true}}}`
	for _, c := range []struct {
		name, format, input string
		args                []string
		wantCode            int
		wantFailures        int
		wantStderr          string
		want                []string
	}{
		// "via" strings are packages the advisory came through, not advisories; a shared source is listed once.
		{"audit at moderate", "npm-audit-json", audit, []string{"--level", "moderate"}, 0, 2, "", []string{"no fix is available"}},
		{"audit at critical", "npm-audit-json", audit, []string{"--level", "critical"}, 0, 1, "", []string{"1 advisories below critical"}},
		{"audit defaults to the realm's high", "npm-audit-json", audit, nil, 0, 1, "", nil},
		{"audit error document", "npm-audit-json", `{"error":{"code":"ENOAUDIT","summary":"audit endpoint returned an error"}}`, nil, 2, 0, "npm audit error: audit endpoint returned an error", nil},
		{"audit level unknown", "npm-audit-json", audit, []string{"--level", "severe"}, 2, 0, "--level severe is not one of", nil},
		{"level on another format", "eslint-json", `[]`, []string{"--level", "high"}, 2, 0, "--level is for the npm-audit-json format", nil},
		{"eslint warnings are not failures", "eslint-json", `[{"filePath":"/w/a.js","messages":[{"ruleId":"semi","severity":1,"message":"m","line":1,"column":1}]}]`, nil, 0, 0, "", []string{"1 warnings are not failures"}},
		{"eslint parse error has no rule", "eslint-json", `[{"filePath":"/w/a.js","messages":[{"ruleId":null,"fatal":true,"severity":2,"message":"Parsing error: x","line":3,"column":2}]}]`, []string{"--root", "/w"}, 0, 1, "", []string{`"a.js:3:2"`}},
		{"root defaults to the working folder", "eslint-json", "", nil, 0, 1, "", []string{`"src/a.js:3:2"`}},
		{"relative root", "eslint-json", `[]`, []string{"--root", "w"}, 2, 0, "--root needs an absolute folder", nil},
		// The same title twice, once failing: the test is a failure and is not listed as passed.
		{"vitest duplicate title", "vitest-json", `{"testResults":[{"name":"/w/a.test.ts","status":"failed","assertionResults":[` +
			`{"ancestorTitles":["d"],"title":"t","status":"passed","failureMessages":[]},` +
			`{"ancestorTitles":["d"],"title":"t","status":"failed","failureMessages":["Error: no\n    at /w/a.test.ts:2:3"]}]}]}`, []string{"--root", "/w"}, 0, 1, "", []string{`"a.test.ts > d > t"`, `"a.test.ts:2:3"`}},
		{"vitest not a report", "vitest-json", `{"tests":[]}`, nil, 2, 0, "no testResults list", nil},
		{"playwright project names and a final failure after a retry", "playwright-json", `{"suites":[{"title":"a.spec.ts","specs":[{"title":"t","tests":[` +
			`{"projectName":"chromium","status":"unexpected","results":[{"status":"failed","error":{"message":"first"}},{"status":"timedOut","error":{"message":"Test timeout of 30000ms exceeded."}}]},` +
			`{"projectName":"firefox","status":"expected","results":[{"status":"passed"}]}]}]}]}`, nil, 0, 1, "", []string{`"[chromium] a.spec.ts > t"`, `"[firefox] a.spec.ts > t"`, "Test timeout of 30000ms"}},
		{"playwright error outside any test", "playwright-json", `{"suites":[],"errors":[{"message":"Error: Cannot find module 'x'","location":{"file":"/w/p.spec.ts","line":1,"column":8}}]}`, []string{"--root", "/w"}, 0, 1, "", []string{`"p.spec.ts:1:8"`}},
		{"playwright unknown status", "playwright-json", `{"suites":[{"title":"a","specs":[{"title":"t","tests":[{"status":"weird","results":[]}]}]}]}`, nil, 2, 0, "not one of expected", nil},
		{"tsc diagnostic with no file", "tsc-text", "error TS5023: Unknown compiler option 'foo'.\n", nil, 0, 1, "", []string{"TS5023"}},
		{"tsc notes other lines", "tsc-text", "Found 1 error.\n", nil, 0, 0, "", []string{"1 lines of tsc output"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			input := c.input
			if c.name == "root defaults to the working folder" {
				input = ""
			}
			dir := fixture(t, map[string]string{"in": input})
			if c.name == "root defaults to the working folder" {
				real, _ := filepath.EvalSymlinks(dir)
				dir = real
				if err := os.WriteFile(filepath.Join(dir, "in"), []byte(`[{"filePath":"`+dir+`/src/a.js","messages":[{"ruleId":null,"severity":2,"message":"x","line":3,"column":2}]}]`), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			args := append([]string{"--check", "c", "--exit", "1", "--duration-ms", "1", "--format", c.format, "--input", "in"}, c.args...)
			got, code, stderr := convert(t, tool, dir, args)
			if code != c.wantCode || (c.wantStderr != "" && !strings.Contains(stderr, c.wantStderr)) {
				t.Fatalf("exit %d, stderr %q; want exit %d and %q", code, stderr, c.wantCode, c.wantStderr)
			}
			if code != 0 {
				if got != nil {
					t.Errorf("a refusal left a result: %s", got)
				}
				return
			}
			r := decodeResult(t, got)
			if len(r.Failures) != c.wantFailures {
				t.Errorf("%d failures, want %d: %s", len(r.Failures), c.wantFailures, got)
			}
			for _, w := range c.want {
				if !strings.Contains(string(got), w) {
					t.Errorf("result lacks %s:\n%s", w, got)
				}
			}
		})
	}
}
