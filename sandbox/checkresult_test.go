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
	// Without the timeout the same cut line is malformed.
	_, code, _ = convert(t, tool, dir, []string{"--check", "unit", "--exit", "1", "--duration-ms", "9", "--format", "go-test-json", "--input", "in"})
	if code != 2 {
		t.Errorf("exit %d; want 2", code)
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
