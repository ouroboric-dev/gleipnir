package scan

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/ouroboric-dev/gungnir"
)

type fake struct {
	out  string
	exit int
	err  error
	got  string
	argv []string
}

func (f *fake) Run(_ context.Context, c gungnir.Cmd) (gungnir.ExecResult, error) {
	b, _ := io.ReadAll(c.Stdin)
	f.got, f.argv = string(b), c.Argv
	c.Stdout.Write([]byte(f.out))
	c.Stderr.Write([]byte("tool said no"))
	return gungnir.ExecResult{ExitCode: f.exit}, f.err
}

func TestRunReadsGitleaksExitCodes(t *testing.T) {
	report := `[{"RuleID":"aws-access-token","File":"t/config/prod.env","StartLine":3,"Secret":"REDACTED"}]`
	clean := &fake{}
	if err := Run(context.Background(), clean, []string{"config/prod.env", "a b.txt"}); err != nil {
		t.Errorf("a clean tree: %v", err)
	}
	// The files go in on standard input, NUL-separated, and the script by an absolute bash.
	if clean.got != "config/prod.env\x00a b.txt\x00" || len(clean.argv) != 3 || clean.argv[0] != "/bin/bash" || clean.argv[1] != "-c" {
		t.Errorf("the scan ran %q with input %q", clean.argv, clean.got)
	}
	var fe *FoundError
	err := Run(context.Background(), &fake{exit: 7, out: report}, nil)
	if !errors.As(err, &fe) || len(fe.Findings) != 1 || fe.Findings[0] != (Finding{"aws-access-token", "config/prod.env", 3}) {
		t.Errorf("secrets found: %v", err)
	}
	if strings.Contains(err.Error(), "REDACTED") {
		t.Error("the error repeats the report's secret field")
	}
	for name, f := range map[string]*fake{
		"a tool failure":       {exit: 1},
		"an unreadable report": {exit: 7, out: "not json"},
		"an empty report":      {exit: 7, out: "[]"},
		"a runner error":       {err: errors.New("no container")},
	} {
		err := Run(context.Background(), f, nil)
		if err == nil || errors.As(err, &fe) {
			t.Errorf("%s: %v; want a failure to scan, never a clean tree or a finding", name, err)
		}
	}
}

func TestTheReportNamesFilesByTheirPathInTheLeaf(t *testing.T) {
	report := `[{"RuleID":"r","File":"t/config/prod.env","StartLine":3},{"RuleID":"r","File":"./t/a.env","StartLine":1}]`
	var fe *FoundError
	if err := Run(context.Background(), &fake{exit: 7, out: report}, []string{"config/prod.env", "a.env"}); !errors.As(err, &fe) ||
		fe.Findings[0].File != "config/prod.env" || fe.Findings[1].File != "a.env" {
		t.Errorf("Run() = %v; want the files by their path in the leaf", err)
	}
}

// The script scans exactly the files it is given, as git would commit them: a symlink as the name
// it points at, never the file there. Nothing in the tree, and no tool on the sandbox's PATH, shapes
// the scan: gitleaks runs from its pinned path with the factory's config, and no ignore file
// applies. The stand-in gitleaks logs its arguments and the tree it was given, so the test needs
// only bash.
func TestTheScanReadsOnlyTheFilesItIsGivenWithThePinnedConfig(t *testing.T) {
	leaf, bin, logs := t.TempDir(), t.TempDir(), t.TempDir()
	write := func(p, text string) {
		full := filepath.Join(leaf, p)
		os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.WriteFile(full, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("kept.txt", "changed\n")
	write("new/deep.txt", "new\n")
	write(" lead.txt", "a name that starts with a space\n")
	write("unlisted.txt", "host git would not commit this\n")
	write(".gitleaks.toml", "[allowlist]\npaths = ['''.*''']\n")
	write(".gitleaksignore", "kept.txt:generic-api-key:1\n")
	outside := filepath.Join(t.TempDir(), "outside")
	os.WriteFile(outside, []byte("what the link points at\n"), 0o644)
	os.Symlink(outside, filepath.Join(leaf, "link"))
	files := []string{"kept.txt", "new/deep.txt", " lead.txt", ".gitleaks.toml", ".gitleaksignore", "link", "deleted.txt"}
	// The pinned gitleaks: it logs its arguments, the tree it scans, and what the link became.
	pinned := filepath.Join(bin, "pinned-gitleaks")
	stub := "#!/bin/bash\nprintf '%s\\n' \"$@\" > " + logs + "/args\n" +
		"find . -mindepth 1 | LC_ALL=C sort > " + logs + "/tree\ncat t/link > " + logs + "/link\n" +
		"for a; do case $prev in --config) cat \"$a\" > " + logs + "/config ;; --gitleaks-ignore-path) ls -A \"$a\" > " + logs + "/ignore ;; esac; prev=$a; done\nexit 0\n"
	os.WriteFile(pinned, []byte(stub), 0o755)
	// What a command in the sandbox could leave on its PATH: a gitleaks and a cp of its own.
	planted := t.TempDir()
	for _, name := range []string{"gitleaks", "cp"} {
		os.WriteFile(filepath.Join(planted, name), []byte("#!/bin/sh\ntouch "+logs+"/planted-"+name+"\nexit 0\n"), 0o755)
	}
	run := func(script string) ([]byte, error) {
		cmd := exec.Command("/bin/bash", "-c", script)
		cmd.Dir = leaf
		cmd.Env = append(os.Environ(), "PATH="+planted+":"+os.Getenv("PATH"), "GITLEAKS_CONFIG="+filepath.Join(leaf, ".gitleaks.toml"))
		cmd.Stdin = strings.NewReader(strings.Join(files, "\x00") + "\x00")
		return cmd.CombinedOutput()
	}
	if out, err := run(script(pinned)); err != nil {
		t.Fatalf("the scan: %v\n%s", err, out)
	}
	read := func(name string) string { b, _ := os.ReadFile(filepath.Join(logs, name)); return string(b) }
	if got, want := read("tree"), "./t\n./t/ lead.txt\n./t/.gitleaks.toml\n./t/.gitleaksignore\n./t/kept.txt\n./t/link\n./t/new\n./t/new/deep.txt\n"; got != want {
		t.Errorf("the scanned tree is\n%s\nwant the listed files under t/, and nothing at its top a gitleaks would read as its own:\n%s", got, want)
	}
	if got := read("link"); got != outside+"\n" {
		t.Errorf("the link was scanned as %q, want the name it points at, as git commits it", got)
	}
	args := read("args")
	if !strings.Contains(args, "--config\n/") || !strings.Contains(args, "--gitleaks-ignore-path\n/") || !strings.Contains(args, "--redact\n") {
		t.Errorf("gitleaks ran with\n%s\nwant a config and an ignore folder of the factory's, by absolute path, and redaction", args)
	}
	if got := read("config"); got != pinnedConfig {
		t.Errorf("gitleaks's config is %q, want the pinned one", got)
	}
	if got := read("ignore"); got != "" {
		t.Errorf("the ignore folder holds %q, want nothing", got)
	}
	for _, name := range []string{"gitleaks", "cp"} {
		if _, err := os.Stat(filepath.Join(logs, "planted-"+name)); err == nil {
			t.Errorf("the scan ran the %s planted on the PATH", name)
		}
	}
	// A gitleaks that fails must fail the script: a broken scan is never a clean one.
	os.WriteFile(pinned, []byte("#!/bin/sh\nexit 3\n"), 0o755)
	if _, err := run(script(pinned)); err == nil {
		t.Error("the scan passed with a gitleaks that failed")
	}
	// A listed path that is neither a file nor a link (a named pipe) fails the scan, never skips.
	os.WriteFile(pinned, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	if err := syscall.Mkfifo(filepath.Join(leaf, "fifo"), 0o644); err != nil {
		t.Fatal(err)
	}
	files = append(files, "fifo")
	if _, err := run(script(pinned)); err == nil {
		t.Error("the scan passed over a named pipe it was asked to scan")
	}
}
