package scan

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ouroboric-dev/gungnir"
)

type fake struct {
	out  string
	exit int
	err  error
	got  string
}

func (f *fake) Run(_ context.Context, c gungnir.Cmd) (gungnir.ExecResult, error) {
	b, _ := io.ReadAll(c.Stdin)
	f.got = string(b)
	c.Stdout.Write([]byte(f.out))
	c.Stderr.Write([]byte("tool said no"))
	return gungnir.ExecResult{ExitCode: f.exit}, f.err
}

func TestRunReadsGitleaksExitCodes(t *testing.T) {
	report := `[{"RuleID":"aws-access-token","File":"/config/prod.env","StartLine":3,"Secret":"REDACTED"}]`
	if err := Run(context.Background(), &fake{}); err != nil {
		t.Errorf("a clean tree: %v", err)
	}
	var fe *FoundError
	err := Run(context.Background(), &fake{exit: 7, out: report})
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
		err := Run(context.Background(), f)
		if err == nil || errors.As(err, &fe) {
			t.Errorf("%s: %v; want a failure to scan, never a clean tree or a finding", name, err)
		}
	}
}

// The script picks the files a checkpoint would commit. gitleaks is a stand-in that lists the files
// it was given, so the test needs only git and bash.
func TestScriptScansWhatWouldBeCommittedAndNothingElse(t *testing.T) {
	repo := t.TempDir()
	bin := t.TempDir()
	write := func(p, text string) {
		full := filepath.Join(repo, p)
		os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.WriteFile(full, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	git := func(args ...string) {
		c := exec.Command("git", append([]string{"-c", "user.name=T", "-c", "user.email=t@example.invalid"}, args...)...)
		c.Dir = repo
		c.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write(".gitignore", ".env\n")
	write("kept.txt", "old\n")
	write("gone.txt", "bye\n")
	git("init", "-q", "-b", "main")
	git("add", ".")
	git("commit", "-q", "-m", "base")
	write("kept.txt", "changed\n")
	write("new/deep.txt", "new\n")
	write(".env", "SECRET=ignored-by-git\n")
	os.Remove(filepath.Join(repo, "gone.txt"))
	os.Symlink("/etc/passwd", filepath.Join(repo, "link"))
	stub := "#!/bin/sh\nfor last; do :; done\n( cd \"$last\" && find . -type f | sort )\nexit 0\n"
	if err := os.WriteFile(filepath.Join(bin, "gitleaks"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-s")
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	cmd.Stdin = strings.NewReader(Script())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("scan.sh: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "./kept.txt\n./new/deep.txt" {
		t.Errorf("scanned %q; want the changed and the new file, not .env, the deleted file or the link", got)
	}
	// A gitleaks that fails must fail the script: a broken scan is never a clean one.
	os.WriteFile(filepath.Join(bin, "gitleaks"), []byte("#!/bin/sh\nexit 3\n"), 0o755)
	cmd = exec.Command("bash", "-s")
	cmd.Dir, cmd.Env, cmd.Stdin = repo, append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH")), strings.NewReader(Script())
	if err := cmd.Run(); err == nil {
		t.Error("scan.sh passed with a gitleaks that failed")
	}
}
