package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// graderDirs writes what a grading run is given: a task's environment folder, a copy of the project's
// /app, a hidden suite's tests folder and an empty folder for the verifier's logs. A file named
// SECRET sits beside each folder, so a test can show that no mount reaches past its folder.
func graderDirs(t *testing.T, dockerfile string) GradeSpec {
	t.Helper()
	root := t.TempDir()
	mk := func(rel, body string) string {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		return filepath.Dir(p)
	}
	mk("task/SECRET", "task\n")
	env := mk("task/environment/Dockerfile", dockerfile)
	mk("task/environment/package.json", "{}\n")
	app := mk("export/app/index.js", "console.log(1)\n")
	mk("export/SECRET", "export\n")
	tests := mk("suite/v1/tests/test.sh", "#!/bin/bash\nexit 0\n")
	mk("suite/SECRET", "suite\n")
	logs := filepath.Join(root, "logs/verifier")
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatal(err)
	}
	return GradeSpec{Run: "20261018-090000-a1b2c3", Task: "client-gallery-lite", Environment: env, App: app, Tests: tests, Logs: logs,
		Timeout: time.Minute, Memory: "4g", CPUs: 4, Env: map[string]string{"WORKERS": "4"}}
}

const graderDockerfile = "FROM " + baseA + "\nWORKDIR /grader\nCOPY package.json ./\nRUN mkdir -p /app\n"

// runCall returns the arguments of the one `podman run` in the engine's log.
func runCall(t *testing.T, log string) []string {
	t.Helper()
	var calls [][]string
	for _, l := range strings.Split(logOf(t, log), "\n") {
		if rest, ok := strings.CutPrefix(l, "podman run "); ok {
			calls = append(calls, strings.Fields(rest))
		}
	}
	if len(calls) != 1 {
		t.Fatalf("want one podman run, got %d:\n%s", len(calls), logOf(t, log))
	}
	return calls[0]
}

func TestGradeBuildsTheImageThenRunsTheSuiteWithoutANetworkAndRemovesTheContainer(t *testing.T) {
	d, log, _ := fakeEngine(t)
	gs := graderDirs(t, graderDockerfile)
	ref, err := GraderImage(gs.Task, gs.Environment)
	if err != nil || !strings.HasPrefix(ref, "localhost/ygg-grader-client-gallery-lite:") {
		t.Fatalf("GraderImage() = %q, %v", ref, err)
	}
	t.Setenv("STUB_MISSING", ref)
	res, err := d.Grade(context.Background(), gs)
	if err != nil || res.ExitCode != 0 || res.Image != ref {
		t.Fatalf("Grade() = %+v, %v", res, err)
	}
	got := logOf(t, log)
	pull := "podman pull -q --authfile " + d.auth + "/auth.json " + baseA
	build := "podman build --pull=never -t " + ref + " -f " + filepath.Join(gs.Environment, "Dockerfile") + " " + gs.Environment
	for _, want := range []string{pull, build, "podman rm -f --ignore --time 0 ygg-grader-20261018-090000-a1b2c3-client-gallery-lite"} {
		if !strings.Contains(got, want) {
			t.Errorf("the engine calls lack %q:\n%s", want, got)
		}
	}
	if !(strings.Index(got, "podman pull") < strings.Index(got, "podman build") && strings.Index(got, "podman build") < strings.Index(got, "podman run") && strings.Index(got, "podman run") < strings.Index(got, "podman rm")) {
		t.Errorf("the calls are not in the order pull, build, run, remove:\n%s", got)
	}
	args := runCall(t, log)
	flags := " " + strings.Join(args, " ") + " "
	for _, want := range []string{" --network none ", " --label ygg.grader=20261018-090000-a1b2c3 ", " --memory 4g ", " --cpus 4 ",
		" --name ygg-grader-20261018-090000-a1b2c3-client-gallery-lite ", " --env WORKERS=4 ", " " + ref + " bash /tests/test.sh"} {
		if !strings.Contains(flags, want) {
			t.Errorf("podman run lacks %q:\n%s", want, flags)
		}
	}
	if !strings.HasSuffix(flags, " "+ref+" bash /tests/test.sh ") {
		t.Errorf("the image and the command must end the line:\n%s", flags)
	}
}

func TestGradeKeepsAnImageThatIsThereAndRefusesABaseNobodyPinned(t *testing.T) {
	d, log, _ := fakeEngine(t)
	gs := graderDirs(t, graderDockerfile)
	if _, err := d.Grade(context.Background(), gs); err != nil {
		t.Fatal(err)
	}
	if got := logOf(t, log); strings.Contains(got, "podman build") || strings.Contains(got, "podman pull") {
		t.Errorf("an image that is there was built again:\n%s", got)
	}
	for name, dockerfile := range map[string]string{
		"a base with no digest": "FROM docker.io/library/node:24\n",
		"a remote file added":   "FROM " + baseA + "\nADD https://example.com/x.tgz /opt/\n",
		"a copy from an image":  "FROM " + baseA + "\nCOPY --from=docker.io/library/busybox:1 /bin/sh /sh\n",
	} {
		d, log, _ := fakeEngine(t)
		gs := graderDirs(t, dockerfile)
		if _, err := d.Grade(context.Background(), gs); err == nil {
			t.Errorf("%s: Grade() = nil, want an error", name)
		}
		if got := logOf(t, log); got != "" {
			t.Errorf("%s: the engine was called:\n%s", name, got)
		}
	}
}

func TestGradeNeverMountsAnythingButTheThreePaths(t *testing.T) {
	d, log, _ := fakeEngine(t)
	gs := graderDirs(t, graderDockerfile)
	if _, err := d.Grade(context.Background(), gs); err != nil {
		t.Fatal(err)
	}
	args := runCall(t, log)
	want := map[string]string{ // destination: the engine's view of the source, and the mode
		"/app":           engineSide(t, d, gs.App) + " rw",
		"/tests":         engineSide(t, d, gs.Tests) + " ro",
		"/logs/verifier": engineSide(t, d, gs.Logs) + " rw",
	}
	got := map[string]string{}
	for i, a := range args {
		switch a {
		case "--mount":
			kv := map[string]string{}
			for _, f := range strings.Split(args[i+1], ",") {
				k, v, _ := strings.Cut(f, "=")
				kv[k] = v
			}
			mode := "rw"
			if kv["ro"] == "true" {
				mode = "ro"
			}
			if kv["type"] != "bind" {
				t.Errorf("mount %q is not a bind mount", args[i+1])
			}
			if _, dup := got[kv["dst"]]; dup {
				t.Errorf("destination %s is mounted twice", kv["dst"])
			}
			got[kv["dst"]] = kv["src"] + " " + mode
		case "-v", "--volume", "--volumes-from", "--tmpfs", "--device", "--privileged", "--pid", "--ipc", "--uts", "--userns", "--cap-add", "--security-opt", "--network", "--net":
			if a != "--network" || args[i+1] != "none" {
				t.Errorf("podman run has the flag %s, which the grader does not use", a)
			}
		}
	}
	if len(got) != len(want) {
		t.Errorf("mounts = %v, want exactly %v", got, want)
	}
	for dst, w := range want {
		if got[dst] != w {
			t.Errorf("mount at %s = %q, want %q", dst, got[dst], w)
		}
	}
	// No path outside the three folders (the task, the other siblings, the environment) reaches the engine.
	root := filepath.Dir(filepath.Dir(gs.Environment))
	line := strings.Join(args, " ")
	for _, leak := range []string{filepath.Join(root, "task"), gs.Environment, filepath.Join(root, "suite", "SECRET"), filepath.Join(root, "export", "SECRET")} {
		if strings.Contains(line, leak) || strings.Contains(line, engineSide(t, d, leak)) {
			t.Errorf("podman run names %s, which is not one of the three paths:\n%s", leak, line)
		}
	}
}

func engineSide(t *testing.T, d *Driver, p string) string {
	t.Helper()
	e, err := d.cfg.MapPath(p)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestGradeSetsNoLimitItWasNotGiven(t *testing.T) {
	d, log, _ := fakeEngine(t)
	gs := graderDirs(t, graderDockerfile)
	gs.Memory, gs.CPUs = "", 0
	if _, err := d.Grade(context.Background(), gs); err != nil {
		t.Fatal(err)
	}
	if line := strings.Join(runCall(t, log), " "); strings.Contains(line, "--memory") || strings.Contains(line, "--cpus") {
		t.Errorf("podman run sets a limit nobody gave:\n%s", line)
	}
}

func TestGradeRefusesPathsItCouldNotMountSafely(t *testing.T) {
	good := graderDirs(t, graderDockerfile)
	other := t.TempDir()
	cases := map[string]func(*GradeSpec){
		"a relative app":           func(g *GradeSpec) { g.App = "app" },
		"an app that is not clean": func(g *GradeSpec) { g.App = g.App + "/../app" },
		"a path with a comma":      func(g *GradeSpec) { g.App = filepath.Join(other, "a,b"); os.MkdirAll(g.App, 0o755) },
		"a missing tests folder":   func(g *GradeSpec) { g.Tests = filepath.Join(other, "nope") },
		"tests without test.sh":    func(g *GradeSpec) { g.Tests = other },
		"logs that are not empty":  func(g *GradeSpec) { os.WriteFile(filepath.Join(g.Logs, "results.json"), []byte("{}"), 0o644) },
		"logs inside the app":      func(g *GradeSpec) { g.Logs = filepath.Join(g.App, "logs"); os.MkdirAll(g.Logs, 0o755) },
		"the tests inside the app": func(g *GradeSpec) {
			g.Tests = filepath.Join(g.App, "tests")
			os.MkdirAll(g.Tests, 0o755)
			os.WriteFile(filepath.Join(g.Tests, "test.sh"), nil, 0o755)
		},
		"the app as the logs":           func(g *GradeSpec) { g.Logs = g.App },
		"a task name with a slash":      func(g *GradeSpec) { g.Task = "a/b" },
		"a run name with a space":       func(g *GradeSpec) { g.Run = "run 1" },
		"no timeout":                    func(g *GradeSpec) { g.Timeout = 0 },
		"a memory limit that is a flag": func(g *GradeSpec) { g.Memory = "--privileged" },
		"negative cpus":                 func(g *GradeSpec) { g.CPUs = -1 },
		"an env name in lower case":     func(g *GradeSpec) { g.Env = map[string]string{"workers": "4"} },
		"an env value with a newline":   func(g *GradeSpec) { g.Env = map[string]string{"WORKERS": "4\n5"} },
	}
	for name, mutate := range cases {
		d, log, _ := fakeEngine(t)
		gs := good
		gs.Logs = filepath.Join(t.TempDir(), "verifier")
		os.MkdirAll(gs.Logs, 0o755)
		mutate(&gs)
		if _, err := d.Grade(context.Background(), gs); err == nil {
			t.Errorf("%s: Grade() = nil, want an error", name)
		}
		if got := logOf(t, log); strings.Contains(got, "podman run") {
			t.Errorf("%s: a container ran:\n%s", name, got)
		}
	}
	d, _, _ := fakeEngine(t)
	d.cfg.Mounts = []PathMap{{Host: "/home/ana/ygg", Engine: "/mnt/wsl/ygg-bind"}}
	if _, err := d.Grade(context.Background(), good); err == nil || !strings.Contains(err.Error(), "engine can't see") {
		t.Errorf("a folder the engine can't see: Grade() = %v", err)
	}
}

func TestGradeAlwaysRemovesTheContainer(t *testing.T) {
	cases := map[string]struct {
		env     map[string]string
		wantErr string
		exit    int
	}{
		"the suite fails":     {map[string]string{"STUB_RUN_EXIT": "1"}, "", 1},
		"the suite passes":    {nil, "", 0},
		"the engine fails":    {map[string]string{"STUB_RUN_EXIT": "125"}, "could not run", 0},
		"the container hangs": {map[string]string{"STUB_RUN_SLEEP": "30"}, "timed out", 0},
	}
	for name, c := range cases {
		d, log, _ := fakeEngine(t)
		for k, v := range c.env {
			t.Setenv(k, v)
		}
		gs := graderDirs(t, graderDockerfile)
		gs.Timeout = 300 * time.Millisecond
		start := time.Now()
		res, err := d.Grade(context.Background(), gs)
		if c.wantErr == "" && (err != nil || res.ExitCode != c.exit) {
			t.Errorf("%s: Grade() = %+v, %v", name, res, err)
		}
		if c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)) {
			t.Errorf("%s: Grade() = %v, want an error naming %q", name, err, c.wantErr)
		}
		if name == "the container hangs" && (!errors.Is(err, ErrGradeTimeout) || time.Since(start) > 10*time.Second) {
			t.Errorf("%s: err = %v after %v, want ErrGradeTimeout soon", name, err, time.Since(start))
		}
		if got := logOf(t, log); !strings.Contains(got, "podman rm -f --ignore --time 0 ygg-grader-") {
			t.Errorf("%s: the container was not removed:\n%s", name, got)
		}
		for k := range c.env {
			os.Unsetenv(k)
		}
	}
}

func TestGradeRemovesTheContainerWhenTheRunIsCancelled(t *testing.T) {
	d, log, _ := fakeEngine(t)
	t.Setenv("STUB_RUN_SLEEP", "30")
	gs := graderDirs(t, graderDockerfile)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	if _, err := d.Grade(ctx, gs); err == nil || errors.Is(err, ErrGradeTimeout) {
		t.Errorf("Grade() = %v, want the cancellation, not a timeout", err)
	}
	if got := logOf(t, log); !strings.Contains(got, "podman rm -f --ignore --time 0 ygg-grader-") {
		t.Errorf("a cancelled grading left its container:\n%s", got)
	}
}

func TestGradeReportsAContainerItCouldNotRemove(t *testing.T) {
	d, _, _ := fakeEngine(t)
	t.Setenv("STUB_RM_EXIT", "1")
	if _, err := d.Grade(context.Background(), graderDirs(t, graderDockerfile)); err == nil || !strings.Contains(err.Error(), "remov") {
		t.Errorf("Grade() = %v, want an error about the container it could not remove", err)
	}
}

func TestGraderLeftoversAreFoundByTheirLabelAndRemoved(t *testing.T) {
	d, log, _ := fakeEngine(t)
	list := filepath.Join(t.TempDir(), "podman")
	os.WriteFile(list, []byte(`#!/bin/sh
echo "podman $*" >> "$STUB_LOG"
case "$1" in
  ps) cat <<'JSON'
[{"Id":"bbb","State":"running","Labels":{"ygg.grader":"20261018-101500-a1b2c3"}},
 {"Id":"aaa","State":"exited","Labels":{"ygg.grader":"20261017-090000-ffffff"}}]
JSON
  ;;
esac
exit 0
`), 0o755)
	d.Podman = list
	ls, err := d.GraderLeftovers(context.Background())
	if err != nil || len(ls) != 2 || ls[0].Run != "20261017-090000-ffffff" || ls[0].Container != "aaa" || ls[1].State != "running" {
		t.Fatalf("GraderLeftovers() = %+v, %v; want two, oldest run first", ls, err)
	}
	if err := d.RemoveGrader(context.Background(), ls[1].Container); err != nil {
		t.Fatal(err)
	}
	got := logOf(t, log)
	if !strings.Contains(got, "podman ps -a --filter label=ygg.grader --format json") || !strings.Contains(got, "podman rm -f --ignore --time 0 bbb") {
		t.Errorf("the engine calls are wrong:\n%s", got)
	}
}

func TestGraderImageIsNamedForEveryFileOfTheEnvironmentAndRefusesWhatCouldLeadOutside(t *testing.T) {
	gs := graderDirs(t, graderDockerfile)
	first, err := GraderImage(gs.Task, gs.Environment)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := GraderImage(gs.Task, gs.Environment); again != first {
		t.Errorf("the same environment gave %s and then %s", first, again)
	}
	// A changed file, a new file and a file made executable are each a new image: nothing stale runs as the task's.
	for name, change := range map[string]func(env string){
		"a changed file of the same size and mode": func(env string) { os.WriteFile(filepath.Join(env, "package.json"), []byte("[]\n"), 0o755) },
		"a new file":           func(env string) { os.WriteFile(filepath.Join(env, "extra.txt"), []byte("x\n"), 0o644) },
		"a file made readonly": func(env string) { os.Chmod(filepath.Join(env, "package.json"), 0o644) },
	} {
		gs := graderDirs(t, graderDockerfile)
		before, _ := GraderImage(gs.Task, gs.Environment)
		change(gs.Environment)
		if got, err := GraderImage(gs.Task, gs.Environment); err != nil || got == before {
			t.Errorf("%s: GraderImage() = %q, %v; the tag was %q before", name, got, err, before)
		}
	}
	// A link in the environment could lead the build outside it.
	gs = graderDirs(t, graderDockerfile)
	if err := os.Symlink("/etc/passwd", filepath.Join(gs.Environment, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := GraderImage(gs.Task, gs.Environment); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("an environment holding a symlink: GraderImage() = %v", err)
	}
	d, log, _ := fakeEngine(t)
	if _, err := d.Grade(context.Background(), gs); err == nil {
		t.Error("Grade() = nil for an environment holding a symlink")
	}
	if got := logOf(t, log); strings.Contains(got, "podman build") || strings.Contains(got, "podman run") {
		t.Errorf("the engine built or ran something:\n%s", got)
	}
}
