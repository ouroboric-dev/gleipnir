//go:build sandbox

package sandbox

// Integration tests of Grade on a real engine (spec §13), with the environment of
// TestSandboxDriverOnARealEngine. They need only the engine and a base image with bash, pinned by digest
// (itStack), which the first run pulls. Set YGG_SANDBOX_ENGINE, YGG_SANDBOX_TREE and
// YGG_SANDBOX_TREE_ENGINE, and YGG_SANDBOX_GRADE_LIMITS=1 on an engine that can apply memory and CPU
// limits (a rootless engine needs cgroup delegation; without it the container fails to start), then run:
//
//	go test -tags sandbox -run TestSandboxGrade -v -timeout 20m ./sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// itGrader returns a driver for the engine and a grading run in a folder of the shared tree. The
// suite's test.sh is the script given.
func itGrader(t *testing.T, script string) (*Driver, GradeSpec) {
	t.Helper()
	socket, tree, engineTree := itEnv(t)
	root, err := os.MkdirTemp(tree, "grade-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	work := filepath.Join(root, "work")
	d, err := New(socket, Config{Mounts: []PathMap{{Host: tree, Engine: engineTree}}, UID: os.Getuid(), GID: os.Getgid()}, work)
	if err != nil {
		t.Fatal(err)
	}
	write := func(rel, body string, mode os.FileMode) string {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		return filepath.Dir(p)
	}
	env := write("task/environment/Dockerfile", "FROM "+itStack+"\nRUN mkdir -p /app /grader\n", 0o644)
	app := write("export/app/index.js", "console.log(1)\n", 0o644)
	tests := write("suite/v1/tests/test.sh", script, 0o755)
	logs := filepath.Join(root, "logs", "verifier")
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatal(err)
	}
	gs := GradeSpec{Run: "20261018-120000-a1b2c3", Task: "it-task", Environment: env, App: app, Tests: tests, Logs: logs,
		Timeout: 5 * time.Minute, Env: map[string]string{"WORKERS": "2"}}
	if os.Getenv("YGG_SANDBOX_GRADE_LIMITS") != "" {
		gs.Memory, gs.CPUs = "1g", 1
	}
	return d, gs
}

const probeScript = `#!/bin/bash
cd /logs/verifier
ls /sys/class/net > ifaces.txt
if (exec 3<>/dev/tcp/1.1.1.1/443) 2>/dev/null; then echo reachable > net.txt; else echo blocked > net.txt; fi
echo from-the-suite > /app/written.txt && echo app-rw > app.txt
if touch /tests/x 2>/dev/null; then echo tests-rw > tests.txt; else echo tests-ro > tests.txt; fi
echo "$WORKERS" > env.txt
cat /proc/self/mountinfo | cut -d' ' -f5 > mounts.txt
echo '{"suites":[]}' > results.json
exit 3
`

func TestSandboxGradeRunsTheSuiteIsolatedAndRemovesTheContainer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	d, gs := itGrader(t, probeScript)
	res, err := d.Grade(ctx, gs)
	if err != nil || res.ExitCode != 3 {
		t.Fatalf("Grade() = %+v, %v; want the suite's exit status 3\n%s", res, err, res.Log)
	}
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(gs.Logs, name))
		if err != nil {
			t.Fatalf("the suite wrote no %s: %v", name, err)
		}
		return strings.TrimSpace(string(b))
	}
	if got := read("ifaces.txt"); got != "lo" {
		t.Errorf("the container's network interfaces = %q, want lo only", got)
	}
	for file, want := range map[string]string{"net.txt": "blocked", "app.txt": "app-rw", "tests.txt": "tests-ro", "env.txt": "2", "results.json": `{"suites":[]}`} {
		if got := read(file); got != want {
			t.Errorf("%s = %q, want %q", file, got, want)
		}
	}
	if b, err := os.ReadFile(filepath.Join(gs.App, "written.txt")); err != nil || strings.TrimSpace(string(b)) != "from-the-suite" {
		t.Errorf("the suite's write to /app did not reach the copy: %q, %v", b, err)
	}
	// Every mount point in the container is the engine's own, or one of the three.
	var user []string
	for _, m := range strings.Fields(read("mounts.txt")) {
		own := false
		for _, p := range []string{"/proc", "/sys", "/dev", "/run", "/etc/hosts", "/etc/hostname", "/etc/resolv.conf"} {
			own = own || m == p || strings.HasPrefix(m, p+"/")
		}
		if !own {
			user = append(user, m)
		}
	}
	sort.Strings(user)
	if got := strings.Join(user, " "); got != "/ /app /logs/verifier /tests" {
		t.Errorf("the container's mounts = %q, want / /app /logs/verifier /tests", got)
	}
	left, err := d.GraderLeftovers(ctx)
	if err != nil || len(left) != 0 {
		t.Errorf("GraderLeftovers() = %+v, %v; want none after Grade", left, err)
	}
}

func TestSandboxGradeLabelsTheContainerAndRemovesItOnATimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	d, gs := itGrader(t, "#!/bin/bash\nsleep 300\n")
	gs.Timeout = 20 * time.Second
	if _, _, err := d.BuildGrader(ctx, gs.Task, gs.Environment); err != nil {
		t.Fatalf("BuildGrader() = %v", err)
	}
	done := make(chan error, 1)
	go func() { _, err := d.Grade(ctx, gs); done <- err }()
	seen := false
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline) && !seen; time.Sleep(500 * time.Millisecond) {
		ls, err := d.GraderLeftovers(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range ls {
			seen = seen || (l.Run == gs.Run && l.State == "running")
		}
	}
	if !seen {
		t.Error("no running container carried the label ygg.grader=" + gs.Run)
	}
	if err := <-done; !errors.Is(err, ErrGradeTimeout) {
		t.Errorf("Grade() = %v, want ErrGradeTimeout", err)
	}
	if ls, err := d.GraderLeftovers(ctx); err != nil || len(ls) != 0 {
		t.Errorf("GraderLeftovers() = %+v, %v; want none after a timeout", ls, err)
	}
}
