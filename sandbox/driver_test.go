package sandbox

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ouroboric-dev/gungnir"
)

const socket = "unix:///mnt/wsl/podman-sockets/podman-machine-default/podman-user.sock"

// fakeEngine puts a podman, a devcontainer and a podman-compose that log what they are asked, in
// front of the real ones. Which answers they give is set by STUB_* variables, which tests set with
// t.Setenv.
func fakeEngine(t *testing.T) (d *Driver, log string, sp gungnir.SandboxSpec) {
	t.Helper()
	bin, work := t.TempDir(), t.TempDir()
	log = filepath.Join(work, "calls.log")
	write := func(name, body string) string {
		p := filepath.Join(bin, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	podman := write("podman", `echo "podman $*" >> "$STUB_LOG"
echo "env host=${CONTAINER_HOST:-} auth=${REGISTRY_AUTH_FILE:-} docker=${DOCKER_CONFIG:-} tok=${TOKEN:-}" >> "$STUB_LOG"
case "$1" in
  image) case " $STUB_MISSING " in *" $3 "*) exit 1 ;; esac; exit 0 ;;
  network) [ "$2" = exists ] && exit 0; exit 0 ;;
  ps) [ -z "$STUB_PS_SLEEP" ] || exec sleep "$STUB_PS_SLEEP"
    case "$*" in *service=fw*) echo fw456 ;; *) echo work123; echo fw456 ;; esac; exit 0 ;;
  exec)
    case "$*" in
      *"test -f /run/ygg-fw/ready"*) exit "${STUB_READY_EXIT:-0}" ;;
      *"/dev/tcp/1.1.1.1/443"*) exit "${STUB_PROBE_EXIT:-124}" ;;
      *"kill -KILL -1"*) exit "${STUB_KILL_EXIT:-0}" ;;
      *"find /home/ygg"*) exit "${STUB_HOME_EXIT:-0}" ;;
    esac
    [ -z "$STUB_EXEC_SLEEP" ] || exec sleep "$STUB_EXEC_SLEEP"
    echo "ran $*"; exit "${STUB_EXEC_EXIT:-0}" ;;
esac
exit 0
`)
	dc := write("devcontainer", `echo "devcontainer $*" >> "$STUB_LOG"
echo '{"outcome":"success","containerId":"work123","composeProjectName":"x","remoteUser":"1000"}'
`)
	t.Setenv("STUB_LOG", log)
	t.Setenv("CONTAINER_HOST", "unix:///var/run/docker.sock") // the shell's own engine, which must never be used
	t.Setenv("DOCKER_CONFIG", "/home/ana/.docker")
	parent := t.TempDir()
	c := cfg()
	c.Mounts = []PathMap{{Host: filepath.Dir(parent), Engine: "/mnt/wsl/t"}, {Host: work, Engine: "/mnt/wsl/w"}}
	var err error
	if d, err = New(socket, c, work); err != nil {
		t.Fatal(err)
	}
	d.Podman, d.Devcontainer, d.Compose, d.ReadyTimeout = podman, dc, "podman-compose", 2*time.Second
	sp = spec(parent)
	return d, log, sp
}

func logOf(t *testing.T, p string) string {
	t.Helper()
	b, _ := os.ReadFile(p)
	return string(b)
}

func TestUpUsesTheEngineAndAuthTheFactoryChose(t *testing.T) {
	d, log, sp := fakeEngine(t)
	env, err := d.Up(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if env.Container != "work123" || env.Workdir != "/u/repos/app" || env.Project != Project(sp) {
		t.Errorf("env = %+v", env)
	}
	got := logOf(t, log)
	if strings.Contains(got, "docker.sock") || strings.Contains(got, "/home/ana/.docker") {
		t.Errorf("a call used the shell's engine or registry config:\n%s", got)
	}
	if !strings.Contains(got, "host="+socket) || !strings.Contains(got, "auth="+filepath.Join(d.work, "registry-auth", "auth.json")) {
		t.Errorf("a call lacked the factory's engine or the isolated auth:\n%s", got)
	}
	for _, want := range []string{"devcontainer up --docker-path", "--skip-post-create", "--config " + filepath.Join(d.work, "repos-app", "devcontainer.json")} {
		if !strings.Contains(got, want) {
			t.Errorf("the devcontainer call lacks %q:\n%s", want, got)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(d.work, "registry-auth", "auth.json")); strings.TrimSpace(string(b)) != "{}" {
		t.Errorf("the registry auth isn't empty: %s", b)
	}
}

func TestUpRefusesAChangedConfigurationBeforeStartingAnything(t *testing.T) {
	d, log, sp := fakeEngine(t)
	d.beforeUp = func(g Generated) {
		mutate(t, g.Devcontainer, func(m map[string]any) { m["initializeCommand"] = "touch /tmp/pwned" })
	}
	_, err := d.Up(context.Background(), sp)
	var pe *PolicyError
	if !errors.As(err, &pe) {
		t.Fatalf("Up() = %v, want a *PolicyError", err)
	}
	if got := logOf(t, log); strings.Contains(got, "devcontainer up") || strings.Contains(got, "podman") {
		t.Errorf("the engine was called after a refusal:\n%s", got)
	}
}

func TestUpNeedsTheImages(t *testing.T) {
	d, _, sp := fakeEngine(t)
	t.Setenv("STUB_MISSING", "localhost/ygg-work:abc")
	if _, err := d.Up(context.Background(), sp); !errors.Is(err, ErrNoImage) {
		t.Errorf("Up() = %v, want ErrNoImage", err)
	}
}

func TestUpRefusesANetworkThatIsNotClosed(t *testing.T) {
	d, log, sp := fakeEngine(t)
	t.Setenv("STUB_PROBE_EXIT", "0") // the connect to 1.1.1.1:443 succeeds
	_, err := d.Up(context.Background(), sp)
	if err == nil || !strings.Contains(err.Error(), "isn't closing") {
		t.Fatalf("Up() = %v, want a refusal: the network is open", err)
	}
	if !strings.Contains(logOf(t, log), "podman rm -f -t 2 --depend work123 fw456") {
		t.Error("a sandbox that failed its check was left running")
	}
	t.Setenv("STUB_PROBE_EXIT", "127")
	if _, err := d.Up(context.Background(), sp); err == nil {
		t.Error("a check that couldn't run counted as a pass")
	}
	t.Setenv("STUB_PROBE_EXIT", "124")
	t.Setenv("STUB_READY_EXIT", "1")
	d.ReadyTimeout = 300 * time.Millisecond
	if _, err := d.Up(context.Background(), sp); err == nil || !strings.Contains(err.Error(), "did not come up") {
		t.Errorf("a firewall that never got ready: %v", err)
	}
}

func TestExecKeepsValuesOffTheCommandLine(t *testing.T) {
	d, log, sp := fakeEngine(t)
	env, err := d.Up(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("STUB_EXEC_EXIT", "3")
	var out bytes.Buffer
	res, err := d.Exec(context.Background(), env, gungnir.Cmd{Argv: []string{"go", "test"}, Dir: "cmd", Env: map[string]string{"TOKEN": "s3cret-value"}, Stdout: &out})
	if err != nil || res.ExitCode != 3 {
		t.Fatalf("Exec() = %+v, %v; want exit 3 as a result", res, err)
	}
	got := logOf(t, log)
	if !strings.Contains(got, "podman exec -i -w /u/repos/app/cmd -e TOKEN work123 go test") {
		t.Errorf("the exec call is wrong:\n%s", got)
	}
	// The value reached the process's environment (the stub saw it) but no command line.
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(line, "podman ") && strings.Contains(line, "s3cret-value") {
			t.Errorf("a secret on a command line: %s", line)
		}
	}
	if !strings.Contains(got, "tok=s3cret-value") {
		t.Error("the value didn't reach the command's environment")
	}
	if _, err := d.Exec(context.Background(), env, gungnir.Cmd{}); err == nil {
		t.Error("an empty command ran")
	}
}

func TestExecKillsWhatItStartedWhenTheContextEnds(t *testing.T) {
	d, log, sp := fakeEngine(t)
	env, err := d.Up(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("STUB_EXEC_SLEEP", "20")
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	began := time.Now()
	_, err = d.Exec(ctx, env, gungnir.Cmd{Argv: []string{"sleep", "100"}})
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(began) > 5*time.Second {
		t.Errorf("Exec() = %v after %v; want the deadline, promptly", err, time.Since(began))
	}
	if !strings.Contains(logOf(t, log), "exec work123 sh -c kill -KILL -1") {
		t.Error("the command's processes were left running in the container")
	}
}

// A command's background processes die when its Exec returns, even when the command exits
// normally: none of them can write to the leaf during the checks, the scan or the checkpoint.
func TestNothingACommandStartedSurvivesItsExec(t *testing.T) {
	d, log, sp := fakeEngine(t)
	env, err := d.Up(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("STUB_EXEC_EXIT", "0")
	if res, err := d.Exec(context.Background(), env, gungnir.Cmd{Argv: []string{"go", "test"}}); err != nil || res.ExitCode != 0 {
		t.Fatalf("Exec() = %+v, %v", res, err)
	}
	got := logOf(t, log)
	cmd := strings.LastIndex(got, "-w /u/repos/app work123 go test")
	kill := strings.LastIndex(got, "exec work123 sh -c "+killScript)
	if cmd < 0 || kill < cmd {
		t.Errorf("no kill of the container's processes after the command:\n%s", got)
	}
	t.Setenv("STUB_EXEC_EXIT", "3")
	if res, err := d.Exec(context.Background(), env, gungnir.Cmd{Argv: []string{"go", "test"}}); err != nil || res.ExitCode != 3 {
		t.Errorf("Exec() of a failing command = %+v, %v; want exit 3 as a result", res, err)
	}
	if n := strings.Count(logOf(t, log), "exec work123 sh -c "+killScript); n < 2 {
		t.Errorf("a failing command's processes were not killed: %d kills", n)
	}
	// A kill that can't prove the container is clear fails the command: its work can't be trusted.
	t.Setenv("STUB_KILL_EXIT", "1")
	if _, err := d.Exec(context.Background(), env, gungnir.Cmd{Argv: []string{"go", "test"}}); err == nil {
		t.Error("Exec() succeeded though processes it started may still run")
	}
}

// Each command finds HOME, and the XDG folders inside it, empty: nothing one command (or one agent
// session) writes there shapes the next, or the secret scan (decision 4).
func TestEachCommandStartsWithAnEmptyHome(t *testing.T) {
	d, log, sp := fakeEngine(t)
	env, err := d.Up(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	compose, _ := os.ReadFile(filepath.Join(d.work, "repos-app", "compose.yaml"))
	for _, kv := range []string{"HOME: /home/ygg", "XDG_CONFIG_HOME: /home/ygg/.config", "XDG_CACHE_HOME: /home/ygg/.cache",
		"XDG_DATA_HOME: /home/ygg/.local/share", "XDG_STATE_HOME: /home/ygg/.local/state"} {
		if !strings.Contains(string(compose), kv) {
			t.Errorf("the work container's environment lacks %s, so a stack image could put that folder outside HOME:\n%s", kv, compose)
		}
	}
	empty := "exec work123 sh -c " + homeScript
	upped := strings.Count(logOf(t, log), empty) // Up's own check of the network is a command too
	for i := 0; i < 2; i++ {
		if _, err := d.Exec(context.Background(), env, gungnir.Cmd{Argv: []string{"go", "test"}}); err != nil {
			t.Fatal(err)
		}
	}
	got := logOf(t, log)
	if n := strings.Count(got, empty) - upped; n != 2 {
		t.Errorf("HOME was emptied %d times for two commands:\n%s", n, got)
	}
	if last := strings.LastIndex(got, "-w /u/repos/app work123 go test"); last < strings.LastIndex(got, empty) {
		t.Errorf("HOME was emptied after the command, not before it:\n%s", got)
	}
	// A HOME that can't be emptied runs nothing.
	t.Setenv("STUB_HOME_EXIT", "1")
	before := strings.Count(logOf(t, log), "work123 go test")
	if _, err := d.Exec(context.Background(), env, gungnir.Cmd{Argv: []string{"go", "test"}}); err == nil {
		t.Error("Exec() ran a command though HOME could not be emptied")
	}
	if strings.Count(logOf(t, log), "work123 go test") != before {
		t.Error("the command ran with what an earlier command left in HOME")
	}
}

func TestDownRemovesByLabelAndRepeats(t *testing.T) {
	d, log, sp := fakeEngine(t)
	env := gungnir.Env{Project: Project(sp), Container: "work123"}
	for i := 0; i < 2; i++ {
		if err := d.Down(context.Background(), env); err != nil {
			t.Fatal(err)
		}
	}
	got := logOf(t, log)
	if strings.Count(got, "podman rm -f -t 2 --depend work123 fw456") != 2 || !strings.Contains(got, "network rm -f "+env.Project+"_default") {
		t.Errorf("Down didn't remove the containers and the network:\n%s", got)
	}
	if err := d.Down(context.Background(), gungnir.Env{}); err == nil {
		t.Error("Down with no project succeeded")
	}
}

func TestNewRefusesAnEngineThatIsNotASocket(t *testing.T) {
	if _, err := New("tcp://10.0.0.1:2375", cfg(), t.TempDir()); err == nil {
		t.Error("a network engine was accepted")
	}
}

func TestLeftoversAreFoundByLabelAndStopped(t *testing.T) {
	d, log, _ := fakeEngine(t)
	// A podman that answers the list; the generic stub's ps prints ids, so this test brings its own.
	list := filepath.Join(t.TempDir(), "podman")
	os.WriteFile(list, []byte(`#!/bin/sh
echo "podman $*" >> "$STUB_LOG"
case "$1" in
  ps)
    case "$*" in
      *--format*) cat <<'JSON'
[{"Id":"bbb","State":"running","Labels":{"dev.ouroboric.ygg.run":"20261016-101500-a1b2c3","dev.ouroboric.ygg.leaf":"repos/app","com.docker.compose.project":"ygg-p1"}},
 {"Id":"aaa","State":"exited","Labels":{"dev.ouroboric.ygg.run":"20261015-090000-ffffff","dev.ouroboric.ygg.leaf":"repos/api","com.docker.compose.project":"ygg-p0"}}]
JSON
      ;;
      *) echo aaa ;;
    esac ;;
esac
exit 0
`), 0o755)
	d.Podman = list
	ls, err := d.Leftovers(context.Background())
	if err != nil || len(ls) != 2 || ls[0].Run != "20261015-090000-ffffff" || ls[0].Container != "aaa" || ls[1].Leaf != "repos/app" || ls[1].Project != "ygg-p1" {
		t.Fatalf("Leftovers() = %+v, %v; want two, oldest run first", ls, err)
	}
	if err := d.StopLeftover(context.Background(), ls[1]); err != nil {
		t.Fatal(err)
	}
	if got := logOf(t, log); !strings.Contains(got, "label=com.docker.compose.project=ygg-p1") || !strings.Contains(got, "podman rm -f -t 2 --depend aaa") {
		t.Errorf("StopLeftover didn't remove the project's containers:\n%s", got)
	}
}

func TestInfoReadsRootlessAndTheVersions(t *testing.T) {
	d, _, _ := fakeEngine(t)
	p := filepath.Join(t.TempDir(), "podman")
	os.WriteFile(p, []byte("#!/bin/sh\necho \"$STUB_INFO\"\n"), 0o755)
	d.Podman = p
	t.Setenv("STUB_INFO", "true 5.7.1")
	if i, err := d.Info(context.Background()); err != nil || !i.Rootless || i.Podman != "5.7.1" {
		t.Errorf("Info() = %+v, %v", i, err)
	}
	t.Setenv("STUB_INFO", "false 5.7.1")
	if i, err := d.Info(context.Background()); err != nil || i.Rootless {
		t.Errorf("a rootful engine: %+v, %v", i, err)
	}
	t.Setenv("STUB_INFO", "garbage")
	if _, err := d.Info(context.Background()); err == nil {
		t.Error("an unreadable answer was accepted")
	}
	dc := filepath.Join(t.TempDir(), "devcontainer")
	os.WriteFile(dc, []byte("#!/bin/sh\necho 0.89.0\n"), 0o755)
	d.Devcontainer = dc
	if v, err := d.DevcontainerCLI(context.Background()); err != nil || v != DevcontainerVersion {
		t.Errorf("DevcontainerCLI() = %q, %v", v, err)
	}
}

func TestUpGivesUpOnADevcontainerThatHangs(t *testing.T) {
	d, log, sp := fakeEngine(t)
	hang := filepath.Join(t.TempDir(), "devcontainer")
	// Like the real CLI, it starts a child that outlives it, holding the output open.
	os.WriteFile(hang, []byte("#!/bin/sh\necho \"devcontainer $*\" >> \"$STUB_LOG\"\n(sleep 30; true) &\nsleep 30\n"), 0o755)
	d.Devcontainer, d.UpTimeout = hang, 300*time.Millisecond
	began := time.Now()
	_, err := d.Up(context.Background(), sp)
	if err == nil || time.Since(began) > 10*time.Second {
		t.Errorf("Up() = %v after %v; want a timeout, promptly", err, time.Since(began))
	}
	if !strings.Contains(logOf(t, log), "podman rm -f -t 2") {
		t.Error("a start that timed out was not cleaned up")
	}
}

// Backlog B-017: podman's own failure is an error, never the command's exit code.
func TestExecReportsAMissingContainerAsAnError(t *testing.T) {
	d, _, sp := fakeEngine(t)
	env, err := d.Up(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("STUB_EXEC_EXIT", "125")
	res, err := d.Exec(context.Background(), env, gungnir.Cmd{Argv: []string{"go", "test"}})
	if err == nil || !strings.Contains(err.Error(), "podman couldn't run go") || res.ExitCode != 0 {
		t.Errorf("Exec() = %+v, %v; want an error and no exit code", res, err)
	}
	for _, code := range []string{"1", "2", "126", "127", "137"} {
		t.Setenv("STUB_EXEC_EXIT", code)
		if res, err := d.Exec(context.Background(), env, gungnir.Cmd{Argv: []string{"go", "test"}}); err != nil || strconv.Itoa(res.ExitCode) != code {
			t.Errorf("exit %s: Exec() = %+v, %v; the command's own exit codes stay results", code, res, err)
		}
	}
}

// Backlog B-016: a probe podman or timeout could not run does not show the network closed.
func TestUpRefusesAProbeThatCouldNotRun(t *testing.T) {
	d, log, sp := fakeEngine(t)
	t.Setenv("STUB_PROBE_EXIT", "125")
	_, err := d.Up(context.Background(), sp)
	if err == nil || !strings.Contains(err.Error(), "couldn't run") {
		t.Fatalf("Up() = %v, want a refusal: the closed-network check could not run", err)
	}
	if !strings.Contains(logOf(t, log), "podman rm -f -t 2 --depend work123 fw456") {
		t.Error("a sandbox that failed its check was left running")
	}
	t.Setenv("STUB_PROBE_EXIT", "124") // timeout's own status for a connect that was dropped: closed
	if _, err := d.Up(context.Background(), sp); err != nil {
		t.Errorf("a connect that timed out must show the network closed: %v", err)
	}
}

// Backlog B-028: a hung engine must not hang Down.
func TestDownGivesUpOnAHungEngine(t *testing.T) {
	d, _, sp := fakeEngine(t)
	d.DownTimeout = 300 * time.Millisecond
	t.Setenv("STUB_PS_SLEEP", "30")
	began := time.Now()
	err := d.Down(context.WithoutCancel(context.Background()), gungnir.Env{Project: Project(sp), Container: "work123"})
	if err == nil || time.Since(began) > 10*time.Second {
		t.Errorf("Down() = %v after %v; want an error, promptly", err, time.Since(began))
	}
}
