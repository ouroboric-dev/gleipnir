package sandbox

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
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
  ps) case "$*" in *service=fw*) echo fw456 ;; *) echo work123; echo fw456 ;; esac; exit 0 ;;
  exec)
    case "$*" in
      *"test -f /run/ygg-fw/ready"*) exit "${STUB_READY_EXIT:-0}" ;;
      *"/dev/tcp/1.1.1.1/443"*) exit "${STUB_PROBE_EXIT:-124}" ;;
      *"kill -KILL -1"*) exit 0 ;;
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
