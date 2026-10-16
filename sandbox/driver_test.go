package sandbox

import (
	"context"
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
