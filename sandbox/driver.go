package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ouroboric-dev/gungnir"
)

// Driver is the devcontainer sandbox (spec §6.1; sandbox spike, decided 2026-10-14). It starts a
// leaf's containers with the devcontainer CLI on Podman's rootless engine, runs commands in them with
// podman exec, and removes them by label. Every engine call carries the isolated registry auth and
// the engine's address from the factory's own configuration, never the shell's.
type Driver struct {
	Podman       string        // the podman client; "podman" by default
	Devcontainer string        // the devcontainer CLI; "devcontainer" by default
	Compose      string        // the compose provider; "podman-compose" by default
	ReadyTimeout time.Duration // how long Up waits for the firewall; a minute by default
	UpTimeout    time.Duration // how long one devcontainer up attempt may take; two minutes by default (a good start takes under 30 s; one that hangs is stopped and tried once more, so Up may take twice this)
	DownTimeout  time.Duration // how long Down may take; two minutes by default

	cfg    Config
	engine string
	work   string // where every sandbox's configuration folder goes
	auth   string // the empty registry auth every call uses
	// stubEnv lets a test's stub tools see the process's variables that start with it, which set
	// their answers.
	stubEnv string
	// beforeUp lets a test change the configuration after Generate, to show Validate runs before the start.
	beforeUp func(Generated)
}

var _ gungnir.Sandbox = (*Driver)(nil)

// ErrNoImage means a sandbox image is missing: build the images first (ygg sandbox build).
var ErrNoImage = errors.New("a sandbox image is missing")

// New returns a driver for the engine at socket, keeping every sandbox's configuration under work.
func New(socket string, cfg Config, work string) (*Driver, error) {
	if !strings.HasPrefix(socket, "unix:///") {
		return nil, fmt.Errorf("engine %q must be a unix socket URL", socket)
	}
	auth := filepath.Join(work, "registry-auth")
	if err := os.MkdirAll(auth, 0o700); err != nil {
		return nil, err
	}
	// An empty auth file: host credentials, and the credential helpers a host's container config
	// names, never reach an image pull (spec §16 item 7).
	if err := os.WriteFile(filepath.Join(auth, "auth.json"), []byte("{}\n"), 0o600); err != nil {
		return nil, err
	}
	return &Driver{Podman: "podman", Devcontainer: "devcontainer", Compose: "podman-compose", ReadyTimeout: time.Minute, UpTimeout: 2 * time.Minute, DownTimeout: 2 * time.Minute,
		cfg: cfg, engine: socket, work: work, auth: auth}, nil
}

// toolEnv names the operator's variables the engine tools keep: those that find the tools and their
// folders, which a rootless podman needs too; the proxy an image pull goes through; podman's own
// configuration files; and the CA bundle that trusts a company proxy (backlog N-5). No other variable
// of the operator's reaches them: compose expands ${NAME} in compose.yaml from their environment, and
// no variable that points them at another engine, other registry credentials or another compose
// project may (review I-6). A proxy URL can hold a password: Env never logs what it passes.
var toolEnv = []string{"PATH", "HOME", "TMPDIR", "XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME",
	"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
	"CONTAINERS_CONF", "CONTAINERS_CONF_OVERRIDE", "CONTAINERS_STORAGE_CONF", "CONTAINERS_REGISTRIES_CONF",
	"SSL_CERT_FILE", "SSL_CERT_DIR"}

// Env returns the environment for every engine call: the operator's variables that toolEnv names, and
// the factory's engine and isolated registry auth, which come last and so win.
func (d *Driver) Env() []string {
	var env []string
	for _, name := range toolEnv {
		if secretName.MatchString(name) {
			continue // a name that looks like a credential never passes, even if toolEnv grows one
		}
		if v, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+v)
		}
	}
	if d.stubEnv != "" {
		for _, kv := range os.Environ() {
			if strings.HasPrefix(kv, d.stubEnv) {
				env = append(env, kv)
			}
		}
	}
	return append(env, "CONTAINER_HOST="+d.engine, "REGISTRY_AUTH_FILE="+filepath.Join(d.auth, "auth.json"), "DOCKER_CONFIG="+d.auth)
}

// command is a tool of the engine's, run in its own process group with the driver's environment.
func (d *Driver) command(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = d.Env()
	// The tools start children of their own (devcontainer runs podman-compose): a timeout kills the
	// whole group, and a child that outlives its parent can't hold the pipes open for long.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 5 * time.Second
	return cmd
}

func (d *Driver) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := d.command(ctx, name, args...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("%s %s: %w: %s", filepath.Base(name), strings.Join(args, " "), err, strings.TrimSpace(errOut.String()))
	}
	return out.Bytes(), nil
}

// Up starts the sandbox of spec: it writes the configuration, checks it against the hardening
// rules, checks that the images exist, starts the containers, waits until the firewall holds, and
// proves from inside that the network is closed. A sandbox that can't prove it is stopped.
func (d *Driver) Up(ctx context.Context, spec gungnir.SandboxSpec) (gungnir.Env, error) {
	if err := spec.Validate(); err != nil {
		return gungnir.Env{}, err
	}
	g, err := Generate(ConfigDir(d.work, spec), spec, d.cfg)
	if err != nil {
		return gungnir.Env{}, err
	}
	if d.beforeUp != nil {
		d.beforeUp(g)
	}
	if err := Validate(g, spec, d.cfg); err != nil {
		return gungnir.Env{}, err
	}
	imgs := d.cfg.ImagesOf(spec)
	needed := []string{imgs.Work, imgs.Firewall}
	for _, v := range spec.Services {
		needed = append(needed, v.Image)
	}
	for _, img := range needed {
		if _, err := d.run(ctx, d.Podman, "image", "exists", img); err != nil {
			return gungnir.Env{}, fmt.Errorf("%w: %s (run ygg sandbox build)", ErrNoImage, img)
		}
	}
	project := Project(spec)
	env := gungnir.Env{Name: spec.Name, Project: project, Workdir: Root + "/" + spec.Layout().Leaf}
	// A start sometimes hangs at compose up for no known cause and the next one succeeds in
	// seconds (sandbox spike, item 1): an attempt that times out is cleaned up and tried once more.
	var out []byte
	for attempt := 1; ; attempt++ {
		upCtx, cancel := context.WithTimeout(ctx, d.UpTimeout)
		out, err = d.run(upCtx, d.Devcontainer, "up", "--docker-path", d.Podman, "--docker-compose-path", d.Compose,
			"--workspace-folder", spec.Leaf, "--config", g.Devcontainer, "--user-data-folder", filepath.Join(g.Dir, "data"),
			"--skip-post-create", "--default-user-env-probe", "none", "--mount-workspace-git-root=false", "--log-format", "json")
		timedOut := err != nil && upCtx.Err() != nil && ctx.Err() == nil
		cancel()
		if err == nil {
			break
		}
		d.Down(context.WithoutCancel(ctx), env)
		if !timedOut || attempt == 2 {
			if timedOut {
				err = fmt.Errorf("devcontainer up timed out after %s on the second attempt too: %w", d.UpTimeout, err)
			}
			return gungnir.Env{}, err
		}
	}
	if env.Container, err = containerID(out); err != nil {
		d.Down(context.WithoutCancel(ctx), env)
		return gungnir.Env{}, err
	}
	if err := d.proveClosed(ctx, env, project); err != nil {
		d.Down(context.WithoutCancel(ctx), env)
		return gungnir.Env{}, err
	}
	return env, nil
}

// containerID reads the result line of devcontainer up: its last line that is a JSON object with an
// outcome.
func containerID(out []byte) (string, error) {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		var r struct {
			Outcome     string `json:"outcome"`
			ContainerID string `json:"containerId"`
			Message     string `json:"message"`
		}
		if json.Unmarshal([]byte(lines[i]), &r) != nil || r.Outcome == "" {
			continue
		}
		if r.Outcome != "success" || r.ContainerID == "" {
			return "", fmt.Errorf("devcontainer up: %s %s", r.Outcome, r.Message)
		}
		return r.ContainerID, nil
	}
	return "", errors.New("devcontainer up gave no result")
}

// proveClosed waits for the firewall sidecar to say it holds, then tries from the work container to
// reach the open internet. If it connects, or the check can't run, the sandbox is refused.
func (d *Driver) proveClosed(ctx context.Context, env gungnir.Env, project string) error {
	fw, err := d.run(ctx, d.Podman, "ps", "-q", "--filter", "label=com.docker.compose.project="+project, "--filter", "label=com.docker.compose.service=fw")
	id := strings.TrimSpace(string(fw))
	if err != nil || id == "" || strings.Contains(id, "\n") {
		return fmt.Errorf("the firewall container of %s was not found: %v", project, err)
	}
	deadline := time.Now().Add(d.ReadyTimeout)
	for {
		if _, err := d.run(ctx, d.Podman, "exec", id, "test", "-f", "/run/ygg-fw/ready"); err == nil {
			break
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return fmt.Errorf("the firewall of %s did not come up in %s", project, d.ReadyTimeout)
		}
		time.Sleep(200 * time.Millisecond)
	}
	// 1.1.1.1:443 is reachable from an open network, and no sandbox lists it: a connect that succeeds
	// means the firewall isn't in the path. Dropped packets time out after three seconds.
	res, err := d.Exec(ctx, env, gungnir.Cmd{Argv: []string{"timeout", "3", "bash", "-c", "exec 3<>/dev/tcp/1.1.1.1/443"}})
	switch {
	case err != nil:
		return fmt.Errorf("the closed-network check couldn't run: %w", err)
	case res.ExitCode == 0:
		return errors.New("the sandbox reached 1.1.1.1:443, so the firewall isn't closing it")
	case res.ExitCode == 126 || res.ExitCode == 127:
		return errors.New("the closed-network check needs bash and timeout in the stack image")
	}
	return nil
}

// Exec runs cmd in the work container, with HOME emptied first. Values in cmd.Env travel in the
// podman process's own environment, never on a command line. When the command ends, or ctx does, Exec kills every
// process left in the container but its first, so nothing the command started outlives it: no
// background process writes to the leaf while Odin checks, scans and commits it. A kill that can't
// show the container clear is an error.
func (d *Driver) Exec(ctx context.Context, env gungnir.Env, c gungnir.Cmd) (gungnir.ExecResult, error) {
	if err := c.Validate(); err != nil {
		return gungnir.ExecResult{}, err
	}
	if env.Container == "" {
		return gungnir.ExecResult{}, errors.New("no sandbox container to run in")
	}
	dir := env.Workdir
	if c.Dir != "" {
		dir = env.Workdir + "/" + filepath.ToSlash(c.Dir)
	}
	args := []string{"exec", "-i", "-w", dir}
	cmdEnv := d.Env()
	for _, k := range sortedEnv(c.Env) {
		args = append(args, "-e", k)
		cmdEnv = append(cmdEnv, k+"="+c.Env[k])
	}
	args = append(append(args, env.Container), c.Argv...)
	if err := d.emptyHome(ctx, env); err != nil {
		return gungnir.ExecResult{}, fmt.Errorf("emptying HOME in the sandbox before %s: %w", c.Argv[0], err)
	}
	cmd := exec.CommandContext(ctx, d.Podman, args...)
	cmd.Env = cmdEnv
	cmd.Stdin, cmd.Stdout, cmd.Stderr = c.Stdin, c.Stdout, c.Stderr
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	killErr := d.killAll(env)
	if ctx.Err() != nil {
		return gungnir.ExecResult{}, ctx.Err()
	}
	if killErr != nil {
		return gungnir.ExecResult{}, fmt.Errorf("stopping what %s started in the sandbox: %w", c.Argv[0], killErr)
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ee.ExitCode() == podmanFailed {
			return gungnir.ExecResult{}, fmt.Errorf("podman couldn't run %s in the sandbox (exit %d): the container may be gone", c.Argv[0], podmanFailed)
		}
		return gungnir.ExecResult{ExitCode: ee.ExitCode()}, nil
	}
	return gungnir.ExecResult{}, err
}

// podmanFailed is the exit status podman exec returns when podman itself failed, such as for a
// container that is gone. It is not the command's: an infrastructure failure must not read as a check
// or a node that failed (spec §12; backlog B-016, B-017). A command that exits 125 on its own reads the
// same way, which is a cost worth paying.
const podmanFailed = 125

func sortedEnv(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	for i := range ks { // small maps: insertion sort keeps this file free of another import
		for j := i; j > 0 && ks[j] < ks[j-1]; j-- {
			ks[j], ks[j-1] = ks[j-1], ks[j]
		}
	}
	return ks
}

// killAll kills every process in the work container but its first (which holds the container
// up) and the kill's own shell. Every process there runs as the operator, so kill -1 reaches them
// all. It kills again until no process is left but zombies, which the first process never reaps.
func (d *Driver) killAll(env gungnir.Env) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := d.run(ctx, d.Podman, "exec", env.Container, "sh", "-c", killScript)
	return err
}

// emptyHome empties the work container's HOME, which holds the XDG folders too, before a command:
// what one command or agent session wrote there never shapes the next (decision 4). It runs as the
// operator, who owns everything in HOME.
func (d *Driver) emptyHome(ctx context.Context, env gungnir.Env) error {
	_, err := d.run(ctx, d.Podman, "exec", env.Container, "sh", "-c", homeScript)
	return err
}

// homeScript makes every folder in HOME searchable and writable, so none can keep its files, removes
// everything below HOME without following a link, and exits 1 unless HOME is then empty.
const homeScript = "cd / && find " + Home + ` -mindepth 1 -type d ! -perm -u=rwx -exec chmod u+rwx {} \; ; find ` + Home + ` -mindepth 1 -delete; [ -z "$(find ` + Home + ` -mindepth 1 -print -quit)" ]`

// killScript kills what runs in the container, as above, and exits 1 when a live process is left
// after ten rounds.
const killScript = `kill -KILL -1 2>/dev/null
for round in 1 2 3 4 5 6 7 8 9 10; do
  live=
  for d in /proc/[0-9]*; do
    p=${d#/proc/}
    if [ "$p" = 1 ] || [ "$p" = "$$" ]; then continue; fi
    st=
    while read -r k v _; do
      if [ "$k" = State: ]; then st=$v; break; fi
    done 2>/dev/null <"$d/status"
    case "$st" in ''|Z|X) ;; *) live=1 ;; esac
  done
  if [ -z "$live" ]; then exit 0; fi
  kill -KILL -1 2>/dev/null
  sleep 0.1
done
echo "processes are still running in the sandbox" >&2
exit 1`

// Down removes the sandbox's containers and networks. It finds them by label, so it works for a
// sandbox this process never started, and it is safe to call twice.
func (d *Driver) Down(ctx context.Context, env gungnir.Env) error {
	if env.Project == "" {
		return errors.New("no sandbox project to stop")
	}
	// Down runs when a run ends, with its own context: an engine that hangs must not hang ygg with it
	// (backlog B-028). What it couldn't remove stays recorded in run.json, and ygg doctor finds it.
	if d.DownTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.DownTimeout)
		defer cancel()
	}
	ids, err := d.run(ctx, d.Podman, "ps", "-a", "-q", "--filter", "label=com.docker.compose.project="+env.Project)
	if err != nil {
		return err
	}
	var errs []error
	if f := strings.Fields(string(ids)); len(f) > 0 {
		if _, err := d.run(ctx, d.Podman, append([]string{"rm", "-f", "-t", "2", "--depend"}, f...)...); err != nil {
			errs = append(errs, err)
		}
	}
	for _, n := range []string{"default", ServicesNetwork} {
		if _, err := d.run(ctx, d.Podman, "network", "exists", env.Project+"_"+n); err == nil {
			if _, err := d.run(ctx, d.Podman, "network", "rm", "-f", env.Project+"_"+n); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}
