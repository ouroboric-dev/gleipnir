package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

	cfg    Config
	engine string
	work   string // where every sandbox's configuration folder goes
	auth   string // the empty registry auth every call uses
	// beforeUp lets a test change the configuration after Generate, to show Validate runs before the start.
	beforeUp func(Generated)
}

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
	return &Driver{Podman: "podman", Devcontainer: "devcontainer", Compose: "podman-compose", ReadyTimeout: time.Minute,
		cfg: cfg, engine: socket, work: work, auth: auth}, nil
}

// Env returns the environment for every engine call: the operator's, without any variable that
// points the tools at another engine or other registry credentials, and with ours.
func (d *Driver) Env() []string {
	var env []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		switch name {
		case "CONTAINER_HOST", "CONTAINER_CONNECTION", "DOCKER_HOST", "DOCKER_CONFIG", "REGISTRY_AUTH_FILE", "DOCKER_CONTEXT", "COMPOSE_PROJECT_NAME":
			continue
		}
		env = append(env, kv)
	}
	return append(env, "CONTAINER_HOST="+d.engine, "REGISTRY_AUTH_FILE="+filepath.Join(d.auth, "auth.json"), "DOCKER_CONFIG="+d.auth)
}

func (d *Driver) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = d.Env()
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("%s %s: %w: %s", filepath.Base(name), strings.Join(args, " "), err, strings.TrimSpace(errOut.String()))
	}
	return out.Bytes(), nil
}

// Down removes the sandbox's containers and network. It finds them by label, so it works for a
// sandbox this process never started, and it is safe to call twice.
func (d *Driver) Down(ctx context.Context, env gungnir.Env) error {
	if env.Project == "" {
		return errors.New("no sandbox project to stop")
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
	if _, err := d.run(ctx, d.Podman, "network", "exists", env.Project+"_default"); err == nil {
		if _, err := d.run(ctx, d.Podman, "network", "rm", "-f", env.Project+"_default"); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
