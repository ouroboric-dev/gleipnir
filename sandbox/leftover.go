package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/ouroboric-dev/gungnir"
)

// Leftover is a container a ygg run started, as the engine lists it. ygg doctor finds them by label
// (spec §12): a ygg that was killed leaves its sandboxes behind.
type Leftover struct {
	Run       string
	Leaf      string
	Project   string // the compose project, which Down needs
	Container string
	State     string
}

// Leftovers lists every container that carries the run label, running or not, sorted by run, leaf
// and container.
func (d *Driver) Leftovers(ctx context.Context) ([]Leftover, error) {
	out, err := d.run(ctx, d.Podman, "ps", "-a", "--filter", "label="+LabelRun, "--format", "json")
	if err != nil {
		return nil, err
	}
	var rows []struct {
		ID     string            `json:"Id"`
		State  string            `json:"State"`
		Labels map[string]string `json:"Labels"`
	}
	if err := json.Unmarshal(out, &rows); err != nil {
		return nil, fmt.Errorf("the engine's container list can't be read: %w", err)
	}
	var ls []Leftover
	for _, r := range rows {
		ls = append(ls, Leftover{Run: r.Labels[LabelRun], Leaf: r.Labels[LabelLeaf], Project: r.Labels["com.docker.compose.project"],
			Container: r.ID, State: r.State})
	}
	sort.Slice(ls, func(i, j int) bool {
		a, b := ls[i], ls[j]
		return a.Run+"\x00"+a.Leaf+"\x00"+a.Container < b.Run+"\x00"+b.Leaf+"\x00"+b.Container
	})
	return ls, nil
}

// StopLeftover removes the containers and the networks of a leftover's project.
func (d *Driver) StopLeftover(ctx context.Context, l Leftover) error {
	return d.Down(ctx, gungnir.Env{Project: l.Project, Name: l.Leaf, Container: l.Container})
}

// PodLeftover is a compose pod of a sandbox that holds no container, as the engine lists it. Compose
// makes a pod per project (named pod_ plus the project) and leaves it behind when its containers go;
// a pod in state Created is not stopped, so podman pod prune keeps it. The pod carries no label, so
// its name is the only tie to its sandbox (backlog B-138).
type PodLeftover struct {
	Project string // the compose project the pod's name ends with, which a run's Project() gave it
	Pod     string // the pod's name
	State   string
}

// podPrefix starts the name of every pod compose makes for a sandbox: pod_ plus a project, which
// starts with ygg.
const podPrefix = "pod_ygg"

// PodLeftovers lists the pods of the factory's sandboxes that hold no container, sorted by project.
// A pod with containers is not listed: Leftovers finds those by label, and StopLeftover removes the
// pod with them. A pod whose name does not start with pod_ygg is never listed. A sandbox that is
// still starting has such a pod for a moment, so ygg doctor removes only the pods of runs no live ygg
// holds: it matches Project against RunPrefix of each run id, and calls RemovePod for the rest.
func (d *Driver) PodLeftovers(ctx context.Context) ([]PodLeftover, error) {
	out, err := d.run(ctx, d.Podman, "pod", "ls", "--format", "json")
	if err != nil {
		return nil, err
	}
	var rows []struct {
		Name       string            `json:"Name"`
		Status     string            `json:"Status"`
		Containers []json.RawMessage `json:"Containers"`
	}
	if err := json.Unmarshal(out, &rows); err != nil {
		return nil, fmt.Errorf("the engine's pod list can't be read: %w", err)
	}
	var ls []PodLeftover
	for _, r := range rows {
		if strings.HasPrefix(r.Name, podPrefix) && len(r.Containers) == 0 {
			ls = append(ls, PodLeftover{Project: strings.TrimPrefix(r.Name, "pod_"), Pod: r.Name, State: r.Status})
		}
	}
	sort.Slice(ls, func(i, j int) bool { return ls[i].Project < ls[j].Project })
	return ls, nil
}

// RemovePod removes a pod PodLeftovers listed, without force: a pod that has gained a container
// since is an error, not a removal.
func (d *Driver) RemovePod(ctx context.Context, l PodLeftover) error {
	return d.removePod(ctx, l.Project, false)
}

// DevcontainerVersion is the version of the devcontainer CLI the factory was tested with (sandbox
// spike, decided 2026-10-14).
const DevcontainerVersion = "0.89.0"

// Info is what ygg doctor checks about the engine.
type Info struct {
	Rootless bool   // the engine runs without root: a container escape lands as the operator's user
	Podman   string // the engine's version
}

// Info asks the engine about itself.
func (d *Driver) Info(ctx context.Context) (Info, error) {
	out, err := d.run(ctx, d.Podman, "info", "--format", "{{.Host.Security.Rootless}} {{.Version.Version}}")
	if err != nil {
		return Info{}, err
	}
	var rootless, version string
	if _, err := fmt.Sscan(string(out), &rootless, &version); err != nil || (rootless != "true" && rootless != "false") {
		return Info{}, fmt.Errorf("the engine's answer can't be read: %q", out)
	}
	return Info{Rootless: rootless == "true", Podman: version}, nil
}

// DevcontainerCLI returns the version the devcontainer CLI reports.
func (d *Driver) DevcontainerCLI(ctx context.Context) (string, error) {
	out, err := d.run(ctx, d.Devcontainer, "--version")
	return strings.TrimSpace(string(out)), err
}
