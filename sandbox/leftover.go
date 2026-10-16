package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

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

// StopLeftover removes the containers and the network of a leftover's project.
func (d *Driver) StopLeftover(ctx context.Context, l Leftover) error {
	return d.Down(ctx, gungnir.Env{Project: l.Project, Name: l.Leaf, Container: l.Container})
}
