package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ouroboric-dev/gungnir"
	"go.yaml.in/yaml/v3"
)

// Root is where a sandbox mounts the mirror of the leaf's parent umbrella (sandbox spike: the
// leaf keeps its path relative to the umbrella, so its .git file still finds its git dir).
const Root = "/u"

// Home is the agent's HOME inside the work container: an empty, writable folder of the image, never
// anything from the host.
const Home = "/home/ygg"

// Label names the labels every container carries, so doctor finds leftovers.
const (
	LabelRun  = "dev.ouroboric.ygg.run"
	LabelLeaf = "dev.ouroboric.ygg.leaf"
)

// PathMap says that the engine sees the host path Host as Engine.
type PathMap struct{ Host, Engine string }

// Images are the two images a sandbox starts: the work container's (the realm's stack layer plus
// the factory layer) and the firewall sidecar's. Both are pinned by id or digest.
type Images struct{ Work, Firewall string }

// Config is the driver's settings, from factory.yaml's sandbox section and the pack's stack.
type Config struct {
	Mounts []PathMap
	Images Images
	UID    int // the operator's uid and gid: the work container runs as them, with keep-id
	GID    int
}

// MapPath returns the path the engine sees for host path p. With no mounts configured, the engine
// is taken to see the host's paths. With mounts, a path outside all of them is an error: the
// engine could not mount it.
func (c Config) MapPath(p string) (string, error) {
	if len(c.Mounts) == 0 {
		return p, nil
	}
	best := -1
	for i, m := range c.Mounts {
		if (p == m.Host || strings.HasPrefix(p, m.Host+"/")) && (best < 0 || len(m.Host) > len(c.Mounts[best].Host)) {
			best = i
		}
	}
	if best < 0 {
		return "", fmt.Errorf("the engine can't see %s: add a sandbox.mounts entry for it in factory.yaml", p)
	}
	m := c.Mounts[best]
	return m.Engine + strings.TrimPrefix(p, m.Host), nil
}

// Generated is where Generate wrote a sandbox's files.
type Generated struct {
	Dir          string // the configuration folder: outside the leaf, never mounted into the work container
	Compose      string
	Devcontainer string
	Hosts        string // the firewall's host list
}

// Project returns the compose project name of a sandbox: one per run and leaf. It is lower-case letters
// and digits only, because the devcontainer CLI strips everything else from the name it gives the
// engine, and Down finds containers by that name (found on a real engine, 2026-10-16).
func Project(s gungnir.SandboxSpec) string {
	return "ygg" + regexp.MustCompile(`[^a-z0-9]`).ReplaceAllString(strings.ToLower(s.Run+s.Name), "")
}

type composeFile struct {
	Name     string             `yaml:"name"`
	Services map[string]service `yaml:"services"`
}

type service struct {
	Image       string            `yaml:"image"`
	Command     []string          `yaml:"command"`
	User        string            `yaml:"user,omitempty"`
	UsernsMode  string            `yaml:"userns_mode"`
	CapAdd      []string          `yaml:"cap_add,omitempty"`
	CapDrop     []string          `yaml:"cap_drop,omitempty"`
	SecurityOpt []string          `yaml:"security_opt,omitempty"`
	NetworkMode string            `yaml:"network_mode,omitempty"`
	DependsOn   []string          `yaml:"depends_on,omitempty"`
	Environment map[string]string `yaml:"environment,omitempty"`
	Labels      map[string]string `yaml:"labels"`
	Volumes     []string          `yaml:"volumes"`
}

// Generate writes a sandbox's devcontainer.json, compose.yaml and firewall host list into dir,
// which must be outside the leaf. The files are the only configuration Up reads: nothing in the leaf
// can reach them or change them (spec §6.2). Generate doesn't check its own output; Up does, before
// every start (see Validate).
func Generate(dir string, spec gungnir.SandboxSpec, c Config) (Generated, error) {
	files, g, err := render(dir, spec, c)
	if err != nil {
		return Generated{}, err
	}
	if err := os.MkdirAll(filepath.Join(dir, "fw"), 0o755); err != nil {
		return Generated{}, err
	}
	for path, body := range files {
		if err := os.WriteFile(path, body, 0o644); err != nil {
			return Generated{}, err
		}
	}
	return g, nil
}

// render returns the files of a sandbox configuration in dir, by path, without writing them.
func render(dir string, spec gungnir.SandboxSpec, c Config) (map[string][]byte, Generated, error) {
	if err := spec.Validate(); err != nil {
		return nil, Generated{}, err
	}
	if c.Images.Work == "" || c.Images.Firewall == "" || c.UID <= 0 || c.GID <= 0 {
		return nil, Generated{}, errors.New("the driver needs both images and a non-root uid and gid")
	}
	for _, p := range []string{dir} {
		if rel, err := filepath.Rel(spec.Leaf, p); err == nil && filepath.IsLocal(rel) {
			return nil, Generated{}, fmt.Errorf("the configuration folder %s is inside the leaf %s", dir, spec.Leaf)
		}
	}
	leaf, err := c.MapPath(spec.Leaf)
	if err != nil {
		return nil, Generated{}, err
	}
	git, err := c.MapPath(spec.GitDir)
	if err != nil {
		return nil, Generated{}, err
	}
	fwDir := filepath.Join(dir, "fw")
	fwEngine, err := c.MapPath(fwDir)
	if err != nil {
		return nil, Generated{}, err
	}
	l := spec.Layout()
	labels := map[string]string{LabelRun: spec.Run, LabelLeaf: spec.Name}
	cf := composeFile{Name: Project(spec), Services: map[string]service{
		"fw": {
			Image: c.Images.Firewall, Command: []string{"sh", "/etc/ygg-fw/egress.sh", "/etc/ygg-fw/hosts"},
			// root of its own user namespace: keep-id alone would run it as the operator, who can't write rules
			User: "0:0", UsernsMode: "keep-id", CapAdd: []string{"NET_ADMIN"}, Labels: labels,
			Volumes: []string{fwEngine + ":/etc/ygg-fw:ro,Z"},
		},
		"work": {
			Image: c.Images.Work, Command: []string{"sleep", "infinity"},
			User: fmt.Sprintf("%d:%d", c.UID, c.GID), UsernsMode: "keep-id",
			CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"},
			NetworkMode: "service:fw", DependsOn: []string{"fw"},
			Environment: map[string]string{"HOME": Home}, Labels: labels,
			Volumes: []string{
				leaf + ":" + Root + "/" + l.Leaf + ":Z",
				git + ":" + Root + "/" + l.GitDir + ":ro,Z",
			},
		},
	}}
	dc := map[string]any{
		"name": Project(spec), "dockerComposeFile": "compose.yaml", "service": "work",
		"workspaceFolder": Root + "/" + l.Leaf, "updateRemoteUserUID": false, "shutdownAction": "stopCompose",
	}
	g := Generated{Dir: dir, Compose: filepath.Join(dir, "compose.yaml"), Devcontainer: filepath.Join(dir, "devcontainer.json"), Hosts: filepath.Join(fwDir, "hosts")}
	composeYAML, err := yaml.Marshal(cf)
	if err != nil {
		return nil, Generated{}, err
	}
	dcJSON, err := json.MarshalIndent(dc, "", "  ")
	if err != nil {
		return nil, Generated{}, err
	}
	hosts := strings.Join(spec.Egress, "\n")
	if hosts != "" {
		hosts += "\n"
	}
	return map[string][]byte{
		g.Compose: composeYAML, g.Devcontainer: append(dcJSON, '\n'), g.Hosts: []byte(hosts),
		filepath.Join(fwDir, "egress.sh"): []byte(EgressScript),
	}, g, nil
}
