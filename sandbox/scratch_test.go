package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ouroboric-dev/gungnir"
	"go.yaml.in/yaml/v3"
)

func scratchSpec(parent string) gungnir.SandboxSpec {
	return gungnir.SandboxSpec{Run: "20261016-101500-a1b2c3", Name: "scratch/design", Scratch: true, Parent: parent,
		Leaf: parent + "/scratch/design", Egress: []string{"api.anthropic.com"}}
}

func TestAScratchSandboxMountsOneFolderAndNothingElse(t *testing.T) {
	tmp := t.TempDir()
	c := cfg()
	c.Mounts = append(c.Mounts, PathMap{Host: tmp, Engine: "/mnt/wsl/cfg"})
	sp := scratchSpec("/home/ana/ygg/proj/.factory/runs/r1")
	g, err := Generate(filepath.Join(tmp, "sandbox"), sp, c)
	if err != nil {
		t.Fatal(err)
	}
	var cf composeFile
	raw, _ := os.ReadFile(g.Compose)
	if err := yaml.Unmarshal(raw, &cf); err != nil {
		t.Fatal(err)
	}
	wantVols := []string{"/mnt/wsl/ygg-bind/proj/.factory/runs/r1/scratch/design:/u/scratch/design:Z"}
	if got := cf.Services["work"].Volumes; strings.Join(got, "|") != strings.Join(wantVols, "|") {
		t.Errorf("work volumes = %q, want only the scratch folder", got)
	}
	if strings.Contains(string(raw), ".git") {
		t.Errorf("a scratch sandbox mentions a git dir:\n%s", raw)
	}
	if dc, _ := os.ReadFile(g.Devcontainer); !strings.Contains(string(dc), `"workspaceFolder": "/u/scratch/design"`) {
		t.Errorf("devcontainer.json = %s", dc)
	}
	if err := Validate(g, sp, c); err != nil {
		t.Errorf("Validate() = %v on what Generate wrote", err)
	}
	elsewhere := Config{Images: c.Images, UID: 1000, GID: 1000, Mounts: []PathMap{{Host: "/home/ana/other", Engine: "/mnt/x"}}}
	if _, err := Generate(filepath.Join(tmp, "unseen"), scratchSpec("/home/ana/ygg/proj/.factory/runs/r1"), elsewhere); err == nil || !strings.Contains(err.Error(), "can't see") {
		t.Errorf("a scratch folder the engine can't see: %v", err)
	}
}

func TestUpStartsAScratchSandbox(t *testing.T) {
	d, log, _ := fakeEngine(t)
	parent := t.TempDir()
	sp := scratchSpec(parent)
	if err := os.MkdirAll(sp.Leaf, 0o755); err != nil {
		t.Fatal(err)
	}
	d.cfg.Mounts = []PathMap{{Host: filepath.Dir(parent), Engine: "/mnt/wsl/t"}, {Host: d.work, Engine: "/mnt/wsl/w"}}
	env, err := d.Up(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if env.Workdir != "/u/scratch/design" || env.Name != "scratch/design" {
		t.Errorf("env = %+v", env)
	}
	if got := logOf(t, log); !strings.Contains(got, "--workspace-folder "+sp.Leaf) {
		t.Errorf("devcontainer was not pointed at the scratch folder:\n%s", got)
	}
}

func TestASandboxWithNoStackStartsTheFactoryLayerOnTheNodeImage(t *testing.T) {
	if FactoryImages() != ImagesFor(FactoryStack) {
		t.Errorf("FactoryImages() = %+v, want %+v", FactoryImages(), ImagesFor(FactoryStack))
	}
	tmp := t.TempDir()
	c := cfg()
	c.Images = FactoryImages()
	c.Mounts = append(c.Mounts, PathMap{Host: tmp, Engine: "/mnt/wsl/cfg"})
	sp := scratchSpec("/home/ana/ygg/proj/.factory/runs/r1")
	if sp.Stack != "" {
		t.Fatalf("the scratch spec names a stack: %q", sp.Stack)
	}
	if c.ImagesOf(sp) != FactoryImages() {
		t.Errorf("ImagesOf(no stack) = %+v, want the factory layer", c.ImagesOf(sp))
	}
	g, err := Generate(filepath.Join(tmp, "sandbox"), sp, c)
	if err != nil {
		t.Fatal(err)
	}
	var cf composeFile
	raw, _ := os.ReadFile(g.Compose)
	if err := yaml.Unmarshal(raw, &cf); err != nil {
		t.Fatal(err)
	}
	if got := cf.Services["work"].Image; got != FactoryImages().Work {
		t.Errorf("work image = %q, want %q", got, FactoryImages().Work)
	}
	if got := cf.Services["fw"].Image; got != FactoryImages().Firewall {
		t.Errorf("firewall image = %q, want %q", got, FactoryImages().Firewall)
	}
	if len(cf.Services) != 2 || len(cf.Networks) != 0 {
		t.Errorf("services = %d, networks = %d; want only work and fw, and no services network", len(cf.Services), len(cf.Networks))
	}
	if got := cf.Services["work"].Volumes; len(got) != 1 || !strings.Contains(got[0], "/u/scratch/design") {
		t.Errorf("work volumes = %q, want the one scratch volume", got)
	}
}
