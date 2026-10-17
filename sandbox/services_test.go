package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ouroboric-dev/gungnir"
	"go.yaml.in/yaml/v3"
)

const (
	pgImage  = "docker.io/library/postgres:17.2@sha256:1111111111111111111111111111111111111111111111111111111111111111"
	s3Image  = "docker.io/chrislusf/seaweedfs:3.80@sha256:2222222222222222222222222222222222222222222222222222222222222222"
	stackImg = "docker.io/library/golang:1.26.7-bookworm@sha256:e8c859f5632dcfde7b32d2012b4351728f6437930887c2f6a91ea242459e5514"
)

func withServices() gungnir.SandboxSpec {
	s := spec("/home/ana/ygg/proj")
	s.Services = []gungnir.Service{
		{Name: "seaweedfs", Image: s3Image, Env: nil, Ports: []int{8333}},
		{Name: "postgres", Image: pgImage, Env: map[string]string{"POSTGRES_DB": "app", "POSTGRES_HOST_AUTH_METHOD": "trust"}, Ports: []int{5432}},
	}
	return s
}

func TestServicesStartBesideTheWorkContainerAndTheFirewall(t *testing.T) {
	tmp := t.TempDir()
	c := cfg()
	c.Mounts = append(c.Mounts, PathMap{Host: tmp, Engine: "/mnt/wsl/cfg"})
	g, err := Generate(filepath.Join(tmp, "sandbox"), withServices(), c)
	if err != nil {
		t.Fatal(err)
	}
	var cf composeFile
	raw, _ := os.ReadFile(g.Compose)
	if err := yaml.Unmarshal(raw, &cf); err != nil {
		t.Fatal(err)
	}
	pg, s3, work, fw := cf.Services["postgres"], cf.Services["seaweedfs"], cf.Services["work"], cf.Services["fw"]
	if pg.Image != pgImage || pg.PullPolicy != "never" || pg.Environment["POSTGRES_DB"] != "app" || pg.Labels[LabelRun] != "20261016-101500-a1b2c3" {
		t.Errorf("postgres = %+v", pg)
	}
	if !slices.Equal(pg.SecurityOpt, []string{"no-new-privileges:true"}) || len(pg.CapAdd) != 0 || pg.NetworkMode != "" || len(pg.Volumes) != 0 || pg.User != "" || pg.UsernsMode != "" {
		t.Errorf("postgres = %+v; a service gets no capability, no mount and the image's own user, and shares no namespace", pg)
	}
	if s3.Image != s3Image || len(s3.Environment) != 0 {
		t.Errorf("seaweedfs = %+v", s3)
	}
	for name, deps := range map[string][]string{"work": work.DependsOn, "fw": fw.DependsOn} {
		if !slices.Equal(deps, wantDeps(name)) {
			t.Errorf("%s depends on %v, want %v: the services are up before the firewall resolves them, and before the work container starts", name, deps, wantDeps(name))
		}
	}
	if !strings.Contains(string(raw), "command:") || strings.Count(string(raw), "command: []") != 0 {
		t.Errorf("a service with no command of its own must not override the image's:\n%s", raw)
	}
}

func wantDeps(name string) []string {
	if name == "fw" {
		return []string{"postgres", "seaweedfs"}
	}
	return []string{"fw", "postgres", "seaweedfs"}
}

func TestAServiceTheFactoryDidNotWriteIsRefusedBeforeItStarts(t *testing.T) {
	tmp := t.TempDir()
	c := cfg()
	c.Mounts = append(c.Mounts, PathMap{Host: tmp, Engine: "/mnt/wsl/cfg"})
	sp := withServices()
	g, err := Generate(filepath.Join(tmp, "sandbox"), sp, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(g, sp, c); err != nil {
		t.Fatalf("Validate() = %v on what Generate wrote", err)
	}
	edit := func(change func(services map[string]any)) {
		t.Helper()
		var cf map[string]any
		b, _ := os.ReadFile(g.Compose)
		if err := yaml.Unmarshal(b, &cf); err != nil {
			t.Fatal(err)
		}
		change(cf["services"].(map[string]any))
		out, _ := yaml.Marshal(cf)
		os.WriteFile(g.Compose, out, 0o644)
	}
	edit(func(svcs map[string]any) { svcs["postgres"].(map[string]any)["privileged"] = true })
	var pe *PolicyError
	if err := Validate(g, sp, c); err == nil || !errors.As(err, &pe) || !strings.Contains(err.Error(), "service postgres has privileged") {
		t.Errorf("a privileged service: Validate() = %v", err)
	}
	g, _ = Generate(filepath.Join(tmp, "sandbox"), sp, c)
	edit(func(svcs map[string]any) {
		svcs["postgres"].(map[string]any)["image"] = "docker.io/library/postgres:evil"
	})
	if err := Validate(g, sp, c); err == nil || !strings.Contains(err.Error(), "differs from what the factory generates") {
		t.Errorf("a swapped service image: Validate() = %v", err)
	}
	bad := withServices()
	bad.Services[1].Env = map[string]string{"POSTGRES_PASSWORD": "dev"}
	if _, err := Generate(filepath.Join(tmp, "other"), bad, c); err == nil {
		t.Error("a service that takes a password was accepted")
	}
}
