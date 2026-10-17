package sandbox

import (
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ouroboric-dev/gungnir"
	"go.yaml.in/yaml/v3"
)

func spec(parent string) gungnir.SandboxSpec {
	return gungnir.SandboxSpec{Run: "20261016-101500-a1b2c3", Name: "repos/app", Parent: parent,
		Leaf: parent + "/repos/app", GitDir: parent + "/.git/modules/repos/app", Egress: []string{"api.anthropic.com", "proxy.golang.org"}}
}

func cfg() Config {
	return Config{Mounts: []PathMap{{Host: "/home/ana/ygg", Engine: "/mnt/wsl/ygg-bind"}},
		Images: Images{Work: "localhost/ygg-work:abc", Firewall: "localhost/ygg-fw:abc"}, UID: 1000, GID: 1000}
}

func TestMapPathUsesTheLongestMount(t *testing.T) {
	c := cfg()
	c.Mounts = append(c.Mounts, PathMap{Host: "/home/ana/ygg/special", Engine: "/mnt/other"})
	for host, want := range map[string]string{
		"/home/ana/ygg/proj/repos/app": "/mnt/wsl/ygg-bind/proj/repos/app",
		"/home/ana/ygg/special/x":      "/mnt/other/x",
		"/home/ana/ygg":                "/mnt/wsl/ygg-bind",
	} {
		if got, err := c.MapPath(host); err != nil || got != want {
			t.Errorf("MapPath(%s) = %q, %v; want %q", host, got, err, want)
		}
	}
	for _, p := range []string{"/home/ana/other", "/home/ana/yggdrasil/x"} {
		if _, err := c.MapPath(p); err == nil {
			t.Errorf("MapPath(%s) succeeded: the engine can't see it", p)
		}
	}
	if got, err := (Config{}).MapPath("/x/y"); err != nil || got != "/x/y" {
		t.Errorf("with no mounts the engine sees the host's paths: %q, %v", got, err)
	}
}

func TestGenerateWritesTheMirroredHardenedConfig(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "sandbox")
	c := cfg()
	c.Mounts = append(c.Mounts, PathMap{Host: tmp, Engine: "/mnt/wsl/cfg"})
	g, err := Generate(dir, spec("/home/ana/ygg/proj"), c)
	if err != nil {
		t.Fatal(err)
	}
	var cf composeFile
	raw, _ := os.ReadFile(g.Compose)
	if err := yaml.Unmarshal(raw, &cf); err != nil {
		t.Fatal(err)
	}
	work, fw := cf.Services["work"], cf.Services["fw"]
	wantVols := []string{
		"/mnt/wsl/ygg-bind/proj/repos/app:/u/repos/app:Z",
		"/mnt/wsl/ygg-bind/proj/.git/modules/repos/app:/u/.git/modules/repos/app:ro,Z",
	}
	if strings.Join(work.Volumes, "|") != strings.Join(wantVols, "|") {
		t.Errorf("work volumes = %q, want the leaf read-write and its git dir read-only, mirrored under /u", work.Volumes)
	}
	if work.NetworkMode != "service:fw" || work.User != "1000:1000" || work.UsernsMode != "keep-id" || fw.UsernsMode != "keep-id" ||
		len(work.CapAdd) != 0 || work.CapDrop[0] != "ALL" || fw.CapAdd[0] != "NET_ADMIN" {
		t.Errorf("work = %+v, fw = %+v; want keep-id on both, no added capability in work, and the firewall in its own sidecar", work, fw)
	}
	if !strings.HasPrefix(cf.Name, "ygg20261016101500a1b2c3reposapp") || len(cf.Name) != len("ygg20261016101500a1b2c3reposapp")+8 || work.Labels[LabelRun] != "20261016-101500-a1b2c3" {
		t.Errorf("project %q, labels %v", cf.Name, work.Labels)
	}
	if fw.User != "0:0" {
		t.Errorf("the firewall runs as %q; it must be root of its own namespace to write rules", fw.User)
	}
	if fw.Volumes[0] != "/mnt/wsl/cfg/sandbox/fw:/etc/ygg-fw:ro,Z" {
		t.Errorf("fw volumes = %q; the firewall reads only its own folder, read-only", fw.Volumes)
	}
	if hosts, _ := os.ReadFile(g.Hosts); string(hosts) != "api.anthropic.com\nproxy.golang.org\n" {
		t.Errorf("hosts = %q", hosts)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "fw", "egress.sh")); string(b) != EgressScript {
		t.Error("the firewall script was not written as embedded")
	}
	if dc, _ := os.ReadFile(g.Devcontainer); !strings.Contains(string(dc), `"workspaceFolder": "/u/repos/app"`) || strings.Contains(string(dc), "initializeCommand") {
		t.Errorf("devcontainer.json = %s", dc)
	}
}

func TestGenerateRefusesWhatCouldNotBeHardened(t *testing.T) {
	s := spec("/home/ana/ygg/proj")
	if _, err := Generate(filepath.Join(s.Leaf, ".devcontainer"), s, cfg()); err == nil {
		t.Error("a configuration folder inside the leaf was accepted: the agent could edit it")
	}
	c := cfg()
	c.Mounts = nil
	c.UID = 0
	if _, err := Generate(t.TempDir(), s, c); err == nil {
		t.Error("a root uid was accepted")
	}
	outside := spec("/home/ana/elsewhere")
	if _, err := Generate(t.TempDir(), outside, cfg()); err == nil || !strings.Contains(err.Error(), "can't see") {
		t.Errorf("a leaf the engine can't see: %v", err)
	}
}

// Review I-6: a '$' in a service's env value is written as '$$', so compose takes it literally and
// never expands it from the environment it runs in. gungnir refuses such a value already; this is the
// second layer.
func TestServiceEnvValuesAreWrittenLiterally(t *testing.T) {
	got := literalEnv(map[string]string{"A": "pre-${SECRET}", "B": "$HOME", "C": "plain", "D": "$$"})
	want := map[string]string{"A": "pre-$${SECRET}", "B": "$$HOME", "C": "plain", "D": "$$$$"}
	if !maps.Equal(got, want) {
		t.Errorf("literalEnv() = %v, want %v", got, want)
	}
	if literalEnv(nil) != nil {
		t.Error("literalEnv(nil) is not nil: a service with no env would get an empty environment key")
	}
}
