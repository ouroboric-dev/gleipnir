package sandbox

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ouroboric-dev/gungnir"
)

func named(name string) gungnir.SandboxSpec {
	s := spec("/home/ana/ygg/proj")
	s.Name = name
	s.Leaf = "/home/ana/ygg/proj/" + name
	s.GitDir = "/home/ana/ygg/proj/.git/modules/" + name
	return s
}

func TestTwoLeavesNeverShareASandboxProject(t *testing.T) {
	names := []string{"repos/web-app", "repos/webapp", "repos/web/app", "repos/web.app", "repos/web_app"}
	seen := map[string]string{}
	for _, n := range names {
		p := Project(named(n))
		if other, dup := seen[p]; dup {
			t.Errorf("%s and %s share the project %s: one leaf's Down would stop the other's sandbox", n, other, p)
		}
		seen[p] = n
		if !regexp.MustCompile(`^ygg[a-z0-9]+$`).MatchString(p) {
			t.Errorf("project %q must be lower-case letters and digits only (the devcontainer CLI strips the rest)", p)
		}
		if p != Project(named(n)) {
			t.Errorf("Project(%s) changes between calls", n)
		}
	}
}

func TestTwoLeavesNeverShareAConfigurationFolder(t *testing.T) {
	seen := map[string]string{}
	for _, n := range []string{"repos/web-app", "repos/web/app", "repos/web.app", "repos/webapp"} {
		dir := ConfigDir("/work", named(n))
		if filepath.Dir(dir) != "/work" || strings.Contains(filepath.Base(dir), "/") {
			t.Errorf("ConfigDir(%s) = %q; want one folder directly under the work folder", n, dir)
		}
		if other, dup := seen[dir]; dup {
			t.Errorf("%s and %s share the folder %s", n, other, dir)
		}
		seen[dir] = n
	}
}
