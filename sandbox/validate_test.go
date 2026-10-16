package sandbox

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// generated writes a fresh configuration and returns it with the spec and config that made it.
func generated(t *testing.T) (Generated, Config) {
	t.Helper()
	tmp := t.TempDir()
	c := cfg()
	c.Mounts = append(c.Mounts, PathMap{Host: tmp, Engine: "/mnt/wsl/cfg"})
	g, err := Generate(filepath.Join(tmp, "sandbox"), spec("/home/ana/ygg/proj"), c)
	if err != nil {
		t.Fatal(err)
	}
	return g, c
}

func edit(t *testing.T, path string, old, new string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), old) {
		t.Fatalf("%s has no %q to replace:\n%s", path, old, b)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(b), old, new, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestValidateAcceptsWhatGenerateWrote(t *testing.T) {
	g, c := generated(t)
	if err := Validate(g, spec("/home/ana/ygg/proj"), c); err != nil {
		t.Errorf("Validate() = %v", err)
	}
}

// mutate rewrites a YAML or JSON file through a map, so a test edits structure, not text.
func mutate(t *testing.T, path string, change func(m map[string]any)) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if strings.HasSuffix(path, ".json") {
		err = json.Unmarshal(b, &m)
	} else {
		err = yaml.Unmarshal(b, &m)
	}
	if err != nil {
		t.Fatal(err)
	}
	change(m)
	if strings.HasSuffix(path, ".json") {
		b, err = json.Marshal(m)
	} else {
		b, err = yaml.Marshal(m)
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func svc(m map[string]any, name string) map[string]any {
	return m["services"].(map[string]any)[name].(map[string]any)
}

// The escape test of spec §13 and §14, at the config: whatever an agent or a hijacked tool adds
// to the factory-owned files, Up must refuse before it starts anything.
func TestValidateRefusesHostileConfigurations(t *testing.T) {
	addVol := func(v string) func(map[string]any) {
		return func(m map[string]any) {
			w := svc(m, "work")
			w["volumes"] = append(w["volumes"].([]any), v)
		}
	}
	cases := map[string]struct {
		file   string // devcontainer, compose, hosts or egress
		change func(map[string]any)
		text   [2]string // for hosts and egress: old, new
		want   string
	}{
		"initializeCommand":         {file: "devcontainer", change: func(m map[string]any) { m["initializeCommand"] = "touch /tmp/pwned" }, want: "initializeCommand, which runs a command on the host"},
		"a postStartCommand":        {file: "devcontainer", change: func(m map[string]any) { m["postStartCommand"] = "curl evil" }, want: "postStartCommand"},
		"extra mounts":              {file: "devcontainer", change: func(m map[string]any) { m["mounts"] = []any{"source=/home/ana/.ssh,target=/ssh,type=bind"} }, want: "mounts"},
		"runArgs --privileged":      {file: "devcontainer", change: func(m map[string]any) { m["runArgs"] = []any{"--privileged"} }, want: "runArgs"},
		"an unknown key":            {file: "devcontainer", change: func(m map[string]any) { m["overrideCommand"] = false }, want: "overrideCommand"},
		"a second compose file":     {file: "devcontainer", change: func(m map[string]any) { m["dockerComposeFile"] = []any{"compose.yaml", "/leaf/override.yml"} }, want: "devcontainer.json differs"},
		"privileged in compose":     {file: "compose", change: func(m map[string]any) { svc(m, "work")["privileged"] = true }, want: "privileged, which removes"},
		"the engine's socket":       {file: "compose", change: addVol("/run/user/1000/podman/podman.sock:/run/podman.sock"), want: "reaches the container engine"},
		"the docker socket":         {file: "compose", change: addVol("/var/run/docker.sock:/var/run/docker.sock"), want: "reaches the container engine"},
		"the host's ssh keys":       {file: "compose", change: addVol("/home/ana/.ssh:/home/ygg/.ssh"), want: "compose.yaml differs"},
		"NET_ADMIN in work":         {file: "compose", change: func(m map[string]any) { svc(m, "work")["cap_add"] = []any{"NET_ADMIN"} }, want: "only the firewall sidecar holds NET_ADMIN"},
		"SYS_ADMIN in the firewall": {file: "compose", change: func(m map[string]any) { svc(m, "fw")["cap_add"] = []any{"NET_ADMIN", "SYS_ADMIN"} }, want: "only the firewall sidecar holds NET_ADMIN"},
		"host networking":           {file: "compose", change: func(m map[string]any) { svc(m, "work")["network_mode"] = "host" }, want: "network_mode"},
		"an API key":                {file: "compose", change: func(m map[string]any) { svc(m, "work")["environment"].(map[string]any)["ANTHROPIC_API_KEY"] = "sk-x" }, want: "ANTHROPIC_API_KEY"},
		"a swapped image":           {file: "compose", change: func(m map[string]any) { svc(m, "work")["image"] = "docker.io/evil/work:latest" }, want: "compose.yaml differs"},
		"a git dir mounted rw": {file: "compose", change: func(m map[string]any) {
			v := svc(m, "work")["volumes"].([]any)
			v[1] = strings.Replace(v[1].(string), ":ro,Z", ":Z", 1)
		}, want: "compose.yaml differs"},
		"a wider firewall list":     {file: "hosts", text: [2]string{"api.anthropic.com\n", "api.anthropic.com\nevil.example.com\n"}, want: "fw/hosts differs"},
		"a changed firewall script": {file: "egress", text: [2]string{"\"$t\" -P OUTPUT DROP", "\"$t\" -P OUTPUT ACCEPT"}, want: "fw/egress.sh differs"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			g, c := generated(t)
			path := map[string]string{"devcontainer": g.Devcontainer, "compose": g.Compose, "hosts": g.Hosts,
				"egress": filepath.Join(filepath.Dir(g.Hosts), "egress.sh")}[tc.file]
			if tc.change != nil {
				mutate(t, path, tc.change)
			} else {
				edit(t, path, tc.text[0], tc.text[1])
			}
			err := Validate(g, spec("/home/ana/ygg/proj"), c)
			var pe *PolicyError
			if !errors.As(err, &pe) || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Validate() = %v, want a *PolicyError naming %q", err, tc.want)
			}
		})
	}
}
