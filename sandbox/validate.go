package sandbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/ouroboric-dev/gungnir"
	"go.yaml.in/yaml/v3"
)

// PolicyError is a sandbox configuration that breaks a hardening rule (spec §6.2). Up returns it
// before anything starts; Odin stops the run at the hard approval point policy-violation.
type PolicyError struct{ Problems []string }

func (e *PolicyError) Error() string {
	return "the sandbox configuration breaks the hardening rules:\n  " + strings.Join(e.Problems, "\n  ")
}

// devcontainer.json keys that run commands on the host or widen the container. Naming them gives
// the person a reason; any other key beyond the allowed ones is refused too.
var forbiddenDevcontainer = map[string]string{
	"initializeCommand":    "runs a command on the host before the container starts",
	"onCreateCommand":      "runs a command in the container before the factory's commands",
	"updateContentCommand": "runs a command in the container before the factory's commands",
	"postCreateCommand":    "runs a command in the container before the factory's commands",
	"postStartCommand":     "runs a command in the container before the factory's commands",
	"postAttachCommand":    "runs a command in the container before the factory's commands",
	"mounts":               "adds mounts the factory didn't choose",
	"workspaceMount":       "changes what the sandbox mounts",
	"runArgs":              "passes engine flags, such as --privileged",
	"privileged":           "removes the container's isolation",
	"capAdd":               "adds capabilities",
	"securityOpt":          "changes the container's security options",
	"containerEnv":         "sets variables the factory didn't choose",
	"remoteEnv":            "sets variables the factory didn't choose",
	"features":             "installs code from outside the pinned images",
	"image":                "replaces the factory's compose file",
	"build":                "replaces the factory's compose file",
	"containerUser":        "changes the user the agent runs as",
	"remoteUser":           "changes the user the agent runs as",
}

var allowedDevcontainer = map[string]bool{"name": true, "dockerComposeFile": true, "service": true,
	"workspaceFolder": true, "updateRemoteUserUID": true, "shutdownAction": true}

// compose service keys that open the host, the network or the engine to a container.
var forbiddenCompose = map[string]string{
	"privileged": "removes the container's isolation", "devices": "gives the container host devices",
	"pid": "shares the host's processes", "ipc": "shares the host's memory", "uts": "shares the host's names",
	"cgroup": "changes the container's cgroup", "cgroup_parent": "changes the container's cgroup",
	"sysctls": "changes kernel settings", "volumes_from": "mounts what another container mounts",
	"ports": "publishes a port on the host", "extra_hosts": "changes name resolution", "dns": "changes name resolution",
	"build": "builds code on the host's engine", "env_file": "reads variables from a file",
	"secrets": "mounts secrets", "configs": "mounts configuration", "tmpfs": "adds mounts the factory didn't choose",
	"entrypoint": "replaces the container's command", "group_add": "adds groups", "external_links": "links containers",
	"links": "links containers", "runtime": "changes the container runtime",
}

var (
	engineSocket = regexp.MustCompile(`(?i)(docker|podman|containerd|crio)[^/]*\.sock|/var/run/|/run/(user|podman|docker)`)
	secretName   = regexp.MustCompile(`(?i)(API_?KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)`)
)

// Validate reads the files Generate wrote and refuses them if they break a hardening rule, or differ
// at all from what the factory generates for spec and c. The first check names what a person must
// not add (spec §6.2: initializeCommand, extra mounts, --privileged, an engine socket); the second
// leaves no room for anything the first doesn't name. Up calls it before every start, so a file
// changed since Generate never runs.
func Validate(g Generated, spec gungnir.SandboxSpec, c Config) error {
	var problems []string
	say := func(f string, a ...any) { problems = append(problems, fmt.Sprintf(f, a...)) }

	dcRaw, err := os.ReadFile(g.Devcontainer)
	if err != nil {
		return err
	}
	var dc map[string]any
	if err := json.Unmarshal(dcRaw, &dc); err != nil {
		say("devcontainer.json isn't plain JSON: %v", err)
	}
	for _, k := range sortedKeys(dc) {
		if why, bad := forbiddenDevcontainer[k]; bad {
			say("devcontainer.json has %s, which %s", k, why)
		} else if !allowedDevcontainer[k] {
			say("devcontainer.json has %s, which the factory doesn't set", k)
		}
	}

	cfRaw, err := os.ReadFile(g.Compose)
	if err != nil {
		return err
	}
	var cf map[string]any
	if err := yaml.Unmarshal(cfRaw, &cf); err != nil {
		say("compose.yaml isn't YAML: %v", err)
	}
	services, _ := cf["services"].(map[string]any)
	for _, name := range sortedKeys(services) {
		svc, _ := services[name].(map[string]any)
		scanService(name, svc, say)
	}

	if len(problems) == 0 {
		problems = append(problems, differences(g, spec, c)...)
	}
	if len(problems) > 0 {
		return &PolicyError{Problems: problems}
	}
	return nil
}

func scanService(name string, svc map[string]any, say func(string, ...any)) {
	for _, k := range sortedKeys(svc) {
		if why, bad := forbiddenCompose[k]; bad {
			say("compose.yaml: service %s has %s, which %s", name, k, why)
		}
	}
	if add, _ := svc["cap_add"].([]any); len(add) > 0 && (name != "fw" || len(add) != 1 || add[0] != "NET_ADMIN") {
		say("compose.yaml: service %s adds capabilities %v; only the firewall sidecar holds NET_ADMIN", name, add)
	}
	if mode, _ := svc["network_mode"].(string); mode != "" && mode != "service:fw" {
		say("compose.yaml: service %s uses network_mode %q; the work container joins the firewall's network namespace", name, mode)
	}
	vols, _ := svc["volumes"].([]any)
	for _, v := range vols {
		if s, _ := v.(string); engineSocket.MatchString(s) {
			say("compose.yaml: service %s mounts %q, which reaches the container engine", name, s)
		}
	}
	if env, ok := svc["environment"].(map[string]any); ok {
		for _, k := range sortedKeys(env) {
			if secretName.MatchString(k) {
				say("compose.yaml: service %s sets %s; credentials go to one command at a time, never into the container", name, k)
			}
		}
	}
}

// differences compares the files with what the factory renders for this sandbox, and says what
// differs.
func differences(g Generated, spec gungnir.SandboxSpec, c Config) []string {
	want, _, err := render(g.Dir, spec, c)
	if err != nil {
		return []string{err.Error()}
	}
	var out []string
	for _, f := range []struct {
		name, path string
		parse      func([]byte) (any, error)
	}{
		{"devcontainer.json", g.Devcontainer, parseJSON},
		{"compose.yaml", g.Compose, parseYAML},
		{"fw/hosts", g.Hosts, parseRaw},
		{"fw/egress.sh", filepath.Join(filepath.Dir(g.Hosts), "egress.sh"), parseRaw},
	} {
		got, err := readParsed(f.path, f.parse)
		exp, _ := f.parse(want[f.path])
		switch {
		case err != nil:
			out = append(out, fmt.Sprintf("%s can't be read: %v", f.name, err))
		case !reflect.DeepEqual(got, exp):
			out = append(out, f.name+" differs from what the factory generates for this sandbox")
		}
	}
	return out
}

func readParsed(path string, parse func([]byte) (any, error)) (any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parse(b)
}

func parseJSON(b []byte) (any, error) {
	var v any
	return v, json.Unmarshal(b, &v)
}

func parseYAML(b []byte) (any, error) {
	var v any
	dec := yaml.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var extra any
	if err := dec.Decode(&extra); err == nil {
		return nil, errors.New("more than one YAML document")
	}
	return v, nil
}

func parseRaw(b []byte) (any, error) { return string(b), nil }

func sortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
