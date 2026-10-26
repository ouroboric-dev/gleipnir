package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ouroboric-dev/gungnir"
)

// The tests of the model network (local-models spec §3.7, §5.3): a sandbox whose spec names a model
// server joins the server's internal network through the firewall, which opens the server's name on
// its one port and nothing else.

var models = &gungnir.ModelServer{Network: "ygg-models", Name: "ygg-models-server", Port: 8090}

// generateIn writes the configuration of sp in a fresh folder the engine sees as /mnt/wsl/cfg.
func generateIn(t *testing.T, sp gungnir.SandboxSpec) (Generated, Config) {
	t.Helper()
	tmp := t.TempDir()
	c := cfg()
	c.Mounts = append(c.Mounts, PathMap{Host: tmp, Engine: "/mnt/wsl/cfg"})
	g, err := Generate(filepath.Join(tmp, "sandbox"), sp, c)
	if err != nil {
		t.Fatal(err)
	}
	return g, c
}

func TestModelsNetworkIsGenerated(t *testing.T) {
	for name, base := range map[string]gungnir.SandboxSpec{"no services": spec("/home/ana/ygg/proj"), "services": withServices()} {
		t.Run(name, func(t *testing.T) {
			sp := base
			sp.Models = models
			g, c := generateIn(t, sp)
			m := composeMap(t, g.Compose)
			declared, _ := m["networks"].(map[string]any)
			want := map[string]any{"external": true, "name": "ygg-models"}
			if got, _ := declared[ModelsNetwork].(map[string]any); !reflect.DeepEqual(got, want) {
				t.Errorf("networks.%s = %v, want %v", ModelsNetwork, declared[ModelsNetwork], want)
			}
			if d, ok := declared["default"]; !ok || d == nil || len(d.(map[string]any)) != 0 {
				t.Errorf("networks.default = %v; it is declared, plain, so the firewall keeps its route to the listed hosts", d)
			}
			wantFw := []string{"default", ModelsNetwork}
			if len(base.Services) > 0 {
				wantFw = []string{"default", ServicesNetwork, ModelsNetwork}
			}
			if got := networksOf(m, "fw"); !slices.Equal(got, wantFw) {
				t.Errorf("fw is on networks %v, want %v", got, wantFw)
			}
			for _, v := range base.Services {
				if got := networksOf(m, v.Name); !slices.Equal(got, []string{ServicesNetwork}) {
					t.Errorf("service %s is on %v; only the firewall joins the model network", v.Name, got)
				}
			}

			// The work container is exactly what it is without a model server.
			plain, _ := generateIn(t, base)
			if got, was := svc(m, "work"), svc(composeMap(t, plain.Compose), "work"); !reflect.DeepEqual(got, was) {
				t.Errorf("work = %v\nwithout models it is %v", got, was)
			}

			services, _ := os.ReadFile(g.Services)
			was, _ := os.ReadFile(plain.Services)
			if want := string(was) + "ygg-models-server 8090\n"; string(services) != want {
				t.Errorf("fw/services = %q, want %q: the server's name on its one port, after the services", services, want)
			}
			if hosts, _ := os.ReadFile(g.Hosts); string(hosts) != "api.anthropic.com\nproxy.golang.org\n" {
				t.Errorf("fw/hosts = %q; the model server is no host of the open internet", hosts)
			}
			if err := Validate(g, sp, c); err != nil {
				t.Errorf("Validate() = %v on what Generate wrote", err)
			}
		})
	}
}

// The golden files in testdata/nomodels were written by Generate at gleipnir 97f2aba (main before the
// model network): a spec without Models must still get them byte for byte.
func TestNoModelsGeneratesWhatItDidBefore(t *testing.T) {
	scratch := gungnir.SandboxSpec{Run: "20261016-101500-a1b2c3", Name: "scratch/design", Scratch: true, Parent: "/home/ana/ygg/proj",
		Leaf: "/home/ana/ygg/proj/scratch/design", Egress: []string{"api.anthropic.com"}}
	for name, sp := range map[string]gungnir.SandboxSpec{"plain": spec("/home/ana/ygg/proj"), "services": withServices(), "scratch": scratch} {
		t.Run(name, func(t *testing.T) {
			g, _ := generateIn(t, sp)
			for base, path := range map[string]string{"compose.yaml": g.Compose, "devcontainer.json": g.Devcontainer, "hosts": g.Hosts, "services": g.Services} {
				got, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				want, err := os.ReadFile(filepath.Join("testdata", "nomodels", name, base))
				if err != nil {
					t.Fatal(err)
				}
				if string(got) != string(want) {
					t.Errorf("%s differs from what main generated:\ngot:\n%s\nwant:\n%s", base, got, want)
				}
			}
		})
	}
}

func TestValidateRefusesAnotherExternalNetwork(t *testing.T) {
	withModels := spec("/home/ana/ygg/proj")
	withModels.Models = models
	for name, tc := range map[string]struct {
		sp     gungnir.SandboxSpec
		change func(m map[string]any)
	}{
		"an external network beside the model network": {withModels, func(m map[string]any) {
			m["networks"].(map[string]any)["outside"] = map[string]any{"external": true, "name": "podman"}
		}},
		"the model network pointed at another network": {withModels, func(m map[string]any) {
			m["networks"].(map[string]any)[ModelsNetwork] = map[string]any{"external": true, "name": "podman"}
		}},
		"the model network under another key": {withModels, func(m map[string]any) {
			nets := m["networks"].(map[string]any)
			nets["llm"] = nets[ModelsNetwork]
			delete(nets, ModelsNetwork)
		}},
		"an external network in a spec without models": {spec("/home/ana/ygg/proj"), func(m map[string]any) {
			m["networks"] = map[string]any{"default": map[string]any{}, ModelsNetwork: map[string]any{"external": true, "name": "ygg-models"}}
		}},
		"external written the way YAML 1.1 reads it": {spec("/home/ana/ygg/proj"), func(m map[string]any) {
			m["networks"] = map[string]any{"default": map[string]any{"external": "yes"}}
		}},
		"external as a map that names the network": {withServices(), func(m map[string]any) {
			m["networks"].(map[string]any)[ServicesNetwork] = map[string]any{"external": map[string]any{"name": "podman"}}
		}},
		"a plain network that names an existing one": {withServices(), func(m map[string]any) {
			m["networks"].(map[string]any)["default"] = map[string]any{"name": "podman"}
		}},
	} {
		t.Run(name, func(t *testing.T) {
			g, c := generateIn(t, tc.sp)
			mutate(t, g.Compose, tc.change)
			err := Validate(g, tc.sp, c)
			var pe *PolicyError
			if !errors.As(err, &pe) || !strings.Contains(err.Error(), "the factory did not make") {
				t.Errorf("Validate() = %v; want a *PolicyError that names a network the factory did not make", err)
			}
		})
	}
}

func TestUpRefusesANetworkThatIsNotInternal(t *testing.T) {
	d, log, sp := fakeEngine(t)
	sp.Models = models
	for answer, why := range map[string]string{"false": "an open network", "": "no answer", "True": "anything but true"} {
		t.Setenv("STUB_NET_INTERNAL", answer)
		_, err := d.Up(context.Background(), sp)
		if err == nil || !strings.Contains(err.Error(), "ygg-models") || !strings.Contains(err.Error(), "internal") {
			t.Errorf("%s: Up() = %v; want a refusal that names the network and says it must be internal", why, err)
		}
	}
	t.Setenv("STUB_NET_INTERNAL", "true")
	t.Setenv("STUB_NET_INSPECT_EXIT", "125")
	if _, err := d.Up(context.Background(), sp); err == nil || !strings.Contains(err.Error(), "ygg-models") {
		t.Errorf("a network that can't be inspected: Up() = %v; want a refusal", err)
	}
	got := logOf(t, log)
	if !strings.Contains(got, "podman network inspect --format {{.Internal}} ygg-models") {
		t.Errorf("the network was not inspected:\n%s", got)
	}
	if strings.Contains(got, "devcontainer up") {
		t.Errorf("the sandbox started on a network that is not internal:\n%s", got)
	}

	t.Setenv("STUB_NET_INSPECT_EXIT", "0")
	env, err := d.Up(context.Background(), sp)
	if err != nil {
		t.Fatalf("an internal network: Up() = %v", err)
	}
	got = logOf(t, log)
	if i, j := strings.LastIndex(got, "podman network inspect"), strings.LastIndex(got, "devcontainer up"); i < 0 || j < i {
		t.Errorf("the network is inspected before compose runs:\n%s", got)
	}
	// The model network is the server's: Down removes the sandbox's own networks and never it.
	if err := d.Down(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(logOf(t, log), "\n") {
		if strings.HasPrefix(line, "podman network") && strings.Contains(line, " rm") && strings.Contains(line, "ygg-models") {
			t.Errorf("Down removed the model network: %s", line)
		}
	}

	// A spec without a model server inspects no network.
	d2, log2, plain := fakeEngine(t)
	if _, err := d2.Up(context.Background(), plain); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logOf(t, log2), "network inspect") {
		t.Error("a sandbox without a model server inspected a network")
	}
}

// A service named like the model server would share its name in the firewall's services file: the
// firewall would open the service's ports on the server's address too, such as 8080, past the gate.
func TestModelsRefusesAServiceNamedLikeTheServer(t *testing.T) {
	sp := withServices()
	sp.Models = &gungnir.ModelServer{Network: "ygg-models", Name: "postgres", Port: 8090}
	tmp := t.TempDir()
	c := cfg()
	c.Mounts = append(c.Mounts, PathMap{Host: tmp, Engine: "/mnt/wsl/cfg"})
	if _, err := Generate(filepath.Join(tmp, "sandbox"), sp, c); err == nil || !strings.Contains(err.Error(), "postgres") {
		t.Errorf("Generate() = %v; want a refusal of the shared name", err)
	}
}
