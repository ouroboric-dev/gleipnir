//go:build sandbox

package sandbox

// The model network on a real engine (local-models spec §3.7, §5.3 items 1, 4 and 5), with the same
// environment as TestSandboxDriverOnARealEngine. A stub model server, on an internal network of the
// test's own, answers HTTP on the gate's port and on 8080, as llama-server and the gate do. It is node's
// http module in the firewall image (node is that image's base, and itDriver builds it), so the test
// pulls nothing. The network and the stub are named for this run alone and removed at the end; the test
// touches nothing else on the engine.
//
// Run: go test -tags sandbox -run TestIntegrationModelNetwork -v -timeout 40m ./sandbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ouroboric-dev/gungnir"
)

func TestIntegrationModelNetwork(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Minute)
	defer cancel()
	d, tree := itDriver(t, ctx)
	podman := func(args ...string) (string, error) {
		out, err := d.run(ctx, d.Podman, args...)
		return strings.TrimSpace(string(out)), err
	}
	b := make([]byte, 4)
	rand.Read(b)
	suffix := hex.EncodeToString(b)
	network, open, server := "lmit-models-"+suffix, "lmit-open-"+suffix, "lmit-server-"+suffix
	const gate = 8090

	// Cleanups run last in, first out: the stub goes before its network.
	for _, args := range [][]string{{"network", "create", "--internal", network}, {"network", "create", open}} {
		if _, err := podman(args...); err != nil {
			t.Fatal(err)
		}
		name := args[len(args)-1]
		t.Cleanup(func() {
			if _, err := d.run(context.Background(), d.Podman, "network", "rm", name); err != nil {
				t.Errorf("removing the test's network %s: %v", name, err)
			}
		})
	}
	stub := `const http = require("http");
for (const port of [8080, ` + strconv.Itoa(gate) + `]) http.createServer((q, r) => r.end("stub " + port + "\n")).listen(port, "0.0.0.0");`
	if _, err := podman("run", "-d", "--pull=never", "--name", server, "--network", network, "--entrypoint", "node",
		d.cfg.ImagesOf(gungnir.SandboxSpec{}).Firewall, "-e", stub); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := d.run(context.Background(), d.Podman, "rm", "-f", "-t", "0", server); err != nil {
			t.Errorf("removing the test's stub server %s: %v", server, err)
		}
	})
	// Control: the stub answers on both ports, so a port the sandbox can't reach is closed by the firewall,
	// not by a server that isn't listening.
	for _, port := range []int{8080, gate} {
		probe := `require("http").get("http://127.0.0.1:` + strconv.Itoa(port) + `/", r => process.exit(r.statusCode == 200 ? 0 : 1)).on("error", () => process.exit(1))`
		for i := 0; ; i++ {
			if _, err := podman("exec", server, "node", "-e", probe); err == nil {
				break
			} else if i == 50 {
				t.Fatalf("control: the stub does not answer on %d: %v", port, err)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	addr, err := podman("inspect", "--format", "{{(index .NetworkSettings.Networks \""+network+"\").IPAddress}}", server)
	if err != nil || addr == "" {
		t.Fatalf("the stub's address on %s: %q, %v", network, addr, err)
	}

	// §5.3 item 1: a model network with a route out is refused before anything starts.
	spec := itTree(t, tree)
	spec.Run = "lmit-" + suffix
	spec.Models = &gungnir.ModelServer{Network: open, Name: server, Port: gate}
	if env, err := d.Up(ctx, spec); err == nil || !strings.Contains(err.Error(), "not internal") {
		d.Down(context.Background(), env)
		t.Fatalf("Up() on a network that is not internal = %v; want a refusal", err)
	}
	if ids, _ := podman("ps", "-a", "-q", "--filter", "label="+LabelRun+"="+spec.Run); ids != "" {
		t.Fatalf("a refused sandbox left containers: %s", ids)
	}

	spec.Models.Network = network
	env, err := d.Up(ctx, spec)
	if err != nil {
		t.Fatalf("Up() = %v", err)
	}
	t.Cleanup(func() { d.Down(context.Background(), env) })

	// §3.7: the gate's port, by name, answers.
	if code, out := inSandbox(t, ctx, d, env, "curl", "-sS", "-m", "6", "http://"+server+":"+strconv.Itoa(gate)+"/"); code != 0 || out != "stub "+strconv.Itoa(gate) {
		t.Errorf("the gate's port by name: exit %d, %q; want the stub's answer", code, out)
	}
	reach := func(host string, port int) int {
		code, _ := inSandbox(t, ctx, d, env, "timeout", "6", "bash", "-c", "exec 3<>/dev/tcp/"+host+"/"+strconv.Itoa(port))
		return code
	}
	// §5.3 item 4: the server's own port is closed, by name and by address.
	for _, host := range []string{server, addr} {
		if code := reach(host, 8080); code == 0 {
			t.Errorf("%s:8080 is reachable from the work container; only the gate's port is open", host)
		}
	}
	if code := reach(addr, gate); code != 0 {
		t.Errorf("control: %s:%d by address: exit %d; the probe can't see a connection", addr, gate, code)
	}
	// §5.3 item 5: an outside host the sandbox does not list stays closed, by name and by address.
	if code, out := inSandbox(t, ctx, d, env, "getent", "ahostsv4", "example.com"); code == 0 {
		t.Errorf("example.com resolves in the work container: %s", out)
	}
	if code, out := inSandbox(t, ctx, d, env, "curl", "-sS", "-m", "6", "-o", "/dev/null", "https://example.com/"); code == 0 {
		t.Errorf("example.com answers from the work container: %s", out)
	}
	if code := reach("1.1.1.1", 443); code == 0 {
		t.Error("the open internet is reachable beside the model network")
	}

	// Down removes the sandbox and leaves the server's network and the server alone.
	if err := d.Down(ctx, env); err != nil {
		t.Fatalf("Down() = %v", err)
	}
	if _, err := podman("network", "exists", network); err != nil {
		t.Errorf("Down removed the model network %s", network)
	}
	if state, err := podman("inspect", "--format", "{{.State.Running}}", server); err != nil || state != "true" {
		t.Errorf("the stub server after Down: running %q, %v", state, err)
	}
	if ids, _ := podman("ps", "-a", "-q", "--filter", "label="+LabelRun+"="+spec.Run); ids != "" {
		t.Errorf("Down left containers: %s", ids)
	}
}
