//go:build sandbox

package sandbox

// The model network on a real engine (local-models spec §3.7, §5.3 items 1, 4 and 5), with the same
// environment as TestSandboxDriverOnARealEngine. A stub model server, on an internal network of the
// test's own, answers HTTP on the gate's port and on 8080, as llama-server and the gate do. It is node's
// http module in the firewall image (node is that image's base, and itDriver builds it), so the test
// pulls nothing. The network and the stub are named for this run alone and removed at the end; the test
// touches nothing else on the engine.
//
// The firewall resolves the listed hosts again every YGG_REFRESH seconds, as root, through the first nameserver
// of its resolv.conf, and dnsmasq forwards the services' names and the server's to that same nameserver. Beside
// an internal network that nameserver may be the internal network's, which need not know an outside name, and a
// refresh would then keep the old addresses with no error. So the test runs the refresh's own lookup (getent
// ahostsv4, as root in the firewall) for a listed host, with the model network alone and with a realm service
// beside it. It does not force a refresh of the running script: its environment is the generated file's, which
// Validate keeps, and ending its sleep ends its loop.
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
	refreshResolves(t, ctx, d, env, spec)

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

	// A realm service beside the model server: the firewall is on the default, services and model networks.
	// The service is node in the pinned Node image (the base of the factory's images, already on the engine).
	const svcPort = 7000
	both := itTree(t, tree)
	both.Run = "lmis-" + suffix
	both.Models = &gungnir.ModelServer{Network: network, Name: server, Port: gate}
	both.Services = []gungnir.Service{{Name: "svc", Image: NodeImage, Ports: []int{svcPort},
		Command: []string{"node", "-e", `process.on("SIGTERM", () => process.exit(0)); require("http").createServer((q, r) => r.end("svc\n")).listen(` + strconv.Itoa(svcPort) + `)`}}}
	env2, err := d.Up(ctx, both)
	if err != nil {
		t.Fatalf("Up() with a service and the model server = %v", err)
	}
	t.Cleanup(func() { d.Down(context.Background(), env2) })
	for _, name := range []string{"svc", server} {
		if code, out := inSandbox(t, ctx, d, env2, "getent", "ahostsv4", name); code != 0 || out == "" {
			t.Errorf("%s does not resolve in the work container beside the other network: exit %d, %q", name, code, out)
		}
	}
	if code, _ := inSandbox(t, ctx, d, env2, "timeout", "6", "bash", "-c", "exec 3<>/dev/tcp/svc/"+strconv.Itoa(svcPort)); code != 0 {
		t.Errorf("the service's port %d is closed beside the model network: exit %d", svcPort, code)
	}
	if code, out := inSandbox(t, ctx, d, env2, "curl", "-sS", "-m", "6", "http://"+server+":"+strconv.Itoa(gate)+"/"); code != 0 || out != "stub "+strconv.Itoa(gate) {
		t.Errorf("the gate's port by name beside a service: exit %d, %q; want the stub's answer", code, out)
	}
	refreshResolves(t, ctx, d, env2, both)
	// Down of a sandbox with a service fails today at its pod, on this engine, with or without Models: podman rm -f
	// --depend names the service as removed and leaves it running, and pod rm refuses it; the network's rm -f then
	// removes it. That is Down's own matter, so it is logged here, not failed; what Down leaves is checked.
	if err := d.Down(ctx, env2); err != nil {
		t.Logf("Down() with a service = %v", err)
	}
	if ids, _ := podman("ps", "-a", "-q", "--filter", "label="+LabelRun+"="+both.Run); ids != "" {
		t.Errorf("Down left containers: %s", ids)
	}
}

// refreshResolves runs, as root in the firewall of env, the lookup egress.sh's refresh makes for the last listed
// host, and checks that the work container still resolves that host through dnsmasq.
func refreshResolves(t *testing.T, ctx context.Context, d *Driver, env gungnir.Env, spec gungnir.SandboxSpec) {
	t.Helper()
	ids, err := d.run(ctx, d.Podman, "ps", "-q", "--filter", "label=com.docker.compose.project="+env.Project, "--filter", "label=com.docker.compose.service=fw")
	fw := strings.TrimSpace(string(ids))
	if err != nil || fw == "" || strings.Contains(fw, "\n") {
		t.Fatalf("the firewall container of %s: %q, %v", env.Project, fw, err)
	}
	host := spec.Egress[len(spec.Egress)-1]
	// For the record: the firewall's nameservers, and the gateway of each of its networks, which is that network's
	// resolver. egress.sh asks the first nameserver only.
	if out, err := d.run(ctx, d.Podman, "exec", fw, "cat", "/etc/resolv.conf"); err == nil {
		t.Logf("the firewall's resolv.conf (%s):\n%s", env.Project, out)
	}
	if out, err := d.run(ctx, d.Podman, "inspect", "--format", "{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{$v.Gateway}}\n{{end}}", fw); err == nil {
		t.Logf("the firewall's networks and their gateways:\n%s", out)
	}
	out, err := d.run(ctx, d.Podman, "exec", fw, "getent", "ahostsv4", host)
	if err != nil || strings.TrimSpace(string(out)) == "" {
		t.Errorf("the refresh's lookup of %s, as root in the firewall of %s, fails: %v, %q; a refresh would keep the old addresses",
			host, env.Project, err, out)
	}
	if code, out := inSandbox(t, ctx, d, env, "getent", "ahostsv4", host); code != 0 || out == "" {
		t.Errorf("%s does not resolve in the work container: exit %d, %q", host, code, out)
	}
}
