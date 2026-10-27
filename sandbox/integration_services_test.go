//go:build sandbox

package sandbox

// Integration tests of services and scratch folders on a real engine (spec §13: behind a build tag, with
// the same environment as TestSandboxDriverOnARealEngine). A service needs an image that listens on a
// port, pinned by digest; set
//
//	YGG_SANDBOX_SERVICE_IMAGE   such as docker.io/library/nginx:1.27-alpine@sha256:<digest>
//	YGG_SANDBOX_SERVICE_PORT    the port it listens on, such as 80
//
// then run: go test -tags sandbox -run 'TestSandboxServices|TestSandboxScratch|TestASandboxService' -v -timeout 40m ./sandbox
//
// TestSandboxDownRemovesARunningService needs no service image: run it with -run TestSandboxDown.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ouroboric-dev/gungnir"
)

// itDriver returns a driver on the real engine with the images built for itStack.
func itDriver(t *testing.T, ctx context.Context) (*Driver, string) {
	t.Helper()
	socket, tree, engineTree := itEnv(t)
	cfg := Config{Mounts: []PathMap{{Host: tree, Engine: engineTree}}, Images: ImagesFor(itStack), UID: os.Getuid(), GID: os.Getgid()}
	work, err := os.MkdirTemp(tree, "work-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(work) })
	d, err := New(socket, cfg, work)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.run(ctx, d.Podman, "image", "exists", cfg.Images.Work); err != nil {
		t.Logf("building the images (a few minutes)")
		if _, err := d.Build(ctx, itStack); err != nil {
			t.Fatalf("Build() = %v", err)
		}
	}
	return d, tree
}

func inSandbox(t *testing.T, ctx context.Context, d *Driver, env gungnir.Env, argv ...string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	res, err := d.Exec(ctx, env, gungnir.Cmd{Argv: argv, Stdout: &out, Stderr: &out})
	if err != nil {
		t.Fatalf("%v: %v", argv, err)
	}
	return res.ExitCode, strings.TrimSpace(out.String())
}

func TestSandboxServicesAreReachableByNameOnTheirPortsOnly(t *testing.T) {
	image, portText := os.Getenv("YGG_SANDBOX_SERVICE_IMAGE"), os.Getenv("YGG_SANDBOX_SERVICE_PORT")
	if image == "" || portText == "" {
		t.Skip("set YGG_SANDBOX_SERVICE_IMAGE and YGG_SANDBOX_SERVICE_PORT to run this test")
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Minute)
	defer cancel()
	d, tree := itDriver(t, ctx)
	spec := itTree(t, tree)
	spec.Services = []gungnir.Service{{Name: "svc", Image: image, Ports: []int{port}}}
	env, err := d.Up(ctx, spec)
	if err != nil {
		t.Fatalf("Up() = %v", err)
	}
	t.Cleanup(func() { d.Down(context.Background(), env) })
	reach := func(host string, p int) int {
		code, _ := inSandbox(t, ctx, d, env, "timeout", "6", "bash", "-c", "exec 3<>/dev/tcp/"+host+"/"+strconv.Itoa(p))
		return code
	}
	if code := reach("svc", port); code != 0 {
		t.Errorf("the service on its listed port: exit %d; the work container reaches it by name", code)
	}
	if code := reach("svc", port+1); code == 0 {
		t.Errorf("the service on %d, which is not listed: reachable", port+1)
	}
	if code := reach("1.1.1.1", 443); code == 0 {
		t.Error("the open internet is reachable beside the service")
	}
	if err := d.Down(ctx, env); err != nil {
		t.Fatalf("Down() = %v", err)
	}
	left, err := d.Leftovers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range left {
		if l.Run == spec.Run {
			t.Errorf("Down left %+v, the service's container among them", l)
		}
	}
}

// Backlog B-206: Down removes a sandbox whose service is running, and leaves no container and no pod of the
// run. podman rm --depend named such a service as removed and left it running, and the pod's removal then
// failed. The service is node in the pinned Node image (the base of the factory's images, already on the
// engine), so the test pulls nothing.
func TestSandboxDownRemovesARunningService(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Minute)
	defer cancel()
	d, tree := itDriver(t, ctx)
	podman := func(args ...string) (string, error) {
		out, err := d.run(ctx, d.Podman, args...)
		return strings.TrimSpace(string(out)), err
	}
	b := make([]byte, 4)
	rand.Read(b)
	const port = 7000
	spec := itTree(t, tree)
	spec.Run = "b206-" + hex.EncodeToString(b)
	spec.Services = []gungnir.Service{{Name: "svc", Image: NodeImage, Ports: []int{port},
		Command: []string{"node", "-e", `process.on("SIGTERM", () => process.exit(0)); require("http").createServer((q, r) => r.end("svc\n")).listen(` + strconv.Itoa(port) + `)`}}}
	env, err := d.Up(ctx, spec)
	if err != nil {
		t.Fatalf("Up() = %v", err)
	}
	t.Cleanup(func() { d.Down(context.Background(), env) })
	// Control: the service runs when Down starts.
	if id, err := podman("ps", "-q", "--filter", "label=com.docker.compose.project="+env.Project, "--filter", "label=com.docker.compose.service=svc"); err != nil || id == "" {
		t.Fatalf("control: the service of %s is not running: %q, %v", env.Project, id, err)
	}
	if err := d.Down(ctx, env); err != nil {
		t.Errorf("Down() = %v", err)
	}
	if ids, _ := podman("ps", "-a", "-q", "--filter", "label="+LabelRun+"="+spec.Run); ids != "" {
		t.Errorf("Down left containers: %s", ids)
	}
	if _, err := podman("pod", "exists", "pod_"+env.Project); err == nil {
		t.Errorf("Down left the pod pod_%s", env.Project)
	}
	if err := d.Down(ctx, env); err != nil {
		t.Errorf("Down() a second time = %v", err)
	}
}

func TestSandboxScratchHoldsOneFolderAndNothingElse(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Minute)
	defer cancel()
	d, tree := itDriver(t, ctx)
	parent, err := os.MkdirTemp(tree, "scratch-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(parent) })
	folder := filepath.Join(parent, "scratch", "design")
	os.MkdirAll(filepath.Join(folder, "out"), 0o755)
	os.WriteFile(filepath.Join(parent, "outside.txt"), []byte("not in the workspace"), 0o644)
	spec := gungnir.SandboxSpec{Run: "20261016-130000-a1b2c3", Name: "scratch/design", Scratch: true, Parent: parent, Leaf: folder,
		Egress: []string{"api.anthropic.com"}}
	env, err := d.Up(ctx, spec)
	if err != nil {
		t.Fatalf("Up() = %v", err)
	}
	t.Cleanup(func() { d.Down(context.Background(), env) })
	if code, out := inSandbox(t, ctx, d, env, "sh", "-c", "echo x > out/made.txt && pwd"); code != 0 || !strings.HasSuffix(out, "/scratch/design") {
		t.Errorf("a write in the workspace: exit %d, %q", code, out)
	}
	if b, err := os.ReadFile(filepath.Join(folder, "out", "made.txt")); err != nil || strings.TrimSpace(string(b)) != "x" {
		t.Errorf("the workspace on the host holds %q, %v", b, err)
	}
	for name, argv := range map[string][]string{
		"a file beside the workspace": {"test", "-e", "../../outside.txt"},
		"a git dir":                   {"sh", "-c", "ls /u/.git 2>/dev/null | grep -q ."},
	} {
		if code, _ := inSandbox(t, ctx, d, env, argv...); code == 0 {
			t.Errorf("%s is there", name)
		}
	}
}

// Backlog N-1: a service sits on the internal services network alone, so nothing in it reaches past
// the sandbox: not the internet, not the network's gateway, not the host, not an outside name. The
// commands run inside the service container through the engine, as proveClosed reaches the firewall's.
// They need busybox's sh, timeout, nc, wget, ip and nslookup, and an HTTP server on the service's
// port (docker.io/library/nginx:*-alpine). A probe passes on any failure of its command; only a
// connection, an answer or a resolved name fails the test. Controls prove the probes can see a
// connection at all: the same probes reach the service's own port on 127.0.0.1.
func TestASandboxServiceHasNoRouteOut(t *testing.T) {
	image, portText := os.Getenv("YGG_SANDBOX_SERVICE_IMAGE"), os.Getenv("YGG_SANDBOX_SERVICE_PORT")
	if image == "" || portText == "" {
		t.Skip("set YGG_SANDBOX_SERVICE_IMAGE and YGG_SANDBOX_SERVICE_PORT to run this test")
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Minute)
	defer cancel()
	d, tree := itDriver(t, ctx)

	// A listener on the host, on every address: a connection from the service that lands here is a
	// route to the host, whatever the probe's command made of it.
	ln, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var taken atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			taken.Add(1)
			c.Write([]byte("ygg-host\n"))
			c.Close()
		}
	}()
	hostPort := ln.Addr().(*net.TCPAddr).Port

	spec := itTree(t, tree)
	spec.Services = []gungnir.Service{{Name: "svc", Image: image, Ports: []int{port}}}
	env, err := d.Up(ctx, spec)
	if err != nil {
		t.Fatalf("Up() = %v", err)
	}
	t.Cleanup(func() { d.Down(context.Background(), env) })
	ids, err := d.run(ctx, d.Podman, "ps", "-q", "--filter", "label=com.docker.compose.project="+env.Project, "--filter", "label=com.docker.compose.service=svc")
	id := strings.TrimSpace(string(ids))
	if err != nil || id == "" || strings.Contains(id, "\n") {
		t.Fatalf("the service container of %s: %q, %v", env.Project, id, err)
	}
	// in runs script in the service container; its exit status is the script's business, so a
	// failing command is no error here. alive shows that the exec itself works, before and after the
	// probes, so a container that is gone never reads as a closed network.
	in := func(script string) string {
		out, _ := d.run(ctx, d.Podman, "exec", id, "sh", "-c", script)
		return strings.TrimSpace(string(out))
	}
	alive := func(when string) {
		t.Helper()
		const tools = `for c in sh timeout nc wget ip nslookup; do command -v "$c" >/dev/null 2>&1 || echo "missing $c"; done; echo ready`
		if out := in(tools); out != "ready" {
			t.Fatalf("%s, the service container can't run the probes: %q", when, out)
		}
	}
	// tcp says REACHED when nc connected: it exited 0, or it printed what the far end sent.
	tcp := func(host string, p int) string {
		return in(`out=$(printf 'GET / HTTP/1.0\r\n\r\n' | timeout 3 nc -w 3 ` + host + ` ` + strconv.Itoa(p) + ` 2>/dev/null); rc=$?
if [ "$rc" = 0 ] || [ -n "$out" ]; then echo REACHED; else echo "blocked ($rc)"; fi`)
	}
	// web says REACHED when wget got an answer, even an HTTP error.
	web := func(url string) string {
		return in(`out=$(timeout 5 wget -S -T 3 -O /dev/null ` + url + ` 2>&1); rc=$?
if [ "$rc" = 0 ] || echo "$out" | grep -q 'HTTP/'; then echo REACHED; else echo "blocked ($rc)"; fi`)
	}

	alive("before the probes")
	local := "127.0.0.1"
	if got := tcp(local, port); got != "REACHED" {
		t.Fatalf("control: nc to the service's own port %d on %s: %q; the probe can't see a connection", port, local, got)
	}
	if got := web("http://" + local + ":" + strconv.Itoa(port) + "/"); got != "REACHED" {
		t.Fatalf("control: wget to the service's own port %d on %s: %q; the probe can't see an answer", port, local, got)
	}

	// (a) the internet, by address.
	if got := tcp("1.1.1.1", 443); got == "REACHED" {
		t.Error("the service connected to 1.1.1.1:443")
	}

	// (b) the gateway and the host. An internal network gives no default route; a gateway it does
	// give is probed too, and so is every address of the host and the name podman gives the host.
	routes := in("ip route 2>&1")
	if routes == "" {
		t.Fatal("ip route printed nothing in the service container")
	}
	t.Logf("the service's routes:\n%s", routes)
	var targets []string
	for _, family := range []string{routes, in("ip -6 route 2>/dev/null")} {
		for _, line := range strings.Split(family, "\n") {
			f := strings.Fields(line)
			if len(f) == 0 || f[0] != "default" {
				continue
			}
			t.Errorf("the service has a default route: %s", line)
			for i := range len(f) - 1 {
				if f[i] == "via" {
					targets = append(targets, f[i+1])
				}
			}
		}
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		if ip, ok := a.(*net.IPNet); ok && ip.IP.To4() != nil && !ip.IP.IsLoopback() {
			targets = append(targets, ip.IP.String())
		}
	}
	if h := in(`awk '{ for (i = 2; i <= NF; i++) if ($i == "host.containers.internal") print $1 }' /etc/hosts | head -n 1`); h != "" {
		targets = append(targets, h)
	}
	for _, host := range targets {
		for _, p := range []int{hostPort, 80, 443} {
			if got := tcp(host, p); got == "REACHED" {
				t.Errorf("the service connected to %s:%d", host, p)
			}
		}
	}

	// (c) an outside name: no address for it, and no connection to it.
	if out := in("timeout 6 nslookup example.com 2>&1"); regexp.MustCompile(`(?m)^Name:\s*example\.com`).MatchString(out) {
		t.Errorf("the service resolved example.com:\n%s", out)
	}
	if got := tcp("example.com", 80); got == "REACHED" {
		t.Error("the service connected to example.com:80")
	}
	if got := web("http://example.com/"); got == "REACHED" {
		t.Error("the service got an answer from http://example.com/")
	}

	alive("after the probes")
	if n := taken.Load(); n > 0 {
		t.Errorf("the host's listener on port %d took %d connections from the service", hostPort, n)
	}
}
