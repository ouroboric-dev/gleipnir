//go:build sandbox

package sandbox

// Integration tests of services and scratch folders on a real engine (spec §13: behind a build tag, with
// the same environment as TestSandboxDriverOnARealEngine). A service needs an image that listens on a
// port, pinned by digest; set
//
//	YGG_SANDBOX_SERVICE_IMAGE   such as docker.io/library/nginx:1.27-alpine@sha256:<digest>
//	YGG_SANDBOX_SERVICE_PORT    the port it listens on, such as 80
//
// then run: go test -tags sandbox -run 'TestSandboxServices|TestSandboxScratch' -v -timeout 40m ./sandbox

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
