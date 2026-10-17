//go:build sandbox

package sandbox

// Integration tests of a realm's built stack and of a service's command on a real engine (spec §13), with
// the same environment as TestSandboxDriverOnARealEngine. The second test needs an image that serves
// when told to, pinned by digest; set
//
//	YGG_SANDBOX_COMMAND_IMAGE   such as docker.io/library/busybox:1.37@sha256:<digest>
//
// then run: go test -tags sandbox -run 'TestSandboxBuilds|TestASandboxServiceTakes' -v -timeout 40m ./sandbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ouroboric-dev/gungnir"
	"github.com/ouroboric-dev/gungnir/schema"
)

func TestSandboxBuildsARealmsStackAndStartsALeafOnIt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Minute)
	defer cancel()
	d, tree := itDriver(t, ctx)
	dir := t.TempDir()
	for name, body := range map[string]string{
		"Containerfile":   "FROM " + itStack + "\nCOPY checks/ /opt/ygg/checks/\n",
		"checks/hello.sh": "#!/bin/sh\necho hello from the stack\n",
	} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	hash, err := schema.StackHash(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	ref := gungnir.LocalStack("it-realm", hash)
	if _, err := d.BuildStack(ctx, ref, dir, ""); err != nil {
		t.Fatalf("BuildStack() = %v", err)
	}
	if built, err := d.BuildStack(ctx, ref, dir, ""); err != nil || built {
		t.Errorf("a second BuildStack() = %v, %v; the image is there", built, err)
	}
	if _, err := d.Build(ctx, ref); err != nil {
		t.Fatalf("Build() = %v", err)
	}
	spec := itTree(t, tree)
	spec.Stack = ref
	env, err := d.Up(ctx, spec)
	if err != nil {
		t.Fatalf("Up() = %v", err)
	}
	t.Cleanup(func() { d.Down(context.Background(), env) })
	if code, out := inSandbox(t, ctx, d, env, "/opt/ygg/checks/hello.sh"); code != 0 || !strings.Contains(out, "hello from the stack") {
		t.Errorf("the check script of the stack: exit %d, %q", code, out)
	}
	if code, _ := inSandbox(t, ctx, d, env, "sh", "-c", "echo weaker >> /opt/ygg/checks/hello.sh"); code == 0 {
		t.Error("the work container's user rewrote a check script baked into the stack")
	}
}

func TestASandboxServiceTakesTheCommandItWasGiven(t *testing.T) {
	image := os.Getenv("YGG_SANDBOX_COMMAND_IMAGE")
	if image == "" {
		t.Skip("set YGG_SANDBOX_COMMAND_IMAGE to run this test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Minute)
	defer cancel()
	d, tree := itDriver(t, ctx)
	spec := itTree(t, tree)
	spec.Services = []gungnir.Service{{Name: "web", Image: image, Ports: []int{8080}, Command: []string{"httpd", "-f", "-p", "8080"}}}
	env, err := d.Up(ctx, spec)
	if err != nil {
		t.Fatalf("Up() = %v", err)
	}
	t.Cleanup(func() { d.Down(context.Background(), env) })
	if code, out := inSandbox(t, ctx, d, env, "timeout", "6", "bash", "-c", "exec 3<>/dev/tcp/web/8080"); code != 0 {
		t.Errorf("the service started with the command it was given: reaching web:8080 gave exit %d (%s)", code, out)
	}
	// A sandbox with a service still reaches the hosts its leaf may (the Go proxy is on the spec's list), and
	// still nothing else: the services network is internal, and the default route must not lead into it.
	if code, out := inSandbox(t, ctx, d, env, "timeout", "10", "bash", "-c", "exec 3<>/dev/tcp/proxy.golang.org/443"); code != 0 {
		t.Errorf("a host on the egress list is not reachable from a sandbox that has a service: exit %d (%s)", code, out)
	}
	if code, _ := inSandbox(t, ctx, d, env, "timeout", "6", "bash", "-c", "exec 3<>/dev/tcp/1.1.1.1/443"); code == 0 {
		t.Error("a host that is not on the egress list is reachable")
	}
}

// A name from a large pool (the Go proxy and the vulnerability databases are Google's) answers with another
// address from time to time. The work container's queries go to the firewall's dnsmasq, which answers from
// the addresses the rules allow, so what it resolves it can connect to, and it resolves nothing else.
func TestSandboxAnswersDNSForTheListedHostsAndTheServicesOnly(t *testing.T) {
	image := os.Getenv("YGG_SANDBOX_COMMAND_IMAGE")
	if image == "" {
		t.Skip("set YGG_SANDBOX_COMMAND_IMAGE to run this test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Minute)
	defer cancel()
	d, tree := itDriver(t, ctx)
	spec := itTree(t, tree)
	spec.Egress = []string{"proxy.golang.org", "api.anthropic.com"}
	spec.Services = []gungnir.Service{{Name: "web", Image: image, Ports: []int{8080}, Command: []string{"httpd", "-f", "-p", "8080"}}}
	env, err := d.Up(ctx, spec)
	if err != nil {
		t.Fatalf("Up() = %v", err)
	}
	t.Cleanup(func() { d.Down(context.Background(), env) })
	if code, out := inSandbox(t, ctx, d, env, "getent", "hosts", "web"); code != 0 || out == "" {
		t.Errorf("the service's name does not resolve: exit %d (%s)", code, out)
	}
	for _, host := range spec.Egress {
		if code, out := inSandbox(t, ctx, d, env, "timeout", "10", "bash", "-c", "exec 3<>/dev/tcp/"+host+"/443"); code != 0 {
			t.Errorf("%s resolves to an address the rules do not allow: exit %d (%s)", host, code, out)
		}
	}
	for _, host := range []string{"example.com", "github.com"} {
		if code, out := inSandbox(t, ctx, d, env, "timeout", "10", "getent", "hosts", host); code == 0 {
			t.Errorf("%s resolves although it is not on the list: %s", host, out)
		}
	}
}
