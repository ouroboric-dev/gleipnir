package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const stackImage = "docker.io/library/golang:1.26.7-bookworm@sha256:e8c859f5632dcfde7b32d2012b4351728f6437930887c2f6a91ea242459e5514"

func TestImageTagsFollowEveryInput(t *testing.T) {
	a, b := ImagesFor(stackImage), ImagesFor(stackImage+"x")
	if a != ImagesFor(stackImage) {
		t.Error("the same inputs gave two tags")
	}
	if a.Work == b.Work {
		t.Error("a different stack kept the work image's tag")
	}
	if a.Firewall != b.Firewall {
		t.Error("the firewall image depends on the stack, which it doesn't hold")
	}
	if !strings.HasPrefix(a.Work, "localhost/ygg-work:") || !strings.HasPrefix(a.Firewall, "localhost/ygg-fw:") {
		t.Errorf("tags = %+v", a)
	}
}

func TestTheFactoryLayerIsPinned(t *testing.T) {
	if !strings.Contains(NodeImage, "@sha256:") || len(GitleaksSHA256) != 64 {
		t.Error("a base image or the gitleaks archive isn't pinned by digest")
	}
	for _, want := range []string{"sha256sum -c", "npm install -g --prefix /opt/ygg", "DISABLE_AUTOUPDATER=1", "AS fw", "AS work", "iptables dnsmasq-base",
		"the stack image needs bash, timeout and git"} {
		if !strings.Contains(containerfile, want) {
			t.Errorf("the Containerfile lacks %q", want)
		}
	}
	if strings.Contains(containerfile, "@latest") || strings.Contains(containerfile, "ANTHROPIC_API_KEY") {
		t.Error("the Containerfile uses a floating version or names an API key")
	}
	for _, want := range []string{"npm ci --prefix /opt/ygg/lib/ygg-submit", "COPY submit/ ", "/opt/ygg/bin/ygg-submit", "/opt/ygg/schemas"} {
		if !strings.Contains(containerfile, want) {
			t.Errorf("the Containerfile lacks %q", want)
		}
	}
}

func TestTheLockFilePinsAjv(t *testing.T) {
	if !strings.Contains(submitPackage, `"ajv": "`+AjvVersion+`"`) || !strings.Contains(submitLock, `"node_modules/ajv": {`) || !strings.Contains(submitLock, `"version": "`+AjvVersion+`"`) {
		t.Errorf("the package file or the lock file does not pin ajv %s", AjvVersion)
	}
}

func TestTheImageAllowsOnlyOdinsServer(t *testing.T) {
	var ms struct {
		HooksOnly   bool `json:"allowManagedHooksOnly"`
		MCPOnly     bool `json:"allowManagedMcpServersOnly"`
		Allowed     []map[string]any
		Bypass      string          `json:"disableBypassPermissionsMode"`
		AllowedJSON json.RawMessage `json:"allowedMcpServers"`
	}
	if err := json.Unmarshal([]byte(ManagedSettings()), &ms); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(ms.AllowedJSON, &ms.Allowed); err != nil {
		t.Fatal(err)
	}
	// With only the first two keys, a project's .mcp.json server still ran (2026-10-16).
	if !ms.HooksOnly || !ms.MCPOnly || ms.Bypass != "disable" {
		t.Errorf("managed settings = %+v; they must block repo hooks and project MCP servers, and bypass mode", ms)
	}
	// By command, not by name: a name admits any command a leaf's .mcp.json gives it (R22).
	cmd, _ := ms.Allowed[0]["serverCommand"].([]any)
	if len(ms.Allowed) != 1 || len(ms.Allowed[0]) != 1 || len(cmd) != 1 || cmd[0] != "/opt/ygg/bin/ygg-submit" {
		t.Errorf("allowedMcpServers = %v; want exactly [{serverCommand: [/opt/ygg/bin/ygg-submit]}]", ms.Allowed)
	}
	var keys map[string]any
	if err := json.Unmarshal([]byte(ManagedSettings()), &keys); err != nil || len(keys) != 4 {
		t.Errorf("managed settings hold %v, %v; want the four keys they held, and no other", keys, err)
	}
}

func TestTheImageTagFollowsTheSubmitToolAndItsSchemas(t *testing.T) {
	same := func() submitInputs {
		return submitInputs{checkResult: checkResultScript, script: submitScript, ajv: AjvVersion, schemas: schemaBytes(t), pkg: submitPackage, lock: submitLock}
	}
	base := imagesFor(stackImage, same())
	if base != ImagesFor(stackImage) {
		t.Fatal("ImagesFor does not hash the embedded script, the ajv pin, the lock file and the schemas")
	}
	for name, edit := range map[string]func(*submitInputs){
		"the script":            func(in *submitInputs) { in.script += "\n" },
		"the check-result tool": func(in *submitInputs) { in.checkResult += "\n" },
		"the ajv pin":           func(in *submitInputs) { in.ajv += "1" },
		"a schema":              func(in *submitInputs) { in.schemas = append(in.schemas, "{}"...) },
		"the lock file":         func(in *submitInputs) { in.lock += " " },
		"package.json":          func(in *submitInputs) { in.pkg += " " },
	} {
		in := same()
		edit(&in)
		got := imagesFor(stackImage, in)
		if got.Work == base.Work {
			t.Errorf("a changed %s kept the work image's tag", name)
		}
		if got.Firewall != base.Firewall {
			t.Errorf("a changed %s moved the firewall image, which holds none of it", name)
		}
	}
}

func schemaBytes(t *testing.T) []byte {
	t.Helper()
	b, err := schemaDigest()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBuildPullsWithIsolatedAuthThenBuildsNeverPulling(t *testing.T) {
	d, log, _ := fakeEngine(t)
	imgs, err := d.Build(context.Background(), stackImage)
	if err != nil {
		t.Fatal(err)
	}
	got := logOf(t, log)
	for _, want := range []string{"podman pull -q --authfile " + d.auth + "/auth.json " + NodeImage, "podman pull -q --authfile " + d.auth + "/auth.json " + stackImage,
		"--pull=never --target fw -t " + imgs.Firewall, "--pull=never --target work -t " + imgs.Work, "STACK_IMAGE=" + stackImage} {
		if !strings.Contains(got, want) {
			t.Errorf("the engine calls lack %q:\n%s", want, got)
		}
	}
	if strings.Index(got, "podman pull") > strings.Index(got, "podman build") {
		t.Error("a build ran before the pulls")
	}
}

const builtStack = "localhost/ygg-stack-midgard-react:0123456789ab"

func TestBuildStartsFromABuiltStackWithoutPullingIt(t *testing.T) {
	d, log, _ := fakeEngine(t)
	imgs, err := d.Build(context.Background(), builtStack)
	if err != nil {
		t.Fatal(err)
	}
	got := logOf(t, log)
	if strings.Contains(got, "podman pull -q --authfile "+d.auth+"/auth.json "+builtStack) {
		t.Errorf("a stack built here was pulled from a registry:\n%s", got)
	}
	for _, want := range []string{"podman image exists " + builtStack, "podman pull -q --authfile " + d.auth + "/auth.json " + NodeImage,
		"STACK_IMAGE=" + builtStack, "--pull=never --target work -t " + imgs.Work} {
		if !strings.Contains(got, want) {
			t.Errorf("the engine calls lack %q:\n%s", want, got)
		}
	}
}

func TestBuildRefusesABuiltStackThatWasNotBuilt(t *testing.T) {
	d, log, _ := fakeEngine(t)
	t.Setenv("STUB_MISSING", builtStack)
	if _, err := d.Build(context.Background(), builtStack); !errors.Is(err, ErrNoImage) || !strings.Contains(err.Error(), builtStack) {
		t.Errorf("Build() = %v; want ErrNoImage naming the stack", err)
	}
	if got := logOf(t, log); strings.Contains(got, "podman build") {
		t.Errorf("the layers were built on a stack that is missing:\n%s", got)
	}
}

func TestBuildFactoryBuildsTheFactoryStackThenTheLayerAndPullsTheNodeImageOnce(t *testing.T) {
	d, log, _ := fakeEngine(t)
	imgs, err := d.BuildFactory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if imgs != FactoryImages() {
		t.Errorf("BuildFactory() = %+v, want %+v", imgs, FactoryImages())
	}
	got := logOf(t, log)
	if n := strings.Count(got, "podman pull -q --authfile "+d.auth+"/auth.json "+NodeImage); n != 1 {
		t.Errorf("the Node image was pulled %d times, want once:\n%s", n, got)
	}
	for _, want := range []string{"podman build --pull=never -t " + FactoryStack, "--build-arg NODE_IMAGE=" + NodeImage,
		"podman image exists " + FactoryStack, "--pull=never --target fw -t " + FactoryImages().Firewall, "--pull=never --target work -t " + FactoryImages().Work,
		"STACK_IMAGE=" + FactoryStack} {
		if !strings.Contains(got, want) {
			t.Errorf("the engine calls lack %q:\n%s", want, got)
		}
	}
	if strings.Index(got, "-t "+FactoryStack) > strings.Index(got, "--target fw") {
		t.Error("the factory layer was built before the factory stack")
	}
}

func TestTheFactoryStackTagFollowsItsFileAndTheNodeImage(t *testing.T) {
	if !strings.HasPrefix(FactoryStack, "localhost/ygg-factory-stack:") || len(FactoryStack) != len("localhost/ygg-factory-stack:")+12 {
		t.Errorf("FactoryStack = %q", FactoryStack)
	}
	if !strings.Contains(factoryStackFile, "install -y --no-install-recommends git") || !strings.Contains(factoryStackFile, "ARG NODE_IMAGE") {
		t.Error("the factory stack file does not install git on the Node image argument")
	}
	if factoryStackTag(factoryStackFile, NodeImage) != FactoryStack || factoryStackTag(factoryStackFile+"x", NodeImage) == FactoryStack ||
		factoryStackTag(factoryStackFile, NodeImage+"x") == FactoryStack {
		t.Error("the tag does not follow the file and the Node image")
	}
	if FactoryImages().Work == ImagesFor(NodeImage).Work {
		t.Error("the factory images are still on the bare Node image")
	}
}
