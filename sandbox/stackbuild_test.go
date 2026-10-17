package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ouroboric-dev/gungnir"
	"github.com/ouroboric-dev/gungnir/schema"
)

const (
	baseA = "docker.io/library/golang:1.26.7-bookworm@sha256:e8c859f5632dcfde7b32d2012b4351728f6437930887c2f6a91ea242459e5514"
	baseB = "docker.io/library/node:24.1.0-bookworm@sha256:3333333333333333333333333333333333333333333333333333333333333333"
)

// stackContext writes a build context with the given Containerfile and returns it with the tag a
// build of it gets.
func stackContext(t *testing.T, containerfile string, more map[string]string) (dir, ref string) {
	t.Helper()
	return stackContextFor(t, containerfile, more, "")
}

func stackContextFor(t *testing.T, containerfile string, more map[string]string, target string) (dir, ref string) {
	t.Helper()
	dir = t.TempDir()
	files := map[string]string{"Containerfile": containerfile}
	for k, v := range more {
		files[k] = v
	}
	for name, body := range files {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	h, err := schema.StackHash(dir, target)
	if err != nil {
		t.Fatal(err)
	}
	return dir, gungnir.LocalStack("midgard-react", h)
}

const goodContainerfile = "# the stack\nFROM " + baseB + " AS tools\nRUN npm install -g prism@5.0.0 \\\n && true\nFROM " + baseA + " AS stack\nCOPY --from=tools /usr/local /opt/tools\nCOPY checks/ /opt/ygg/checks/\nRUN true\n"

func TestBuildStackPullsTheBasesByDigestThenBuildsTheContextNeverPulling(t *testing.T) {
	d, log, _ := fakeEngine(t)
	dir, ref := stackContext(t, goodContainerfile, map[string]string{"checks/go-unit.sh": "#!/bin/sh\n"})
	t.Setenv("STUB_MISSING", ref)
	built, err := d.BuildStack(context.Background(), ref, dir, "")
	if err != nil || !built {
		t.Fatalf("BuildStack() = %v, %v", built, err)
	}
	got := logOf(t, log)
	for _, want := range []string{"podman pull -q --authfile " + d.auth + "/auth.json " + baseA, "podman pull -q --authfile " + d.auth + "/auth.json " + baseB,
		"podman build --pull=never -t " + ref + " -f " + filepath.Join(dir, "Containerfile") + " " + dir} {
		if !strings.Contains(got, want) {
			t.Errorf("the engine calls lack %q:\n%s", want, got)
		}
	}
	if strings.Index(got, "podman pull") > strings.Index(got, "podman build") {
		t.Error("a build ran before the pulls")
	}
	if strings.Count(got, "podman pull") != 2 {
		t.Errorf("each base is pulled once:\n%s", got)
	}
}

func TestBuildStackLeavesAnImageThatIsThereAlone(t *testing.T) {
	d, log, _ := fakeEngine(t)
	dir, ref := stackContext(t, goodContainerfile, nil)
	built, err := d.BuildStack(context.Background(), ref, dir, "")
	if err != nil || built {
		t.Fatalf("BuildStack() = %v, %v; the tag is a hash of the context, so an image with it is this image", built, err)
	}
	if got := logOf(t, log); strings.Contains(got, "podman build") || strings.Contains(got, "podman pull") {
		t.Errorf("an existing stack was built or pulled again:\n%s", got)
	}
}

func TestBuildStackRefusesAContextItCouldNotBuildFromPinnedInputsOnly(t *testing.T) {
	bad := map[string]string{
		"a base with a tag and no digest":      "FROM docker.io/library/golang:1.26.7\n",
		"a base from an argument":              "ARG BASE=" + baseA + "\nFROM ${BASE}\n",
		"a stage copied from an image":         "FROM " + baseA + "\nCOPY --from=docker.io/library/busybox:1 /bin/sh /sh\n",
		"a stage copied from a later stage":    "FROM " + baseA + " AS a\nCOPY --from=b /x /x\nFROM " + baseB + " AS b\n",
		"a mount from an image":                "FROM " + baseA + "\nRUN --mount=type=bind,from=docker.io/library/busybox:1,target=/x true\n",
		"a remote file added":                  "FROM " + baseA + "\nADD https://example.com/tool.tgz /opt/\n",
		"no base at all":                       "RUN true\n",
		"a base on an option and not a digest": "FROM --platform=linux/amd64 docker.io/library/golang:1.26.7\n",
	}
	for name, cf := range bad {
		d, log, _ := fakeEngine(t)
		dir, ref := stackContext(t, cf, nil)
		if _, err := d.BuildStack(context.Background(), ref, dir, ""); err == nil {
			t.Errorf("%s: BuildStack() = nil, want an error", name)
		}
		if got := logOf(t, log); got != "" {
			t.Errorf("%s: the engine was called before the context was refused:\n%s", name, got)
		}
	}
	d, log, _ := fakeEngine(t)
	dir, ref := stackContext(t, goodContainerfile, nil)
	if err := os.WriteFile(filepath.Join(dir, "late.sh"), []byte("echo changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := d.BuildStack(context.Background(), ref, dir, ""); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Errorf("a tag that does not match the context: BuildStack() = %v", err)
	}
	for _, other := range []string{baseA, "localhost/ygg-work:abc", "localhost/ygg-stack-x:latest"} {
		if _, err := d.BuildStack(context.Background(), other, dir, ""); err == nil {
			t.Errorf("BuildStack(%q) = nil, want an error: only the tag of a built stack is built", other)
		}
	}
	if got := logOf(t, log); got != "" {
		t.Errorf("the engine was called:\n%s", got)
	}
}

func TestBuildStackBuildsTheStageItWasToldTo(t *testing.T) {
	cf := "FROM " + baseA + " AS web\nRUN true\nFROM web AS acceptance\nRUN true\n"
	d, log, _ := fakeEngine(t)
	dir, ref := stackContextFor(t, cf, nil, "acceptance")
	t.Setenv("STUB_MISSING", ref)
	if built, err := d.BuildStack(context.Background(), ref, dir, "acceptance"); err != nil || !built {
		t.Fatalf("BuildStack() = %v, %v", built, err)
	}
	if got := logOf(t, log); !strings.Contains(got, "-t "+ref+" -f "+filepath.Join(dir, "Containerfile")+" --target acceptance "+dir) {
		t.Errorf("the build lacks --target acceptance:\n%s", got)
	}
	if _, err := d.BuildStack(context.Background(), ref, dir, "web"); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Errorf("a tag made for another stage: BuildStack() = %v", err)
	}
	dir2, ref2 := stackContextFor(t, cf, nil, "nope")
	d2, log2, _ := fakeEngine(t)
	if _, err := d2.BuildStack(context.Background(), ref2, dir2, "nope"); err == nil || !strings.Contains(err.Error(), "no stage named") {
		t.Errorf("a stage the Containerfile lacks: BuildStack() = %v", err)
	}
	if got := logOf(t, log2); got != "" {
		t.Errorf("the engine was called:\n%s", got)
	}
}
