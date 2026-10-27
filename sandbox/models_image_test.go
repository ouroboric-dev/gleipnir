package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ouroboric-dev/gungnir"
)

// The tests of the model server's image (local-models spec §3.4): its tag, its pinned inputs, its build and its
// entrypoint. The image itself is built by the founder's first start, on a GPU host; here BuildModels runs against
// the fake engine.

const llamaCommit = "4c3c5810f87efe177949f1b85ae509d38a2a311f" // ggml-org/llama.cpp 4c3c581, the spike's build

func TestModelsImageTagFollowsItsFiles(t *testing.T) {
	tag := ModelsImage()
	if !regexp.MustCompile(`^localhost/ygg-models:[0-9a-f]{12}$`).MatchString(tag) {
		t.Fatalf("ModelsImage() = %q", tag)
	}
	if modelsTag(modelsContainerfile, modelsEntrypoint, modelGateSource, "") != tag {
		t.Error("ModelsImage() is not the tag of the embedded files")
	}
	for name, other := range map[string]string{
		"Containerfile": modelsTag(modelsContainerfile+"\n", modelsEntrypoint, modelGateSource, ""),
		"entrypoint":    modelsTag(modelsContainerfile, modelsEntrypoint+"\n", modelGateSource, ""),
		"gate":          modelsTag(modelsContainerfile, modelsEntrypoint, modelGateSource+"\n", ""),
		"a moved byte":  modelsTag(modelsContainerfile+modelsEntrypoint[:1], modelsEntrypoint[1:], modelGateSource, ""),
	} {
		if other == tag {
			t.Errorf("a changed %s kept the tag", name)
		}
	}
	if tag == ImagesFor(stackImage).Work || tag == FactoryStack {
		t.Error("the model image shares a tag with a sandbox image")
	}
}

// fromLine is one FROM of a Containerfile: its image and its stage name.
var fromLine = regexp.MustCompile(`(?m)^FROM\s+(\S+)(?:\s+AS\s+(\S+))?\s*$`)

func TestModelsContainerfilePinsItsBases(t *testing.T) {
	args := map[string]string{} // the ARG defaults before the first FROM
	head, _, _ := strings.Cut(modelsContainerfile, "\nFROM ")
	for _, m := range regexp.MustCompile(`(?m)^ARG\s+([A-Z_]+)=(\S+)\s*$`).FindAllStringSubmatch(head, -1) {
		args[m[1]] = m[2]
	}
	stages := map[string]bool{}
	var bases []string
	froms := fromLine.FindAllStringSubmatch(modelsContainerfile, -1)
	if len(froms) < 3 {
		t.Fatalf("the Containerfile has %d stages; want the llama.cpp build, the gate's build and the server", len(froms))
	}
	for _, m := range froms {
		ref := m[1]
		if v, ok := strings.CutPrefix(ref, "${"); ok && strings.HasSuffix(v, "}") {
			ref = args[strings.TrimSuffix(v, "}")]
		}
		switch {
		case stages[ref]:
		case gungnir.ValidImage(ref):
			bases = append(bases, ref)
		default:
			t.Errorf("FROM %s is neither an earlier stage nor an image pinned by digest", m[1])
		}
		if m[2] != "" {
			stages[m[2]] = true
		}
	}
	if got := modelsBases(); strings.Join(got, " ") != strings.Join(bases, " ") {
		t.Errorf("modelsBases() = %q; the Containerfile's bases are %q", got, bases)
	}
	for _, want := range []string{"docker.io/nvidia/cuda:12.9.1-devel-ubuntu22.04@sha256:", "docker.io/nvidia/cuda:12.9.1-runtime-ubuntu22.04@sha256:", "docker.io/library/golang:"} {
		if !strings.Contains(strings.Join(bases, " "), want) {
			t.Errorf("no base is %s…: %q", want, bases)
		}
	}
	for _, want := range []string{
		"ARG CUDA_ARCH=89\n",
		"ARG LLAMA_CPP_COMMIT=" + llamaCommit + "\n",
		"https://github.com/ggml-org/llama.cpp",
		`test "$(git rev-parse HEAD)" = "${LLAMA_CPP_COMMIT}"`,
		"-DGGML_CUDA=ON",
		"-DCMAKE_CUDA_ARCHITECTURES=${CUDA_ARCH}",
		"COPY modelgate/main.go",
		"COPY models-entrypoint.sh",
	} {
		if !strings.Contains(modelsContainerfile, want) {
			t.Errorf("the Containerfile lacks %q", want)
		}
	}
	if !regexp.MustCompile(`ENTRYPOINT \["[^"]*ygg-models-entrypoint"\]\s*$`).MatchString(modelsContainerfile) {
		t.Error("the last stage does not end with the entrypoint that starts both programs")
	}
}

// podmanWithContext wraps the fake engine's podman: on a build it also logs the files of the build's context (its
// last argument), so a test can see what the context held before the driver removed it.
func podmanWithContext(t *testing.T, d *Driver) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "podman")
	body := "#!/bin/sh\nif [ \"$1\" = build ]; then for a; do last=\"$a\"; done; (cd \"$last\" && find . -type f | sort | sed 's/^/context /') >> \"$STUB_LOG\"; fi\nexec " + d.Podman + " \"$@\"\n"
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	d.Podman = p
}

// The default architecture keeps today's formula: the hash of the three files alone.
func TestModelsImageForDefaultKeepsTheThreeFileHash(t *testing.T) {
	h := sha256.New()
	for _, part := range []string{modelsContainerfile, modelsEntrypoint, modelGateSource} {
		fmt.Fprintf(h, "%d:%s\n", len(part), part)
	}
	want := "localhost/ygg-models:" + hex.EncodeToString(h.Sum(nil))[:12]
	if got := ModelsImage(); got != want {
		t.Errorf("ModelsImage() = %q, want the three-file hash %q", got, want)
	}
	for _, arch := range []string{"", "89"} {
		got, err := ModelsImageFor(arch)
		if err != nil || got != want {
			t.Errorf("ModelsImageFor(%q) = %q, %v; want %q", arch, got, err, want)
		}
	}
}

func TestModelsImageForAnotherArchitectureIsAnotherTag(t *testing.T) {
	seen := map[string]string{"default": ModelsImage()}
	for _, arch := range []string{"86", "86;89", "89-real", "90a"} {
		got, err := ModelsImageFor(arch)
		if err != nil {
			t.Fatalf("ModelsImageFor(%q) = %v", arch, err)
		}
		for name, tag := range seen {
			if got == tag {
				t.Errorf("ModelsImageFor(%q) = %q, the tag of %s", arch, got, name)
			}
		}
		seen[arch] = got
	}
}

func TestModelsImageForRefusesWhatBuildModelsRefuses(t *testing.T) {
	d, _, _ := fakeEngine(t)
	for _, arch := range []string{"8.6", "89;", "x", " 89"} {
		_, want := d.BuildModels(context.Background(), arch)
		_, err := ModelsImageFor(arch)
		if err == nil || want == nil || err.Error() != want.Error() {
			t.Errorf("ModelsImageFor(%q) = %v; want the error of BuildModels: %v", arch, err, want)
		}
	}
}

func TestModelsImageBuildPullsTheBasesThenBuildsNeverPulling(t *testing.T) {
	d, log, _ := fakeEngine(t)
	podmanWithContext(t, d)
	tag, err := d.BuildModels(context.Background(), "86")
	if err != nil {
		t.Fatal(err)
	}
	want, err := ModelsImageFor("86")
	if err != nil {
		t.Fatal(err)
	}
	if tag != want || tag == ModelsImage() {
		t.Errorf("BuildModels(86) = %q, want ModelsImageFor(86) = %q, not the default %q", tag, want, ModelsImage())
	}
	got := logOf(t, log)
	for _, base := range modelsBases() {
		if n := strings.Count(got, "podman pull -q --authfile "+d.auth+"/auth.json "+base+"\n"); n != 1 {
			t.Errorf("%s was pulled %d times with the isolated auth, want once:\n%s", base, n, got)
		}
	}
	for _, want := range []string{"podman build --pull=never -t " + tag + " -f ", "--build-arg CUDA_ARCH=86 ",
		"context ./Containerfile\n", "context ./models-entrypoint.sh\n", "context ./modelgate/main.go\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("the engine calls lack %q:\n%s", want, got)
		}
	}
	if strings.LastIndex(got, "podman pull") > strings.Index(got, "podman build") {
		t.Error("the build ran before the pulls")
	}
	if left, _ := filepath.Glob(filepath.Join(d.work, "models-*")); len(left) != 0 {
		t.Errorf("the build context was left behind: %q", left)
	}
}

func TestModelsImageBuildTakesTheDefaultArchitecture(t *testing.T) {
	d, log, _ := fakeEngine(t)
	if _, err := d.BuildModels(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if got := logOf(t, log); strings.Contains(got, "CUDA_ARCH") || !strings.Contains(got, "podman build --pull=never -t "+ModelsImage()) {
		t.Errorf("with no architecture, the build must leave CUDA_ARCH to the Containerfile (89):\n%s", got)
	}
}

func TestModelsImageBuildRefusesAnArchitectureItCannotPass(t *testing.T) {
	for _, arch := range []string{"89; rm -rf /", "$(id)", "89 90", "sm_89", "-89", "89;"} {
		d, log, _ := fakeEngine(t)
		if _, err := d.BuildModels(context.Background(), arch); err == nil || !strings.Contains(err.Error(), "CUDA") {
			t.Errorf("BuildModels(%q) = %v; want an error naming the CUDA architecture", arch, err)
		}
		if got := logOf(t, log); got != "" {
			t.Errorf("BuildModels(%q) called the engine:\n%s", arch, got)
		}
	}
	for _, arch := range []string{"89", "86;89", "89-real", "90a", "86-virtual;89-real"} {
		d, _, _ := fakeEngine(t)
		if _, err := d.BuildModels(context.Background(), arch); err != nil {
			t.Errorf("BuildModels(%q) = %v", arch, err)
		}
	}
}

// fakeServerPrograms writes a llama-server and a ygg-modelgate that log their arguments and stay up until they are
// stopped, or exit with the code their variable gives. With SERVER_TERM_PARENT set, llama-server first sends TERM to
// its parent, the entrypoint, so the TERM arrives before the gate starts.
func fakeServerPrograms(t *testing.T) (bin, log string) {
	t.Helper()
	bin = t.TempDir()
	log = filepath.Join(bin, "calls.log")
	for name, exitVar := range map[string]string{"llama-server": "SERVER_EXIT", "ygg-modelgate": "GATE_EXIT"} {
		body := "#!/bin/sh\necho \"" + name + " $*\" >> \"$CALLS\"\n" +
			termParent(name) +
			"if [ -n \"${" + exitVar + ":-}\" ]; then sleep 0.3; exit \"$" + exitVar + "\"; fi\n" +
			"trap 'echo \"" + name + " stopped\" >> \"$CALLS\"; kill \"$s\" 2>/dev/null; exit 143' TERM\n" +
			"sleep 30 & s=$!\nwait \"$s\"\n"
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return bin, log
}

func termParent(name string) string {
	if name != "llama-server" {
		return ""
	}
	return "if [ -n \"${SERVER_TERM_PARENT:-}\" ]; then kill -TERM \"$PPID\"; fi\n"
}

func runEntrypoint(t *testing.T, env ...string) (code int, calls string, took time.Duration) {
	t.Helper()
	bin, log := fakeServerPrograms(t)
	script := filepath.Join(t.TempDir(), "models-entrypoint.sh")
	if err := os.WriteFile(script, []byte(modelsEntrypoint), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, script)
	cmd.Env = append([]string{"PATH=" + bin + ":/usr/bin:/bin", "CALLS=" + log}, env...)
	start := time.Now()
	out, err := cmd.CombinedOutput()
	took = time.Since(start)
	t.Logf("entrypoint output: %s", out)
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatal(err)
		}
		code = ee.ExitCode()
	}
	return code, logOf(t, log), took
}

func TestModelsImageEntrypointStartsBothAndExitsWhenEitherExits(t *testing.T) {
	for name, c := range map[string]struct {
		env      string
		code     int
		survivor string // the program the entrypoint must stop
	}{
		"the gate exits":   {"GATE_EXIT=3", 3, "llama-server"},
		"the server exits": {"SERVER_EXIT=4", 4, "ygg-modelgate"},
	} {
		t.Run(name, func(t *testing.T) {
			code, calls, took := runEntrypoint(t, "YGG_MODELGATE_PORT=8090", c.env)
			if code != c.code {
				t.Errorf("the entrypoint exited %d; want %d, the code of the program that exited", code, c.code)
			}
			if took > 10*time.Second {
				t.Errorf("the entrypoint took %s to exit", took)
			}
			for _, want := range []string{
				"llama-server --models-preset /etc/ygg-models/preset.ini --models-max 1 --host 0.0.0.0 --port 8080\n",
				"ygg-modelgate -listen :8090 -upstream http://127.0.0.1:8080 -allow /etc/ygg-models/allowed\n",
				c.survivor + " stopped\n",
			} {
				if !strings.Contains(calls, want) {
					t.Errorf("the calls lack %q:\n%s", want, calls)
				}
			}
		})
	}
}

func TestModelsImageEntrypointStopsWhatItStartedOnATermBeforeTheGateStarts(t *testing.T) {
	code, calls, took := runEntrypoint(t, "YGG_MODELGATE_PORT=8090", "SERVER_TERM_PARENT=1")
	if code == 0 {
		t.Errorf("the entrypoint exited 0 after a TERM")
	}
	if took > 10*time.Second {
		t.Errorf("the entrypoint took %s to exit", took)
	}
	if !strings.Contains(calls, "llama-server stopped\n") {
		t.Errorf("the TERM was not passed on to llama-server:\n%s", calls)
	}
}

func TestModelsImageEntrypointRefusesABadGatePort(t *testing.T) {
	for _, env := range []string{"", "YGG_MODELGATE_PORT=", "YGG_MODELGATE_PORT=8080", "YGG_MODELGATE_PORT=08080",
		"YGG_MODELGATE_PORT=0", "YGG_MODELGATE_PORT=65536", "YGG_MODELGATE_PORT=80x", "YGG_MODELGATE_PORT=:8090"} {
		code, calls, _ := runEntrypoint(t, env)
		if code == 0 || calls != "" {
			t.Errorf("%q: exit %d, calls %q; want a refusal before either program starts", env, code, calls)
		}
	}
}
