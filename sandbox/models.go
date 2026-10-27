package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ouroboric-dev/gungnir"
)

// The model server's image (local-models spec §3.4): llama-server in router mode and the model gate in front of it,
// started by assets/models-entrypoint.sh. Its bases are pinned by digest in assets/Containerfile.models. The three
// files are embedded in assets.go.

// defaultCUDAArch is the architecture the Containerfile builds for when CUDA_ARCH is not set.
const defaultCUDAArch = "89"

// ModelsImage returns the local tag of the model server's image for the default architecture: a hash of its
// Containerfile, its entrypoint and the gate's source, so a change to any of them is a new image, never a silently
// changed one.
func ModelsImage() string {
	return modelsTag(modelsContainerfile, modelsEntrypoint, modelGateSource, "")
}

// ModelsImageFor returns the tag of the image built for cudaArch. Empty and the default, 89, give ModelsImage's tag;
// another valid value gives another tag, so an image built for another GPU never shares a tag with the default one.
// It refuses a value BuildModels refuses.
func ModelsImageFor(cudaArch string) (string, error) {
	if err := checkCUDAArch(cudaArch); err != nil {
		return "", err
	}
	return modelsTag(modelsContainerfile, modelsEntrypoint, modelGateSource, cudaArch), nil
}

func checkCUDAArch(cudaArch string) error {
	if cudaArch != "" && !cudaArchs.MatchString(cudaArch) {
		return fmt.Errorf("the CUDA architecture %q is not a list such as 89, 90a or 86;89-real", cudaArch)
	}
	return nil
}

// modelsTag hashes the three files, and the architecture when it is not the default.
func modelsTag(containerfile, entrypoint, gate, cudaArch string) string {
	h := sha256.New()
	for _, part := range []string{containerfile, entrypoint, gate} {
		fmt.Fprintf(h, "%d:%s\n", len(part), part)
	}
	if cudaArch != "" && cudaArch != defaultCUDAArch {
		fmt.Fprintf(h, "cuda-arch:%d:%s\n", len(cudaArch), cudaArch)
	}
	return "localhost/ygg-models:" + hex.EncodeToString(h.Sum(nil))[:12]
}

var (
	argDefault = regexp.MustCompile(`(?m)^ARG\s+([A-Z_]+)=(\S+)\s*$`)
	fromStage  = regexp.MustCompile(`(?m)^FROM\s+(\S+)(?:\s+AS\s+(\S+))?\s*$`)
	// cudaArchs is a value of CMAKE_CUDA_ARCHITECTURES: architectures such as 89, 90a or 89-real, joined by ';'.
	cudaArchs = regexp.MustCompile(`^[0-9]+[a-z]?(-real|-virtual)?(;[0-9]+[a-z]?(-real|-virtual)?)*$`)
)

// modelsBases returns the images the Containerfile's stages start from, in their order: the defaults of the ARGs
// before its first FROM, which every FROM that is not an earlier stage names.
func modelsBases() []string {
	head, _, _ := strings.Cut(modelsContainerfile, "\nFROM ")
	args := map[string]string{}
	for _, m := range argDefault.FindAllStringSubmatch(head, -1) {
		args[m[1]] = m[2]
	}
	stages := map[string]bool{}
	var bases []string
	for _, m := range fromStage.FindAllStringSubmatch(modelsContainerfile, -1) {
		ref := m[1]
		if v, ok := strings.CutPrefix(ref, "${"); ok && strings.HasSuffix(v, "}") {
			ref = args[strings.TrimSuffix(v, "}")]
		}
		if !stages[ref] {
			bases = append(bases, ref)
		}
		if m[2] != "" {
			stages[m[2]] = true
		}
	}
	return bases
}

// BuildModels builds the model server's image from the embedded files and returns its tag. It pulls the bases by
// digest with the isolated registry auth, then builds with --pull=never. cudaArch sets CMAKE_CUDA_ARCHITECTURES
// (such as 89 or 86;89); empty leaves the Containerfile's default, 89. Like Build, it is for ygg models build alone:
// a run never builds.
func (d *Driver) BuildModels(ctx context.Context, cudaArch string) (string, error) {
	tag, err := ModelsImageFor(cudaArch)
	if err != nil {
		return "", err
	}
	for _, base := range modelsBases() {
		if !gungnir.ValidImage(base) {
			return "", fmt.Errorf("the model server's base %q is not pinned by digest, so it is not pulled", base) // a broken build of gleipnir
		}
		if _, err := d.run(ctx, d.Podman, "pull", "-q", "--authfile", filepath.Join(d.auth, "auth.json"), base); err != nil {
			return "", err
		}
	}
	dir, err := os.MkdirTemp(d.work, "models-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	if err := os.Mkdir(filepath.Join(dir, "modelgate"), 0o755); err != nil {
		return "", err
	}
	for name, f := range map[string]struct {
		body string
		mode os.FileMode
	}{
		"Containerfile":        {modelsContainerfile, 0o644},
		"models-entrypoint.sh": {modelsEntrypoint, 0o755},
		"modelgate/main.go":    {modelGateSource, 0o644},
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(f.body), f.mode); err != nil {
			return "", err
		}
	}
	args := []string{"build", "--pull=never", "-t", tag, "-f", filepath.Join(dir, "Containerfile")}
	if cudaArch != "" {
		args = append(args, "--build-arg", "CUDA_ARCH="+cudaArch)
	}
	if _, err := d.run(ctx, d.Podman, append(args, dir)...); err != nil {
		return "", err
	}
	return tag, nil
}
