package sandbox

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ouroboric-dev/gungnir"
)

//go:embed assets/Containerfile
var containerfile string

//go:embed assets/Containerfile.factory-stack
var factoryStackFile string

//go:embed assets/managed-settings.json
var managedSettings string

// Pinned inputs of the factory layer. Each version is at least two weeks old (Phase 3 decision 6),
// and a bump is a reviewed change that moves every image tag.
const (
	NodeImage       = "docker.io/library/node@sha256:efd0ab5780c2d9ab1f0f869571a00d5edb17793bff4cce4a2792e3eb0ffc7562"
	ClaudeCode      = "2.1.284"
	OpenCode        = "1.18.32"
	GitleaksVersion = "8.30.1"
	GitleaksSHA256  = "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb" // gitleaks_8.30.1_linux_x64.tar.gz
)

// ManagedSettings is the file the work image carries at /etc/claude-code/managed-settings.json: it
// blocks repository hooks and project MCP servers, whatever flags a session gets (spec §6.2).
func ManagedSettings() string { return managedSettings }

// ImagesFor returns the tags of the images for a stack layer. The tag is a hash of every input, so
// a new stack, a new pin or a changed Containerfile is a new image, never a silently changed one.
func ImagesFor(stack string) Images {
	h := sha256.New()
	for _, part := range []string{containerfile, managedSettings, NodeImage, ClaudeCode, OpenCode, GitleaksVersion, GitleaksSHA256} {
		fmt.Fprintf(h, "%d:%s\n", len(part), part)
	}
	fw := hex.EncodeToString(h.Sum(nil))[:12]
	fmt.Fprintf(h, "%d:%s\n", len(stack), stack)
	return Images{Work: "localhost/ygg-work:" + hex.EncodeToString(h.Sum(nil))[:12], Firewall: "localhost/ygg-fw:" + fw}
}

// FactoryStack is the local tag of the stack of a sandbox with no stack: the pinned Node image plus git
// (assets/Containerfile.factory-stack). The tag is a hash of that file and the Node image.
var FactoryStack = factoryStackTag(factoryStackFile, NodeImage)

func factoryStackTag(file, node string) string {
	h := sha256.New()
	for _, part := range []string{file, node} {
		fmt.Fprintf(h, "%d:%s\n", len(part), part)
	}
	return "localhost/ygg-factory-stack:" + hex.EncodeToString(h.Sum(nil))[:12]
}

// FactoryImages returns the images of a sandbox with no stack: the factory layer on FactoryStack. A scratch
// session (design, spec, plan) starts on them; Config.Images holds them for a spec that names no Stack.
func FactoryImages() Images { return ImagesFor(FactoryStack) }

// BuildFactory builds FactoryStack locally from the Node image, pulled once with the isolated auth, then
// the factory layer on it. Like Build, it is for ygg sandbox build alone.
func (d *Driver) BuildFactory(ctx context.Context) (Images, error) {
	if _, err := d.run(ctx, d.Podman, "pull", "-q", "--authfile", filepath.Join(d.auth, "auth.json"), NodeImage); err != nil {
		return Images{}, err
	}
	dir, err := os.MkdirTemp(d.work, "factory-stack-")
	if err != nil {
		return Images{}, err
	}
	defer os.RemoveAll(dir)
	file := filepath.Join(dir, "Containerfile")
	if err := os.WriteFile(file, []byte(factoryStackFile), 0o644); err != nil {
		return Images{}, err
	}
	if _, err := d.run(ctx, d.Podman, "build", "--pull=never", "-t", FactoryStack, "-f", file, "--build-arg", "NODE_IMAGE="+NodeImage, dir); err != nil {
		return Images{}, err
	}
	return d.build(ctx, FactoryStack, true)
}

// Pull fetches one image, which must be pinned by digest, with the isolated registry auth: a service's
// image, which a sandbox's compose file uses without ever pulling it (a run never pulls). Like Build, it
// is for ygg sandbox build alone.
func (d *Driver) Pull(ctx context.Context, image string) error {
	if !gungnir.ValidImage(image) {
		return fmt.Errorf("%q is not an image pinned by digest, so it is not pulled", image)
	}
	_, err := d.run(ctx, d.Podman, "pull", "-q", "--authfile", filepath.Join(d.auth, "auth.json"), image)
	return err
}

// Build pulls the bases by digest, with the isolated auth, and builds the firewall and work images
// for stack. It is the only call that reaches a registry, and ygg sandbox build is the only caller:
// a run never pulls or builds.
func (d *Driver) Build(ctx context.Context, stack string) (Images, error) {
	return d.build(ctx, stack, false)
}

// build is Build; nodePulled says the caller has just pulled the Node image, and may be true only straight
// after pull NodeImage, as in BuildFactory.
func (d *Driver) build(ctx context.Context, stack string, nodePulled bool) (Images, error) {
	imgs := ImagesFor(stack)
	ctxDir, err := os.MkdirTemp(d.work, "build-")
	if err != nil {
		return Images{}, err
	}
	defer os.RemoveAll(ctxDir)
	for name, body := range map[string]string{"Containerfile": containerfile, "managed-settings.json": managedSettings} {
		if err := os.WriteFile(filepath.Join(ctxDir, name), []byte(body), 0o644); err != nil {
			return Images{}, err
		}
	}
	for _, base := range []string{NodeImage, stack} {
		if base == NodeImage && nodePulled {
			continue
		}
		if base == stack && !gungnir.ValidImage(stack) {
			// A stack built from a realm's context is local (BuildStack): there is nothing to pull.
			if _, err := d.run(ctx, d.Podman, "image", "exists", stack); err != nil {
				return Images{}, fmt.Errorf("%w: %s (build the realm's stack first)", ErrNoImage, stack)
			}
			continue
		}
		if _, err := d.run(ctx, d.Podman, "pull", "-q", "--authfile", filepath.Join(d.auth, "auth.json"), base); err != nil {
			return Images{}, err
		}
	}
	args := func(target, tag string) []string {
		return []string{"build", "--pull=never", "--target", target, "-t", tag, "-f", filepath.Join(ctxDir, "Containerfile"),
			"--build-arg", "NODE_IMAGE=" + NodeImage, "--build-arg", "STACK_IMAGE=" + stack,
			"--build-arg", "CLAUDE_CODE_VERSION=" + ClaudeCode, "--build-arg", "OPENCODE_VERSION=" + OpenCode,
			"--build-arg", "GITLEAKS_VERSION=" + GitleaksVersion, "--build-arg", "GITLEAKS_SHA256=" + GitleaksSHA256, ctxDir}
	}
	for _, b := range []struct{ target, tag string }{{"fw", imgs.Firewall}, {"work", imgs.Work}} {
		if _, err := d.run(ctx, d.Podman, args(b.target, b.tag)...); err != nil {
			return Images{}, err
		}
	}
	return imgs, nil
}
