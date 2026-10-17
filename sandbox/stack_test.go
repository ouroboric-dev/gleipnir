package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const otherStack = "docker.io/library/node:24.1.0-bookworm@sha256:3333333333333333333333333333333333333333333333333333333333333333"

func TestEachLeafStartsOnTheStackLayerOfItsRealm(t *testing.T) {
	tmp := t.TempDir()
	c := cfg()
	c.Mounts = append(c.Mounts, PathMap{Host: tmp, Engine: "/mnt/wsl/cfg"})
	work := func(stack string) (workImage, fwImage string) {
		sp := spec("/home/ana/ygg/proj")
		sp.Stack = stack
		g, err := Generate(filepath.Join(tmp, "s", strings.ReplaceAll(stack, "/", "_")), sp, c)
		if err != nil {
			t.Fatal(err)
		}
		var cf composeFile
		raw, _ := os.ReadFile(g.Compose)
		if err := yaml.Unmarshal(raw, &cf); err != nil {
			t.Fatal(err)
		}
		return cf.Services["work"].Image, cf.Services["fw"].Image
	}
	goWork, goFW := work(stackImg)
	nodeWork, nodeFW := work(otherStack)
	defWork, defFW := work("")
	if goWork != ImagesFor(stackImg).Work || nodeWork != ImagesFor(otherStack).Work {
		t.Errorf("work images %q and %q; want each realm's own stack layer", goWork, nodeWork)
	}
	if goWork == nodeWork {
		t.Error("two realms with two stacks got one work image")
	}
	if goFW != nodeFW || goFW != ImagesFor(stackImg).Firewall {
		t.Errorf("firewall images %q and %q; the firewall does not depend on the stack", goFW, nodeFW)
	}
	if defWork != c.Images.Work || defFW != c.Images.Firewall {
		t.Errorf("a spec with no stack uses the driver's images: %q, %q", defWork, defFW)
	}
}

func TestUpChecksTheImagesOfTheStackItWasGiven(t *testing.T) {
	d, log, sp := fakeEngine(t)
	sp.Stack = otherStack
	if _, err := d.Up(context.Background(), sp); err != nil {
		t.Fatal(err)
	}
	got := logOf(t, log)
	for _, want := range []string{"image exists " + ImagesFor(otherStack).Work, "image exists " + ImagesFor(otherStack).Firewall} {
		if !strings.Contains(got, want) {
			t.Errorf("Up did not check %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "image exists "+d.cfg.Images.Work) {
		t.Errorf("Up checked the driver's default work image for a spec with a stack:\n%s", got)
	}
	t.Setenv("STUB_MISSING", ImagesFor(otherStack).Work)
	d2, _, sp2 := fakeEngine(t)
	sp2.Stack = otherStack
	if _, err := d2.Up(context.Background(), sp2); !errors.Is(err, ErrNoImage) || !strings.Contains(err.Error(), ImagesFor(otherStack).Work) {
		t.Errorf("a missing image of the realm's stack: Up() = %v", err)
	}
}

func TestAConfigWithNoImagesAndASpecWithNoStackIsRefused(t *testing.T) {
	c := cfg()
	c.Images = Images{}
	if _, err := Generate(t.TempDir(), spec("/home/ana/ygg/proj"), Config{Images: c.Images, UID: 1000, GID: 1000}); err == nil {
		t.Error("a sandbox with no images at all was generated")
	}
	sp := spec("/home/ana/ygg/proj")
	sp.Stack = stackImg
	if _, err := Generate(t.TempDir(), sp, Config{UID: 1000, GID: 1000}); err != nil {
		t.Errorf("a spec with a stack needs no default images: %v", err)
	}
}
