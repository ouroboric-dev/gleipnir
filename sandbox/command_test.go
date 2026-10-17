package sandbox

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestAServiceRunsTheCommandItWasGivenAndNotTheImagesOwn(t *testing.T) {
	tmp := t.TempDir()
	c := cfg()
	c.Mounts = append(c.Mounts, PathMap{Host: tmp, Engine: "/mnt/wsl/cfg"})
	sp := withServices()
	sp.Services[0].Command = []string{"server", "-s3", "-dir=/data"}
	g, err := Generate(filepath.Join(tmp, "sandbox"), sp, c)
	if err != nil {
		t.Fatal(err)
	}
	var cf composeFile
	raw, _ := os.ReadFile(g.Compose)
	if err := yaml.Unmarshal(raw, &cf); err != nil {
		t.Fatal(err)
	}
	if got := cf.Services["seaweedfs"].Command; !slices.Equal(got, sp.Services[0].Command) {
		t.Errorf("seaweedfs command = %v, want %v", got, sp.Services[0].Command)
	}
	if got := cf.Services["postgres"].Command; got != nil {
		t.Errorf("postgres has no command of its own, yet compose says %v", got)
	}
	if err := Validate(g, sp, c); err != nil {
		t.Errorf("Validate() = %v; a command the spec names is part of what the factory renders", err)
	}
	// A command that differs from the spec's is not what the factory generated.
	tampered := strings.Replace(string(raw), "-dir=/data", "-dir=/etc", 1)
	if err := os.WriteFile(g.Compose, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Validate(g, sp, c); err == nil {
		t.Error("Validate() = nil for a compose file whose service command was changed")
	}
}
