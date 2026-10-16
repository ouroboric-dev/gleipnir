package skills

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/ouroboric-dev/havamal"
)

func pinned(t *testing.T) *havamal.Library {
	t.Helper()
	text := "---\nname: plain-language\ndescription: Write plainly.\n---\nUse short words.\n"
	fsys := fstest.MapFS{
		"skills/.gitkeep":                {},
		"skills/plain-language/SKILL.md": {Data: []byte(text)},
		"skills/plain-language/LICENSE":  {Data: []byte("MIT\n")},
	}
	lock := &havamal.Lock{Skills: []havamal.Entry{{Name: "plain-language", Licence: "MIT",
		Upstream: &havamal.Upstream{Repo: "https://github.com/example/w", Path: "plain-language", Commit: strings.Repeat("a", 40)},
		Files:    []havamal.File{{Path: "LICENSE", SHA256: havamal.Sum([]byte("MIT\n"))}, {Path: "SKILL.md", SHA256: havamal.Sum([]byte(text))}}}}}
	b, _ := lock.Marshal()
	fsys["skills.lock"] = &fstest.MapFile{Data: b}
	lib, err := havamal.Open(fsys)
	if err != nil {
		t.Fatal(err)
	}
	return lib
}

func TestLoadGivesOnlyTheNamedSkills(t *testing.T) {
	l := Libraries{Pinned: pinned(t)}
	text, err := l.Load([]string{"plain-language"})
	if err != nil || !strings.Contains(text, "### plain-language") || !strings.Contains(text, "Use short words.") || strings.Contains(text, "name:") {
		t.Errorf("Load() = %q, %v; want the skill's text without its front matter", text, err)
	}
	if text, err := l.Load(nil); err != nil || text != "" {
		t.Errorf("a task naming no skill got %q, %v", text, err)
	}
	if _, err := l.Load([]string{"nope"}); err == nil {
		t.Error("a task naming a skill nobody has loaded without an error")
	}
}

func TestTheRecordHashesTheSetAndNamesPrivateSkills(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "mine"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "mine", "SKILL.md"), []byte("---\nname: mine\ndescription: Mine.\n---\nHi.\n"), 0o644)
	private, err := havamal.OpenPrivate(dir)
	if err != nil {
		t.Fatal(err)
	}
	l := Libraries{Pinned: pinned(t), Private: private}
	r, err := l.Record([]string{"plain-language", "mine", "plain-language"})
	if err != nil || len(r.Hash) != 64 || strings.Join(r.Skills, ",") != "mine,plain-language" || len(r.Private) != 1 || r.Private[0].Name != "mine" {
		t.Fatalf("Record() = %+v, %v", r, err)
	}
	only, _ := l.Record([]string{"plain-language"})
	if only.Hash == r.Hash {
		t.Error("the hash ignores the private skill")
	}
	if _, err := l.Record([]string{"missing"}); err == nil {
		t.Error("a record for a missing skill")
	}
}
