package opencode

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ouroboric-dev/gungnir"
)

func newAgent(t *testing.T, privacy string, price *Price) *Agent {
	t.Helper()
	a, err := New("openrouter/openai/gpt-4o-mini", Config{Privacy: privacy, Price: price,
		Getenv: func(k string) string { return map[string]string{KeyVar: "or-key-secret"}[k] }})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestStrictPrivacyIsSetOnEveryModelTheToolMayCall(t *testing.T) {
	a := newAgent(t, "strict", nil)
	conf, err := a.ConfigJSON(gungnir.Task{})
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Small    string `json:"small_model"`
		Provider map[string]struct {
			Options map[string]string `json:"options"`
			Models  map[string]struct {
				Options struct{ Provider map[string]any } `json:"options"`
			} `json:"models"`
		} `json:"provider"`
	}
	if err := json.Unmarshal([]byte(conf), &c); err != nil {
		t.Fatal(err)
	}
	m := c.Provider["openrouter"].Models["openai/gpt-4o-mini"].Options.Provider
	if m["data_collection"] != "deny" || m["zdr"] != true || m["allow_fallbacks"] != false {
		t.Errorf("the model's provider settings = %v", m)
	}
	if c.Small != "openrouter/openai/gpt-4o-mini" {
		t.Errorf("small_model = %q: it must be a model that carries the settings, or titles go out unfiltered", c.Small)
	}
	if strings.Contains(conf, "or-key-secret") || !strings.Contains(conf, "{env:"+KeyVar+"}") {
		t.Errorf("the config holds the key instead of a reference: %s", conf)
	}
	standard, _ := newAgent(t, "standard", nil).ConfigJSON(gungnir.Task{})
	if strings.Contains(standard, "data_collection") {
		t.Error("standard privacy sets provider restrictions")
	}
}

func TestStrictRefusesAModelItCannotTighten(t *testing.T) {
	for _, model := range []string{"anthropic/claude-sonnet", "openrouter/", "gpt-4o"} {
		if _, err := New(model, Config{Privacy: "strict"}); err == nil {
			t.Errorf("New(%q) = nil, want a refusal", model)
		}
	}
	if _, err := New("openrouter/x/y", Config{Privacy: "paranoid"}); err == nil {
		t.Error("an unknown privacy level was accepted")
	}
}

func TestAReadOnlyRoleGetsNoWriteOrShellPermission(t *testing.T) {
	conf, _ := newAgent(t, "standard", nil).ConfigJSON(gungnir.Task{ReadOnly: true, MaxTurns: 6})
	if !strings.Contains(conf, `"edit":"deny"`) || !strings.Contains(conf, `"bash":"deny"`) || !strings.Contains(conf, `"steps":6`) {
		t.Errorf("config = %s", conf)
	}
	if got := strings.Join(Args(gungnir.Task{ReadOnly: true}, "x/y"), " "); strings.Contains(got, "--auto") {
		t.Errorf("a read-only role's command line = %q", got)
	}
}
