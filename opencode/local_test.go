package opencode

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ouroboric-dev/gungnir"
)

func localAgent(t *testing.T, getenv func(string) string) *Agent {
	t.Helper()
	a, err := New("local/qwen3.8-27b", Config{
		Price:  &Price{Input: 0.10, Output: 0.40},
		Local:  &Local{BaseURL: "http://ygg-models:8089/v1", Context: 102400, Output: 32768},
		Getenv: getenv,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func localTask(f *fake, t *testing.T) gungnir.Task {
	tk := task(f, t)
	tk.Model = "local/qwen3.8-27b"
	return tk
}

func TestLocalConfigNamesTheLocalProvider(t *testing.T) {
	f := &fake{}
	conf, err := localAgent(t, nil).ConfigJSON(localTask(f, t))
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Small    string `json:"small_model"`
		Provider map[string]struct {
			NPM     string         `json:"npm"`
			Options map[string]any `json:"options"`
			Models  map[string]struct {
				ToolCall  bool           `json:"tool_call"`
				Reasoning bool           `json:"reasoning"`
				Options   map[string]any `json:"options"`
				Limit     struct{ Context, Output int }
			} `json:"models"`
		} `json:"provider"`
	}
	if err := json.Unmarshal([]byte(conf), &c); err != nil {
		t.Fatal(err)
	}
	if len(c.Provider) != 1 {
		t.Fatalf("providers = %v, want only local", c.Provider)
	}
	p, ok := c.Provider[LocalProvider]
	if !ok || p.NPM != "@ai-sdk/openai-compatible" || p.Options["baseURL"] != "http://ygg-models:8089/v1" {
		t.Fatalf("provider local = %+v", p)
	}
	if _, has := p.Options["apiKey"]; has || strings.Contains(conf, "apiKey") || strings.Contains(conf, KeyVar) {
		t.Errorf("a local configuration names a key: %s", conf)
	}
	m, ok := p.Models["qwen3.8-27b"]
	if !ok || !m.ToolCall || !m.Reasoning || m.Limit.Context != 102400 || m.Limit.Output != 32768 {
		t.Errorf("model = %+v", m)
	}
	if _, has := m.Options["reasoning"]; has || strings.Contains(conf, "reasoning\":{") {
		t.Errorf("a local configuration names a reasoning option: %s", conf)
	}
	if c.Small != "local/qwen3.8-27b" {
		t.Errorf("small_model = %q", c.Small)
	}
}

func TestLocalSessionNeedsNoOpenRouterKey(t *testing.T) {
	f := &fake{stdout: map[string]string{"run": fixture(t, "success.jsonl")}}
	a := localAgent(t, func(string) string { return "" })
	r, err := a.Run(context.Background(), localTask(f, t))
	if err != nil {
		t.Fatal(err)
	}
	run := f.calls[len(f.calls)-1]
	for _, k := range []string{"OPENCODE_CONFIG_CONTENT", "OPENCODE_DISABLE_PROJECT_CONFIG", "OPENCODE_DISABLE_CLAUDE_CODE", "OPENCODE_DISABLE_EXTERNAL_SKILLS", "OPENCODE_DISABLE_AUTOUPDATE", "OPENCODE_DISABLE_SHARE", "OPENCODE_DISABLE_MODELS_FETCH"} {
		if run.Env[k] == "" {
			t.Errorf("%s isn't set in a local session", k)
		}
	}
	if _, has := run.Env[KeyVar]; has {
		t.Error("the key variable is in a local session's environment")
	}
	if got := strings.Join(run.Argv, " "); got != "opencode run --format json -m local/qwen3.8-27b --auto" {
		t.Errorf("argv = %q", got)
	}
	if r.Provider != "local" {
		t.Errorf("Provider = %q", r.Provider)
	}
	tk := localTask(f, t)
	tk.Model = "openrouter/openai/gpt-4o-mini"
	if _, err := a.Run(context.Background(), tk); err == nil {
		t.Error("a task for another model ran")
	}
}

func TestLocalSessionCostsTheListPrice(t *testing.T) {
	f := &fake{stdout: map[string]string{"run": fixture(t, "success.jsonl")}}
	r, err := localAgent(t, nil).Run(context.Background(), localTask(f, t))
	if err != nil {
		t.Fatal(err)
	}
	want := (7*0.10 + 5*0.40) / 1e6
	if r.Usage.CostUSD != want || !r.Usage.CostEstimated || r.Provider != "local" {
		t.Errorf("usage = %+v, provider %q; want cost %v estimated", r.Usage, r.Provider, want)
	}
}

func TestLocalNeedsAPriceAndAServer(t *testing.T) {
	price, srv := &Price{Input: 1, Output: 1}, &Local{BaseURL: "http://m:1/v1", Context: 1000, Output: 100}
	for name, cfg := range map[string]Config{
		"no price":  {Local: srv},
		"no server": {Price: price},
		"no url":    {Price: price, Local: &Local{Context: 1000, Output: 100}},
		"no limits": {Price: price, Local: &Local{BaseURL: "http://m:1/v1"}},
	} {
		if _, err := New("local/qwen", cfg); err == nil {
			t.Errorf("%s: New() = nil, want an error", name)
		}
	}
	if _, err := New("local/Bad Name", Config{Price: price, Local: srv}); err == nil {
		t.Error("a bad local name was accepted")
	}
	if _, err := New("local/qwen", Config{Price: price, Local: srv}); err != nil {
		t.Errorf("a complete local config: %v", err)
	}
}

// A local model sends nothing outside the machine, so it meets privacy: strict (design §6) with the same config.
func TestLocalMeetsStrictPrivacyWithTheSameConfig(t *testing.T) {
	cfg := Config{Price: &Price{Input: 1, Output: 1}, Local: &Local{BaseURL: "http://m:1/v1", Context: 1000, Output: 100}}
	var confs []string
	for _, privacy := range []string{"", "standard", "strict"} {
		cfg.Privacy = privacy
		a, err := New("local/qwen", cfg)
		if err != nil {
			t.Fatalf("privacy %q: %v", privacy, err)
		}
		c, err := a.ConfigJSON(gungnir.Task{})
		if err != nil {
			t.Fatal(err)
		}
		confs = append(confs, c)
	}
	if confs[0] != confs[1] || confs[1] != confs[2] {
		t.Errorf("the configs differ by privacy: %v", confs)
	}
	cfg.Privacy = "loose"
	if _, err := New("local/qwen", cfg); err == nil {
		t.Error("an unknown privacy was accepted")
	}
}
