// Package opencode is the adapter for opencode run with JSON events (spec §5), on OpenRouter
// models. It runs only in a sandbox. Its configuration goes in through the environment, and the
// repository's own opencode configuration, plugins and skills are switched off, because a plugin
// in a hostile repository ran on startup in the sandbox spike's check.
package opencode

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ouroboric-dev/gungnir"
)

// KeyVar is the one credential the adapter passes: a dedicated OpenRouter key with a hard credit
// limit (spec §6.3).
const KeyVar = "OPENROUTER_API_KEY"

// Hosts are what the sandbox's firewall must open for a session.
var Hosts = []string{"openrouter.ai"}

// Price is a model's price in dollars per million tokens. An operator sets it in factory.yaml when
// the tool's own cost figure is missing or wrong.
type Price struct{ Input, Output, CacheRead, CacheWrite float64 }

// Config holds what one role's adapter needs.
type Config struct {
	Privacy string              // "standard" or "strict"
	Price   *Price              // optional: cost is then computed from tokens, and marked estimated
	Getenv  func(string) string // the host's environment; os.Getenv by default
}

// Agent is the opencode adapter for one role's model.
type Agent struct {
	cfg   Config
	model string // the id on OpenRouter, without the openrouter/ prefix
}

// strictProvider is what privacy: strict means on OpenRouter (sandbox spike C, decided 2026-10-14):
// providers that keep no data and don't train, and no fallback to another one.
var strictProvider = map[string]any{"data_collection": "deny", "zdr": true, "allow_fallbacks": false}

// New returns the adapter for model, such as openrouter/deepseek/deepseek-v4-flash. It refuses
// privacy: strict for a model it can't tighten: the setting is made on OpenRouter's requests, so
// it can't cover a model served any other way.
func New(model string, cfg Config) (*Agent, error) {
	id, ok := strings.CutPrefix(model, "openrouter/")
	if !ok || id == "" {
		return nil, fmt.Errorf("opencode: model %q must be openrouter/<model>: v0 runs opencode on OpenRouter only", model)
	}
	switch cfg.Privacy {
	case "", "standard", "strict":
	default:
		return nil, fmt.Errorf("opencode: privacy %q is neither standard nor strict", cfg.Privacy)
	}
	return &Agent{cfg: cfg, model: id}, nil
}

func (a *Agent) Name() string { return "opencode" }

func (a *Agent) getenv(k string) string {
	if a.cfg.Getenv != nil {
		return a.cfg.Getenv(k)
	}
	return os.Getenv(k)
}

// ConfigJSON is the configuration of a session, which reaches opencode as OPENCODE_CONFIG_CONTENT.
// The key is a reference to the environment, never a value. Under strict privacy the provider
// settings sit on the model, and small_model, which opencode uses for titles, is the same model: a
// second model without them would send the prompt to a provider chosen with no filter (spike C).
func (a *Agent) ConfigJSON(t gungnir.Task) (string, error) {
	model := map[string]any{}
	if a.cfg.Privacy == "strict" {
		model["options"] = map[string]any{"provider": strictProvider}
	}
	c := map[string]any{
		"$schema": "https://opencode.ai/config.json", "autoupdate": false, "share": "disabled",
		"provider": map[string]any{"openrouter": map[string]any{
			"options": map[string]any{"apiKey": "{env:" + KeyVar + "}"},
			"models":  map[string]any{a.model: model},
		}},
		"small_model": "openrouter/" + a.model,
	}
	if t.MaxTurns > 0 {
		c["agent"] = map[string]any{"build": map[string]any{"steps": t.MaxTurns}}
	}
	if t.ReadOnly {
		c["permission"] = map[string]any{"edit": "deny", "bash": "deny", "webfetch": "deny"}
	}
	b, err := json.Marshal(c)
	return string(b), err
}

// Args returns the command line of a session, apart from its prompt, which goes on stdin.
func Args(t gungnir.Task, model string) []string {
	args := []string{"opencode", "run", "--format", "json", "-m", "openrouter/" + model}
	if !t.ReadOnly {
		args = append(args, "--auto")
	}
	return args
}
