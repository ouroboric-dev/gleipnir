package failure

import (
	"testing"

	"github.com/ouroboric-dev/gungnir"
)

func TestClassify(t *testing.T) {
	const (
		agent     = gungnir.FailureAgent
		transient = gungnir.FailureTransient
		quota     = gungnir.FailureQuota
	)
	cases := []struct {
		name    string
		status  int
		message string
		want    gungnir.FailureKind
	}{
		{"a rate limit", 429, "Rate limit exceeded, retry in 20s", transient},
		{"overloaded", 529, "Overloaded", transient},
		{"a server error", 502, "Bad Gateway", transient},
		{"a request timeout", 408, "Request Timeout", transient},
		{"a network error with no status", 0, "fetch failed: ECONNRESET", transient},
		{"a rate limit with no status", 0, "too many requests", transient},
		{"credits used up", 402, "Insufficient credits", quota},
		{"credits used up, reported as a 429", 429, "You have insufficient credits for this request", quota},
		{"a plan's usage limit", 0, "Claude usage limit reached. Your limit will reset at 3pm", quota},
		{"a plan's usage limit, reported as a 429", 429, "5-hour limit reached, resets 3pm", quota},
		{"a key over its credit limit", 403, "Key limit exceeded (monthly limit)", quota},
		{"a quota", 429, "You exceeded your current quota", quota},
		{"a bad request", 400, "invalid request", agent},
		{"an unauthorised key", 401, "invalid api key", agent},
		{"a not found model", 404, "model not found", agent},
		{"no status and no known words", 0, "the agent gave up", agent},
		{"nothing at all", 0, "", agent},
		{"an agent that talks about a network", 0, "I could not finish: the tests need network access and a timeout", agent},
	}
	for _, c := range cases {
		if got := Classify(c.status, c.message); got != c.want {
			t.Errorf("%s: Classify(%d, %q) = %q, want %q", c.name, c.status, c.message, got, c.want)
		}
	}
}
