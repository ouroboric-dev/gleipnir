// Package failure decides how a failed model session failed (spec §12), from what the provider or
// the tool reported. The answer decides what happens next: a transient failure is retried with a
// backoff, a used-up quota pauses the run, anything else is an agent failure that counts as a loop
// attempt. What this package can't tell is an agent failure: the loop is bounded, so the safe reading
// of an unknown failure is the one that counts against the attempts.
package failure

import (
	"regexp"

	"github.com/ouroboric-dev/gungnir"
)

// quota matches the words providers use when a quota, a credit balance or a plan's usage limit is
// used up. A plain rate limit is not here: it clears in seconds, and is transient.
var quota = regexp.MustCompile(`(?i)usage limit|(?:key|credit|spend|monthly|daily|weekly) limit|limit reached|reached (?:your|the) (?:\w+ )?limit|hit your limit|quota|insufficient (?:credits|funds)|out of credits|credit balance|billing|payment required`)

// transient matches the words of a network or capacity failure that reports no status.
var transient = regexp.MustCompile(`(?i)overloaded|rate.?limit|too many requests|temporarily unavailable|ECONNRESET|ECONNREFUSED|ETIMEDOUT|EAI_AGAIN|socket hang up|fetch failed|connection (?:reset|refused|closed)|service unavailable|bad gateway|gateway time-?out`)

// Classify returns how a session failed, given the HTTP status the provider returned (0 when none was
// reported) and the message the tool printed. Quota wins over every status, since providers report a
// used-up quota with a 429.
func Classify(status int, message string) gungnir.FailureKind {
	switch {
	case status == 402 || quota.MatchString(message):
		return gungnir.FailureQuota
	case status == 408 || status == 429 || status >= 500:
		return gungnir.FailureTransient
	case status == 0 && transient.MatchString(message):
		return gungnir.FailureTransient
	}
	return gungnir.FailureAgent
}
