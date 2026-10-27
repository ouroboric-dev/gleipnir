package main

import (
	"net/url"
	"testing"
	"time"
)

// The link-time override of the body window may only shorten it: a longer, zero, negative or unparsable value
// keeps the 60 seconds.
func TestBodyWindowOverrideOnlyShortens(t *testing.T) {
	defer func(old string) { bodyWindowOverride = old }(bodyWindowOverride)
	up := &url.URL{Scheme: "http", Host: "x"}
	for _, c := range []struct {
		override string
		want     time.Duration
	}{
		{"", bodyWindow},
		{"300ms", 300 * time.Millisecond},
		{"10m", bodyWindow},
		{"60s", bodyWindow},
		{"0s", bodyWindow},
		{"-1s", bodyWindow},
		{"soon", bodyWindow},
	} {
		bodyWindowOverride = c.override
		if got := newGate(up, "allow").window; got != c.want {
			t.Errorf("override %q: window %v, want %v", c.override, got, c.want)
		}
	}
}
