// Package sandbox is Gleipnir's devcontainer driver (spec §6): it builds a leaf's hardened
// sandbox from a factory-owned configuration, checks that configuration before every start, and
// runs commands in it through the container engine.
package sandbox

import _ "embed"

// EgressScript is the firewall sidecar's script. See the comment at its top.
//
//go:embed assets/egress.sh
var EgressScript string
