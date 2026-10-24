// Package sandbox is Gleipnir's devcontainer driver (spec §6): it builds a leaf's hardened
// sandbox from a factory-owned configuration, checks that configuration before every start, and
// runs commands in it through the container engine.
package sandbox

import (
	_ "embed"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/ouroboric-dev/gungnir/schema"
)

// EgressScript is the firewall sidecar's script. See the comment at its top.
//
//go:embed assets/egress.sh
var EgressScript string

// submitScript is ygg-submit, the stdio MCP server through which a session hands back its typed output
// (change typed-boundaries). The work image carries it at /opt/ygg/bin/ygg-submit.
//
//go:embed assets/ygg-submit.mjs
var submitScript string

// checkResultScript is ygg-check-result, which converts a check tool's machine output into a ygg.check/v1 result
// (change typed-boundaries, design section 4). The work image carries it at /opt/ygg/bin/ygg-check-result.
//
//go:embed assets/ygg-check-result.mjs
var checkResultScript string

// submitPackage and submitLock pin ygg-submit's validator and everything under it. The work image installs
// them with npm ci, and the tests install the same tree.
//
//go:embed assets/submit/package.json
var submitPackage string

//go:embed assets/submit/package-lock.json
var submitLock string

// writeSchemas writes every embedded schema of gungnir into dir: the contracts the work image carries at
// /opt/ygg/schemas, which ygg-submit validates against.
func writeSchemas(dir string) error {
	return fs.WalkDir(schema.SchemaFS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		body, err := fs.ReadFile(schema.SchemaFS(), p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dir, filepath.Base(p)), body, 0o644)
	})
}
