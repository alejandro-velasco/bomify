package plugin

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"

	"log/slog"
)

// Pull invokes the plugin binary's "pull" subcommand, which fetches or
// builds component and writes it into componentDir's directory. Pull
// clears that directory (if it already exists) and recreates it empty
// before invoking the plugin — see the package doc comment for why it
// might not already be empty — and removes it again if the plugin fails.
//
// The plugin reports the pulled artifact's SHA-256 (see
// pluginlib.HashAlgorithm).
// If component declares its own SHA-256 in its SBOM metadata, Pull
// verifies the two match —
// removing dir and failing on a mismatch for a pull this call just
// performed, or failing without touching dir when reusing a concurrent
// or prior pull's result, since this call doesn't own it. Verification is
// skipped if either side has no hash to compare.
//
// Pull is safe to call concurrently — including from separate bomify
// processes — for components that hash to the same directory (e.g.
// duplicate purls within or across SBOMs). See the package doc comment
// for the exact rules it follows to avoid pulling the same component
// twice at once.
//
// logger controls whether the plugin's own log file is printed with
// bomify's log while it runs: it is if logger has debug-level logging
// enabled (i.e. bomify was run with --verbose), and isn't otherwise.
//
// tracker, if not nil, shows the plugin's run and the progress it
// reports; a pull reused from a prior or concurrent one shows nothing.
func Pull(path string, component cdx.Component, baseDir string, logger *slog.Logger, tracker Tracker) (*pluginlib.Result, error) {
	return pull(component, baseDir, func(dir string) (*pluginlib.Result, error) {
		return runComponent[pluginlib.Result](path, "pull", component, baseDir, logger, tracker, "--output", dir)
	})
}

// CheckPull invokes the plugin's "pull" subcommand in --check mode: an
// inexpensive verification that a real Pull would succeed, without
// transferring content. It's stateless — no component directory, pid
// file, or dedup against a concurrent/prior call. If the plugin reports a
// hash, CheckPull verifies it against component's SBOM-declared hash
// exactly as Pull does.
func CheckPull(path string, component cdx.Component, baseDir string, logger *slog.Logger) (*pluginlib.Result, error) {
	result, err := runComponent[pluginlib.Result](path, "pull", component, baseDir, logger, nil, "--check=true")
	if err != nil {
		return nil, err
	}

	if err := verifyHash(component, result); err != nil {
		return nil, err
	}

	return result, nil
}

// Pack invokes the plugin binary's "pack" subcommand, which describes the
// component a prior Pull wrote into input in its kind's own registry
// format (see pluginlib.PackResult), any blob it builds inline. The zero
// PackResult means the kind has no format of its own.
//
// logger controls log streaming exactly as it does for Pull.
func Pack(path string, component cdx.Component, baseDir, input string, logger *slog.Logger) (*pluginlib.PackResult, error) {
	return runComponent[pluginlib.PackResult](path, "pack", component, baseDir, logger, nil, "--input", input)
}
