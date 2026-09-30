package plugin

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"

	"fmt"
	"log/slog"
	"os"

	"github.com/alejandro-velasco/bomify/internal/layout"
)

// HashAlgorithm is the one hash algorithm bomify verifies components
// with, and the only one a component plugin reports (see
// plugins/COMPONENT-CONTRACT.md): the data directory is keyed by SHA-256
// throughout, so supporting any other would buy nothing.
const HashAlgorithm = pluginlib.HashAlgorithm

// Pull invokes the plugin binary's "pull" subcommand, which fetches or
// builds component and writes it into componentDir's directory. Pull
// clears that directory (if it already exists) and recreates it empty
// before invoking the plugin — see the package doc comment for why it
// might not already be empty — and removes it again if the plugin fails.
//
// The plugin reports the pulled artifact's SHA-256 (see HashAlgorithm).
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
// logger controls whether the plugin's own log file is streamed live to
// stdout while it runs: it is if logger has debug-level logging enabled
// (i.e. bomify was run with --verbose), and isn't otherwise.
func Pull(path string, component cdx.Component, baseDir string, logger *slog.Logger) (*pluginlib.Result, error) {
	return pull(component, baseDir, func(dir string) (*pluginlib.Result, error) {
		return runComponent[pluginlib.Result](path, "pull", component, baseDir, logger, "--output", dir)
	})
}

// Push invokes the plugin binary's "push" subcommand, which publishes to
// remote the component a prior call to Pull wrote into baseDir. Push looks
// for that pull's manifest and fails before invoking the plugin if it
// doesn't exist (Pull only writes it after succeeding).
//
// logger controls log streaming exactly as it does for Pull.
func Push(path string, component cdx.Component, baseDir, remote string, logger *slog.Logger) (*pluginlib.Result, error) {
	dir := layout.ComponentLayer(baseDir, component.PackageURL)

	if _, err := os.Stat(layout.ComponentManifest(baseDir, component.PackageURL)); err != nil {
		return nil, fmt.Errorf("component not found in %s (run bomify build first): %w", dir, err)
	}

	return runComponent[pluginlib.Result](path, "push", component, baseDir, logger, "--input", dir, "--remote", remote)
}

// CheckPull invokes the plugin's "pull" subcommand in --check mode: an
// inexpensive verification that a real Pull would succeed, without
// transferring content. Like Remote, it's stateless — no component
// directory, pid file, or dedup against a concurrent/prior call. If the
// plugin reports a hash, CheckPull verifies it against component's
// SBOM-declared hash exactly as Pull does.
func CheckPull(path string, component cdx.Component, baseDir string, logger *slog.Logger) (*pluginlib.Result, error) {
	result, err := runComponent[pluginlib.Result](path, "pull", component, baseDir, logger, "--check=true")
	if err != nil {
		return nil, err
	}

	if err := verifyHash(component, result); err != nil {
		return nil, err
	}

	return result, nil
}

// CheckPush invokes the plugin's "push" subcommand in --check mode: an
// inexpensive verification that a real Push to remote would succeed,
// without publishing anything. Like CheckPull, it's stateless and
// requires no prior Pull.
func CheckPush(path string, component cdx.Component, baseDir, remote string, logger *slog.Logger) (*pluginlib.Result, error) {
	return runComponent[pluginlib.Result](path, "push", component, baseDir, logger, "--remote", remote, "--check=true")
}

// Remote invokes the plugin binary's "remote" subcommand, which reports
// where component's content comes from or is published under (see
// pluginlib.RemoteResult), independent of any specific --remote a push
// might target — this is what a distribution rule's --match compares
// against (see internal/distribution). Unlike Pull/Push, Remote is a
// pure, stateless query: it never touches baseDir beyond a throwaway log
// file, and nothing about its result is cached.
//
// logger controls log streaming exactly as it does for Pull/Push.
func Remote(path string, component cdx.Component, baseDir string, logger *slog.Logger) (string, error) {
	result, err := runComponent[pluginlib.RemoteResult](path, "remote", component, baseDir, logger)
	if err != nil {
		return "", err
	}
	return result.Remote, nil
}
