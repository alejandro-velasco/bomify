// Package plugin dispatches SBOM components to external "bomify-plugin-*"
// helper binaries, letting bomify delegate component types it doesn't know
// how to build itself (e.g. container images) to a separate executable.
//
// A plugin for "kind" must be named "bomify-plugin-<kind>", be discoverable
// on PATH, and implement two subcommands:
//
//	bomify-plugin-<kind> pull --purl '<component purl>' --output <dir>
//	bomify-plugin-<kind> push --purl '<component purl>' --input <dir> --remote <endpoint>
//
// Both dir arguments are the same directory: a subdirectory of the base
// directory bomify was given, named after a hash of the component's purl,
// so pull and push (even in separate bomify invocations) independently
// agree on where the component lives without bomify tracking any state.
//
// pull fetches or builds the component and writes it into dir, which Pull
// creates before invoking the plugin — the plugin may assume dir already
// exists. If the plugin fails, Pull removes dir. On success, Pull writes a
// "<hash>.json" manifest next to dir (see Manifest); that manifest's
// existence is the authoritative signal that the pull succeeded. push
// publishes the component pull already wrote into dir to the remote
// endpoint; Push fails before invoking the plugin if that manifest doesn't
// exist (nothing was successfully pulled).
//
// On success the plugin must print a single JSON object describing the
// result to stdout (see Result) and exit 0. On failure it should exit
// non-zero; anything written to stderr is surfaced in bomify's error.
package plugin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
)

// binaryPrefix precedes the kind in a plugin's executable name.
const binaryPrefix = "bomify-plugin-"

// Result is the structured output a plugin prints to stdout on success.
type Result struct {
	// OutputPath is the location of the artifact the plugin produced.
	OutputPath string `json:"outputPath"`
	// Message is an optional human-readable summary of what happened.
	Message string `json:"message,omitempty"`
	// Hash is the content hash of the pulled artifact, for the algorithm
	// requested via --hash. A pull plugin should leave this zero if it
	// cannot compute a hash for the requested algorithm.
	Hash Hash `json:"hash,omitempty"`
}

// Hash is a content hash reported by a plugin, mirroring cdx.Hash.
type Hash struct {
	Algorithm cdx.HashAlgorithm `json:"algorithm,omitempty"`
	Value     string            `json:"value,omitempty"`
}

// hashAlgorithms lists the CycloneDX hash algorithms recognized by
// NormalizeHashAlgorithm.
var hashAlgorithms = []cdx.HashAlgorithm{
	cdx.HashAlgoMD5,
	cdx.HashAlgoSHA1,
	cdx.HashAlgoSHA256,
	cdx.HashAlgoSHA384,
	cdx.HashAlgoSHA512,
	cdx.HashAlgoSHA3_256,
	cdx.HashAlgoSHA3_384,
	cdx.HashAlgoSHA3_512,
	cdx.HashAlgoBlake2b_256,
	cdx.HashAlgoBlake2b_384,
	cdx.HashAlgoBlake2b_512,
	cdx.HashAlgoBlake3,
	cdx.HashAlgoStreebog256,
	cdx.HashAlgoStreebog512,
}

// NormalizeHashAlgorithm resolves a case- and hyphen-insensitive hash
// algorithm name, such as one passed via a --hash flag (e.g. "sha-256" or
// "sha256"), to its canonical CycloneDX form (e.g. "SHA-256"). It returns
// an error if name isn't a recognized CycloneDX hash algorithm.
func NormalizeHashAlgorithm(name string) (cdx.HashAlgorithm, error) {
	fold := func(s string) string {
		return strings.ToUpper(strings.ReplaceAll(s, "-", ""))
	}

	target := fold(name)
	for _, alg := range hashAlgorithms {
		if fold(string(alg)) == target {
			return alg, nil
		}
	}

	return "", fmt.Errorf("unrecognized hash algorithm %q", name)
}

// Print writes r to w as the single JSON object bomify expects a plugin to
// print to stdout on success. Plugins should call this instead of
// re-implementing JSON encoding themselves.
func (r *Result) Print(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("encode result: %w", err)
	}
	return nil
}

// Detect returns the plugin kind corresponding to the given SBOM component.
func Detect(component cdx.Component) (string, error) {
	purl, err := packageurl.FromString(component.PackageURL)
	if err != nil {
		return "", fmt.Errorf("parse package URL: %w", err)
	}

	return purl.Type, nil
}

// BinaryName returns the expected executable name for the plugin handling
// kind, e.g. BinaryName("docker") == "bomify-plugin-docker".
func BinaryName(kind string) string {
	return binaryPrefix + kind
}

// Find resolves the plugin binary for kind by searching PATH. It returns an
// error if no such plugin is installed.
func Find(kind string) (string, error) {
	name := BinaryName(kind)

	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("plugin %q not found on PATH: %w", name, err)
	}

	return path, nil
}

// Pull invokes the plugin binary's "pull" subcommand, which fetches or
// builds component and writes it into a subdirectory of baseDir named
// after a hash of component's purl. Pull creates that subdirectory before
// invoking the plugin and removes it again if the plugin fails.
//
// hashAlgorithm is passed to the plugin via --hash, asking it to report
// the pulled artifact's content hash for that algorithm in the result. If
// component declares its own hash for hashAlgorithm (in its SBOM
// metadata), Pull verifies the plugin's reported hash matches it, removing
// dir and failing on a mismatch. If either side has no hash to compare
// (the plugin couldn't compute one, or the SBOM doesn't declare one for
// this algorithm), verification is skipped.
func Pull(path string, component cdx.Component, baseDir string, hashAlgorithm cdx.HashAlgorithm) (*Result, error) {
	dir := componentDir(baseDir, component)

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create component directory %s: %w", dir, err)
	}

	result, err := run(path, "pull", component.PackageURL, "--output", dir, "--hash", string(hashAlgorithm))
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}

	if err := verifyHash(component, result); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}

	if err := writeManifest(baseDir, component, result.Hash); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}

	return result, nil
}

// Manifest is the record Pull writes to "<baseDir>/<purl-hash>.json" after
// a successful pull. Its existence at that path is the authoritative
// signal that the pull for the component it describes succeeded.
type Manifest struct {
	// Component is the SBOM component that was pulled, with the hash
	// computed during that pull (if any) merged into its Hashes.
	Component cdx.Component `json:"component"`
}

// writeManifest records component (with computed merged into its Hashes,
// if set) as the manifest for baseDir's component directory.
func writeManifest(baseDir string, component cdx.Component, computed Hash) error {
	if computed.Algorithm != "" {
		component.Hashes = mergeHash(component.Hashes, computed)
	}

	// json.Marshal HTML-escapes '&', '<', and '>' by default, which would
	// otherwise mangle purl query strings (e.g. "...&tag=..." becomes
	// "...&tag=..."). Encode directly with that disabled instead.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(Manifest{Component: component}); err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}

	path := manifestPath(baseDir, component)
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write manifest %s: %w", path, err)
	}

	return nil
}

// mergeHash returns existing with computed either replacing the entry for
// the same algorithm or appended, so a component's Hashes always reflects
// the most recently computed value for that algorithm.
func mergeHash(existing *[]cdx.Hash, computed Hash) *[]cdx.Hash {
	hashes := []cdx.Hash{}
	if existing != nil {
		hashes = append(hashes, *existing...)
	}

	for i, h := range hashes {
		if h.Algorithm == computed.Algorithm {
			hashes[i].Value = computed.Value
			return &hashes
		}
	}

	hashes = append(hashes, cdx.Hash{Algorithm: computed.Algorithm, Value: computed.Value})
	return &hashes
}

// verifyHash checks, when component declares an SBOM hash for the same
// algorithm result.Hash reports, that the two values match.
func verifyHash(component cdx.Component, result *Result) error {
	if result.Hash.Algorithm == "" || component.Hashes == nil {
		return nil
	}

	for _, declared := range *component.Hashes {
		if declared.Algorithm != result.Hash.Algorithm {
			continue
		}
		if !strings.EqualFold(declared.Value, result.Hash.Value) {
			return fmt.Errorf("%s hash mismatch for %s@%s: SBOM declares %s, pulled artifact has %s",
				result.Hash.Algorithm, component.Name, component.Version, declared.Value, result.Hash.Value)
		}
		return nil
	}

	return nil
}

// Push invokes the plugin binary's "push" subcommand, which publishes to
// remote the component a prior call to Pull wrote into baseDir. Push looks
// for that pull's manifest and fails before invoking the plugin if it
// doesn't exist (Pull only writes it after succeeding).
func Push(path string, component cdx.Component, baseDir, remote string) (*Result, error) {
	dir := componentDir(baseDir, component)

	if _, err := os.Stat(manifestPath(baseDir, component)); err != nil {
		return nil, fmt.Errorf("component not found in %s (run bomify build first): %w", dir, err)
	}

	return run(path, "push", component.PackageURL, "--input", dir, "--remote", remote)
}

// purlHash returns a hex-encoded hash of component's purl, used to derive
// both componentDir and manifestPath so pull and push independently agree
// on the same locations.
func purlHash(component cdx.Component) string {
	sum := sha256.Sum256([]byte(component.PackageURL))
	return hex.EncodeToString(sum[:])
}

// componentDir returns the deterministic subdirectory of baseDir where a
// component's pulled artifact lives.
func componentDir(baseDir string, component cdx.Component) string {
	return filepath.Join(baseDir, purlHash(component))
}

// manifestPath returns the deterministic path of a component's manifest
// file (see Manifest), a sibling of its componentDir.
func manifestPath(baseDir string, component cdx.Component) string {
	return filepath.Join(baseDir, purlHash(component)+".json")
}

// run invokes the plugin binary at path with subcommand verb, passing purl
// and the given extra arguments, and returns the plugin's parsed result.
func run(path, verb, purl string, extraArgs ...string) (*Result, error) {
	args := append([]string{verb, "--purl", purl}, extraArgs...)
	cmd := exec.Command(path, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("run plugin %s %s: %w%s", path, verb, err, formatStderr(stderr.String()))
	}

	var result Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		return nil, fmt.Errorf("parse output of plugin %s %s: %w", path, verb, err)
	}

	return &result, nil
}

func formatStderr(stderr string) string {
	stderr = strings.TrimSpace(stderr)
	if stderr == "" {
		return ""
	}
	return ": " + stderr
}
