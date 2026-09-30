// Package layout is the single source of truth for where everything lives
// inside a bomify data directory (see docs/architecture/data-directory.md).
// Every other package derives its paths from here rather than
// joining directory names itself, so the layout can only ever change in
// one place.
//
// Content is keyed two ways: a build's own manifest by its SBOM's content
// hash, and everything belonging to one component (its layer, pull
// manifest, pid file, plugin log, and vulnerability report) by its purl's
// hash (see PurlHash), so an identical component pulled by two different
// SBOMs shares one of each.
package layout

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
)

// PurlHash returns the hex-encoded SHA-256 of purl: the key every
// per-component file in the data directory is named by.
func PurlHash(purl string) string {
	sum := sha256.Sum256([]byte(purl))
	return hex.EncodeToString(sum[:])
}

// Layers returns "<dataDir>/layers".
func Layers(dataDir string) string { return filepath.Join(dataDir, "layers") }

// Layer returns "<dataDir>/layers/<hash>": a component's pulled content
// when hash is its PurlHash, or a foreign OCI layer's when hash is that
// blob's digest.
func Layer(dataDir, hash string) string { return filepath.Join(Layers(dataDir), hash) }

// Manifests returns "<dataDir>/manifests".
func Manifests(dataDir string) string { return filepath.Join(dataDir, "manifests") }

// Manifest returns "<dataDir>/manifests/<hash>.json": a build's own SBOM
// manifest when hash is the SBOM's content hash, or a component's pull
// manifest when hash is its PurlHash.
func Manifest(dataDir, hash string) string {
	return filepath.Join(Manifests(dataDir), hash+".json")
}

// PID returns "<dataDir>/manifests/<hash>.pid", the pid file claimed
// while the component whose PurlHash is hash is being pulled.
func PID(dataDir, hash string) string { return filepath.Join(Manifests(dataDir), hash+".pid") }

// Log returns "<dataDir>/logs/<hash>.log", the transient plugin log for
// the component whose PurlHash is hash.
func Log(dataDir, hash string) string { return filepath.Join(dataDir, "logs", hash+".log") }

// Reports returns "<dataDir>/vulnerabilities".
func Reports(dataDir string) string { return filepath.Join(dataDir, "vulnerabilities") }

// Report returns "<dataDir>/vulnerabilities/<hash>.json", the
// vulnerability report of the component whose PurlHash is hash.
func Report(dataDir, hash string) string { return filepath.Join(Reports(dataDir), hash+".json") }

// ComponentLayer is Layer for the component with purl.
func ComponentLayer(dataDir, purl string) string { return Layer(dataDir, PurlHash(purl)) }

// ComponentManifest is Manifest for the component with purl.
func ComponentManifest(dataDir, purl string) string { return Manifest(dataDir, PurlHash(purl)) }

// ComponentPID is PID for the component with purl.
func ComponentPID(dataDir, purl string) string { return PID(dataDir, PurlHash(purl)) }

// ComponentLog is Log for the component with purl.
func ComponentLog(dataDir, purl string) string { return Log(dataDir, PurlHash(purl)) }

// ComponentReport is Report for the component with purl.
func ComponentReport(dataDir, purl string) string { return Report(dataDir, PurlHash(purl)) }

// Repositories returns "<dataDir>/package/repositories.json", the tag
// record.
func Repositories(dataDir string) string {
	return filepath.Join(dataDir, "package", "repositories.json")
}

// Plugins returns "<dataDir>/plugins", the only directory plugins are
// installed into and discovered from.
func Plugins(dataDir string) string { return filepath.Join(dataDir, "plugins") }

// Keys returns "<dataDir>/keys", the managed public key store.
func Keys(dataDir string) string { return filepath.Join(dataDir, "keys") }

// VEX returns "<dataDir>/vex", the managed VEX document store.
func VEX(dataDir string) string { return filepath.Join(dataDir, "vex") }

// DistributionConfig returns "<dataDir>/conf/distribution.json".
func DistributionConfig(dataDir string) string { return conf(dataDir, "distribution.json") }

// TrustConfig returns "<dataDir>/conf/trust.json".
func TrustConfig(dataDir string) string { return conf(dataDir, "trust.json") }

// ScanConfig returns "<dataDir>/conf/scan.json".
func ScanConfig(dataDir string) string { return conf(dataDir, "scan.json") }

func conf(dataDir, name string) string { return filepath.Join(dataDir, "conf", name) }
