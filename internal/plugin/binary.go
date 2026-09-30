package plugin

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"

	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

// Binary describes a PurlType component: the plugin binary it carries,
// and the platform that binary was built for.
type Binary struct {
	// Kind is the plugin's kind — the purl's name — so the binary is
	// installed as bomify-plugin-<Kind>.
	Kind string
	// Version is the purl's version, if any.
	Version string
	// OS and Arch are the purl's "os"/"arch" qualifiers, in GOOS/GOARCH
	// terms. Either is empty when the binary doesn't depend on it.
	OS   string
	Arch string
}

// ParseBinary parses component's purl as a PurlType component. ok is
// false, with a nil error, when component simply isn't one.
func ParseBinary(component cdx.Component) (b Binary, ok bool, err error) {
	if component.PackageURL == "" {
		return Binary{}, false, nil
	}

	purl, err := packageurl.FromString(component.PackageURL)
	if err != nil {
		return Binary{}, false, fmt.Errorf("parse package URL: %w", err)
	}
	if purl.Type != PurlType {
		return Binary{}, false, nil
	}
	if purl.Namespace != "" || purl.Name == "" || strings.ContainsAny(purl.Name, `/\`) || purl.Name == "." || purl.Name == ".." {
		return Binary{}, false, fmt.Errorf("%s: want pkg:%s/<kind>[@version][?os=...&arch=...]", component.PackageURL, PurlType)
	}

	qualifiers := purl.Qualifiers.Map()
	return Binary{Kind: purl.Name, Version: purl.Version, OS: qualifiers["os"], Arch: qualifiers["arch"]}, true, nil
}

// Matches reports whether b runs on goos/goarch: each of OS/Arch either
// equals it or is empty.
func (b Binary) Matches(goos, goarch string) bool {
	return (b.OS == "" || b.OS == goos) && (b.Arch == "" || b.Arch == goarch)
}

// FileName is the name b's binary is stored under inside its component
// directory: bomify-plugin-<Kind>, plus ".exe" when built for Windows.
func (b Binary) FileName() string {
	return ExecutableName(b.Kind, b.OS)
}

// PullBinary is Pull for a PurlType component: rather than dispatching it
// to a plugin, bomify copies the binary itself, from the local file its
// "distribution" external reference names (see BinarySource), into
// component's directory under baseDir — with exactly Pull's concurrency,
// reuse, hash verification, and manifest bookkeeping. sbomDir is the
// directory of the SBOM component came from, which a relative source path
// is resolved against.
func PullBinary(component cdx.Component, sbomDir, baseDir string) (*pluginlib.Result, error) {
	b, ok, err := ParseBinary(component)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%s is not a pkg:%s component", component.PackageURL, PurlType)
	}

	return pull(component, baseDir, func(dir string) (*pluginlib.Result, error) {
		src, err := BinarySource(component, sbomDir)
		if err != nil {
			return nil, err
		}

		dst := filepath.Join(dir, b.FileName())
		sum, err := copyHashed(src, dst)
		if err != nil {
			return nil, err
		}

		return &pluginlib.Result{
			OutputPath: dst,
			Message:    "copied plugin binary from " + src,
			Hash:       pluginlib.NewHash(sum),
		}, nil
	})
}

// CheckBinary is CheckPull for a PurlType component: it confirms the
// binary PullBinary would copy exists and matches component's
// SBOM-declared hash, without copying anything.
func CheckBinary(component cdx.Component, sbomDir string) (*pluginlib.Result, error) {
	src, err := BinarySource(component, sbomDir)
	if err != nil {
		return nil, err
	}

	sum, err := HashFile(src)
	if err != nil {
		return nil, err
	}

	result := &pluginlib.Result{Message: "plugin binary found at " + src, Hash: pluginlib.NewHash(sum)}
	if err := verifyHash(component, result); err != nil {
		return nil, err
	}
	return result, nil
}

// BinarySource returns the local file a PurlType component's binary is
// copied from at build time: the URL of its "distribution" external
// reference — a plain path, relative ones resolved against sbomDir, or a
// file:// URL. Remote URLs aren't supported.
func BinarySource(component cdx.Component, sbomDir string) (string, error) {
	if component.ExternalReferences != nil {
		for _, ref := range *component.ExternalReferences {
			if ref.Type != cdx.ERTypeDistribution || ref.URL == "" {
				continue
			}
			return localPath(ref.URL, sbomDir)
		}
	}
	return "", fmt.Errorf("%s has no %q external reference naming its binary", component.PackageURL, cdx.ERTypeDistribution)
}

// localPath resolves raw — a plain path or a file:// URL — to a local
// file path.
func localPath(raw, sbomDir string) (string, error) {
	if strings.HasPrefix(raw, "file://") {
		u, err := url.Parse(raw)
		if err != nil {
			return "", fmt.Errorf("parse %s: %w", raw, err)
		}
		p := u.Path
		// file:///C:/x parses to "/C:/x" on Windows; drop the leading slash.
		if runtime.GOOS == "windows" && len(p) > 2 && p[0] == '/' && p[2] == ':' {
			p = p[1:]
		}
		return filepath.FromSlash(p), nil
	}
	if strings.Contains(raw, "://") {
		return "", fmt.Errorf("%s: only local paths and file:// URLs are supported for plugin binaries", raw)
	}
	if !filepath.IsAbs(raw) {
		raw = filepath.Join(sbomDir, raw)
	}
	return raw, nil
}

// HashFile returns path's SHA-256 (see pluginlib.HashAlgorithm),
// hex-encoded.
func HashFile(path string) (string, error) {
	h := sha256.New()
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// copyHashed copies src to dst (executable), returning its SHA-256 (see
// pluginlib.HashAlgorithm), hex-encoded.
func copyHashed(src, dst string) (string, error) {
	h := sha256.New()
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(io.MultiWriter(out, h), in); err != nil {
		out.Close()
		return "", fmt.Errorf("copy %s: %w", src, err)
	}
	if err := out.Close(); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
