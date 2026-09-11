package image

import (
	"fmt"
	"log/slog"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	gcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/package-url/packageurl-go"

	"github.com/alejandro-velasco/bomify/internal/auth"
	"github.com/alejandro-velasco/bomify/internal/plugin"
)

// craneAuth resolves crane's registry credentials from bomify's shared
// credential store (see internal/auth) rather than crane's own default
// keychain, so `bomify login` covers this plugin the same way it covers
// `bomify push`/`bomify pull`. In practice the two end up equivalent —
// both ultimately read $HOME/.docker/config.json — but this makes that
// dependency explicit rather than relying on crane's default happening to
// agree with bomify's own store.
var craneAuth = crane.WithAuthFromKeychain(authn.NewKeychainFromHelper(auth.HelperFunc(auth.Get)))

// Pull downloads ref and saves it into outputDir as an OCI Image Layout,
// so the pulled artifact is in OCI format rather than a docker-style
// tarball. outputDir is a directory bomify has already created dedicated
// to this component, so Pull writes directly into it.
//
// hashAlgorithm is the hash bomify wants reported in the result. OCI/docker
// images are always content-addressed with SHA-256, so any other
// algorithm is unsupported and returns an error.
func Pull(ref string, outputDir string, hashAlgorithm cdx.HashAlgorithm, logger *slog.Logger) (*plugin.Result, error) {
	logger.Info("pulling image", "ref", ref)
	img, err := crane.Pull(ref, craneAuth)
	if err != nil {
		return nil, fmt.Errorf("pull %s: %w", ref, err)
	}

	logger.Info("saving OCI image layout", "output", outputDir)
	if err := crane.SaveOCI(img, outputDir); err != nil {
		return nil, fmt.Errorf("save %s to %s: %w", ref, outputDir, err)
	}

	hash, err := digestHash(img, hashAlgorithm)
	if err != nil {
		return nil, err
	}
	logger.Info("pull complete", "ref", ref, "hash", hash.Value)

	return &plugin.Result{OutputPath: outputDir, Message: fmt.Sprintf("pulled %s", ref), Hash: hash}, nil
}

// digestHash returns img's content digest as a plugin.Hash for
// hashAlgorithm.
func digestHash(img gcrv1.Image, hashAlgorithm cdx.HashAlgorithm) (plugin.Hash, error) {
	if hashAlgorithm != cdx.HashAlgoSHA256 {
		return plugin.Hash{}, fmt.Errorf("bomify-plugin-oci: unsupported hash algorithm %q, only %s is supported", hashAlgorithm, cdx.HashAlgoSHA256)
	}

	digest, err := img.Digest()
	if err != nil {
		return plugin.Hash{}, fmt.Errorf("compute image digest: %w", err)
	}

	return plugin.Hash{Algorithm: cdx.HashAlgoSHA256, Value: digest.Hex}, nil
}

// Push reads the OCI Image Layout a prior Pull wrote into inputDir and
// pushes it to a tag under remote.
func Push(inputDir string, purlString string, remote string, logger *slog.Logger) (*plugin.Result, error) {
	logger.Info("reading OCI image layout", "input", inputDir)
	idx, err := layout.ImageIndexFromPath(inputDir)
	if err != nil {
		return nil, fmt.Errorf("read OCI layout at %s: %w", inputDir, err)
	}

	manifest, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("read OCI layout manifest at %s: %w", inputDir, err)
	}
	if len(manifest.Manifests) == 0 {
		return nil, fmt.Errorf("no images found in OCI layout at %s", inputDir)
	}

	img, err := idx.Image(manifest.Manifests[0].Digest)
	if err != nil {
		return nil, fmt.Errorf("read image from OCI layout at %s: %w", inputDir, err)
	}

	dst, err := destinationReference(remote, purlString)
	if err != nil {
		return nil, err
	}

	logger.Info("pushing image", "destination", dst)
	if err := crane.Push(img, dst, craneAuth); err != nil {
		return nil, fmt.Errorf("push %s to %s: %w", inputDir, dst, err)
	}
	logger.Info("push complete", "destination", dst)

	return &plugin.Result{OutputPath: dst, Message: fmt.Sprintf("pushed %s to %s", inputDir, dst)}, nil
}

// destinationReference derives a "<remote>/<name>:<version>" reference from
// purlString, defaulting to "latest" when it declares no version.
func destinationReference(remote, purlString string) (string, error) {
	purl, err := packageurl.FromString(purlString)
	if err != nil {
		return "", fmt.Errorf("parse purl %q: %w", purlString, err)
	}

	version := purl.Version
	if version == "" {
		version = "latest"
	}

	remote = strings.TrimSuffix(remote, "/")
	return fmt.Sprintf("%s/%s:%s", remote, purl.Name, version), nil
}
