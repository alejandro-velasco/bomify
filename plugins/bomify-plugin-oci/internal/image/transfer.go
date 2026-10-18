package image

import (
	"fmt"
	"log/slog"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"

	"github.com/alejandro-velasco/bomify/pkg/auth"
	"github.com/alejandro-velasco/bomify/pkg/plugin"
)

// craneAuth resolves registry credentials from bomify's shared credential
// store (see pkg/auth) rather than crane's own default keychain, so
// `bomify login` covers this plugin too.
var craneAuth = crane.WithAuthFromKeychain(authn.NewKeychainFromHelper(auth.HelperFunc(auth.Get)))

// Pull downloads ref and saves it into outputDir as an OCI Image Layout,
// so the pulled artifact is in OCI format rather than a docker-style
// tarball. outputDir is a directory bomify has already created dedicated
// to this component, so Pull writes directly into it.
// The reported hash is the image's own SHA-256 digest.
func Pull(ref string, outputDir string, logger *slog.Logger) (*plugin.Result, error) {
	logger.Info("pulling image", "ref", ref)
	img, err := crane.Pull(ref, craneAuth)
	if err != nil {
		return nil, fmt.Errorf("pull %s: %w", ref, err)
	}

	logger.Info("saving OCI image layout", "output", outputDir)
	if err := crane.SaveOCI(img, outputDir); err != nil {
		return nil, fmt.Errorf("save %s to %s: %w", ref, outputDir, err)
	}

	digest, err := img.Digest()
	if err != nil {
		return nil, fmt.Errorf("compute image digest: %w", err)
	}
	hash := plugin.NewHash(digest.Hex)
	logger.Info("pull complete", "ref", ref, "hash", hash.Value)

	return &plugin.Result{OutputPath: outputDir, Message: fmt.Sprintf("pulled %s", ref), Hash: hash}, nil
}

// CheckPull verifies ref exists and is readable via the same crane.Pull
// manifest resolution Pull uses, just stopping short of crane.SaveOCI
// (the part that downloads layer blobs). Deliberately not crane.Head:
// for a multi-platform ref, HEAD reports the manifest list's own digest,
// while Pull resolves to a specific platform's image digest — using
// HEAD's digest here would disagree with what Pull (and a real,
// non-check build) verifies against the SBOM's declared hash.
func CheckPull(ref string, logger *slog.Logger) (*plugin.Result, error) {
	logger.Info("resolving image", "ref", ref)
	img, err := crane.Pull(ref, craneAuth)
	if err != nil {
		return nil, fmt.Errorf("check %s: %w", ref, err)
	}

	digest, err := img.Digest()
	if err != nil {
		return nil, fmt.Errorf("compute image digest: %w", err)
	}
	hash := plugin.NewHash(digest.Hex)
	logger.Info("check complete", "ref", ref, "hash", hash.Value)

	return &plugin.Result{OutputPath: ref, Message: fmt.Sprintf("%s exists and is pullable", ref), Hash: hash}, nil
}
