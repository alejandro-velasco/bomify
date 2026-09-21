package image

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	gcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	gcrremote "github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/package-url/packageurl-go"

	"github.com/alejandro-velasco/bomify/pkg/auth"
	"github.com/alejandro-velasco/bomify/pkg/plugin"
)

// keychain resolves registry credentials from bomify's shared credential
// store (see pkg/auth) rather than crane's own default keychain, so
// `bomify login` covers this plugin the same way it covers `bomify
// push`/`bomify pull`. In practice the two end up equivalent — both
// ultimately read $HOME/.docker/config.json — but this makes that
// dependency explicit rather than relying on crane's default happening to
// agree with bomify's own store. It's kept as the raw authn.Keychain
// (rather than only the crane.Option craneAuth wraps it in) because
// CheckPush needs it directly, for remote.CheckPushPermission.
var keychain = authn.NewKeychainFromHelper(auth.HelperFunc(auth.Get))

// craneAuth is keychain adapted to a crane.Option, for the crane-level
// calls (Pull, Push, Head).
var craneAuth = crane.WithAuthFromKeychain(keychain)

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

	digest, err := img.Digest()
	if err != nil {
		return nil, fmt.Errorf("compute image digest: %w", err)
	}
	hash, err := digestHash(digest, hashAlgorithm)
	if err != nil {
		return nil, err
	}
	logger.Info("pull complete", "ref", ref, "hash", hash.Value)

	return &plugin.Result{OutputPath: outputDir, Message: fmt.Sprintf("pulled %s", ref), Hash: hash}, nil
}

// CheckPull verifies that a real Pull of ref would succeed — the image
// exists and the caller is authorized to read it — via the same
// crane.Pull manifest resolution Pull itself uses, just stopping short
// of crane.SaveOCI, which is the part that actually downloads layer
// blobs. This deliberately does *not* use a plain manifest HEAD
// (crane.Head): for a multi-platform ref, HEAD reports the top-level
// manifest list's own digest, while Pull resolves through it to a
// specific platform's image and reports that child manifest's digest
// instead — using HEAD's digest here would silently disagree with what
// Pull (and hence a real, non-check build) actually verifies against the
// SBOM's declared hash.
func CheckPull(ref string, hashAlgorithm cdx.HashAlgorithm, logger *slog.Logger) (*plugin.Result, error) {
	logger.Info("resolving image", "ref", ref)
	img, err := crane.Pull(ref, craneAuth)
	if err != nil {
		return nil, fmt.Errorf("check %s: %w", ref, err)
	}

	digest, err := img.Digest()
	if err != nil {
		return nil, fmt.Errorf("compute image digest: %w", err)
	}
	hash, err := digestHash(digest, hashAlgorithm)
	if err != nil {
		return nil, err
	}
	logger.Info("check complete", "ref", ref, "hash", hash.Value)

	return &plugin.Result{OutputPath: ref, Message: fmt.Sprintf("%s exists and is pullable", ref), Hash: hash}, nil
}

// digestHash converts an image digest to a plugin.Hash for hashAlgorithm.
func digestHash(digest gcrv1.Hash, hashAlgorithm cdx.HashAlgorithm) (plugin.Hash, error) {
	if hashAlgorithm != cdx.HashAlgoSHA256 {
		return plugin.Hash{}, fmt.Errorf("bomify-plugin-oci: unsupported hash algorithm %q, only %s is supported", hashAlgorithm, cdx.HashAlgoSHA256)
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

// CheckPush verifies that a real Push of purlString to remote would
// succeed — the caller is authorized to write there — without publishing
// anything. It uses remote.CheckPushPermission, which probes push
// authorization the same inexpensive way a real push permission check
// should: initiating an upload session and immediately cancelling it,
// never sending any actual blob content.
func CheckPush(purlString string, remote string, logger *slog.Logger) (*plugin.Result, error) {
	dst, err := destinationReference(remote, purlString)
	if err != nil {
		return nil, err
	}

	ref, err := name.ParseReference(dst)
	if err != nil {
		return nil, fmt.Errorf("parse destination %q: %w", dst, err)
	}

	logger.Info("checking push permission", "destination", dst)
	if err := gcrremote.CheckPushPermission(ref, keychain, http.DefaultTransport); err != nil {
		return nil, fmt.Errorf("check push permission for %s: %w", dst, err)
	}
	logger.Info("check complete", "destination", dst)

	return &plugin.Result{OutputPath: dst, Message: fmt.Sprintf("authorized to push to %s", dst)}, nil
}

// destinationReference derives a "<remote>/<name>" reference from
// purlString, preferring the "tag" qualifier, then a digest-shaped version
// (joined with "@"), then a plain tag-shaped version (joined with ":"), and
// finally the "latest" tag when purlString declares neither — the same
// precedence Resolve uses for pull.
func destinationReference(remote, purlString string) (string, error) {
	purl, err := packageurl.FromString(purlString)
	if err != nil {
		return "", fmt.Errorf("parse purl %q: %w", purlString, err)
	}

	remote = strings.TrimSuffix(remote, "/")
	repository := remote + "/" + purl.Name

	qualifiers := purl.Qualifiers.Map()
	switch {
	case qualifiers["tag"] != "":
		return repository + ":" + qualifiers["tag"], nil
	case strings.HasPrefix(purl.Version, "sha256:"):
		return repository + "@" + purl.Version, nil
	case purl.Version != "":
		return repository + ":" + purl.Version, nil
	default:
		return repository + ":latest", nil
	}
}
