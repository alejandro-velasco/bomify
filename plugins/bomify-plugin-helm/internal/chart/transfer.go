package chart

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/registry"

	"bomify/internal/plugin"
)

// Pull downloads the chart ref describes and saves it into outputDir as
// ref.Filename(), using the Helm SDK's pull action — the same
// implementation behind the `helm pull` CLI command. It supports both
// classic HTTP(S) chart repositories and OCI registries, per ref.OCI.
func Pull(ref Ref, outputDir string, hashAlgorithm cdx.HashAlgorithm) (*plugin.Result, error) {
	registryClient, err := registry.NewClient()
	if err != nil {
		return nil, fmt.Errorf("create OCI registry client: %w", err)
	}

	pull := action.NewPullWithOpts(action.WithConfig(&action.Configuration{RegistryClient: registryClient}))
	pull.Settings = cli.New()
	pull.DestDir = outputDir
	pull.Version = ref.Version

	// action.Pull.Run takes the chart name/reference to resolve, plus the
	// version separately. For OCI it wants a bare "oci://.../<name>" ref
	// (no tag); for a classic repo it wants just the chart name, with the
	// repo's base URL supplied via RepoURL instead.
	chartRef := ref.Name
	if ref.OCI {
		chartRef = strings.TrimSuffix(ref.RepositoryURL, "/") + "/" + ref.Name
	} else {
		pull.RepoURL = ref.RepositoryURL
	}

	if _, err := pull.Run(chartRef); err != nil {
		return nil, fmt.Errorf("pull %s@%s from %s: %w", ref.Name, ref.Version, ref.RepositoryURL, err)
	}

	path := filepath.Join(outputDir, ref.Filename())
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read pulled chart %s: %w", path, err)
	}

	hash, err := chartHash(hashAlgorithm, data)
	if err != nil {
		return nil, err
	}

	return &plugin.Result{
		OutputPath: path,
		Message:    fmt.Sprintf("pulled %s@%s from %s", ref.Name, ref.Version, ref.RepositoryURL),
		Hash:       hash,
	}, nil
}

// Push uploads the chart a prior Pull wrote into inputDir to remote,
// using the Helm SDK's push action — the same implementation behind the
// `helm push` CLI command.
//
// Unlike Pull, Push only supports OCI registries (remote must be an
// "oci://..." reference): the Helm SDK registers no pusher for classic
// HTTP(S) chart repositories, since they're read-only static index.yaml
// listings with no upload API.
func Push(inputDir string, ref Ref, remote string) (*plugin.Result, error) {
	path := filepath.Join(inputDir, ref.Filename())

	registryClient, err := registry.NewClient()
	if err != nil {
		return nil, fmt.Errorf("create OCI registry client: %w", err)
	}

	push := action.NewPushWithOpts(action.WithPushConfig(&action.Configuration{RegistryClient: registryClient}))
	push.Settings = cli.New()

	if _, err := push.Run(path, remote); err != nil {
		return nil, fmt.Errorf("push %s to %s: %w", path, remote, err)
	}

	// The push action appends "/<chart-name>:<chart-version>" (read from
	// the chart archive's own metadata) onto remote itself; mirror that
	// here purely to report where it landed.
	dst := strings.TrimSuffix(remote, "/") + "/" + ref.Name + ":" + ref.Version

	return &plugin.Result{OutputPath: dst, Message: fmt.Sprintf("pushed %s to %s", path, dst)}, nil
}

// chartHash returns the content hash to report for a pulled chart,
// computed directly from its downloaded bytes. Unlike an OCI image
// digest, this isn't independently verified by a registry for HTTP-repo
// pulls, but it's still the actual hash of what was written to disk.
func chartHash(hashAlgorithm cdx.HashAlgorithm, data []byte) (plugin.Hash, error) {
	if hashAlgorithm != cdx.HashAlgoSHA256 {
		return plugin.Hash{}, fmt.Errorf("bomify-plugin-helm: unsupported hash algorithm %q, only %s is supported", hashAlgorithm, cdx.HashAlgoSHA256)
	}

	sum := sha256.Sum256(data)
	return plugin.Hash{Algorithm: cdx.HashAlgoSHA256, Value: hex.EncodeToString(sum[:])}, nil
}
