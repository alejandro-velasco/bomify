package chart

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	gcrremote "github.com/google/go-containerregistry/pkg/v1/remote"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/registry"
	"helm.sh/helm/v3/pkg/repo"
	"sigs.k8s.io/yaml"

	"github.com/alejandro-velasco/bomify/pkg/auth"
	"github.com/alejandro-velasco/bomify/pkg/plugin"
)

// keychain resolves registry credentials from bomify's shared credential
// store (see pkg/auth), for CheckPush's remote.CheckPushPermission probe
// — a Helm OCI chart is an ordinary OCI Distribution artifact, so
// go-containerregistry's permission check applies here too, same as
// bomify-plugin-oci.
var keychain = authn.NewKeychainFromHelper(auth.HelperFunc(auth.Get))

// newRegistryClient is a var — rather than a plain func — solely so tests
// can substitute a different constructor (e.g. one that enables plain
// HTTP for a local, in-process test registry) without changing real CLI
// behavior; see internal/auth's newStore/newPlaintextStore for the same
// pattern.
var newRegistryClient = defaultRegistryClient

// defaultRegistryClient builds a Helm OCI registry client authenticated,
// for host, with whatever bomify's shared credential store (fetched via
// pkg/auth.Get; see internal/auth for the store itself, the same one
// `bomify login`/`docker login` write) has for it. A host with nothing
// stored gets an anonymous client, exactly like a bomify pull/push
// against a public registry.
func defaultRegistryClient(host string) (*registry.Client, error) {
	var opts []registry.ClientOption

	if host != "" {
		username, password, err := auth.Get(host)
		if err != nil {
			return nil, fmt.Errorf("look up credentials for %s: %w", host, err)
		}
		if username != "" || password != "" {
			opts = append(opts, registry.ClientOptBasicAuth(username, password))
		}
	}

	client, err := registry.NewClient(opts...)
	if err != nil {
		return nil, fmt.Errorf("create OCI registry client: %w", err)
	}
	return client, nil
}

// registryHost extracts the hostname to look up credentials for from a
// repository URL, which is either a classic "https://host/path" chart
// repo or an "oci://host/path" registry reference — both are ordinary
// URLs as far as net/url is concerned.
func registryHost(repositoryURL string) string {
	u, err := url.Parse(repositoryURL)
	if err != nil {
		return ""
	}
	return u.Host
}

// Pull downloads the chart ref describes and saves it into outputDir as
// ref.Filename(), using the Helm SDK's pull action — the same
// implementation behind the `helm pull` CLI command. It supports both
// classic HTTP(S) chart repositories and OCI registries, per ref.OCI.
func Pull(ref Ref, outputDir string, hashAlgorithm cdx.HashAlgorithm, logger *slog.Logger) (*plugin.Result, error) {
	host := registryHost(ref.RepositoryURL)

	registryClient, err := newRegistryClient(host)
	if err != nil {
		return nil, err
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

		// The OCI registry client above only authenticates OCI pulls;
		// classic HTTP(S) chart repo auth goes through ChartPathOptions
		// (embedded in Pull) instead.
		if host != "" {
			username, password, err := auth.Get(host)
			if err != nil {
				return nil, fmt.Errorf("look up credentials for %s: %w", host, err)
			}
			pull.Username = username
			pull.Password = password
		}
	}

	logger.Info("pulling chart", "chart", chartRef, "version", ref.Version, "repository_url", ref.RepositoryURL)
	if _, err := pull.Run(chartRef); err != nil {
		return nil, fmt.Errorf("pull %s@%s from %s: %w", ref.Name, ref.Version, ref.RepositoryURL, err)
	}

	path := filepath.Join(outputDir, ref.Filename())
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read pulled chart %s: %w", path, err)
	}
	logger.Info("pull complete", "path", path)

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

// CheckPull verifies ref exists and is fetchable without downloading it:
// an OCI manifest resolve (no chart layer) for an OCI registry, or a
// fetch of the small index.yaml a real Pull consults first, for a
// classic HTTP(S) repository.
func CheckPull(ref Ref, hashAlgorithm cdx.HashAlgorithm, logger *slog.Logger) (*plugin.Result, error) {
	if ref.OCI {
		return checkPullOCI(ref, logger)
	}
	return checkPullHTTP(ref, hashAlgorithm, logger)
}

// checkPullOCI resolves ref's manifest without pulling its chart layer.
// The resolved descriptor's digest is the OCI manifest's own digest, not
// the chart tarball hash chartHash computes for a real Pull, so no hash
// is reported here.
func checkPullOCI(ref Ref, logger *slog.Logger) (*plugin.Result, error) {
	registryClient, err := newRegistryClient(registryHost(ref.RepositoryURL))
	if err != nil {
		return nil, err
	}

	displayRef := strings.TrimSuffix(ref.RepositoryURL, "/") + "/" + ref.Name + ":" + ref.Version
	// Client.Resolve wants a bare "host/repository:tag", no "oci://"
	// scheme — see Client.ValidateReference for the same convention.
	resolveRef := strings.TrimPrefix(displayRef, registry.OCIScheme+"://")

	logger.Info("resolving chart", "ref", resolveRef)
	if _, err := registryClient.Resolve(resolveRef); err != nil {
		return nil, fmt.Errorf("resolve %s: %w", displayRef, err)
	}
	logger.Info("check complete", "ref", displayRef)

	return &plugin.Result{OutputPath: displayRef, Message: fmt.Sprintf("%s exists and is pullable", displayRef)}, nil
}

// checkPullHTTP fetches ref.RepositoryURL's small index.yaml — the same
// listing a real Pull consults first — and looks for a matching entry,
// without downloading the chart. Its digest field is the same SHA-256
// chartHash would compute from the downloaded chart, so hash comes back
// populated at no extra cost.
func checkPullHTTP(ref Ref, hashAlgorithm cdx.HashAlgorithm, logger *slog.Logger) (*plugin.Result, error) {
	indexURL := strings.TrimSuffix(ref.RepositoryURL, "/") + "/index.yaml"

	req, err := http.NewRequest(http.MethodGet, indexURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build GET request for %s: %w", indexURL, err)
	}
	if host := registryHost(ref.RepositoryURL); host != "" {
		username, password, err := auth.Get(host)
		if err != nil {
			return nil, fmt.Errorf("look up credentials for %s: %w", host, err)
		}
		if username != "" || password != "" {
			req.SetBasicAuth(username, password)
		}
	}

	logger.Info("GET", "url", indexURL)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", indexURL, err)
	}
	defer resp.Body.Close()
	logger.Info("response received", "status", resp.Status)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("GET %s: unexpected status %s: %s", indexURL, resp.Status, strings.TrimSpace(string(body)))
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", indexURL, err)
	}

	var idx repo.IndexFile
	if err := yaml.Unmarshal(data, &idx); err != nil {
		return nil, fmt.Errorf("parse %s: %w", indexURL, err)
	}

	entry := findChartVersion(idx, ref.Name, ref.Version)
	if entry == nil {
		return nil, fmt.Errorf("chart %s@%s not found in %s", ref.Name, ref.Version, indexURL)
	}
	logger.Info("check complete", "chart", ref.Name, "version", ref.Version)

	result := &plugin.Result{
		OutputPath: entryURL(ref.RepositoryURL, entry),
		Message:    fmt.Sprintf("%s@%s exists at %s", ref.Name, ref.Version, ref.RepositoryURL),
	}
	if hashAlgorithm == cdx.HashAlgoSHA256 && entry.Digest != "" {
		result.Hash = plugin.Hash{Algorithm: cdx.HashAlgoSHA256, Value: entry.Digest}
	}
	return result, nil
}

// findChartVersion looks up the entry for name@version in idx, or nil if
// there isn't one.
func findChartVersion(idx repo.IndexFile, name, version string) *repo.ChartVersion {
	for _, v := range idx.Entries[name] {
		if v.Version == version {
			return v
		}
	}
	return nil
}

// entryURL resolves entry's first download URL against repositoryURL
// (index.yaml entries are allowed to use a URL relative to the index
// itself), falling back to repositoryURL when entry has no URLs at all.
func entryURL(repositoryURL string, entry *repo.ChartVersion) string {
	if len(entry.URLs) == 0 {
		return repositoryURL
	}

	base, err := url.Parse(repositoryURL)
	if err != nil {
		return entry.URLs[0]
	}
	ref, err := url.Parse(entry.URLs[0])
	if err != nil {
		return entry.URLs[0]
	}
	return base.ResolveReference(ref).String()
}

// Push uploads the chart a prior Pull wrote into inputDir to remote,
// using the Helm SDK's push action — the same implementation behind the
// `helm push` CLI command.
//
// Unlike Pull, Push only supports OCI registries (remote must be an
// "oci://..." reference): the Helm SDK registers no pusher for classic
// HTTP(S) chart repositories, since they're read-only static index.yaml
// listings with no upload API.
func Push(inputDir string, ref Ref, remote string, logger *slog.Logger) (*plugin.Result, error) {
	path := filepath.Join(inputDir, ref.Filename())

	registryClient, err := newRegistryClient(registryHost(remote))
	if err != nil {
		return nil, err
	}

	push := action.NewPushWithOpts(action.WithPushConfig(&action.Configuration{RegistryClient: registryClient}))
	push.Settings = cli.New()

	logger.Info("pushing chart", "path", path, "remote", remote)
	if _, err := push.Run(path, remote); err != nil {
		return nil, fmt.Errorf("push %s to %s: %w", path, remote, err)
	}

	// The push action appends "/<chart-name>:<chart-version>" (read from
	// the chart archive's own metadata) onto remote itself; mirror that
	// here purely to report where it landed.
	dst := strings.TrimSuffix(remote, "/") + "/" + ref.Name + ":" + ref.Version
	logger.Info("push complete", "destination", dst)

	return &plugin.Result{OutputPath: dst, Message: fmt.Sprintf("pushed %s to %s", path, dst)}, nil
}

// CheckPush verifies the caller is authorized to push ref to remote,
// without publishing anything, via remote.CheckPushPermission (see the
// keychain doc comment). Like Push, it's OCI-only; a classic HTTP(S)
// remote fails the same way a real Push would.
func CheckPush(ref Ref, remote string, logger *slog.Logger) (*plugin.Result, error) {
	if !registry.IsOCI(remote) {
		return nil, fmt.Errorf("push only supports OCI registries, got %q", remote)
	}

	dst := strings.TrimSuffix(strings.TrimPrefix(remote, registry.OCIScheme+"://"), "/") + "/" + ref.Name + ":" + ref.Version
	nameRef, err := name.ParseReference(dst)
	if err != nil {
		return nil, fmt.Errorf("parse destination %q: %w", dst, err)
	}

	logger.Info("checking push permission", "destination", dst)
	if err := gcrremote.CheckPushPermission(nameRef, keychain, http.DefaultTransport); err != nil {
		return nil, fmt.Errorf("check push permission for %s: %w", dst, err)
	}
	logger.Info("check complete", "destination", dst)

	return &plugin.Result{OutputPath: dst, Message: fmt.Sprintf("authorized to push to %s", dst)}, nil
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
