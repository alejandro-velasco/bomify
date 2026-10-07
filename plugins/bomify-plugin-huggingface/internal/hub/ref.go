// Package hub resolves pkg:huggingface purls to Hugging Face Hub model
// repositories, and pulls and pushes them over the Hub's HTTP API.
package hub

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/package-url/packageurl-go"
)

// PurlType is the package-url type this plugin handles.
const PurlType = "huggingface"

// DefaultHost is the hub a purl without a repository_url qualifier names.
const DefaultHost = "huggingface.co"

// commitHash matches a full Git commit hash, the only revision a purl may
// pin: a branch or tag can move, so a pull of it isn't reproducible.
var commitHash = regexp.MustCompile(`^[0-9a-f]{40}$`)

// Ref is one model repository at one commit.
type Ref struct {
	// Namespace is the repository's user or organization.
	Namespace string
	// Name is the repository's name.
	Name string
	// Revision is the full commit hash.
	Revision string
	// Endpoint is the hub's base URL from the purl's repository_url
	// qualifier, e.g. "https://hub.example.com", or empty for hf's default
	// (huggingface.co, or $HF_ENDPOINT).
	Endpoint string
}

// Resolve parses purlString, a pkg:huggingface purl as the package-url
// spec defines it: pkg:huggingface/<namespace>/<name>@<commit>, with an
// optional repository_url qualifier naming another hub.
func Resolve(purlString string) (Ref, error) {
	purl, err := packageurl.FromString(purlString)
	if err != nil {
		return Ref{}, fmt.Errorf("parse purl %q: %w", purlString, err)
	}
	if purl.Type != PurlType {
		return Ref{}, fmt.Errorf("purl %q isn't a %s purl", purlString, PurlType)
	}
	if purl.Namespace == "" || strings.Contains(purl.Namespace, "/") || purl.Name == "" {
		return Ref{}, fmt.Errorf("purl %q isn't pkg:%s/<namespace>/<name>@<commit>", purlString, PurlType)
	}
	if purl.Subpath != "" {
		return Ref{}, fmt.Errorf("purl %q has a subpath, but a pull is always the whole repository", purlString)
	}

	revision := strings.ToLower(purl.Version)
	if !commitHash.MatchString(revision) {
		return Ref{}, fmt.Errorf("purl %q isn't pinned to a commit: its version must be the repository's full 40-character commit hash, so every pull gets the same files", purlString)
	}

	endpoint, err := endpointOf(purl.Qualifiers.Map()["repository_url"])
	if err != nil {
		return Ref{}, fmt.Errorf("purl %q: %w", purlString, err)
	}

	ref := Ref{
		Namespace: purl.Namespace,
		Name:      purl.Name,
		Revision:  revision,
		Endpoint:  endpoint,
	}
	return ref, nil
}

// endpointOf validates a repository_url qualifier and returns it without a
// trailing slash, or "" if it's empty.
func endpointOf(repositoryURL string) (string, error) {
	if repositoryURL == "" {
		return "", nil
	}
	parsed, err := url.Parse(repositoryURL)
	if err != nil {
		return "", fmt.Errorf("parse repository_url %q: %w", repositoryURL, err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("repository_url %q isn't an https:// hub address", repositoryURL)
	}
	return strings.TrimSuffix(repositoryURL, "/"), nil
}

// RepoID returns the repository's "<namespace>/<name>", as hf takes it.
func (r Ref) RepoID() string {
	return r.Namespace + "/" + r.Name
}

// Remote returns where r comes from: the hub's host (and path, if its
// repository_url has one) and r's namespace, e.g.
// "huggingface.co/meta-llama", in the shape push's --remote takes.
func (r Ref) Remote() string {
	host := DefaultHost
	if r.Endpoint != "" {
		host = strings.TrimPrefix(r.Endpoint, "https://")
	}
	return host + "/" + r.Namespace
}

// ParseRemote splits push's --remote, "[https://]<host>[/<path>]/<namespace>",
// into the hub's base URL and the namespace to upload into.
func ParseRemote(remote string) (endpoint, namespace string, err error) {
	trimmed := strings.TrimSuffix(strings.TrimPrefix(remote, "https://"), "/")
	if strings.Contains(trimmed, "://") {
		return "", "", fmt.Errorf("--remote %q isn't an https:// hub address", remote)
	}
	slash := strings.LastIndex(trimmed, "/")
	if slash <= 0 || slash == len(trimmed)-1 {
		return "", "", fmt.Errorf("--remote %q isn't <hub host>/<namespace>, e.g. %s/my-org", remote, DefaultHost)
	}
	return "https://" + trimmed[:slash], trimmed[slash+1:], nil
}
