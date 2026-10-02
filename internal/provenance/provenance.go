// Package provenance records how a package was built, as a SLSA v1
// provenance predicate (https://slsa.dev/provenance/v1), and attaches it
// to the package as an in-toto attestation when the package is pushed or
// saved. See docs/architecture/provenance.md.
package provenance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/alejandro-velasco/bomify/internal/buildinfo"
	"github.com/alejandro-velasco/bomify/internal/fsutil"
	"github.com/alejandro-velasco/bomify/internal/layout"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

const (
	// StatementType is the in-toto statement type.
	StatementType = "https://in-toto.io/Statement/v1"
	// PredicateType is the SLSA provenance predicate type.
	PredicateType = "https://slsa.dev/provenance/v1"
	// MediaType is the media type of an in-toto statement, and the DSSE
	// payload type it's signed as.
	MediaType = pluginlib.InTotoPayloadType
	// BuildType identifies bomify builds, documenting what their
	// externalParameters and resolvedDependencies mean.
	BuildType = "https://github.com/alejandro-velasco/bomify/blob/main/docs/architecture/provenance.md"
	// BuilderID identifies bomify as the builder; runDetails.builder.version
	// says which version.
	BuilderID = "https://github.com/alejandro-velasco/bomify"
)

// Predicate is a SLSA v1 provenance predicate.
type Predicate struct {
	BuildDefinition BuildDefinition `json:"buildDefinition"`
	RunDetails      RunDetails      `json:"runDetails"`
}

type BuildDefinition struct {
	BuildType            string               `json:"buildType"`
	ExternalParameters   ExternalParameters   `json:"externalParameters"`
	ResolvedDependencies []ResourceDescriptor `json:"resolvedDependencies,omitempty"`
}

// ExternalParameters are what the user asked bomify build to do.
type ExternalParameters struct {
	SBOM ResourceDescriptor `json:"sbom"`
	Tags []string           `json:"tags,omitempty"`
}

// ResourceDescriptor is an in-toto resource descriptor.
type ResourceDescriptor struct {
	URI    string            `json:"uri,omitempty"`
	Name   string            `json:"name,omitempty"`
	Digest map[string]string `json:"digest,omitempty"`
}

type RunDetails struct {
	Builder  Builder  `json:"builder"`
	Metadata Metadata `json:"metadata"`
}

type Builder struct {
	ID      string            `json:"id"`
	Version map[string]string `json:"version,omitempty"`
}

type Metadata struct {
	InvocationID string `json:"invocationId,omitempty"`
	StartedOn    string `json:"startedOn,omitempty"`
	FinishedOn   string `json:"finishedOn,omitempty"`
}

// Statement is an in-toto statement about one subject.
type Statement struct {
	Type          string               `json:"_type"`
	Subject       []ResourceDescriptor `json:"subject"`
	PredicateType string               `json:"predicateType"`
	Predicate     Predicate            `json:"predicate"`
}

// Recorder collects a build's resolved dependencies as its components are
// pulled. It's safe for concurrent use.
type Recorder struct {
	started time.Time

	mu      sync.Mutex
	deps    map[string]ResourceDescriptor
	plugins map[string]bool
}

// NewRecorder starts recording a build now.
func NewRecorder() *Recorder {
	return &Recorder{started: time.Now().UTC(), deps: map[string]ResourceDescriptor{}, plugins: map[string]bool{}}
}

// AddComponent records a pulled component by purl and, if known, the
// SHA-256 of what was pulled.
func (r *Recorder) AddComponent(purl, sha256 string) {
	r.add(ResourceDescriptor{URI: purl, Digest: digest(sha256)})
}

// AddPlugin records the plugin binary for kind at path, once per kind. Its
// version is version (as "bomify plugin install" recorded it, if at all),
// used only when recordedSHA256 matches the binary actually there, so a
// binary replaced by hand is never credited with a version it isn't.
func (r *Recorder) AddPlugin(kind, path, version, recordedSHA256 string, hash func(string) (string, error)) error {
	r.mu.Lock()
	seen := r.plugins[kind]
	r.plugins[kind] = true
	r.mu.Unlock()
	if seen {
		return nil
	}

	sum, err := hash(path)
	if err != nil {
		return fmt.Errorf("hash plugin %s: %w", kind, err)
	}
	uri := "pkg:bomify-plugin/" + kind
	if version != "" && strings.EqualFold(recordedSHA256, sum) {
		uri += "@" + version
	}
	r.add(ResourceDescriptor{URI: uri, Name: "bomify-plugin-" + kind, Digest: digest(sum)})
	return nil
}

func (r *Recorder) add(d ResourceDescriptor) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deps[d.URI] = d
}

// Write records the build of the SBOM hashing to sbomHash, tagged tags, as
// baseDir's provenance for that build, replacing any earlier record.
func (r *Recorder) Write(baseDir, sbomHash string, tags []string) error {
	r.mu.Lock()
	deps := make([]ResourceDescriptor, 0, len(r.deps))
	for _, d := range r.deps {
		deps = append(deps, d)
	}
	r.mu.Unlock()
	slices.SortFunc(deps, func(a, b ResourceDescriptor) int { return strings.Compare(a.URI, b.URI) })

	p := Predicate{
		BuildDefinition: BuildDefinition{
			BuildType:            BuildType,
			ExternalParameters:   ExternalParameters{SBOM: ResourceDescriptor{Digest: digest(sbomHash)}, Tags: tags},
			ResolvedDependencies: deps,
		},
		RunDetails: RunDetails{
			Builder: Builder{ID: BuilderID, Version: map[string]string{"bomify": buildinfo.GetBuildInfo().Version}},
			Metadata: Metadata{
				InvocationID: invocationID(),
				StartedOn:    r.started.Format(time.RFC3339),
				FinishedOn:   time.Now().UTC().Format(time.RFC3339),
			},
		},
	}
	return fsutil.WriteJSON(layout.Provenance(baseDir, sbomHash), p)
}

// Read returns baseDir's provenance for the build of sbomHash; ok is false
// if that build recorded none.
func Read(baseDir, sbomHash string) (p Predicate, ok bool, err error) {
	path := layout.Provenance(baseDir, sbomHash)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return Predicate{}, false, nil
	}
	if err := fsutil.ReadJSON(path, &p); err != nil {
		return Predicate{}, false, err
	}
	return p, true, nil
}

// NewStatement returns p as an in-toto statement whose subject is the
// artifact name with the given sha256 digest, encoded deterministically.
func NewStatement(p Predicate, name, sha256 string) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	err := enc.Encode(Statement{
		Type:          StatementType,
		Subject:       []ResourceDescriptor{{Name: name, Digest: digest(sha256)}},
		PredicateType: PredicateType,
		Predicate:     p,
	})
	if err != nil {
		return nil, fmt.Errorf("encode provenance statement: %w", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func digest(sha256 string) map[string]string {
	if sha256 == "" {
		return nil
	}
	return map[string]string{"sha256": strings.ToLower(sha256)}
}

// invocationID identifies the CI run this build is part of, when there is
// one: a GitHub Actions run's URL.
func invocationID() string {
	server, repo, run := os.Getenv("GITHUB_SERVER_URL"), os.Getenv("GITHUB_REPOSITORY"), os.Getenv("GITHUB_RUN_ID")
	if server == "" || repo == "" || run == "" {
		return ""
	}
	id := server + "/" + repo + "/actions/runs/" + run
	if attempt := os.Getenv("GITHUB_RUN_ATTEMPT"); attempt != "" {
		id += "/attempts/" + attempt
	}
	return id
}
